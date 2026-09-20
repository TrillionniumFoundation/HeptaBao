#!/usr/bin/env python3
"""Exercise pinned schema-22 bounded LDAP state through native LDAP (schema 23+)."""
from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import tempfile
import time

from bao_http import Client, SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from identity_upgrade import validate_binary_pins
from ldap_renewal_live import RenewalDirectory, Trace as LdapTrace, configuration as bounded_configuration, user_configuration
from ldap_native_live import configuration as native_configuration
from online_evidence import admit_output, source_identity
from provider_renewal_upgrade import durable_manifest
from radius_renewal_live import renewal_token_shape
from remote_jwks_live import Instance

LEGACY_SOURCE = "b0c3981461b2d950f070c3b48feeb1e847048790"
LEGACY_SHA256 = "3f0dc5c475942c2391fa9f01f3dd5e986fed78d786a874d58a65a31768c4209a"
LEGACY_RECEIPT = ROOT / "qa/openbao-acceptance/evidence/radius-native-upgrade-0e47d47-to-b0c3981.json"


def admit_legacy(candidate, legacy, expected, receipt):
    required = {"build_source_commit": LEGACY_SOURCE, "harness_source_commit": LEGACY_SOURCE,
                "harness_source_dirty": False, "harness_source_unchanged": True,
                "binaries_unchanged": True, "candidate_binary_sha256": LEGACY_SHA256, "status": "passed"}
    if expected != LEGACY_SHA256 or any(receipt.get(key) != value for key, value in required.items()):
        raise ValueError("legacy_schema22_build_receipt_mismatch")
    return validate_binary_pins(candidate, legacy, expected)


class Trace(LdapTrace):
    def check(self, name, condition, **observed):
        case = "ldap_native_upgrade." + name
        self.results.append({"case": case, **observed, "passed": bool(condition)})
        if not condition:
            raise ScenarioFailure(case)


def prepare_legacy(instance, directory, cases):
    instance.start()
    status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
    if status != 200:
        raise ScenarioFailure("ldap_native_upgrade.initialize")
    instance.token, key = initialized["root_token"], initialized["keys_base64"][0]
    t = Trace(Client(instance.address, str(instance.root / "ca.crt"), instance.token), directory, cases)
    t.call("legacy.unseal", "sys/unseal", {"key": key})
    rules = ('path "secret/data/ldap-upgrade" { capabilities = ["read"] }\n'
             'path "auth/token/create" { capabilities = ["update", "sudo"] }\n'
             'path "auth/token/create-orphan" { capabilities = ["update", "sudo"] }')
    t.call("legacy.policy", "sys/policies/acl/upgrade-reader", {"policy": rules}, method="PUT", expected=204)
    t.call("legacy.mount", "sys/auth/ldap-bounded", {"type": "ldap"}, expected=204)
    config = bounded_configuration("candidate", directory, (instance.root / "ca.crt").read_text())
    t.call("legacy.config", "auth/ldap-bounded/config", config, expected=204)
    user = dict(user_configuration("candidate", ["default", "upgrade-reader"]), token_ttl=300)
    t.call("legacy.no_mapping_denied", "auth/ldap-bounded/login/alice",
           {"password": directory.user_password}, token="", expected=403)
    t.call("legacy.mapping", "auth/ldap-bounded/users/alice", user, method="PUT", expected=204)
    t.call("legacy.value", "secret/data/ldap-upgrade", {"data": {"synthetic": True}})
    original = t.login("legacy.login", "ldap-bounded")
    t.check("legacy.renewable", original.get("renewable") is True and original.get("lease_duration") == 300)
    tokens = {"bounded": original}
    for label, path in [("child", "auth/token/create"), ("orphan", "auth/token/create-orphan")]:
        auth = t.call("legacy." + label + ".create", path, {"policies": ["default", "upgrade-reader"], "ttl": 300},
                      token=original["client_token"]).get("auth", {})
        t.check("legacy." + label + ".shape", isinstance(auth.get("client_token"), str) and bool(auth["client_token"]))
        tokens[label] = auth
    t.call("legacy.renew", "auth/token/renew-self", {"increment": 300}, token=original["client_token"], provider="search")
    return t, key, config, user, tokens


def run_upgrade(instance, directory, candidate, legacy, cases):
    t, key, config, user, tokens = prepare_legacy(instance, directory, cases)
    instance.stop()
    store = instance.root / "data"
    old_application = durable_manifest(store, application_only=True)
    instance.binary = candidate
    instance.start()
    t.call("current.unseal", "sys/unseal", {"key": key})
    t.check("current.reopen_preserves_application", durable_manifest(store, application_only=True) == old_application)
    before = durable_manifest(store)
    for label, auth in tokens.items():
        value = t.call("current." + label + ".read", "secret/data/ldap-upgrade", method="GET", token=auth["client_token"])
        t.check("current." + label + ".value", value.get("data", {}).get("data") == {"synthetic": True})
        t.call("current." + label + ".active", "auth/token/lookup-self", method="GET", token=auth["client_token"])
    t.call("current.bounded_config", "auth/ldap-bounded/config", method="GET")
    t.check("current.pure_reads_preserve_store", durable_manifest(store) == before)
    native_config = native_configuration("candidate", directory, (instance.root / "ca.crt").read_text(),
                                         token_ttl=300, token_max_ttl=600, token_policies=["upgrade-reader"])
    t.call("current.in_place_mode_change_denied", "auth/ldap-bounded/config", native_config, expected=409)
    t.check("current.mode_denial_preserves_store", durable_manifest(store) == before)
    t.call("current.remove_bounded_mapping", "auth/ldap-bounded/users/alice", method="DELETE", expected=204)
    before = durable_manifest(store)
    cursor = directory.cursor()
    t.call("current.bounded_login_still_needs_mapping", "auth/ldap-bounded/login/alice",
           {"password": directory.user_password}, token="", expected=403)
    t.call("current.bounded_renew_still_needs_mapping", "auth/token/renew-self", {},
           token=tokens["bounded"]["client_token"], expected=403)
    t.check("current.bounded_mapping_denials_preserve_store_and_skip_provider",
            durable_manifest(store) == before and directory.unchanged(cursor))
    t.call("current.restore_bounded_mapping", "auth/ldap-bounded/users/alice", user, method="PUT", expected=204)
    t.call("current.bounded_renew_restored", "auth/token/renew-self", {"increment": 300},
           token=tokens["bounded"]["client_token"], provider="search")
    t.call("native.mount", "sys/auth/ldap-native-upgrade", {"type": "ldap"}, expected=204)
    t.call("native.config", "auth/ldap-native-upgrade/config", native_config, expected=204)
    before = durable_manifest(store)
    t.call("native.reverse_mode_change_denied", "auth/ldap-native-upgrade/config", config, expected=409)
    t.check("native.reverse_mode_denial_preserves_store", durable_manifest(store) == before)
    readback = t.call("native.config_read", "auth/ldap-native-upgrade/config", method="GET")
    t.check("native.manager_secret_redacted", directory.admin_password not in json.dumps(readback)
            and "bindpass" not in readback.get("data", {}))
    t.call("native.mapping_absent", "auth/ldap-native-upgrade/users/alice", method="GET", expected=404)
    native = t.login("native.login_without_mapping", "ldap-native-upgrade")
    t.check("native.new_issuer_authority", native.get("renewable") is True and native.get("lease_duration") == 300
            and native.get("entity_id") != tokens["bounded"].get("entity_id"))
    tokens["native"] = native
    for label, path, body, token in [
            ("self", "auth/token/renew-self", {}, native["client_token"]),
            ("token", "auth/token/renew", {"token": native["client_token"]}, None),
            ("accessor", "auth/token/renew-accessor", {"accessor": native["accessor"]}, None)]:
        body = t.call("native." + label + ".renew", path, dict(body, increment=300), token=token, provider="search")
        t.check("native." + label + ".lease_and_echo", body.get("auth", {}).get("lease_duration") == 300
                and renewal_token_shape(body.get("auth"), native["client_token"], via_accessor=label == "accessor"))
    t.call("native.mapping_added", "auth/ldap-native-upgrade/users/alice", {"policies": ["changed"]}, expected=204)
    before = durable_manifest(store)
    denied = t.call("native.policy_change_denies_renewal", "auth/token/renew-self", {},
                    token=native["client_token"], expected=500, provider="search")
    t.check("native.denial_no_token_or_mutation", not denied.get("auth") and not denied.get("wrap_info")
            and durable_manifest(store) == before)
    t.call("native.mapping_deleted", "auth/ldap-native-upgrade/users/alice", method="DELETE", expected=204)
    t.call("native.deletion_restores_renewal", "auth/token/renew-self", {"increment": 300}, token=native["client_token"], provider="search")
    next_login = t.login("native.mapping_deletion_does_not_disable_directory_user", "ldap-native-upgrade")
    t.check("native.identity_stable", next_login.get("entity_id") == native.get("entity_id"))
    tokens["native-again"] = next_login
    instance.stop()
    upgraded_application = durable_manifest(store, application_only=True)
    t.check("native.mutation_persisted", upgraded_application != old_application)
    instance.binary = legacy
    instance.start()
    t.call("downgrade.unseal_rejected", "sys/unseal", {"key": key}, expected=503)
    t.call("downgrade.still_sealed", "sys/health", method="GET", expected=503)
    instance.stop()
    t.check("downgrade.application_unchanged", durable_manifest(store, application_only=True) == upgraded_application)
    instance.binary = candidate
    instance.start()
    t.call("recovery.unseal", "sys/unseal", {"key": key})
    t.check("recovery.application_unchanged", durable_manifest(store, application_only=True) == upgraded_application)
    for label, auth in tokens.items():
        t.call("recovery." + label + ".active", "auth/token/lookup-self", method="GET", token=auth["client_token"])
    for label in ("bounded", "native", "native-again"):
        auth = tokens[label]
        t.call("recovery." + label + ".renew", "auth/token/renew-self", {"increment": 300}, token=auth["client_token"],
               provider="search")
    directory.stop()
    cursor = directory.cursor()
    for label in ("child", "orphan"):
        t.call("recovery." + label + ".renew_without_directory", "auth/token/renew-self", {"increment": 300},
               token=tokens[label]["client_token"])
    t.check("recovery.children_have_no_provider_dependency", directory.unchanged(cursor))
    directory.start()
    t.call("recovery.remove_bounded_mapping", "auth/ldap-bounded/users/alice", method="DELETE", expected=204)
    before = durable_manifest(store)
    cursor = directory.cursor()
    t.call("recovery.bounded_login_still_needs_mapping", "auth/ldap-bounded/login/alice",
           {"password": directory.user_password}, token="", expected=403)
    t.call("recovery.bounded_renew_still_needs_mapping", "auth/token/renew-self", {},
           token=tokens["bounded"]["client_token"], expected=403)
    t.check("recovery.bounded_mapping_denials_preserve_store_and_skip_provider",
            durable_manifest(store) == before and directory.unchanged(cursor))
    t.call("recovery.restore_bounded_mapping", "auth/ldap-bounded/users/alice", user, method="PUT", expected=204)
    t.call("recovery.bounded_renew_restored", "auth/token/renew-self", {"increment": 300},
           token=tokens["bounded"]["client_token"], provider="search")
    instance.stop()
    secrets = [directory.admin_password, directory.user_password, user["password"], key, instance.token,
               *(auth["client_token"] for auth in tokens.values())]
    files = [p for p in store.rglob("*") if p.is_file()] + [instance.root / "server.log", instance.root / "audit.jsonl"]
    t.check("plaintext_credentials_absent", all(secret.encode() not in path.read_bytes()
            for path in files if path.exists() for secret in secrets))


def main():
    parser = SafeArgumentParser(description=__doc__)
    for name in ("binary", "legacy-binary", "expected-legacy-sha256", "build-source-commit", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.build_source_commit) is None:
        parser.error("full build source commit required")
    candidate, legacy = Path(args.binary).resolve(strict=True), Path(args.legacy_binary).resolve(strict=True)
    candidate_hash, legacy_hash = admit_legacy(candidate, legacy, args.expected_legacy_sha256, json.loads(LEGACY_RECEIPT.read_text()))
    output = Path(args.output).absolute()
    parent = admit_output(output)
    before = source_identity(ROOT, candidate)
    runner_hash = file_hash(Path(__file__))
    root = Path(tempfile.mkdtemp(prefix="heptabao-ldap-native-upgrade-"))
    root.chmod(0o700)
    instance = directory = None
    result = {"schema": "heptabao.ldap-native-upgrade.v1", "from_schema": 22, "minimum_to_schema": 23,
              "synthetic_only": True, "legacy_source_commit": LEGACY_SOURCE, "legacy_binary_sha256": legacy_hash,
              "legacy_receipt_sha256": file_hash(LEGACY_RECEIPT), "candidate_binary_sha256": candidate_hash,
              "build_source_commit": args.build_source_commit, "runner_sha256": runner_hash,
              "build_source_binding_basis": "caller-supplied commit and observed binary hash; not independent attestation",
              "cases": [], "started_at_unix": time.time(), "actual_openldap": True,
              "full_openbao_compatibility": False, "full_migration_qualification": False,
              "rolling_upgrade_qualification": False, "independent_qualification": False, "production_authority": False,
              "reopen_replay_ledger_may_change": True,
              "unchanged_application_artifacts_scope": "all store entries except root ledger.hbl, rebuilt before schema admission"}
    try:
        instance = Instance(legacy, root / "instance")
        directory = RenewalDirectory(root / "directory", instance.root / "tls.crt", instance.root / "tls.key", instance.root / "ca.crt")
        path = instance.root / "server.json"
        settings = json.loads(path.read_text())
        settings["lifecycle_interval_seconds"] = 0
        settings["outbound_endpoints"] = [{"origin": directory.origin, "address": "127.0.0.1:" + str(directory.port),
            "server_name": "127.0.0.1", "ca_pem": (instance.root / "ca.crt").read_text(), "path_prefix": "/"}]
        private_write(path, settings)
        run_upgrade(instance, directory, candidate, legacy, result["cases"])
        result["status"] = "passed"
    except Exception as error:
        result["status"] = "failed"
        result["safe_failure_code"] = str(error) if isinstance(error, ScenarioFailure) else "unexpected_" + type(error).__name__
    finally:
        if instance is not None:
            instance.stop()
        if directory is not None:
            directory.stop()
        shutil.rmtree(root)
        after = source_identity(ROOT, candidate)
        result["binaries_unchanged"] = after["binary_sha256"] == candidate_hash and file_hash(legacy) == legacy_hash
        for field in ("source_commit", "source_tree", "source_dirty", "source_content_sha256"):
            result["harness_" + field] = before[field]
        result["harness_source_unchanged"] = before == after
        if not result["binaries_unchanged"] or file_hash(Path(__file__)) != runner_hash or before != after:
            result["status"], result["safe_failure_code"] = "failed", "source_or_binary_changed_during_execution"
        if admit_output(output) != parent:
            raise ValueError("report_parent_changed")
        private_write(output, result, replace=False)
    print(json.dumps({"status": result["status"], "checks": len(result["cases"]), "safe_failure_code": result.get("safe_failure_code")}))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
