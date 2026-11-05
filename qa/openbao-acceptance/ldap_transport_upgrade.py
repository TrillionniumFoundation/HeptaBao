#!/usr/bin/env python3
"""Real schema-24 native LDAP enrollment through schema-25 API transport.

Only pinned legacy binaries, fresh private stores and an actual local slapd are
accepted. Preparation mode observes the old binary only, never an upgrade.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from bao_http import Client, SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from identity_upgrade import validate_binary_pins
from ldap_renewal_live import RenewalDirectory, Trace as LdapTrace
from online_evidence import admit_output, source_identity
from provider_renewal_upgrade import durable_manifest
from radius_renewal_live import renewal_token_shape
from remote_jwks_live import Instance

LEGACY_SOURCE = "6ce7f3a1ddc3652f2c2236d39f0a26450f641f36"
LEGACY_SHA256 = "c48447896ace3e7d052cd2c187e6e5525008ce112a5ff64fbab9f3e36c7958ea"
LEGACY_RECEIPT = ROOT / "qa/openbao-acceptance/evidence/ldap-native-live-6ce7f3a.json"
MOUNT = "ldap-transport-upgrade"
CONFIG_PATH = "auth/" + MOUNT + "/config"
VALUE_PATH = "secret/data/ldap-transport-upgrade"
TRANSPORT_FIELDS = {"certificate", "connection_timeout", "request_timeout"}


def admit_legacy_receipt(expected, receipt):
    identity = receipt.get("source_identity", {})
    if (expected != LEGACY_SHA256 or receipt.get("status") != "passed"
            or receipt.get("source_and_binary_unchanged") is not True
            or receipt.get("cases_match") is not True
            or identity.get("source_commit") != LEGACY_SOURCE
            or identity.get("binary_sha256") != LEGACY_SHA256
            or identity.get("source_dirty") is not False):
        raise ValueError("legacy_schema24_build_receipt_mismatch")


def admit_legacy(candidate, legacy, expected, receipt):
    admit_legacy_receipt(expected, receipt)
    return validate_binary_pins(candidate, legacy, expected)


class Trace(LdapTrace):
    def check(self, name, condition, **observed):
        if (not re.fullmatch(r"[a-z0-9_.]{1,140}", name)
                or any(type(value) not in (bool, int) for value in observed.values())):
            raise ValueError("unsafe_upgrade_observation")
        case = "ldap_transport_upgrade." + name
        self.results.append({"case": case, **observed, "passed": bool(condition)})
        if not condition:
            raise ScenarioFailure(case)


def provider_idle(directory, cursor):
    with (directory.root / "slapd.log").open("rb") as stream:
        stream.seek(cursor)
        suffix = stream.read()
    return b"do_bind" not in suffix and b"do_search" not in suffix


def legacy_configuration(directory):
    # Do not import native_live.configuration: its fresh-config transport
    # fields intentionally evolve with the new binary under qualification.
    return {"url": directory.origin, "binddn": directory.admin_dn,
            "bindpass": directory.admin_password, "userdn": "ou=people,dc=example,dc=test",
            "userattr": "uid", "groupdn": "ou=groups,dc=example,dc=test", "groupattr": "cn",
            "token_ttl": 300, "token_max_ttl": 3600, "token_policies": ["upgrade-reader"]}


def enrolled_settings(instance, directory):
    settings = json.loads((instance.root / "server.json").read_text())
    settings["lifecycle_interval_seconds"] = 0
    settings["outbound_endpoints"] = [{"origin": directory.origin,
        "address": "127.0.0.1:" + str(directory.port), "server_name": "127.0.0.1",
        "ca_pem": (instance.root / "ca.crt").read_text(), "path_prefix": "/"}]
    return settings


def restart(instance, binary, settings, t, name, key):
    instance.stop()
    private_write(instance.root / "server.json", settings)
    instance.binary = binary
    instance.start()
    return t.call(name + ".unseal", "sys/unseal", {"key": key})


def renewals(t, prefix, auth, *, expected=200, provider="search", increment=300):
    for via, path, payload, actor in [
            ("self", "auth/token/renew-self", {}, auth["client_token"]),
            ("token", "auth/token/renew", {"token": auth["client_token"]}, None),
            ("accessor", "auth/token/renew-accessor", {"accessor": auth["accessor"]}, None)]:
        body = t.call(prefix + "." + via, path, dict(payload, increment=increment), token=actor,
                      expected=expected, provider=provider)
        if expected == 200:
            renewed = body.get("auth", {})
            t.check(prefix + "." + via + ".shape", renewed.get("lease_duration") == increment
                    and renewed.get("entity_id") == auth["entity_id"]
                    and renewal_token_shape(renewed, auth["client_token"], via_accessor=via == "accessor"))
        else:
            t.check(prefix + "." + via + ".no_secret", not body.get("auth") and not body.get("wrap_info"))


def prepare_legacy(instance, directory, cases):
    instance.start()
    status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
    if status != 200:
        raise ScenarioFailure("ldap_transport_upgrade.legacy.initialize")
    instance.token, key = initialized["root_token"], initialized["keys_base64"][0]
    t = Trace(Client(instance.address, str(instance.root / "ca.crt"), instance.token), directory, cases)
    t.call("legacy.unseal", "sys/unseal", {"key": key})
    rules = ('path "' + VALUE_PATH + '" { capabilities = ["read"] }\n'
             'path "auth/token/create" { capabilities = ["update", "sudo"] }')
    t.call("legacy.policy", "sys/policies/acl/upgrade-reader", {"policy": rules}, method="PUT", expected=204)
    t.call("legacy.mount", "sys/auth/" + MOUNT, {"type": "ldap"}, expected=204)
    config = legacy_configuration(directory)
    t.check("legacy.no_api_transport_fields", not TRANSPORT_FIELDS.intersection(config))
    t.call("legacy.config", CONFIG_PATH, config, expected=204)
    readback = t.call("legacy.config_read", CONFIG_PATH, method="GET").get("data", {})
    t.check("legacy.enrollment_profile", not TRANSPORT_FIELDS.intersection(readback)
            and "bindpass" not in readback and readback.get("token_policies") == ["upgrade-reader"])
    t.call("legacy.value", VALUE_PATH, {"data": {"synthetic": True}})
    original = t.login("legacy.login", MOUNT)
    t.check("legacy.direct_token", original.get("renewable") is True
            and original.get("lease_duration") == 300
            and set(original.get("token_policies", [])) == {"default", "upgrade-reader"})
    child = t.call("legacy.child", "auth/token/create", {"policies": ["upgrade-reader"], "ttl": 300},
                   token=original["client_token"]).get("auth", {})
    t.check("legacy.child_shape", isinstance(child.get("client_token"), str) and bool(child["client_token"]))
    renewals(t, "legacy.renew", original)
    t.check("legacy.complete", True)
    return t, key, config, {"direct": original, "child": child}


def wrong_ca(root):
    path = root / "unrelated-ca.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                    "-keyout", str(root / "unrelated-ca.key"), "-out", str(path),
                    "-subj", "/CN=Unrelated Synthetic LDAP CA", "-addext", "basicConstraints=critical,CA:TRUE",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    (root / "unrelated-ca.key").chmod(0o600)
    return path.read_text()


def run_upgrade(instance, directory, candidate, legacy, settings, cases):
    t, key, config, tokens = prepare_legacy(instance, directory, cases)
    direct = tokens["direct"]
    instance.stop()
    store = instance.root / "data"
    old_application = durable_manifest(store, application_only=True)
    restart(instance, candidate, settings, t, "current", key)
    t.check("current.reopen_preserves_application", durable_manifest(store, application_only=True) == old_application)
    before = durable_manifest(store)
    for label, auth in tokens.items():
        value = t.call("current." + label + ".read", VALUE_PATH, method="GET", token=auth["client_token"])
        t.check("current." + label + ".value", value.get("data", {}).get("data") == {"synthetic": True})
        t.call("current." + label + ".active", "auth/token/lookup-self", method="GET", token=auth["client_token"])
    readback = t.call("current.config", CONFIG_PATH, method="GET").get("data", {})
    t.check("current.old_config_shape", not TRANSPORT_FIELDS.intersection(readback)
            and all(readback.get(name) == value for name, value in config.items() if name != "bindpass"))
    t.check("current.pure_reads_preserve_store", durable_manifest(store) == before)
    t.call("partial.policy_update", CONFIG_PATH, {"token_policies": ["upgrade-reader"], "token_ttl": 240}, expected=204)
    data = t.call("partial.config", CONFIG_PATH, method="GET").get("data", {})
    t.check("partial.keeps_enrolled_profile", not TRANSPORT_FIELDS.intersection(data)
            and data.get("token_ttl") == 240 and data.get("token_policies") == ["upgrade-reader"])
    no_enrollment = dict(settings, outbound_endpoints=[])
    restart(instance, candidate, no_enrollment, t, "partial.no_enrollment", key)
    before, cursor = durable_manifest(store), directory.cursor()
    renewals(t, "partial.still_requires_enrollment", direct, expected=400, provider=None)
    t.check("partial.denial_without_enrollment_is_atomic", durable_manifest(store) == before
            and provider_idle(directory, cursor))
    restart(instance, candidate, settings, t, "partial.restore_enrollment", key)
    renewals(t, "partial.restored_renew", direct)
    t.check("partial.complete", True)

    ca = (instance.root / "ca.crt").read_text()
    t.call("migration.api_transport", CONFIG_PATH,
           {"certificate": ca, "connection_timeout": 2, "request_timeout": 3}, expected=204)
    data = t.call("migration.config", CONFIG_PATH, method="GET").get("data", {})
    t.check("migration.readback", data.get("certificate") == ca and data.get("connection_timeout") == 2
            and data.get("request_timeout") == 3 and data.get("token_ttl") == 240 and "bindpass" not in data)
    instance.stop()
    migrated_application = durable_manifest(store, application_only=True)
    restart(instance, candidate, no_enrollment, t, "migration.no_enrollment_restart", key)
    t.check("migration.restart_preserves_application", durable_manifest(store, application_only=True) == migrated_application)
    renewals(t, "migration.old_token_renew", direct)
    fresh = t.login("migration.fresh_login", MOUNT)
    t.check("migration.identity_preserved", fresh.get("entity_id") == direct["entity_id"])
    tokens["fresh"] = fresh
    t.check("migration.complete", True)

    t.call("trust.wrong_ca", CONFIG_PATH, {"certificate": wrong_ca(instance.root)}, expected=204)
    for via, path, payload, actor in [
            ("self", "auth/token/renew-self", {}, direct["client_token"]),
            ("token", "auth/token/renew", {"token": direct["client_token"]}, None),
            ("accessor", "auth/token/renew-accessor", {"accessor": direct["accessor"]}, None)]:
        ttl = t.ttl("trust." + via + ".before", direct["client_token"])
        before, cursor = durable_manifest(store), directory.cursor()
        denied = t.call("trust." + via + ".reject", path, dict(payload, increment=600), token=actor, expected=400)
        unchanged, idle = durable_manifest(store) == before, provider_idle(directory, cursor)
        after = t.ttl("trust." + via + ".after", direct["client_token"])
        t.check("trust." + via + ".no_extension_or_mutation", after <= ttl and unchanged and idle
                and not denied.get("auth") and not denied.get("wrap_info"))
    t.call("trust.restore_ca_without_restart", CONFIG_PATH, {"certificate": ca}, expected=204)
    renewals(t, "trust.restored", direct)
    t.check("trust.complete", True)
    directory.stop()
    cursor = directory.cursor()
    t.call("child.renew_without_directory", "auth/token/renew-self", {"increment": 300}, token=tokens["child"]["client_token"])
    t.check("child.no_provider_dependency", provider_idle(directory, cursor))
    directory.start()

    instance.stop()
    upgraded_application = durable_manifest(store, application_only=True)
    t.check("migration.state_changed", upgraded_application != old_application)
    private_write(instance.root / "server.json", settings)
    instance.binary = legacy
    instance.start()
    t.call("downgrade.unseal_rejected", "sys/unseal", {"key": key}, expected=503)
    t.call("downgrade.sealed", "sys/health", method="GET", expected=503)
    instance.stop()
    t.check("downgrade.application_unchanged", durable_manifest(store, application_only=True) == upgraded_application)
    restart(instance, candidate, no_enrollment, t, "recovery", key)
    t.check("recovery.application_unchanged", durable_manifest(store, application_only=True) == upgraded_application)
    for label, auth in tokens.items():
        value = t.call("recovery." + label + ".read", VALUE_PATH, method="GET", token=auth["client_token"])
        t.check("recovery." + label + ".value", value.get("data", {}).get("data") == {"synthetic": True})
    renewals(t, "recovery.old_token_renew", direct)
    instance.stop()
    secrets = [directory.admin_password, directory.user_password, key, instance.token,
               *(auth["client_token"] for auth in tokens.values())]
    files = [path for path in store.rglob("*") if path.is_file()] + [instance.root / "server.log", instance.root / "audit.jsonl"]
    t.check("plaintext_credentials_absent", all(secret.encode() not in path.read_bytes()
            for path in files if path.exists() for secret in secrets))
    t.check("complete", True)


MILESTONES = {"legacy.complete", "current.reopen_preserves_application", "current.pure_reads_preserve_store",
              "partial.denial_without_enrollment_is_atomic", "partial.complete", "migration.complete", "trust.complete",
              "child.no_provider_dependency", "downgrade.application_unchanged", "recovery.application_unchanged",
              "plaintext_credentials_absent", "complete"}
MILESTONES |= {prefix + "." + via + ".shape"
               for prefix in ("migration.old_token_renew", "trust.restored", "recovery.old_token_renew")
               for via in ("self", "token", "accessor")}
MILESTONES |= {"trust." + via + ".no_extension_or_mutation" for via in ("self", "token", "accessor")}


def complete_scenarios(rows):
    if not rows or any(row.get("passed") is not True for row in rows):
        return False
    names = [row.get("case") for row in rows]
    if any(not isinstance(name, str) for name in names) or len(set(names)) != len(names):
        return False
    return ({"ldap_transport_upgrade." + name for name in MILESTONES}.issubset(names)
            and names[-1] == "ldap_transport_upgrade.complete")


def main():
    parser = SafeArgumentParser(description=__doc__)
    for name in ("legacy-binary", "expected-legacy-sha256", "build-source-commit", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--binary")
    parser.add_argument("--legacy-prepare-only", action="store_true")
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.build_source_commit) is None:
        parser.error("full build source commit required")
    legacy = Path(args.legacy_binary).resolve(strict=True)
    receipt = json.loads(LEGACY_RECEIPT.read_text())
    admit_legacy_receipt(args.expected_legacy_sha256, receipt)
    if args.legacy_prepare_only:
        if args.binary is not None or args.build_source_commit != LEGACY_SOURCE:
            parser.error("legacy preparation requires only the pinned legacy build")
        candidate, candidate_hash = legacy, file_hash(legacy)
        if candidate_hash != LEGACY_SHA256:
            raise ValueError("legacy_schema24_binary_mismatch")
        legacy_hash = candidate_hash
    else:
        if not args.binary:
            parser.error("candidate binary required for upgrade")
        candidate = Path(args.binary).resolve(strict=True)
        candidate_hash, legacy_hash = admit_legacy(candidate, legacy, args.expected_legacy_sha256, receipt)
    output = Path(args.output).absolute()
    parent = admit_output(output)
    before, runner_hash = source_identity(ROOT, candidate), file_hash(Path(__file__))
    root = Path(tempfile.mkdtemp(prefix="heptabao-ldap-transport-upgrade-"))
    root.chmod(0o700)
    instance = directory = None
    result = {"schema": "heptabao.ldap-transport-upgrade.v1", "from_schema": 24, "minimum_to_schema": 25,
              "legacy_prepare_only": args.legacy_prepare_only, "candidate_observed": not args.legacy_prepare_only,
              "synthetic_only": True, "actual_openldap": True, "legacy_source_commit": LEGACY_SOURCE,
              "legacy_binary_sha256": legacy_hash, "legacy_receipt_sha256": file_hash(LEGACY_RECEIPT),
              "observed_binary_sha256": candidate_hash, "build_source_commit": args.build_source_commit,
              "runner_sha256": runner_hash,
              "build_source_binding_basis": "caller-supplied commit and observed binary hash; not independent attestation",
              "full_openbao_compatibility": False, "full_migration_qualification": False,
              "rolling_upgrade_qualification": False, "independent_qualification": False, "production_authority": False,
              "reopen_replay_ledger_may_change": True,
              "unchanged_application_artifacts_scope": "all store entries except root ledger.hbl, rebuilt before schema admission",
              "started_at_unix": time.time(), "cases": []}
    if not args.legacy_prepare_only:
        result["candidate_binary_sha256"] = candidate_hash
    try:
        instance = Instance(legacy, root / "instance")
        directory = RenewalDirectory(root / "directory", instance.root / "tls.crt", instance.root / "tls.key", instance.root / "ca.crt")
        settings = enrolled_settings(instance, directory)
        private_write(instance.root / "server.json", settings)
        if args.legacy_prepare_only:
            prepare_legacy(instance, directory, result["cases"])
            result["status"] = "passed_legacy_prepare"
        else:
            run_upgrade(instance, directory, candidate, legacy, settings, result["cases"])
            result["status"] = "passed" if complete_scenarios(result["cases"]) else "failed"
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
    return 0 if result["status"] in ("passed", "passed_legacy_prepare") else 1


if __name__ == "__main__":
    raise SystemExit(main())
