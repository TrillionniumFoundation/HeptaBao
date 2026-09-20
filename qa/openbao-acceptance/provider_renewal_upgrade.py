#!/usr/bin/env python3
"""Exercise pinned schema-15 LDAP state through schema-17 renewal upgrade.

Only fresh private stores and actual local OpenLDAP are used. The fixed legacy
binary is bound to the committed f31b98e receipt; no existing-store input exists.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import time

from bao_http import Client, SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from identity_upgrade import validate_binary_pins
from ldap_renewal_live import RenewalDirectory, configuration, user_configuration, Trace, Instance
from ldap_openldap_live import private
from online_evidence import admit_output, source_identity
from radius_renewal_live import renewal_token_shape

LEGACY_SOURCE = "f31b98eadf145332ab4e472c5a5973d3e0804017"
LEGACY_SHA256 = "bb36e16c3d8340ffb70e13ba78f36766b80ee7b99b8deb293aba3f6d366daaa7"
LEGACY_RECEIPT = ROOT / "qa/openbao-acceptance/evidence/kv-enumeration-f31b98e.json"
CANDIDATE_SOURCE = "8f7c90782f659dfc32d7ef9acd374d0a988b1a57"
CANDIDATE_SHA256 = "5ae9a0d270be024c31215f478fb0771cc77f407e7895d0153337a390d77a89a7"
CANDIDATE_RECEIPT = ROOT / "qa/openbao-acceptance/evidence/ldap-renewal-8f7c907.json"


def admit_legacy(candidate, legacy, expected, receipt):
    if expected != LEGACY_SHA256:
        raise ValueError("legacy_schema15_pin_required")
    required = {"source_commit": LEGACY_SOURCE, "candidate_binary_sha256": LEGACY_SHA256,
                "source_worktree_dirty": False, "candidate_binary_unchanged": True, "status": "passed"}
    if any(receipt.get(key) != value for key, value in required.items()):
        raise ValueError("legacy_build_receipt_mismatch")
    return validate_binary_pins(candidate, legacy, expected)


def admit_candidate(candidate_hash, receipt):
    required = {"source_commit": CANDIDATE_SOURCE, "candidate_binary_sha256": CANDIDATE_SHA256,
                "source_worktree_dirty": False, "candidate_binary_unchanged": True, "status": "passed"}
    if candidate_hash != CANDIDATE_SHA256 or any(receipt.get(key) != value for key, value in required.items()):
        raise ValueError("candidate_schema17_build_receipt_mismatch")


def durable_manifest(root, *, application_only=False):
    """Cover all entries; optionally omit the replay ledger re-sealed on reopen.

    The append journal and application snapshot are always included. Even an old
    binary rebuilds ledger.hbl before checking the application's schema version.
    """
    if not root.is_dir() or root.is_symlink():
        raise ValueError("store_manifest_root_invalid")
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        if application_only and path == root / "ledger.hbl":
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("store_manifest_nonregular_entry")
            continue
        name = path.relative_to(root).as_posix().encode()
        digest.update(len(name).to_bytes(8, "big") + name)
        digest.update(stat.S_IMODE(info.st_mode).to_bytes(4, "big"))
        if stat.S_ISDIR(info.st_mode):
            digest.update(b"directory")
        elif stat.S_ISREG(info.st_mode):
            digest.update(b"file" + bytes.fromhex(file_hash(path)))
        else:
            raise ValueError("store_manifest_nonregular_entry")
    return digest.hexdigest()


def run_upgrade(instance, directory, candidate, legacy, checks):
    instance.start()
    status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
    if status != 200:
        raise ScenarioFailure("provider_upgrade.legacy_init")
    instance.token, key = initialized["root_token"], initialized["keys_base64"][0]
    client = Client(instance.address, str(instance.root / "ca.crt"), instance.token)
    t = Trace(client, directory, checks)
    t.check("upgrade.legacy_init", True)
    t.call("upgrade.legacy_unseal", "sys/unseal", {"key": key})
    t.mount("ldap-upgrade", configuration("candidate", directory, (instance.root / "ca.crt").read_text()),
            lambda policies: dict(user_configuration("candidate", policies), token_ttl=120))
    rules = ('path "secret/data/provider-upgrade" { capabilities = ["read"] }\n'
             'path "auth/token/create" { capabilities = ["update", "sudo"] }\n'
             'path "auth/token/create-orphan" { capabilities = ["update", "sudo"] }')
    t.call("upgrade.legacy_policy", "sys/policies/acl/upgrade-reader", {"policy": rules},
           method="PUT", expected=204)
    t.call("upgrade.legacy_mapping", "auth/ldap-upgrade/users/alice",
           dict(user_configuration("candidate", ["default", "upgrade-reader"]), token_ttl=120),
           method="PUT", expected=204)
    t.call("upgrade.legacy_value", "secret/data/provider-upgrade", {"data": {"synthetic": True}})
    direct = t.login("upgrade.legacy_direct", "ldap-upgrade")
    direct_token = direct["client_token"]
    tokens = {"direct": direct}
    for name, path in [("child", "auth/token/create"), ("orphan", "auth/token/create-orphan")]:
        body = t.call("upgrade.legacy_" + name, path,
                      {"policies": ["default", "upgrade-reader"], "ttl": "60s",
                       "display_name": "ldap-alice"}, token=direct_token)
        auth = body.get("auth", {})
        t.check("upgrade.legacy_" + name + ".shape", all(isinstance(auth.get(field), str) and auth[field]
                  for field in ("client_token", "accessor")))
        tokens[name] = auth
    for name, auth in tokens.items():
        t.call("upgrade.legacy_" + name + ".read", "secret/data/provider-upgrade",
               method="GET", token=auth["client_token"])

    instance.stop()
    store = instance.root / "data"
    old_application = durable_manifest(store, application_only=True)
    instance.binary = candidate
    instance.start()
    t.call("upgrade.current_unseal", "sys/unseal", {"key": key})
    t.check("upgrade.reopen_preserves_legacy_application_artifacts", durable_manifest(store, application_only=True) == old_application)
    old_store = durable_manifest(store)
    for name, auth in tokens.items():
        body = t.call("upgrade.current_" + name + ".read", "secret/data/provider-upgrade",
                      method="GET", token=auth["client_token"])
        t.check("upgrade.current_" + name + ".value", body.get("data", {}).get("data") == {"synthetic": True})
    t.check("upgrade.pure_reads_preserve_entire_legacy_store", durable_manifest(store) == old_store)
    for name in ("direct", "orphan"):
        auth = tokens[name]
        before = t.ttl("upgrade." + name + ".before", auth["client_token"])
        for route, payload, caller in [("renew-self", {}, auth["client_token"]),
                                       ("renew", {"token": auth["client_token"]}, None),
                                       ("renew-accessor", {"accessor": auth["accessor"]}, None)]:
            cursor = directory.cursor()
            t.call("upgrade." + name + "." + route + ".ambiguous_denied", "auth/token/" + route,
                   dict(payload, increment=300), token=caller, expected=400)
            t.check("upgrade." + name + "." + route + ".no_provider", not directory.observed(cursor, search=False))
        t.check("upgrade." + name + ".no_extension", t.ttl("upgrade." + name + ".after", auth["client_token"]) <= before)
    t.check("upgrade.ambiguity_rejection_preserves_legacy_store", durable_manifest(store) == old_store)

    child = tokens["child"]["client_token"]
    cursor = directory.cursor()
    body = t.call("upgrade.legacy_child_renews", "auth/token/renew-self", {"increment": 90}, token=child)
    t.check("upgrade.legacy_child_echo", renewal_token_shape(body.get("auth"), child, via_accessor=False))
    t.check("upgrade.legacy_child_no_provider", not directory.observed(cursor, search=False))
    fresh = t.login("upgrade.new_direct_login", "ldap-upgrade")
    fresh_token = fresh["client_token"]
    t.call("upgrade.new_direct_renews", "auth/token/renew-self", {"increment": 180}, token=fresh_token, provider="search")
    directory.password("synthetic-upgrade-password-replacement")
    before = t.ttl("upgrade.new_direct.before_reject", fresh_token)
    t.call("upgrade.new_direct_provider_rejects", "auth/token/renew-self", {"increment": 300},
           token=fresh_token, expected=400, provider="bind")
    t.check("upgrade.new_direct.no_extension", t.ttl("upgrade.new_direct.after_reject", fresh_token) <= before)
    directory.password(directory.user_password)
    instance.stop()
    upgraded_store = durable_manifest(store)
    upgraded_application = durable_manifest(store, application_only=True)
    t.check("upgrade.new_behavior_durably_published", upgraded_store != old_store)
    instance.binary = legacy
    instance.start()
    t.call("upgrade.legacy_rejects_new_state", "sys/unseal", {"key": key}, expected=503)
    t.call("upgrade.legacy_remains_sealed", "sys/health", method="GET", expected=503)
    for name, token in [("old", direct_token), ("fresh", fresh_token)]:
        t.call("upgrade.downgrade_" + name + ".cannot_read", "secret/data/provider-upgrade", method="GET", token=token, expected=503)
    instance.stop()
    t.check("upgrade.failed_downgrade_preserves_application_artifacts", durable_manifest(store, application_only=True) == upgraded_application)
    instance.binary = candidate
    instance.start()
    t.call("upgrade.current_recovers", "sys/unseal", {"key": key})
    for name, auth in tokens.items():
        t.call("upgrade.recovered_" + name + ".read", "secret/data/provider-upgrade", method="GET", token=auth["client_token"])
    directory.password("synthetic-upgrade-password-replacement")
    t.call("upgrade.recovered_provider_rejects", "auth/token/renew-self", {"increment": 300}, token=fresh_token, expected=400, provider="bind")
    directory.password(directory.user_password)
    t.call("upgrade.recovered_provider_accepts", "auth/token/renew-self", {"increment": 180}, token=fresh_token, provider="search")
    t.call("upgrade.recovered_legacy_still_ambiguous", "auth/token/renew-self", {"increment": 300}, token=direct_token, expected=400)
    return [directory.user_password.encode(), directory.admin_password.encode(),
            *(auth["client_token"].encode() for auth in tokens.values()), fresh_token.encode()]


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--legacy-binary", required=True)
    parser.add_argument("--expected-legacy-sha256", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    candidate, legacy = Path(args.binary).resolve(strict=True), Path(args.legacy_binary).resolve(strict=True)
    try:
        candidate_hash, legacy_hash = admit_legacy(candidate, legacy, args.expected_legacy_sha256,
                                                   json.loads(LEGACY_RECEIPT.read_text()))
        admit_candidate(candidate_hash, json.loads(CANDIDATE_RECEIPT.read_text()))
    except (ValueError, OSError):
        parser.error("fixed schema15/schema17 binaries and verified build receipts required")
    output = Path(args.output).absolute()
    output_parent = admit_output(output)
    before = source_identity(ROOT, candidate)
    root = Path(tempfile.mkdtemp(prefix="heptabao-provider-upgrade-"))
    root.chmod(0o700)
    instance = directory = None
    result = {"schema": "heptabao.provider-renewal-upgrade.v1", "synthetic_only": True,
              "from_schema": 15, "to_schema": 17, "legacy_source_commit": LEGACY_SOURCE,
              "legacy_binary_sha256": legacy_hash, "legacy_receipt_sha256": file_hash(LEGACY_RECEIPT),
              "candidate_binary_sha256": candidate_hash, "build_source_commit": CANDIDATE_SOURCE,
              "candidate_receipt_sha256": file_hash(CANDIDATE_RECEIPT),
              "build_source_binding_basis": "caller-supplied build commit and exact binary hash matched clean execution receipt; not binary attestation",
              "runner_sha256": file_hash(Path(__file__)), "cases": [], "started_at_unix": time.time(),
              "independent_qualification": False, "full_migration_qualification": False,
              "rolling_upgrade_qualification": False, "production_authority": False}
    result["reopen_replay_ledger_may_change"] = True
    result["unchanged_application_artifacts_scope"] = "all store files and directories except ledger.hbl; schema15 and schema17 reopen rebuild the encrypted replay ledger before application-schema validation"
    try:
        instance = Instance(legacy, root / "server")
        directory = RenewalDirectory(root / "ldap", instance.root / "tls.crt", instance.root / "tls.key", instance.root / "ca.crt")
        config_path = instance.root / "server.json"
        config = json.loads(config_path.read_text())
        config["lifecycle_interval_seconds"] = 0
        config["outbound_endpoints"] = [{"origin": directory.origin, "address": "127.0.0.1:" + str(directory.port),
            "server_name": "127.0.0.1", "ca_pem": (instance.root / "ca.crt").read_text(), "path_prefix": "/"}]
        private(config_path, json.dumps(config))
        secrets = run_upgrade(instance, directory, candidate, legacy, result["cases"])
        files = [*(instance.root / "data").rglob("*"), instance.root / "audit.jsonl", instance.root / "server.log"]
        secret_free = all(not any(secret in path.read_bytes() for secret in secrets) for path in files if path.is_file())
        result["cases"].append({"case": "ldap_renewal.upgrade.secrets_absent_from_storage_and_server_logs", "passed": secret_free})
        if not secret_free:
            raise ScenarioFailure("provider_upgrade.secret_in_server_storage_or_log")
        result["status"] = "passed"
    except ScenarioFailure as error:
        result["status"], result["failure"] = "failed", str(error)
    except Exception as error:
        result["status"], result["failure"] = "failed", "unexpected_" + type(error).__name__
    finally:
        if instance is not None:
            instance.stop()
        if directory is not None:
            directory.stop()
        shutil.rmtree(root)
        after = source_identity(ROOT, candidate)
        for name in ("source_commit", "source_tree", "source_dirty", "source_content_sha256"):
            result["harness_" + name] = before[name]
        result["harness_source_unchanged"] = before == after
        result["binaries_unchanged"] = file_hash(candidate) == candidate_hash and file_hash(legacy) == legacy_hash
        if not result["binaries_unchanged"] or result["runner_sha256"] != file_hash(Path(__file__)):
            result["status"], result["failure"] = "failed", "source_or_binary_changed_during_execution"
        result["finished_at_unix"] = time.time()
        if admit_output(output) != output_parent:
            raise ValueError("output_parent_changed")
        private_write(output, result)
    print(json.dumps({"status": result["status"], "checks": len(result["cases"]), "failure": result.get("failure")}))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
