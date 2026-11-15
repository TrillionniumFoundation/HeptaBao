#!/usr/bin/env python3
"""Exercise a pinned schema-20 OIDC store, pending callback and schema-21 renewal.

The historical build pin is filled only from the completed clean schema-20
receipt. Old state and code sessions are created through the actual binary;
no pre-existing stores or fabricated encrypted sessions are accepted.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import tempfile
import time
import urllib.parse

from bao_http import Client, SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from identity_upgrade import validate_binary_pins
from oidc_renewal_live import OfficialIssuer, Trace as RenewalTrace, configuration, role, free_port
from official_openbao_launcher import BINARY_SHA256, start_oracle, stop_oracle
from online_evidence import admit_output, source_identity
from provider_renewal_upgrade import durable_manifest
from radius_renewal_live import renewal_token_shape
from remote_jwks_live import Instance

# Bound to the observed schema-20 build and its committed clean receipt.
# A caller-supplied digest alone must never create historical source provenance.
LEGACY_SOURCE = "1dafa68ee4580d5ec894c92f3333128a4aa3a2ef"
LEGACY_SHA256 = "5393685158bfc9ae95198215eb9b232cefbcecbbae19d908eb4e5cae78ee7df2"
LEGACY_RECEIPT = ROOT / "qa/openbao-acceptance/evidence/kubernetes-renewal-1dafa68.json"


def admit_legacy(candidate, legacy, expected, receipt):
    if re.fullmatch(r"[0-9a-f]{40}", LEGACY_SOURCE) is None or re.fullmatch(r"[0-9a-f]{64}", LEGACY_SHA256) is None:
        raise ValueError("legacy_schema20_pin_not_configured")
    required = {"build_source_commit": LEGACY_SOURCE,
                "harness_source_commit": LEGACY_SOURCE, "harness_source_dirty": False,
                "harness_source_unchanged": True, "candidate_binary_unchanged": True,
                "candidate_binary_sha256": LEGACY_SHA256, "status": "passed"}
    if expected != LEGACY_SHA256 or any(receipt.get(key) != value for key, value in required.items()):
        raise ValueError("legacy_schema20_build_receipt_mismatch")
    return validate_binary_pins(candidate, legacy, expected)


class Trace(RenewalTrace):
    def check(self, name, condition, **observed):
        case = "oidc_native_upgrade." + name
        self.rows.append({"case": case, **observed, "passed": bool(condition)})
        if not condition:
            raise ScenarioFailure(case)


def prepare_legacy(instance, issuer, cases):
    instance.start()
    status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
    if status != 200:
        raise ScenarioFailure("oidc_native_upgrade.initialize")
    instance.token, key = initialized["root_token"], initialized["keys_base64"][0]
    t = Trace(Client(instance.address, str(instance.root / "ca.crt"), instance.token), issuer, cases)
    t.call("legacy.unseal", "sys/unseal", {"key": key})
    # Keep the original nonrenewable token alive across stop/reopen. Short ID
    # tokens are covered by the separate native renewal differential profile.
    issuer.setup(t, id_token_ttl=300)
    mount = "browser/upgrade"
    role_path = "auth/" + mount + "/role/test"
    t.call("legacy.mount", "sys/auth/" + mount, {"type": "oidc"}, expected=204)
    legacy_config = configuration("candidate", issuer)
    # Schema20 has only the original process-enrolled transport. Do not send
    # a field introduced by the current shared fixture's schema28 adapter.
    legacy_config.pop("oidc_discovery_ca_pem", None)
    t.call("legacy.config", "auth/" + mount + "/config", legacy_config, expected=204)
    old_role = role(issuer.redirect, token_ttl=120, token_policies=["default"])
    old_role.pop("token_max_ttl")
    t.call("legacy.role", role_path, old_role, expected=204)
    t.call("legacy.write", "secret/data/oidc-upgrade", {"data": {"synthetic": True}})
    completed = issuer.begin(t, "legacy.completed", mount, "test")
    original = issuer.finish(t, "candidate", "legacy.completed", mount, completed)
    t.check("legacy.nonrenewable", original.get("renewable") is False and original.get("lease_duration") == 120)
    t.call("legacy.renew_denied", "auth/token/renew-self", {}, bearer=original["client_token"], expected=400)
    pending = issuer.begin(t, "legacy.pending", mount, "test")
    t.check("legacy.distinct_pending_session", pending["state"] != completed["state"]
            and pending["code"] != completed["code"] and pending["client_nonce"] != completed["client_nonce"])
    # The caller stops this exact consumer next. Both session and PKCE verifier
    # are persisted by the old binary; all callback credentials stay in memory.
    return {"trace": t, "key": key, "original": original, "completed": completed,
            "pending": pending, "mount": mount, "role_path": role_path}


def reject_old(t, original, store, prefix):
    before = durable_manifest(store)
    for label, path, payload, bearer in [
            ("self", "auth/token/renew-self", {}, original["client_token"]),
            ("token", "auth/token/renew", {"token": original["client_token"]}, None),
            ("accessor", "auth/token/renew-accessor", {"accessor": original["accessor"]}, None)]:
        rejected = t.call(prefix + "." + label, path, payload, bearer=bearer, expected=400)
        t.check(prefix + "." + label + ".no_token", not rejected.get("auth") and not rejected.get("wrap_info"))
    t.check(prefix + ".entire_store_unchanged", durable_manifest(store) == before)


def run_upgrade(instance, issuer, candidate, legacy, cases):
    prepared = prepare_legacy(instance, issuer, cases)
    t, key, original = prepared["trace"], prepared["key"], prepared["original"]
    store = instance.root / "data"
    instance.stop()
    old_application = durable_manifest(store, application_only=True)
    instance.binary = candidate
    instance.start()
    t.call("current.unseal", "sys/unseal", {"key": key})
    t.check("current.reopen_preserves_application", durable_manifest(store, application_only=True) == old_application)
    before = durable_manifest(store)
    body = t.call("current.read", "secret/data/oidc-upgrade", method="GET")
    t.check("current.value_preserved", body.get("data", {}).get("data") == {"synthetic": True})
    old = t.call("current.old_token_active", "auth/token/lookup-self", method="GET", bearer=original["client_token"])
    t.check("current.old_still_nonrenewable", old.get("data", {}).get("renewable") is False)
    values = t.call("current.old_role_readback", prepared["role_path"], method="GET").get("data", {})
    t.check("current.compatible_role_limits", values.get("token_ttl") == 120
            and values.get("token_max_ttl") == 0 and values.get("token_period") == 0
            and values.get("token_explicit_max_ttl") == 0)
    t.check("current.reads_preserve_entire_store", durable_manifest(store) == before)
    reject_old(t, original, store, "current.old_renew_denied")
    pending_token = issuer.finish(t, "candidate", "current.old_pending_completes", prepared["mount"], prepared["pending"])
    t.check("current.old_pending_issues_native", pending_token.get("renewable") is True
            and pending_token.get("lease_duration") == 120 and pending_token.get("entity_id") == original["entity_id"]
            and pending_token["client_token"] != original["client_token"])
    t.call("current.old_pending_one_use", "auth/" + prepared["mount"] + "/oidc/callback",
           prepared["pending"], bearer="", expected=403)
    t.call("current.old_completed_stays_consumed", "auth/" + prepared["mount"] + "/oidc/callback",
           prepared["completed"], bearer="", expected=403)
    t.call("current.role_explicitly_updated", prepared["role_path"],
           role(issuer.redirect, token_ttl=120, token_max_ttl=600, token_period=0,
                token_explicit_max_ttl=0, token_policies=["default"]), expected=204)
    reject_old(t, original, store, "current.role_update_does_not_upgrade_token")
    fresh_callback = issuer.begin(t, "current.fresh", prepared["mount"], "test")
    fresh = issuer.finish(t, "candidate", "current.fresh", prepared["mount"], fresh_callback)
    t.check("current.fresh_native", fresh.get("renewable") is True and fresh.get("lease_duration") == 120
            and fresh.get("entity_id") == original["entity_id"] and fresh["client_token"] != pending_token["client_token"])
    stop_oracle(issuer.server)
    t.check("current.issuer_stopped", issuer.stopped())
    for label, auth in [("pending", pending_token), ("fresh", fresh)]:
        renewed = t.call("current." + label + ".renews", "auth/token/renew-self", {"increment": 300},
                         bearer=auth["client_token"], offline=True)
        t.check("current." + label + ".lease_and_echo", renewed.get("auth", {}).get("lease_duration") == 300
                and renewal_token_shape(renewed.get("auth"), auth["client_token"], via_accessor=False))
    instance.stop()
    upgraded_application = durable_manifest(store, application_only=True)
    t.check("current.native_mutation_persisted", upgraded_application != old_application)
    instance.binary = legacy
    instance.start()
    t.call("downgrade.unseal_rejected", "sys/unseal", {"key": key}, expected=503)
    t.call("downgrade.remains_sealed", "sys/health", method="GET", expected=503)
    t.call("downgrade.read_denied", "secret/data/oidc-upgrade", method="GET", expected=503)
    instance.stop()
    t.check("downgrade.application_unchanged", durable_manifest(store, application_only=True) == upgraded_application)
    instance.binary = candidate
    instance.start()
    t.call("recovery.unseal", "sys/unseal", {"key": key})
    t.check("recovery.application_unchanged", durable_manifest(store, application_only=True) == upgraded_application)
    for label, auth in [("old", original), ("pending", pending_token), ("fresh", fresh)]:
        t.call("recovery." + label + ".active", "auth/token/lookup-self", method="GET", bearer=auth["client_token"], offline=True)
    reject_old(t, original, store, "recovery.old_still_nonrenewable")
    for label, auth in [("pending", pending_token), ("fresh", fresh)]:
        body = t.call("recovery." + label + ".renews", "auth/token/renew-self", {"increment": 300},
                      bearer=auth["client_token"], offline=True)
        t.check("recovery." + label + ".native_lease", body.get("auth", {}).get("lease_duration") == 300)
    t.call("recovery.old_pending_stays_consumed", "auth/" + prepared["mount"] + "/oidc/callback",
           prepared["pending"], bearer="", expected=403, offline=True)
    instance.stop()
    sensitive = [key, instance.token, issuer.client_secret, issuer.enduser,
                 original["client_token"], pending_token["client_token"], fresh["client_token"],
                 *prepared["completed"].values(), *prepared["pending"].values(), *fresh_callback.values()]
    files = [p for p in store.rglob("*") if p.is_file()] + [instance.root / "server.log", instance.root / "audit.jsonl"]
    t.check("plaintext_credentials_absent", all(secret.encode() not in path.read_bytes()
                                               for path in files if path.exists() for secret in sensitive))


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--legacy-binary", required=True)
    parser.add_argument("--expected-legacy-sha256", required=True)
    parser.add_argument("--build-source-commit", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.build_source_commit):
        parser.error("full build source commit required")
    candidate, legacy = Path(args.binary).resolve(strict=True), Path(args.legacy_binary).resolve(strict=True)
    candidate_hash, legacy_hash = admit_legacy(candidate, legacy, args.expected_legacy_sha256,
                                              json.loads(LEGACY_RECEIPT.read_text()))
    output = Path(args.output).absolute()
    parent = admit_output(output)
    before = source_identity(ROOT, candidate)
    runner_hash = file_hash(Path(__file__))
    root = Path(tempfile.mkdtemp(prefix="heptabao-oidc-native-upgrade-"))
    root.chmod(0o700)
    instance = issuer = None
    result = {"schema": "heptabao.oidc-native-upgrade.v1", "from_schema": 20, "minimum_to_schema": 21,
              "synthetic_only": True, "legacy_source_commit": LEGACY_SOURCE,
              "legacy_binary_sha256": legacy_hash, "legacy_receipt_sha256": file_hash(LEGACY_RECEIPT),
              "candidate_binary_sha256": candidate_hash, "build_source_commit": args.build_source_commit,
              "build_source_binding_basis": "caller-supplied build commit and observed binary hash; not independent binary attestation",
              "runner_sha256": runner_hash, "cases": [], "started_at_unix": time.time(),
              "actual_official_oidc_issuer": True, "browser_ui_automation": False,
              "official_issuer_binary_sha256": BINARY_SHA256,
              "independent_qualification": False, "full_migration_qualification": False,
              "rolling_upgrade_qualification": False, "production_authority": False,
              "reopen_replay_ledger_may_change": True,
              "unchanged_application_artifacts_scope": "all store entries except root ledger.hbl, rebuilt before schema validation on reopen"}
    try:
        instance = Instance(legacy, root / "instance")
        config_path = instance.root / "server.json"
        config = json.loads(config_path.read_text())
        config["lifecycle_interval_seconds"] = 0
        issuer = OfficialIssuer(start_oracle(free_port()))
        config["outbound_endpoints"] = [{"origin": issuer.server["address"],
            "address": "127.0.0.1:" + str(urllib.parse.urlsplit(issuer.server["address"]).port),
            "server_name": "127.0.0.1", "ca_pem": Path(issuer.server["ca_file"]).read_text()}]
        private_write(config_path, config)
        run_upgrade(instance, issuer, candidate, legacy, result["cases"])
        result["status"] = "passed"
    except Exception as error:
        result["status"] = "failed"
        result["safe_failure_code"] = str(error) if isinstance(error, ScenarioFailure) else type(error).__name__
    finally:
        if instance is not None:
            instance.stop()
        if issuer is not None:
            stop_oracle(issuer.server)
            shutil.rmtree(issuer.server["root"])
        shutil.rmtree(root)
        after = source_identity(ROOT, candidate)
        result["binaries_unchanged"] = (after["binary_sha256"] == candidate_hash and file_hash(legacy) == legacy_hash)
        for field in ("source_commit", "source_tree", "source_dirty", "source_content_sha256"):
            result["harness_" + field] = before[field]
        result["harness_source_unchanged"] = before == after
        if not result["binaries_unchanged"] or file_hash(Path(__file__)) != runner_hash:
            result["status"], result["safe_failure_code"] = "failed", "binary_or_runner_changed_during_execution"
        result["finished_at_unix"] = time.time()
        if admit_output(output) != parent:
            raise ValueError("report_parent_changed")
        private_write(output, result, replace=False)
    print(json.dumps({"status": result["status"], "checks": len(result["cases"]),
                      "safe_failure_code": result.get("safe_failure_code")}))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
