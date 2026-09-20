#!/usr/bin/env python3
"""Exercise the pinned schema-18 JWT store through native login (schema 19+).

This creates a synthetic store, preserves explicit legacy trust extensions,
retires ordinary JWT replay restrictions, and verifies rejected downgrade.
"""
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
from jwt_login_claims_live import signed_assertion, distinct_service_tokens
from online_evidence import admit_output, source_identity
from provider_renewal_upgrade import durable_manifest
from remote_jwks_live import Instance, signing_key

LEGACY_SOURCE = "c749caf65990fb66ebd0e3c7167f258e5547d8da"
LEGACY_SHA256 = "45ab0f3bcffed777a1d62c98d94c141a46543ec0043334c649fe18da317ff893"
LEGACY_RECEIPT = ROOT / "qa/openbao-acceptance/evidence/jwt-renewal-c749caf.json"


def admit_legacy(candidate, legacy, expected, receipt):
    required = {"build_source_commit": LEGACY_SOURCE,
                "harness_source_commit": LEGACY_SOURCE, "harness_source_dirty": False,
                "harness_source_unchanged": True, "candidate_binary_unchanged": True,
                "candidate_binary_sha256": LEGACY_SHA256, "status": "passed"}
    if expected != LEGACY_SHA256 or any(receipt.get(key) != value for key, value in required.items()):
        raise ValueError("legacy_schema18_build_receipt_mismatch")
    return validate_binary_pins(candidate, legacy, expected)


class Trace:
    def __init__(self, client, cases):
        self.client, self.cases = client, cases

    def check(self, name, condition, **observed):
        name = "jwt_native_upgrade." + name
        self.cases.append({"case": name, **observed, "passed": bool(condition)})
        if not condition:
            raise ScenarioFailure(name)

    def call(self, name, path, body=None, *, method="POST", token=None, expected=200):
        response = self.client.request(method, "/v1/" + path, body, token=token)
        self.check(name, response.status == expected, status=response.status)
        return response.body


def run_upgrade(instance, candidate, legacy, cases):
    instance.start()
    status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
    if status != 200:
        raise ScenarioFailure("jwt_native_upgrade.initialize")
    instance.token, key = initialized["root_token"], initialized["keys_base64"][0]
    t = Trace(Client(instance.address, str(instance.root / "ca.crt"), instance.token), cases)
    t.call("legacy.unseal", "sys/unseal", {"key": key})
    t.call("legacy.mount", "sys/auth/jwt-upgrade", {"type": "jwt"}, expected=204)
    private, jwk = signing_key("ES256", "upgrade-key")
    issuer = "https://synthetic-issuer.invalid"
    config = {"issuer": issuer, "audiences": ["heptabao-test"], "jwks": {"keys": [jwk]}}
    config_path, role_path, login_path = ("auth/jwt-upgrade/" + part for part in ("config", "role/test", "login"))
    # Schema 18 stores these defaults as concrete constraints. The upgraded
    # reader must retain those constraints until the config is explicitly changed.
    t.call("legacy.explicit_extensions", config_path,
           dict(config, clock_skew_seconds=0, maximum_token_lifetime_seconds=3600), expected=204)
    t.call("legacy.role", role_path, {"role_type": "jwt", "user_claim": "sub",
           "bound_audiences": ["heptabao-test"], "token_policies": ["default"],
           "token_ttl": 60, "token_max_ttl": 600}, expected=204)
    t.call("legacy.write", "secret/data/jwt-upgrade", {"data": {"synthetic": True}})
    signed = signed_assertion(private, jwk, issuer, case="upgrade")
    original = t.call("legacy.login", login_path, {"role": "test", "jwt": signed}, token="").get("auth", {})
    t.check("legacy.token_shape", all(isinstance(original.get(k), str) and original[k]
                                     for k in ("client_token", "accessor", "entity_id")))
    rejected = t.call("legacy.replay_denied", login_path, {"role": "test", "jwt": signed}, token="", expected=403)
    t.check("legacy.replay_has_no_token", not rejected.get("auth"))
    instance.stop()
    store = instance.root / "data"
    old_application = durable_manifest(store, application_only=True)
    instance.binary = candidate
    instance.start()
    t.call("current.unseal", "sys/unseal", {"key": key})
    t.check("current.reopen_preserves_application", durable_manifest(store, application_only=True) == old_application)
    before = durable_manifest(store)
    value = t.call("current.read", "secret/data/jwt-upgrade", method="GET")
    t.check("current.value_preserved", value.get("data", {}).get("data") == {"synthetic": True})
    t.call("current.old_token_active", "auth/token/lookup-self", method="GET", token=original["client_token"])
    configured = t.call("current.legacy_config", config_path, method="GET").get("data", {})
    t.check("current.extensions_preserved", configured.get("clock_skew_seconds") == 0
            and configured.get("maximum_token_lifetime_seconds") == 3600)
    t.check("current.reads_preserve_entire_store", durable_manifest(store) == before)
    no_iat = signed_assertion(private, jwk, issuer, omit=("iat",), case="missing-iat")
    long_lived = signed_assertion(private, jwk, issuer, exp=int(time.time()) + 7200, case="long")
    future_issued_at = int(time.time()) + 30
    future_iat = signed_assertion(private, jwk, issuer, iat=future_issued_at, case="future-iat")
    t.check("current.signed_iat_is_still_future", int(time.time()) < future_issued_at)
    for label, assertion in [("missing_signed_iat", no_iat), ("explicit_maximum", long_lived),
                             ("zero_clock_grace", future_iat)]:
        denied = t.call("current.extension_" + label, login_path, {"role": "test", "jwt": assertion},
                        token="", expected=400)
        t.check("current.extension_" + label + ".no_token", not denied.get("auth"))
    t.check("current.failed_logins_preserve_store", durable_manifest(store) == before)
    repeated = t.call("current.legacy_assertion_reusable", login_path,
                      {"role": "test", "jwt": signed}, token="").get("auth", {})
    t.check("current.distinct_token_same_entity", distinct_service_tokens(original, repeated))
    renewed = t.call("current.old_token_renews", "auth/token/renew-self", {"increment": 120},
                     token=original["client_token"])
    t.check("current.old_token_lease", renewed.get("auth", {}).get("lease_duration") == 120)
    t.call("current.native_config", config_path, config, expected=204)
    native_tokens = []
    for label, assertion in [("missing_iat", no_iat), ("long_lived", long_lived),
                             ("default_clock_grace", future_iat)]:
        native = t.call("current.native_" + label, login_path,
                        {"role": "test", "jwt": assertion}, token="").get("auth", {})
        t.check("current.native_" + label + ".same_entity", distinct_service_tokens(original, native))
        native_tokens.append(native["client_token"])
    instance.stop()
    upgraded_application = durable_manifest(store, application_only=True)
    t.check("current.native_mutation_persisted", upgraded_application != old_application)
    instance.binary = legacy
    instance.start()
    t.call("downgrade.unseal_rejected", "sys/unseal", {"key": key}, expected=503)
    t.call("downgrade.remains_sealed", "sys/health", method="GET", expected=503)
    t.call("downgrade.read_denied", "secret/data/jwt-upgrade", method="GET", expected=503)
    instance.stop()
    t.check("downgrade.application_unchanged", durable_manifest(store, application_only=True) == upgraded_application)
    instance.binary = candidate
    instance.start()
    t.call("recovery.unseal", "sys/unseal", {"key": key})
    for label, bearer in [("old", original["client_token"]), ("repeated", repeated["client_token"]),
                           *[("native_" + str(i), token) for i, token in enumerate(native_tokens)]]:
        t.call("recovery." + label + "_token_active", "auth/token/lookup-self", method="GET", token=bearer)
    recovered = t.call("recovery.assertion_reusable", login_path,
                       {"role": "test", "jwt": signed}, token="").get("auth", {})
    t.check("recovery.distinct_token_same_entity", distinct_service_tokens(repeated, recovered))
    instance.stop()
    secrets = [signed, no_iat, long_lived, future_iat, key, instance.token, original["client_token"],
               repeated["client_token"], recovered["client_token"], *native_tokens]
    files = [p for p in store.rglob("*") if p.is_file()] + [instance.root / "server.log", instance.root / "audit.jsonl"]
    t.check("plaintext_credentials_absent", all(secret.encode() not in p.read_bytes()
                                               for p in files if p.exists() for secret in secrets))


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
    root = Path(tempfile.mkdtemp(prefix="heptabao-jwt-native-upgrade-"))
    root.chmod(0o700)
    instance = None
    result = {"schema": "heptabao.jwt-native-upgrade.v1", "from_schema": 18, "minimum_to_schema": 19,
              "synthetic_only": True, "legacy_source_commit": LEGACY_SOURCE,
              "legacy_binary_sha256": legacy_hash, "legacy_receipt_sha256": file_hash(LEGACY_RECEIPT),
              "candidate_binary_sha256": candidate_hash, "build_source_commit": args.build_source_commit,
              "build_source_binding_basis": "caller-supplied build commit and observed binary hash; not independent binary attestation",
              "runner_sha256": runner_hash, "cases": [], "started_at_unix": time.time(),
              "independent_qualification": False, "full_migration_qualification": False,
              "rolling_upgrade_qualification": False, "production_authority": False,
              "reopen_replay_ledger_may_change": True,
              "unchanged_application_artifacts_scope": "all store entries except root ledger.hbl, rebuilt before schema validation on reopen"}
    try:
        instance = Instance(legacy, root / "instance")
        config_path = instance.root / "server.json"
        config = json.loads(config_path.read_text())
        config["lifecycle_interval_seconds"] = 0
        private_write(config_path, config)
        run_upgrade(instance, candidate, legacy, result["cases"])
        result["status"] = "passed"
    except Exception as error:
        result["status"] = "failed"
        result["safe_failure_code"] = str(error) if isinstance(error, ScenarioFailure) else type(error).__name__
    finally:
        if instance is not None:
            instance.stop()
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
