#!/usr/bin/env python3
"""Exercise the pinned schema-19 Kubernetes store through native renewal (schema 20+).

Only fresh synthetic stores and a pinned TLS TokenReview protocol are used.
Old nonrenewable tokens never gain native renewal provenance during upgrade.
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
from kubernetes_renewal_live import Reviewer, assertion, configuration, role
from radius_renewal_live import renewal_token_shape
from online_evidence import admit_output, source_identity
from provider_renewal_upgrade import durable_manifest
from remote_jwks_live import Instance, signing_key

LEGACY_SOURCE = "39ee3edbf908ec55bd1afc7526fb425693a0ef15"
LEGACY_SHA256 = "d90f78d4c5a20477ae73ac2da19eb552f319bde3c9cfee096e0366d91e9d40d2"
LEGACY_RECEIPT = ROOT / "qa/openbao-acceptance/evidence/jwt-renewal-39ee3ed.json"


def admit_legacy(candidate, legacy, expected, receipt):
    required = {"build_source_commit": LEGACY_SOURCE,
                "harness_source_commit": LEGACY_SOURCE, "harness_source_dirty": False,
                "harness_source_unchanged": True, "candidate_binary_unchanged": True,
                "candidate_binary_sha256": LEGACY_SHA256, "status": "passed"}
    if expected != LEGACY_SHA256 or any(receipt.get(key) != value for key, value in required.items()):
        raise ValueError("legacy_schema19_build_receipt_mismatch")
    return validate_binary_pins(candidate, legacy, expected)


class Trace:
    def __init__(self, client, cases):
        self.client, self.cases = client, cases

    def check(self, name, condition, **observed):
        name = "kubernetes_native_upgrade." + name
        self.cases.append({"case": name, **observed, "passed": bool(condition)})
        if not condition:
            raise ScenarioFailure(name)

    def call(self, name, path, body=None, *, method="POST", token=None, expected=200):
        response = self.client.request(method, "/v1/" + path, body, token=token)
        self.check(name, response.status == expected, status=response.status)
        return response.body


def prepare_legacy(instance, reviewer, cases):
    """Create schema-19 state with the actual pinned binary; keep secrets in memory."""
    instance.start()
    status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
    if status != 200:
        raise ScenarioFailure("kubernetes_native_upgrade.initialize")
    instance.token, key = initialized["root_token"], initialized["keys_base64"][0]
    t = Trace(Client(instance.address, str(instance.root / "ca.crt"), instance.token), cases)
    t.call("legacy.unseal", "sys/unseal", {"key": key})
    t.call("legacy.mount", "sys/auth/kubernetes-upgrade", {"type": "kubernetes"}, expected=204)
    private, jwk = signing_key("ES256", "upgrade-key")
    config_path, role_path, login_path = ("auth/kubernetes-upgrade/" + part for part in ("config", "role/test", "login"))
    config = configuration("candidate", reviewer, private, (instance.root / "ca.crt").read_text())
    t.call("legacy.config", config_path, config, expected=204)
    rules = ('path "auth/token/create" { capabilities = ["update", "sudo"] }\n'
             'path "auth/token/create-orphan" { capabilities = ["update", "sudo"] }')
    t.call("legacy.policy", "sys/policies/acl/kube-upgrade", {"policy": rules}, method="PUT", expected=204)
    # Schema 19 has no Kubernetes max/period/explicit-max fields. Do not inject
    # future-schema fields or patch the encrypted owner state to make this pass.
    old_role = role(token_ttl=120, token_policies=["kube-upgrade"])
    old_role.pop("token_max_ttl")
    t.call("legacy.role", role_path, old_role, expected=204)
    t.call("legacy.write", "secret/data/kubernetes-upgrade", {"data": {"synthetic": True}})
    reviewer.presented = assertion(private, jwk)
    before = len(reviewer.calls)
    original = t.call("legacy.login", login_path, {"role": "test", "jwt": reviewer.presented}, token="").get("auth", {})
    t.check("legacy.token_shape", all(isinstance(original.get(k), str) and original[k]
                                     for k in ("client_token", "accessor", "entity_id")))
    t.check("legacy.nonrenewable", original.get("renewable") is False and original.get("lease_duration") == 120)
    t.check("legacy.tokenreview_bound", len(reviewer.calls) == before + 1 and reviewer.request_valid)
    children = {}
    for label, path in [("child", "auth/token/create"), ("orphan", "auth/token/create-orphan")]:
        child = t.call("legacy." + label + ".create", path, {"policies": ["default"], "ttl": "120s"},
                       token=original["client_token"]).get("auth", {})
        t.check("legacy." + label + ".shape", isinstance(child.get("client_token"), str)
                and bool(child["client_token"]) and child.get("renewable") is True)
        children[label] = child["client_token"]
    t.call("legacy.nonrenewable_denied", "auth/token/renew-self", {}, token=original["client_token"], expected=400)
    return {"key": key, "trace": t, "original": original, "children": children,
            "role_path": role_path, "login_path": login_path, "private": private, "jwk": jwk,
            "old_assertion": reviewer.presented}


def reject_legacy_renewal(t, original, reviewer, store, prefix):
    """All dispatch paths must preserve the legacy nonrenewable status and state."""
    before, calls = durable_manifest(store), len(reviewer.calls)
    for label, path, body, token in [
            ("self", "auth/token/renew-self", {}, original["client_token"]),
            ("token", "auth/token/renew", {"token": original["client_token"]}, None),
            ("accessor", "auth/token/renew-accessor", {"accessor": original["accessor"]}, None)]:
        rejected = t.call(prefix + "." + label, path, body, token=token, expected=400)
        t.check(prefix + "." + label + ".no_token", not rejected.get("auth") and not rejected.get("wrap_info"))
    t.check(prefix + ".no_tokenreview", len(reviewer.calls) == calls)
    t.check(prefix + ".entire_store_unchanged", durable_manifest(store) == before)


def run_upgrade(instance, reviewer, candidate, legacy, cases):
    prepared = prepare_legacy(instance, reviewer, cases)
    t, key, original = prepared["trace"], prepared["key"], prepared["original"]
    children = prepared["children"]
    instance.stop()
    store = instance.root / "data"
    old_application = durable_manifest(store, application_only=True)
    instance.binary = candidate
    instance.start()
    t.call("current.unseal", "sys/unseal", {"key": key})
    t.check("current.reopen_preserves_application", durable_manifest(store, application_only=True) == old_application)
    before = durable_manifest(store)
    value = t.call("current.read", "secret/data/kubernetes-upgrade", method="GET")
    t.check("current.value_preserved", value.get("data", {}).get("data") == {"synthetic": True})
    old = t.call("current.old_token_active", "auth/token/lookup-self", method="GET", token=original["client_token"])
    t.check("current.old_token_still_nonrenewable", old.get("data", {}).get("renewable") is False)
    role_data = t.call("current.old_role", prepared["role_path"], method="GET").get("data", {})
    t.check("current.old_role_compatible_defaults", role_data.get("token_ttl") == 120
            and role_data.get("token_max_ttl") == 0 and role_data.get("token_period") == 0
            and role_data.get("token_explicit_max_ttl") == 0)
    for label, child in children.items():
        t.call("current." + label + ".active", "auth/token/lookup-self", method="GET", token=child)
    t.check("current.reads_preserve_entire_store", durable_manifest(store) == before)
    reviewer.mode = "unavailable"
    reject_legacy_renewal(t, original, reviewer, store, "current.old_nonrenewable")
    t.call("current.role_explicitly_updated", prepared["role_path"],
           role(token_ttl=120, token_max_ttl=600, token_period=0, token_explicit_max_ttl=0,
                token_policies=["kube-upgrade"]), expected=204)
    reject_legacy_renewal(t, original, reviewer, store, "current.role_update_does_not_upgrade_token")
    reviewer.mode = "normal"
    reviewer.presented = assertion(prepared["private"], prepared["jwk"])
    calls = len(reviewer.calls)
    native = t.call("current.native_login", prepared["login_path"],
                    {"role": "test", "jwt": reviewer.presented}, token="").get("auth", {})
    t.check("current.native_shape", native.get("renewable") is True and native.get("lease_duration") == 120
            and isinstance(native.get("client_token"), str) and bool(native["client_token"])
            and native.get("entity_id") == original["entity_id"]
            and native["client_token"] != original["client_token"])
    t.check("current.native_tokenreview_bound", len(reviewer.calls) == calls + 1 and reviewer.request_valid)
    reviewer.mode = "unavailable"
    calls = len(reviewer.calls)
    renewed = t.call("current.native_renews", "auth/token/renew-self", {"increment": 300}, token=native["client_token"])
    t.check("current.native_lease_and_echo", renewed.get("auth", {}).get("lease_duration") == 300
            and renewal_token_shape(renewed.get("auth"), native["client_token"], via_accessor=False))
    for label, child in children.items():
        t.call("current." + label + ".renews", "auth/token/renew-self", {"increment": 300}, token=child)
    t.check("current.renewals_without_tokenreview", len(reviewer.calls) == calls)
    instance.stop()
    upgraded_application = durable_manifest(store, application_only=True)
    t.check("current.native_mutation_persisted", upgraded_application != old_application)
    instance.binary = legacy
    instance.start()
    t.call("downgrade.unseal_rejected", "sys/unseal", {"key": key}, expected=503)
    t.call("downgrade.remains_sealed", "sys/health", method="GET", expected=503)
    t.call("downgrade.read_denied", "secret/data/kubernetes-upgrade", method="GET", expected=503)
    instance.stop()
    t.check("downgrade.application_unchanged", durable_manifest(store, application_only=True) == upgraded_application)
    instance.binary = candidate
    instance.start()
    t.call("recovery.unseal", "sys/unseal", {"key": key})
    t.check("recovery.application_unchanged", durable_manifest(store, application_only=True) == upgraded_application)
    for label, bearer in [("old", original["client_token"]), ("native", native["client_token"]), *children.items()]:
        t.call("recovery." + label + ".active", "auth/token/lookup-self", method="GET", token=bearer)
    reject_legacy_renewal(t, original, reviewer, store, "recovery.old_still_nonrenewable")
    calls = len(reviewer.calls)
    for label, bearer in [("native", native["client_token"]), *children.items()]:
        renewed = t.call("recovery." + label + ".renews", "auth/token/renew-self", {"increment": 300}, token=bearer)
        t.check("recovery." + label + ".renewable", renewed.get("auth", {}).get("renewable") is True)
    t.check("recovery.renewals_without_tokenreview", len(reviewer.calls) == calls)
    instance.stop()
    sensitive = [prepared["old_assertion"], reviewer.presented, reviewer.reviewer, key, instance.token,
                 original["client_token"], native["client_token"], *children.values()]
    files = [p for p in store.rglob("*") if p.is_file()] + [instance.root / "server.log", instance.root / "audit.jsonl"]
    t.check("plaintext_credentials_absent", all(secret.encode() not in p.read_bytes()
                                               for p in files if p.exists() for secret in sensitive))


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
    root = Path(tempfile.mkdtemp(prefix="heptabao-kubernetes-native-upgrade-"))
    root.chmod(0o700)
    instance = reviewer = None
    result = {"schema": "heptabao.kubernetes-native-upgrade.v1", "from_schema": 19, "minimum_to_schema": 20,
              "synthetic_only": True, "legacy_source_commit": LEGACY_SOURCE,
              "legacy_binary_sha256": legacy_hash, "legacy_receipt_sha256": file_hash(LEGACY_RECEIPT),
              "candidate_binary_sha256": candidate_hash, "build_source_commit": args.build_source_commit,
              "build_source_binding_basis": "caller-supplied build commit and observed binary hash; not independent binary attestation",
              "runner_sha256": runner_hash, "cases": [], "started_at_unix": time.time(),
              "actual_kube_apiserver": False, "kubernetes_rbac_acceptance": False,
              "independent_qualification": False, "full_migration_qualification": False,
              "rolling_upgrade_qualification": False, "production_authority": False,
              "reopen_replay_ledger_may_change": True,
              "unchanged_application_artifacts_scope": "all store entries except root ledger.hbl, rebuilt before schema validation on reopen"}
    try:
        instance = Instance(legacy, root / "instance")
        config_path = instance.root / "server.json"
        config = json.loads(config_path.read_text())
        config["lifecycle_interval_seconds"] = 0
        reviewer = Reviewer(instance.root / "tls.crt", instance.root / "tls.key", "candidate")
        config["outbound_endpoints"] = [{"origin": reviewer.origin, "address": "127.0.0.1:" + str(reviewer.port),
                                         "server_name": "localhost", "ca_pem": (instance.root / "ca.crt").read_text(),
                                         "path_prefix": "/apis/authentication.k8s.io/v1/"}]
        private_write(config_path, config)
        run_upgrade(instance, reviewer, candidate, legacy, result["cases"])
        result["status"] = "passed"
    except Exception as error:
        result["status"] = "failed"
        result["safe_failure_code"] = str(error) if isinstance(error, ScenarioFailure) else type(error).__name__
    finally:
        if instance is not None:
            instance.stop()
        if reviewer is not None:
            reviewer.close()
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
