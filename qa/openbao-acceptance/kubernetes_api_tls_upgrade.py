#!/usr/bin/env python3
"""Actual enrolled Kubernetes schema28 to explicit API CA transport migration.

Synthetic HTTPS TokenReview only. No state fabrication and no rolling upgrade claim.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import shutil
import tempfile
from bao_http import Client, SafeArgumentParser, private_write
from core_isolation import ROOT, file_hash
from identity_upgrade import validate_binary_pins
from jwt_api_tls_live import Failure, Trace
from jwt_api_tls_upgrade import restart
from kubernetes_renewal_live import Reviewer, assertion, role
from official_openbao_launcher import certificates
from online_evidence import admit_output, source_identity
from provider_renewal_upgrade import durable_manifest
from remote_jwks_live import Instance, signing_key

LEGACY_SOURCE = "649c125af5c59064edbac4bfa5f10bc608b9e37d"
LEGACY_HARNESS_SOURCE = LEGACY_SOURCE
LEGACY_SHA256 = "0c2438e0df8a67ea9478aa15c4ff7cff33e8f90aa1671fa054de7c00cab750ac"
LEGACY_RECEIPT = ROOT / "qa/openbao-acceptance/evidence/provider-login-wrapping-649c125.json"
VALUE_PATH = "secret/data/kubernetes-api-tls-upgrade"
BASE = "auth/kubernetes-upgrade"


def admit_legacy_receipt(expected, receipt):
    identity = receipt.get("source_identity", {})
    required = {"status": "passed", "source_and_binary_unchanged": True, "runner_unchanged": True,
                "build_source_commit": LEGACY_SOURCE, "candidate_binary_sha256": LEGACY_SHA256, "cases_match": True}
    if (expected != LEGACY_SHA256 or any(receipt.get(k) != v for k, v in required.items())
            or identity.get("source_commit") != LEGACY_SOURCE or identity.get("source_dirty") is not False
            or identity.get("binary_sha256") != LEGACY_SHA256):
        raise ValueError("legacy_schema28_build_receipt_mismatch")


def legacy_configuration(reviewer):
    # Exact old API shape; deliberately independent of evolving fresh helpers.
    return {"kubernetes_host": reviewer.origin, "token_reviewer_jwt": reviewer.reviewer,
            "disable_local_ca_jwt": True}


def login(t, reviewer, phase):
    before = len(reviewer.calls)
    reviewer.request_valid = True
    auth = t.call(phase, BASE + "/login", {"role": "app", "jwt": reviewer.presented}, bearer="").get("auth", {})
    t.check(phase + ".real_post", len(reviewer.calls) == before + 1 and reviewer.request_valid)
    t.check(phase + ".issued", isinstance(auth.get("client_token"), str) and bool(auth["client_token"])
            and auth.get("renewable") is True)
    return auth


def prepare_legacy(instance, reviewer, rows):
    instance.start()
    status, init = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
    if status != 200:
        raise Failure("legacy_initialization_failed")
    instance.token, key = init["root_token"], init["keys_base64"][0]
    t = Trace(Client(instance.address, str(instance.root / "ca.crt"), instance.token), rows, "upgrade")
    t.call("legacy.unseal", "sys/unseal", {"key": key})
    t.call("legacy.kv", VALUE_PATH, {"data": {"synthetic": True}})
    t.call("legacy.mount", "sys/auth/kubernetes-upgrade", {"type": "kubernetes"}, expected=204)
    config = legacy_configuration(reviewer)
    t.check("legacy.no_api_ca", "kubernetes_ca_cert" not in config)
    t.call("legacy.config", BASE + "/config", config, expected=204)
    t.call("legacy.role", BASE + "/role/app", role(token_policies=["default"], token_ttl=600, token_max_ttl=1200), expected=204)
    auth = login(t, reviewer, "legacy.login")
    t.check("legacy.complete", True)
    return t, key, config, {"legacy": auth}


def run_upgrade(instance, reviewer, ca, candidate, legacy, settings, rows):
    t, key, config, tokens = prepare_legacy(instance, reviewer, rows)
    store = instance.root / "data"
    instance.stop()
    application = durable_manifest(store, application_only=True)
    restart(instance, candidate, settings, key, t, "current")
    t.check("current.reopen_preserves_application", durable_manifest(store, application_only=True) == application)
    before = durable_manifest(store)
    value = t.call("current.kv", VALUE_PATH, method="GET")
    t.check("current.value_preserved", value.get("data", {}).get("data") == {"synthetic": True})
    t.call("current.old_token", "auth/token/lookup-self", method="GET", bearer=tokens["legacy"]["client_token"])
    t.call("current.config", BASE + "/config", method="GET")
    t.check("current.pure_reads_preserve_store", durable_manifest(store) == before)
    t.call("retained.rewrite_without_ca", BASE + "/config", config, expected=204)
    no_enrollment = dict(settings, outbound_endpoints=[])
    restart(instance, candidate, no_enrollment, key, t, "retained.no_enrollment")
    before = durable_manifest(store)
    posts = len(reviewer.calls)
    denied = t.call("retained.login_requires_enrollment", BASE + "/login", {"role": "app", "jwt": reviewer.presented}, bearer="", expected=503)
    t.check("retained.no_publication", durable_manifest(store) == before and not denied.get("auth") and not denied.get("wrap_info"))
    t.check("retained.no_post", len(reviewer.calls) == posts)
    t.call("retained.old_token_renew_without_provider", "auth/token/renew-self", {}, bearer=tokens["legacy"]["client_token"])
    t.check("retained.renew_no_post", len(reviewer.calls) == posts)
    restart(instance, candidate, settings, key, t, "retained.restore_enrollment")
    restored = login(t, reviewer, "retained.login_restored")
    t.check("retained.same_identity", restored.get("entity_id") == tokens["legacy"].get("entity_id"))
    tokens["retained"] = restored
    t.check("retained.complete", True)
    t.call("migration.explicit_ca", BASE + "/config", dict(config, kubernetes_ca_cert=ca), expected=204)
    data = t.call("migration.config_read", BASE + "/config", method="GET").get("data", {})
    t.check("migration.ca_public_reviewer_hidden", data.get("kubernetes_ca_cert") == ca and "token_reviewer_jwt" not in data)
    before = durable_manifest(store)
    t.call("migration.no_silent_demotion", BASE + "/config", config, expected=400)
    t.check("migration.failed_demotion_unchanged", durable_manifest(store) == before)
    instance.stop()
    application = durable_manifest(store, application_only=True)
    restart(instance, candidate, no_enrollment, key, t, "migration.no_enrollment")
    t.check("migration.reopen_preserves_application", durable_manifest(store, application_only=True) == application)
    tokens["native"] = login(t, reviewer, "migration.native_login")
    t.check("migration.same_identity", tokens["native"].get("entity_id") == tokens["legacy"].get("entity_id"))
    posts = len(reviewer.calls)
    reviewer.mode = "unavailable"
    for name, auth in tokens.items():
        t.call("migration.renew_" + name, "auth/token/renew-self", {}, bearer=auth["client_token"])
    t.check("migration.renewals_no_provider", len(reviewer.calls) == posts)
    reviewer.mode = "normal"
    t.check("migration.complete", True)
    instance.stop()
    application = durable_manifest(store, application_only=True)
    private_write(instance.root / "server.json", settings)
    instance.binary = legacy
    instance.start()
    t.call("downgrade.unseal_rejected", "sys/unseal", {"key": key}, expected=503)
    t.call("downgrade.remains_sealed", "sys/health", method="GET", expected=503)
    instance.stop()
    t.check("downgrade.application_unchanged", durable_manifest(store, application_only=True) == application)
    restart(instance, candidate, no_enrollment, key, t, "recovery")
    t.check("recovery.application_unchanged", durable_manifest(store, application_only=True) == application)
    for name, auth in tokens.items():
        t.call("recovery.token_" + name, "auth/token/lookup-self", method="GET", bearer=auth["client_token"])
    tokens["recovery"] = login(t, reviewer, "recovery.new_login")
    instance.stop()
    sensitive = [key, instance.token, reviewer.reviewer, reviewer.presented, *(auth["client_token"] for auth in tokens.values())]
    files = [path for path in store.rglob("*") if path.is_file()] + [instance.root / "server.log", instance.root / "audit.jsonl"]
    t.check("plaintext_credentials_absent", all(secret.encode() not in path.read_bytes()
            for path in files if path.exists() for secret in sensitive))
    t.check("complete", True)


def complete(rows, prepare):
    required = {"legacy.complete"}
    if not prepare:
        required |= {"current.pure_reads_preserve_store", "retained.complete", "migration.complete",
                     "downgrade.application_unchanged", "recovery.application_unchanged", "plaintext_credentials_absent", "complete"}
    names = [row.get("case") for row in rows if isinstance(row, dict)]
    return (len(names) == len(rows) and len(names) == len(set(names))
            and {"api_tls.upgrade." + name for name in required}.issubset(names)
            and all(row.get("passed") is True and all(type(value) in (bool, int)
                    for name, value in row.items() if name not in ("case", "passed")) for row in rows))


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--prepare-legacy", action="store_true")
    for name in ("legacy-binary", "expected-legacy-sha256", "build-source-commit", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.build_source_commit) is None:
        parser.error("full build source commit required")
    legacy = Path(args.legacy_binary).resolve(strict=True)
    receipt = json.loads(LEGACY_RECEIPT.read_text())
    admit_legacy_receipt(args.expected_legacy_sha256, receipt)
    if args.prepare_legacy:
        if args.binary is not None or args.build_source_commit != LEGACY_SOURCE or file_hash(legacy) != LEGACY_SHA256:
            parser.error("prepare requires only the exact pinned historical binary/source")
        candidate = legacy
        candidate_hash = legacy_hash = LEGACY_SHA256
    else:
        if args.binary is None:
            parser.error("candidate binary required")
        candidate = args.binary.resolve(strict=True)
        candidate_hash, legacy_hash = validate_binary_pins(candidate, legacy, args.expected_legacy_sha256)
    output = Path(args.output).absolute()
    admitted = admit_output(output)
    before = source_identity(ROOT, candidate)
    runner_hash = file_hash(Path(__file__))
    root = Path(tempfile.mkdtemp(prefix="heptabao-kubernetes-api-tls-upgrade-"))
    root.chmod(0o700)
    instance = issuer = None
    rows, setup, failure = [], [], None
    try:
        cert_root = root / "provider-certs"
        cert_root.mkdir(mode=0o700)
        certificates(cert_root)
        issuer = Reviewer(cert_root / "tls.crt", cert_root / "tls.key", "candidate")
        private, jwk = signing_key("ES256", "synthetic-upgrade")
        issuer.presented = assertion(private, jwk)
        instance = Instance(legacy, root / "candidate")
        settings = json.loads((instance.root / "server.json").read_text())
        settings["lifecycle_interval_seconds"] = 0
        ca = (cert_root / "ca.crt").read_text()
        settings["outbound_endpoints"] = [
            {"origin": issuer.origin, "address": "127.0.0.1:" + str(issuer.port), "server_name": "localhost", "ca_pem": ca}]
        private_write(instance.root / "server.json", settings)
        if args.prepare_legacy:
            prepare_legacy(instance, issuer, rows)
        else:
            run_upgrade(instance, issuer, ca, candidate, legacy, settings, rows)
    except Exception as error:
        failure = str(error) if isinstance(error, Failure) else "fixture_" + type(error).__name__
    finally:
        if instance is not None:
            instance.stop()
        if issuer is not None:
            issuer.close()
        shutil.rmtree(root)
    after = source_identity(ROOT, candidate)
    binaries_unchanged = after["binary_sha256"] == candidate_hash and file_hash(legacy) == legacy_hash
    source_unchanged = before == after
    if not binaries_unchanged or not source_unchanged or file_hash(Path(__file__)) != runner_hash:
        failure = "source_binary_or_runner_changed"
    if not complete(rows, args.prepare_legacy):
        failure = failure or "incomplete_observations"
    report = {"schema": "heptabao.kubernetes-api-tls-upgrade.v1", "status": "passed" if failure is None else "failed",
        "from_schema": 28, "minimum_to_schema": None if args.prepare_legacy else 29, "prepare_legacy_only": args.prepare_legacy,
        "failure": failure, "cases": rows, "setup": setup, "source_identity": before,
        "legacy_source_commit": LEGACY_SOURCE, "legacy_harness_source_commit": LEGACY_HARNESS_SOURCE,
        "legacy_binary_sha256": legacy_hash,
        "legacy_receipt_sha256": file_hash(LEGACY_RECEIPT), "candidate_binary_sha256": None if args.prepare_legacy else candidate_hash,
        "build_source_commit": args.build_source_commit, "binaries_unchanged": binaries_unchanged,
        "source_and_binary_unchanged": source_unchanged, "runner_sha256": runner_hash,
        "synthetic_tokenreview": True, "actual_kube_apiserver": False,
        "reopen_replay_ledger_may_change": True,
        "application_artifact_scope": "all store entries except root ledger.hbl, rebuilt before schema validation",
        "synthetic_only": True, "rolling_upgrade_qualification": False,
        "full_migration_qualification": False, "independent_qualification": False, "production_authority": False}
    if admit_output(output) != admitted:
        raise ValueError("report_parent_changed")
    private_write(output, report, replace=False)
    print(json.dumps({"status": report["status"], "checks": len(rows), "failure": failure}))
    return 0 if failure is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
