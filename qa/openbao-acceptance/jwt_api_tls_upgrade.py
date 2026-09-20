#!/usr/bin/env python3
"""Exercise actual schema-27 enrolled JWT/OIDC state through API TLS schema 28.

Old tokens and a pending PKCE code session are created only by the pinned old
binary. The new binary must retain legacy endpoint authority until explicit CA
opt-in, then work with an empty startup endpoint list. No rolling-upgrade claim.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import tempfile
import urllib.parse

from bao_http import Client, SafeArgumentParser, private_write
from core_isolation import ROOT, file_hash
from identity_upgrade import validate_binary_pins
from jwt_api_tls_live import MODES, Failure, Trace, bounded_issuer, discovery
from oidc_renewal_live import OfficialIssuer, free_port
from official_openbao_launcher import BINARY_SHA256, start_oracle, stop_oracle
from online_evidence import admit_output, source_identity
from provider_renewal_upgrade import durable_manifest
from remote_jwks_live import Instance, signing_key, token

LEGACY_SOURCE = "6b4fed2f1a909452a45d86960d53a786ac10bd41"
LEGACY_HARNESS_SOURCE = "d4da0baab03c79e47c573141989f362bb955d563"
LEGACY_SHA256 = "ca26f8f6233d6939a47337379c7d153105ad93cca4c9422b557330dfe459700e"
LEGACY_RECEIPT = ROOT / "qa/openbao-acceptance/evidence/jwt-split-phase-d4da0ba.json"
VALUE_PATH = "secret/data/jwt-api-tls-upgrade"


def admit_legacy_receipt(expected, receipt):
    required = {"status": "passed", "source_and_binary_unchanged": True, "runner_unchanged": True,
                "source_commit": LEGACY_HARNESS_SOURCE, "build_source_commit": LEGACY_SOURCE,
                "source_dirty": False, "binary_sha256": LEGACY_SHA256}
    if expected != LEGACY_SHA256 or any(receipt.get(name) != value for name, value in required.items()):
        raise ValueError("legacy_schema27_build_receipt_mismatch")


def legacy_configuration(mode, issuer, oidc):
    # This shape is historical. Do not reuse an evolving fresh-config helper
    # which may silently inject new transport authority before the old run.
    if mode == "oidc":
        return {"oidc_discovery_url": oidc.discovery, "oidc_client_id": oidc.client_id,
                "oidc_client_secret": oidc.client_secret, "jwt_supported_algs": ["RS256"],
                "pkce_s256_enrolled": True}
    result = {"bound_issuer": issuer.origin, "jwt_supported_algs": ["ES256"]}
    if mode == "jwks":
        result["jwks_url"] = issuer.origin + "/keys"
    else:
        result["oidc_discovery_url"] = issuer.origin
    return result


def mounted(mode):
    return "tls-upgrade-" + mode


def login(t, label, mode, issuer, oidc, private, jwk):
    mount = mounted(mode)
    if mode == "oidc":
        return oidc.login(t, "candidate", label, mount, "app")
    result = t.call(label, "auth/" + mount + "/login",
                    {"role": "app", "jwt": token(private, jwk, issuer.origin)}, bearer="")
    auth = result.get("auth", {})
    t.check(label + ".token", isinstance(auth.get("client_token"), str) and bool(auth["client_token"])
            and isinstance(auth.get("entity_id"), str) and bool(auth["entity_id"]))
    return auth


def prepare_legacy(instance, issuer, oidc, private, jwk, rows):
    instance.start()
    status, initial = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
    if status != 200:
        raise Failure("legacy_initialization_failed")
    instance.token, key = initial["root_token"], initial["keys_base64"][0]
    t = Trace(Client(instance.address, str(instance.root / "ca.crt"), instance.token), rows, "upgrade")
    t.call("legacy.unseal", "sys/unseal", {"key": key})
    t.call("legacy.kv", VALUE_PATH, {"data": {"synthetic": True}})
    tokens, configs = {}, {}
    for mode in MODES:
        mount = mounted(mode)
        t.call("legacy." + mode + ".mount", "sys/auth/" + mount,
               {"type": "oidc" if mode == "oidc" else "jwt"}, expected=204)
        config = legacy_configuration(mode, issuer, oidc)
        t.check("legacy." + mode + ".no_api_ca", not {"jwks_ca_pem", "oidc_discovery_ca_pem"}.intersection(config))
        t.call("legacy." + mode + ".config", "auth/" + mount + "/config", config, expected=204)
        role = {"role_type": "oidc" if mode == "oidc" else "jwt", "user_claim": "sub",
                "token_policies": ["default"], "token_ttl": 600, "token_max_ttl": 1200}
        role.update({"allowed_redirect_uris": [oidc.redirect]} if mode == "oidc" else {"bound_audiences": ["heptabao-test"]})
        t.call("legacy." + mode + ".role", "auth/" + mount + "/role/app", role, expected=204)
        tokens[mode] = login(t, "legacy." + mode + ".login", mode, issuer, oidc, private, jwk)
        configs[mode] = config
    pending = oidc.begin(t, "legacy.pending", mounted("oidc"), "app")
    t.check("legacy.complete", True)
    return t, key, configs, tokens, pending


def restart(instance, binary, settings, key, t, phase):
    instance.stop()
    private_write(instance.root / "server.json", settings)
    instance.binary = binary
    instance.start()
    t.call(phase + ".unseal", "sys/unseal", {"key": key})


def run_upgrade(instance, issuer, oidc, private, jwk, candidate, legacy, settings, rows):
    t, key, configs, tokens, pending = prepare_legacy(instance, issuer, oidc, private, jwk, rows)
    store = instance.root / "data"
    instance.stop()
    old_application = durable_manifest(store, application_only=True)
    restart(instance, candidate, settings, key, t, "current")
    t.check("current.reopen_preserves_application", durable_manifest(store, application_only=True) == old_application)
    before = durable_manifest(store)
    body = t.call("current.kv", VALUE_PATH, method="GET")
    t.check("current.value_preserved", body.get("data", {}).get("data") == {"synthetic": True})
    for mode, auth in tokens.items():
        t.call("current." + mode + ".old_token", "auth/token/lookup-self", method="GET", bearer=auth["client_token"])
        t.call("current." + mode + ".config", "auth/" + mounted(mode) + "/config", method="GET")
    t.check("current.pure_reads_preserve_store", durable_manifest(store) == before)
    pending_token = oidc.finish(t, "candidate", "current.old_pending", mounted("oidc"), pending)
    t.check("current.old_pending_same_identity", pending_token.get("entity_id") == tokens["oidc"]["entity_id"])
    t.call("current.old_pending_single_use", "auth/" + mounted("oidc") + "/oidc/callback", pending, bearer="", expected=403)
    tokens["pending"] = pending_token
    for mode in MODES:
        t.call("retained." + mode + ".rewrite_without_ca", "auth/" + mounted(mode) + "/config", configs[mode], expected=204)
    no_enrollment = dict(settings, outbound_endpoints=[])
    restart(instance, candidate, no_enrollment, key, t, "retained.no_enrollment")
    for mode in MODES:
        before = durable_manifest(store)
        if mode == "oidc":
            body = {"role": "app", "redirect_uri": oidc.redirect, "client_nonce": "synthetic-upgrade-client-nonce-1234567890"}
            path = "auth/" + mounted(mode) + "/oidc/auth_url"
        else:
            body = {"role": "app", "jwt": token(private, jwk, issuer.origin)}
            path = "auth/" + mounted(mode) + "/login"
        rejected = t.call("retained." + mode + ".still_requires_enrollment", path, body, bearer="", expected=503)
        t.check("retained." + mode + ".no_publication", durable_manifest(store) == before
                and not rejected.get("auth") and not rejected.get("data") and not rejected.get("wrap_info"))
    restart(instance, candidate, settings, key, t, "retained.restore_enrollment")
    for mode in MODES:
        auth = login(t, "retained." + mode + ".restored", mode, issuer, oidc, private, jwk)
        t.check("retained." + mode + ".identity", auth.get("entity_id") == tokens[mode]["entity_id"])
    t.check("retained.complete", True)
    ca = Path(oidc.server["ca_file"]).read_text()
    for mode in MODES:
        field = "jwks_ca_pem" if mode == "jwks" else "oidc_discovery_ca_pem"
        t.call("migration." + mode + ".explicit_ca", "auth/" + mounted(mode) + "/config",
               dict(configs[mode], **{field: ca}), expected=204)
    instance.stop()
    upgraded = durable_manifest(store, application_only=True)
    restart(instance, candidate, no_enrollment, key, t, "migration.no_enrollment")
    t.check("migration.reopen_preserves_application", durable_manifest(store, application_only=True) == upgraded)
    for mode in MODES:
        auth = login(t, "migration." + mode + ".api_login", mode, issuer, oidc, private, jwk)
        t.check("migration." + mode + ".same_identity", auth.get("entity_id") == tokens[mode]["entity_id"])
        tokens["fresh_" + mode] = auth
        t.call("migration." + mode + ".old_token_renew", "auth/token/renew-self", {"increment": 300}, bearer=tokens[mode]["client_token"])
    t.check("migration.complete", True)
    instance.stop()
    final_application = durable_manifest(store, application_only=True)
    private_write(instance.root / "server.json", settings)
    instance.binary = legacy
    instance.start()
    t.call("downgrade.unseal_rejected", "sys/unseal", {"key": key}, expected=503)
    t.call("downgrade.remains_sealed", "sys/health", method="GET", expected=503)
    instance.stop()
    t.check("downgrade.application_unchanged", durable_manifest(store, application_only=True) == final_application)
    restart(instance, candidate, no_enrollment, key, t, "recovery")
    t.check("recovery.application_unchanged", durable_manifest(store, application_only=True) == final_application)
    for label, auth in tokens.items():
        t.call("recovery." + label + ".usable", "auth/token/lookup-self", method="GET", bearer=auth["client_token"])
    for mode in MODES:
        login(t, "recovery." + mode + ".new_api_login", mode, issuer, oidc, private, jwk)
    t.call("recovery.old_pending_still_consumed", "auth/" + mounted("oidc") + "/oidc/callback", pending, bearer="", expected=403)
    instance.stop()
    sensitive = [key, instance.token, oidc.client_secret, oidc.enduser, *pending.values(),
                 *(auth["client_token"] for auth in tokens.values())]
    files = [path for path in store.rglob("*") if path.is_file()] + [instance.root / "server.log", instance.root / "audit.jsonl"]
    t.check("plaintext_credentials_absent", all(secret.encode() not in path.read_bytes()
            for path in files if path.exists() for secret in sensitive))
    t.check("complete", True)


def complete(rows, prepare):
    names = [row.get("case") for row in rows if isinstance(row, dict)]
    required = {"api_tls.upgrade.legacy.complete"}
    if not prepare:
        required |= {"api_tls.upgrade." + name for name in ("current.old_pending_same_identity", "retained.complete",
            "migration.complete", "downgrade.application_unchanged", "recovery.application_unchanged", "plaintext_credentials_absent", "complete")}
    return (len(names) == len(rows) and len(names) == len(set(names)) and required.issubset(names)
            and all(row.get("passed") is True for row in rows))


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
    root = Path(tempfile.mkdtemp(prefix="heptabao-jwt-api-tls-upgrade-"))
    root.chmod(0o700)
    instance = issuer = oidc = None
    rows, setup, failure = [], [], None
    try:
        oidc = OfficialIssuer(start_oracle(free_port()))
        oidc.setup(Trace(oidc.admin, setup), id_token_ttl=300)
        cert_root = Path(oidc.server["root"])
        issuer = bounded_issuer(cert_root / "tls.crt", cert_root / "tls.key")
        private, jwk = signing_key("ES256", "synthetic-upgrade")
        issuer.documents["/keys"] = {"keys": [jwk]}
        issuer.documents["/.well-known/openid-configuration"] = discovery(issuer.origin)
        instance = Instance(legacy, root / "candidate")
        settings = json.loads((instance.root / "server.json").read_text())
        settings["lifecycle_interval_seconds"] = 0
        ca = Path(oidc.server["ca_file"]).read_text()
        settings["outbound_endpoints"] = [
            {"origin": issuer.origin, "address": "127.0.0.1:" + str(issuer.port), "server_name": "localhost", "ca_pem": ca},
            {"origin": oidc.server["address"], "address": "127.0.0.1:" + str(urllib.parse.urlsplit(oidc.server["address"]).port),
             "server_name": "127.0.0.1", "ca_pem": ca}]
        private_write(instance.root / "server.json", settings)
        if args.prepare_legacy:
            prepare_legacy(instance, issuer, oidc, private, jwk, rows)
        else:
            run_upgrade(instance, issuer, oidc, private, jwk, candidate, legacy, settings, rows)
    except Exception as error:
        failure = str(error) if isinstance(error, Failure) else "fixture_" + type(error).__name__
    finally:
        if instance is not None:
            instance.stop()
        if issuer is not None:
            issuer.close()
        if oidc is not None:
            stop_oracle(oidc.server)
            shutil.rmtree(oidc.server["root"])
        shutil.rmtree(root)
    after = source_identity(ROOT, candidate)
    binaries_unchanged = after["binary_sha256"] == candidate_hash and file_hash(legacy) == legacy_hash
    source_unchanged = before == after
    if not binaries_unchanged or not source_unchanged or file_hash(Path(__file__)) != runner_hash:
        failure = "source_binary_or_runner_changed"
    if not complete(rows, args.prepare_legacy):
        failure = failure or "incomplete_observations"
    report = {"schema": "heptabao.jwt-api-tls-upgrade.v1", "status": "passed" if failure is None else "failed",
        "from_schema": 27, "minimum_to_schema": None if args.prepare_legacy else 28, "prepare_legacy_only": args.prepare_legacy,
        "failure": failure, "cases": rows, "setup": setup, "source_identity": before,
        "legacy_source_commit": LEGACY_SOURCE, "legacy_harness_source_commit": LEGACY_HARNESS_SOURCE,
        "legacy_binary_sha256": legacy_hash,
        "legacy_receipt_sha256": file_hash(LEGACY_RECEIPT), "candidate_binary_sha256": None if args.prepare_legacy else candidate_hash,
        "build_source_commit": args.build_source_commit, "binaries_unchanged": binaries_unchanged,
        "source_and_binary_unchanged": source_unchanged, "runner_sha256": runner_hash,
        "official_issuer_binary_sha256": BINARY_SHA256,
        "real_pending_code_from_legacy_binary": any(row.get("case") == "api_tls.upgrade.legacy.pending.actual_issuer_authorize" and row.get("passed") is True for row in rows),
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
