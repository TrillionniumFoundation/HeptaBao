#!/usr/bin/env python3
"""Actual schema-29 JWT state -> bound-claim rules -> refused downgrade.

Both binary inputs are local and pinned. Fresh synthetic static-key and API
JWKS roles are created by the old process, never by JSON state fabrication.
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
from jwt_api_tls_live import Failure, bounded_issuer
from online_evidence import admit_output, source_identity
from provider_renewal_upgrade import durable_manifest
from remote_jwks_live import Instance, signing_key, token

LEGACY_SOURCE = "a14a7fd03ed535dbc97fd33bff771bdd9b1f3bb7"
LEGACY_SHA256 = "cb3477f0e2fb26ac6005a17aafb25b455b47834e2079df7a8a15556e0f14b55e"
LEGACY_RECEIPT = ROOT / "qa/openbao-acceptance/evidence/kubernetes-api-tls-a14a7fd.json"
MODES = ("static", "remote")
VALUE_PATH = "secret/data/jwt-bound-upgrade"
BOUNDS = {"value": 42, "/context/enabled": True}


def admit_legacy_receipt(expected, receipt):
    source = receipt.get("candidate_source", {})
    if (expected != LEGACY_SHA256 or receipt.get("status") != "passed"
            or receipt.get("build_source_commit") != LEGACY_SOURCE
            or receipt.get("source_and_binary_unchanged") is not True
            or receipt.get("runner_unchanged") is not True
            or source.get("source_commit") != LEGACY_SOURCE
            or source.get("source_dirty") is not False
            or source.get("binary_sha256") != LEGACY_SHA256):
        raise ValueError("legacy_schema29_receipt_mismatch")


class Trace:
    def __init__(self, client, rows):
        self.client, self.rows = client, rows

    def check(self, label, condition, **observed):
        if (not isinstance(label, str) or re.fullmatch(r"[a-z0-9_.]{1,150}", label) is None
                or any(type(value) not in (int, bool) for value in observed.values())):
            raise Failure("invalid_observation_shape")
        name = "jwt_bound_upgrade." + label
        self.rows.append({"case": name, **observed, "passed": condition is True})
        if condition is not True:
            raise Failure(name)

    def call(self, label, path, body=None, *, method="POST", bearer=None, expected=200, wrap=None):
        result = self.client.request(method, "/v1/" + path, body, token=bearer, wrap_ttl=wrap)
        self.check(label, result.status == expected, status=result.status)
        return result.body


def paths(mode):
    mount = "bound-upgrade-" + mode
    return mount, "auth/" + mount + "/role/app", "auth/" + mount + "/login"


def legacy_configuration(mode, issuer, jwk, ca):
    # Freeze the old shape locally: evolving role helpers must not inject the
    # very feature this historical binary is supposed to precede.
    if mode == "static":
        return {"issuer": issuer.origin, "audiences": ["heptabao-test"], "jwks": {"keys": [jwk]}}
    return {"bound_issuer": issuer.origin, "jwks_url": issuer.origin + "/keys",
            "jwks_ca_pem": ca, "jwt_supported_algs": ["ES256"]}


def retained_role_readback(current, previous):
    additions = {"bound_claims", "bound_claims_type", "role_type", "user_claim"}
    retained = {key:value for key,value in current.items() if key not in additions or key in previous}
    return (retained == previous and current.get("bound_claims_type") == "string"
            and not current.get("bound_claims")
            and current.get("role_type", "jwt") == "jwt"
            and current.get("user_claim", "sub") == "sub")


def old_role():
    return {"role_type": "jwt", "user_claim": "sub", "bound_audiences": ["heptabao-test"],
            "token_policies": ["default", "upgrade-child"], "token_ttl": 600, "token_max_ttl": 1200}


def prepare_legacy(instance, issuer, private, jwk, rows):
    instance.start()
    status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
    if status != 200:
        raise Failure("legacy_initialization_failed")
    instance.token, key = initialized["root_token"], initialized["keys_base64"][0]
    t = Trace(Client(instance.address, str(instance.root / "ca.crt"), instance.token), rows)
    t.call("legacy.unseal", "sys/unseal", {"key": key})
    t.call("legacy.kv", VALUE_PATH, {"data": {"synthetic": True}})
    t.call("legacy.child_policy", "sys/policies/acl/upgrade-child",
           {"policy": 'path "auth/token/create" { capabilities = ["update"] }'}, expected=204)
    saved = {}
    for mode in MODES:
        mount, role_path, login_path = paths(mode)
        prefix = "legacy." + mode
        t.call(prefix + ".mount", "sys/auth/" + mount, {"type": "jwt"}, expected=204)
        t.call(prefix + ".config", "auth/" + mount + "/config",
               legacy_configuration(mode, issuer, jwk, (instance.root / "ca.crt").read_text()), expected=204)
        payload = old_role()
        t.check(prefix + ".role_has_no_new_fields", not {"bound_claims", "bound_claims_type"}.intersection(payload))
        t.call(prefix + ".role", role_path, payload, expected=204)
        signed = token(private, jwk, issuer.origin, value="old")
        auth = t.call(prefix + ".login", login_path, {"role": "app", "jwt": signed}, bearer="").get("auth", {})
        t.check(prefix + ".token", all(isinstance(auth.get(field), str) and bool(auth[field])
                for field in ("client_token", "accessor", "entity_id")))
        child = t.call(prefix + ".child", "auth/token/create", {"policies": ["default"], "ttl": 300},
                       bearer=auth["client_token"]).get("auth", {})
        t.check(prefix + ".child_token", isinstance(child.get("client_token"), str) and bool(child["client_token"]))
        role = t.call(prefix + ".read_role", role_path, method="GET").get("data", {})
        before = durable_manifest(instance.root / "data")
        denied = t.call(prefix + ".bounds_unsupported", role_path,
                        {"role_type": "jwt", "bound_claims": BOUNDS}, expected=400)
        t.check(prefix + ".unsupported_does_not_mutate", not denied.get("auth")
                and durable_manifest(instance.root / "data") == before)
        saved[mode] = {"auth": auth, "child": child, "role": role, "signed": signed}
    t.check("legacy.complete", True)
    return t, key, saved


def restart(instance, binary, key, t, label):
    instance.stop()
    instance.binary = binary
    instance.start()
    t.call(label + ".unseal", "sys/unseal", {"key": key})


def accepted_login(t, label, mode, private, jwk, issuer, saved, extra):
    signed = token(private, jwk, issuer.origin, **extra)
    body = t.call(label, paths(mode)[2], {"role": "app", "jwt": signed}, bearer="")
    auth = body.get("auth", {})
    t.check(label + ".identity", auth.get("entity_id") == saved["auth"]["entity_id"]
            and isinstance(auth.get("client_token"), str) and bool(auth["client_token"]))
    return auth, signed


def reject_unchanged(t, instance, label, path, body, *, bearer="", wrap=None):
    before = durable_manifest(instance.root / "data")
    denied = t.call(label, path, body, bearer=bearer, expected=400, wrap=wrap)
    t.check(label + ".no_publication", not denied.get("auth") and not denied.get("wrap_info")
            and durable_manifest(instance.root / "data") == before)


def run_upgrade(instance, issuer, private, jwk, candidate, legacy, rows):
    t, key, saved = prepare_legacy(instance, issuer, private, jwk, rows)
    store = instance.root / "data"
    instance.stop()
    old_application = durable_manifest(store, application_only=True)
    restart(instance, candidate, key, t, "current")
    t.check("current.reopen_preserves_application", durable_manifest(store, application_only=True) == old_application)
    before = durable_manifest(store)
    value = t.call("current.kv", VALUE_PATH, method="GET")
    t.check("current.value_preserved", value.get("data", {}).get("data") == {"synthetic": True})
    for mode, record in saved.items():
        prefix = "current." + mode
        role = t.call(prefix + ".old_role", paths(mode)[1], method="GET").get("data", {})
        t.check(prefix + ".old_fields_preserved", retained_role_readback(role, record["role"]))
        for kind in ("auth", "child"):
            t.call(prefix + ".old_" + kind + "_active", "auth/token/lookup-self", method="GET",
                   bearer=record[kind]["client_token"])
    t.check("current.reads_preserve_entire_store", durable_manifest(store) == before)
    new_auth, assertions, snapshots = {}, [], {}
    for mode, record in saved.items():
        prefix = "migration." + mode
        _, role_path, login_path = paths(mode)
        t.call(prefix + ".bind", role_path, {"role_type":"jwt", "bound_claims": BOUNDS}, expected=204)
        role = t.call(prefix + ".read_bound", role_path, method="GET").get("data", {})
        t.check(prefix + ".typed_map", role.get("bound_claims_type") == "string"
                and role.get("bound_claims") == BOUNDS and type(role["bound_claims"]["value"]) is int
                and type(role["bound_claims"]["/context/enabled"]) is bool)
        reject_unchanged(t, instance, prefix + ".old_assertion_denied", login_path,
                         {"role":"app", "jwt":record["signed"]})
        rejected = token(private, jwk, issuer.origin, value=[42], context={"enabled":True})
        assertions.append(rejected)
        reject_unchanged(t, instance, prefix + ".wrapped_array_denied", login_path,
                         {"role":"app", "jwt":rejected}, wrap="60s")
        issued, signed = accepted_login(t, prefix + ".scalar_accepted", mode, private, jwk, issuer,
                                       record, {"value":42.9, "context":{"enabled":True}})
        new_auth[mode] = issued
        assertions.append(signed)
        for entry in ("renew-self", "renew", "renew-accessor"):
            auth = record["auth"]
            body = {"increment":300}
            bearer = None
            if entry == "renew-self": bearer = auth["client_token"]
            elif entry == "renew": body["token"] = auth["client_token"]
            else: body["accessor"] = auth["accessor"]
            renewed = t.call(prefix + ".old_" + entry.replace('-', '_'), "auth/token/" + entry, body, bearer=bearer)
            t.check(prefix + ".old_" + entry.replace('-', '_') + ".snapshot", renewed.get("auth", {}).get("token_policies") == auth["token_policies"])
        t.call(prefix + ".child_renews", "auth/token/renew-self", {"increment":120}, bearer=record["child"]["client_token"])
        # A separate numeric rule proves that JSON float category survives the
        # durable round trip; 42.0 is deliberately not the bound number 42.
        float_role = old_role() | {"bound_claims":{"value":42.0}}
        t.call(prefix + ".float_role", role_path.rsplit('/', 1)[0] + "/float", float_role, expected=204)
        snapshots[mode] = t.call(prefix + ".snapshot", role_path, method="GET").get("data", {})
    instance.stop()
    final_application = durable_manifest(store, application_only=True)
    restart(instance, candidate, key, t, "reopen")
    t.check("reopen.application_unchanged", durable_manifest(store, application_only=True) == final_application)
    for mode, record in saved.items():
        role_path = paths(mode)[1]
        role = t.call("reopen." + mode + ".role", role_path, method="GET").get("data", {})
        t.check("reopen." + mode + ".role_exact", role == snapshots[mode])
        floating = t.call("reopen." + mode + ".float_role", role_path.rsplit('/', 1)[0] + "/float", method="GET").get("data", {})
        t.check("reopen." + mode + ".float_category", type(floating.get("bound_claims", {}).get("value")) is float)
        signed = token(private, jwk, issuer.origin, value=42)
        assertions.append(signed)
        reject_unchanged(t, instance, "reopen." + mode + ".float_bound_denied", paths(mode)[2], {"role":"float", "jwt":signed})
    instance.stop()
    final_application = durable_manifest(store, application_only=True)
    instance.binary = legacy
    instance.start()
    t.call("downgrade.unseal_rejected", "sys/unseal", {"key":key}, expected=503)
    t.call("downgrade.remains_sealed", "sys/health", method="GET", expected=503)
    instance.stop()
    t.check("downgrade.application_unchanged", durable_manifest(store, application_only=True) == final_application)
    restart(instance, candidate, key, t, "recovery")
    t.check("recovery.application_unchanged", durable_manifest(store, application_only=True) == final_application)
    for mode, record in saved.items():
        for kind, auth in [("old", record["auth"]), ("child", record["child"]), ("new", new_auth[mode])]:
            t.call("recovery." + mode + "." + kind, "auth/token/lookup-self", method="GET", bearer=auth["client_token"])
        auth, signed = accepted_login(t, "recovery." + mode + ".matching", mode, private, jwk, issuer,
                                      record, {"value":42.9, "context":{"enabled":True}})
        assertions += [signed, auth["client_token"]]
        reject_unchanged(t, instance, "recovery." + mode + ".old_assertion_denied", paths(mode)[2],
                         {"role":"app", "jwt":record["signed"]})
    instance.stop()
    sensitive = [key, instance.token, *assertions,
                 *(r[k]["client_token"] for r in saved.values() for k in ("auth", "child")),
                 *(r["signed"] for r in saved.values()), *(a["client_token"] for a in new_auth.values())]
    files = [path for path in store.rglob('*') if path.is_file()] + [instance.root / "server.log", instance.root / "audit.jsonl"]
    t.check("plaintext_credentials_absent", all(secret.encode() not in path.read_bytes()
            for secret in sensitive for path in files if path.exists()))
    t.check("complete", True)


def required_cases(prepare):
    names = {"legacy.complete"}
    for mode in MODES:
        names |= {"legacy." + mode + "." + suffix for suffix in
                  ("role_has_no_new_fields", "token", "child_token", "unsupported_does_not_mutate")}
    if prepare:
        names.add("legacy.plaintext_credentials_absent")
    else:
        names |= {"current.reopen_preserves_application", "current.reads_preserve_entire_store",
                  "reopen.application_unchanged", "downgrade.unseal_rejected", "downgrade.application_unchanged",
                  "recovery.application_unchanged", "plaintext_credentials_absent", "complete"}
        for mode in MODES:
            names |= {"current." + mode + ".old_fields_preserved",
                      "migration." + mode + ".typed_map",
                      "migration." + mode + ".old_assertion_denied.no_publication",
                      "migration." + mode + ".wrapped_array_denied.no_publication",
                      "migration." + mode + ".scalar_accepted.identity",
                      "migration." + mode + ".child_renews",
                      "reopen." + mode + ".role_exact", "reopen." + mode + ".float_category",
                      "reopen." + mode + ".float_bound_denied.no_publication",
                      "recovery." + mode + ".matching.identity",
                      "recovery." + mode + ".old_assertion_denied.no_publication"}
            names |= {"migration." + mode + ".old_" + entry + ".snapshot"
                      for entry in ("renew_self", "renew", "renew_accessor")}
    return {"jwt_bound_upgrade." + name for name in names}


def complete(rows, prepare):
    if not isinstance(rows, list) or not rows:
        return False
    if any(not isinstance(row, dict) or not isinstance(row.get("case"), str)
           or row.get("passed") is not True for row in rows):
        return False
    names = [row["case"] for row in rows]
    return len(names) == len(set(names)) and required_cases(prepare).issubset(names)


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
    admit_legacy_receipt(args.expected_legacy_sha256, json.loads(LEGACY_RECEIPT.read_text()))
    if args.prepare_legacy:
        if args.binary is not None or args.build_source_commit != LEGACY_SOURCE or file_hash(legacy) != LEGACY_SHA256:
            parser.error("prepare requires only the pinned historical binary/source")
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
    root = Path(tempfile.mkdtemp(prefix="heptabao-jwt-bound-upgrade-"))
    root.chmod(0o700)
    instance = issuer = None
    rows, failure = [], None
    try:
        instance = Instance(legacy, root / "candidate")
        settings = json.loads((instance.root / "server.json").read_text())
        settings.update(lifecycle_interval_seconds=0, outbound_endpoints=[])
        private_write(instance.root / "server.json", settings)
        issuer = bounded_issuer(instance.root / "tls.crt", instance.root / "tls.key")
        private, jwk = signing_key("ES256", "synthetic-bound-upgrade")
        issuer.documents["/keys"] = {"keys": [jwk]}
        if args.prepare_legacy:
            t, key, saved = prepare_legacy(instance, issuer, private, jwk, rows)
            instance.stop()
            sensitive = [key, instance.token, *(r["signed"] for r in saved.values()),
                         *(r[k]["client_token"] for r in saved.values() for k in ("auth", "child"))]
            files = [p for p in (instance.root / "data").rglob('*') if p.is_file()]
            files += [instance.root / "server.log", instance.root / "audit.jsonl"]
            t.check("legacy.plaintext_credentials_absent", all(secret.encode() not in p.read_bytes()
                    for secret in sensitive for p in files if p.exists()))
        else:
            run_upgrade(instance, issuer, private, jwk, candidate, legacy, rows)
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
    runner_unchanged = file_hash(Path(__file__)) == runner_hash
    if not binaries_unchanged or not source_unchanged or not runner_unchanged:
        failure = "source_binary_or_runner_changed"
    if not complete(rows, args.prepare_legacy):
        failure = failure or "incomplete_observations"
    report = {"schema":"heptabao.jwt-bound-claims-upgrade.v1", "status":"passed" if failure is None else "failed",
        "from_schema":29, "minimum_to_schema":None if args.prepare_legacy else 30,
        "prepare_legacy_only":args.prepare_legacy, "failure":failure, "cases":rows,
        "source_identity":before, "source_and_binary_unchanged":source_unchanged,
        "legacy_source_commit":LEGACY_SOURCE, "legacy_binary_sha256":legacy_hash,
        "legacy_receipt_sha256":file_hash(LEGACY_RECEIPT),
        "candidate_binary_sha256":None if args.prepare_legacy else candidate_hash,
        "build_source_commit":args.build_source_commit,
        "build_source_binding_basis":"caller-supplied build commit and observed binary hash, not independent attestation",
        "binaries_unchanged":binaries_unchanged, "runner_sha256":runner_hash, "runner_unchanged":runner_unchanged,
        "candidate_startup_enrollment_empty":True, "reopen_replay_ledger_may_change":True,
        "application_artifact_scope":"all store entries except root ledger.hbl, rebuilt before schema validation",
        "synthetic_only":True, "oidc_covered":False, "rolling_upgrade_qualification":False,
        "full_migration_qualification":False, "independent_qualification":False, "production_authority":False}
    if admit_output(output) != admitted:
        raise ValueError("report_parent_changed")
    private_write(output, report, replace=False)
    print(json.dumps({"status":report["status"], "checks":len(rows), "failure":failure}))
    return 0 if failure is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
