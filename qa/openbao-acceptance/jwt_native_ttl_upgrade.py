#!/usr/bin/env python3
"""Actual schema-31 JWT roles -> native mount TTL defaults -> refused downgrade.

The historical process creates every old role and token. Historical pin fields
must be fixed from a clean runtime receipt before this runner can execute.
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
from radius_renewal_live import renewal_token_shape
from remote_jwks_live import Instance, signing_key, token

# Pinned to the real schema-31 build and its clean runtime receipt. Missing
# pins are rejected; no caller-supplied fallback or fabricated state is accepted.
LEGACY_SOURCE = "d2c669d2b270563dfe4ea524161dcf4b68a6bb25"
LEGACY_SHA256 = "157b71ff82f0054953551245eaf2bbf6e91cb2d51239b4d217440cbca855b20d"
LEGACY_RECEIPT = ROOT / "qa/openbao-acceptance/evidence/kubernetes-cidrs-d2c669d.json"
MODES = ("static", "remote")
VALUE_PATH = "secret/data/jwt-native-ttl-upgrade"
DURATION_FIELDS = ("token_ttl", "token_max_ttl", "token_period", "token_explicit_max_ttl")


def require_legacy_pin():
    if (not isinstance(LEGACY_SOURCE, str) or re.fullmatch(r"[0-9a-f]{40}", LEGACY_SOURCE) is None
            or not isinstance(LEGACY_SHA256, str) or re.fullmatch(r"[0-9a-f]{64}", LEGACY_SHA256) is None
            or not isinstance(LEGACY_RECEIPT, Path)):
        raise ValueError("legacy_schema31_pin_not_available")


def admit_legacy_receipt(expected, receipt):
    require_legacy_pin()
    source = receipt.get("candidate_source", {})
    if (expected != LEGACY_SHA256 or receipt.get("status") != "passed"
            or receipt.get("build_source_commit") != LEGACY_SOURCE
            or receipt.get("source_and_binary_unchanged") is not True
            or receipt.get("runner_unchanged") is not True
            or source.get("source_commit") != LEGACY_SOURCE
            or source.get("source_dirty") is not False
            or source.get("binary_sha256") != LEGACY_SHA256):
        raise ValueError("legacy_schema31_receipt_mismatch")


class Trace:
    def __init__(self, client, issuer, rows):
        self.client, self.issuer, self.rows = client, issuer, rows
        self.secrets = []

    def check(self, label, condition, **observed):
        if (not isinstance(label, str) or re.fullmatch(r"[a-z0-9_.]{1,150}", label) is None
                or any(type(value) not in (int, bool) for value in observed.values())):
            raise Failure("invalid_observation_shape")
        name = "jwt_native_ttl_upgrade." + label
        self.rows.append({"case":name, **observed, "passed":condition is True})
        if condition is not True:
            raise Failure(name)

    def call(self, label, path, body=None, *, method="POST", bearer=None, expected=200, no_provider=False):
        before = len(self.issuer.calls)
        result = self.client.request(method, "/v1/" + path, body, token=bearer)
        self.check(label, result.status == expected and (not no_provider or len(self.issuer.calls) == before),
                   status=result.status)
        if no_provider:
            self.check(label + ".no_provider", len(self.issuer.calls) == before)
        return result.body

    def lookup(self, label, auth):
        return self.call(label, "auth/token/lookup-self", method="GET",
                         bearer=auth["client_token"], no_provider=True).get("data", {})


def paths(mode, name="app"):
    mount = "ttl-upgrade-" + mode
    return mount, "auth/" + mount + "/role/" + name, "auth/" + mount + "/login"


def legacy_configuration(mode, issuer, jwk, ca):
    if mode == "static":
        return {"issuer":issuer.origin, "audiences":["heptabao-test"], "jwks":{"keys":[jwk]}}
    return {"bound_issuer":issuer.origin, "jwks_url":issuer.origin + "/keys",
            "jwks_ca_pem":ca, "jwt_supported_algs":["ES256"]}


def old_role():
    # Omissions are essential: schema 31 must write its actual 3600/3600 defaults.
    return {"role_type":"jwt", "user_claim":"sub", "bound_audiences":["heptabao-test"],
            "token_policies":["default", "ttl-upgrade-child"]}


def issue(t, label, mode, private, jwk, issuer, *, role_name="app", lease):
    signed = token(private, jwk, issuer.origin)
    auth = t.call(label, paths(mode)[2], {"role":role_name, "jwt":signed}, bearer="").get("auth", {})
    t.check(label + ".issued", all(isinstance(auth.get(f), str) and bool(auth[f])
            for f in ("client_token", "accessor", "entity_id")) and auth.get("renewable") is True
            and auth.get("lease_duration") == lease)
    t.secrets.extend([signed, auth["client_token"]])
    return auth


def prepare_legacy(instance, issuer, private, jwk, rows):
    instance.start()
    status, initialized = instance.call("POST", "sys/init", {"secret_shares":1, "secret_threshold":1})
    if status != 200:
        raise Failure("legacy_initialization_failed")
    instance.token, key = initialized["root_token"], initialized["keys_base64"][0]
    t = Trace(Client(instance.address, str(instance.root / "ca.crt"), instance.token), issuer, rows)
    t.secrets.extend([key, instance.token])
    t.call("legacy.unseal", "sys/unseal", {"key":key})
    t.call("legacy.kv", VALUE_PATH, {"data":{"synthetic":True}})
    t.call("legacy.child_policy", "sys/policies/acl/ttl-upgrade-child",
           {"policy":'path "auth/token/create" { capabilities = ["update"] }'}, expected=204)
    saved = {}
    for mode in MODES:
        mount, role_path, _ = paths(mode)
        prefix = "legacy." + mode
        t.call(prefix + ".mount", "sys/auth/" + mount, {"type":"jwt"}, expected=204)
        t.call(prefix + ".tune", "sys/auth/" + mount + "/tune",
               {"default_lease_ttl":75, "max_lease_ttl":600}, expected=204)
        t.call(prefix + ".config", "auth/" + mount + "/config",
               legacy_configuration(mode, issuer, jwk, (instance.root / "ca.crt").read_text()), expected=204)
        payload = old_role()
        t.check(prefix + ".role_omits_durations", not set(DURATION_FIELDS).intersection(payload))
        t.call(prefix + ".role", role_path, payload, expected=204)
        role = t.call(prefix + ".role_read", role_path, method="GET").get("data", {})
        t.check(prefix + ".stored_old_defaults", role.get("token_ttl") == 3600 and role.get("token_max_ttl") == 3600)
        auth = issue(t, prefix + ".login", mode, private, jwk, issuer, lease=600)
        child = t.call(prefix + ".child", "auth/token/create", {"policies":["default"], "ttl":300},
                       bearer=auth["client_token"]).get("auth", {})
        t.check(prefix + ".child_issued", isinstance(child.get("client_token"), str) and bool(child["client_token"]))
        t.secrets.append(child["client_token"])
        periodic_role = old_role() | {"token_ttl":120, "token_max_ttl":600,
                                     "token_period":180, "token_explicit_max_ttl":480}
        t.call(prefix + ".periodic_role", paths(mode, "periodic")[1], periodic_role, expected=204)
        periodic = issue(t, prefix + ".periodic_login", mode, private, jwk, issuer, role_name="periodic", lease=180)
        periodic_read = t.call(prefix + ".periodic_read", paths(mode, "periodic")[1], method="GET").get("data", {})
        snapshot = t.lookup(prefix + ".periodic_snapshot", periodic)
        t.check(prefix + ".issued_caps", snapshot.get("period") == 180 and snapshot.get("explicit_max_ttl") == 480)
        before = durable_manifest(instance.root / "data")
        t.call(prefix + ".zero_rejected", role_path, {"role_type":"jwt", "token_ttl":0, "token_max_ttl":0}, expected=400)
        t.check(prefix + ".rejection_does_not_mutate", durable_manifest(instance.root / "data") == before)
        saved[mode] = {"auth":auth, "child":child, "periodic":periodic, "role":role,
                       "periodic_role":periodic_read, "periodic_snapshot":snapshot}
    t.check("legacy.complete", True)
    return t, key, saved


def restart(instance, binary, key, t, label):
    instance.stop()
    instance.binary = binary
    instance.start()
    t.call(label + ".unseal", "sys/unseal", {"key":key})


def renew_all(t, label, auth, *, lease=None):
    for entry in ("renew-self", "renew", "renew-accessor"):
        body, bearer = {"increment":900}, None
        if entry == "renew-self":
            bearer = auth["client_token"]
        elif entry == "renew":
            body["token"] = auth["client_token"]
        else:
            body["accessor"] = auth["accessor"]
        name = label + "." + entry.replace('-', '_')
        renewed = t.call(name, "auth/token/" + entry, body, bearer=bearer, no_provider=True).get("auth", {})
        t.check(name + ".shape", renewal_token_shape(renewed, auth["client_token"], via_accessor=entry == "renew-accessor")
                and (lease is None or renewed.get("lease_duration") == lease))


def caps_preserved(current, issued):
    return (current.get("period") == issued.get("period") == 180
            and current.get("explicit_max_ttl") == issued.get("explicit_max_ttl") == 480
            and current.get("creation_time") == issued.get("creation_time")
            and type(current.get("creation_time")) is int
            and current.get("expire_time_unix") == current["creation_time"] + 480)


def scan_storage(root, secrets):
    store = root / "data"
    files = [p for p in store.rglob('*') if p.is_file()]
    if not files or not (root / "server.log").is_file() or not secrets or any(not s for s in secrets):
        return False
    files += [p for p in (root / "server.log", root / "audit.jsonl") if p.is_file()]
    return all(secret.encode() not in path.read_bytes() for secret in secrets for path in files)


def run_upgrade(instance, issuer, private, jwk, candidate, legacy, rows):
    t, key, saved = prepare_legacy(instance, issuer, private, jwk, rows)
    store = instance.root / "data"
    instance.stop()
    application = durable_manifest(store, application_only=True)
    for phase in ("current", "untouched_restart"):
        restart(instance, candidate, key, t, phase)
        t.check(phase + ".application_unchanged", durable_manifest(store, application_only=True) == application)
        before = durable_manifest(store)
        value = t.call(phase + ".kv", VALUE_PATH, method="GET")
        t.check(phase + ".value_preserved", value.get("data", {}).get("data") == {"synthetic":True})
        for mode, record in saved.items():
            for name, previous in (("app", record["role"]), ("periodic", record["periodic_role"])):
                read = t.call(phase + "." + mode + "." + name, paths(mode, name)[1], method="GET").get("data", {})
                t.check(phase + "." + mode + "." + name + ".exact", read == previous)
            for kind in ("auth", "child", "periodic"):
                t.lookup(phase + "." + mode + ".token_" + kind, record[kind])
        t.check(phase + ".reads_preserve_entire_store", durable_manifest(store) == before)
    new_auth, snapshots = {}, {}
    for mode, record in saved.items():
        prefix = "migration." + mode
        mount, role_path, _ = paths(mode)
        before = durable_manifest(store)
        for name, previous in (("app", record["role"]), ("periodic", record["periodic_role"])):
            t.call(prefix + "." + name + ".null", paths(mode, name)[1],
                   {"role_type":"jwt", **{field:None for field in DURATION_FIELDS}}, expected=204)
            read = t.call(prefix + "." + name + ".null_read", paths(mode, name)[1], method="GET").get("data", {})
            t.check(prefix + "." + name + ".null_preserves_exact", read == previous)
        t.check(prefix + ".null_does_not_publish", durable_manifest(store) == before)
        t.call(prefix + ".zero", role_path, {"role_type":"jwt", "token_ttl":0, "token_max_ttl":0}, expected=204)
        role = t.call(prefix + ".zero_read", role_path, method="GET").get("data", {})
        t.check(prefix + ".zero_read_exact", role == record["role"] | {"token_ttl":0, "token_max_ttl":0})
        issued = issue(t, prefix + ".inherited_login", mode, private, jwk, issuer, lease=75)
        # New omissions now persist zero, not a guessed rewrite of old roles.
        t.call(prefix + ".fresh_role", paths(mode, "fresh")[1], old_role(), expected=204)
        fresh_role = t.call(prefix + ".fresh_read", paths(mode, "fresh")[1], method="GET").get("data", {})
        t.check(prefix + ".fresh_defaults_zero", fresh_role.get("token_ttl") == 0 and fresh_role.get("token_max_ttl") == 0)
        fresh = issue(t, prefix + ".fresh_login", mode, private, jwk, issuer, role_name="fresh", lease=75)
        t.call(prefix + ".retune", "sys/auth/" + mount + "/tune",
               {"default_lease_ttl":95, "max_lease_ttl":1200}, expected=204)
        # The newly configured explicit cap only governs future logins.
        t.call(prefix + ".new_explicit_cap", role_path, {"role_type":"jwt", "token_explicit_max_ttl":600}, expected=204)
        renew_all(t, prefix + ".old_uncapped", record["auth"], lease=900)
        renew_all(t, prefix + ".new_uncapped", issued, lease=900)
        unchanged_cap = t.lookup(prefix + ".uncapped_snapshot", record["auth"])
        t.check(prefix + ".old_explicit_stays_zero", unchanged_cap.get("explicit_max_ttl") == 0 and unchanged_cap.get("period", 0) == 0)
        renewed = t.call(prefix + ".fresh_mount_default", "auth/token/renew-self", {}, bearer=fresh["client_token"], no_provider=True)
        t.check(prefix + ".current_mount_default_used", renewed.get("auth", {}).get("lease_duration") == 95)
        t.call(prefix + ".periodic_zero", paths(mode, "periodic")[1],
               {"role_type":"jwt", **{field:0 for field in DURATION_FIELDS}}, expected=204)
        renew_all(t, prefix + ".issued_cap", record["periodic"])
        cap = t.lookup(prefix + ".issued_cap_lookup", record["periodic"])
        t.check(prefix + ".issued_cap_and_period_preserved", caps_preserved(cap, record["periodic_snapshot"]))
        t.call(prefix + ".child_renews", "auth/token/renew-self", {"increment":300}, bearer=record["child"]["client_token"], no_provider=True)
        future = issue(t, prefix + ".future_without_old_cap", mode, private, jwk, issuer, role_name="periodic", lease=95)
        future_info = t.lookup(prefix + ".future_snapshot", future)
        t.check(prefix + ".future_has_no_issued_cap_or_period", future_info.get("explicit_max_ttl") == 0 and future_info.get("period", 0) == 0)
        new_auth[mode] = {"inherited":issued, "fresh":fresh, "future":future}
        snapshots[mode] = {name:t.call(prefix + ".snapshot_" + name, paths(mode, name)[1], method="GET").get("data", {})
                           for name in ("app", "periodic", "fresh")}
    instance.stop()
    application = durable_manifest(store, application_only=True)
    restart(instance, candidate, key, t, "reopen")
    t.check("reopen.application_unchanged", durable_manifest(store, application_only=True) == application)
    for mode, roles in snapshots.items():
        for name, previous in roles.items():
            read = t.call("reopen." + mode + "." + name, paths(mode, name)[1], method="GET").get("data", {})
            t.check("reopen." + mode + "." + name + ".exact", read == previous)
        cap = t.lookup("reopen." + mode + ".issued_cap", saved[mode]["periodic"])
        t.check("reopen." + mode + ".issued_caps_exact", caps_preserved(cap, saved[mode]["periodic_snapshot"]))
    instance.stop()
    application = durable_manifest(store, application_only=True)
    instance.binary = legacy
    instance.start()
    t.call("downgrade.unseal_rejected", "sys/unseal", {"key":key}, expected=503)
    t.call("downgrade.remains_sealed", "sys/health", method="GET", expected=503)
    instance.stop()
    t.check("downgrade.application_unchanged", durable_manifest(store, application_only=True) == application)
    restart(instance, candidate, key, t, "recovery")
    t.check("recovery.application_unchanged", durable_manifest(store, application_only=True) == application)
    for mode, record in saved.items():
        for kind in ("auth", "child", "periodic"):
            t.lookup("recovery." + mode + ".old_" + kind, record[kind])
        for kind, auth in new_auth[mode].items():
            t.lookup("recovery." + mode + ".new_" + kind, auth)
        renew_all(t, "recovery." + mode + ".old_uncapped", record["auth"], lease=900)
        renew_all(t, "recovery." + mode + ".issued_cap", record["periodic"])
        cap = t.lookup("recovery." + mode + ".issued_cap_lookup", record["periodic"])
        t.check("recovery." + mode + ".issued_caps_exact", caps_preserved(cap, record["periodic_snapshot"]))
        issue(t, "recovery." + mode + ".fresh_login", mode, private, jwk, issuer, role_name="fresh", lease=95)
    instance.stop()
    t.check("plaintext_credentials_absent", scan_storage(instance.root, t.secrets))
    t.check("complete", True)


def required_cases(prepare):
    names = {"legacy.complete"}
    for mode in MODES:
        names |= {"legacy." + mode + "." + suffix for suffix in
                  ("role_omits_durations", "stored_old_defaults", "login.issued", "child_issued",
                   "periodic_login.issued", "issued_caps", "rejection_does_not_mutate")}
    if prepare:
        names.add("legacy.plaintext_credentials_absent")
    else:
        names |= {phase + "." + suffix for phase in ("current", "untouched_restart")
                  for suffix in ("application_unchanged", "reads_preserve_entire_store")}
        names |= {"reopen.application_unchanged", "downgrade.unseal_rejected", "downgrade.remains_sealed",
                  "downgrade.application_unchanged", "recovery.application_unchanged", "plaintext_credentials_absent", "complete"}
        for mode in MODES:
            for phase in ("current", "untouched_restart"):
                names |= {phase + "." + mode + "." + name + ".exact" for name in ("app", "periodic")}
            names |= {"migration." + mode + "." + suffix for suffix in
                      ("app.null_preserves_exact", "periodic.null_preserves_exact", "null_does_not_publish",
                       "zero_read_exact", "inherited_login.issued", "fresh_defaults_zero", "fresh_login.issued",
                       "old_explicit_stays_zero", "current_mount_default_used", "issued_cap_and_period_preserved",
                       "child_renews", "future_has_no_issued_cap_or_period")}
            for phase in ("migration", "recovery"):
                for kind in ("old_uncapped", "issued_cap"):
                    names |= {phase + "." + mode + "." + kind + "." + entry + suffix
                              for entry in ("renew_self", "renew", "renew_accessor") for suffix in (".shape", ".no_provider")}
            names |= {"reopen." + mode + "." + name + ".exact" for name in ("app", "periodic", "fresh")}
            names |= {"reopen." + mode + ".issued_caps_exact", "recovery." + mode + ".issued_caps_exact",
                      "recovery." + mode + ".fresh_login.issued"}
            names |= {"recovery." + mode + "." + kind for kind in
                      ("old_auth", "old_child", "old_periodic", "new_inherited", "new_fresh", "new_future")}
    return {"jwt_native_ttl_upgrade." + name for name in names}


def complete(rows, prepare):
    if not isinstance(rows, list) or not rows:
        return False
    if any(not isinstance(row, dict) or not isinstance(row.get("case"), str)
           or re.fullmatch(r"jwt_native_ttl_upgrade\.[a-z0-9_.]{1,150}", row["case"]) is None
           or row.get("passed") is not True
           or any(type(v) not in (int, bool) for k,v in row.items() if k not in ("case", "passed")) for row in rows):
        return False
    names = [row["case"] for row in rows]
    end = "legacy.plaintext_credentials_absent" if prepare else "complete"
    return (len(names) == len(set(names)) and required_cases(prepare).issubset(names)
            and names[-1] == "jwt_native_ttl_upgrade." + end)


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--prepare-legacy", action="store_true")
    for name in ("legacy-binary", "expected-legacy-sha256", "build-source-commit", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    require_legacy_pin()
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
    root = Path(tempfile.mkdtemp(prefix="heptabao-jwt-native-ttl-upgrade-"))
    root.chmod(0o700)
    instance = issuer = None
    rows, failure = [], None
    try:
        instance = Instance(legacy, root / "candidate")
        settings = json.loads((instance.root / "server.json").read_text())
        settings.update(lifecycle_interval_seconds=0, outbound_endpoints=[])
        private_write(instance.root / "server.json", settings)
        issuer = bounded_issuer(instance.root / "tls.crt", instance.root / "tls.key")
        private, jwk = signing_key("ES256", "synthetic-native-ttl-upgrade")
        issuer.documents["/keys"] = {"keys":[jwk]}
        if args.prepare_legacy:
            t, _, _ = prepare_legacy(instance, issuer, private, jwk, rows)
            instance.stop()
            t.check("legacy.plaintext_credentials_absent", scan_storage(instance.root, t.secrets))
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
    report = {"schema":"heptabao.jwt-native-ttl-upgrade.v1", "status":"passed" if failure is None else "failed",
        "from_schema":31, "minimum_to_schema":None if args.prepare_legacy else 32,
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
