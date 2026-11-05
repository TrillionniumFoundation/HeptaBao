#!/usr/bin/env python3
"""Actual schema-32 token defaults -> schema-33 migration and fresh defaults.

Two old-process stores distinguish inherited one-hour defaults from explicit
token-mount tuning. A separate fresh store proves the new-install default.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import tempfile

from bao_http import Client, SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from identity_upgrade import validate_binary_pins
from jwt_native_ttl_upgrade import scan_storage
from online_evidence import admit_output, source_identity
from provider_renewal_upgrade import durable_manifest
from radius_renewal_live import renewal_token_shape
from smoke import Instance

# Pinned to the real clean schema-32 runtime receipt. Missing pins are a hard
# refusal; no serialized-state fabrication is supported.
LEGACY_SOURCE = "4d5b6b8b043d5fa058af1ca82e4af3cffb4342c0"
LEGACY_SHA256 = "bcf18f5b729b441acf1b2376bb2e6c5bd638112ec68c3a1fd1ab9a67b03362a0"
LEGACY_RECEIPT = ROOT / "qa/openbao-acceptance/evidence/jwt-native-ttl-4d5b6b8.json"
OLD_DEFAULT = 3600
MAX_TTL = 32 * 24 * 3600
PROFILES = ("default", "tuned")
TUNE = "sys/auth/token/tune"
ROLE = "auth/approle/role/preserved"
VALUE = "secret/data/token-defaults-upgrade"


def require_legacy_pin():
    if (not isinstance(LEGACY_SOURCE, str) or re.fullmatch(r"[0-9a-f]{40}", LEGACY_SOURCE) is None
            or not isinstance(LEGACY_SHA256, str) or re.fullmatch(r"[0-9a-f]{64}", LEGACY_SHA256) is None
            or not isinstance(LEGACY_RECEIPT, Path)):
        raise ValueError("legacy_schema32_pin_not_available")


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
        raise ValueError("legacy_schema32_receipt_mismatch")


class Trace:
    def __init__(self, instance, profile, rows):
        self.instance, self.profile, self.rows = instance, profile, rows
        self.client = Client(instance.address, str(instance.root / "ca.crt"), instance.token)
        self.secrets = [instance.token]

    def check(self, label, condition, **observed):
        if (not isinstance(label, str) or re.fullmatch(r"[a-z0-9_.]{1,150}", label) is None
                or any(type(value) not in (int, bool) for value in observed.values())):
            raise ScenarioFailure("invalid_observation_shape")
        name = "token_defaults_upgrade." + self.profile + "." + label
        self.rows.append({"case":name, **observed, "passed":condition is True})
        if condition is not True:
            raise ScenarioFailure(name)

    def call(self, label, path, body=None, *, method="POST", bearer=None, expected=200):
        result = self.client.request(method, "/v1/" + path, body, token=bearer)
        self.check(label, result.status == expected, status=result.status)
        return result.body

    def lookup(self, label, auth):
        return self.call(label, "auth/token/lookup", {"token":auth["client_token"]}).get("data", {})

    def issue(self, label, *, lease, body=None, bearer=None):
        body = {"policies":["default"]} | (body or {})
        auth = self.call(label, "auth/token/create", body, bearer=bearer).get("auth", {})
        self.check(label + ".issued", all(isinstance(auth.get(f), str) and bool(auth[f])
                   for f in ("client_token", "accessor")) and auth.get("renewable") is True
                   and auth.get("lease_duration") == lease)
        self.secrets.append(auth["client_token"])
        return auth

    def renew(self, label, auth, *, lease=None, increment=None, max_lease=None):
        for entry in ("renew-self", "renew", "renew-accessor"):
            body = {} if increment is None else {"increment":increment}
            bearer = None
            if entry == "renew-self":
                bearer = auth["client_token"]
            elif entry == "renew":
                body["token"] = auth["client_token"]
            else:
                body["accessor"] = auth["accessor"]
            name = label + "." + entry.replace('-', '_')
            auth_body = self.call(name, "auth/token/" + entry, body, bearer=bearer).get("auth", {})
            grant = auth_body.get("lease_duration")
            self.check(name + ".shape", renewal_token_shape(auth_body, auth["client_token"], via_accessor=entry == "renew-accessor")
                       and type(grant) is int and grant > 0
                       and (lease is None or grant == lease) and (max_lease is None or grant <= max_lease),
                       lease_duration=grant if type(grant) is int else -1)


def initialize(instance, profile, rows):
    instance.start()
    status, initialized = instance.call("POST", "sys/init", {"secret_shares":1, "secret_threshold":1})
    if status != 200:
        raise ScenarioFailure("token_defaults_upgrade.initialization_failed")
    instance.token, key = initialized["root_token"], initialized["keys_base64"][0]
    t = Trace(instance, profile, rows)
    t.secrets.append(key)
    t.call("initialize.unseal", "sys/unseal", {"key":key})
    return t, key


def prepare_legacy(instance, profile, rows):
    t, key = initialize(instance, profile, rows)
    t.call("legacy.value", VALUE, {"data":{"synthetic":True}})
    t.call("legacy.child_policy", "sys/policies/acl/token-upgrade-child",
           {"policy":'path "auth/token/create" { capabilities = ["update"] }'}, expected=204)
    if profile == "tuned":
        t.call("legacy.tune", TUNE, {"default_lease_ttl":75, "max_lease_ttl":600}, expected=204)
    tune = t.call("legacy.tune_read", TUNE, method="GET").get("data", {})
    t.check("legacy.tune_exact", (tune.get("default_lease_ttl"), tune.get("max_lease_ttl")) ==
            ((0,0) if profile == "default" else (75,600)))
    ordinary = t.issue("legacy.ordinary", lease=OLD_DEFAULT, body={"policies":["default", "token-upgrade-child"]})
    child = t.issue("legacy.child", lease=300, body={"ttl":300}, bearer=ordinary["client_token"])
    explicit = t.issue("legacy.explicit", lease=120, body={"ttl":120, "explicit_max_ttl":480})
    periodic = t.issue("legacy.periodic", lease=180, body={"period":180})
    auth = {"ordinary":ordinary, "child":child, "explicit":explicit, "periodic":periodic}
    snapshots = {name:t.lookup("legacy.snapshot_" + name, value) for name,value in auth.items()}
    t.check("legacy.cap_shapes", snapshots["ordinary"].get("explicit_max_ttl") == MAX_TTL
            and snapshots["child"].get("explicit_max_ttl") == MAX_TTL
            and snapshots["explicit"].get("explicit_max_ttl") == 480
            and snapshots["periodic"].get("explicit_max_ttl") == 0
            and snapshots["periodic"].get("period") == 180)
    t.call("legacy.role", ROLE, {"token_policies":["default"], "token_ttl":120, "token_max_ttl":600}, expected=204)
    role = t.call("legacy.role_read", ROLE, method="GET").get("data", {})
    t.check("legacy.role_and_secret_defaults", role.get("token_ttl") == 120 and role.get("token_max_ttl") == 600
            and role.get("secret_id_ttl") == OLD_DEFAULT)
    secret = t.call("legacy.secret_id", ROLE + "/secret-id", {}).get("data", {})
    t.check("legacy.secret_id_default", secret.get("secret_id_ttl") == OLD_DEFAULT and bool(secret.get("secret_id")))
    t.secrets.append(secret["secret_id"])
    t.check("legacy.complete", True)
    return t, key, {"auth":auth, "snapshots":snapshots, "role":role, "tune":tune}


def retained_tune(current, old):
    # New GET resolves inherited values but must retain every other old field;
    # the application-artifact assertion separately proves no stored rewrite.
    return current == old | {"default_lease_ttl":old.get("default_lease_ttl") or OLD_DEFAULT,
                             "max_lease_ttl":old.get("max_lease_ttl") or MAX_TTL}


def retained_lookup(current, old):
    return {k:v for k,v in current.items() if k != "ttl"} == {k:v for k,v in old.items() if k != "ttl"}


def restart(instance, binary, key, t, label):
    instance.stop()
    instance.binary = binary
    instance.start()
    t.call(label + ".unseal", "sys/unseal", {"key":key})


def cap_deadline(current, issued, cap):
    return (current.get("explicit_max_ttl") == cap and current.get("creation_time") == issued.get("creation_time")
            and type(current.get("creation_time")) is int
            and current.get("expire_time_unix") == current["creation_time"] + cap)


def run_upgrade(instance, profile, candidate, legacy, rows):
    t, key, saved = prepare_legacy(instance, profile, rows)
    store = instance.root / "data"
    instance.stop()
    application = durable_manifest(store, application_only=True)
    for phase in ("current", "untouched_restart"):
        restart(instance, candidate, key, t, phase)
        t.check(phase + ".application_unchanged", durable_manifest(store, application_only=True) == application)
        before = durable_manifest(store)
        value = t.call(phase + ".value", VALUE, method="GET")
        t.check(phase + ".value_preserved", value.get("data", {}).get("data") == {"synthetic":True})
        tune = t.call(phase + ".tune", TUNE, method="GET").get("data", {})
        t.check(phase + ".tune_preserved", retained_tune(tune, saved["tune"]))
        role = t.call(phase + ".role", ROLE, method="GET").get("data", {})
        t.check(phase + ".role_exact", role == saved["role"])
        for kind, auth in saved["auth"].items():
            current = t.lookup(phase + "." + kind, auth)
            t.check(phase + "." + kind + ".exact", retained_lookup(current, saved["snapshots"][kind]))
        t.check(phase + ".reads_preserve_entire_store", durable_manifest(store) == before)
    # Failed writes cannot quietly introduce the new format/default marker.
    before = durable_manifest(store)
    denied = t.call("migration.invalid_create", "auth/token/create", {"policies":["default"], "ttl":-1}, expected=400)
    t.check("migration.failure_does_not_publish", not denied.get("auth") and durable_manifest(store) == before)
    inherited = 3600 if profile == "default" else 75
    new = t.issue("migration.first_create", lease=inherited)
    info = t.lookup("migration.new_snapshot", new)
    t.check("migration.new_ordinary_has_no_explicit_cap", info.get("explicit_max_ttl") == 0)
    # Old states have no last-granted TTL field. Their first renewal retains
    # the historical 3600 request, constrained by the current mount maximum.
    t.renew("migration.old_default", saved["auth"]["ordinary"], lease=OLD_DEFAULT if profile == "default" else None)
    old_first = t.lookup("migration.old_default_snapshot", saved["auth"]["ordinary"])
    t.check("migration.old_missing_grant_conservative", old_first.get("explicit_max_ttl") == MAX_TTL
            and (profile == "default" or old_first.get("expire_time_unix") == old_first.get("creation_time", -1) + 600))
    t.renew("migration.new_default", new, lease=inherited)
    # Record explicit grants before changing mount defaults. This makes the
    # following omitted-increment checks exact without using elapsed-time fuzz.
    t.renew("migration.old_record_grant", saved["auth"]["ordinary"], lease=60, increment=60)
    t.renew("migration.new_record_grant", new, lease=40, increment=40)
    old = t.lookup("migration.old_snapshot", saved["auth"]["ordinary"])
    t.check("migration.old_ambiguous_cap_retained", old.get("explicit_max_ttl") == MAX_TTL
            and old.get("creation_time") == saved["snapshots"]["ordinary"].get("creation_time"))
    role = t.call("migration.role", ROLE, method="GET").get("data", {})
    t.check("migration.role_not_rewritten", role == saved["role"])
    t.call("migration.retune", TUNE, {"default_lease_ttl":95, "max_lease_ttl":900}, expected=204)
    t.renew("migration.old_current_tune", saved["auth"]["ordinary"], lease=60)
    t.renew("migration.new_current_tune", new, lease=40)
    t.renew("migration.child_record_grant", saved["auth"]["child"], lease=50, increment=50)
    t.renew("migration.child_current_tune", saved["auth"]["child"], lease=50)
    t.renew("migration.explicit_cap", saved["auth"]["explicit"], increment=900, max_lease=480)
    capped = t.lookup("migration.explicit_snapshot", saved["auth"]["explicit"])
    t.check("migration.issued_explicit_deadline", cap_deadline(capped, saved["snapshots"]["explicit"], 480))
    t.call("migration.period_tune", TUNE, {"default_lease_ttl":95, "max_lease_ttl":120}, expected=204)
    t.renew("migration.period_clamped", saved["auth"]["periodic"], lease=120, increment=900)
    period = t.lookup("migration.period_snapshot", saved["auth"]["periodic"])
    t.check("migration.issued_period_retained", period.get("period") == 180 and period.get("explicit_max_ttl") == 0)
    t.call("migration.restore_tune", TUNE, {"default_lease_ttl":95, "max_lease_ttl":900}, expected=204)
    tune = t.call("migration.final_tune", TUNE, method="GET").get("data", {})
    instance.stop()
    application = durable_manifest(store, application_only=True)
    restart(instance, candidate, key, t, "reopen")
    t.check("reopen.application_unchanged", durable_manifest(store, application_only=True) == application)
    read = t.call("reopen.tune", TUNE, method="GET").get("data", {})
    t.check("reopen.tune_exact", read == tune)
    t.check("reopen.old_cap_retained", t.lookup("reopen.old", saved["auth"]["ordinary"]).get("explicit_max_ttl") == MAX_TTL)
    t.check("reopen.new_cap_absent", t.lookup("reopen.new", new).get("explicit_max_ttl") == 0)
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
    for kind, auth in saved["auth"].items():
        t.lookup("recovery.old_" + kind, auth)
    t.lookup("recovery.new", new)
    t.renew("recovery.old_current_tune", saved["auth"]["ordinary"], lease=60)
    t.renew("recovery.new_current_tune", new, lease=40)
    t.renew("recovery.explicit_cap", saved["auth"]["explicit"], increment=900, max_lease=480)
    capped = t.lookup("recovery.explicit_snapshot", saved["auth"]["explicit"])
    t.check("recovery.issued_explicit_deadline", cap_deadline(capped, saved["snapshots"]["explicit"], 480))
    t.call("recovery.reset_tune", TUNE, {"default_lease_ttl":0, "max_lease_ttl":0}, expected=204)
    t.issue("recovery.inherited_one_hour", lease=OLD_DEFAULT)
    tune = t.call("recovery.inherited_tune", TUNE, method="GET").get("data", {})
    t.check("recovery.legacy_system_defaults_preserved", tune.get("default_lease_ttl") == OLD_DEFAULT and tune.get("max_lease_ttl") == MAX_TTL)
    instance.stop()
    t.check("plaintext_credentials_absent", scan_storage(instance.root, t.secrets))
    t.check("complete", True)


def run_fresh(instance, candidate, rows):
    t, key = initialize(instance, "fresh", rows)
    tune = t.call("system_tune", TUNE, method="GET").get("data", {})
    t.check("system_defaults", tune.get("default_lease_ttl") == MAX_TTL and tune.get("max_lease_ttl") == MAX_TTL)
    auth = t.issue("default_login", lease=MAX_TTL)
    t.check("ordinary_has_no_explicit_cap", t.lookup("lookup", auth).get("explicit_max_ttl") == 0)
    t.call("role", ROLE, {"token_policies":["default"], "token_ttl":120, "token_max_ttl":600}, expected=204)
    role = t.call("role_read", ROLE, method="GET").get("data", {})
    secret = t.call("secret_id", ROLE + "/secret-id", {}).get("data", {})
    t.check("secret_id_default_still_one_hour", role.get("secret_id_ttl") == OLD_DEFAULT
            and secret.get("secret_id_ttl") == OLD_DEFAULT and bool(secret.get("secret_id")))
    t.secrets.append(secret["secret_id"])
    instance.stop()
    application = durable_manifest(instance.root / "data", application_only=True)
    restart(instance, candidate, key, t, "reopen")
    t.check("reopen.application_unchanged", durable_manifest(instance.root / "data", application_only=True) == application)
    read = t.call("reopen.tune", TUNE, method="GET").get("data", {})
    t.check("reopen.defaults_persist", read == tune)
    t.lookup("reopen.token", auth)
    t.issue("reopen.new_default", lease=MAX_TTL)
    instance.stop()
    t.check("plaintext_credentials_absent", scan_storage(instance.root, t.secrets))
    t.check("complete", True)


def required_cases(prepare):
    names = set()
    for profile in PROFILES:
        values = {"legacy.tune_exact", "legacy.ordinary.issued", "legacy.child.issued", "legacy.explicit.issued",
                  "legacy.periodic.issued", "legacy.cap_shapes", "legacy.role_and_secret_defaults", "legacy.secret_id_default", "legacy.complete"}
        if prepare:
            values.add("legacy.plaintext_credentials_absent")
        else:
            for phase in ("current", "untouched_restart"):
                values |= {phase + "." + suffix for suffix in
                           ("application_unchanged", "tune_preserved", "role_exact", "reads_preserve_entire_store")}
                values |= {phase + "." + kind + ".exact" for kind in ("ordinary", "child", "explicit", "periodic")}
            values |= {"migration." + suffix for suffix in
                       ("failure_does_not_publish", "first_create.issued", "new_ordinary_has_no_explicit_cap",
                        "old_ambiguous_cap_retained", "old_missing_grant_conservative", "role_not_rewritten", "issued_explicit_deadline", "issued_period_retained")}
            for label in ("migration.old_default", "migration.new_default", "migration.old_record_grant", "migration.new_record_grant",
                          "migration.child_record_grant", "migration.old_current_tune",
                          "migration.new_current_tune", "migration.child_current_tune", "migration.explicit_cap",
                          "migration.period_clamped", "recovery.old_current_tune", "recovery.new_current_tune", "recovery.explicit_cap"):
                values |= {label + "." + entry + ".shape" for entry in ("renew_self", "renew", "renew_accessor")}
            values |= {"reopen.application_unchanged", "reopen.tune_exact", "reopen.old_cap_retained", "reopen.new_cap_absent",
                       "downgrade.unseal_rejected", "downgrade.remains_sealed", "downgrade.application_unchanged",
                       "recovery.application_unchanged", "recovery.issued_explicit_deadline", "recovery.inherited_one_hour.issued",
                       "recovery.legacy_system_defaults_preserved", "plaintext_credentials_absent", "complete"}
            values |= {"recovery.old_" + kind for kind in ("ordinary", "child", "explicit", "periodic")}
            values.add("recovery.new")
        names |= {"token_defaults_upgrade." + profile + "." + value for value in values}
    if not prepare:
        names |= {"token_defaults_upgrade.fresh." + value for value in
                  ("system_defaults", "default_login.issued", "ordinary_has_no_explicit_cap", "secret_id_default_still_one_hour",
                   "reopen.application_unchanged", "reopen.defaults_persist", "reopen.new_default.issued", "plaintext_credentials_absent", "complete")}
    return names


def complete(rows, prepare):
    if not isinstance(rows, list) or not rows:
        return False
    if any(not isinstance(row, dict) or not isinstance(row.get("case"), str)
           or re.fullmatch(r"token_defaults_upgrade\.[a-z0-9_.]{1,170}", row["case"]) is None
           or row.get("passed") is not True
           or any(type(v) not in (int, bool) for k,v in row.items() if k not in ("case", "passed")) for row in rows):
        return False
    names = [row["case"] for row in rows]
    final = "tuned.legacy.plaintext_credentials_absent" if prepare else "fresh.complete"
    return (len(names) == len(set(names)) and required_cases(prepare).issubset(names)
            and names[-1] == "token_defaults_upgrade." + final)


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
    root = Path(tempfile.mkdtemp(prefix="heptabao-token-defaults-upgrade-"))
    root.chmod(0o700)
    instance = None
    rows, failure = [], None
    try:
        for profile in (*PROFILES, *(("fresh",) if not args.prepare_legacy else ())):
            instance = Instance(candidate if profile == "fresh" else legacy, root / profile)
            settings = json.loads((instance.root / "server.json").read_text())
            settings.update(lifecycle_interval_seconds=0, outbound_endpoints=[])
            private_write(instance.root / "server.json", settings)
            if profile == "fresh":
                run_fresh(instance, candidate, rows)
            elif args.prepare_legacy:
                t, _, _ = prepare_legacy(instance, profile, rows)
                instance.stop()
                t.check("legacy.plaintext_credentials_absent", scan_storage(instance.root, t.secrets))
            else:
                run_upgrade(instance, profile, candidate, legacy, rows)
            instance.stop()
    except Exception as error:
        failure = str(error) if isinstance(error, ScenarioFailure) else "fixture_" + type(error).__name__
    finally:
        if instance is not None:
            instance.stop()
        shutil.rmtree(root)
    after = source_identity(ROOT, candidate)
    binaries_unchanged = after["binary_sha256"] == candidate_hash and file_hash(legacy) == legacy_hash
    source_unchanged = before == after
    runner_unchanged = file_hash(Path(__file__)) == runner_hash
    if not binaries_unchanged or not source_unchanged or not runner_unchanged:
        failure = "source_binary_or_runner_changed"
    if not complete(rows, args.prepare_legacy):
        failure = failure or "incomplete_observations"
    report = {"schema":"heptabao.token-defaults-upgrade.v1", "status":"passed" if failure is None else "failed",
        "from_schema":32, "minimum_to_schema":None if args.prepare_legacy else 33,
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
        "tune_readback_adaptation":"zero stored tune fields now display inherited legacy 3600/32-day values; all other fields preserved",
        "old_ambiguous_max_caps":"historical ordinary max_expires_at is retained conservatively, never guessed to be implicit",
        "old_missing_grant":"old tokens without a last-granted TTL use the prior 3600 renewal default until successful renewal records a grant",
        "synthetic_only":True, "rolling_upgrade_qualification":False, "full_migration_qualification":False,
        "independent_qualification":False, "production_authority":False}
    if admit_output(output) != admitted:
        raise ValueError("report_parent_changed")
    private_write(output, report, replace=False)
    print(json.dumps({"status":report["status"], "checks":len(rows), "failure":failure}))
    return 0 if failure is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
