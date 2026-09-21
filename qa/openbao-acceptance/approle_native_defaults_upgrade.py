#!/usr/bin/env python3
"""Actual schema-33 AppRole/SecretID state -> native defaults and metadata.

Old positive defaults and issued SecretIDs are created by the historical
process. Missing historical metadata is never guessed from current settings.
"""
from __future__ import annotations

from datetime import datetime
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

LEGACY_SOURCE = "f2650f44c09549c25afd8cac78589b197f6dac1d"
LEGACY_SHA256 = "e70ec380ef4f3dde9f3aec750988888955081e7b45de9b4751978d721e2e2d5f"
LEGACY_RECEIPT = ROOT / "qa/openbao-acceptance/evidence/token-mount-ttl-f2650f4.json"
MOUNTS = {"builtin":"approle", "custom":"workload-approle"}
DURATIONS = ("token_ttl", "token_max_ttl", "token_period", "token_explicit_max_ttl", "secret_id_ttl")
ISSUANCE = {"secret_id_ttl", "creation_time", "last_updated_time"}
VALUE = "secret/data/approle-defaults-upgrade"


def require_legacy_pin():
    if (not isinstance(LEGACY_SOURCE, str) or re.fullmatch(r"[0-9a-f]{40}", LEGACY_SOURCE) is None
            or not isinstance(LEGACY_SHA256, str) or re.fullmatch(r"[0-9a-f]{64}", LEGACY_SHA256) is None
            or not isinstance(LEGACY_RECEIPT, Path)):
        raise ValueError("legacy_schema33_pin_not_available")


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
        raise ValueError("legacy_schema33_receipt_mismatch")


def role_path(mount, name="preserved"):
    return "auth/" + mount + "/role/" + name


def unix_time(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return int(parsed.timestamp()) if parsed.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def retained_secret(current, old):
    expected_extra = {"expiration_time", "metadata", "cidr_list", "token_bound_cidrs"}
    retained = {k:v for k,v in current.items() if k not in expected_extra}
    return (retained == old and not ISSUANCE.intersection(current)
            and unix_time(current.get("expiration_time")) == old.get("expiration_time_unix")
            and current.get("metadata") == {} and current.get("cidr_list") is None
            and current.get("token_bound_cidrs") == [])


def native_secret(current, *, ttl, uses, lifetime):
    created, updated = unix_time(current.get("creation_time")), unix_time(current.get("last_updated_time"))
    expiry = current.get("expiration_time")
    actual = unix_time(expiry)
    return (current.get("secret_id_ttl") == ttl and current.get("secret_id_num_uses") == uses
            and isinstance(current.get("secret_id_accessor"), str) and bool(current["secret_id_accessor"])
            and type(created) is int and type(updated) is int and updated >= created
            and (expiry == "0001-01-01T00:00:00Z" and current.get("expiration_time_unix") is None
                 if lifetime == 0 else type(actual) is int and actual - created == lifetime
                    and current.get("expiration_time_unix") == actual))


class Trace:
    def __init__(self, instance, rows):
        self.instance, self.rows = instance, rows
        self.client = Client(instance.address, str(instance.root / "ca.crt"), instance.token)
        self.secrets = [instance.token]

    def check(self, label, condition, **observed):
        if (not isinstance(label, str) or re.fullmatch(r"[a-z0-9_.]{1,150}", label) is None
                or any(type(value) not in (int, bool) for value in observed.values())):
            raise ScenarioFailure("invalid_observation_shape")
        name = "approle_defaults_upgrade." + label
        self.rows.append({"case":name, **observed, "passed":condition is True})
        if condition is not True:
            raise ScenarioFailure(name)

    def call(self, label, path, body=None, *, method="POST", bearer=None, expected=200):
        result = self.client.request(method, "/v1/" + path, body, token=bearer)
        self.check(label, result.status == expected, status=result.status)
        return result.body

    def secret(self, label, mount, *, name="preserved", ttl, uses):
        data = self.call(label, role_path(mount, name) + "/secret-id", {}).get("data", {})
        self.check(label + ".issued", isinstance(data.get("secret_id"), str) and bool(data["secret_id"])
                   and isinstance(data.get("secret_id_accessor"), str) and bool(data["secret_id_accessor"])
                   and data.get("secret_id_ttl") == ttl and data.get("secret_id_num_uses") == uses)
        self.secrets.append(data["secret_id"])
        return data

    def secret_lookup(self, label, mount, secret, *, name="preserved", accessor=False):
        suffix, field = ("secret-id-accessor/lookup", "secret_id_accessor") if accessor else ("secret-id/lookup", "secret_id")
        return self.call(label, role_path(mount, name) + "/" + suffix, {field:secret[field]}).get("data", {})

    def login(self, label, mount, role_id, secret, *, lease, expected=200):
        body = self.call(label, "auth/" + mount + "/login", {"role_id":role_id, "secret_id":secret["secret_id"]},
                         bearer="", expected=expected)
        if expected != 200:
            self.check(label + ".no_token", not body.get("auth") and not body.get("wrap_info"))
            return None
        auth = body.get("auth", {})
        self.check(label + ".issued", all(isinstance(auth.get(f), str) and bool(auth[f])
                   for f in ("client_token", "accessor", "entity_id")) and auth.get("lease_duration") == lease
                   and auth.get("renewable") is True)
        self.secrets.append(auth["client_token"])
        return auth

    def renew(self, label, auth, lease):
        for entry in ("renew-self", "renew", "renew-accessor"):
            body, bearer = {}, None
            if entry == "renew-self":
                bearer = auth["client_token"]
            elif entry == "renew":
                body["token"] = auth["client_token"]
            else:
                body["accessor"] = auth["accessor"]
            name = label + "." + entry.replace('-', '_')
            response = self.call(name, "auth/token/" + entry, body, bearer=bearer).get("auth", {})
            self.check(name + ".lease", renewal_token_shape(response, auth["client_token"], via_accessor=entry == "renew-accessor")
                       and type(response.get("lease_duration")) is int and response["lease_duration"] == lease)


def prepare_legacy(instance, rows):
    instance.start()
    status, initialized = instance.call("POST", "sys/init", {"secret_shares":1, "secret_threshold":1})
    if status != 200:
        raise ScenarioFailure("approle_defaults_upgrade.initialization_failed")
    instance.token, key = initialized["root_token"], initialized["keys_base64"][0]
    t = Trace(instance, rows)
    t.secrets.append(key)
    t.call("legacy.unseal", "sys/unseal", {"key":key})
    t.call("legacy.value", VALUE, {"data":{"synthetic":True}})
    saved = {}
    for profile, mount in MOUNTS.items():
        prefix = "legacy." + profile
        if profile == "custom":
            t.call(prefix + ".mount", "sys/auth/" + mount, {"type":"approle"}, expected=204)
        t.call(prefix + ".tune", "sys/auth/" + mount + "/tune", {"default_lease_ttl":75, "max_lease_ttl":600}, expected=204)
        t.call(prefix + ".role", role_path(mount), {"token_policies":["default"]}, expected=204)
        role = t.call(prefix + ".role_read", role_path(mount), method="GET").get("data", {})
        t.check(prefix + ".old_defaults", all(role.get(field) == expected for field,expected in
                (("token_ttl",75), ("token_max_ttl",600), ("secret_id_ttl",3600), ("secret_id_num_uses",1))))
        role_id = t.call(prefix + ".role_id", role_path(mount) + "/role-id", method="GET").get("data", {}).get("role_id")
        t.check(prefix + ".role_id_present", isinstance(role_id, str) and bool(role_id))
        t.secrets.append(role_id)
        held = t.secret(prefix + ".held", mount, ttl=3600, uses=1)
        held_lookup = t.secret_lookup(prefix + ".held_read", mount, held)
        t.check(prefix + ".old_metadata_absent", not ISSUANCE.intersection(held_lookup)
                and type(held_lookup.get("expiration_time_unix")) is int and held_lookup.get("secret_id_num_uses") == 1)
        used = t.secret(prefix + ".login_secret", mount, ttl=3600, uses=1)
        auth = t.login(prefix + ".login", mount, role_id, used, lease=75)
        lookup = t.call(prefix + ".token_lookup", "auth/token/lookup", {"token":auth["client_token"]}).get("data", {})
        saved[profile] = {"role":role, "role_id":role_id, "held":held, "held_lookup":held_lookup,
                          "auth":auth, "token_lookup":lookup}
    t.check("legacy.complete", True)
    return t, key, saved


def restart(instance, binary, key, t, label):
    instance.stop()
    instance.binary = binary
    instance.start()
    t.call(label + ".unseal", "sys/unseal", {"key":key})


def run_upgrade(instance, candidate, legacy, rows):
    t, key, saved = prepare_legacy(instance, rows)
    store = instance.root / "data"
    instance.stop()
    application = durable_manifest(store, application_only=True)
    for phase in ("current", "untouched_restart"):
        restart(instance, candidate, key, t, phase)
        t.check(phase + ".application_unchanged", durable_manifest(store, application_only=True) == application)
        before = durable_manifest(store)
        value = t.call(phase + ".value", VALUE, method="GET")
        t.check(phase + ".value_preserved", value.get("data", {}).get("data") == {"synthetic":True})
        for profile, mount in MOUNTS.items():
            prefix, record = phase + "." + profile, saved[profile]
            role = t.call(prefix + ".role", role_path(mount), method="GET").get("data", {})
            t.check(prefix + ".role_exact", role == record["role"])
            held = t.secret_lookup(prefix + ".held", mount, record["held"])
            t.check(prefix + ".legacy_metadata_honest", retained_secret(held, record["held_lookup"]))
            lookup = t.call(prefix + ".token", "auth/token/lookup", {"token":record["auth"]["client_token"]}).get("data", {})
            t.check(prefix + ".token_exact", {k:v for k,v in lookup.items() if k != "ttl"} ==
                    {k:v for k,v in record["token_lookup"].items() if k != "ttl"})
        t.check(phase + ".reads_preserve_entire_store", durable_manifest(store) == before)
    native = {}
    for profile, mount in MOUNTS.items():
        prefix, record = "migration." + profile, saved[profile]
        before = durable_manifest(store)
        t.call(prefix + ".duration_null", role_path(mount), {field:None for field in DURATIONS}, expected=204)
        role = t.call(prefix + ".null_read", role_path(mount), method="GET").get("data", {})
        t.check(prefix + ".null_preserves_old_role", role == record["role"] and durable_manifest(store) == before)
        capped = t.secret(prefix + ".new_under_old_role", mount, ttl=600, uses=1)
        cap_info = t.secret_lookup(prefix + ".new_capped_read", mount, capped)
        t.check(prefix + ".requested_ttl_preserved", native_secret(cap_info, ttl=3600, uses=1, lifetime=600))
        t.call(prefix + ".fresh_role", role_path(mount, "fresh"), {"token_policies":["default"]}, expected=204)
        fresh_role = t.call(prefix + ".fresh_read", role_path(mount, "fresh"), method="GET").get("data", {})
        t.check(prefix + ".fresh_zero_defaults", all(fresh_role.get(field) == 0 for field in (*DURATIONS, "token_num_uses", "secret_id_num_uses")))
        fresh_id = t.call(prefix + ".fresh_id", role_path(mount, "fresh") + "/role-id", method="GET").get("data", {}).get("role_id")
        t.check(prefix + ".fresh_id_present", isinstance(fresh_id, str) and bool(fresh_id))
        t.secrets.append(fresh_id)
        unlimited = t.secret(prefix + ".unlimited", mount, name="fresh", ttl=0, uses=0)
        unlimited_info = t.secret_lookup(prefix + ".unlimited_read", mount, unlimited, name="fresh")
        t.check(prefix + ".unlimited_metadata", native_secret(unlimited_info, ttl=0, uses=0, lifetime=0))
        first = t.login(prefix + ".first_login", mount, fresh_id, unlimited, lease=75)
        t.login(prefix + ".repeat_login", mount, fresh_id, unlimited, lease=75)
        repeated = t.secret_lookup(prefix + ".after_repeat", mount, unlimited, name="fresh")
        t.check(prefix + ".unlimited_metadata_unchanged", repeated == unlimited_info)
        t.call(prefix + ".retune", "sys/auth/" + mount + "/tune", {"default_lease_ttl":95, "max_lease_ttl":900}, expected=204)
        t.renew(prefix + ".old_positive_role", record["auth"], 75)
        t.renew(prefix + ".new_inherited_role", first, 95)
        t.call(prefix + ".reset_old_role", role_path(mount),
               {"token_ttl":0, "token_max_ttl":0, "secret_id_ttl":0, "secret_id_num_uses":None, "token_num_uses":None}, expected=204)
        zeroed = t.call(prefix + ".zeroed_read", role_path(mount), method="GET").get("data", {})
        t.check(prefix + ".explicit_zero_and_null_counts", all(zeroed.get(field) == 0 for field in
                ("token_ttl", "token_max_ttl", "secret_id_ttl", "secret_id_num_uses", "token_num_uses")))
        held = t.secret_lookup(prefix + ".old_held_after_reset", mount, record["held"])
        t.check(prefix + ".old_secret_not_reinterpreted", retained_secret(held, record["held_lookup"]))
        t.login(prefix + ".old_held_once", mount, record["role_id"], record["held"], lease=95)
        t.login(prefix + ".old_held_exhausted", mount, record["role_id"], record["held"], lease=0, expected=400)
        t.call(prefix + ".exhausted_lookup", role_path(mount) + "/secret-id/lookup", {"secret_id":record["held"]["secret_id"]}, expected=204)
        t.call(prefix + ".exhausted_accessor", role_path(mount) + "/secret-id-accessor/lookup",
               {"secret_id_accessor":record["held"]["secret_id_accessor"]}, expected=404)
        t.renew(prefix + ".old_after_reset", record["auth"], 95)
        native[profile] = {"unlimited":unlimited, "unlimited_info":unlimited_info, "fresh_id":fresh_id,
                           "auth":first, "capped":capped, "cap_info":cap_info, "role":zeroed, "fresh_role":fresh_role}
    instance.stop()
    application = durable_manifest(store, application_only=True)
    restart(instance, candidate, key, t, "reopen")
    t.check("reopen.application_unchanged", durable_manifest(store, application_only=True) == application)
    for profile, mount in MOUNTS.items():
        record = native[profile]
        capped = t.secret_lookup("reopen." + profile + ".capped", mount, record["capped"])
        unlimited = t.secret_lookup("reopen." + profile + ".unlimited", mount, record["unlimited"], name="fresh")
        t.check("reopen." + profile + ".metadata_exact", capped == record["cap_info"] and unlimited == record["unlimited_info"])
        for name, expected in (("preserved", record["role"]), ("fresh", record["fresh_role"])):
            role = t.call("reopen." + profile + ".role_" + name, role_path(mount, name), method="GET").get("data", {})
            t.check("reopen." + profile + ".role_" + name + ".exact", role == expected)
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
    for profile, mount in MOUNTS.items():
        record, old = native[profile], saved[profile]
        t.renew("recovery." + profile + ".old_token", old["auth"], 95)
        t.renew("recovery." + profile + ".new_token", record["auth"], 95)
        t.login("recovery." + profile + ".unlimited_login", mount, record["fresh_id"], record["unlimited"], lease=95)
        current = t.secret_lookup("recovery." + profile + ".unlimited", mount, record["unlimited"], name="fresh")
        t.check("recovery." + profile + ".metadata_exact", current == record["unlimited_info"])
        t.login("recovery." + profile + ".old_exhaustion_persists", mount, old["role_id"], old["held"], lease=0, expected=400)
    instance.stop()
    t.check("plaintext_credentials_absent", scan_storage(instance.root, t.secrets))
    t.check("complete", True)


def required_cases(prepare):
    names = {"legacy.complete"}
    for profile in MOUNTS:
        names |= {"legacy." + profile + "." + suffix for suffix in
                  ("old_defaults", "held.issued", "old_metadata_absent", "login.issued")}
    if prepare:
        names.add("legacy.plaintext_credentials_absent")
    else:
        for phase in ("current", "untouched_restart"):
            names |= {phase + ".application_unchanged", phase + ".reads_preserve_entire_store"}
            for profile in MOUNTS:
                names |= {phase + "." + profile + "." + suffix for suffix in ("role_exact", "legacy_metadata_honest", "token_exact")}
        names |= {"reopen.application_unchanged", "downgrade.unseal_rejected", "downgrade.remains_sealed",
                  "downgrade.application_unchanged", "recovery.application_unchanged", "plaintext_credentials_absent", "complete"}
        for profile in MOUNTS:
            names |= {"migration." + profile + "." + suffix for suffix in
                      ("null_preserves_old_role", "requested_ttl_preserved", "fresh_zero_defaults", "unlimited_metadata",
                       "first_login.issued", "repeat_login.issued", "unlimited_metadata_unchanged", "explicit_zero_and_null_counts",
                       "old_secret_not_reinterpreted", "old_held_once.issued", "old_held_exhausted.no_token", "exhausted_lookup", "exhausted_accessor")}
            for phase, labels in (("migration", ("old_positive_role", "new_inherited_role", "old_after_reset")),
                                  ("recovery", ("old_token", "new_token"))):
                names |= {phase + "." + profile + "." + label + "." + entry + ".lease"
                          for label in labels for entry in ("renew_self", "renew", "renew_accessor")}
            names |= {"reopen." + profile + "." + suffix for suffix in ("metadata_exact", "role_preserved.exact", "role_fresh.exact")}
            names |= {"recovery." + profile + "." + suffix for suffix in
                      ("unlimited_login.issued", "metadata_exact", "old_exhaustion_persists.no_token")}
    return {"approle_defaults_upgrade." + name for name in names}


def complete(rows, prepare):
    if not isinstance(rows, list) or not rows:
        return False
    if any(not isinstance(row, dict) or not isinstance(row.get("case"), str)
           or re.fullmatch(r"approle_defaults_upgrade\.[a-z0-9_.]{1,150}", row["case"]) is None
           or row.get("passed") is not True
           or any(type(v) not in (int, bool) for k,v in row.items() if k not in ("case", "passed")) for row in rows):
        return False
    names = [row["case"] for row in rows]
    end = "legacy.plaintext_credentials_absent" if prepare else "complete"
    return (len(names) == len(set(names)) and required_cases(prepare).issubset(names)
            and names[-1] == "approle_defaults_upgrade." + end)


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
    root = Path(tempfile.mkdtemp(prefix="heptabao-approle-defaults-upgrade-"))
    root.chmod(0o700)
    instance = None
    rows, failure = [], None
    try:
        instance = Instance(legacy, root / "candidate")
        settings = json.loads((instance.root / "server.json").read_text())
        settings.update(lifecycle_interval_seconds=0, outbound_endpoints=[])
        private_write(instance.root / "server.json", settings)
        if args.prepare_legacy:
            t, _, _ = prepare_legacy(instance, rows)
            instance.stop()
            t.check("legacy.plaintext_credentials_absent", scan_storage(instance.root, t.secrets))
        else:
            run_upgrade(instance, candidate, legacy, rows)
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
    report = {"schema":"heptabao.approle-native-defaults-upgrade.v1", "status":"passed" if failure is None else "failed",
        "from_schema":33, "minimum_to_schema":None if args.prepare_legacy else 34,
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
        "legacy_secretid_metadata":"requested TTL and creation/update times remain absent; known expiry/count retained",
        "immediate_expiry_rejection_parity":False, "expiry_tidy_timing_covered":False,
        "synthetic_only":True, "rolling_upgrade_qualification":False, "full_migration_qualification":False,
        "independent_qualification":False, "production_authority":False}
    if admit_output(output) != admitted:
        raise ValueError("report_parent_changed")
    private_write(output, report, replace=False)
    print(json.dumps({"status":report["status"], "checks":len(rows), "failure":failure}))
    return 0 if failure is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
