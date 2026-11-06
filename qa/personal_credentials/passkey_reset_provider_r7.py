#!/usr/bin/env python3
"""Case-bound synthetic provider-data reset, after a current real SAF backup.

This is only the reset portion of M05 or G11. It does not import a backup, establish a
new store, qualify a phone case, or prove physical-device migration. The caller
must create the checkpoint and M04 receipt from actual observations, never from
this module's examples or host-only stubs. Existing reset intent means stop and
reconcile; this helper never automatically repeats an uncertain ``pm clear``.
All reset intents for this run/provider are checked before either case. A second
case is admitted only after a complete, hash-bound success for the first case,
with a new current recovery backup. The G11 stale input is a separate artifact.
The result alone is provisional: a separate witness is created only after its
file and directory fsyncs succeed. Recovery re-syncs an existing valid witness;
it never repeats pm clear or manufactures a witness for an uncertain result.

All input JSON files are private, ordinary files in --root. See --schema for the
exact checkpoint/backup receipt shapes. --self-test performs no ADB or network IO.
"""
import argparse
import base64
import copy
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import time
import types
import urllib.request

DRIVER_SHA256 = "e0fefb8be676cd9e1e2da4d2b88d7abfa728bc4fdfdf725f6957869da976c9cd"
RP_SOURCE_SHA256 = "386de84bb5335f21998a000b4a1267eaa17fadbde1e1753d5df1c30325709a63"
PROFILE_SOURCE_SHA256 = "a568f1e51f4d4e6c096b0b871bb7a9be5f7da88cf3aef39fca17e59bf8564706"
PROFILE_PUBLIC_SHA256 = "8a2c3e83c878ea5a6c6d646f94559d0de5154fd9b8210604bcdc879349a7165d"
BUILD_RECEIPT_SHA256 = "e12bd68de3c606e03ce22a7a688ebb90c7b6ec4a951d15e5be233339e698042b"
PROVIDER_APK_SHA256 = "b16e82916330fac6909f82696089798c3ec76d7b4058fe9290e7e841b9e00459"
FIXTURE_CERT_SHA256 = "cb684e07720b0233e9aa87bc74e87cf40956476770dabc2a426bee30dcba6135"
RP_ID = "passkeys.heptabao.test"
RP_URL = "http://127.0.0.1:38491/state"
PROVIDER = "org.heptabao.passkey.preview"
CASES = ("M05", "G11")
MAX_JSON = 1024 * 1024
MAX_BACKUP = 8 * 1024 * 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")
BACKUP_PATH = re.compile(r"/sdcard/Download/HeptaBao-Passkey-QA-20261106-r7/heptabao-passkey-(?:backup|latest-recovery|stale-input)\.hbv\Z")


class Failed(Exception):
    """Only fixed codes, never external output, enter public diagnostics."""


def require(condition, code):
    if not condition:
        raise Failed(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate_json_key")
            value[key] = item
        return value

    def number(text):
        value = float(text)
        require(math.isfinite(value), "invalid_json_number")
        return value

    def constant(_):
        raise Failed("invalid_json_number")

    require(0 < len(raw) <= MAX_JSON, "input_json_size")
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                          parse_float=number, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError):
        raise Failed("invalid_input_json") from None


def exact(value, keys, code):
    require(type(value) is dict and set(value) == set(keys), code)


def digest(value):
    return type(value) is str and HEX.fullmatch(value) is not None


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def names(case_id):
    require(case_id in CASES, "unsupported_reset_case")
    prefix = "provider-reset-" + case_id
    return (prefix + "-checkpoint.private.json", prefix + "-intent.private.json", prefix + "-result.public.json")


def completion_name(case_id):
    require(case_id in CASES, "unsupported_reset_case")
    return "provider-reset-" + case_id + "-completion.public.json"


def private_read(path, maximum=MAX_JSON, code_source=False, durable=False):
    require(path.is_absolute() and str(path) == str(path.resolve(strict=True)), "unsafe_input_path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        mode = stat.S_IMODE(before.st_mode)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and 0 < before.st_size <= maximum
                and (mode & 0o022 == 0 if code_source else mode == 0o600), "unsafe_input_file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd)
        require(len(raw) == before.st_size <= maximum and
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "input_changed_during_read")
        if durable:
            # Re-establish persistence of an already present witness, using the
            # same validated file handle. This never creates a missing witness.
            os.fsync(fd)
            named = path.lstat()
            require((named.st_dev, named.st_ino) == (after.st_dev, after.st_ino), "witness_path_changed")
            parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try: os.fsync(parent)
            finally: os.close(parent)
        return raw
    finally:
        os.close(fd)


def load_driver(path):
    raw = private_read(path, code_source=True)
    require(sha(raw) == DRIVER_SHA256, "driver_source_changed")
    # Execute the bytes just hashed, rather than reopening a mutable path.
    live = types.ModuleType("passkey_live_pinned_for_reset")
    live.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), live.__dict__)
    require(live.PROVIDER == PROVIDER, "driver_provider_changed")
    return live


def relative_json(root, name):
    require(type(name) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}\.json", name)
            and ".." not in name and not name.startswith("provider-reset-"), "unsafe_evidence_name")
    return root / name


def rp_state(value, fixture_cert):
    exact(value, {"ok", "rp_id", "fixture_cert_sha256", "origin", "revision", "credential_count",
                  "ceremony_counts", "counters", "event_count", "credentials"}, "invalid_rp_snapshot")
    expected_origin = "android:apk-key-hash:" + base64.urlsafe_b64encode(bytes.fromhex(fixture_cert)).decode().rstrip("=")
    require(value["ok"] is True and value["rp_id"] == RP_ID and value["fixture_cert_sha256"] == fixture_cert
            and value["origin"] == expected_origin, "rp_identity_changed")
    for key in ("revision", "credential_count", "event_count"):
        require(type(value[key]) is int and 0 <= value[key] <= 1000000, "invalid_rp_snapshot")
    require(value["revision"] == value["event_count"] and value["revision"] > 0
            and value["credential_count"] == 1 and type(value["credentials"]) is list
            and len(value["credentials"]) == 1, "single_synthetic_credential_required")
    exact(value["ceremony_counts"], {"pending", "consumed", "restart_invalidated"}, "invalid_rp_snapshot")
    exact(value["counters"], {"options", "verification_attempts", "registrations", "authentications", "rejected", "restart_invalidated"}, "invalid_rp_snapshot")
    for counts in (value["ceremony_counts"], value["counters"]):
        require(all(type(n) is int and 0 <= n <= 1000000 for n in counts.values()), "invalid_rp_snapshot")
    require(value["counters"]["registrations"] == 1 and value["counters"]["authentications"] >= 1,
            "rp_positive_create_and_get_required")
    credential = value["credentials"][0]
    exact(credential, {"credential_id", "public_key_sha256", "sign_count", "flags"}, "invalid_rp_credential")
    identifier = credential["credential_id"]
    require(type(identifier) is str and re.fullmatch(r"[A-Za-z0-9_-]{43}", identifier), "invalid_rp_credential")
    decoded = base64.urlsafe_b64decode(identifier + "=")
    require(len(decoded) == 32 and base64.urlsafe_b64encode(decoded).decode().rstrip("=") == identifier
            and digest(credential["public_key_sha256"])
            and type(credential["sign_count"]) is int and 1 <= credential["sign_count"] <= 0xFFFFFFFF
            and type(credential["flags"]) is int and credential["flags"] in (0x0D, 0x1D), "invalid_rp_credential")
    return value


def read_rp():
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise Failed("rp_redirect_rejected")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(RP_URL, timeout=5) as response:
        require(response.status == 200 and response.geturl() == RP_URL, "rp_state_unavailable")
        raw = response.read(65537)
    require(len(raw) <= 65536, "rp_state_too_large")
    return unique_json(raw)


def validate_backup(backup):
    exact(backup, {"device_path", "bytes", "sha256"}, "invalid_backup_binding")
    require(type(backup["device_path"]) is str and BACKUP_PATH.fullmatch(backup["device_path"])
            and type(backup["bytes"]) is int and 1 <= backup["bytes"] <= MAX_BACKUP
            and digest(backup["sha256"]), "invalid_backup_binding")


INPUT_KEYS = {"driver", "helper", "build", "journal", "checkpoint", "backup_receipt", "rp_snapshot",
              "profile_source", "profile_public"}
INTENT_KEYS = {"schema", "scope", "case_id", "reset_id", "device_sha256", "provider_package", "user",
               "argv", "input_sha256", "provider_apk_sha256", "settings_before", "old_provider_pid",
               "recovery_backup", "stale_input", "rp_snapshot", "prior_reset_result_sha256",
               "operation_may_have_run_after_this_intent", "created_unix_ns"}
SUCCESS_KEYS = {"schema", "ok", "scope", "case_id", "reset_id", "device_sha256", "provider_package",
                "intent_sha256", "input_sha256", "provider_apk_sha256", "apk_unchanged", "settings_sha256",
                "all_three_settings_unchanged", "old_provider_pid_sha256", "nonempty_old_pid_observed",
                "post_reset_provider_pid_sha256", "old_provider_process_absence_observed", "pm_clear_exit_code",
                "pm_clear_exact_success_observed", "external_recovery_backup", "stale_input_sha256",
                "rp_snapshot_sha256", "rp_key_and_counter_unchanged", "credential", "journal_unchanged",
                "reset_completed", "synthetic_only", "case_passed", "physical_device_migration",
                "production_qualified", "completed_unix_ns"}
COMPLETION_KEYS = {"schema", "scope", "case_id", "reset_id", "device_sha256", "provider_package",
                   "intent_sha256", "result_sha256", "result_persisted_before_witness", "completed_unix_ns"}


def reset_history(live, root, case_id, build, build_sha):
    """Unknown/missing/failed prior outcomes fence both cases, not only one ID."""
    allowed = {name for case in CASES for name in (*names(case), completion_name(case))}
    require(all(not path.name.startswith("provider-reset-") or path.name in allowed
                for path in root.iterdir()), "unknown_reset_record_reconcile_first")
    previous = {}
    for case in CASES:
        _, intent_name, result_name = names(case)
        intent_path, result_path, complete_path = root / intent_name, root / result_name, root / completion_name(case)
        present = (os.path.lexists(intent_path), os.path.lexists(result_path), os.path.lexists(complete_path))
        if present == (False, False, False):
            continue
        require(present == (True, True, True), "unresolved_prior_reset_fences_provider")
        raw = private_read(intent_path)
        intent, result_raw = unique_json(raw), private_read(result_path)
        result = unique_json(result_raw)
        complete = unique_json(private_read(complete_path, durable=True))
        exact(intent, INTENT_KEYS, "invalid_prior_reset_intent")
        exact(result, SUCCESS_KEYS, "unresolved_prior_reset_fences_provider")
        exact(complete, COMPLETION_KEYS, "invalid_reset_completion_witness")
        require(type(complete["schema"]) is int and complete["schema"] == 1
                and complete["scope"] == "reset_result_durability_witness"
                and complete["case_id"] == case and complete["reset_id"] == case + "-reset-1"
                and complete["device_sha256"] == live.DEVICE_SHA256 and complete["provider_package"] == PROVIDER
                and complete["intent_sha256"] == sha(raw) and complete["result_sha256"] == sha(result_raw)
                and complete["result_persisted_before_witness"] is True
                and type(complete["completed_unix_ns"]) is int and type(result["completed_unix_ns"]) is int
                and complete["completed_unix_ns"] >= result["completed_unix_ns"], "invalid_reset_completion_witness")
        exact(intent["input_sha256"], INPUT_KEYS, "invalid_prior_reset_binding")
        require(all(digest(value) for value in intent["input_sha256"].values())
                and intent["input_sha256"]["driver"] == DRIVER_SHA256
                and intent["input_sha256"]["build"] == build_sha
                and intent["input_sha256"]["profile_source"] == PROFILE_SOURCE_SHA256
                and intent["input_sha256"]["profile_public"] == PROFILE_PUBLIC_SHA256,
                "invalid_prior_reset_binding")
        require(type(intent["schema"]) is int and intent["schema"] == 1
                and intent["scope"] == "same_device_synthetic_provider_pm_clear_intent"
                and intent["case_id"] == case and intent["reset_id"] == case + "-reset-1"
                and intent["device_sha256"] == live.DEVICE_SHA256 and intent["provider_package"] == PROVIDER
                and type(intent["user"]) is int and intent["user"] == 0
                and intent["argv"] == ["pm", "clear", "--user", "0", PROVIDER]
                and intent["provider_apk_sha256"] == build["artifacts"]["provider"]["sha256"]
                and intent["operation_may_have_run_after_this_intent"] is True
                and type(intent["old_provider_pid"]) is str
                and re.fullmatch(r"[1-9][0-9]{0,8}", intent["old_provider_pid"])
                and type(intent["created_unix_ns"]) is int and intent["created_unix_ns"] > 0,
                "invalid_prior_reset_intent")
        exact(intent["settings_before"], live.SETTING_KEYS, "invalid_prior_reset_settings")
        require(all(type(value) is str for value in intent["settings_before"].values()), "invalid_prior_reset_settings")
        validate_backup(intent["recovery_backup"])
        rp_state(intent["rp_snapshot"], build["artifacts"]["fixture-good"]["certificate_sha256"])
        require(type(result["schema"]) is int and result["schema"] == 1 and result["ok"] is True
                and result["scope"] == "synthetic_same_device_app_data_reset_only"
                and result["case_id"] == case and result["reset_id"] == intent["reset_id"]
                and result["device_sha256"] == live.DEVICE_SHA256 and result["provider_package"] == PROVIDER
                and result["intent_sha256"] == sha(raw) and result["input_sha256"] == intent["input_sha256"]
                and result["provider_apk_sha256"] == intent["provider_apk_sha256"]
                and result["settings_sha256"] == {k: sha(v.encode()) for k, v in intent["settings_before"].items()}
                and result["old_provider_pid_sha256"] == sha(intent["old_provider_pid"].encode())
                and type(result["post_reset_provider_pid_sha256"]) is list
                and len(result["post_reset_provider_pid_sha256"]) <= 1
                and all(digest(pid) and pid != result["old_provider_pid_sha256"] for pid in result["post_reset_provider_pid_sha256"])
                and type(result["pm_clear_exit_code"]) is int and result["pm_clear_exit_code"] == 0
                and result["external_recovery_backup"] == {k: intent["recovery_backup"][k] for k in ("bytes", "sha256")}
                and result["rp_snapshot_sha256"] == intent["input_sha256"]["rp_snapshot"]
                and result["credential"] == intent["rp_snapshot"]["credentials"][0]
                and type(result["completed_unix_ns"]) is int
                and result["completed_unix_ns"] >= intent["created_unix_ns"], "invalid_prior_reset_success")
        for key in ("apk_unchanged", "all_three_settings_unchanged", "nonempty_old_pid_observed",
                    "old_provider_process_absence_observed", "pm_clear_exact_success_observed",
                    "rp_key_and_counter_unchanged", "journal_unchanged", "reset_completed", "synthetic_only"):
            require(result[key] is True, "unresolved_prior_reset_fences_provider")
        for key in ("case_passed", "physical_device_migration", "production_qualified"):
            require(result[key] is False, "invalid_prior_reset_scope")
        if case == "M05":
            require(intent["stale_input"] is None and result["stale_input_sha256"] is None
                    and intent["prior_reset_result_sha256"] is None, "invalid_prior_reset_sequence")
        else:
            require("M05" in previous and intent["prior_reset_result_sha256"] == previous["M05"]["result_sha256"],
                    "invalid_prior_reset_sequence")
            validate_stale_input(intent["stale_input"], intent["recovery_backup"],
                                 intent["rp_snapshot"]["credentials"][0], previous["M05"])
            require(result["stale_input_sha256"] == intent["stale_input"]["backup"]["sha256"], "invalid_prior_reset_sequence")
        previous[case] = {"intent": intent, "result": result, "result_sha256": sha(result_raw)}
    require(case_id not in previous, "completed_case_cannot_repeat_reset")
    require((case_id == "M05" and not previous) or (case_id == "G11" and set(previous) == {"M05"}),
            "reset_case_sequence_unconfirmed")
    return previous.get("M05")


def validate_stale_input(value, recovery, credential, previous):
    exact(value, {"backup", "credential", "source_reset_result_sha256"}, "invalid_stale_input")
    validate_backup(value["backup"])
    old = previous["intent"]
    require(value["source_reset_result_sha256"] == previous["result_sha256"]
            and value["credential"] == old["rp_snapshot"]["credentials"][0]
            and all(value["backup"][key] == old["recovery_backup"][key] for key in ("bytes", "sha256"))
            and value["backup"]["device_path"] != recovery["device_path"]
            and Path(value["backup"]["device_path"]).parent == Path(recovery["device_path"]).parent
            and Path(recovery["device_path"]).parent == Path(old["recovery_backup"]["device_path"]).parent
            and value["backup"]["sha256"] != recovery["sha256"]
            and value["credential"]["credential_id"] == credential["credential_id"]
            and value["credential"]["public_key_sha256"] == credential["public_key_sha256"]
            and value["credential"]["sign_count"] < credential["sign_count"], "stale_input_not_separate_verified_historical_backup")


def validate_fixed_build(build, build_sha):
    # The immutable r7 profile is the authority for this one candidate. Supplying
    # a self-consistent different build/journal/checkpoint must not select it.
    require(build_sha == BUILD_RECEIPT_SHA256, "profile_build_binding_changed")
    require(type(build) is dict and type(build.get("artifacts")) is dict,
            "profile_provider_binding_changed")
    provider = build["artifacts"].get("provider")
    fixture = build["artifacts"].get("fixture-good")
    require(type(provider) is dict and provider.get("package") == PROVIDER
            and provider.get("sha256") == PROVIDER_APK_SHA256,
            "profile_provider_binding_changed")
    require(type(fixture) is dict and fixture.get("package") == "org.heptabao.passkey.fixture"
            and fixture.get("certificate_sha256") == FIXTURE_CERT_SHA256
            and build.get("fixture_certificate_sha256") == FIXTURE_CERT_SHA256,
            "profile_fixture_binding_changed")


def validate_inputs(live, build, build_sha, journal, checkpoint, backup_receipt, rp_snapshot, case_id):
    validate_fixed_build(build, build_sha)
    live.validate_journal(journal, build, build_sha)
    require("restoration" not in journal and bool(journal["owned_settings"])
            and journal["settings_intent"] is not None, "run_not_active")
    artifact = build["artifacts"]["provider"]
    cert = build["artifacts"]["fixture-good"]["certificate_sha256"]
    require(artifact["package"] == PROVIDER and digest(artifact["sha256"]) and digest(cert), "invalid_build_binding")
    require(journal["initial_packages_absent"][PROVIDER] is True
            and artifact["sha256"] in journal["owned_packages"].get(PROVIDER, []), "provider_not_owned")
    exact(checkpoint, {"schema", "scope", "case_id", "reset_id", "device_sha256", "build_receipt_sha256", "provider_apk_sha256",
                       "recovery_backup", "backup_receipt_file", "backup_receipt_sha256", "rp_snapshot_file", "rp_snapshot_sha256",
                       "rp_source_sha256", "profile_source_sha256", "profile_public_sha256", "credential", "created_unix_ns",
                       "stale_input", "prior_reset_result_sha256"}, "invalid_reset_checkpoint")
    require(type(checkpoint["schema"]) is int and checkpoint["schema"] == 1
            and checkpoint["scope"] == "same_device_synthetic_provider_reset"
            and case_id in CASES and checkpoint["case_id"] == case_id and checkpoint["reset_id"] == case_id + "-reset-1"
            and checkpoint["device_sha256"] == live.DEVICE_SHA256
            and checkpoint["build_receipt_sha256"] == build_sha
            and checkpoint["provider_apk_sha256"] == artifact["sha256"]
            and checkpoint["rp_source_sha256"] == RP_SOURCE_SHA256
            and checkpoint["profile_source_sha256"] == PROFILE_SOURCE_SHA256
            and checkpoint["profile_public_sha256"] == PROFILE_PUBLIC_SHA256
            and digest(checkpoint["backup_receipt_sha256"]) and digest(checkpoint["rp_snapshot_sha256"])
            and type(checkpoint["created_unix_ns"]) is int and checkpoint["created_unix_ns"] > 0,
            "invalid_reset_checkpoint")
    backup = checkpoint["recovery_backup"]
    validate_backup(backup)
    exact(backup_receipt, {"schema", "scope", "source_case_id", "device_sha256", "build_receipt_sha256", "provider_apk_sha256",
                          "observed_backup", "ordinary_saf_export_observed", "provider_write_readback_verified",
                          "synthetic_directory_initial_absent", "rp_before_sha256", "rp_after_sha256", "credential", "completed_unix_ns"},
          "invalid_observed_backup_receipt")
    validate_backup(backup_receipt["observed_backup"])
    require(type(backup_receipt["schema"]) is int and backup_receipt["schema"] == 1
            and backup_receipt["scope"] == "observed_ordinary_saf_backup_for_reset"
            and backup_receipt["source_case_id"] == ("M04" if case_id == "M05" else "G11_RECOVERY_EXPORT")
            and backup_receipt["device_sha256"] == live.DEVICE_SHA256
            and backup_receipt["build_receipt_sha256"] == build_sha
            and backup_receipt["provider_apk_sha256"] == artifact["sha256"]
            and all(backup_receipt["observed_backup"][key] == backup[key] for key in ("bytes", "sha256"))
            and Path(backup_receipt["observed_backup"]["device_path"]).parent == Path(backup["device_path"]).parent
            and backup_receipt["rp_before_sha256"] == checkpoint["rp_snapshot_sha256"]
            and backup_receipt["rp_after_sha256"] == checkpoint["rp_snapshot_sha256"]
            and backup_receipt["credential"] == checkpoint["credential"]
            and backup_receipt["ordinary_saf_export_observed"] is True
            and backup_receipt["provider_write_readback_verified"] is True
            and backup_receipt["synthetic_directory_initial_absent"] is True
            and type(backup_receipt["completed_unix_ns"]) is int
            and 0 < backup_receipt["completed_unix_ns"] <= checkpoint["created_unix_ns"], "current_recovery_backup_not_confirmed")
    rp_state(rp_snapshot, cert)
    require(checkpoint["credential"] == rp_snapshot["credentials"][0], "rp_key_or_counter_binding_changed")
    if case_id == "M05":
        require(checkpoint["stale_input"] is None and checkpoint["prior_reset_result_sha256"] is None, "invalid_reset_sequence")
    else:
        require(digest(checkpoint["prior_reset_result_sha256"]) and type(checkpoint["stale_input"]) is dict, "invalid_reset_sequence")
    return artifact["sha256"], cert


def backup_observation(device, backup):
    path = backup["device_path"]
    def information():
        text = device.shell("stat", "-c", "%f %s %d %i %Y %Z", path, timeout=5)
        require(re.fullmatch(r"[0-9a-fA-F]+ [0-9]+ [0-9]+ [0-9]+ [0-9]+ [0-9]+", text), "backup_stat_unconfirmed")
        fields = text.split()
        require(stat.S_ISREG(int(fields[0], 16)) and int(fields[1]) == backup["bytes"], "backup_not_regular_or_size_changed")
        return fields
    before = information()
    output = device.shell("sha256sum", path, timeout=10)
    match = re.fullmatch(r"([0-9a-f]{64})  " + re.escape(path), output)
    require(match is not None and match.group(1) == backup["sha256"], "backup_digest_changed")
    require(information() == before, "backup_changed_during_verification")
    return {"bytes": backup["bytes"], "sha256": backup["sha256"]}


def provider_pid(device, old_pid=None):
    result = device.adb_call("shell", "pidof " + shlex.quote(PROVIDER), timeout=5, allow_failure=True)
    require(result.stderr == b"", "provider_pid_query_unconfirmed")
    if old_pid is not None and result.returncode == 1 and result.stdout == b"":
        return []
    text = result.stdout.decode("ascii", "strict").strip()
    require(result.returncode == 0 and re.fullmatch(r"[1-9][0-9]{0,8}", text), "nonempty_single_old_provider_pid_required")
    if old_pid is not None:
        require(text != old_pid, "old_provider_process_still_present")
        return [text]
    return text


def execute_reset(live, device, root, build, build_sha, journal_raw, checkpoint, backup_receipt,
                  rp_snapshot, input_hashes, rp_get=read_rp):
    """Caller holds driver.lock. Tests inject only an in-memory synthetic Device."""
    journal = unique_json(journal_raw)
    case_id = checkpoint["case_id"]
    _, intent_name, result_name = names(case_id)
    apk, cert = validate_inputs(live, build, build_sha, journal, checkpoint, backup_receipt, rp_snapshot, case_id)
    exact(input_hashes, INPUT_KEYS, "invalid_current_input_hashes")
    require(all(digest(value) for value in input_hashes.values()) and input_hashes["driver"] == DRIVER_SHA256
            and input_hashes["build"] == build_sha and input_hashes["journal"] == sha(journal_raw)
            and input_hashes["backup_receipt"] == checkpoint["backup_receipt_sha256"]
            and input_hashes["rp_snapshot"] == checkpoint["rp_snapshot_sha256"]
            and input_hashes["profile_source"] == PROFILE_SOURCE_SHA256
            and input_hashes["profile_public"] == PROFILE_PUBLIC_SHA256, "invalid_current_input_hashes")
    previous = reset_history(live, root, case_id, build, build_sha)
    if case_id == "G11":
        require(checkpoint["prior_reset_result_sha256"] == previous["result_sha256"], "prior_reset_result_changed")
        validate_stale_input(checkpoint["stale_input"], checkpoint["recovery_backup"], checkpoint["credential"], previous)
        require(backup_receipt["completed_unix_ns"] > previous["result"]["completed_unix_ns"],
                "new_recovery_backup_required_after_prior_reset")
    original_settings = journal["owned_settings"]

    def check_read_only(expected_pid=None):
        require(device.package_hash(PROVIDER) == apk, "provider_apk_changed")
        settings = {key: device.setting(key) for key in live.SETTING_KEYS}
        require(settings == original_settings, "current_settings_changed_preserved")
        backup_observation(device, checkpoint["recovery_backup"])
        if checkpoint["stale_input"] is not None:
            backup_observation(device, checkpoint["stale_input"]["backup"])
        current_rp = rp_state(rp_get(), cert)
        require(current_rp == rp_snapshot, "rp_state_changed")
        pid = provider_pid(device)
        require(expected_pid is None or pid == expected_pid, "provider_process_changed_before_reset")
        require(private_read(root / "journal.private.json") == journal_raw, "journal_changed")
        return pid

    old_pid = check_read_only()
    intent = {"schema": 1, "scope": "same_device_synthetic_provider_pm_clear_intent",
              "case_id": case_id, "reset_id": checkpoint["reset_id"],
              "device_sha256": live.DEVICE_SHA256, "provider_package": PROVIDER, "user": 0,
              "argv": ["pm", "clear", "--user", "0", PROVIDER], "input_sha256": input_hashes,
              "provider_apk_sha256": apk, "settings_before": original_settings, "old_provider_pid": old_pid,
              "recovery_backup": checkpoint["recovery_backup"], "stale_input": checkpoint["stale_input"],
              "rp_snapshot": rp_snapshot, "prior_reset_result_sha256": checkpoint["prior_reset_result_sha256"],
              "operation_may_have_run_after_this_intent": True, "created_unix_ns": time.time_ns()}
    live.atomic(root / intent_name, intent)
    intent_raw = private_read(root / intent_name)
    require(unique_json(intent_raw) == intent, "reset_intent_readback_changed")
    intent_sha = sha(intent_raw)
    dispatched = False
    try:
        # The intent records a possible side effect, not a permission to repeat.
        check_read_only(expected_pid=old_pid)
        dispatched = True
        output = device.adb_call("shell", "pm clear --user 0 " + shlex.quote(PROVIDER), timeout=30)
        require(output.returncode == 0 and output.stdout in (b"Success\n", b"Success\r\n", b"Success")
                and output.stderr == b"", "pm_clear_exact_success_unconfirmed")
        require(device.package_hash(PROVIDER) == apk, "provider_apk_changed_after_reset")
        require({key: device.setting(key) for key in live.SETTING_KEYS} == original_settings, "settings_changed_after_reset")
        post_reset_pids = provider_pid(device, old_pid=old_pid)
        backup_observation(device, checkpoint["recovery_backup"])
        if checkpoint["stale_input"] is not None:
            backup_observation(device, checkpoint["stale_input"]["backup"])
        require(rp_state(rp_get(), cert) == rp_snapshot, "rp_state_changed_after_reset")
        require(private_read(root / "journal.private.json") == journal_raw, "journal_changed_after_reset")
        result = {"schema": 1, "ok": True, "scope": "synthetic_same_device_app_data_reset_only",
                  "case_id": case_id, "reset_id": checkpoint["reset_id"], "device_sha256": live.DEVICE_SHA256,
                  "provider_package": PROVIDER,
                  "intent_sha256": intent_sha, "input_sha256": input_hashes,
                  "provider_apk_sha256": apk, "apk_unchanged": True,
                  "settings_sha256": {k: sha(v.encode()) for k, v in original_settings.items()}, "all_three_settings_unchanged": True,
                  "old_provider_pid_sha256": sha(old_pid.encode()), "nonempty_old_pid_observed": True,
                  "post_reset_provider_pid_sha256": [sha(pid.encode()) for pid in post_reset_pids], "old_provider_process_absence_observed": True,
                  "pm_clear_exit_code": 0, "pm_clear_exact_success_observed": True,
                  "external_recovery_backup": {"bytes": checkpoint["recovery_backup"]["bytes"], "sha256": checkpoint["recovery_backup"]["sha256"]},
                  "stale_input_sha256": None if checkpoint["stale_input"] is None else checkpoint["stale_input"]["backup"]["sha256"],
                  "rp_snapshot_sha256": input_hashes["rp_snapshot"], "rp_key_and_counter_unchanged": True,
                  "credential": checkpoint["credential"], "journal_unchanged": True,
                  "reset_completed": True, "synthetic_only": True, "case_passed": False, "physical_device_migration": False,
                  "production_qualified": False, "completed_unix_ns": time.time_ns()}
        live.atomic(root / result_name, result)
        # Only reaching here proves the result's atomic() returned after both
        # file and directory fsync. A visible result from a failed atomic()
        # cannot reach this witness creation, even if failure reporting fails.
        result_raw = private_read(root / result_name)
        require(unique_json(result_raw) == result, "reset_result_readback_changed")
        completion = {"schema": 1, "scope": "reset_result_durability_witness", "case_id": case_id,
                      "reset_id": checkpoint["reset_id"], "device_sha256": live.DEVICE_SHA256,
                      "provider_package": PROVIDER, "intent_sha256": intent_sha, "result_sha256": sha(result_raw),
                      "result_persisted_before_witness": True, "completed_unix_ns": time.time_ns()}
        live.atomic(root / completion_name(case_id), completion)
        return result
    except Exception:
        # Preserve the original intent. Even a pre-dispatch failure is fenced;
        # retries require an independent reconciliation, never another pm clear.
        failure = {"schema": 1, "ok": False, "scope": "synthetic_same_device_app_data_reset_only",
                   "case_id": case_id, "reset_id": checkpoint["reset_id"], "device_sha256": live.DEVICE_SHA256,
                   "provider_package": PROVIDER,
                   "intent_sha256": intent_sha, "dispatch_attempted": dispatched,
                   "error": "reset_postconditions_unconfirmed_reconcile_before_retry" if dispatched else "reset_pre_dispatch_changed_reconcile_before_retry",
                   "reset_completed": False, "production_qualified": False}
        # This diagnostic is best effort. Safety does not depend on replacing a
        # provisional success: no completion witness exists for an uncertain
        # result, and all later cases reject that incomplete record set.
        live.atomic(root / result_name, failure)
        raise


def schema():
    backup = {"device_path": "/sdcard/Download/HeptaBao-Passkey-QA-20261106-r7/heptabao-passkey-backup.hbv",
              "bytes": "ACTUALLY_OBSERVED_INTEGER", "sha256": "ACTUALLY_OBSERVED_SHA256"}
    credential = {"credential_id": "FROM_ACTUAL_RP_STATE", "public_key_sha256": "FROM_ACTUAL_RP_STATE",
                  "sign_count": "ACTUAL_POSITIVE_INTEGER", "flags": "ACTUAL_INTEGER_13_OR_29"}
    checkpoint = {"schema": 1, "scope": "same_device_synthetic_provider_reset", "case_id": "M05", "reset_id": "M05-reset-1",
                "device_sha256": "FROM_RUN_JOURNAL",
                "build_receipt_sha256": "FROZEN_BUILD_SHA256", "provider_apk_sha256": "FROZEN_PROVIDER_APK_SHA256", "recovery_backup": backup,
                "backup_receipt_file": "m04-backup-verified.private.json", "backup_receipt_sha256": "ACTUAL_FILE_SHA256",
                "rp_snapshot_file": "m05-rp-before.private.json", "rp_snapshot_sha256": "ACTUAL_FILE_SHA256",
                "rp_source_sha256": RP_SOURCE_SHA256,
                "profile_source_sha256": PROFILE_SOURCE_SHA256, "profile_public_sha256": PROFILE_PUBLIC_SHA256,
                "credential": credential, "created_unix_ns": "ACTUAL_INTEGER", "stale_input": None, "prior_reset_result_sha256": None}
    receipt = {"schema": 1, "scope": "observed_ordinary_saf_backup_for_reset", "source_case_id": "M04", "device_sha256": "FROM_RUN_JOURNAL",
                "build_receipt_sha256": "FROZEN_BUILD_SHA256", "provider_apk_sha256": "FROZEN_PROVIDER_APK_SHA256", "observed_backup": backup,
                "ordinary_saf_export_observed": "TRUE_ONLY_AFTER_REAL_OBSERVATION", "provider_write_readback_verified": "TRUE_ONLY_AFTER_REAL_OBSERVATION",
                "synthetic_directory_initial_absent": "TRUE_ONLY_FROM_PRE_ACTION_DOCUMENT_JOURNAL", "completed_unix_ns": "ACTUAL_INTEGER",
                "rp_before_sha256": "SAME_ACTUAL_RP_SNAPSHOT_FILE_SHA256", "rp_after_sha256": "SAME_ACTUAL_RP_SNAPSHOT_FILE_SHA256", "credential": credential}
    g11 = copy.deepcopy(checkpoint)
    g11.update(case_id="G11", reset_id="G11-reset-1", backup_receipt_file="g11-current-backup.private.json",
               rp_snapshot_file="g11-rp-before.private.json", prior_reset_result_sha256="ACTUAL_M05_RESET_RESULT_SHA256")
    g11["recovery_backup"]["device_path"] = backup["device_path"].replace("-backup.hbv", "-latest-recovery.hbv")
    g11["recovery_backup"]["sha256"] = "ACTUAL_CURRENT_RECOVERY_SHA256_DIFFERENT_FROM_STALE_INPUT"
    stale = copy.deepcopy(backup); stale["device_path"] = backup["device_path"].replace("-backup.hbv", "-stale-input.hbv")
    g11["stale_input"] = {"backup": stale, "credential": "EXACT_M05_PRE_RESET_PUBLIC_CREDENTIAL_WITH_OLDER_COUNTER",
                          "source_reset_result_sha256": "ACTUAL_M05_RESET_RESULT_SHA256"}
    g11_receipt = copy.deepcopy(receipt)
    g11_receipt.update(source_case_id="G11_RECOVERY_EXPORT", observed_backup=g11["recovery_backup"])
    return {"scope": "input_schema_only_not_device_evidence", "driver_sha256": DRIVER_SHA256,
            "case_filenames": {case: dict(zip(("checkpoint", "intent", "result", "completion"),
                                              (*names(case), completion_name(case)))) for case in CASES},
            "checkpoint_M05": checkpoint, "observed_backup_receipt_M05": receipt,
            "checkpoint_G11": g11, "observed_backup_receipt_G11": g11_receipt,
            "rp_snapshot": "Exact bounded JSON response from fixed http://127.0.0.1:38491/state, including ok; no private key or password.",
            "backup_rules": "Observe ordinary SAF export with unchanged RP before/after. The current RP credential/key/count must still equal that export. A same-SHA copy may use another allowed leaf in the same run directory. G11 requires a NEW current export after M05; its separate stale input must match M05's actual prior backup digest/length/credential and have a strictly older counter. No counter editing.",
            "fence_rules": "Only M05 then G11, one reset each. Prior success requires a matching completion witness written only after result file+directory fsync returned. An existing witness is re-synced through its validated descriptor and parent before use; a missing witness is never manufactured. Any unknown, incomplete, failed, or malformed record fences both cases; no case-ID change or automatic pm clear repeat resolves it.",
            "file_rules": "All JSON evidence: single safe filename in root; mode0600, same owner, ordinary non-symlink single-link file. Existing journal and prior reset records are never modified."}


def self_test(live):
    """Meaningful negative controls; fake devices never invoke subprocess/ADB."""
    from unittest import mock
    os.umask(0o077)
    passed = []
    apk, cert, build_sha = PROVIDER_APK_SHA256, FIXTURE_CERT_SHA256, BUILD_RECEIPT_SHA256
    components = sorted({live.SERVICE, PROVIDER + "/.ProviderService"})
    original = {"credential_service": "", "credential_service_primary": "", "autofill_service": "synthetic.original/.Service"}
    joints = [{"credential_service": a, "credential_service_primary": b, "autofill_service": live.SYSTEM_BRIDGE} for a in components for b in components]
    intent = {"kind": "select_primary_with_verified_system_bridge_from_empty", "before": original,
              "allowed_after": {"credential_service": components, "credential_service_primary": components, "autofill_service": [live.SYSTEM_BRIDGE]},
              "joint_after": joints, "bridge": {"component": live.SYSTEM_BRIDGE, "apk_path": live.SYSTEM_BRIDGE_APK,
                "apk_sha256": live.SYSTEM_BRIDGE_SHA256, "system_flag": True, "service_query": live.SYSTEM_BRIDGE_SHORT}, "armed_unix_ns": 1}
    build = {"fixture_certificate_sha256": cert, "artifacts": {"provider": {"package": PROVIDER, "sha256": apk},
                           "fixture-good": {"package": live.FIXTURE, "sha256": "e" * 64, "certificate_sha256": cert}}}
    journal = {"schema": 1, "device_sha256": live.DEVICE_SHA256, "build_receipt_sha256": build_sha, "started_unix_ns": 1,
               "original_settings": original, "owned_settings": joints[0], "settings_intent": intent, "owned_packages": {PROVIDER: [apk]},
               "initial_packages_absent": {p: True for p in live.OWNED}, "install_intents": [{"variant": "provider", "package": PROVIDER, "sha256": apk, "attempted_unix_ns": 1}],
               "reverse_owned": True, "phases": [], "credential_entry": "synthetic_only_adb_input_text_argv", "production_qualified": False,
               "credential_manager_exercised": False, "p4_qualified": False}
    credential = {"credential_id": base64.urlsafe_b64encode(b"i" * 32).decode().rstrip("="), "public_key_sha256": "f" * 64, "sign_count": 1, "flags": 13}
    rp = {"ok": True, "rp_id": RP_ID, "fixture_cert_sha256": cert, "origin": "android:apk-key-hash:" + base64.urlsafe_b64encode(bytes.fromhex(cert)).decode().rstrip("="),
          "revision": 5, "credential_count": 1, "ceremony_counts": {"pending": 0, "consumed": 2, "restart_invalidated": 0},
          "counters": {"options": 2, "verification_attempts": 2, "registrations": 1, "authentications": 1, "rejected": 0, "restart_invalidated": 0},
          "event_count": 5, "credentials": [credential]}
    backup = {"device_path": "/sdcard/Download/HeptaBao-Passkey-QA-20261106-r7/heptabao-passkey-backup.hbv", "bytes": 700, "sha256": "d" * 64}
    m04 = {"schema": 1, "scope": "observed_ordinary_saf_backup_for_reset", "source_case_id": "M04",
           "device_sha256": live.DEVICE_SHA256, "build_receipt_sha256": build_sha,
           "provider_apk_sha256": apk, "observed_backup": backup, "ordinary_saf_export_observed": True, "provider_write_readback_verified": True,
           "synthetic_directory_initial_absent": True, "completed_unix_ns": 2,
           "rp_before_sha256": sha(canonical(rp)), "rp_after_sha256": sha(canonical(rp)), "credential": credential}
    checkpoint = {"schema": 1, "scope": "same_device_synthetic_provider_reset", "case_id": "M05", "reset_id": "M05-reset-1",
                  "device_sha256": live.DEVICE_SHA256,
                  "build_receipt_sha256": build_sha, "provider_apk_sha256": apk, "recovery_backup": backup,
                  "backup_receipt_file": "m04.private.json", "backup_receipt_sha256": sha(canonical(m04)),
                  "rp_snapshot_file": "rp.private.json", "rp_snapshot_sha256": sha(canonical(rp)), "rp_source_sha256": RP_SOURCE_SHA256,
                  "profile_source_sha256": PROFILE_SOURCE_SHA256, "profile_public_sha256": PROFILE_PUBLIC_SHA256,
                  "credential": credential, "created_unix_ns": 3, "stale_input": None, "prior_reset_result_sha256": None}

    def hashes_for(raw, c, m, r):
        return {"driver": DRIVER_SHA256, "helper": sha(Path(__file__).read_bytes()), "journal": sha(raw), "build": build_sha,
                "checkpoint": sha(canonical(c)), "backup_receipt": sha(canonical(m)), "rp_snapshot": sha(canonical(r)),
                "profile_source": PROFILE_SOURCE_SHA256, "profile_public": PROFILE_PUBLIC_SHA256}

    class FakeDevice:
        def __init__(self, root):
            self.root = root; self.apk = apk; self.settings = dict(joints[0]); self.pid = "12345"
            self.clear_calls = 0; self.pid_calls = 0; self.mode = "81a4"; self.backup_sha = None
            self.backups = {backup["device_path"]: (backup["bytes"], backup["sha256"])}; self.case_id = "M05"
            self.rp = copy.deepcopy(rp); self.fault = None; self.apk_calls = 0
        def package_hash(self, package):
            require(package == PROVIDER, "test_scope_failure")
            self.apk_calls += 1
            if self.fault == "changed_before_dispatch" and self.apk_calls == 2: return "0" * 64
            return self.apk
        def setting(self, key): return self.settings[key]
        def shell(self, *args, **kwargs):
            path = args[-1]; size, digest_value = self.backups[path]
            if args[0] == "stat": return self.mode + " " + str(size) + " 1 2 3 4"
            if args[0] == "sha256sum": return (self.backup_sha or digest_value) + "  " + path
            raise AssertionError("unexpected_fake_device_shell")
        def adb_call(self, *args, **kwargs):
            if args == ("shell", "pidof " + PROVIDER):
                self.pid_calls += 1
                if self.fault == "pid_query_error": return subprocess.CompletedProcess([], 255, b"", b"offline")
                return subprocess.CompletedProcess([], 0 if self.pid else 1, (self.pid + "\n").encode() if self.pid else b"", b"")
            require(args == ("shell", "pm clear --user 0 " + PROVIDER), "test_scope_failure")
            require((self.root / names(self.case_id)[1]).is_file(), "test_intent_missing_before_clear")
            self.clear_calls += 1
            if self.fault == "clear_nonzero": return subprocess.CompletedProcess([], 1, b"Success\n", b"")
            if self.fault == "clear_extra_output": return subprocess.CompletedProcess([], 0, b"Success\nunknown\n", b"")
            if self.fault != "old_pid_remains": self.pid = ""
            if self.fault == "system_rebind_distinct_pid": self.pid = "34567"
            if self.fault == "settings_after": self.settings["autofill_service"] = "unrelated/.Service"
            if self.fault == "apk_after": self.apk = "0" * 64
            if self.fault == "rp_after": self.rp["credentials"][0]["sign_count"] += 1
            return subprocess.CompletedProcess([], 0, b"Success\n", b"")

    class SimulatedTermination(BaseException):
        """Stop before execute_reset's Exception handler, without a real child."""

    def trial(name, change=None, expected_clear=0, success=False, intent_failure=False, repeat=False,
              result_failure=False, double_failure=False, simulated_termination=False, expected_error=None):
        with tempfile.TemporaryDirectory(prefix="passkey-reset-stub-") as directory:
            root = Path(directory); d = FakeDevice(root)
            j, c, m, r = map(copy.deepcopy, (journal, checkpoint, m04, rp))
            if change: change(d, j, c, m, r)
            raw = canonical(j); (root / "journal.private.json").write_bytes(raw)
            (root / "journal.private.json").chmod(0o600)
            if repeat: (root / names("M05")[1]).write_text("previous intent retained")
            hashes = hashes_for(raw, c, m, r)
            try:
                if intent_failure:
                    with mock.patch.object(live, "atomic", side_effect=OSError("synthetic_fsync_failure")):
                        execute_reset(live, d, root, build, build_sha, raw, c, m, r, hashes, lambda: copy.deepcopy(d.rp))
                elif result_failure or double_failure or simulated_termination:
                    real_atomic = live.atomic
                    real_fsync = os.fsync
                    failure_writes = []
                    def fail_directory_fsync(fd):
                        if stat.S_ISDIR(os.fstat(fd).st_mode):
                            raise OSError("synthetic_result_directory_fsync_failure")
                        return real_fsync(fd)
                    def uncertain_result(path, value):
                        if path.name == names("M05")[2] and value.get("ok") is True:
                            if double_failure or simulated_termination:
                                # Exercise the actual atomic ordering: its file
                                # fsync and rename run; its directory fsync fails.
                                with mock.patch.object(os, "fsync", side_effect=fail_directory_fsync):
                                    try: real_atomic(path, value)
                                    except OSError:
                                        if simulated_termination:
                                            raise SimulatedTermination() from None
                                        raise
                            else:
                                real_atomic(path, value)
                                raise OSError("synthetic_failure_after_result_rename")
                        elif path.name == names("M05")[2] and value.get("ok") is False and double_failure:
                            failure_writes.append("attempted_before_replace")
                            raise OSError("synthetic_failure_diagnostic_write_failure")
                        else:
                            real_atomic(path, value)
                    with mock.patch.object(live, "atomic", side_effect=uncertain_result):
                        execute_reset(live, d, root, build, build_sha, raw, c, m, r, hashes, lambda: copy.deepcopy(d.rp))
                else:
                    result = execute_reset(live, d, root, build, build_sha, raw, c, m, r, hashes, lambda: copy.deepcopy(d.rp))
                assert success and result["ok"] and not result["case_passed"]
            except (Failed, live.Failed, OSError, SimulatedTermination) as error:
                assert not success, name
                if expected_error is not None: assert isinstance(error, Failed) and str(error) == expected_error, name
            assert d.clear_calls == expected_clear, name
            if expected_clear and not success:
                failure = unique_json((root / names("M05")[2]).read_bytes())
                if double_failure or simulated_termination:
                    # A complete-looking success really remains on disk. It
                    # must not become a reusable success without its witness.
                    assert failure["ok"] is True and failure["reset_completed"] is True
                    assert not os.path.lexists(root / completion_name("M05"))
                    assert failure_writes == (["attempted_before_replace"] if double_failure else [])
                else:
                    assert failure["ok"] is False and failure["reset_completed"] is False
                for case in CASES:
                    try: reset_history(live, root, case, build, build_sha)
                    except Failed: pass
                    else: raise AssertionError("failed_reset_did_not_fence_provider")
            passed.append(name)

    # Crosscheck failures enter the real execute_reset path and cannot call the
    # fake device's pm clear, even when their other input bindings are coherent.
    saved_build_sha = build_sha
    build_sha = "0" * 64
    def other_build(d, j, c, m, r):
        j["build_receipt_sha256"] = build_sha
        c["build_receipt_sha256"] = build_sha
        m["build_receipt_sha256"] = build_sha
        c["backup_receipt_sha256"] = sha(canonical(m))
    try:
        trial("different_self_consistent_build_denied", other_build,
              expected_error="profile_build_binding_changed")
    finally:
        build_sha = saved_build_sha
    saved_apk = build["artifacts"]["provider"]["sha256"]
    build["artifacts"]["provider"]["sha256"] = "0" * 64
    def other_provider(d, j, c, m, r):
        d.apk = "0" * 64
        j["owned_packages"][PROVIDER] = [d.apk]
        j["install_intents"][0]["sha256"] = d.apk
        c["provider_apk_sha256"] = d.apk
        m["provider_apk_sha256"] = d.apk
        c["backup_receipt_sha256"] = sha(canonical(m))
    try:
        trial("different_self_consistent_provider_artifact_denied", other_provider,
              expected_error="profile_provider_binding_changed")
    finally:
        build["artifacts"]["provider"]["sha256"] = saved_apk
    saved_cert = build["artifacts"]["fixture-good"]["certificate_sha256"]
    build["artifacts"]["fixture-good"]["certificate_sha256"] = "0" * 64
    build["fixture_certificate_sha256"] = "0" * 64
    def other_fixture(d, j, c, m, r):
        r["fixture_cert_sha256"] = "0" * 64
        r["origin"] = "android:apk-key-hash:" + base64.urlsafe_b64encode(bytes(32)).decode().rstrip("=")
        d.rp = copy.deepcopy(r)
        c["rp_snapshot_sha256"] = sha(canonical(r))
        m["rp_before_sha256"] = m["rp_after_sha256"] = sha(canonical(r))
        c["backup_receipt_sha256"] = sha(canonical(m))
    try:
        trial("different_self_consistent_fixture_certificate_denied", other_fixture,
              expected_error="profile_fixture_binding_changed")
    finally:
        build["artifacts"]["fixture-good"]["certificate_sha256"] = saved_cert
        build["fixture_certificate_sha256"] = saved_cert

    trial("positive_exact_single_clear_after_durable_intent", expected_clear=1, success=True)
    trial("positive_system_rebind_has_distinct_new_pid", lambda d,j,c,m,r: setattr(d, "fault", "system_rebind_distinct_pid"), expected_clear=1, success=True)
    trial("initially_present_provider_denied", lambda d,j,c,m,r: j["initial_packages_absent"].__setitem__(PROVIDER, False))
    trial("unknown_apk_denied", lambda d,j,c,m,r: setattr(d, "apk", "0" * 64))
    trial("missing_provider_ownership_denied", lambda d,j,c,m,r: j["owned_packages"].clear())
    trial("unverified_m04_denied", lambda d,j,c,m,r: m.__setitem__("provider_write_readback_verified", False))
    trial("outside_owned_backup_path_denied", lambda d,j,c,m,r: c["recovery_backup"].__setitem__("device_path", "/sdcard/Download/other.hbv"))
    trial("backup_symlink_type_denied", lambda d,j,c,m,r: setattr(d, "mode", "a1ff"))
    trial("backup_digest_mismatch_denied", lambda d,j,c,m,r: setattr(d, "backup_sha", "0" * 64))
    trial("rp_key_changed_denied", lambda d,j,c,m,r: d.rp["credentials"][0].__setitem__("public_key_sha256", "0" * 64))
    trial("rp_counter_changed_denied", lambda d,j,c,m,r: d.rp["credentials"][0].__setitem__("sign_count", 2))
    trial("no_old_pid_denied", lambda d,j,c,m,r: setattr(d, "pid", ""))
    trial("ambiguous_old_pid_denied", lambda d,j,c,m,r: setattr(d, "pid", "123 456"))
    trial("pid_transport_failure_denied", lambda d,j,c,m,r: setattr(d, "fault", "pid_query_error"))
    trial("intent_persistence_failure_prevents_clear", intent_failure=True)
    trial("published_result_fsync_error_remains_fenced", expected_clear=1, result_failure=True)
    trial("result_dir_fsync_and_failure_write_both_fail_fences_provider", expected_clear=1, double_failure=True)
    trial("termination_after_result_rename_before_failure_write_fences_provider", expected_clear=1, simulated_termination=True)
    trial("state_change_after_intent_prevents_clear", lambda d,j,c,m,r: setattr(d, "fault", "changed_before_dispatch"))
    trial("existing_intent_never_repeats_clear", repeat=True)
    for fault in ("clear_nonzero", "clear_extra_output", "old_pid_remains", "settings_after", "apk_after", "rp_after"):
        trial(fault + "_not_completed", lambda d,j,c,m,r,f=fault: setattr(d, "fault", f), expected_clear=1)
    trial("backup_counter_behind_rp_denied", lambda d,j,c,m,r: m["credential"].__setitem__("sign_count", 0))
    trial("rp_changed_during_export_denied", lambda d,j,c,m,r: m.__setitem__("rp_after_sha256", "0" * 64))
    trial("old_profile_binding_denied", lambda d,j,c,m,r: c.__setitem__("profile_source_sha256", "0" * 64))

    def second_case(name, fault=None):
        with tempfile.TemporaryDirectory(prefix="passkey-reset-sequence-stub-") as directory:
            root = Path(directory); d = FakeDevice(root)
            raw = canonical(journal); (root / "journal.private.json").write_bytes(raw)
            (root / "journal.private.json").chmod(0o600)
            execute_reset(live, d, root, build, build_sha, raw, checkpoint, m04, rp,
                          hashes_for(raw, checkpoint, m04, rp), lambda: copy.deepcopy(d.rp))
            old_result_path = root / names("M05")[2]
            old_result = unique_json(old_result_path.read_bytes()); old_result_sha = sha(old_result_path.read_bytes())
            d.case_id = "G11"; d.pid = "23456"; d.apk_calls = 0
            d.rp["revision"] += 2; d.rp["event_count"] += 2
            d.rp["counters"]["options"] += 1; d.rp["counters"]["verification_attempts"] += 1
            d.rp["counters"]["authentications"] += 1; d.rp["ceremony_counts"]["consumed"] += 1
            d.rp["credentials"][0]["sign_count"] = 2; d.rp["credentials"][0]["flags"] = 29
            r = copy.deepcopy(d.rp); rp_sha = sha(canonical(r))
            recovery = {"device_path": backup["device_path"].replace("-backup.hbv", "-latest-recovery.hbv"), "bytes": 701, "sha256": "9" * 64}
            stale = copy.deepcopy(backup); stale["device_path"] = backup["device_path"].replace("-backup.hbv", "-stale-input.hbv")
            d.backups[recovery["device_path"]] = (701, recovery["sha256"])
            d.backups[stale["device_path"]] = (700, stale["sha256"])
            m = copy.deepcopy(m04)
            m.update(source_case_id="G11_RECOVERY_EXPORT", observed_backup=recovery, completed_unix_ns=time.time_ns(),
                     rp_before_sha256=rp_sha, rp_after_sha256=rp_sha, credential=r["credentials"][0])
            c = copy.deepcopy(checkpoint)
            c.update(case_id="G11", reset_id="G11-reset-1", recovery_backup=recovery,
                     backup_receipt_file="g11-backup.private.json", rp_snapshot_file="g11-rp.private.json",
                     rp_snapshot_sha256=rp_sha, credential=r["credentials"][0], created_unix_ns=time.time_ns(),
                     prior_reset_result_sha256=old_result_sha,
                     stale_input={"backup": stale, "credential": copy.deepcopy(credential), "source_reset_result_sha256": old_result_sha})
            if fault == "prior_result_missing": old_result_path.unlink()
            if fault == "prior_result_failed":
                old_result["ok"] = False; live.atomic(old_result_path, old_result)
            if fault == "prior_result_incomplete":
                del old_result["old_provider_process_absence_observed"]; live.atomic(old_result_path, old_result)
            if fault == "prior_intent_changed":
                path = root / names("M05")[1]; value = unique_json(path.read_bytes())
                value["old_provider_pid"] = "99999"; live.atomic(path, value)
            if fault == "unknown_case_record":
                (root / "provider-reset-G12-intent.private.json").write_bytes(b"{}")
            if fault == "old_case_repeated":
                c, m, r = map(copy.deepcopy, (checkpoint, m04, rp)); d.rp = copy.deepcopy(r)
            if fault == "recovery_is_stale":
                c["recovery_backup"]["sha256"] = stale["sha256"]
            if fault == "stale_counter_not_older": c["stale_input"]["credential"]["sign_count"] = 2
            if fault == "stale_digest_not_historical": c["stale_input"]["backup"]["sha256"] = "8" * 64
            if fault == "stale_path_same_as_recovery": c["stale_input"]["backup"]["device_path"] = recovery["device_path"]
            if fault == "recovery_export_not_new": m["completed_unix_ns"] = old_result["completed_unix_ns"]
            if fault == "second_reset_clear_unknown": d.fault = "clear_nonzero"
            c["backup_receipt_sha256"] = sha(canonical(m))
            try:
                result = execute_reset(live, d, root, build, build_sha, raw, c, m, r,
                                       hashes_for(raw, c, m, r), lambda: copy.deepcopy(d.rp))
                assert fault is None and result["ok"] and result["case_id"] == "G11" and not result["case_passed"], name
            except (Failed, live.Failed, OSError):
                assert fault is not None, name
            assert d.clear_calls == (2 if fault in (None, "second_reset_clear_unknown") else 1), name
            if fault == "second_reset_clear_unknown":
                for attempted_case in CASES:
                    try: reset_history(live, root, attempted_case, build, build_sha)
                    except Failed: pass
                    else: raise AssertionError("unknown_second_reset_must_fence_every_case")
            passed.append(name)

    second_case("confirmed_m05_then_new_backup_g11_exactly_once")
    for fault in ("prior_result_missing", "prior_result_failed", "prior_result_incomplete", "prior_intent_changed",
                  "unknown_case_record", "old_case_repeated", "recovery_is_stale", "stale_counter_not_older",
                  "stale_digest_not_historical", "stale_path_same_as_recovery", "recovery_export_not_new", "second_reset_clear_unknown"):
        second_case(fault + "_fences_provider", fault)
    for name, raw in (("duplicate_json_key_denied", b'{"a":1,"a":2}'), ("nonfinite_json_denied", b'{"n":1e999}')):
        try: unique_json(raw)
        except Failed: passed.append(name)
        else: raise AssertionError(name)
    with tempfile.TemporaryDirectory(prefix="passkey-reset-path-") as directory:
        root = Path(directory); target = root / "plain.json"; target.write_bytes(b"{}"); target.chmod(0o600)
        (root / "link.json").symlink_to(target)
        for name, path in (("private_symlink_denied", root / "link.json"),):
            try: private_read(path)
            except (Failed, OSError): passed.append(name)
            else: raise AssertionError(name)
        try: relative_json(root, "../outside.json")
        except Failed: passed.append("traversal_evidence_name_denied")
        else: raise AssertionError("traversal_evidence_name_denied")
    return {"schema": 1, "scope": "host_only_reset_helper_stubs", "checks": passed, "passed": len(passed),
            "adb_calls": 0, "network_calls": 0, "phone_qualified": False, "author_self_test_not_independent_review": True,
            "driver_sha256": DRIVER_SHA256, "helper_sha256": sha(Path(__file__).read_bytes())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", type=Path, default=Path(__file__).with_name("passkey_live.py"))
    parser.add_argument("--adb", type=Path)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--expected-build-sha256")
    parser.add_argument("--expected-checkpoint-sha256")
    parser.add_argument("--case-id", choices=CASES)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--schema", action="store_true")
    args = parser.parse_args(); os.umask(0o077)
    if args.schema:
        print(json.dumps(schema(), sort_keys=True, indent=2)); return
    live = load_driver(args.driver.absolute())
    if args.self_test:
        from unittest import mock
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("host_test_subprocess_forbidden")), \
             mock.patch.object(subprocess, "Popen", side_effect=AssertionError("host_test_subprocess_forbidden")), \
             mock.patch.object(urllib.request.OpenerDirector, "open", side_effect=AssertionError("host_test_http_forbidden")):
            report = self_test(live)
        report["subprocess_and_http_disabled"] = True
        print(json.dumps(report, sort_keys=True)); return
    require(args.adb is not None and args.root is not None and args.artifacts is not None
            and args.case_id in CASES and digest(args.expected_build_sha256)
            and digest(args.expected_checkpoint_sha256), "reset_arguments_missing")
    root, artifacts = args.root.absolute(), args.artifacts.absolute()
    live.private_directory(root.parent); live.private_directory(root); live.private_directory(artifacts)
    lock = os.open(root / "driver.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(lock)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_nlink == 1, "unsafe_driver_lock")
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise Failed("driver_phase_already_running") from None
        checkpoint_name, _, _ = names(args.case_id)
        build_raw = private_read(artifacts / "build.receipt.json")
        checkpoint_raw = private_read(root / checkpoint_name)
        profile_raw = private_read(root / "profile.public.json")
        require(sha(build_raw) == args.expected_build_sha256 and sha(checkpoint_raw) == args.expected_checkpoint_sha256, "input_digest_changed")
        require(sha(profile_raw) == PROFILE_PUBLIC_SHA256, "run_profile_changed")
        build, checkpoint = unique_json(build_raw), unique_json(checkpoint_raw)
        journal_raw = private_read(root / "journal.private.json")
        backup_raw = private_read(relative_json(root, checkpoint["backup_receipt_file"]))
        rp_raw = private_read(relative_json(root, checkpoint["rp_snapshot_file"]))
        require(sha(backup_raw) == checkpoint["backup_receipt_sha256"] and sha(rp_raw) == checkpoint["rp_snapshot_sha256"], "backup_or_rp_evidence_changed")
        backup_receipt, rp_snapshot = unique_json(backup_raw), unique_json(rp_raw)
        validate_inputs(live, build, args.expected_build_sha256, unique_json(journal_raw), checkpoint, backup_receipt, rp_snapshot, args.case_id)
        reset_history(live, root, args.case_id, build, args.expected_build_sha256)
        device = live.Device(args.adb)
        hashes = {"driver": DRIVER_SHA256, "helper": sha(private_read(Path(__file__).absolute(), code_source=True)), "build": sha(build_raw),
                  "journal": sha(journal_raw), "checkpoint": sha(checkpoint_raw), "backup_receipt": sha(backup_raw), "rp_snapshot": sha(rp_raw),
                  "profile_source": PROFILE_SOURCE_SHA256, "profile_public": sha(profile_raw)}
        result = execute_reset(live, device, root, build, args.expected_build_sha256, journal_raw,
                               checkpoint, backup_receipt, rp_snapshot, hashes)
        print(json.dumps(result, sort_keys=True))
    finally:
        os.close(lock)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # An existing intent is deliberately not removed or overwritten here.
        print(json.dumps({"ok": False, "scope": "synthetic_same_device_app_data_reset_only",
                          "error": "reset_failed_or_unknown_reconcile_existing_intent_before_retry",
                          "production_qualified": False}, sort_keys=True))
        raise SystemExit(1) from None
