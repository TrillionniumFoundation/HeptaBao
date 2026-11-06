#!/usr/bin/env python3
"""Read only the two fixed r2 summaries. Emit an explicit safe projection."""
import time
START = time.monotonic()
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import sys

ROOT = Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1")
SOURCE = ROOT / "source-dr25-a2577-r2"
WORK = ROOT / "full34-dr25-r2"
DR_PATH = WORK / "dr25-summary.json"
BASELINE_PATH = WORK / "quarantine/original-closure/summary.json"
WRAPPER_PATH = ROOT / "dr25-execution-4bde9-r2/result.public.json"
QA_COMMIT = "a25772377e9bfad91564cf6702a26e861fded16f"
QA_TREE = "d34d344e261811c406f63de56b3a7227c0e0ddf3"
PRODUCT_COMMIT = "4bde9aee03fcd27c59e13607e529b1cee594b249"
PRODUCT_TREE = "f08493a23f8ea0637073651231865ea9607b790e"
WRAPPER_SHA = "22a0c151ad3c1a075d6763f0b3d7037eed12a21d19e84d9b94fadd91ff44fc9f"
PYTHON_SHA = "cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13"
SOURCE_PINS = {"kv2_271_lossless_native_live.py":{"bytes":49393,"sha256":"383176647f0670837f40f3989496c6d1c902f8503dfa006d386b75877436b581"},"kv2_dr_process_custody.py":{"bytes":26131,"sha256":"669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008"},"kv2_native_fresh_directory_dr_live.py":{"bytes":75012,"sha256":"2271a4ca539e1190b03e95e95d4d1c79414bd852c80ac85e205def2adac74263"}}
DR_CASES = ["input_source_and_binaries_pinned","official_271_live_identity_verified","official_full34_api_and_raw_history_bound","normal_native_v6_file_profile","preactivation_seed_export_pinned","independent_backup_filesystem_verified","official_cli_v6_save_complete","complete_v6_archive_seal_binding","backup_manifest_and_separate_key_custody","original_processes_stopped","original_directories_quarantined","fresh_recovery_directory_and_tls_identity","exact_seed_stage_verified","old_closure_negative_cannot_read_history","wrong_unseal_key_denied","tampered_archive_denied_without_commit","official_cli_v6_restore_once","restored_api_19_versions_exact","restored_raw_19_versions_exact","restored_cold_reopen_history_exact","soft_deleted_payload_undelete_exact","destroyed_payload_not_resurrected","data_and_metadata_cas_guards_exact","new_write_survives_cold_reopen","final_custody_cleanup_and_redaction"]
BASELINE_CASES = ["official_271_pins_and_live_identity","two_distinct_owned_processes","source_api_oracle_captured","source_retained_deleted_destroyed_seeded","source_metadata_cas_seeded","source_cold_restart_exact","target_pristine_before_import","source_export_once","source_raw_history_exact","exported_soft_deleted_payload_preserved","source_unchanged_after_export","target_import_once","target_active_native_v6","target_full_history_exact","target_storage_full_history_exact","target_cold_restart_exact","target_storage_cold_history_exact","snapshot_download","post_snapshot_mutation_once","snapshot_restore_once","restored_cold_history_exact","restored_storage_history_exact","soft_deleted_payload_undelete_exact","destroyed_payload_remains_absent","data_cas_denied_without_effect","metadata_cas_denied_without_effect","metadata_cas_success_counter_exact","source_unchanged_after_target_mutations","source_and_binary_unchanged","owned_processes_stopped","report_excludes_runtime_credentials"]
STORAGE_CASES = ["target_storage_full_history_exact","target_storage_cold_history_exact","restored_storage_history_exact"]
CAPTURE_CASES = BASELINE_CASES[:18]
ARCHIVE_NAMES = ["meta.json", "state.bin", "SHA256SUMS", "SHA256SUMS.sealed"]
SEED_NAMES = ["state.hbs", "journal.hbj", "ledger.hbl", "seal.json"]
BACKUP_NAMES = ["native-v6.snap", "seed-export.json", "oracle-witness.json"] + ["seed/" + x for x in SEED_NAMES]
COMMAND_NAMES = ["seed_export", "official_v6_save", "seed_stage", "tampered_v6_restore", "official_v6_restore"]
VERSIONS = list(range(1, 20))
IDENTITY_COLUMNS = ["pid", "ppid", "pgid", "sid", "uid", "start_ticks", "state"]
CHILD_COLUMNS = ["index", "exec_admitted", "original_wait_completed", "original_wait_count", "returncode",
                 "no_live_members_before_reap", "gaps_count", "birth", "members_at_leader_exit",
                 "members_before_original_reap"]
DEADLINE_FIRED = False
REPORT = {
    "schema": "heptabao.mac-dr25-r2-independent-safe-projection.v1",
    "actual_dr_job": "1a1b1639f4d-fc05-7839",
    "read_only": True, "products_or_services_started": False, "tests_rerun": False,
    "archive_key_manifest_or_private_log_contents_opened": False,
    "private_summary_bytes_or_fingerprints_emitted": False,
    "qa_commit": QA_COMMIT, "qa_tree": QA_TREE, "product_commit": PRODUCT_COMMIT, "product_tree": PRODUCT_TREE,
    "work_deadline_seconds": 52, "runtime_cap_seconds": 60,
    "durable_completion_authority": "separate_original_runtime_terminal_with_60_second_cap",
    "elapsed_observation_before_receipt_publication": True,
    "real_business_credentials_tested": False, "physical_ha_qualified": False,
    "production_authority": False, "formal_replacement_qualified": False,
    "all_clients_and_backups_migrated": False,
}

class Refused(Exception):
    pass

def need(value, code):
    if not value:
        raise Refused(code)

def check():
    need(not DEADLINE_FIRED and time.monotonic() < START + 52, "original_projection_deadline")

def alarm(_number, _frame):
    global DEADLINE_FIRED
    DEADLINE_FIRED = True
    raise Refused("original_projection_deadline")

def unique(pairs):
    out = {}
    for key, value in pairs:
        need(key not in out, "duplicate_json_key")
        out[key] = value
    return out

def bad_constant(_value):
    raise Refused("nonfinite_json_constant")

def ident(info):
    return [getattr(info, key) for key in ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode",
            "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")]

def read_file(path, private=True):
    check()
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "canonical_fixed_input")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= 8 * 1024 * 1024, "bounded_regular_input")
        if private:
            need(before.st_uid == 501 and stat.S_IMODE(before.st_mode) == 0o600, "private_summary_custody")
        else:
            need(before.st_uid in (0, 501) and not (stat.S_IMODE(before.st_mode) & 0o022), "fixed_public_input_custody")
        parts, count = [], 0
        while True:
            check()
            block = os.read(fd, 65536)
            if not block:
                break
            count += len(block)
            need(count <= 8 * 1024 * 1024, "bounded_input_read")
            parts.append(block)
        need(count == before.st_size and ident(before) == ident(os.fstat(fd)) == ident(path.lstat()),
             "input_changed_while_read")
        return b"".join(parts), ident(before), {
            "bytes": count, "owner_uid": before.st_uid, "mode": stat.S_IMODE(before.st_mode),
            "link_count": before.st_nlink, "stable_while_read": True,
        }
    finally:
        os.close(fd)

def read_json(path):
    raw, identity, metadata = read_file(path)
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=bad_constant)
    need(isinstance(value, dict), "summary_object_required")
    return value, raw, identity, metadata

def obj(value):
    return value if isinstance(value, dict) else {}

def rows(value):
    return value if isinstance(value, list) else []

def integer(value):
    return value if type(value) is int and -(1 << 64) <= value <= (1 << 64) else None

def number(value):
    return value if type(value) in (int, float) and math.isfinite(value) and abs(value) <= (1 << 64) else None

def boolean(value):
    return value if type(value) is bool else None

def present_equal(left, right):
    return left is not None and right is not None and left == right

def checks(value, expected):
    original = value.get("checks")
    actual = rows(original)
    safe = []
    for i, row in enumerate(actual):
        row = obj(row)
        name = row.get("case")
        safe.append([i, name if name in expected else None, boolean(row.get("passed"))])
    observed = [row[1] for row in safe]
    return {
        "columns": ["observed_index", "case", "passed"], "rows": safe,
        "required_count": len(expected), "observed_count": len(safe),
        "passed_count": sum(row[2] is True for row in safe),
        "failed_count": sum(row[2] is False for row in safe),
        "unknown_or_invalid_count": sum(row[1] is None or row[2] is None for row in safe),
        "exact_names": len(observed) == len(set(observed)) == len(expected) and set(observed) == set(expected),
        "all_passed": bool(safe) and all(row[2] is True for row in safe),
    }

def directory_numbers(value):
    value = obj(value)
    return {key: integer(value.get(key)) for key in ("device", "inode", "uid", "mode")}

def identity_row(value):
    value = obj(value)
    state = value.get("state")
    return [integer(value.get(key)) for key in IDENTITY_COLUMNS[:-1]] + [
        state if isinstance(state, str) and len(state) == 1 and state in "RSDTIUZX?" else None]

def identity_valid(value, birth=False):
    needed = (0, 1, 2, 3, 4)
    return (isinstance(value, list) and len(value) == len(IDENTITY_COLUMNS)
            and all(type(value[i]) is int for i in needed)
            and value[0] > 0 and value[1] >= 0 and value[2] > 0 and value[3] > 0
            and value[4] >= 0 and value[6] is not None
            and (not birth or (value[0] == value[2] == value[3] and value[4] == 501)))

def custody(value):
    value = obj(value)
    children = value.get("children")
    out = {
        "schema_exact": value.get("schema") == "heptabao.dr-original-process-custody.v1",
        "platform_darwin": value.get("platform") == "darwin",
        "original_count": integer(value.get("original_count")),
        "finished": boolean(value.get("finished")), "failed": boolean(value.get("failed")),
        "interrupted": boolean(value.get("interrupted")),
        "passed_process_custody": boolean(value.get("passed_process_custody")),
        "identity_columns": IDENTITY_COLUMNS, "child_columns": CHILD_COLUMNS, "children": [],
        "unreaped_original_is_signal_anchor": boolean(value.get("unreaped_original_is_signal_anchor")),
        "escaped_session_containment_claim": boolean(value.get("escaped_session_containment_claim")),
        "storage_or_production_authority": boolean(value.get("storage_or_production_authority")),
    }
    counts = {key: 0 for key in ("exec_admitted", "wait_completed", "wait_once", "no_live_before_reap",
              "zero_gaps", "valid_birth", "valid_exit_observation", "valid_prereap_observation",
              "exit_no_live_descendants", "prereap_no_live_descendants")}
    rc = {}
    for i, original in enumerate(rows(children)):
        check()
        child = obj(original)
        birth = identity_row(child.get("birth"))
        observations = []
        for key in ("members_at_leader_exit", "members_before_original_reap"):
            member_rows = child.get(key)
            observations.append([identity_row(x) for x in member_rows] if isinstance(member_rows, list) else None)
        gaps = child.get("gaps")
        row = [i, boolean(child.get("exec_admitted")), boolean(child.get("original_wait_completed")),
               integer(child.get("original_wait_count")), integer(child.get("returncode")),
               boolean(child.get("no_live_members_before_reap")), len(gaps) if isinstance(gaps, list) else None,
               birth, *observations]
        out["children"].append(row)
        counts["exec_admitted"] += row[1] is True
        counts["wait_completed"] += row[2] is True
        counts["wait_once"] += row[3] == 1
        counts["no_live_before_reap"] += row[5] is True
        counts["zero_gaps"] += row[6] == 0
        counts["valid_birth"] += identity_valid(birth, birth=True)
        for prefix, members in zip(("exit", "prereap"), observations):
            valid = (isinstance(members, list) and bool(members) and all(identity_valid(x) for x in members)
                     and any(x[0] == birth[0] and x[6] in ("Z", "X") for x in members))
            counts["valid_" + ("exit" if prefix == "exit" else "prereap") + "_observation"] += valid
            counts[prefix + "_no_live_descendants"] += (valid and all(
                x[0] == birth[0] or x[6] in ("Z", "X") for x in members))
        if type(row[4]) is int:
            rc[str(row[4])] = rc.get(str(row[4]), 0) + 1
    count = len(out["children"])
    out.update(children_count=count, independent_counts=counts, returncode_counts=rc)
    out["independent_all_owned_retired"] = (
        isinstance(children, list) and count > 0 and out["original_count"] == count
        and all(v == count for v in counts.values())
        and out["schema_exact"] and out["platform_darwin"] and out["finished"] is True
        and out["failed"] is False and out["interrupted"] is False
        and out["passed_process_custody"] is True)
    return out

def parent_handles(value):
    value = obj(value)
    stdio = []
    for row in rows(value.get("stdio")):
        row = obj(row)
        streams = obj(row.get("streams"))
        stdio.append([integer(row.get("owner_index")), integer(row.get("pid")),
            *[boolean(obj(streams.get(name)).get(key))
              for name in ("stdin", "stdout", "stderr") for key in ("present", "closed")]])
    scans = []
    for scan in rows(value.get("scans")):
        scan = obj(scan)
        scans.append([integer(scan.get("number")), boolean(scan.get("complete")),
                      len(rows(scan.get("observed"))), len(rows(scan.get("closed_during_scan"))),
                      len(rows(scan.get("matches_original_manifest"))), "observation_error" in scan])
    return {
        "passed": boolean(value.get("passed")), "scope_exact": value.get("scope") == "current_parent_and_manifest_covered_closure_only",
        "thread_count_before": integer(value.get("python_thread_count_before")),
        "thread_count_after": integer(value.get("python_thread_count_after")),
        "all_tracked_stdio_closed": boolean(value.get("all_tracked_stdio_closed")),
        "no_parent_fd_matches_manifest": boolean(value.get("no_parent_fd_matches_manifest")),
        "hostile_same_uid_isolation_claim": boolean(value.get("hostile_same_uid_isolation_claim")),
        "stdio_columns": ["owner_index", "pid", "stdin_present", "stdin_closed", "stdout_present", "stdout_closed", "stderr_present", "stderr_closed"],
        "stdio": stdio, "scan_columns": ["number", "complete", "observed_count", "closed_during_scan_count", "matching_count", "observation_error_present"],
        "scans": scans,
        "independent_fd_gate": len(scans) == 2 and [x[0] for x in scans] == [1, 2]
            and all(x[1] is True and x[4] == 0 and x[5] is False for x in scans)
            and bool(stdio) and all(x[i] is True for x in stdio for i in (3, 5, 7))
            and value.get("python_thread_count_before") == value.get("python_thread_count_after") == 1,
    }

def wire_rows(values):
    out = []
    for original in rows(values):
        row = obj(original)
        path = row.get("path")
        version = next((v for v in VERSIONS if path == "secret/data/history?version=" + str(v)), None)
        out.append([version, integer(row.get("status")), integer(row.get("body_bytes")),
                    boolean(row.get("same_response_decoded")), row.get("endpoint") == "source", row.get("method") == "GET"])
    return {"columns": ["version", "status", "body_bytes", "same_response_decoded", "source_endpoint", "get_method"],
            "rows": out, "count": len(out),
            "exact_19": len(out) == 19 and {x[0] for x in out} == set(VERSIONS),
            "all_valid": bool(out) and all(x[1] == 200 and type(x[2]) is int and x[2] > 0 and all(v is True for v in x[3:]) for x in out)}

def stage_rows(values, expected):
    out = []
    for value in rows(values):
        value = obj(value)
        stage = value.get("stage")
        entries = []
        for row in rows(value.get("versions")):
            row = obj(row)
            entries.append([integer(row.get("version")), boolean(row.get("payload_present")),
                            integer(row.get("payload_canonical_bytes")), boolean(row.get("destroyed"))])
        exact = len(entries) == 19 and {x[0] for x in entries} == set(VERSIONS)
        valid = exact and all(x[1] is (x[0] != 2) and x[3] is (x[0] == 2)
                    and type(x[2]) is int and (x[2] == 0 if x[0] == 2 else x[2] >= (2 * 1024**2 if x[0] >= 3 else 1))
                    for x in entries)
        out.append({"stage": stage if stage in expected else None, "source_raw_bound": boolean(value.get("source_raw_bound")),
                    "version_columns": ["version", "payload_present", "payload_canonical_bytes", "destroyed"],
                    "versions": entries, "count": len(entries), "exact_19": exact, "payload_contract": valid})
    return {"stages": out, "count": len(out), "exact_stages": len(out) == len(expected) and {x["stage"] for x in out} == set(expected),
            "all_bound_exact_19": bool(out) and all(x["source_raw_bound"] is True and x["exact_19"] and x["payload_contract"] for x in out)}

def api_history(value, oracle):
    value, oracle = obj(value), obj(oracle)
    expected = {r.get("version"): r for r in rows(oracle.get("versions")) if isinstance(r, dict)}
    out = []
    for row in rows(value.get("versions")):
        row = obj(row)
        version = integer(row.get("version"))
        before = obj(expected.get(version))
        out.append([version, integer(row.get("status")),
                    row.get("status") == before.get("status") and type(row.get("status")) is int,
                    present_equal(row.get("response_data_sha256"), before.get("response_data_sha256"))])
    return {"columns": ["version", "status", "status_matches_oracle", "response_matches_oracle"],
            "versions": out, "count": len(out), "exact_19": len(out) == 19 and {x[0] for x in out} == set(VERSIONS),
            "all_versions_match": bool(out) and all(x[2] is True and x[3] is True for x in out),
            "history_matches_oracle": present_equal(value.get("history_sha256"), oracle.get("history_sha256")),
            "config_matches_oracle": present_equal(value.get("config"), oracle.get("config")),
            "metadata_matches_oracle": present_equal(value.get("metadata"), oracle.get("metadata"))}

def raw_history(value, oracle):
    value, oracle = obj(value), obj(oracle)
    expected = {r.get("version"): r for r in rows(oracle.get("raw_versions")) if isinstance(r, dict)}
    metadata = obj(obj(oracle.get("metadata")).get("versions"))
    out = []
    for row in rows(value.get("versions")):
        row = obj(row)
        version = integer(row.get("version"))
        before, meta = obj(expected.get(version)), obj(metadata.get(str(version)))
        out.append([version, integer(row.get("http_status")), boolean(row.get("payload_present")),
                    integer(row.get("payload_canonical_bytes")), boolean(row.get("destroyed")),
                    isinstance(row.get("deletion_time"), str) and bool(row["deletion_time"]),
                    integer(row.get("source_publication_generation")), integer(row.get("mount_incarnation")),
                    bool(before) and all(row.get(k) == before.get(k) for k in ("payload_present", "payload_canonical_bytes", "payload_canonical_sha256")),
                    bool(meta) and all(row.get(k) == meta.get(k) for k in ("created_time", "deletion_time", "destroyed"))])
    return {"columns": ["version", "http_status", "payload_present", "payload_canonical_bytes", "destroyed", "soft_deleted",
                        "source_publication_generation", "mount_incarnation", "payload_matches_original_raw", "metadata_matches_original"],
            "versions": out, "count": len(out), "exact_19": len(out) == 19 and {x[0] for x in out} == set(VERSIONS),
            "all_original_raw_bindings_match": bool(out) and all(x[1] == 200 and x[8] is True and x[9] is True for x in out),
            "source_bundle_binding_matches": present_equal(value.get("source_bundle_sha256"), oracle.get("source_bundle_sha256"))}

def restart(value):
    value = obj(value)
    return {key: integer(value.get(key)) for key in ("old_pid", "old_returncode", "new_pid", "unseal_status")}

def archive_projection(value):
    value = obj(value)
    meta = obj(value.get("metadata"))
    seal = obj(meta.get("seal_identity"))
    members = [[row.get("name") if row.get("name") in ARCHIVE_NAMES else None, integer(row.get("bytes"))]
               for row in map(obj, rows(value.get("members")))]
    state = next((r[1] for r in members if r[0] == "state.bin"), None)
    return {
        "physical_state_bytes": integer(meta.get("state_bytes")), "generation": integer(meta.get("generation")),
        "format_expected": meta.get("format") == "heptabao-native-object-snapshot-v1",
        "state_format_expected": meta.get("state_format") == "heptabao-encrypted-object-backup/HBV6PK01",
        "seal_binding_shape_valid": set(seal) == {"format", "sha256"}
            and seal.get("format") == "heptabao-seal-metadata-digest-v1"
            and isinstance(seal.get("sha256"), str) and re.fullmatch(r"[a-f0-9]{64}", seal["sha256"]) is not None,
        "member_columns": ["fixed_name", "bytes"], "members": members,
        "exact_members": len(members) == 4 and {r[0] for r in members} == set(ARCHIVE_NAMES),
        "state_bytes_match_member": type(state) is int and state > 0 and state == meta.get("state_bytes"),
        "outer_checksums_verified": boolean(value.get("outer_checksums_verified")),
        "standalone_aead_verified": boolean(value.get("standalone_aead_verified")),
    }

def command(value):
    value = obj(value)
    return {"label": value.get("label") if value.get("label") in COMMAND_NAMES else None,
            "budget_seconds": number(value.get("budget_seconds")), "retried": boolean(value.get("retried")),
            "returncode": integer(value.get("returncode")), "original_wait_completed": boolean(value.get("original_wait_completed")),
            "elapsed_seconds": number(value.get("elapsed_seconds")),
            "response_received": value.get("outcome") == "response_received",
            "http_status_codes": [integer(x) for x in rows(value.get("http_status_codes"))]}

def main():
    need(sys.platform == "darwin" and os.geteuid() == 501 and sys.version_info[:3] == (3, 14, 3), "fixed_darwin_python_required")
    python_raw, _, _ = read_file(Path(sys.executable).resolve(strict=True), private=False)
    need(hashlib.sha256(python_raw).hexdigest() == PYTHON_SHA, "fixed_python_pin")
    for name, pin in SOURCE_PINS.items():
        raw, _, _ = read_file(SOURCE / "qa/openbao-acceptance" / name, private=False)
        need(len(raw) == pin["bytes"] and hashlib.sha256(raw).hexdigest() == pin["sha256"], "fixed_qa_source_pin")
    wrapper_raw, _, wrapper_meta = read_file(WRAPPER_PATH)
    need(len(wrapper_raw) == 1437 and hashlib.sha256(wrapper_raw).hexdigest() == WRAPPER_SHA, "actual_wrapper_receipt_pin")
    wrapper = json.loads(wrapper_raw, object_pairs_hook=unique, parse_constant=bad_constant)
    wd = obj(wrapper.get("deadline"))
    REPORT["actual_wrapper_contract"] = {
        "schema_exact": wrapper.get("schema") == "heptabao.mac-full34-dr25-fixed-execution.v1",
        "status_passed": wrapper.get("status") == "passed",
        "controller_exit_code": integer(wrapper.get("controller_exit_code")),
        **{key: boolean(wrapper.get(key)) for key in ("baseline_31_passed", "dr25_passed", "all_originals_retired",
             "fresh_directory_same_seal_v6_recovery_verified", "automatic_retry", "signal_and_timer_restored",
             "formal_kv2_migration_qualified", "physical_ha_qualified", "authbus_qualified", "full_replacement_qualified", "production_authority")},
        "observed_dr25_check_count": integer(wrapper.get("observed_dr25_check_count")),
        "observed_dr25_pass_count": integer(wrapper.get("observed_dr25_pass_count")),
        "missing_required_count": len(rows(wrapper.get("missing_required_dr25"))),
        "summary_path_exact": wrapper.get("summary") == str(DR_PATH),
        "http_seconds": integer(wrapper.get("http_seconds")), "migration_seconds": integer(wrapper.get("migration_seconds")),
        "runtime_outer_seconds": integer(wrapper.get("runtime_outer_seconds")),
        "work_seconds": integer(wd.get("work_seconds_from_entry")), "cleanup_reserve_seconds": integer(wd.get("cleanup_reserve_within_outer_seconds")),
        "deadline_fired": boolean(wd.get("fired")), "deadline_renewed": boolean(wd.get("deadline_renewed")),
        "elapsed_seconds": number(wrapper.get("elapsed_seconds")),
    }
    REPORT["input_bindings"] = {"qa_files_exact": True, "fixed_python_exact": True, "actual_wrapper_receipt_exact": True,
                               "wrapper_file_metadata": wrapper_meta}
    dr, dr_raw, dr_identity, dr_meta = read_json(DR_PATH)
    baseline, baseline_raw, baseline_identity, baseline_meta = read_json(BASELINE_PATH)
    REPORT["summary_metadata"] = {"dr": dr_meta, "quarantined_baseline": baseline_meta}
    REPORT["baseline_location"] = {
        "quarantined_summary_reference_exact": obj(dr.get("baseline")).get("summary") == str(BASELINE_PATH),
        "original_summary_reference_exact": obj(dr.get("baseline")).get("original_summary") == str(WORK / "baseline/summary.json"),
        "original_baseline_directory_absent": not os.path.lexists(WORK / "baseline"),
        "required_count": integer(obj(dr.get("baseline")).get("required_count")),
        "qualified": boolean(obj(dr.get("baseline")).get("qualified")),
    }
    dc, bc = checks(dr, DR_CASES), checks(baseline, BASELINE_CASES)
    REPORT["dr25"], REPORT["baseline31"] = dc, bc
    dc.update(status_passed=dr.get("status") == "passed", schema_exact=dr.get("schema") == "heptabao.native-v6-fresh-directory-dr25.v1",
              required_names_exact=dr.get("required_checks") == DR_CASES, missing_check_count=len(rows(dr.get("missing_checks"))),
              cleanup_failure_count=len(rows(dr.get("cleanup_failures"))), failure_present=bool(dr.get("failure")),
              fresh_directory_same_seal_v6_recovery_verified=boolean(dr.get("fresh_directory_same_seal_v6_recovery_verified")))
    bc.update(status_passed=baseline.get("status") == "passed",
              schema_exact=baseline.get("schema") == "heptabao.openbao271-kv2-lossless-native-live.v1",
              profile_full34=baseline.get("profile") == "full34", migration_lane_native_large=baseline.get("migration_lane") == "native-large",
              full34_qualified=boolean(baseline.get("full34_qualified")), tls_verified=boolean(baseline.get("tls_verified")),
              failure_present=bool(baseline.get("failure")))
    by_case = {row.get("case"): row for row in rows(dr.get("checks")) if isinstance(row, dict) and row.get("case") in DR_CASES}
    def evidence(name):
        return obj(obj(by_case.get(name)).get("evidence"))
    source = evidence("input_source_and_binaries_pinned")
    final = evidence("final_custody_cleanup_and_redaction")
    oracle = obj(evidence("official_full34_api_and_raw_history_bound").get("oracle"))
    REPORT["qualification_boundaries"] = {key: boolean(dr.get(key)) for key in
        ("synthetic_only", "physical_disk_independence_verified", "physical_power_loss_tested", "ha_qualified",
         "cross_seal_restore", "production_authority", "replacement_authority", "independent_qualification")}
    REPORT["original_budgets"] = {key: number(obj(dr.get("original_budgets")).get(key))
        for key in ("http_seconds", "migration_seconds", "cli_and_seed_seconds")}
    before = obj(source.get("controller_and_server"))
    binding = obj(source.get("build_binding"))
    REPORT["source_and_product"] = {
        "source_before_after_exact": present_equal(source.get("controller_and_server"), final.get("source_identity_after")),
        "qa_commit_exact": before.get("source_commit") == QA_COMMIT, "qa_tree_exact": before.get("source_tree") == QA_TREE,
        "source_clean": before.get("source_dirty") is False,
        "product_commit_exact": source.get("build_source_commit") == binding.get("source_commit") == PRODUCT_COMMIT,
        "product_tree_exact": binding.get("source_tree") == PRODUCT_TREE,
        "build_status_passed": binding.get("status") == "passed", "passed_build_cases": integer(binding.get("passed_cases")),
        "source_and_artifacts_unchanged": boolean(binding.get("source_and_artifacts_unchanged")),
        "official_version_exact": dr.get("official_version") == baseline.get("official_version") == "2.7.1",
    }
    official = evidence("official_271_live_identity_verified")
    REPORT["source_and_product"].update(
        official_cli_matches_release=present_equal(obj(source.get("official_cli")).get("sha256"), obj(source.get("official_release")).get("binary_sha256")),
        official_live_identity_matches_baseline=present_equal(official.get("live_identity"), baseline.get("official_identity")))
    normal = evidence("normal_native_v6_file_profile")
    normal_startup, normal_capacity = obj(normal.get("startup")), obj(normal.get("capacity"))
    REPORT["normal_native_profile"] = {
        "fixture_options": boolean(normal_startup.get("fixture_options")),
        "storage_profile_native_v6_file": normal_startup.get("storage_profile") == "native_v6_file",
        "state_v6": normal_capacity.get("state_storage_format") == "heptabao-state-records-v6",
        "native_reader_format": integer(normal_capacity.get("native_kv2_reader_format")),
        "logical_payload_bytes": integer(normal_capacity.get("native_kv2_logical_payload_bytes")),
    }
    REPORT["baseline_source_api"] = wire_rows(baseline.get("source_api_wire_observations"))
    REPORT["baseline_raw_stages"] = stage_rows(baseline.get("target_storage_witnesses"), STORAGE_CASES)
    archive_gate = evidence("complete_v6_archive_seal_binding")
    history = obj(archive_gate.get("full34_logical_history"))
    hc = checks({"checks": history.get("capture_checks")}, CAPTURE_CASES)
    hw = wire_rows(history.get("source_api_observations"))
    hs = stage_rows(history.get("storage_witnesses"), STORAGE_CASES[:2])
    cap = obj(history.get("capacity_after_import"))
    REPORT["snapshot_logical_history"] = {
        "schema_expected": history.get("schema") == "heptabao.dr25-full34-snapshot-history.v1",
        "profile_full34": history.get("profile") == "full34", "migration_lane_native_large": history.get("migration_lane") == "native-large",
        "retained_live_versions": integer(history.get("retained_live_versions")),
        "live_payload_bytes": integer(history.get("live_payload_bytes")),
        "required_logical_payload_bytes": integer(history.get("required_logical_payload_bytes")),
        "native_before_import": boolean(history.get("native_before_import")),
        "logical_payload_bytes": integer(cap.get("native_kv2_logical_payload_bytes")),
        "logical_at_least_34mib": type(cap.get("native_kv2_logical_payload_bytes")) is int and cap["native_kv2_logical_payload_bytes"] >= 34 * 1024**2,
        "state_v6": cap.get("state_storage_format") == "heptabao-state-records-v6",
        "native_reader_format": integer(cap.get("native_kv2_reader_format")),
        "capture18": hc, "source_api19": hw, "raw_stages": hs,
        "physical_pack_size_not_logical_history_size": boolean(archive_gate.get("physical_pack_bytes_are_observations_not_logical_history_size")),
        "aead_required_at_restore": boolean(archive_gate.get("aead_authentication_required_at_restore")),
    }
    ca, ha = obj(archive_gate.get("cli_archive")), obj(archive_gate.get("normal_http_archive"))
    REPORT["archive_contract"] = {"cli": archive_projection(ca), "http": archive_projection(ha),
        "seal_identity_equal": present_equal(obj(ca.get("metadata")).get("seal_identity"), obj(ha.get("metadata")).get("seal_identity"))}
    backup = evidence("backup_manifest_and_separate_key_custody")
    independent = evidence("independent_backup_filesystem_verified")
    file_rows = [[r.get("path") if r.get("path") in BACKUP_NAMES else None, integer(r.get("bytes")),
                  integer(r.get("mode")), integer(r.get("uid")), integer(r.get("links"))]
                 for r in map(obj, rows(backup.get("files")))]
    key_rows = [[r.get("name") if r.get("name") in ("unseal.key", "root.token") else None, integer(r.get("mode"))]
                for r in map(obj, rows(backup.get("key_files")))]
    directories = {key: directory_numbers(obj(final.get("private_directory_custody")).get(key))
                   for key in ("work", "backup_parent", "key_parent", "backup", "keys")}
    REPORT["backup_key_custody"] = {
        "scope_distinct_filesystems_only": independent.get("scope") == "distinct_st_dev_filesystems_only",
        "work_backup_distinct_device_numbers": obj(independent.get("work")).get("device") != obj(independent.get("backup_parent")).get("device"),
        "physical_device_claim": boolean(independent.get("physical_device_claim")),
        "backup_file_columns": ["fixed_name", "bytes", "mode", "uid", "links"], "backup_files": file_rows,
        "exact_backup_file_names": len(file_rows) == len(BACKUP_NAMES) and {x[0] for x in file_rows} == set(BACKUP_NAMES),
        "backup_files_private": bool(file_rows) and all(x[2:] == [0o600, 501, 1] for x in file_rows),
        "key_file_columns": ["fixed_name", "mode"], "key_files": key_rows,
        "exact_private_key_files": len(key_rows) == 2 and {x[0] for x in key_rows} == {"unseal.key", "root.token"} and all(x[1] == 0o600 for x in key_rows),
        "key_material_absent_from_backup": boolean(backup.get("key_material_absent_from_backup")),
        "plaintext_business_values_in_witness": boolean(backup.get("plaintext_business_values_in_witness")),
        "manifest_before_after_exact": present_equal(backup.get("manifest"), final.get("backup_manifest")),
        "backup_directory_before_after_exact": present_equal(backup.get("backup_directory"), obj(final.get("private_directory_custody")).get("backup")),
        "key_directory_before_after_exact": present_equal(backup.get("key_directory"), obj(final.get("private_directory_custody")).get("keys")),
        "key_files_unchanged_and_private": boolean(final.get("key_files_unchanged_and_private")),
        "final_directories": directories,
    }
    stopped = evidence("original_processes_stopped")
    quarantined = evidence("original_directories_quarantined")
    REPORT["original_closure"] = {
        "original_process_columns": ["pid", "returncode"], "original_processes": [[integer(obj(x).get("pid")), integer(obj(x).get("returncode"))] for x in rows(stopped.get("original_processes"))],
        "parent_service_log_handles_closed": {k: boolean(obj(stopped.get("parent_service_log_handles_closed")).get(k)) for k in ("candidate", "oracle")},
        "quarantine_original_path_exact": quarantined.get("original_path") == str(WORK / "baseline"),
        "quarantined_path_exact": quarantined.get("quarantined_path") == str(WORK / "quarantine/original-closure"),
        "before_after_tree_summary_equal": present_equal(quarantined.get("before"), quarantined.get("after")),
        "after_recovery_tree_summary_equal": present_equal(quarantined.get("after"), final.get("quarantine_after")),
        "quarantine_file_count": integer(obj(quarantined.get("after")).get("file_count")),
        "quarantine_directory_count": integer(obj(quarantined.get("after")).get("directory_count")),
        "private_manifest_retained": boolean(obj(quarantined.get("after")).get("complete_manifest_retained_privately")),
        "credential_dependent_fingerprints_published": boolean(obj(quarantined.get("after")).get("credential_dependent_fingerprints_published")),
        "original_api_payload_objects_before_release": integer(quarantined.get("original_api_payload_objects_before_release")),
        "original_api_payload_objects_after_release": integer(quarantined.get("original_api_payload_objects_after_release")),
        "original_endpoint_objects_released": boolean(quarantined.get("original_endpoint_objects_released")),
        "same_uid_adversary_isolation_claim": boolean(quarantined.get("same_uid_adversary_isolation_claim")),
        "parent_handle_retirement": parent_handles(quarantined.get("parent_handle_retirement")),
    }
    seed_export = evidence("preactivation_seed_export_pinned")
    seed_stage = evidence("exact_seed_stage_verified")
    seed_receipt = obj(seed_stage.get("receipt"))
    exported = rows(seed_export.get("artifacts")); staged = rows(seed_stage.get("artifacts"))
    safe_seed = []
    for x in staged:
        x = obj(x)
        name = x.get("leaf")
        original = next((obj(y) for y in exported if obj(y).get("leaf") == name), {})
        safe_seed.append([name if name in SEED_NAMES else None, integer(x.get("bytes")), integer(x.get("mode")),
                          bool(original) and x.get("bytes") == original.get("bytes") and present_equal(x.get("sha256"), original.get("sha256"))])
    fresh = evidence("fresh_recovery_directory_and_tls_identity")
    REPORT["fresh_directory_and_seed"] = {
        "data_absent_before_stage": boolean(fresh.get("data_directory_absent_before_stage")),
        "new_tls_identity_distinct": fresh.get("new_tls_certificate_sha256") is not None and fresh.get("original_tls_certificate_sha256") is not None
            and fresh["new_tls_certificate_sha256"] != fresh["original_tls_certificate_sha256"],
        "fixture_options": boolean(fresh.get("fixture_options")),
        "seed_retained_native_objects": integer(seed_export.get("retained_native_objects")),
        "seed_export_writer_returncode": integer(seed_export.get("returncode")),
        "seed_columns": ["fixed_leaf", "bytes", "mode", "matches_exported_bytes_and_digest"], "seed_artifacts": safe_seed,
        "exact_four_seed_files": len(safe_seed) == 4 and {x[0] for x in safe_seed} == set(SEED_NAMES),
        "all_seed_files_match": bool(safe_seed) and all(x[3] is True for x in safe_seed),
        "operation_stage": seed_receipt.get("operation") == "stage",
        **{key: boolean(seed_receipt.get(key)) for key in ("original_writer_fence_held", "every_file_synced_and_read_back", "directory_publication_synced",
               "cryptographic_state_admission_performed", "ha_qualified")},
    }
    negative = evidence("old_closure_negative_cannot_read_history")
    missing = [[integer(obj(x).get("version")), integer(obj(x).get("api_status")), integer(obj(x).get("raw_status")),
                boolean(obj(x).get("api_payload_present")), boolean(obj(x).get("raw_witness_present"))]
               for x in rows(negative.get("historical_reads"))]
    REPORT["old_closure_negative"] = {
        "columns": ["version", "api_status", "raw_status", "api_payload_present", "raw_witness_present"], "rows": missing,
        "exact_19": len(missing) == 19 and {x[0] for x in missing} == set(VERSIONS),
        "all_denied_without_payload": bool(missing) and all(x[1:] == [404, 501, False, False] for x in missing),
        "original_root_exists": boolean(negative.get("original_root_exists")),
        "external_object_count_before_restore": len(rows(negative.get("external_objects_before_restore"))),
    }
    wrong = evidence("wrong_unseal_key_denied")
    REPORT["wrong_key"] = {key: integer(wrong.get(key)) for key in ("wrong_unseal_status", "health_status")}
    REPORT["wrong_key"].update(sealed=boolean(wrong.get("sealed")), seal_unchanged=present_equal(wrong.get("seal_before"), wrong.get("seal_after")))
    tampered = evidence("tampered_archive_denied_without_commit")
    oldcap, newcap, coldcap = [obj(tampered.get(k)) for k in ("capacity_before", "capacity_after", "cold_capacity_after")]
    REPORT["tampered_archive"] = {
        "command": command(tampered.get("command")),
        "generation_columns": ["before", "after_denial", "after_cold_reopen"],
        "generations": [integer(x.get("generation")) for x in (oldcap, newcap, coldcap)],
        "generation_unchanged": oldcap.get("generation") is not None and oldcap.get("generation") == newcap.get("generation") == coldcap.get("generation"),
        "storage_format_unchanged": oldcap.get("state_storage_format") is not None and oldcap.get("state_storage_format") == newcap.get("state_storage_format") == coldcap.get("state_storage_format"),
        "history_status_after": integer(tampered.get("history_status_after")), "cold_history_status_after": integer(tampered.get("cold_history_status_after")),
        "same_seal_bytes_and_identity": boolean(tampered.get("same_seal_bytes_and_identity")),
        "restart_after_rejection": restart(tampered.get("restart_after_rejection")),
    }
    restored = evidence("official_cli_v6_restore_once")
    activecap = obj(restored.get("capacity_after"))
    REPORT["restore_once"] = {
        "command": command(restored.get("command")), "valid_restore_attempt_count": integer(restored.get("valid_restore_attempt_count")),
        "source_bundle_imports_after_quarantine": integer(restored.get("source_bundle_imports_after_quarantine")),
        "state_v6": activecap.get("state_storage_format") == "heptabao-state-records-v6",
        "native_reader_format": integer(activecap.get("native_kv2_reader_format")),
        "logical_payload_bytes": integer(activecap.get("native_kv2_logical_payload_bytes")),
        "archive_matches_saved_backup": present_equal(restored.get("archive"), ca.get("archive")),
    }
    REPORT["restored_api19"] = api_history(evidence("restored_api_19_versions_exact"), oracle)
    REPORT["restored_raw19"] = raw_history(evidence("restored_raw_19_versions_exact"), oracle)
    cold = evidence("restored_cold_reopen_history_exact")
    REPORT["restored_cold"] = {"restart": restart(cold.get("restart")), "api19": api_history(cold.get("api"), oracle),
                               "raw19": raw_history(cold.get("raw"), oracle)}
    soft = evidence("soft_deleted_payload_undelete_exact")
    destroyed = evidence("destroyed_payload_not_resurrected")
    destroyed_raw = obj(obj(destroyed.get("raw")).get("data"))
    REPORT["delete_destroy"] = {
        "undelete_status": integer(soft.get("undelete_status")), "undeleted_read_status": integer(soft.get("read_status")),
        "undeleted_payload_matches_original": present_equal(soft.get("payload_sha256"), soft.get("source_api_payload_sha256")),
        "undeleted_deletion_time_empty": obj(soft.get("metadata")).get("deletion_time") == "",
        "destroyed_undelete_status": integer(destroyed.get("undelete_status")), "destroyed_read_status": integer(destroyed.get("read_status")),
        "destroyed_flag": boolean(obj(destroyed.get("metadata")).get("destroyed")), "destroyed_raw_status": integer(destroyed.get("raw_status")),
        "destroyed_payload_present": boolean(destroyed_raw.get("payload_present")),
        "destroyed_payload_bytes": integer(destroyed_raw.get("payload_canonical_bytes")),
        "destroyed_payload_digest_absent": destroyed_raw.get("payload_canonical_sha256") is None,
    }
    cas = evidence("data_and_metadata_cas_guards_exact")
    data_cas, meta_cas = obj(cas.get("data_cas")), obj(cas.get("metadata_cas"))
    beforemeta, validmeta = obj(obj(meta_cas.get("before")).get("metadata")), obj(obj(meta_cas.get("after_valid")).get("metadata"))
    oldcounter, newcounter = beforemeta.get("current_metadata_version"), validmeta.get("current_metadata_version")
    REPORT["cas"] = {
        "data_denied_status": integer(data_cas.get("status")), "data_denial_no_change": present_equal(data_cas.get("before"), data_cas.get("after")),
        "metadata_denied_status": integer(meta_cas.get("denied_status")),
        "metadata_denial_no_change": present_equal(meta_cas.get("before"), meta_cas.get("after_denial")),
        "metadata_valid_status": integer(meta_cas.get("valid_status")), "counter_before": integer(oldcounter), "counter_after": integer(newcounter),
        "counter_increment_exactly_one": type(oldcounter) is int and type(newcounter) is int and newcounter == oldcounter + 1,
        "valid_custom_metadata_expected": validmeta.get("custom_metadata") == {"revision": "dr25"},
    }
    new = evidence("new_write_survives_cold_reopen")
    newraw = obj(new.get("raw"))
    expected_payload = json.dumps({"after_fresh_directory_restore": True}, sort_keys=True, separators=(",", ":")).encode()
    REPORT["new_version20"] = {
        "write_status": integer(new.get("write_status")), "version": integer(new.get("version")), "read_status": integer(new.get("read_status")),
        "raw_status": integer(new.get("raw_status")), "restart": restart(new.get("restart")),
        "before_after_cold_history_exact": present_equal(new.get("before_restart"), new.get("after_restart")),
        "before_version_count": len(rows(obj(new.get("before_restart")).get("versions"))),
        "after_version_count": len(rows(obj(new.get("after_restart")).get("versions"))),
        "raw_version": integer(newraw.get("version")), "payload_present": boolean(newraw.get("payload_present")),
        "payload_bytes": integer(newraw.get("payload_canonical_bytes")),
        "raw_payload_matches_fixed_new_value": newraw.get("payload_canonical_sha256") == hashlib.sha256(expected_payload).hexdigest(),
    }
    REPORT["commands"] = [command(x) for x in rows(dr.get("commands"))]
    REPORT["command_set_exact"] = len(REPORT["commands"]) == len(COMMAND_NAMES) and {x["label"] for x in REPORT["commands"]} == set(COMMAND_NAMES)
    REPORT["all_commands_no_retry_and_waited"] = all(x["retried"] is False and x["original_wait_completed"] is True
            and x["budget_seconds"] == 15 and x["response_received"] is True for x in REPORT["commands"])
    REPORT["owned_process_custody"] = custody(dr.get("process_custody"))
    REPORT["final_custody_reference_matches"] = present_equal(dr.get("process_custody"), final.get("all_owned_sessions"))
    REPORT["runtime_credentials_and_fingerprints_absent"] = boolean(final.get("runtime_credentials_and_fingerprints_absent"))
    for path, original, identity in ((DR_PATH, dr_raw, dr_identity), (BASELINE_PATH, baseline_raw, baseline_identity)):
        again, final_identity, _ = read_file(path)
        need(again == original and final_identity == identity, "private_summary_changed_after_projection")
    REPORT["private_summaries_unchanged"] = True
    for name, pin in SOURCE_PINS.items():
        source_raw, _, _ = read_file(SOURCE / "qa/openbao-acceptance" / name, private=False)
        need(len(source_raw) == pin["bytes"] and hashlib.sha256(source_raw).hexdigest() == pin["sha256"], "qa_source_changed_after_projection")
    REPORT["fixed_qa_source_pins_unchanged"] = True
    check()
    REPORT["projection_complete"] = True
    REPORT["independent_case_and_retirement_gate"] = (
        all(v["exact_names"] and v["all_passed"] and v["status_passed"] and v["schema_exact"] for v in (dc, bc))
        and dc["required_names_exact"] and not dc["failure_present"] and not bc["failure_present"]
        and dc["missing_check_count"] == dc["cleanup_failure_count"] == 0
        and bc["full34_qualified"] is True and REPORT["baseline_location"]["qualified"] is True
        and REPORT["owned_process_custody"]["independent_all_owned_retired"]
        and REPORT["original_closure"]["parent_handle_retirement"]["independent_fd_gate"])
    w = REPORT["actual_wrapper_contract"]
    sp = REPORT["source_and_product"]
    n = REPORT["normal_native_profile"]
    bk = REPORT["backup_key_custody"]
    oc = REPORT["original_closure"]
    fs = REPORT["fresh_directory_and_seed"]
    ar = REPORT["archive_contract"]
    ta = REPORT["tampered_archive"]
    rr = REPORT["restore_once"]
    dd = REPORT["delete_destroy"]
    cc = REPORT["cas"]
    nv = REPORT["new_version20"]
    def api_ok(value):
        return value["exact_19"] and value["all_versions_match"] and value["history_matches_oracle"] and value["config_matches_oracle"] and value["metadata_matches_oracle"]
    def raw_ok(value):
        return value["exact_19"] and value["all_original_raw_bindings_match"] and value["source_bundle_binding_matches"]
    def restart_ok(value):
        return type(value["old_pid"]) is int and type(value["new_pid"]) is int and value["old_pid"] != value["new_pid"] and type(value["old_returncode"]) is int and value["unseal_status"] == 200
    gates = {
        "exact_31_25_cases_and_all_owned_retired": REPORT["independent_case_and_retirement_gate"],
        "actual_wrapper_contract": w["schema_exact"] and w["status_passed"] and w["controller_exit_code"] == 0
            and all(w[k] is True for k in ("baseline_31_passed", "dr25_passed", "all_originals_retired",
                    "fresh_directory_same_seal_v6_recovery_verified", "signal_and_timer_restored"))
            and all(w[k] is False for k in ("automatic_retry", "deadline_fired", "deadline_renewed",
                    "formal_kv2_migration_qualified", "physical_ha_qualified", "authbus_qualified", "full_replacement_qualified", "production_authority"))
            and w["observed_dr25_check_count"] == w["observed_dr25_pass_count"] == 25 and w["missing_required_count"] == 0
            and w["summary_path_exact"] and (w["http_seconds"], w["migration_seconds"], w["runtime_outer_seconds"],
                w["work_seconds"], w["cleanup_reserve_seconds"]) == (15, 360, 1800, 1740, 60),
        "private_summary_locations": all(REPORT["baseline_location"][k] is True for k in
            ("quarantined_summary_reference_exact", "original_summary_reference_exact", "original_baseline_directory_absent", "qualified"))
            and REPORT["baseline_location"]["required_count"] == 31,
        "source_product_official_identity": all(sp[k] is True for k in ("source_before_after_exact", "qa_commit_exact", "qa_tree_exact",
            "source_clean", "product_commit_exact", "product_tree_exact", "build_status_passed", "source_and_artifacts_unchanged",
            "official_version_exact", "official_cli_matches_release", "official_live_identity_matches_baseline")) and sp["passed_build_cases"] == 107,
        "normal_native_profile": n["fixture_options"] is False and n["storage_profile_native_v6_file"] and n["state_v6"]
            and n["native_reader_format"] == 2 and type(n["logical_payload_bytes"]) is int and n["logical_payload_bytes"] >= 34 * 1024**2,
        "baseline_source_api19": REPORT["baseline_source_api"]["exact_19"] and REPORT["baseline_source_api"]["all_valid"],
        "baseline_three_raw19_stages": REPORT["baseline_raw_stages"]["exact_stages"] and REPORT["baseline_raw_stages"]["all_bound_exact_19"],
        "snapshot_capture18_api19_two_raw19": hc["exact_names"] and hc["all_passed"] and hw["exact_19"] and hw["all_valid"]
            and hs["exact_stages"] and hs["all_bound_exact_19"] and REPORT["snapshot_logical_history"]["logical_at_least_34mib"]
            and REPORT["snapshot_logical_history"]["retained_live_versions"] == 17
            and REPORT["snapshot_logical_history"]["live_payload_bytes"] == REPORT["snapshot_logical_history"]["required_logical_payload_bytes"] == 34 * 1024**2
            and REPORT["snapshot_logical_history"]["native_before_import"] is True and REPORT["snapshot_logical_history"]["state_v6"]
            and REPORT["snapshot_logical_history"]["native_reader_format"] == 2,
        "archive_contract_and_same_seal": ar["seal_identity_equal"] and all(all(ar[name][key] is True for key in
            ("format_expected", "state_format_expected", "seal_binding_shape_valid", "exact_members", "state_bytes_match_member", "outer_checksums_verified"))
            and ar[name]["standalone_aead_verified"] is False for name in ("cli", "http")),
        "backup_and_key_custody": all(bk[k] is True for k in ("scope_distinct_filesystems_only", "work_backup_distinct_device_numbers",
            "exact_backup_file_names", "backup_files_private", "exact_private_key_files", "key_material_absent_from_backup",
            "manifest_before_after_exact", "backup_directory_before_after_exact", "key_directory_before_after_exact", "key_files_unchanged_and_private"))
            and bk["physical_device_claim"] is False and bk["plaintext_business_values_in_witness"] is False
            and all(x["uid"] == 501 and x["mode"] == 0o700 and type(x["device"]) is int and type(x["inode"]) is int
                    for x in bk["final_directories"].values()),
        "original_quarantine_and_parent_handles": all(oc[k] is True for k in ("quarantine_original_path_exact", "quarantined_path_exact",
            "before_after_tree_summary_equal", "after_recovery_tree_summary_equal", "private_manifest_retained", "original_endpoint_objects_released"))
            and len(oc["original_processes"]) == 2 and all(type(x[0]) is int and type(x[1]) is int for x in oc["original_processes"])
            and all(x is True for x in oc["parent_service_log_handles_closed"].values())
            and oc["original_api_payload_objects_after_release"] == 0 and oc["credential_dependent_fingerprints_published"] is False
            and oc["same_uid_adversary_isolation_claim"] is False and oc["parent_handle_retirement"]["independent_fd_gate"],
        "fresh_directory_tls_and_seed": all(fs[k] is True for k in ("data_absent_before_stage", "new_tls_identity_distinct", "exact_four_seed_files",
            "all_seed_files_match", "operation_stage", "original_writer_fence_held", "every_file_synced_and_read_back", "directory_publication_synced"))
            and fs["fixture_options"] is False and fs["seed_retained_native_objects"] == 0
            and fs["cryptographic_state_admission_performed"] is False and fs["ha_qualified"] is False,
        "old_closure_negative": REPORT["old_closure_negative"]["exact_19"] and REPORT["old_closure_negative"]["all_denied_without_payload"]
            and REPORT["old_closure_negative"]["original_root_exists"] is False and REPORT["old_closure_negative"]["external_object_count_before_restore"] == 0,
        "wrong_key": REPORT["wrong_key"]["wrong_unseal_status"] == 400 and REPORT["wrong_key"]["health_status"] == 503
            and REPORT["wrong_key"]["sealed"] is True and REPORT["wrong_key"]["seal_unchanged"],
        "tampered_archive_no_commit": ta["generation_unchanged"] and ta["storage_format_unchanged"]
            and ta["history_status_after"] == ta["cold_history_status_after"] == 404
            and ta["same_seal_bytes_and_identity"] is True and restart_ok(ta["restart_after_rejection"])
            and type(ta["command"]["returncode"]) is int and ta["command"]["returncode"] != 0 and ta["command"]["http_status_codes"] == [400],
        "restore_once": rr["valid_restore_attempt_count"] == 1 and rr["source_bundle_imports_after_quarantine"] == 0
            and rr["state_v6"] and rr["native_reader_format"] == 2 and type(rr["logical_payload_bytes"]) is int
            and rr["logical_payload_bytes"] >= 34 * 1024**2 and rr["archive_matches_saved_backup"] and rr["command"]["returncode"] == 0,
        "restored_api19": api_ok(REPORT["restored_api19"]), "restored_raw19": raw_ok(REPORT["restored_raw19"]),
        "cold_reopen_api19_raw19": api_ok(REPORT["restored_cold"]["api19"]) and raw_ok(REPORT["restored_cold"]["raw19"])
            and restart_ok(REPORT["restored_cold"]["restart"]),
        "delete_and_destroy": dd["undelete_status"] == 204 and dd["undeleted_read_status"] == 200 and dd["undeleted_payload_matches_original"]
            and dd["undeleted_deletion_time_empty"] and dd["destroyed_undelete_status"] == 204 and dd["destroyed_read_status"] == 404
            and dd["destroyed_flag"] is True and dd["destroyed_raw_status"] == 200 and dd["destroyed_payload_present"] is False
            and dd["destroyed_payload_bytes"] == 0 and dd["destroyed_payload_digest_absent"],
        "cas": cc["data_denied_status"] == cc["metadata_denied_status"] == 400 and cc["data_denial_no_change"] and cc["metadata_denial_no_change"]
            and cc["metadata_valid_status"] == 204 and cc["counter_increment_exactly_one"] and cc["valid_custom_metadata_expected"],
        "new_version20_after_cold_reopen": nv["write_status"] == nv["read_status"] == nv["raw_status"] == 200
            and nv["version"] == nv["raw_version"] == 20 and nv["before_after_cold_history_exact"]
            and nv["before_version_count"] == nv["after_version_count"] == 20 and nv["payload_present"] is True
            and nv["raw_payload_matches_fixed_new_value"] and restart_ok(nv["restart"]),
        "commands_once_and_retired": REPORT["command_set_exact"] and REPORT["all_commands_no_retry_and_waited"]
            and all((x["returncode"] == 0 if x["label"] != "tampered_v6_restore" else
                     type(x["returncode"]) is int and x["returncode"] != 0 and x["http_status_codes"] == [400]) for x in REPORT["commands"]),
        "final_custody_and_redaction": REPORT["final_custody_reference_matches"] and REPORT["runtime_credentials_and_fingerprints_absent"] is True
            and REPORT["owned_process_custody"]["independent_all_owned_retired"],
        "unchanged_fixed_inputs": REPORT["private_summaries_unchanged"] and REPORT["fixed_qa_source_pins_unchanged"],
        "qualification_limits_retained": REPORT["qualification_boundaries"]["synthetic_only"] is True
            and all(REPORT["qualification_boundaries"][k] is False for k in ("physical_disk_independence_verified", "physical_power_loss_tested",
                "ha_qualified", "cross_seal_restore", "production_authority", "replacement_authority", "independent_qualification")),
    }
    REPORT["independent_subobservation_gates"] = gates
    REPORT["all_requested_safe_gates_passed"] = all(value is True for value in gates.values())
    REPORT["status"] = "passed" if REPORT["all_requested_safe_gates_passed"] else "failed"

try:
    need(signal.getsignal(signal.SIGALRM) == signal.SIG_DFL and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
         "unowned_original_timer_required")
    signal.signal(signal.SIGALRM, alarm)
    signal.setitimer(signal.ITIMER_REAL, max(0.000001, START + 52 - time.monotonic()))
    main()
except BaseException as error:
    REPORT["status"] = "failed"
    REPORT["projection_error_type"] = type(error).__name__
    if isinstance(error, Refused) and re.fullmatch(r"[a-z_]{1,100}", str(error)):
        REPORT["projection_failure_code"] = str(error)
finally:
    REPORT["deadline_fired"] = DEADLINE_FIRED
    REPORT["elapsed_seconds"] = round(time.monotonic() - START, 6)
    if DEADLINE_FIRED or time.monotonic() >= START + 52:
        REPORT["status"] = "failed"
        REPORT["projection_failure_code"] = "original_projection_deadline"
    signal.setitimer(signal.ITIMER_REAL, 0)
    encoded = json.dumps(REPORT, sort_keys=True, separators=(",", ":"), allow_nan=False)
    print(encoded, flush=True)
sys.exit(0 if REPORT.get("status") == "passed" else 1)
