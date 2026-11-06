#!/usr/bin/env python3
"""One bounded current-data protection attempt; no product or service launch.

The unchanged, separately qualified capture implementation owns all SQLite,
encrypted backup and fresh restore operations. This outer admission does not
claim a writer fence, cross-database atomicity, credential validity or KV2
migration. All source-dependent values and their hashes remain private.
"""
import time
ENTRY = time.monotonic()

import argparse
import ast
import contextlib
import hashlib
import importlib.metadata
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import signal
import stat
import subprocess
import sys
import zipfile

sys.dont_write_bytecode = True
ROOT = Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1")
INPUT = ROOT / "control/current-sqlite-data-protection-inputs-r2"
OUT = ROOT / "control/current-sqlite-data-protection-execution-r2"
ENVIRONMENT = ROOT / "control/formal-kv2-python-env-50-0-2-r3"
ENV_INPUT = ROOT / "control/formal-kv2-python-env-inputs-r3"
PLAN_STAGE = ROOT / "control/mac-current-kv2-plan-stage-r1"
QA = ROOT / "source-dr25-a2577-r2/qa/openbao-acceptance"
WORK_END = ENTRY + 840
TOTAL_END = ENTRY + 900
PREFLIGHT_END = min(ENTRY + 60, WORK_END)
MIB = 1024 ** 2
UID = 501
CODE_SHA = "9e27369657667dc3360ae276bb62e2d1ad0c6f55f07290d91304d7d396d72972"
PRODUCT_COMMIT = "4bde9aee03fcd27c59e13607e529b1cee594b249"
PRODUCT_TREE = "f08493a23f8ea0637073651231865ea9607b790e"
QA_COMMIT = "a25772377e9bfad91564cf6702a26e861fded16f"
QA_TREE = "d34d344e261811c406f63de56b3a7227c0e0ddf3"
FIRED = False
INTERRUPTED = False
FINISHING = False
FS_PROTECTED = False
FAILURE_CLEANUP = False
ACTIVE_END = PREFLIGHT_END
CUSTODY = None
OWNER = None
CORE = None
CONTROL = None
DIRECTORIES = []
READS = []
COMMAND_WINDOW = False
WORKFLOW_WINDOW = False
AUDIT_DENIALS = []
CORE_ERROR_CODES = set()
PHASE = "startup"
PRIVATE = {"schema": "heptabao.current-sqlite-outer-private.v1"}
PUBLIC = {
    "schema": "heptabao.current-sqlite-data-protection-outer.v1",
    "status": "failed",
    "data_protection_only": True,
    "workflow_invoked": False,
    "capture_backup_and_fresh_restore_completed": False,
    "source_code_unchanged": False,
    "all_bound_inputs_and_artifacts_unchanged": False,
    "business_source_values_or_fingerprints_published": False,
    "private_plan_or_config_hashes_published": False,
    "public_output_is_explicit_safe_projection": True,
    "known_product_ci_failures_remain_unresolved_by_this_work": True,
    "full_workspace_product_qualification": False,
    "source_data_write_invoked": False,
    "source_native_sqlite_sidecar_writes_excluded": False,
    "all_known_writers_fenced": False,
    "cross_database_atomic_snapshot_qualified": False,
    "source_freshness_after_capture_qualified": False,
    "current_credential_validity_qualified": False,
    "source_device_loss_recovery_qualified": False,
    "formal_kv2_qualified": False,
    "ha_qualified": False,
    "authbus_qualified": False,
    "all_clients_and_backups_migrated": False,
    "product_or_sdk_executed": False,
    "provider_or_j3160_called": False,
    "production_service_started": False,
    "service_or_client_configuration_changed": False,
    "traffic_cutover_performed": False,
    "old_assets_removed": False,
    "automatic_retry": False,
    "resume_after_failed_phase_supported": False,
    "runtime_cap_seconds": 900,
    "work_cap_seconds_from_original_entry": 840,
    "admission_cap_within_original_work_seconds": 60,
    "phase_caps_seconds": {"capture": 300, "backup": 300, "restore_verify": 300},
    "cleanup_and_receipt_reserve_seconds": 60,
    "deadline_renewed": False,
    "durable_completion_authority": "separate_original_runtime_terminal_with_900_second_cap",
}


class Refused(Exception):
    pass


class Interrupted(BaseException):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def record_failure(error, phase, *, cleanup=False):
    code = str(error) if isinstance(error, Refused) else type(error).__name__
    row = {"phase": phase, "code": code if re.fullmatch(r"[A-Za-z0-9_]{1,100}", code) else "private_failure"}
    PUBLIC.update(status="failed", capture_backup_and_fresh_restore_completed=False)
    if cleanup:
        PUBLIC.setdefault("cleanup_failures", []).append(row)
        if "primary_failure" not in PUBLIC:
            PUBLIC.setdefault("failure_code", row["code"])
            PUBLIC.setdefault("failure_phase", row["phase"])
    else:
        PUBLIC.setdefault("primary_failure", row)
        PUBLIC["failure_code"] = PUBLIC["primary_failure"]["code"]
        PUBLIC["failure_phase"] = PUBLIC["primary_failure"]["phase"]


def unique(pairs):
    out = {}
    for key, value in pairs:
        need(key not in out, "duplicate_json_key")
        out[key] = value
    return out


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode()


def check(end=None):
    limit = ACTIVE_END if end is None else min(end, ACTIVE_END)
    need(not FIRED and not INTERRUPTED and time.monotonic() < limit, "original_deadline_or_interrupt")


def interrupt(signum, frame):
    global FIRED, INTERRUPTED
    if signum == signal.SIGALRM:
        FIRED = True
    else:
        INTERRUPTED = True
    owner = getattr(CUSTODY, "_ACTIVE", None) if CUSTODY is not None else None
    if owner is not None:
        owner._interrupt(signum, frame)
    elif not FINISHING and not FS_PROTECTED:
        raise Interrupted()


def arm_workflow(end):
    """The core may use the original total ceiling only for failure receipt cleanup."""
    global ACTIVE_END, FAILURE_CLEANUP
    need(type(end) in (int, float) and end <= TOTAL_END, "deadline_cannot_extend_original_runtime")
    if end > WORK_END:
        need(end == TOTAL_END, "only_original_total_cleanup_ceiling")
        FAILURE_CLEANUP = True
    else:
        need(not FAILURE_CLEANUP and not FIRED and not INTERRUPTED, "failed_attempt_cannot_resume")
    ACTIVE_END = end
    remaining = end - time.monotonic()
    need(remaining > 0, "original_deadline_expired")
    signal.setitimer(signal.ITIMER_REAL, remaining)


def file_identity(st):
    return {"dev": st.st_dev, "inode": st.st_ino, "uid": st.st_uid, "gid": st.st_gid,
            "mode": stat.S_IMODE(st.st_mode), "file_type": stat.S_IFMT(st.st_mode),
            "nlink": st.st_nlink, "bytes": st.st_size,
            "mtime_ns": st.st_mtime_ns, "ctime_ns": st.st_ctime_ns}


def version(identity):
    return ":".join(str(identity[k]) for k in ("dev", "inode", "bytes", "mtime_ns", "ctime_ns"))


def directory_identity(path, *, private=True):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "canonical_directory")
    st = path.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid in (0, UID)
         and not (stat.S_IMODE(st.st_mode) & 0o022), "controlled_directory")
    if private:
        need(st.st_uid == UID and stat.S_IMODE(st.st_mode) == 0o700, "owned_private_directory")
    return {"path": str(path), "dev": st.st_dev, "inode": st.st_ino,
            "uid": st.st_uid, "gid": st.st_gid, "mode": stat.S_IMODE(st.st_mode)}


def fd_directory(path, fd):
    st = os.fstat(fd)
    need(stat.S_ISDIR(st.st_mode), "original_directory_handle")
    return {"path": str(path), "dev": st.st_dev, "inode": st.st_ino,
            "uid": st.st_uid, "gid": st.st_gid, "mode": stat.S_IMODE(st.st_mode)}


def hold_directory(path, *, private=True):
    global FS_PROTECTED
    path = Path(path)
    for row in DIRECTORIES:
        if row["path"] == path:
            need(directory_identity(path, private=row["private"]) == row["pin"] == fd_directory(path, row["fd"]),
                 "retained_directory_changed")
            return row
    pin = directory_identity(path, private=private)
    previous = FS_PROTECTED
    FS_PROTECTED = True
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        need(fd_directory(path, fd) == pin == directory_identity(path, private=private), "directory_path_handle_race")
        row = {"path": path, "pin": pin, "fd": fd, "private": private}
        DIRECTORIES.append(row)
        fd = None
        return row
    finally:
        if fd is not None:
            os.close(fd)
        FS_PROTECTED = previous


def volume_directory_identity(alias, path, expected):
    """Observe only the two fixed, read-only volume roots against stage pins."""
    mounts = {"Data": Path("/System/Volumes/Data"), "T5": Path("/Volumes/T5")}
    path = Path(path)
    need(alias in mounts and path == mounts[alias], "fixed_volume_alias_and_path")
    need(set(expected) == {"path", "dev", "inode", "uid", "gid", "mode"}
         and expected["path"] == str(path)
         and all(type(expected[key]) is int and expected[key] >= 0 for key in ("dev", "inode", "uid", "gid", "mode"))
         and expected["uid"] in (0, UID) and expected["mode"] <= 0o7777,
         "fixed_volume_original_identity_fields")
    need(path.resolve(strict=True) == path, "fixed_volume_canonical_directory")
    st = path.lstat()
    need(stat.S_ISDIR(st.st_mode), "fixed_volume_directory_required")
    observed = {"path": str(path), "dev": st.st_dev, "inode": st.st_ino,
                "uid": st.st_uid, "gid": st.st_gid, "mode": stat.S_IMODE(st.st_mode)}
    need(observed == expected, "fixed_volume_original_identity_changed")
    return observed


def hold_volume_directory(alias, path, expected):
    global FS_PROTECTED
    path = Path(path)
    binding = {"alias": alias, "expected": dict(expected)}
    pin = volume_directory_identity(alias, path, expected)
    for row in DIRECTORIES:
        if row["path"] == path:
            need(row.get("volume_binding") == binding and row["pin"] == pin == fd_directory(path, row["fd"]),
                 "fixed_volume_retained_original_handle")
            return row
    previous = FS_PROTECTED
    FS_PROTECTED = True
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        need(fd_directory(path, fd) == pin == volume_directory_identity(alias, path, expected),
             "fixed_volume_path_handle_race")
        row = {"path": path, "pin": pin, "fd": fd, "private": False, "volume_binding": binding}
        DIRECTORIES.append(row)
        fd = None
        return row
    finally:
        if fd is not None:
            os.close(fd)
        FS_PROTECTED = previous


def verify_directories():
    for row in DIRECTORIES:
        if "volume_binding" in row:
            binding = row["volume_binding"]
            observed = volume_directory_identity(binding["alias"], row["path"], binding["expected"])
        else:
            observed = directory_identity(row["path"], private=row["private"])
        need(observed == row["pin"]
             == fd_directory(row["path"], row["fd"]), "original_directory_identity_changed")


def read_file(path, maximum, *, private=True, pin=None, remember=False):
    check()
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "canonical_file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        ident = file_identity(st)
        need(stat.S_ISREG(st.st_mode) and st.st_uid in (0, UID) and st.st_nlink == 1
             and not (stat.S_IMODE(st.st_mode) & 0o022) and 0 <= st.st_size <= maximum,
             "bounded_regular_owned_file")
        if private:
            need(st.st_uid == UID and stat.S_IMODE(st.st_mode) == 0o600, "private_file_custody")
        value, blocks, count = hashlib.sha256(), [], 0
        while True:
            check()
            block = os.read(fd, MIB)
            if not block:
                break
            count += len(block)
            need(count <= maximum, "file_byte_bound")
            value.update(block)
            blocks.append(block)
        need(count == st.st_size and ident == file_identity(os.fstat(fd)) == file_identity(path.lstat()),
             "file_changed_during_read")
        actual = {"bytes": count, "sha256": value.hexdigest()}
        if pin is not None:
            need(actual == {"bytes": pin["bytes"], "sha256": pin["sha256"]}, "exact_file_bytes_required")
        if remember:
            READS.append({"path": path, "maximum": maximum, "private": private, "pin": actual, "identity": ident})
        return b"".join(blocks), ident
    finally:
        os.close(fd)


def hash_artifact(path, pin):
    """Stream large immutable executables without retaining their payload."""
    check()
    path = Path(path)
    need(path.resolve(strict=True) == path, "canonical_artifact")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        ident = file_identity(st)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == UID and st.st_nlink == 1
             and not (stat.S_IMODE(st.st_mode) & 0o022) and st.st_size == pin["bytes"]
             and 0 < st.st_size <= 256 * MIB, "fixed_artifact_custody")
        value, count = hashlib.sha256(), 0
        while True:
            check()
            block = os.read(fd, MIB)
            if not block:
                break
            count += len(block)
            need(count <= pin["bytes"], "artifact_byte_bound")
            value.update(block)
        need(count == pin["bytes"] and value.hexdigest() == pin["sha256"]
             and ident == file_identity(os.fstat(fd)) == file_identity(path.lstat()), "artifact_pin_or_identity_changed")
        return ident
    finally:
        os.close(fd)


def control_write(name, raw):
    need(CONTROL is not None and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name), "controlled_output_name")
    verify_directories()
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=CONTROL["fd"])
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
        st = os.fstat(fd)
        ident = file_identity(st)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == UID and st.st_nlink == 1
             and stat.S_IMODE(st.st_mode) == 0o600 and st.st_size == len(raw),
             "owned_output_file_custody")
        need(ident == file_identity(os.stat(name, dir_fd=CONTROL["fd"], follow_symlinks=False)),
             "owned_output_file_path_handle_identity")
    finally:
        os.close(fd)
    os.fsync(CONTROL["fd"])
    verify_directories()
    need(ident == file_identity(os.stat(name, dir_fd=CONTROL["fd"], follow_symlinks=False)),
         "owned_output_file_changed_after_fsync")
    return ident


def create_output():
    global CONTROL, FS_PROTECTED
    parent = hold_directory(OUT.parent)
    need(not os.path.lexists(OUT), "create_only_outer_output")
    FS_PROTECTED = True
    try:
        os.mkdir(OUT.name, 0o700, dir_fd=parent["fd"])
        PRIVATE["output_created"] = True
        os.fsync(parent["fd"])
        CONTROL = hold_directory(OUT)
        verify_directories()
    finally:
        FS_PROTECTED = False
    check()


@contextlib.contextmanager
def private_stdio():
    """Capture native descriptors as well as Python output; never export their hash."""
    saved, targets = [], []
    global FS_PROTECTED
    try:
        FS_PROTECTED = True
        try:
            for number, name in ((1, "workflow.stdout.private"), (2, "workflow.stderr.private")):
                stream = sys.stdout if number == 1 else sys.stderr
                stream.flush()
                saved.append((number, os.dup(number)))
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=CONTROL["fd"])
                targets.append(fd)
                os.dup2(fd, number)
        finally:
            FS_PROTECTED = False
        check()
        yield
    finally:
        FS_PROTECTED = True
        errors = []
        try:
            for stream in (sys.stdout, sys.stderr):
                try:
                    stream.flush()
                except BaseException:
                    errors.append("flush")
            for number, fd in reversed(saved):
                try:
                    os.dup2(fd, number)
                except BaseException:
                    errors.append("restore")
                finally:
                    os.close(fd)
            for fd in targets:
                try:
                    os.fsync(fd)
                except BaseException:
                    errors.append("fsync")
                finally:
                    os.close(fd)
            os.fsync(CONTROL["fd"])
        finally:
            FS_PROTECTED = False
        need(not errors, "native_stdio_restore_failed")


def successful_terminal(value, job):
    need(value["job_id"] == job and value["state"] == "succeeded" and value["exit_code"] == 0
         and value["timed_out"] is False and value["cancelled"] is False
         and value["automatic_retry"] is False and value["output_complete"] is True
         and value["output_durable"] is True and value["terminal_publication_confirmed"] is True,
         "successful_durable_original_terminal_required")
    for stream in ("stdout", "stderr"):
        need(value["log_synced"][stream] is True and value["log_truncated"][stream] is False
             and value["log_errors"][stream] is None
             and value["log_bytes"][stream]["seen"] == value["log_bytes"][stream]["stored"],
             "complete_original_runtime_stream_required")


def validate_owned_safe(value, count, job):
    need(value["schema"] == "heptabao.owned-process-complete-safe-projection.v1"
         and value["source_binding"]["runtime_job_id"] == job
         and value["original_count"] == len(value["children"]) == count
         and value["finished"] is True and value["passed_process_custody"] is True
         and value["failed"] is False and value["interrupted"] is False, "complete_owned_process_evidence")
    for index, row in enumerate(value["children"]):
        birth = row["birth"]
        need(row["index"] == index and row["exec_admitted"] is True and row["returncode"] == 0
             and row["original_wait_completed"] is True and row["original_wait_count"] == 1
             and row["no_live_members_before_reap"] is True and row["gaps"] == []
             and birth["pid"] == row["pid"] == birth["pgid"] == birth["sid"]
             and birth["uid"] == UID and birth["ppid"] > 0, "original_process_retirement_required")
        for key in ("members_at_leader_exit", "members_before_original_reap"):
            need(isinstance(row[key], list) and all(m["state"].startswith("Z") for m in row[key]),
                 "no_live_owned_member_required")


def validate_build107(build, selection):
    need(build["schema"] == "heptabao.convergence-normal-build-tests.v1" and build["status"] == "passed"
         and build["source_commit"] == PRODUCT_COMMIT and build["source_tree"] == PRODUCT_TREE
         and build["source_and_artifacts_unchanged"] is True and build["all_owned_processes_gone"] is True
         and build["passed_cases"] == build["executed_passed_cases"] == build["observed_test_executed_cases"] == 107
         and build["observed_test_failed_cases"] == build["observed_test_ignored_cases"]
         == build["unexecuted_or_ignored_required_cases"] == 0, "normal_107_actual_complete")
    selected = selection["legacy_groups"] + selection["legacy_additional_groups"] + selection["added_groups"]
    expected = {g["label"]: g for g in selected}
    need(len(expected) == len(selected) == len(build["groups"]) == 16, "original_107_group_denominator")
    names = []
    for row in build["groups"]:
        group = expected[row["label"]]
        need(row["status"] == "passed" and row["expected_count"] == row["passed"] == group["expected_count"]
             and row["tests"] == group["tests"] and row["budget_renewed_per_case"] is False
             and row["original_group_budget_seconds"] == group["runtime_seconds"]
             and build["enumeration"][row["label"]]["matched_count"] == group["expected_count"]
             and sorted(build["enumeration"][row["label"]]["matched_names"]) == sorted(group["tests"]),
             "original_group_names_and_budget")
        need(sum(r["passed"] for r in row["results"]) == group["expected_count"]
             and all(r["reported_state"] == "ok" and r["exact_denominator_passed"] is True
                     and r["failed"] == r["ignored"] == r["measured"] == 0 for r in row["results"]),
             "actual_group_result_complete")
        names.extend(group["tests"])
    need(len(names) == len(set(names)) == 107, "unique_107_cases")
    need(set(build["artifacts"]) == {"heptabao-server", "heptabao-seed", "heptabao-server-libtest", "heptabao-ha-service-libtest"},
         "all_four_bound_artifacts")
    for row in build["artifacts"].values():
        need(row["source_commit"] == PRODUCT_COMMIT and row["source_tree"] == PRODUCT_TREE
             and row["normal_features_profile_and_source_verified"] is True,
             "artifact_actual_source_and_normal_profile")


def validate_dr(wrapper, projection):
    need(wrapper["schema"] == "heptabao.mac-full34-dr25-fixed-execution.v1"
         and wrapper["status"] == "passed" and wrapper["controller_exit_code"] == 0
         and wrapper["baseline_31_passed"] is True and wrapper["dr25_passed"] is True
         and wrapper["observed_dr25_check_count"] == wrapper["observed_dr25_pass_count"] == 25
         and wrapper["missing_required_dr25"] == [] and wrapper["all_originals_retired"] is True
         and wrapper["deadline"]["fired"] is False and wrapper["deadline"]["deadline_renewed"] is False
         and wrapper["runtime_outer_seconds"] == 1800, "actual_full34_dr25_complete")
    need(projection["schema"] == "heptabao.mac-dr25-r2-independent-safe-projection.v1"
         and projection["status"] == "passed" and projection["projection_complete"] is True
         and projection["actual_dr_job"] == "1a1b1639f4d-fc05-7839"
         and projection["product_commit"] == PRODUCT_COMMIT and projection["product_tree"] == PRODUCT_TREE
         and projection["qa_commit"] == QA_COMMIT and projection["qa_tree"] == QA_TREE
         and projection["fixed_qa_source_pins_unchanged"] is True
         and projection["private_summaries_unchanged"] is True
         and projection["private_summary_bytes_or_fingerprints_emitted"] is False,
         "independent_actual_dr_projection")
    gates = projection["independent_subobservation_gates"]
    need(len(gates) == 26 and all(value is True for value in gates.values()), "all_26_independent_gates")
    for key, count in (("baseline31", 31), ("dr25", 25)):
        value = projection[key]
        need(value["observed_count"] == value["required_count"] == value["passed_count"] == count
             and value["exact_names"] is True and value["all_passed"] is True
             and value["unknown_or_invalid_count"] == value["failed_count"] == 0
             and len(value["rows"]) == count
             and all(row[0] == i and row[2] is True for i, row in enumerate(value["rows"]))
             and len({r[1] for r in value["rows"]}) == count, "exact_31_25_case_evidence")
    c = projection["owned_process_custody"]
    need(c["original_count"] == c["children_count"] == len(c["children"]) == 700
         and c["finished"] is True and c["passed_process_custody"] is True
         and c["failed"] is False and c["interrupted"] is False
         and c["child_columns"] == ["index", "exec_admitted", "original_wait_completed", "original_wait_count", "returncode",
                                     "no_live_members_before_reap", "gaps_count", "birth", "members_at_leader_exit", "members_before_original_reap"],
         "complete_700_originals")
    for index, row in enumerate(c["children"]):
        need(len(row) == 10 and row[0] == index and row[1] is True and row[2] is True and row[3] == 1
             and type(row[4]) is int and row[5] is True and row[6] == 0
             and len(row[7]) == 7 and row[7][0] == row[7][2] == row[7][3] and row[7][4] == UID
             and all(len(m) == 7 and m[6].startswith("Z") for group in row[8:10] for m in group),
             "every_original_retired_without_live_members")
    need(projection["formal_replacement_qualified"] is False and projection["production_authority"] is False
         and projection["qualification_boundaries"]["synthetic_only"] is True,
         "synthetic_dr_qualification_boundary")


def validate_env_and_controls(env, controls, env_owned, control_owned, test_source):
    need(env["schema"] == "heptabao.mac-create-only-capture-python-environment.v1"
         and env["status"] == "passed" and env["environment_ready"] is True
         and env["original_inputs_unchanged"] is True and env["all_owned_processes_retired"] is True
         and env["deadline_fired"] is False and env["interrupted"] is False
         and env["installed_packages"] == {"pip": "26.3", "cryptography": "50.0.2", "cffi": "2.0.0", "pycparser": "2.23"},
         "actual_isolated_environment_complete")
    validate_owned_safe(env_owned, 3, "1a1b1c05955-fc05-7aa0")
    validate_owned_safe(control_owned, 1, "1a1b1c4c600-fc05-7abc")
    tree = ast.parse(test_source)
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "CurrentCaptureControls")
    expected = sorted("test_mac_current_sqlite_capture.CurrentCaptureControls." + n.name
                      for n in cls.body if isinstance(n, ast.FunctionDef) and n.name.startswith("test_"))
    need(len(expected) == len(set(expected)) == 18, "unchanged_18_test_source")
    c = controls["controls"]
    need(controls["schema"] == "heptabao.mac-current-sqlite-capture-controls.v1" and controls["status"] == "passed"
         and controls["actual_darwin_capture_controls_qualified"] is True
         and controls["inputs_unchanged"] is True and controls["all_owned_processes_retired"] is True
         and controls["owned_fixtures_retired"] is True and controls["real_two_filesystems"] is True
         and controls["enumeration"]["names"] == c["started"] == expected
         and [row["test"] for row in c["completed"]] == expected
         and all(row["status"] == "passed" for row in c["completed"])
         and controls["enumeration"]["unique"] == controls["expected_tests"] == c["tests_run"] == 18
         and all(c[key] == 0 for key in ("errors", "failures", "skipped", "expected_failures", "unexpected_successes"))
         and controls["deadline_fired"] is False and controls["interrupted"] is False,
         "all_18_actual_darwin_controls")
    need(control_owned["real_two_filesystems"] is True
         and control_owned["owned_synthetic_directory_identities"]["internal_fixture"][0]
         != control_owned["owned_synthetic_directory_identities"]["output"][0], "actual_independent_fixture_filesystems")


def load_public_gates(inputs, test_source):
    values = {}
    for name, pin in inputs["public_files"].items():
        need(re.fullmatch(r"[A-Za-z0-9_.-]+", name), "fixed_public_input_name")
        raw, _ = read_file(INPUT / name, 2 * MIB, pin=pin, remember=True)
        values[name] = json.loads(raw, object_pairs_hook=unique)
    for name, job in inputs["terminal_jobs"].items():
        successful_terminal(values[name], job)
    build, selection = values["mac107-result.public.json"], values["mac107-selection.public.json"]
    need(build["selection_sha256"] == inputs["public_files"]["mac107-selection.public.json"]["sha256"], "build_selection_binding")
    validate_build107(build, selection)
    validate_dr(values["dr2-result.public.json"], values["dr26-runtime.stdout.original"])
    validate_env_and_controls(values["environment-result.public.json"], values["controls18-result.public.json"],
                              values["environment-owned-three.public.json"], values["controls18-owned-one.public.json"], test_source)
    PUBLIC["previous_bounded_evidence"] = {"normal_rust_tests": 107, "full34_cases": 31, "fresh_directory_dr_cases": 25,
                                           "independent_dr_gates": 26, "dr_original_processes": 700,
                                           "environment_original_processes": 3, "actual_darwin_controls": 18,
                                           "control_original_writers": 1, "grants_product_qualification": False}
    return values


def preserve_prior_failed_attempt(inputs, values):
    terminal = values["prior-r1-runtime-terminal.original.json"]
    failed = values["prior-r1-result.public.json"]
    need(terminal["job_id"] == "1a1b1f76336-fc05-7bc7" and terminal["state"] == "failed"
         and terminal["exit_code"] == 1 and terminal["timed_out"] is False and terminal["cancelled"] is False
         and terminal["automatic_retry"] is False and terminal["output_complete"] is True
         and terminal["output_durable"] is True and terminal["terminal_publication_confirmed"] is True,
         "original_r1_failed_terminal_preserved")
    for stream in ("stdout", "stderr"):
        need(terminal["log_synced"][stream] is True and terminal["log_truncated"][stream] is False
             and terminal["log_errors"][stream] is None
             and terminal["log_bytes"][stream]["seen"] == terminal["log_bytes"][stream]["stored"],
             "original_r1_complete_streams")
    need(failed["schema"] == "heptabao.current-sqlite-data-protection-outer.v1"
         and failed["status"] == "failed" and failed["workflow_invoked"] is False
         and failed["failure_code"] == "final_owned_custody_incomplete"
         and failed["owned_native_metadata_processes"]["original_count"] == 1
         and failed["owned_native_metadata_processes"]["failed"] is True
         and failed["owned_native_metadata_processes"]["passed_process_custody"] is False,
         "original_r1_failure_not_reclassified")
    old_input = ROOT / "control/current-sqlite-data-protection-inputs-r1"
    old_output = ROOT / "control/current-sqlite-data-protection-execution-r1"
    hold_directory(old_input)
    hold_directory(old_output)
    read_file(old_output / "result.public.json", 16384,
              pin=inputs["public_files"]["prior-r1-result.public.json"], remember=True)
    read_file(old_input / "mac_current_sqlite_data_protection_outer.py", 128 * 1024,
              pin={"bytes": 55776, "sha256": "4ac1110cb3a065f06a1f408b9b5b0b17565a3e0517a322d380307ab11b5ff88d"}, remember=True)
    read_file(old_input / "fixed-inputs.public.json", 16384,
              pin={"bytes": 5386, "sha256": "413027c61091eae87f17ab247930a48a0d7a3f20b105432b15d2826c8dbb337b"}, remember=True)
    PUBLIC["prior_failed_attempt"] = {"job_id": terminal["job_id"], "original_status": "failed",
                                       "original_exit_code": 1, "workflow_invoked": False,
                                       "reclassified_as_success": False}


def validate_private_pin(raw, identity, pin, published_identity):
    need(set(pin) == {"bytes", "sha256", "version", "uid", "mode", "nlink"}, "independent_private_pin_fields")
    need(len(raw) == pin["bytes"] and hashlib.sha256(raw).hexdigest() == pin["sha256"]
         and version(identity) == pin["version"] and identity == published_identity
         and pin["uid"] == identity["uid"] == UID and pin["mode"] == identity["mode"] == 0o600
         and pin["nlink"] == identity["nlink"] == 1, "independent_private_plan_pin_mismatch")


def load_private_plan(inputs, values):
    stage = values["plan-stage-result.public.json"]
    need(stage["status"] == "private_plan_staged_workflow_not_executed" and stage["observation_complete"] is True
         and stage["current_private_baseline_reconstructed_from_live_scope"] is True
         and stage["historical_private_unchanged_since_admission_proven"] is False
         and stage["historical_private_file_opened_or_used_for_current_qualification"] is False
         and stage["configured_agent_count"] == 5 and stage["declared_database_families"] == 9
         and stage["private_plan_readback_exact"] is True
         and stage["private_plan_original_file_identities_preserved"] is True
         and stage["actual_workflow_attempt_directories_all_absent"] is True
         and stage["workflow_executed"] is False and stage["formal_kv2_qualified"] is False
         and stage["deadline_fired"] is False and stage["interrupted"] is False,
         "completed_fresh_private_plan_stage_required")
    raw, _ = read_file(INPUT / "independent-plan-pins.private.json", 65536, remember=True)
    pins = json.loads(raw, object_pairs_hook=unique)
    need(set(pins) == {"schema", "stage_job_id", "stage_public_result_sha256", "stage_terminal_sha256", "files"}
         and pins["schema"] == "heptabao.independent-current-private-plan-file-pins.v1"
         and pins["stage_job_id"] == inputs["stage_job_id"]
         and pins["stage_public_result_sha256"] == inputs["public_files"]["plan-stage-result.public.json"]["sha256"]
         and pins["stage_terminal_sha256"] == inputs["public_files"]["plan-stage-runtime-terminal.original.json"]["sha256"],
         "independent_private_plan_stage_binding")
    published = {row["role"]: row["identity"] for row in stage["private_output_file_identities"]}
    need(set(published) == set(pins["files"]) == {"workflow_plan", "workflow_plan_binding"}, "exact_two_private_plan_outputs")
    result = {}
    for role, name in (("workflow_plan", "workflow-plan.private.json"),
                       ("workflow_plan_binding", "workflow-plan-binding.private.json")):
        raw, ident = read_file(PLAN_STAGE / name, 512 * 1024, remember=True)
        validate_private_pin(raw, ident, pins["files"][role], published[role])
        result[role] = json.loads(raw, object_pairs_hook=unique)
        if role == "workflow_plan":
            plan_raw, plan_ident = raw, ident
    plan, binding = result["workflow_plan"], result["workflow_plan_binding"]
    need(binding["schema"] == "heptabao.current-workflow-private-plan-binding.v1"
         and binding["plan_path"] == str(PLAN_STAGE / "workflow-plan.private.json")
         and binding["plan_bytes"] == len(plan_raw)
         and binding["plan_sha256"] == hashlib.sha256(plan_raw).hexdigest()
         and binding["plan_file_identity"] == plan_ident and binding["capture_code_sha256"] == CODE_SHA,
         "private_plan_binding_exact")
    need(plan["overall_budget_seconds"] == 900
         and all(plan[part]["budget_seconds"] == 300 for part in ("capture", "backup", "restore"))
         and plan["capture"]["maximum_database_bytes"] == 3087007744
         and plan["capture"]["maximum_total_bytes"] == 4227858432
         and len(plan["capture"]["agents"]) == 5,
         "original_current_scope_capacity_and_budgets")
    current = binding["fresh_current_private_baseline"]
    need(plan["capture"]["agents"] == current["configured_agents"]
         and plan["capture"]["source_config_sha256"] == current["source_config_sha256"] == binding["source_config_sha256"]
         and binding["source_root_identity"] == current["source_root_identity"]
         and binding["workflow_executed"] is False and binding["all_known_writers_fenced"] is False
         and binding["cross_database_atomic"] is False, "current_private_scope_not_historical_or_fenced")
    CORE.validate_workflow(plan)
    for role, pin in binding["parent_identities"].items():
        need(role in ("capture", "archive", "key", "restore") and hold_directory(pin["path"])["pin"] == pin,
             "current_parent_original_identity")
    need(set(binding["parent_identities"]) == {"capture", "archive", "key", "restore"}, "exact_four_parent_roles")
    need(hold_directory(plan["capture"]["source_root"])["pin"] == binding["source_root_identity"], "current_source_root_identity")
    paths = {
        "capture": Path(plan["capture"]["capture_parent"]) / plan["capture"]["capture_name"],
        "archive": Path(plan["backup"]["archive_parent"]) / plan["backup"]["archive_name"],
        "key": Path(plan["backup"]["key_parent"]) / plan["backup"]["key_name"],
        "restore": Path(plan["restore"]["restore_parent"]) / plan["restore"]["restore_name"],
    }
    need(set(str(p) for p in paths.values()) == set(binding["actual_workflow_attempt_roots"])
         and len(binding["actual_workflow_attempt_roots"]) == 4
         and all(not os.path.lexists(path) for path in paths.values()), "all_four_attempts_absent")
    CORE.workflow_location_admission(plan)
    PRIVATE.update(independent_private_plan_pins=pins, workflow_plan=plan, workflow_plan_binding=binding)
    PUBLIC["fresh_current_plan_and_independent_native_file_pins_bound"] = True
    return plan, binding, paths


def verify_installed_runtime(inputs):
    need(sys.platform == "darwin" and os.geteuid() == UID and sys.version_info[:3] == (3, 14, 3)
         and sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1
         and Path(sys.prefix) == ENVIRONMENT / "venv"
         and Path(sys.executable) == ENVIRONMENT / "venv/bin/python3", "actual_fixed_isolated_darwin_runtime")
    read_file(Path(sys.executable), MIB, private=False, pin=inputs["python"], remember=True)
    read_file(ENVIRONMENT / "venv/pyvenv.cfg", 4096, private=False,
              pin=inputs["venv_configuration"], remember=True)
    raw, _ = read_file(ENV_INPUT / "fixed-wheel-plan.json", 65536, pin=inputs["environment_plan"], remember=True)
    plan = json.loads(raw, object_pairs_hook=unique)
    site = ENVIRONMENT / "venv/lib/python3.14/site-packages"
    need(site.resolve(strict=True) == site, "fixed_environment_site_packages")
    counts = {}
    for package in plan["packages"]:
        project, wheel = package["project"], package["wheel"]
        need(importlib.metadata.distribution(project).version == package["version"], "fixed_installed_package_version")
        path = ENVIRONMENT / "wheels" / wheel["filename"]
        raw, _ = read_file(path, 8 * MIB, pin=wheel, remember=True)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            names = archive.namelist()
            need(len(names) == len(set(names)) and len(names) <= 4096, "bounded_unique_public_wheel_members")
            checked = 0
            for item in archive.infolist():
                if item.is_dir():
                    continue
                rel = PurePosixPath(item.filename)
                need(not rel.is_absolute() and ".." not in rel.parts and str(rel) == item.filename,
                     "canonical_wheel_member")
                if rel.name == "RECORD" and rel.parent.name.endswith(".dist-info"):
                    continue  # pip rewrites this bookkeeping file when installing scripts.
                need(not any(part.endswith(".data") for part in rel.parts), "unsupported_wheel_install_mapping")
                need(item.file_size <= 32 * MIB, "bounded_installed_package_member")
                expected = archive.read(item)
                installed, _ = read_file(site / item.filename, 32 * MIB, private=False,
                                         pin={"bytes": len(expected), "sha256": hashlib.sha256(expected).hexdigest()}, remember=True)
                need(installed == expected, "installed_importable_file_exact_wheel_bytes")
                checked += 1
        counts[project] = checked
    need(set(counts) == {"pip", "cryptography", "cffi", "pycparser"}, "all_four_fixed_distributions")
    import cryptography
    from cryptography.fernet import Fernet
    need(cryptography.__version__ == "50.0.2" and callable(Fernet.generate_key)
         and Path(cryptography.__file__).resolve(strict=True) == site / "cryptography/__init__.py",
         "fixed_cryptography_import_origin")
    PUBLIC["installed_public_package_files_equal_fixed_wheels"] = counts


def load_core_and_custody(inputs):
    global CORE, CUSTODY
    raw, _ = read_file(ENV_INPUT / "mac_current_sqlite_capture.py", 128 * 1024,
                       pin=inputs["capture_source"], remember=True)
    test_raw, _ = read_file(ENV_INPUT / "test_mac_current_sqlite_capture.py", 128 * 1024,
                            pin=inputs["capture_tests"], remember=True)
    need(inputs["capture_source"] == {"bytes": 57280, "sha256": CODE_SHA}, "unchanged_qualified_capture_source")
    for node in ast.walk(ast.parse(raw)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            index = 1 if node.func.id == "need" else 0 if node.func.id == "Refused" else None
            if index is not None and len(node.args) > index and isinstance(node.args[index], ast.Constant):
                value = node.args[index].value
                if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_]{1,100}", value):
                    CORE_ERROR_CODES.add(value)
    for name, pin in inputs["custody_helpers"].items():
        read_file(QA / name, 65536, private=False, pin=pin, remember=True)
    sys.path.insert(0, str(QA))
    import kv2_dr_process_custody as custody
    need(Path(custody.__file__).resolve(strict=True) == QA / "kv2_dr_process_custody.py", "fixed_custody_module_origin")
    CUSTODY = custody
    spec = importlib.util.spec_from_file_location("qualified_current_sqlite_capture", ENV_INPUT / "mac_current_sqlite_capture.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    CORE = module
    need(CORE.MAX_WORKFLOW_SECONDS == 900 and CORE.MAX_SECONDS == 300 and CORE.CHUNK == 4 * MIB,
         "qualified_core_original_limits")
    return test_raw


def safe_custody(receipt):
    rows = []
    for index, child in enumerate(receipt.get("children", [])):
        row = {key: child.get(key) for key in ("pid", "exec_admitted", "returncode", "original_wait_count",
                                              "original_wait_completed", "no_live_members_before_reap")}
        row.update(index=index, gap_count=len(child.get("gaps", [])),
                   birth={k: child.get("birth", {}).get(k) for k in ("pid", "ppid", "pgid", "sid", "uid", "state")})
        for name in ("members_at_leader_exit", "members_before_original_reap"):
            row[name] = [{k: member.get(k) for k in ("pid", "ppid", "pgid", "sid", "uid", "state")}
                         for member in child.get(name, [])]
        rows.append(row)
    return {"original_count": receipt.get("original_count"), "finished": receipt.get("finished"),
            "failed": receipt.get("failed"), "interrupted": receipt.get("interrupted"),
            "passed_process_custody": receipt.get("passed_process_custody"), "children": rows,
            "escaped_session_containment_claim": False}


def verify_volumes(binding):
    global OWNER, COMMAND_WINDOW, PHASE
    need(set(binding["volume_identities"]) == {"Data", "T5"}, "exact_two_actual_volumes")
    COMMAND_WINDOW = True
    try:
        with CUSTODY.activated() as owner:
            OWNER = owner
            for alias, mount in (("Data", "/System/Volumes/Data"), ("T5", "/Volumes/T5")):
                PHASE = "verify_volume_" + alias
                check()
                expected = binding["volume_identities"][alias]
                before = hold_volume_directory(alias, mount, expected["directory"])
                need(before["pin"] == expected["directory"], "original_stage_volume_directory_identity")
                result = subprocess.run(["/usr/sbin/diskutil", "info", "-plist", mount], stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=OUT,
                                        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
                                        timeout=min(5.0, max(0.001, PREFLIGHT_END - time.monotonic())), check=False)
                need(result.returncode == 0 and result.stderr == b"" and len(result.stdout) <= MIB,
                     "bounded_actual_diskutil_observation")
                value = plistlib.loads(result.stdout)
                actual = {k: value.get(k) for k in ("MountPoint", "VolumeUUID", "DiskUUID", "DeviceIdentifier", "FilesystemType", "Internal")}
                need(actual == expected["selected_diskutil"] and actual["MountPoint"] == mount
                     and type(actual["VolumeUUID"]) is str and bool(actual["VolumeUUID"])
                     and type(actual["FilesystemType"]) is str and bool(actual["FilesystemType"])
                     and type(actual["Internal"]) is bool and actual["Internal"] is (alias == "Data"),
                     "current_actual_volume_identity_changed")
                PRIVATE.setdefault("actual_volume_observations", {})[alias] = actual
            owner.assert_retired()
    finally:
        COMMAND_WINDOW = False
    receipt = OWNER.receipt()
    PRIVATE["native_volume_process_custody"] = receipt
    PUBLIC["owned_native_metadata_processes"] = safe_custody(receipt)
    need(receipt["original_count"] == len(receipt["children"]) == 2 and receipt["finished"] is True
         and receipt["passed_process_custody"] is True and receipt["failed"] is False
         and receipt["interrupted"] is False
         and all(c["exec_admitted"] is True and c["original_wait_completed"] is True
                 and c["original_wait_count"] == 1 and c["no_live_members_before_reap"] is True
                 and c["gaps"] == [] and c["returncode"] == 0 for c in receipt["children"]),
         "exact_two_volume_originals_retired")
    for alias, minimum in (("Data", 16844324864), ("T5", 6208968022)):
        mount = binding["volume_identities"][alias]["directory"]["path"]
        st = os.statvfs(mount)
        need(st.f_bavail * st.f_frsize >= minimum, "complete_fixed_lifecycle_disk_headroom")
    PUBLIC["current_two_volume_identities_and_complete_lifecycle_space_verified"] = True
    PUBLIC["read_only_volume_roots_bound_to_original_stage_identity"] = True


def audit(event, args):
    if event.startswith("socket.") or event in ("os.system", "pty.spawn"):
        AUDIT_DENIALS.append(event)
        raise Refused("network_or_shell_outside_data_protection_scope")
    if event in ("subprocess.Popen", "os.fork", "os.forkpty", "os.posix_spawn") and not COMMAND_WINDOW:
        AUDIT_DENIALS.append(event)
        raise Refused("subprocess_outside_fixed_metadata_phase")
    if event == "sqlite3.connect" and not WORKFLOW_WINDOW:
        AUDIT_DENIALS.append(event)
        raise Refused("sqlite_outside_qualified_workflow")


def safe_workflow_projection(report):
    need(isinstance(report, dict) and report.get("schema") == "heptabao.mac-current-sqlite-recovery-workflow.public.v1",
         "qualified_workflow_public_schema")
    allowed = ("source_data_write_invoked", "provider_or_sdk_called", "service_or_client_configuration_changed",
               "traffic_cutover_performed", "old_assets_removed", "source_native_sqlite_sidecar_writes_excluded",
               "cross_database_atomic_snapshot_qualified", "all_known_writers_fenced", "source_freshness_after_capture_qualified",
               "current_credential_validity_qualified", "full_host_inventory_qualified", "formal_kv2_qualified",
               "all_clients_and_backups_migrated", "credential_values_or_content_fingerprints_published",
               "source_capture_or_service_cutover_qualified", "automatic_retry", "resume_after_failed_phase_supported")
    need(all(report.get(key) is False for key in allowed), "original_qualification_boundaries_preserved")
    phases = []
    for row in report.get("phases", []):
        need(set(row) == {"phase", "status", "phase_cap_seconds", "elapsed_seconds",
                          "completion_observed_within_original_phase_and_total_deadlines"}
             and row["phase"] in ("capture", "backup", "restore-verify") and row["status"] == "passed"
             and row["phase_cap_seconds"] == 300
             and type(row["elapsed_seconds"]) in (int, float) and 0 <= row["elapsed_seconds"] < 300
             and row["completion_observed_within_original_phase_and_total_deadlines"] is True,
             "safe_phase_counts_and_original_budgets")
        phases.append(dict(row))
    out = {"status": report.get("status"), "phases": phases}
    if report.get("status") == "passed":
        need([r["phase"] for r in phases] == ["capture", "backup", "restore-verify"], "three_phases_complete_in_order")
        counts = report["counts"]
        need(set(counts) == {"configured_agents", "captured_database_entries", "logical_snapshot_bytes", "recovery"}
             and counts["configured_agents"] == 5 and counts["captured_database_entries"] == 9
             and type(counts["logical_snapshot_bytes"]) is int and 0 <= counts["logical_snapshot_bytes"] <= 4227858432,
             "complete_current_database_denominator")
        recovery = counts["recovery"]
        need(set(recovery) == {"nonempty_databases", "auth_stores", "absent_families", "all_declared_files", "plaintext_bytes"}
             and all(type(value) is int and value >= 0 for value in recovery.values())
             and recovery["nonempty_databases"] <= 9 and recovery["absent_families"] <= 9
             and recovery["auth_stores"] <= 5, "safe_complete_recovery_counts")
        out["counts"] = counts
    else:
        need(report.get("status") == "failed", "workflow_status")
        for key in ("error", "failed_phase", "failure_receipt_publication_error"):
            if key in report:
                value = report[key]
                allowed = {"admission", "capture", "backup", "restore-verify"} if key == "failed_phase" else CORE_ERROR_CODES | {
                    "Interrupted", "OperationalError", "DatabaseError", "IntegrityError", "InvalidToken", "TimeoutError",
                    "OSError", "FileNotFoundError", "PermissionError", "ValueError", "TypeError", "KeyError", "IndexError", "RuntimeError",
                }
                out[key] = value if isinstance(value, str) and value in allowed else "private_failure"
        out["partial_owned_directories_retained"] = True
    return out


def invoke_workflow(plan, *, core=None):
    global WORKFLOW_WINDOW, ACTIVE_END
    module = CORE if core is None else core
    need(not FAILURE_CLEANUP and not FIRED and not INTERRUPTED and time.monotonic() < WORK_END,
         "admission_consumed_original_work_budget")
    PUBLIC["workflow_invoked"] = True
    ACTIVE_END = WORK_END
    WORKFLOW_WINDOW = True
    try:
        report = module.run_workflow(plan, start=ENTRY, arm=arm_workflow)
    finally:
        WORKFLOW_WINDOW = False
    safe = safe_workflow_projection(report)
    PUBLIC["workflow"] = safe
    PRIVATE["qualified_core_public_result"] = safe
    need(safe["status"] == "passed" and not FAILURE_CLEANUP and not FIRED and not INTERRUPTED
         and time.monotonic() < WORK_END, "original_attempt_did_not_complete_successfully")
    # The three phases have finished under their own original limits. Only
    # the remaining part of the same outer work deadline may fund postflight.
    arm_workflow(WORK_END)
    return safe


def postflight(artifacts):
    verify_directories()
    for row in READS:
        _, ident = read_file(row["path"], row["maximum"], private=row["private"], pin=row["pin"])
        need(ident == row["identity"], "bound_input_identity_changed")
    for path, pin, ident in artifacts:
        need(hash_artifact(path, pin) == ident, "original_artifact_changed")
    need(not AUDIT_DENIALS, "forbidden_effect_attempted")
    check(WORK_END)


def verify_attempt_roots_absent(paths):
    need(set(paths) == {"capture", "archive", "key", "restore"}, "four_unused_attempt_roles")
    observed = {}
    for role, path in paths.items():
        check(WORK_END)
        try:
            path.lstat()
        except FileNotFoundError:
            observed[role] = True
        else:
            raise Refused("unused_attempt_root_must_be_absent")
    PUBLIC["unused_data_roots_observed_absent_before_capture"] = observed


def finish_original_custody_and_directories():
    complete = True
    try:
        if OWNER is not None:
            OWNER.finish()
            receipt = OWNER.receipt()
            PRIVATE["native_volume_process_custody"] = receipt
            PUBLIC["owned_native_metadata_processes"] = safe_custody(receipt)
            need(receipt["finished"] is True and receipt["passed_process_custody"] is True
                 and receipt["failed"] is False, "final_original_process_custody")
    except BaseException as error:
        record_failure(error, "process_custody", cleanup=True)
        complete = False
    # An owner-body failure does not suppress independent directory evidence.
    try:
        verify_directories()
        PUBLIC["original_directory_paths_and_handles_preserved"] = True
    except BaseException as error:
        PUBLIC["original_directory_paths_and_handles_preserved"] = False
        record_failure(error, "directory_identity", cleanup=True)
        complete = False
    return complete


def run(inputs, controller_pin):
    global ACTIVE_END, PHASE
    PHASE = "runtime_and_public_admission"
    need(inputs["schema"] == "heptabao.current-sqlite-outer-fixed-inputs.v1" and inputs["stage_ready"] is True,
         "actual_current_plan_stage_required")
    need(inputs["budgets"] == {"runtime": 900, "work": 840, "cleanup": 60, "admission_within_work": 60,
                                "capture": 300, "backup": 300, "restore_verify": 300}, "fixed_one_attempt_budget")
    read_file(Path(__file__).resolve(strict=True), 256 * 1024, pin=controller_pin, remember=True)
    verify_installed_runtime(inputs)
    test_source = load_core_and_custody(inputs)
    values = load_public_gates(inputs, test_source)
    preserve_prior_failed_attempt(inputs, values)
    need(inputs["known_ci"]["run_id"] == 42229582001
         and inputs["known_ci"]["merge_job_id"] == 127931720502
         and inputs["known_ci"]["head_job_id"] == 127931720823
         and inputs["known_ci"]["product_tree"] == PRODUCT_TREE
         and inputs["known_ci"]["qualification_resolved_by_data_protection"] is False,
         "known_product_ci_boundary_required")
    PUBLIC["known_product_ci"] = inputs["known_ci"]
    artifacts = []
    for row in values["mac107-result.public.json"]["artifacts"].values():
        path = Path(row["path"])
        need(path.parent == ROOT / "build-test-4bde9-r1/artifacts", "exact_bound_artifact_parent")
        pin = {"bytes": row["bytes"], "sha256": row["sha256"]}
        artifacts.append((path, pin, hash_artifact(path, pin)))
    PHASE = "current_private_plan_admission"
    plan, binding, paths = load_private_plan(inputs, values)
    verify_volumes(binding)
    check(PREFLIGHT_END)
    PUBLIC["admission_seconds_from_original_entry"] = time.monotonic() - ENTRY
    PUBLIC["remaining_work_seconds_at_capture_entry"] = WORK_END - time.monotonic()
    verify_attempt_roots_absent(paths)
    PHASE = "capture_backup_restore"
    report = invoke_workflow(plan)
    PRIVATE["qualified_core_public_result"] = report
    PUBLIC["workflow"] = report
    PHASE = "workflow_closeout_binding"
    # Bind the actual generation observed at this successful workflow's
    # closeout. This is not a claim about inode history before this observation.
    check(WORK_END)
    actual_roots = {role: hold_directory(path)["pin"] for role, path in paths.items()}
    PRIVATE["actual_attempt_root_identities_at_workflow_closeout"] = actual_roots
    PUBLIC["actual_attempt_roots_at_workflow_closeout"] = [
        {"role": role, "identity": {key: pin[key] for key in ("dev", "inode", "uid", "gid", "mode")}}
        for role, pin in actual_roots.items()
    ]
    PUBLIC["actual_root_identity_observation_scope"] = "original_workflow_successful_closeout_not_earlier_inode_history"
    closure_files = (
        ("capture_manifest", paths["capture"] / "capture.private.json", CORE.MAX_META),
        ("capture_binding", paths["capture"] / "capture-binding.private.json", CORE.MAX_META),
        ("archive_manifest", paths["archive"] / "manifest.fernet", CORE.MAX_META * 2),
        ("recovery_key", paths["key"] / "recovery.key", 44),
        ("restore_capture_manifest", paths["restore"] / "capture.private.json", CORE.MAX_META),
    )
    PRIVATE["completed_file_pins_at_workflow_closeout"] = {}
    for role, path, maximum in closure_files:
        raw, ident = read_file(path, maximum, remember=True)
        need(role != "recovery_key" or len(raw) == 44, "original_recovery_key_length")
        PRIVATE["completed_file_pins_at_workflow_closeout"][role] = {
            "path": str(path), "identity": ident, "sha256": hashlib.sha256(raw).hexdigest(),
        }
    PUBLIC["completed_private_closure_file_count"] = len(closure_files)
    # Only the declared safe per-phase receipts are re-opened here; no source
    # credential or private database/archive manifest is exported.
    for role, phase in (("capture", "capture"), ("archive", "backup"), ("restore", "restore-verify")):
        raw, _ = read_file(paths[role] / "result.public.json", 65536)
        result = json.loads(raw, object_pairs_hook=unique)
        need(result["status"] == "passed" and result["phase"] == phase
             and result["credential_values_or_content_fingerprints_published"] is False,
             "original_phase_safe_receipt_complete")
    PHASE = "postflight"
    postflight(artifacts)
    PUBLIC.update(status="passed", capture_backup_and_fresh_restore_completed=True,
                  source_code_unchanged=True, all_bound_inputs_and_artifacts_unchanged=True,
                  original_per_database_transaction_scope_preserved=True,
                  original_archive_and_key_parent_identity_dependency_preserved=True)


def main(argv=None):
    global FINISHING, CONTROL, ACTIVE_END
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs-sha256", required=True)
    parser.add_argument("--controller-sha256", required=True)
    args = parser.parse_args(argv)
    signals = (signal.SIGALRM, signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    old_handlers = {number: signal.getsignal(number) for number in signals}
    old_timer = signal.getitimer(signal.ITIMER_REAL)
    old_umask = os.umask(0o077)
    exit_code, timer_owned = 1, False
    try:
        need(old_timer == (0.0, 0.0), "foreign_timer_refused")
        need(all(re.fullmatch(r"[0-9a-f]{64}", value) for value in (args.inputs_sha256, args.controller_sha256)),
             "exact_public_input_pins")
        for number in signals:
            signal.signal(number, interrupt)
        signal.setitimer(signal.ITIMER_REAL, max(0.000001, PREFLIGHT_END - time.monotonic()))
        timer_owned = True
        hold_directory(INPUT)
        create_output()
        sys.addaudithook(audit)
        with private_stdio():
            raw, _ = read_file(INPUT / "fixed-inputs.public.json", 256 * 1024, remember=True)
            need(hashlib.sha256(raw).hexdigest() == args.inputs_sha256, "fixed_public_inputs_sha256")
            inputs = json.loads(raw, object_pairs_hook=unique)
            controller_path = Path(__file__).resolve(strict=True)
            controller_pin = {"bytes": controller_path.stat().st_size, "sha256": args.controller_sha256}
            run(inputs, controller_pin)
            check(WORK_END)
        exit_code = 0
    except BaseException as error:
        # No exception payload, private filename, SQL or source hash is emitted.
        record_failure(error, PHASE)
        exit_code = 1
    finally:
        FINISHING = True
        if not finish_original_custody_and_directories():
            exit_code = 1
        elapsed = time.monotonic() - ENTRY
        if FIRED or INTERRUPTED or elapsed >= 840 or FAILURE_CLEANUP:
            record_failure(Refused("original_work_deadline_or_failed_phase"), "final_work_deadline", cleanup=True)
            exit_code = 1
        PUBLIC.update(deadline_fired=FIRED, interrupted=INTERRUPTED,
                      elapsed_observation_before_receipt_publication_seconds=elapsed,
                      elapsed_observation_before_receipt_publication=True,
                      partial_owned_outputs_retained=exit_code != 0,
                      forbidden_effect_attempt_count=len(AUDIT_DENIALS))
        # All computation and validation is finished. The original remaining
        # Runtime ceiling is reserved solely for closure and durable receipts.
        if timer_owned:
            signal.setitimer(signal.ITIMER_REAL, 0)
        PRIVATE["public_result_before_publication"] = dict(PUBLIC)
        if CONTROL is not None:
            try:
                private_identity = control_write("outer.private.json", encoded(PRIVATE))
                PUBLIC["private_closure_file_identity"] = private_identity
                PUBLIC["private_closure_binding_scope"] = "fsynced_original_workflow_closeout_private_record"
                if FIRED or INTERRUPTED:
                    record_failure(Refused("interrupted_during_private_publication"), "private_publication", cleanup=True)
                    exit_code = 1
                PUBLIC["owned_directory_handle_count"] = len(DIRECTORIES)
                # Output FD is included and is closed after its fsynced receipt.
                PUBLIC["directory_handle_close_is_runtime_terminal_dependent"] = True
                control_write("result.public.json", encoded(PUBLIC))
            except BaseException as error:
                record_failure(error, "receipt_publication", cleanup=True)
                exit_code = 1
        closed = 0
        for row in reversed(DIRECTORIES):
            try:
                os.close(row["fd"])
                closed += 1
            except OSError as error:
                record_failure(error, "directory_close", cleanup=True)
                exit_code = 1
        CONTROL = None
        PUBLIC["owned_directory_handles_closed"] = closed
        PUBLIC["all_owned_directory_handles_retired"] = closed == len(DIRECTORIES)
        for number, handler in old_handlers.items():
            signal.signal(number, handler)
        if timer_owned:
            signal.setitimer(signal.ITIMER_REAL, *old_timer)
        os.umask(old_umask)
        if FIRED or INTERRUPTED or time.monotonic() >= TOTAL_END:
            record_failure(Refused("original_runtime_or_final_interrupt"), "final_runtime_deadline", cleanup=True)
            exit_code = 1
        if exit_code:
            PUBLIC["status"] = "failed"
        print(json.dumps(PUBLIC, sort_keys=True, separators=(",", ":")), flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
