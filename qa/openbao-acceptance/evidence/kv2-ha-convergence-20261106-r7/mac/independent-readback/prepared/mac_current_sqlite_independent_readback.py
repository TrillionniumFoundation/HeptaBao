#!/usr/bin/env python3
"""One independent read-only whole-data verification after a completed workflow.

No live source, provider, SDK, child process, capture, backup or restore creation.
The new 900-second Runtime envelope does not extend the original workflow.
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
import re
import signal
import sqlite3
import stat
import sys
import zipfile

sys.dont_write_bytecode = True
ROOT = Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1")
INPUT = ROOT / "control/current-sqlite-independent-readback-inputs-r1"
OUT = ROOT / "control/current-sqlite-independent-readback-execution-r1"
ORIGINAL_INPUT = ROOT / "control/current-sqlite-data-protection-inputs-r2"
ORIGINAL_OUT = ROOT / "control/current-sqlite-data-protection-execution-r2"
PLAN_STAGE = ROOT / "control/mac-current-kv2-plan-stage-r1"
ENVIRONMENT = ROOT / "control/formal-kv2-python-env-50-0-2-r3"
ENV_INPUT = ROOT / "control/formal-kv2-python-env-inputs-r3"
LIVE_SOURCE = Path("/Users/qianqi/.openclaw")
UID = 501
MIB = 1024 ** 2
CODE_SHA = "9e27369657667dc3360ae276bb62e2d1ad0c6f55f07290d91304d7d396d72972"
ORIGINAL_OUTER_SHA = "550c7b4017dafcb19b7ffb85f2fab40f2270c649b8549cdde1c7329cd5a85415"
WORK_END = ENTRY + 840
TOTAL_END = ENTRY + 900
PREFLIGHT_END = ENTRY + 60
ACTIVE_END = PREFLIGHT_END
FIRED = False
INTERRUPTED = False
FINISHING = False
FS_PROTECTED = False
CORE = None
CONTROL = None
DIRECTORIES = []
READS = []
DATA_FILE_OBSERVATIONS = {}
SQLITE_ALLOWLIST = set()
SQLITE_OPEN_IDENTITIES = []
SQLITE_CONNECTIONS_OPENED = 0
SQLITE_CONNECTIONS_CLOSED = 0
AUDIT_DENIALS = []
CORE_ERROR_CODES = set()
PHASES = []
CHECKS = []
PRIVATE = {"schema": "heptabao.independent-current-sqlite-readback.private.v1"}
PUBLIC = {
    "schema": "heptabao.independent-current-sqlite-readback.public.v1",
    "status": "failed",
    "verification_complete": False,
    "independent_attempt_not_original_workflow_extension": True,
    "new_runtime_seconds": 900,
    "new_work_seconds": 840,
    "new_cleanup_reserve_seconds": 60,
    "admission_cap_seconds": 60,
    "archive_authentication_cap_seconds": 300,
    "dual_copy_hash_and_cold_sqlite_cap_seconds": 300,
    "deadline_renewed": False,
    "automatic_retry": False,
    "source_live_database_opened": False,
    "source_live_configuration_opened": False,
    "source_data_written": False,
    "existing_capture_archive_key_restore_modified": False,
    "new_capture_backup_or_restore_created": False,
    "new_child_processes_spawned": 0,
    "network_provider_or_j3160_called": False,
    "product_sdk_or_service_executed": False,
    "credential_values_or_content_fingerprints_published": False,
    "only_declared_captured_generation": True,
    "candidate_workspace_independently_verified": False,
    "application_boot_or_client_routing_qualified": False,
    "restored_configuration_paths_rewritten": False,
    "all_known_writers_fenced": False,
    "cross_database_atomic_snapshot_qualified": False,
    "live_source_freshness_qualified": False,
    "current_credential_validity_qualified": False,
    "full_host_secret_source_inventory_qualified": False,
    "source_device_loss_recovery_qualified": False,
    "known_product_ci_failures_resolved_by_this_work": False,
    "formal_kv2_qualified": False,
    "ha_qualified": False,
    "authbus_qualified": False,
    "traffic_cutover_performed": False,
    "old_assets_removed": False,
    "durable_completion_authority": "separate_original_independent_runtime_terminal_and_final_stdout_with_900_second_cap",
}


class Refused(Exception):
    pass


class Interrupted(BaseException):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def unique(pairs):
    out = {}
    for key, value in pairs:
        need(key not in out, "duplicate_json_key")
        out[key] = value
    return out


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode()


def captured_encoded(value):
    # Byte-for-byte serialization semantics of the pinned capture9e helper.
    # This is only for comparing already captured schema/auth-row digests.
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False,
                      default=lambda x: {"blobHex": x.hex()} if isinstance(x, bytes) else None).encode()


def path_present(path):
    # Permission/observation errors must never become a qualified absence.
    try:
        Path(path).lstat()
    except FileNotFoundError:
        return False
    return True


def check(end=None):
    limit = ACTIVE_END if end is None else min(end, ACTIVE_END)
    need(not FIRED and not INTERRUPTED and time.monotonic() < limit, "original_deadline_or_interrupt")


def interrupt(signum, frame):
    global FIRED, INTERRUPTED
    if signum == signal.SIGALRM:
        FIRED = True
    else:
        INTERRUPTED = True
    if not FINISHING and not FS_PROTECTED:
        raise Interrupted()


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
    """Only two fixed read-only volume roots may use the original stage mode."""
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
        need(observed == row["pin"] == fd_directory(row["path"], row["fd"]),
             "original_directory_identity_changed")


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

def safe_error(error):
    if isinstance(error, Refused):
        value = str(error)
        return value if re.fullmatch(r"[A-Za-z0-9_]{1,100}", value) else "private_failure"
    if CORE is not None and isinstance(error, CORE.Refused):
        value = str(error)
        return value if value in CORE_ERROR_CODES else "private_core_failure"
    return type(error).__name__ if type(error).__name__ in {
        "Interrupted", "OperationalError", "DatabaseError", "IntegrityError", "InvalidToken",
        "TimeoutError", "OSError", "FileNotFoundError", "PermissionError", "ValueError",
        "TypeError", "KeyError", "IndexError", "RuntimeError",
    } else "private_failure"


def audit_readback(event, args):
    if event.startswith("socket.") or event in (
        "subprocess.Popen", "os.system", "pty.spawn", "os.fork", "os.forkpty",
        "os.posix_spawn", "os.exec", "os.execve",
    ):
        AUDIT_DENIALS.append("network_or_process")
        raise Refused("network_or_child_process_forbidden")
    if event in ("os.mkdir", "os.rmdir", "os.remove", "os.rename", "os.link",
                 "os.symlink", "os.chmod", "os.chown", "os.truncate", "os.utime",
                 "os.setxattr", "os.removexattr"):
        AUDIT_DENIALS.append("mutation")
        raise Refused("existing_data_mutation_forbidden")
    if event == "sqlite3.connect":
        if not (args and type(args[0]) is str and args[0] in SQLITE_ALLOWLIST):
            AUDIT_DENIALS.append("unapproved_sqlite_open")
            raise Refused("sqlite_only_explicit_existing_cold_copy")
    if event == "open":
        path, mode, flags = args
        if isinstance(path, (str, bytes)):
            text = os.fsdecode(path)
            current = Path(text)
            absolute = current if current.is_absolute() else Path.cwd() / current
            if absolute == LIVE_SOURCE or LIVE_SOURCE in absolute.parents:
                AUDIT_DENIALS.append("live_source_open")
                raise Refused("live_source_open_forbidden")
            resolved = absolute.resolve(strict=False)
            if resolved == LIVE_SOURCE or LIVE_SOURCE in resolved.parents:
                AUDIT_DENIALS.append("live_source_alias_open")
                raise Refused("live_source_alias_open_forbidden")
            write = bool((flags or 0) & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            write = write or (isinstance(mode, str) and any(c in mode for c in ("w", "a", "+", "x")))
            if write:
                if not (CONTROL is not None and not current.is_absolute()
                        and text in {"workflow.stdout.private", "workflow.stderr.private",
                                     "verification.private.json", "result.public.json"}):
                    AUDIT_DENIALS.append("unapproved_file_write")
                    raise Refused("write_only_fixed_verification_receipt")


def arm(end):
    global ACTIVE_END
    need(type(end) in (int, float) and end <= WORK_END and not FIRED and not INTERRUPTED,
         "independent_deadline_cannot_extend_or_restart")
    need(time.monotonic() < end, "independent_original_deadline_expired")
    ACTIVE_END = end
    signal.setitimer(signal.ITIMER_REAL, end - time.monotonic())


def phase(name, cap, function):
    check(WORK_END)
    begin = time.monotonic()
    end = min(WORK_END, begin + cap)
    arm(end)
    value = function(end)
    check(end)
    PHASES.append({"phase": name, "status": "passed", "cap_seconds": cap,
                   "elapsed_seconds": time.monotonic() - begin,
                   "completed_within_original_phase_and_new_attempt_work_deadline": True})
    return value


def checked(name, value):
    need(type(value) is bool, "fixed_check_boolean")
    CHECKS.append({"check": name, "passed": value})
    need(value, name)


def load_readonly_core(inputs):
    global CORE
    pin = inputs["capture_source"]
    need(pin == {"bytes": 57280, "sha256": CODE_SHA}, "fixed_qualified_readonly_source")
    raw, _ = read_file(ENV_INPUT / "mac_current_sqlite_capture.py", 128 * 1024,
                       pin=pin, remember=True)
    for node in ast.walk(ast.parse(raw)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            index = 1 if node.func.id == "need" else 0 if node.func.id == "Refused" else None
            if index is not None and len(node.args) > index and isinstance(node.args[index], ast.Constant):
                value = node.args[index].value
                if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_]{1,100}", value):
                    CORE_ERROR_CODES.add(value)
    spec = importlib.util.spec_from_file_location("qualified_readonly_capture_helpers",
                                                ENV_INPUT / "mac_current_sqlite_capture.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    need(module.MAX_WORKFLOW_SECONDS == 900 and module.MAX_SECONDS == 300
         and module.CHUNK == 4 * MIB and module.MAX_FILES == 80, "unchanged_core_readonly_bounds")
    CORE = module


def validate_producer_success(result, final, terminal, expected_job):
    successful_terminal(terminal, expected_job)
    need(expected_job != "1a1b1f76336-fc05-7bc7", "failed_r1_is_never_a_recovery_generation")
    need(result["schema"] == final["schema"] == "heptabao.current-sqlite-data-protection-outer.v1"
         and result["status"] == final["status"] == "passed"
         and result["workflow_invoked"] is True and result["capture_backup_and_fresh_restore_completed"] is True
         and result["source_code_unchanged"] is True and result["all_bound_inputs_and_artifacts_unchanged"] is True
         and result["fresh_current_plan_and_independent_native_file_pins_bound"] is True
         and result["read_only_volume_roots_bound_to_original_stage_identity"] is True
         and result["prior_failed_attempt"]["job_id"] == "1a1b1f76336-fc05-7bc7"
         and result["prior_failed_attempt"]["original_status"] == "failed"
         and result["prior_failed_attempt"]["reclassified_as_success"] is False
         and "primary_failure" not in result and not result.get("cleanup_failures")
         and result["completed_private_closure_file_count"] == 5
         and result["private_closure_binding_scope"] == "fsynced_original_workflow_closeout_private_record",
         "original_workflow_success_and_private_anchor_required")
    final_only = {"owned_directory_handles_closed", "all_owned_directory_handles_retired"}
    need(set(final) == set(result) | final_only
         and all(final[key] == value for key, value in result.items())
         and final["all_owned_directory_handles_retired"] is True
         and final["owned_directory_handles_closed"] == result["owned_directory_handle_count"]
         and type(result["owned_directory_handle_count"]) is int and result["owned_directory_handle_count"] > 0,
         "original_result_final_stdout_and_final_handle_closure")
    need(result["runtime_cap_seconds"] == 900 and result["work_cap_seconds_from_original_entry"] == 840
         and result["cleanup_and_receipt_reserve_seconds"] == 60
         and result["phase_caps_seconds"] == {"capture": 300, "backup": 300, "restore_verify": 300}
         and result["deadline_renewed"] is False and result["deadline_fired"] is False
         and result["interrupted"] is False and result["forbidden_effect_attempt_count"] == 0,
         "original_workflow_budget_and_effect_boundary")
    need(all(result[key] is False for key in (
        "formal_kv2_qualified", "ha_qualified", "authbus_qualified", "all_known_writers_fenced",
        "cross_database_atomic_snapshot_qualified", "current_credential_validity_qualified",
        "source_device_loss_recovery_qualified", "all_clients_and_backups_migrated",
        "product_or_sdk_executed", "provider_or_j3160_called", "production_service_started",
        "service_or_client_configuration_changed", "traffic_cutover_performed", "old_assets_removed",
        "business_source_values_or_fingerprints_published", "private_plan_or_config_hashes_published",
    )), "original_data_protection_did_not_grant_production")
    c = result["owned_native_metadata_processes"]
    need(c["original_count"] == len(c["children"]) == 2 and c["finished"] is True
         and c["passed_process_custody"] is True and c["failed"] is False and c["interrupted"] is False,
         "original_two_metadata_children_closed")
    for i, row in enumerate(c["children"]):
        birth = row["birth"]
        need(row["index"] == i and row["exec_admitted"] is True and row["returncode"] == 0
             and row["original_wait_completed"] is True and row["original_wait_count"] == 1
             and row["no_live_members_before_reap"] is True and row["gap_count"] == 0
             and birth["pid"] == row["pid"] == birth["pgid"] == birth["sid"]
             and birth["uid"] == UID and birth["ppid"] > 0,
             "original_child_full_retirement")
        for name in ("members_at_leader_exit", "members_before_original_reap"):
            need(isinstance(row[name], list)
                 and all(type(member["state"]) is str and member["state"].startswith("Z")
                         for member in row[name]), "original_child_no_live_member_evidence")
    need(result["workflow"]["status"] == "passed"
         and [row["phase"] for row in result["workflow"]["phases"]] == ["capture", "backup", "restore-verify"],
         "original_three_phases_passed_in_order")


def validated_core_workflow_projection(value):
    """Validate the full core receipt before deriving the outer's safe subset."""
    false_fields = {
        "all_clients_and_backups_migrated", "all_known_writers_fenced", "automatic_retry",
        "credential_values_or_content_fingerprints_published", "cross_database_atomic_snapshot_qualified",
        "current_credential_validity_qualified", "formal_kv2_qualified", "full_host_inventory_qualified",
        "old_assets_removed", "provider_or_sdk_called", "resume_after_failed_phase_supported",
        "service_or_client_configuration_changed", "source_capture_or_service_cutover_qualified",
        "source_data_write_invoked", "source_freshness_after_capture_qualified",
        "source_native_sqlite_sidecar_writes_excluded", "traffic_cutover_performed",
    }
    need(set(value) == false_fields | {
        "schema", "phase", "status", "error", "counts", "phases", "budget_origin",
        "cleanup_and_receipt_reserve_seconds", "controller_work_cap_seconds",
        "durable_completion_authority", "elapsed_observation_before_receipt_publication_seconds",
        "only_declared_captured_generation", "total_runtime_cap_seconds",
    }, "complete_original_core_workflow_receipt_fields")
    need(value["schema"] == "heptabao.mac-current-sqlite-recovery-workflow.public.v1"
         and value["phase"] == "current-source-recovery-workflow" and value["status"] == "passed"
         and value["error"] is None and value["only_declared_captured_generation"] is True
         and all(value[name] is False for name in false_fields),
         "complete_original_core_workflow_scope_and_status")
    need(value["total_runtime_cap_seconds"] == 900 and value["controller_work_cap_seconds"] == 840
         and value["cleanup_and_receipt_reserve_seconds"] == 60
         and value["budget_origin"] == "new_workflow_definition_not_previous_whole_capture_budget"
         and value["durable_completion_authority"] == "separate_original_runtime_terminal"
         and type(value["elapsed_observation_before_receipt_publication_seconds"]) in (int, float)
         and 0 <= value["elapsed_observation_before_receipt_publication_seconds"] < 840,
         "complete_original_core_workflow_budgets")
    need(isinstance(value["phases"], list)
         and [row["phase"] for row in value["phases"]] == ["capture", "backup", "restore-verify"],
         "complete_original_core_phase_order")
    for row in value["phases"]:
        need(set(row) == {"phase", "status", "phase_cap_seconds", "elapsed_seconds",
                          "completion_observed_within_original_phase_and_total_deadlines"}
             and row["status"] == "passed" and row["phase_cap_seconds"] == 300
             and row["completion_observed_within_original_phase_and_total_deadlines"] is True
             and type(row["elapsed_seconds"]) in (int, float) and 0 <= row["elapsed_seconds"] < 300,
             "complete_original_core_phase_budgets")
    counts = value["counts"]
    need(set(counts) == {"captured_database_entries", "configured_agents", "logical_snapshot_bytes", "recovery"}
         and all(type(counts[name]) is int and counts[name] >= 0
                 for name in ("captured_database_entries", "configured_agents", "logical_snapshot_bytes"))
         and set(counts["recovery"]) == {"absent_families", "all_declared_files", "auth_stores",
                                        "nonempty_databases", "plaintext_bytes"}
         and all(type(number) is int and number >= 0 for number in counts["recovery"].values()),
         "complete_original_core_count_fields")
    return {name: value[name] for name in ("counts", "phases", "status")}


def load_public_admission(inputs):
    need(inputs["ready"] is True and isinstance(inputs["original_workflow_job_id"], str),
         "real_successful_workflow_inputs_not_ready")
    need(inputs["budgets"] == {"runtime": 900, "work": 840, "cleanup": 60,
                               "admission": 60, "archive": 300, "dual_copy": 300},
         "new_independent_attempt_fixed_budgets")
    names = {"original-workflow-result.public.json", "original-workflow-runtime.stdout.original",
             "original-workflow-runtime-terminal.original.json",
             "plan-stage-result.public.json", "plan-stage-runtime-terminal.original.json",
             "observed-core-workflow-result.public.json"}
    need(set(inputs["public_files"]) == names, "exact_public_original_gate_files")
    values, originals = {}, {}
    for name, pin in inputs["public_files"].items():
        raw, _ = read_file(INPUT / name, 2 * MIB, pin=pin, remember=True)
        originals[name] = raw
        values[name] = json.loads(raw, object_pairs_hook=unique)
    terminal = values["original-workflow-runtime-terminal.original.json"]
    need(terminal["log_bytes"]["stdout"]["stored"] ==
         len(originals["original-workflow-runtime.stdout.original"]), "original_final_stdout_length_binding")
    validate_producer_success(values["original-workflow-result.public.json"],
                              values["original-workflow-runtime.stdout.original"], terminal,
                              inputs["original_workflow_job_id"])
    observed = inputs["core_workflow_receipt_observation"]
    need(set(observed) == {"scope", "asserted_as_producer_closeout_pin", "bytes", "sha256", "version"}
         and observed["scope"] == "independent_native_read_after_producer_terminal"
         and observed["asserted_as_producer_closeout_pin"] is False
         and {key: observed[key] for key in ("bytes", "sha256")}
             == inputs["public_files"]["observed-core-workflow-result.public.json"]
         and type(observed["version"]) is str and re.fullmatch(r"[0-9]+(?::[0-9]+){4}", observed["version"]),
         "new_complete_core_receipt_observation_not_historical_closeout_pin")
    need(validated_core_workflow_projection(values["observed-core-workflow-result.public.json"])
         == values["original-workflow-result.public.json"]["workflow"],
         "complete_core_workflow_projects_exactly_to_original_outer")
    values["observed_core_workflow_original_bytes"] = originals["observed-core-workflow-result.public.json"]
    stage = values["plan-stage-result.public.json"]
    successful_terminal(values["plan-stage-runtime-terminal.original.json"], "1a1b1dca238-fc05-7b30")
    need(stage["status"] == "private_plan_staged_workflow_not_executed"
         and stage["historical_private_unchanged_since_admission_proven"] is False
         and stage["historical_private_file_opened_or_used_for_current_qualification"] is False
         and stage["current_private_baseline_reconstructed_from_live_scope"] is True
         and stage["private_plan_original_file_identities_preserved"] is True
         and stage["workflow_executed"] is False, "actual_fresh_stage_not_old_private_assumption")
    actual, _ = read_file(ORIGINAL_OUT / "result.public.json", 2 * MIB,
                         pin=inputs["public_files"]["original-workflow-result.public.json"], remember=True)
    need(actual == originals["original-workflow-result.public.json"], "original_result_at_original_location")
    actual, _ = read_file(PLAN_STAGE / "result.public.json", 65536,
                         pin=inputs["public_files"]["plan-stage-result.public.json"], remember=True)
    need(actual == originals["plan-stage-result.public.json"], "stage_result_at_original_location")
    read_file(ORIGINAL_INPUT / "mac_current_sqlite_data_protection_outer.py", 256 * 1024,
              pin=inputs["original_outer_source"], remember=True)
    need(inputs["original_outer_source"]["sha256"] == ORIGINAL_OUTER_SHA,
         "admitted_original_outer_source")
    read_file(ORIGINAL_INPUT / "fixed-inputs.public.json", 256 * 1024,
              pin=inputs["original_outer_inputs"], remember=True)
    PUBLIC["original_successful_workflow_job_id"] = inputs["original_workflow_job_id"]
    checked("original_complete_workflow_and_fresh_stage_bound", True)
    return values


def validate_native_pin(raw, ident, pin, published):
    need(set(pin) == {"bytes", "sha256", "version", "uid", "mode", "nlink"},
         "private_native_pin_shape")
    need(len(raw) == pin["bytes"] and hashlib.sha256(raw).hexdigest() == pin["sha256"]
         and version(ident) == pin["version"] and ident == published
         and pin["uid"] == ident["uid"] == UID and pin["mode"] == ident["mode"] == 0o600
         and pin["nlink"] == ident["nlink"] == 1, "original_private_file_native_identity_and_hash")


def load_completed_generation(inputs, values):
    result = values["original-workflow-result.public.json"]
    stage = values["plan-stage-result.public.json"]
    raw, _ = read_file(INPUT / "original-outer-private-native-pin.private.json", 65536, remember=True)
    native = json.loads(raw, object_pairs_hook=unique)
    need(set(native) == {"schema", "original_workflow_job_id", "public_result_sha256", "terminal_sha256", "file"}
         and native["schema"] == "heptabao.independent-original-workflow-private-pin.v1"
         and native["original_workflow_job_id"] == inputs["original_workflow_job_id"]
         and native["public_result_sha256"] == inputs["public_files"]["original-workflow-result.public.json"]["sha256"]
         and native["terminal_sha256"] == inputs["public_files"]["original-workflow-runtime-terminal.original.json"]["sha256"],
         "native_original_private_pin_is_bound_to_original_job")
    outer_raw, outer_ident = read_file(ORIGINAL_OUT / "outer.private.json", 16 * MIB, remember=True)
    validate_native_pin(outer_raw, outer_ident, native["file"], result["private_closure_file_identity"])
    outer = json.loads(outer_raw, object_pairs_hook=unique)
    need(outer["schema"] == "heptabao.current-sqlite-outer-private.v1", "original_private_closure_schema")
    publication_only = {"private_closure_file_identity", "private_closure_binding_scope",
                        "owned_directory_handle_count", "directory_handle_close_is_runtime_terminal_dependent"}
    need(set(result) == set(outer["public_result_before_publication"]) | publication_only
         and all(result[k] == v for k, v in outer["public_result_before_publication"].items()),
         "original_private_closure_matches_original_public_receipt")
    plan_pins = outer["independent_private_plan_pins"]
    need(plan_pins["schema"] == "heptabao.independent-current-private-plan-file-pins.v1"
         and plan_pins["stage_job_id"] == "1a1b1dca238-fc05-7b30"
         and plan_pins["stage_public_result_sha256"] == inputs["public_files"]["plan-stage-result.public.json"]["sha256"]
         and plan_pins["stage_terminal_sha256"] == inputs["public_files"]["plan-stage-runtime-terminal.original.json"]["sha256"],
         "original_stage_private_pin_chain")
    published = {row["role"]: row["identity"] for row in stage["private_output_file_identities"]}
    need(set(published) == set(plan_pins["files"]) == {"workflow_plan", "workflow_plan_binding"}
         and len(stage["private_output_file_identities"]) == 2, "exact_stage_private_file_denominator")
    loaded = {}
    for role, name in (("workflow_plan", "workflow-plan.private.json"),
                       ("workflow_plan_binding", "workflow-plan-binding.private.json")):
        data, ident = read_file(PLAN_STAGE / name, 512 * 1024, remember=True)
        validate_native_pin(data, ident, plan_pins["files"][role], published[role])
        loaded[role] = json.loads(data, object_pairs_hook=unique)
        if role == "workflow_plan":
            plan_raw, plan_ident = data, ident
    plan, binding = loaded["workflow_plan"], loaded["workflow_plan_binding"]
    need(plan == outer["workflow_plan"] and binding == outer["workflow_plan_binding"]
         and binding["plan_path"] == str(PLAN_STAGE / "workflow-plan.private.json")
         and binding["plan_sha256"] == hashlib.sha256(plan_raw).hexdigest()
         and binding["plan_bytes"] == len(plan_raw) and binding["plan_file_identity"] == plan_ident
         and binding["capture_code_sha256"] == CODE_SHA, "same_original_private_plan_generation")
    need(plan["schema"] == "heptabao.mac-current-sqlite-recovery-workflow.v1"
         and Path(plan["capture"]["source_root"]) == LIVE_SOURCE
         and binding["source_root_identity"]["path"] == str(LIVE_SOURCE)
         and plan["overall_budget_seconds"] == 900
         and all(plan[k]["budget_seconds"] == 300 for k in ("capture", "backup", "restore"))
         and plan["capture"]["maximum_database_bytes"] == 3087007744
         and plan["capture"]["maximum_total_bytes"] == 4227858432, "original_plan_boundaries")
    agents = plan["capture"]["agents"]
    need(isinstance(agents, list) and 0 < len(agents) <= 64
         and all(isinstance(a, str) and CORE.NAME.fullmatch(a) and a not in (".", "..") for a in agents)
         and len(set(agents)) == len(agents)
         and agents == binding["fresh_current_private_baseline"]["configured_agents"],
         "complete_actual_captured_agent_denominator")
    paths = {"capture": Path(plan["capture"]["capture_parent"]) / plan["capture"]["capture_name"],
             "archive": Path(plan["backup"]["archive_parent"]) / plan["backup"]["archive_name"],
             "key": Path(plan["backup"]["key_parent"]) / plan["backup"]["key_name"],
             "restore": Path(plan["restore"]["restore_parent"]) / plan["restore"]["restore_name"]}
    need(set(map(str, paths.values())) == set(binding["actual_workflow_attempt_roots"])
         and len(set(map(str, paths.values()))) == 4, "exact_original_four_attempt_paths")
    roots = outer["actual_attempt_root_identities_at_workflow_closeout"]
    public_roots = {r["role"]: r["identity"] for r in result["actual_attempt_roots_at_workflow_closeout"]}
    need(set(roots) == set(public_roots) == set(paths) and len(result["actual_attempt_roots_at_workflow_closeout"]) == 4,
         "original_four_root_identity_denominator")
    for role, path in paths.items():
        need(path.is_absolute() and path != LIVE_SOURCE and LIVE_SOURCE not in path.parents
             and roots[role]["path"] == str(path)
             and {k: roots[role][k] for k in ("dev", "inode", "uid", "gid", "mode")} == public_roots[role]
             and hold_directory(path)["pin"] == roots[role], "actual_original_generation_directory")
        need(hold_directory(path.parent)["pin"] == binding["parent_identities"][role],
             "original_parent_identity_preserved")
    volumes = binding["volume_identities"]
    need(set(volumes) == {"Data", "T5"}, "original_two_volume_denominator")
    for alias, mount in (("Data", "/System/Volumes/Data"), ("T5", "/Volumes/T5")):
        need(hold_volume_directory(alias, mount, volumes[alias]["directory"])["pin"]
             == volumes[alias]["directory"],
             "current_mount_object_same_as_original_workflow")
        observed = outer["actual_volume_observations"][alias]
        need(observed == volumes[alias]["selected_diskutil"] and observed["MountPoint"] == mount
             and type(observed["VolumeUUID"]) is str and bool(observed["VolumeUUID"])
             and type(observed["FilesystemType"]) is str and bool(observed["FilesystemType"])
             and type(observed["Internal"]) is bool and observed["Internal"] is (alias == "Data"),
             "original_successful_workflow_volume_observation_bound")
    need(roots["archive"]["dev"] == volumes["T5"]["directory"]["dev"]
         and roots["capture"]["dev"] == roots["key"]["dev"] == roots["restore"]["dev"] == volumes["Data"]["directory"]["dev"]
         and roots["archive"]["dev"] != roots["capture"]["dev"], "actual_archive_key_and_data_filesystem_boundary")
    closure = outer["completed_file_pins_at_workflow_closeout"]
    specs = {"capture_manifest": (paths["capture"] / "capture.private.json", CORE.MAX_META),
             "capture_binding": (paths["capture"] / "capture-binding.private.json", CORE.MAX_META),
             "archive_manifest": (paths["archive"] / "manifest.fernet", CORE.MAX_META * 2),
             "recovery_key": (paths["key"] / "recovery.key", 44),
             "restore_capture_manifest": (paths["restore"] / "capture.private.json", CORE.MAX_META)}
    need(set(closure) == set(specs), "five_original_completed_file_bindings")
    originals = {}
    for role, (path, maximum) in specs.items():
        pin = closure[role]
        need(set(pin) == {"path", "identity", "sha256"} and pin["path"] == str(path),
             "fixed_original_completion_file_role")
        data, ident = read_file(path, maximum, pin={"bytes": pin["identity"]["bytes"], "sha256": pin["sha256"]}, remember=True)
        need(ident == pin["identity"] and (role != "recovery_key" or len(data) == 44),
             "original_completed_file_identity")
        originals[role] = data
        DATA_FILE_OBSERVATIONS[str(path)] = ident
    cap_binding = json.loads(originals["capture_binding"], object_pairs_hook=unique)
    capture_sha = hashlib.sha256(originals["capture_manifest"]).hexdigest()
    need(set(cap_binding) == {"capture_sha256", "bytes"} and cap_binding["capture_sha256"] == capture_sha
         and cap_binding["bytes"] == len(originals["capture_manifest"])
         and originals["restore_capture_manifest"] == originals["capture_manifest"], "original_capture_and_restored_manifest_same_bytes")
    PRIVATE.update(original_outer_native_pin=native, original_outer_private_identity=outer_ident,
                   original_workflow_plan=plan, original_workflow_binding=binding,
                   actual_attempt_root_identities=roots, original_completed_file_pins=closure)
    PUBLIC["captured_agent_count"] = len(agents)
    PUBLIC["declared_database_family_count"] = len(agents) + 4
    PUBLIC["declared_safety_file_count"] = 7
    PUBLIC["original_successful_workflow_volume_uuid_binding_reused"] = True
    PUBLIC["current_two_fixed_volume_root_identities_verified"] = True
    PUBLIC["new_volume_uuid_query_performed"] = False
    checked("original_private_generation_roots_files_and_plan_bound", True)
    return {"plan": plan, "binding": binding, "paths": paths, "originals": originals,
            "capture_sha256": capture_sha, "agents": agents, "original_workflow_result": result["workflow"],
            "observed_core_workflow_original_bytes": values["observed_core_workflow_original_bytes"],
            "observed_core_workflow_pin": inputs["core_workflow_receipt_observation"]}

def observe_data_file(path, expected_bytes=None):
    check()
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "canonical_existing_data_file")
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid == UID and stat.S_IMODE(st.st_mode) == 0o600
         and st.st_nlink == 1 and (expected_bytes is None or st.st_size == expected_bytes),
         "existing_owned_data_file_identity")
    ident = file_identity(st)
    old = DATA_FILE_OBSERVATIONS.get(str(path))
    need(old is None or old == ident, "consumed_data_file_changed")
    DATA_FILE_OBSERVATIONS[str(path)] = ident
    return ident


def relative_name(name):
    need(isinstance(name, str) and name and "\\" not in name and "\x00" not in name,
         "relative_snapshot_name")
    path = PurePosixPath(name)
    need(not path.is_absolute() and str(path) == name and all(x not in ("", ".", "..") for x in path.parts),
         "canonical_snapshot_relative_name")
    return path


def absent(root, relative):
    path = Path(root) / str(relative_name(relative))
    need(path.resolve(strict=False) == path and not path_present(path), "declared_snapshot_absence")
    return True


def exact_tree(root, names, *, required_dirs=()):
    """Read only the finite exact authenticated namespace; no prefix inventory."""
    root = Path(root)
    files = {str(relative_name(name)) for name in names}
    dirs = {""}
    for name in files:
        parent = PurePosixPath(name).parent
        while str(parent) != ".":
            dirs.add(str(parent))
            parent = parent.parent
    for name in required_dirs:
        directory = relative_name(name)
        dirs.add(str(directory))
        parent = directory.parent
        while str(parent) != ".":
            dirs.add(str(parent))
            parent = parent.parent
    need(not (files & (dirs - {""})), "file_directory_namespace_collision")
    expected = {name: {} for name in dirs}
    for name in dirs - {""}:
        parent = str(PurePosixPath(name).parent)
        expected["" if parent == "." else parent][PurePosixPath(name).name] = "directory"
    for name in files:
        parent = str(PurePosixPath(name).parent)
        expected["" if parent == "." else parent][PurePosixPath(name).name] = "file"
    for relative in sorted(dirs, key=lambda x: (len(PurePosixPath(x).parts), x)):
        check()
        directory = root if not relative else root / relative
        hold_directory(directory)
        seen = set()
        with os.scandir(directory) as listing:
            for entry in listing:
                check()
                need(entry.name in expected[relative] and entry.name not in seen,
                     "unexpected_snapshot_tree_entry")
                seen.add(entry.name)
                st = entry.stat(follow_symlinks=False)
                if expected[relative][entry.name] == "directory":
                    need(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode),
                         "snapshot_tree_directory_type")
                else:
                    need(stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode),
                         "snapshot_tree_regular_file_type")
        need(seen == set(expected[relative]), "missing_snapshot_tree_entry")
    return {"files": len(files), "directories": len(dirs)}


def verify_capture_top(root):
    expected = {"baseline-state": "directory", "candidate-state": "directory",
                "source-config.private.json": "file", "capture.private.json": "file",
                "capture-binding.private.json": "file", "result.public.json": "file",
                "workflow.plan.private.json": "file", "workflow-locations.private.json": "file",
                "workflow-result.public.json": "file"}
    seen = set()
    with os.scandir(root) as listing:
        for entry in listing:
            check()
            need(entry.name in expected and entry.name not in seen, "unexpected_capture_top_entry")
            seen.add(entry.name)
            st = entry.stat(follow_symlinks=False)
            need(not stat.S_ISLNK(st.st_mode) and
                 (stat.S_ISDIR(st.st_mode) if expected[entry.name] == "directory" else stat.S_ISREG(st.st_mode)),
                 "capture_top_entry_type")
    need(seen == set(expected), "complete_original_capture_top_level")


def archive_verification(context, end):
    from cryptography.fernet import Fernet
    paths, originals = context["paths"], context["originals"]
    plaintext = Fernet(originals["recovery_key"]).decrypt(originals["archive_manifest"])
    need(len(plaintext) <= CORE.MAX_META, "bounded_original_authenticated_manifest")
    preliminary = json.loads(plaintext, object_pairs_hook=unique)
    need(preliminary["schema"] == CORE.ARCHIVE_SCHEMA and preliminary["chunk_bytes"] == CORE.CHUNK
         and preliminary["capture_sha256"] == context["capture_sha256"], "preliminary_original_archive_binding")
    chunk_names, cipher_bytes = [], 0
    need(isinstance(preliminary["files"], list) and 0 < len(preliminary["files"]) <= CORE.MAX_FILES,
         "complete_archive_declaration_bound")
    for row in preliminary["files"]:
        check()
        relative_name(row["path"])
        need(isinstance(row["chunks"], list), "complete_chunk_array")
        for chunk in row["chunks"]:
            check()
            expected_name = f"{len(chunk_names):08d}.fernet"
            need(chunk["name"] == expected_name and type(chunk["bytes"]) is int
                 and 0 < chunk["bytes"] <= 2 * CORE.CHUNK, "ordered_bounded_chunk_metadata")
            observe_data_file(paths["archive"] / "chunks" / expected_name, chunk["bytes"])
            chunk_names.append(expected_name)
            cipher_bytes += chunk["bytes"]
    archive_tree = exact_tree(paths["archive"],
                              {"manifest.fernet", "result.public.json",
                               *("chunks/" + name for name in chunk_names)}, required_dirs=("chunks",))
    key_tree = exact_tree(paths["key"], {"recovery.key"})
    restore_plan = {"archive_root": str(paths["archive"]),
                    "key_file": str(paths["key"] / "recovery.key"),
                    "capture_sha256": context["capture_sha256"],
                    "restore_parent": str(paths["restore"].parent),
                    "restore_name": paths["restore"].name}
    # This frozen function only authenticates/reads. restore_verify is never called.
    archive, _cipher, manifest, captured, key_identity = CORE.authenticate_archive(restore_plan, end)
    need(archive == paths["archive"] and manifest == preliminary, "same_fully_authenticated_manifest")
    need(hashlib.sha256(originals["capture_manifest"]).hexdigest() == context["capture_sha256"]
         and json.loads(originals["capture_manifest"], object_pairs_hook=unique) == captured,
         "authenticated_original_capture_bytes")
    locations = manifest["private_location_binding"]
    for role, key in (("archive", "archive_root"), ("key", "key_root")):
        pin = PRIVATE["actual_attempt_root_identities"][role]
        need(locations[key] == {"path": pin["path"],
                               "identity": {k: pin[k] for k in ("dev", "inode", "uid", "mode")}},
             "authenticated_actual_backup_root_identity")
    for role, key in (("archive", "archive_parent"), ("key", "key_parent")):
        pin = context["binding"]["parent_identities"][role]
        need(locations[key] == {"path": pin["path"],
                               "identity": {k: pin[k] for k in ("dev", "inode", "uid", "mode")}},
             "authenticated_actual_backup_parent_identity")
    source = context["binding"]["source_root_identity"]
    capture = PRIVATE["actual_attempt_root_identities"]["capture"]
    need(captured["origin_directories"] == {
        "source_root": {"path": source["path"], "identity": {k: source[k] for k in ("dev", "inode", "uid", "mode")}},
        "capture_root": {"path": capture["path"], "identity": {k: capture[k] for k in ("dev", "inode", "uid", "mode")}},
    }, "authenticated_original_source_and_capture_metadata_only")
    agents = context["agents"]
    databases = captured["database_rows"]
    need(captured["configured_agent_count"] == len(agents)
         and len(databases) == len(agents) + 4
         and {row["agent"] for row in databases if row["kind"] == "agent"} == set(agents)
         and len([row for row in databases if row["kind"] == "agent"]) == len(agents)
         and len(captured["files"]) == len(agents) + 13
         and len(manifest["files"]) == len(agents) + 14, "dynamic_complete_agent_database_and_file_denominators")
    need(captured["source_config_sha256"] == context["plan"]["capture"]["source_config_sha256"]
         and 0 <= captured["logical_snapshot_bytes"] <= context["plan"]["capture"]["maximum_total_bytes"],
         "same_declared_source_configuration_and_logical_bound")
    for row in databases:
        need(row["kind"] in ("agent", "shared", "quarantine", "transport")
             and type(row["present"]) is bool
             and (not row["present"] or 0 <= row["snapshot_bytes"] <= context["plan"]["capture"]["maximum_database_bytes"]),
             "all_current_database_rows_within_original_bounds")
    need(sum(row["present"] and row.get("snapshot_bytes", 0) or 0 for row in databases)
         <= context["plan"]["capture"]["maximum_total_bytes"], "aggregate_closed_database_bytes_bound")
    total = sum(row.get("bytes", 0) for row in manifest["files"] if row["present"])
    need(total <= context["plan"]["capture"]["maximum_total_bytes"] + 256 * MIB,
         "complete_archive_plaintext_with_original_metadata_allowance")
    context.update(manifest=manifest, captured=captured, key_identity=key_identity,
                   chunk_names=chunk_names, restore_plan=restore_plan)
    PRIVATE["authenticated_manifest_sha256"] = hashlib.sha256(plaintext).hexdigest()
    PUBLIC["archive"] = {"declared_files": len(manifest["files"]),
                         "present_files": sum(row["present"] for row in manifest["files"]),
                         "absent_files": sum(not row["present"] for row in manifest["files"]),
                         "encrypted_chunks": len(chunk_names), "ciphertext_chunk_bytes": cipher_bytes,
                         "declared_plaintext_bytes": total, "every_chunk_authenticated": True,
                         "ordered_chunk_inventory_complete": True, "no_missing_or_extra_archive_files": True,
                         "archive_tree_files": archive_tree["files"], "key_tree_files": key_tree["files"]}
    checked("complete_ordered_authenticated_archive_generation", True)
    return context


def hash_copies(context, end):
    paths, manifest, captured = context["paths"], context["manifest"], context["captured"]
    files = manifest["files"]
    baseline_names = {row["path"][len("baseline-state/"):] for row in files
                      if row["present"] and row["path"].startswith("baseline-state/")}
    restore_names = {row["path"] for row in files if row["present"]} | {"result.public.json"}
    verify_capture_top(paths["capture"])
    baseline_tree = exact_tree(paths["capture"] / "baseline-state", baseline_names)
    restore_tree = exact_tree(paths["restore"], restore_names)
    per_copy = {}
    full_hashes = {}
    for role in ("capture", "restore"):
        root = paths[role]
        present, absent_count, byte_count = 0, 0, 0
        full_hashes[role] = []
        for index, row in enumerate(files):
            check(end)
            name = str(relative_name(row["path"]))
            if not row["present"]:
                absent(root, name)
                absent_count += 1
                full_hashes[role].append({"index": index, "present": False})
                continue
            path = root / name
            ident = observe_data_file(path, row["bytes"])
            observed = CORE.file_hash(path, row["bytes"], end)
            need(observed == row["sha256"] and file_identity(path.lstat()) == ident,
                 "whole_declared_file_bytes_match_authenticated_generation")
            present += 1
            byte_count += row["bytes"]
            full_hashes[role].append({"index": index, "present": True, "bytes": row["bytes"], "sha256": observed})
        decoded, declarations = CORE.capture_inputs(root, context["capture_sha256"], end,
                                                     require_completion=role == "capture")
        need(decoded == captured and len(declarations) == len(files)
             and {row["path"]: row for row in declarations} ==
                 {row["path"]: {k: row[k] for k in ("path", "present", "bytes", "sha256") if k in row} for row in files},
             "every_original_capture_file_and_absence_cross_bound")
        per_copy[role] = {"declared_files": len(files), "present_files_hashed": present,
                          "absent_files_verified": absent_count, "whole_plaintext_bytes_hashed": byte_count,
                          "complete_manifest_matches_authenticated_archive": True}
    source_raw, _ = read_file(paths["capture"] / "source-config.private.json", MIB, remember=True)
    CORE.validate_original_configuration(captured, source_raw)
    expected = json.loads(source_raw, object_pairs_hook=unique)
    for row in expected["agents"]["list"]:
        row["agentDir"] = str(paths["capture"] / "baseline-state/agents" / row["id"] / "agent")
    projected_raw, _ = read_file(paths["capture"] / "baseline-state/openclaw.json", 2 * MIB, remember=True)
    projected = json.loads(projected_raw, object_pairs_hook=unique)
    need(projected == expected, "baseline_configuration_only_controlled_agent_directory_projection")
    workflow_raw, _ = read_file(paths["capture"] / "workflow.plan.private.json", 512 * 1024, remember=True)
    need(json.loads(workflow_raw, object_pairs_hook=unique) == context["plan"],
         "existing_capture_workflow_plan_equals_original_stage_plan")
    locations_raw, _ = read_file(paths["capture"] / "workflow-locations.private.json", 65536, remember=True)
    pins = {"source_root": context["binding"]["source_root_identity"],
            **{role + "_parent": value for role, value in context["binding"]["parent_identities"].items()}}
    expected_locations = {name: {"path": pin["path"],
                                  "identity": {key: pin[key] for key in ("dev", "inode", "uid", "mode")}}
                          for name, pin in pins.items()}
    need(json.loads(locations_raw, object_pairs_hook=unique) == expected_locations,
         "existing_capture_workflow_locations_equal_original_generation")
    workflow_result_raw, workflow_ident = read_file(
        paths["capture"] / "workflow-result.public.json", 65536,
        pin=context["observed_core_workflow_pin"], remember=True)
    need(workflow_result_raw == context["observed_core_workflow_original_bytes"]
         and version(workflow_ident) == context["observed_core_workflow_pin"]["version"],
         "independently_observed_complete_core_workflow_receipt_unchanged")
    need(validated_core_workflow_projection(json.loads(workflow_result_raw, object_pairs_hook=unique))
         == context["original_workflow_result"], "existing_complete_core_workflow_projects_to_original_success")
    context["per_copy_files"] = per_copy
    PRIVATE["whole_declared_file_readback_hashes"] = full_hashes
    PUBLIC["whole_file_readback"] = per_copy
    PUBLIC["namespace"] = {"baseline_present_files": baseline_tree["files"],
                           "baseline_directories": baseline_tree["directories"],
                           "restore_present_files_including_phase_receipt": restore_tree["files"],
                           "restore_directories": restore_tree["directories"],
                           "all_declared_absences_verified": True, "exact_baseline_and_restore_trees": True}
    PUBLIC["baseline_configuration_controlled_projection_verified"] = True
    PUBLIC["original_capture_workflow_plan_locations_and_result_verified"] = True
    checked("both_existing_copies_full_declared_bytes_and_absences", True)


def cold_copies(context, end):
    global SQLITE_CONNECTIONS_OPENED, SQLITE_CONNECTIONS_CLOSED
    rows = context["captured"]["database_rows"]
    outcomes = {}
    for role in ("capture", "restore"):
        root = context["paths"][role] / "baseline-state"
        result_rows, nonempty, empty, absent_count, auth_stores, auth_rows_count, auth_state_count = [], 0, 0, 0, 0, 0, 0
        for index, row in enumerate(rows):
            check(end)
            path = root / str(relative_name(row["relative_path"]))
            members = {suffix: path_present(Path(str(path) + suffix)) for suffix in CORE.FAMILY}
            if not row["present"]:
                need(not any(members.values()), "absent_database_and_all_sidecars")
                absent_count += 1
                result_rows.append({"index": index, "kind": row["kind"], "state": "absent_family_verified"})
                continue
            ident = observe_data_file(path, row["snapshot_bytes"])
            need(not any(members[suffix] for suffix in CORE.FAMILY[1:]),
                 "cold_copy_starts_without_sidecars")
            if row.get("empty_database_marker"):
                need(row["snapshot_bytes"] == 0 and ident["bytes"] == 0, "whole_empty_marker_verified")
                empty += 1
                result_rows.append({"index": index, "kind": row["kind"], "state": "empty_marker_verified"})
                continue
            uri = path.as_uri() + "?mode=ro&immutable=1"
            SQLITE_ALLOWLIST.add(uri)
            conn = None
            with CORE.held(path, row["snapshot_bytes"], exact=row["snapshot_bytes"]) as (_, before):
                SQLITE_OPEN_IDENTITIES.append([before.st_dev, before.st_ino])
                try:
                    conn = sqlite3.connect(uri, uri=True, timeout=1)
                    SQLITE_CONNECTIONS_OPENED += 1
                    conn.execute("PRAGMA query_only=ON")
                    conn.set_progress_handler(lambda: int(FIRED or INTERRUPTED or time.monotonic() >= end), 1000)
                    need(conn.execute("PRAGMA quick_check").fetchall() == [("ok",)]
                         and hashlib.sha256(captured_encoded(CORE.db_schema(conn))).hexdigest() == row["schema_sha256"],
                         "whole_cold_database_integrity_and_schema_exact")
                    need(conn.execute("PRAGMA page_count").fetchone()[0] == row["page_count"],
                         "whole_cold_database_page_denominator")
                    if row["kind"] == "agent":
                        observed = CORE.auth_rows(conn)
                        need(hashlib.sha256(captured_encoded(observed)).hexdigest() == row["auth_rows_sha256"]
                             and len(observed["auth_profile_store"]) == row["auth_store_rows"]
                             and len(observed["auth_profile_state"]) == row["auth_state_rows"],
                             "all_agent_authentication_rows_exact")
                        auth_stores += row["auth_store_rows"] > 0
                        auth_rows_count += row["auth_store_rows"]
                        auth_state_count += row["auth_state_rows"]
                        del observed
                    nonempty += 1
                    result_rows.append({"index": index, "kind": row["kind"], "state": "cold_database_verified",
                                        "all_agent_auth_rows_exact_or_not_agent": True})
                finally:
                    if conn is not None:
                        conn.close()
                        SQLITE_CONNECTIONS_CLOSED += 1
                    SQLITE_ALLOWLIST.discard(uri)
            need(file_identity(path.lstat()) == ident
                 and not any(path_present(Path(str(path) + suffix)) for suffix in CORE.FAMILY[1:]),
                 "cold_read_changed_no_file_or_sidecar")
        need(nonempty + empty + absent_count == len(rows) == len(result_rows), "complete_cold_database_partition")
        outcomes[role] = {"database_families": len(rows), "nonempty_cold_checked": nonempty,
                          "empty_markers_verified": empty, "absent_families_verified": absent_count,
                          "agent_auth_stores_nonempty": auth_stores, "all_agent_auth_store_rows": auth_rows_count,
                          "all_agent_auth_state_rows": auth_state_count, "rows": result_rows}
    need(outcomes["capture"] == outcomes["restore"], "both_copy_cold_results_equal")
    need(SQLITE_CONNECTIONS_OPENED == SQLITE_CONNECTIONS_CLOSED and not SQLITE_ALLOWLIST,
         "all_cold_connections_closed")
    CORE.no_owned_source_handles(SQLITE_OPEN_IDENTITIES)
    PUBLIC["cold_sqlite"] = outcomes
    PUBLIC["cold_connections_opened"] = SQLITE_CONNECTIONS_OPENED
    PUBLIC["cold_connections_closed"] = SQLITE_CONNECTIONS_CLOSED
    PUBLIC["all_cold_copy_handles_retired"] = True
    checked("every_nonempty_database_cold_and_all_agent_rows_exact", True)


def copies_verification(context, end):
    hash_copies(context, end)
    cold_copies(context, end)
    paths = context["paths"]
    for role, expected_phase in (("capture", "capture"), ("archive", "backup"), ("restore", "restore-verify")):
        raw, _ = read_file(paths[role] / "result.public.json", 65536, remember=True)
        report = json.loads(raw, object_pairs_hook=unique)
        need(report["schema"] == "heptabao.current-sqlite-reversible-work.public.v1"
             and report["status"] == "passed" and report["phase"] == expected_phase
             and report["credential_values_or_content_fingerprints_published"] is False,
             "existing_original_phase_receipt_matches_role")
    safety = {"baseline-state/" + name for name in CORE.SAFETY}
    rows = [row for row in context["manifest"]["files"] if row["path"] in safety]
    need(len(rows) == len(safety) == 7 and {row["path"] for row in rows} == safety,
         "complete_seven_safety_file_denominator")
    PUBLIC["safety_files"] = {"required_count": 7,
                               "present_count": sum(row["present"] for row in rows),
                               "absent_count": sum(not row["present"] for row in rows),
                               "complete_both_copy_full_bytes_and_absences_verified": True}
    checked("all_seven_safety_and_absent_file_boundaries_covered", True)
    return context

def postflight(context):
    verify_directories()
    for row in READS:
        _, ident = read_file(row["path"], row["maximum"], private=row["private"], pin=row["pin"])
        need(ident == row["identity"], "original_verifier_input_identity_changed")
    for name, old in DATA_FILE_OBSERVATIONS.items():
        need(observe_data_file(name, old["bytes"]) == old, "authenticated_consumed_file_changed_after_readback")
    paths, files = context["paths"], context["manifest"]["files"]
    exact_tree(paths["archive"], {"manifest.fernet", "result.public.json",
                                  *("chunks/" + n for n in context["chunk_names"])}, required_dirs=("chunks",))
    exact_tree(paths["key"], {"recovery.key"})
    exact_tree(paths["capture"] / "baseline-state",
               {row["path"][len("baseline-state/"):] for row in files
                if row["present"] and row["path"].startswith("baseline-state/")})
    exact_tree(paths["restore"], {row["path"] for row in files if row["present"]} | {"result.public.json"})
    verify_capture_top(paths["capture"])
    for row in files:
        if not row["present"]:
            for role in ("capture", "restore"):
                absent(paths[role], row["path"])
    for database in context["captured"]["database_rows"]:
        for role in ("capture", "restore"):
            path = paths[role] / "baseline-state" / database["relative_path"]
            need(not any(path_present(Path(str(path) + suffix)) for suffix in CORE.FAMILY[1:]),
                 "no_sqlite_sidecars_at_final_boundary")
    checked("all_bound_inputs_consumed_files_and_roots_unchanged", True)
    targets = [[row["dev"], row["inode"]] for row in DATA_FILE_OBSERVATIONS.values()]
    targets += [[row["identity"]["dev"], row["identity"]["inode"]] for row in READS]
    CORE.no_owned_source_handles(targets)
    need(SQLITE_CONNECTIONS_OPENED == SQLITE_CONNECTIONS_CLOSED and not SQLITE_ALLOWLIST,
         "all_original_cold_connections_retired")
    PUBLIC["consumed_data_file_identity_count"] = len(DATA_FILE_OBSERVATIONS)
    PUBLIC["consumed_input_observation_count"] = len(READS)
    PUBLIC["independent_fd_inode_target_count"] = len({tuple(row) for row in targets})
    checked("all_consumed_plaintext_key_and_input_handles_retired", True)
    need(not AUDIT_DENIALS, "forbidden_readback_effect_attempted")
    checked("no_live_source_network_process_or_mutation_effect", True)
    check(WORK_END)


REQUIRED_CHECKS = (
    "fixed_readonly_code_and_environment_bound",
    "original_complete_workflow_and_fresh_stage_bound",
    "original_private_generation_roots_files_and_plan_bound",
    "complete_ordered_authenticated_archive_generation",
    "both_existing_copies_full_declared_bytes_and_absences",
    "every_nonempty_database_cold_and_all_agent_rows_exact",
    "all_seven_safety_and_absent_file_boundaries_covered",
    "complete_current_snapshot_denominators_without_truncation",
    "all_bound_inputs_consumed_files_and_roots_unchanged",
    "all_consumed_plaintext_key_and_input_handles_retired",
    "no_live_source_network_process_or_mutation_effect",
)


def run(inputs, controller_pin):
    need(inputs["schema"] == "heptabao.current-sqlite-independent-readback-fixed-inputs.v1"
         and inputs["ready"] is True, "actual_original_workflow_success_required_before_consumption")
    read_file(Path(__file__).resolve(strict=True), 256 * 1024, pin=controller_pin, remember=True)
    verify_installed_runtime(inputs)
    load_readonly_core(inputs)
    checked("fixed_readonly_code_and_environment_bound", True)
    values = load_public_admission(inputs)
    context = load_completed_generation(inputs, values)
    check(PREFLIGHT_END)
    PUBLIC["admission_seconds_from_new_original_entry"] = time.monotonic() - ENTRY
    PUBLIC["remaining_work_seconds_at_archive_entry"] = WORK_END - time.monotonic()
    PHASES.append({"phase": "admission", "status": "passed", "cap_seconds": 60,
                   "elapsed_seconds": time.monotonic() - ENTRY,
                   "completed_within_original_phase_and_new_attempt_work_deadline": True})
    context = phase("archive_authentication", 300, lambda end: archive_verification(context, end))
    context["originals"].clear()
    context = phase("existing_copies_full_hash_and_cold_sqlite", 300,
                    lambda end: copies_verification(context, end))
    agents = len(context["agents"])
    checked("complete_current_snapshot_denominators_without_truncation",
            len(context["captured"]["database_rows"]) == agents + 4
            and len(context["captured"]["files"]) == agents + 13
            and len(context["manifest"]["files"]) == agents + 14
            and all(row["declared_files"] == agents + 14 for row in context["per_copy_files"].values()))
    arm(WORK_END)
    post_begin = time.monotonic()
    postflight(context)
    PHASES.append({"phase": "postflight", "status": "passed",
                   "absolute_new_entry_work_ceiling_seconds": 840,
                   "elapsed_seconds": time.monotonic() - post_begin,
                   "completed_within_original_phase_and_new_attempt_work_deadline": True})
    need(len(CHECKS) == len(REQUIRED_CHECKS) and {row["check"] for row in CHECKS} == set(REQUIRED_CHECKS)
         and all(row["passed"] is True for row in CHECKS), "complete_independent_verification_check_set")
    PUBLIC.update(status="passed", verification_complete=True,
                  complete_declared_capture_archive_and_existing_restore_verified=True,
                  all_bound_verifier_inputs_unchanged=True,
                  existing_original_generation_identity_preserved=True,
                  all_safety_files_and_declared_absences_verified=True,
                  all_archive_chunks_authenticated_in_exact_order=True,
                  all_existing_nonempty_databases_cold_verified=True,
                  no_new_restore_or_mutating_core_entrypoint_called=True,
                  source_and_live_clients_not_consulted=True)


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
    primary_failure, cleanup_failures = None, []
    try:
        need(old_timer == (0.0, 0.0), "ambient_timer_refused")
        need(all(re.fullmatch(r"[0-9a-f]{64}", v) for v in (args.inputs_sha256, args.controller_sha256)),
             "exact_fixed_public_input_pins")
        for number in signals:
            signal.signal(number, interrupt)
        signal.setitimer(signal.ITIMER_REAL, max(0.000001, PREFLIGHT_END - time.monotonic()))
        timer_owned = True
        hold_directory(INPUT)
        create_output()
        sys.addaudithook(audit_readback)
        with private_stdio():
            raw, _ = read_file(INPUT / "fixed-inputs.public.json", 256 * 1024, remember=True)
            need(hashlib.sha256(raw).hexdigest() == args.inputs_sha256, "fixed_public_inputs_sha256")
            inputs = json.loads(raw, object_pairs_hook=unique)
            own = Path(__file__).resolve(strict=True)
            run(inputs, {"bytes": own.stat().st_size, "sha256": args.controller_sha256})
            check(WORK_END)
        exit_code = 0
    except BaseException as error:
        primary_failure = safe_error(error)
        PUBLIC.update(status="failed", verification_complete=False, primary_failure_code=primary_failure)
        exit_code = 1
    finally:
        FINISHING = True
        try:
            need(SQLITE_CONNECTIONS_OPENED == SQLITE_CONNECTIONS_CLOSED and not SQLITE_ALLOWLIST,
                 "final_cold_connection_custody")
            verify_directories()
            PUBLIC["original_directory_paths_and_handles_preserved"] = True
        except BaseException as error:
            cleanup_failures.append(safe_error(error))
            PUBLIC.update(status="failed", verification_complete=False,
                          original_directory_paths_and_handles_preserved=False)
            exit_code = 1
        elapsed = time.monotonic() - ENTRY
        if FIRED or INTERRUPTED or elapsed >= 840:
            cleanup_failures.append("original_independent_work_deadline_or_interrupt")
            PUBLIC.update(status="failed", verification_complete=False)
            exit_code = 1
        PUBLIC.update(primary_failure_code=primary_failure, cleanup_failure_codes=list(cleanup_failures),
                      deadline_fired=FIRED, interrupted=INTERRUPTED,
                      elapsed_observation_before_receipt_publication_seconds=elapsed,
                      elapsed_observation_before_receipt_publication=True,
                      partial_owned_verification_output_retained=exit_code != 0,
                      forbidden_effect_attempt_count=len(AUDIT_DENIALS),
                      cold_connections_opened=SQLITE_CONNECTIONS_OPENED,
                      cold_connections_closed=SQLITE_CONNECTIONS_CLOSED,
                      new_child_processes_spawned=0,
                      phases=list(PHASES), verification_checks=list(CHECKS),
                      required_verification_check_count=len(REQUIRED_CHECKS),
                      observed_verification_check_count=len(CHECKS),
                      passed_verification_check_count=sum(row["passed"] is True for row in CHECKS),
                      missing_required_checks=[name for name in REQUIRED_CHECKS if name not in {r["check"] for r in CHECKS}])
        if timer_owned:
            signal.setitimer(signal.ITIMER_REAL, 0)
        PRIVATE.update(public_result_before_publication=dict(PUBLIC),
                       data_file_original_identity_observations=DATA_FILE_OBSERVATIONS,
                       consumed_input_original_observations=[{k: (str(v) if isinstance(v, Path) else v)
                                                              for k, v in row.items()} for row in READS])
        if CONTROL is not None:
            try:
                ident = control_write("verification.private.json", encoded(PRIVATE))
                PUBLIC["verification_private_file_identity"] = ident
                if FIRED or INTERRUPTED:
                    cleanup_failures.append("interrupt_during_private_receipt_publication")
                    PUBLIC.update(status="failed", verification_complete=False)
                    exit_code = 1
                PUBLIC["cleanup_failure_codes"] = list(cleanup_failures)
                PUBLIC["owned_directory_handle_count"] = len(DIRECTORIES)
                PUBLIC["directory_handle_close_is_runtime_terminal_dependent"] = True
                control_write("result.public.json", encoded(PUBLIC))
            except BaseException as error:
                cleanup_failures.append(safe_error(error))
                PUBLIC.update(status="failed", verification_complete=False)
                exit_code = 1
        closed = 0
        for row in reversed(DIRECTORIES):
            try:
                os.close(row["fd"])
                closed += 1
            except OSError:
                cleanup_failures.append("owned_directory_close_failed")
                PUBLIC.update(status="failed", verification_complete=False)
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
            cleanup_failures.append("original_independent_runtime_or_final_interrupt")
            PUBLIC.update(status="failed", verification_complete=False)
            exit_code = 1
        PUBLIC["cleanup_failure_codes"] = cleanup_failures
        if exit_code:
            PUBLIC.update(status="failed", verification_complete=False)
        print(json.dumps(PUBLIC, sort_keys=True, separators=(",", ":")), flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())





