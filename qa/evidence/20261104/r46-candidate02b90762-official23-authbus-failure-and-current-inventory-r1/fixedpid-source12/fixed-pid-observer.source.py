#!/usr/bin/env python3
"""One fixed Linux process identity observation. No target control or discovery."""
import errno
import json
import os
import re
import stat
import sys
import time

PID = 2031533
EXPECTED_BOOT = "b19bd1b9-4dbe-4335-96cf-ed98d393efea"
EXPECTED_START = 35455670
EXPECTED_UID = 100
PROC = "/proc/2031533"
BOOT = "/proc/sys/kernel/random/boot_id"
SECONDS = 5.0
OUT_LIMIT = 16384
UNTIL = time.monotonic() + SECONDS
STARTED = time.monotonic()
STAGE = "entry"
CLOSE_ERRORS = []
COUNTS = {"open_attempts": 0, "read_attempts": 0, "readlink_attempts": 0}
READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW

class Refused(Exception):
    pass

def gate(stage):
    global STAGE
    STAGE = stage
    if time.monotonic() >= UNTIL:
        raise Refused("shared_deadline_expired")

def close_once(fd, stage):
    try:
        os.close(fd)
    except OSError as exc:
        CLOSE_ERRORS.append({"stage": stage, "errno": exc.errno})

def read_fixed(path, cap, stage, directory=None):
    if directory is None:
        if path != BOOT:
            raise Refused("absolute_path_not_allowed")
    elif path not in ("stat", "status", "cgroup"):
        raise Refused("relative_path_not_allowed")
    gate(stage + ".open")
    COUNTS["open_attempts"] += 1
    fd = os.open(path, READ_FLAGS, dir_fd=directory)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Refused("proc_file_not_regular")
        gate(stage + ".read")
        COUNTS["read_attempts"] += 1
        body = os.read(fd, cap + 1)
        if len(body) > cap:
            raise Refused("fixed_read_cap_exceeded")
        gate(stage + ".eof")
        COUNTS["read_attempts"] += 1
        if os.read(fd, 1) != b"":
            raise Refused("single_read_did_not_reach_eof")
        gate(stage + ".done")
        return body
    finally:
        close_once(fd, stage + ".close")

def open_proc(stage):
    gate(stage)
    COUNTS["open_attempts"] += 1
    return os.open(PROC, READ_FLAGS | os.O_DIRECTORY)

def directory_identity(fd):
    value = os.fstat(fd)
    if not stat.S_ISDIR(value.st_mode):
        raise Refused("proc_directory_not_directory")
    return [value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode]

def identity(stage):
    boot = read_fixed(BOOT, 64, stage + ".boot").decode("ascii").strip()
    if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot) is None:
        raise Refused("boot_id_shape")
    fd = open_proc(stage + ".directory")
    try:
        directory = directory_identity(fd)
        raw_stat = read_fixed("stat", 4096, stage + ".stat", fd)
        left = raw_stat.find(b" (")
        right = raw_stat.rfind(b") ")
        if left < 1 or right <= left:
            raise Refused("stat_shape")
        pid_token = raw_stat[:left]
        rest = raw_stat[right + 2:].split()
        if not pid_token.isdigit() or len(pid_token) > 10 or len(rest) < 20:
            raise Refused("stat_fields")
        start_token = rest[19]
        if not start_token.isdigit() or len(start_token) > 20:
            raise Refused("start_ticks_shape")
        status = read_fixed("status", 8192, stage + ".uid", fd)
        uid_lines = [line[4:].split() for line in status.splitlines()
                     if line.startswith(b"Uid:")]
        if len(uid_lines) != 1 or len(uid_lines[0]) != 4:
            raise Refused("uid_fields")
        if any(not token.isdigit() or len(token) > 10 for token in uid_lines[0]):
            raise Refused("uid_token_shape")
        uids = [int(token) for token in uid_lines[0]]
        if any(value > 4294967295 for value in uids):
            raise Refused("uid_range")
        return {
            "boot_id": boot, "pid": int(pid_token),
            "start_ticks": int(start_token),
            "uids_real_effective_saved_fs": uids,
            "proc_directory_identity": directory
        }
    finally:
        close_once(fd, stage + ".directory.close")

def require_expected(value, held_directory):
    if (value["boot_id"] != EXPECTED_BOOT or value["pid"] != PID
            or value["start_ticks"] != EXPECTED_START
            or value["uids_real_effective_saved_fs"][0] != EXPECTED_UID
            or value["uids_real_effective_saved_fs"][1] != EXPECTED_UID
            or value["proc_directory_identity"] != held_directory):
        raise Refused("fixed_process_identity_mismatch")

def public_cgroup(body):
    lines = body.decode("utf-8").splitlines()
    if not lines or len(lines) > 16:
        raise Refused("cgroup_line_limit")
    result = []
    for line in lines:
        parts = line.split(":", 2)
        if len(parts) != 3:
            raise Refused("cgroup_shape")
        hierarchy, controllers, path = parts
        if (not hierarchy.isdigit() or len(hierarchy) > 10
                or re.fullmatch(r"[A-Za-z0-9_,=.-]*", controllers) is None
                or not path.startswith("/")
                or len(path.encode("utf-8")) > 2048
                or any(ord(ch) < 32 or ord(ch) == 127 for ch in path)):
            raise Refused("cgroup_public_fields")
        result.append({
            "hierarchy": int(hierarchy),
            "controllers": controllers,
            "path": path
        })
    return result

def error_record(exc, stage):
    if isinstance(exc, OSError):
        return {"stage": stage, "code": "os_error", "errno": exc.errno}
    if isinstance(exc, Refused):
        return {"stage": stage, "code": str(exc)}
    return {"stage": stage, "code": "unexpected_local_exception"}

def main():
    global STAGE
    before = None
    after = None
    held = None
    draft = {}
    failures = []
    stable = False
    try:
        if sys.platform != "linux":
            raise Refused("linux_only")
        held = open_proc("held.directory")
        held_directory = directory_identity(held)
        before = identity("before")
        require_expected(before, held_directory)
        if CLOSE_ERRORS:
            raise Refused("pre_identity_close_error")
        try:
            # Stop projection reads on the first failure. The independent
            # after-identity read below is closure, not a fallback projection.
            draft["cgroup"] = public_cgroup(
                read_fixed("cgroup", 4096, "projection.cgroup", held))
            if CLOSE_ERRORS:
                raise Refused("cgroup_close_error")
            gate("projection.exe.readlink")
            COUNTS["readlink_attempts"] += 1
            link = os.readlink("exe", dir_fd=held)
            gate("projection.exe.done")
            if (not link.startswith("/") or len(link.encode("utf-8")) > 4096
                    or any(ord(ch) < 32 or ord(ch) == 127 for ch in link)):
                raise Refused("exe_link_public_shape")
            draft["exe_link"] = link
        except Exception as exc:
            failures.append(error_record(exc, STAGE))
        # This is a new fixed read of boot/stat/Uid from an independent proc
        # directory FD. It never retries exe/cgroup and never scans a PID list.
        after = identity("after")
        require_expected(after, held_directory)
        if before != after:
            raise Refused("identity_changed_during_observation")
        gate("final_identity")
        stable = True
    except Exception as exc:
        failures.append(error_record(exc, STAGE))
    finally:
        if held is not None:
            close_once(held, "held.directory.close")
    publish = stable and not CLOSE_ERRORS
    observed = draft if publish else {}
    ok = (publish and not failures and set(observed) == {"exe_link", "cgroup"})
    result = {
        "schema": "heptabao.x230.fixed-bao-public-process-identity.v1",
        "ok": ok,
        "host_alias": "x230",
        "expected": {
            "boot_id": EXPECTED_BOOT, "pid": PID,
            "start_ticks": EXPECTED_START, "uid": EXPECTED_UID
        },
        "before": before,
        "after": after,
        "fixed_identity_stable": stable,
        "projection_released_after_identity_closure": publish,
        "observed_public_fields": observed,
        "all_requested_public_fields_observed": set(observed) == {"exe_link", "cgroup"},
        "errors": failures,
        "explicit_close_errors": CLOSE_ERRORS,
        "syscall_attempts": COUNTS,
        "shared_deadline_seconds": SECONDS,
        "elapsed_ms": round((time.monotonic() - STARTED) * 1000, 3),
        "argv_environment_target_fds_read": False,
        "binary_or_configuration_body_read": False,
        "target_control_actions": False,
        "children_started_by_this_program": False,
        "service_mapping_or_binary_version_qualified": False,
        "prior_unknowns_changed": False
    }
    output = json.dumps(result, ensure_ascii=True, sort_keys=True) + "\n"
    if len(output.encode("utf-8")) > OUT_LIMIT:
        output = json.dumps({
            "schema": result["schema"], "ok": False,
            "error": "public_output_limit",
            "prior_unknowns_changed": False
        }, sort_keys=True) + "\n"
        ok = False
    sys.stdout.write(output)
    sys.stdout.flush()
    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
