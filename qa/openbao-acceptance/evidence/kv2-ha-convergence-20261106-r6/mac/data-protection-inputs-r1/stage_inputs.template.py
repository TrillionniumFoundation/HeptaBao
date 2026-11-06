#!/usr/bin/env python3
"""Create-only 19 inputs. The mixed request remains private; no workflow runs."""
import time
ENTRY = time.monotonic()
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys

PARENT = Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control")
OUT = PARENT / "current-sqlite-data-protection-inputs-r1"
END = ENTRY + 52
FIRED = False
INTERRUPTED = False
PROTECTED = False
FINISHING = False
PARENT_FD = None
OUT_FD = None
PARENT_PIN = None
OUT_PIN = None
PUBLIC = {"schema": "heptabao.current-data-protection-input-stage.v1", "status": "failed",
          "work_seconds": 52, "runtime_seconds": 60, "workflow_executed": False,
          "business_source_opened": False, "product_or_sdk_executed": False,
          "provider_or_j3160_called": False, "service_modified": False,
          "original_plan_or_binding_modified": False, "existing_inputs_replaced": False,
          "private_content_or_fingerprints_published": False, "subprocesses_started": False,
          "original_count": 0, "automatic_retry": False, "formal_kv2_qualified": False,
          "durable_completion_authority": "separate_original_runtime_terminal_with_60_second_cap"}


class Refused(Exception):
    pass


class Interrupted(BaseException):
    pass


def need(value, label):
    if not value:
        raise Refused(label)


def check():
    need(not FIRED and not INTERRUPTED and time.monotonic() < END, "original_stage_deadline")


def interrupt(signum, frame):
    global FIRED, INTERRUPTED
    if signum == signal.SIGALRM:
        FIRED = True
    else:
        INTERRUPTED = True
    if not PROTECTED and not FINISHING:
        raise Interrupted()


def directory_pin(path, fd=None):
    need(path.resolve(strict=True) == path, "canonical_stage_directory")
    st = path.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == 501 and stat.S_IMODE(st.st_mode) == 0o700,
         "owned_private_stage_directory")
    pin = [st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)]
    if fd is not None:
        held = os.fstat(fd)
        need(stat.S_ISDIR(held.st_mode)
             and pin == [held.st_dev, held.st_ino, held.st_uid, held.st_gid, stat.S_IMODE(held.st_mode)],
             "original_directory_fd_binding")
    return pin


def directories_unchanged():
    need(directory_pin(PARENT, PARENT_FD) == PARENT_PIN and directory_pin(OUT, OUT_FD) == OUT_PIN,
         "stage_directory_changed")


def file_identity(st):
    return {"dev": st.st_dev, "inode": st.st_ino, "uid": st.st_uid, "gid": st.st_gid,
            "mode": stat.S_IMODE(st.st_mode), "file_type": stat.S_IFMT(st.st_mode),
            "nlink": st.st_nlink, "bytes": st.st_size, "mtime_ns": st.st_mtime_ns, "ctime_ns": st.st_ctime_ns}


def create(name, raw):
    directories_unchanged()
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=OUT_FD)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(OUT_FD)
    directories_unchanged()


def readback(item):
    check()
    fd = os.open(item["name"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=OUT_FD)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_nlink == 1
             and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size == item["bytes"], "input_readback_custody")
        raw = bytearray()
        while len(raw) <= item["bytes"]:
            check()
            part = os.read(fd, 65536)
            if not part:
                break
            raw.extend(part)
        ident = file_identity(before)
        need(len(raw) == item["bytes"] and hashlib.sha256(raw).hexdigest() == item["sha256"]
             and ident == file_identity(os.fstat(fd))
             == file_identity(os.stat(item["name"], dir_fd=OUT_FD, follow_symlinks=False)), "input_readback_exact")
        return ident
    finally:
        os.close(fd)


def run(items):
    global PARENT_FD, OUT_FD, PARENT_PIN, OUT_PIN, PROTECTED
    check()
    need(sys.platform == "darwin" and os.geteuid() == 501 and sys.version_info[:3] == (3, 14, 3), "fixed_mac_interpreter")
    python = Path(sys.executable).resolve(strict=True)
    raw = python.read_bytes()
    need(len(raw) == 34640 and hashlib.sha256(raw).hexdigest()
         == "cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13", "fixed_python_bytes")
    names = [item["name"] for item in items]
    need(len(items) == len(set(names)) == 19 and sum(item["private"] for item in items) == 1
         and [item["name"] for item in items if item["private"]] == ["independent-plan-pins.private.json"],
         "exact_nineteen_inputs_one_private")
    need(sum(item["bytes"] for item in items) <= 800000, "fixed_input_total_cap")
    for item in items:
        need(set(item) == {"name", "bytes", "sha256", "text", "private"}
             and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", item["name"])
             and type(item["private"]) is bool, "fixed_input_name_fields")
        encoded = item["text"].encode()
        need(len(encoded) == item["bytes"] and hashlib.sha256(encoded).hexdigest() == item["sha256"], "request_exact_input_bytes")
    PARENT_PIN = directory_pin(PARENT)
    need(not os.path.lexists(OUT), "new_input_root_must_be_absent")
    PROTECTED = True
    try:
        PARENT_FD = os.open(PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        need(directory_pin(PARENT, PARENT_FD) == PARENT_PIN, "parent_before_creation")
        os.mkdir(OUT.name, 0o700, dir_fd=PARENT_FD)
        os.fsync(PARENT_FD)
        OUT_FD = os.open(OUT.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=PARENT_FD)
        OUT_PIN = directory_pin(OUT, OUT_FD)
    finally:
        PROTECTED = False
    PUBLIC["input_root_created"] = True
    PUBLIC["input_root_identity"] = OUT_PIN
    rows = []
    for item in items:
        check()
        create(item["name"], item["text"].encode())
        ident = readback(item)
        row = {"role": "independent_private_pins" if item["private"] else item["name"],
               "bytes": item["bytes"], "private": item["private"], "exact_readback": True,
               "mode": ident["mode"], "uid": ident["uid"], "nlink": ident["nlink"]}
        if not item["private"]:
            row["sha256"] = item["sha256"]
        else:
            row["identity"] = ident
        rows.append(row)
    for item in items:
        readback(item)
    directories_unchanged()
    check()
    PUBLIC.update(status="passed", staged_inputs=19, staged_public_inputs=18, staged_private_inputs=1,
                  all_input_bytes_and_modes_exact=True, all_original_directories_preserved=True,
                  inputs=rows)


def main(items):
    global FINISHING
    signals = (signal.SIGALRM, signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    previous = {n: signal.getsignal(n) for n in signals}
    old_timer = signal.getitimer(signal.ITIMER_REAL)
    old_umask = os.umask(0o077)
    result, armed = 1, False
    try:
        need(old_timer == (0.0, 0.0), "foreign_timer_refused")
        for n in signals:
            signal.signal(n, interrupt)
        signal.setitimer(signal.ITIMER_REAL, max(0.000001, END - time.monotonic()))
        armed = True
        run(items)
        check()
        result = 0
    except BaseException as error:
        name = str(error) if isinstance(error, Refused) else type(error).__name__
        PUBLIC.update(status="failed", error=name if re.fullmatch(r"[A-Za-z0-9_]{1,100}", name) else "private_stage_failure")
    finally:
        FINISHING = True
        try:
            if OUT_FD is not None:
                directories_unchanged()
        except BaseException:
            PUBLIC.update(status="failed", error="original_directory_identity_changed")
            result = 1
        elapsed = time.monotonic() - ENTRY
        if FIRED or INTERRUPTED or elapsed >= 52:
            PUBLIC.update(status="failed", error="original_deadline_or_interrupt")
            result = 1
        PUBLIC.update(deadline_fired=FIRED, interrupted=INTERRUPTED,
                      elapsed_observation_before_receipt_publication_seconds=elapsed,
                      partial_new_inputs_retained=result != 0)
        if armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
        if OUT_FD is not None:
            try:
                create("input-stage-result.public.json", (json.dumps(PUBLIC, sort_keys=True, indent=2) + "\n").encode())
            except BaseException:
                PUBLIC.update(status="failed", error="input_stage_receipt_failed")
                result = 1
        closed = 0
        for fd in (OUT_FD, PARENT_FD):
            if fd is not None:
                try:
                    os.close(fd)
                    closed += 1
                except OSError:
                    PUBLIC.update(status="failed", error="owned_directory_handle_close_failed")
                    result = 1
        PUBLIC["owned_directory_handles_closed"] = closed
        PUBLIC["all_owned_directory_handles_retired"] = closed == int(OUT_FD is not None) + int(PARENT_FD is not None)
        for n, handler in previous.items():
            signal.signal(n, handler)
        if armed:
            signal.setitimer(signal.ITIMER_REAL, *old_timer)
        os.umask(old_umask)
        if FIRED or INTERRUPTED:
            PUBLIC.update(status="failed", error="interrupted_during_final_cleanup")
            result = 1
        print(json.dumps(PUBLIC, sort_keys=True, separators=(",", ":")), flush=True)
    return result


# The exact 19 items are appended as one private base64 JSON literal at freeze.
