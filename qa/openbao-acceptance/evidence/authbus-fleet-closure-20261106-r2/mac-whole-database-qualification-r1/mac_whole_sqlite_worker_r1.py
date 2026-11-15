#!/usr/bin/env python3
"""One fixed-root synthetic whole-database qualification inside the kernel sandbox."""
import errno
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import stat
import sys
import time

ROOT = Path("/Users/qianqi/heptabao-authbus-whole-database-qualification-20261106-r1")
START = time.monotonic()
UNTIL = float(sys.argv[1])
sys.path.insert(0, str(ROOT / "code"))
from qualify_whole_sqlite_bundle_r1 import run_qualification
from whole_sqlite_bundle_r1 import full9, need, SnapshotRefused

fds = []
report = {"schema": "heptabao.actual-mac-whole-sqlite-qualification-worker.r1", "ok": False,
          "productionReads": 0, "productionWrites": 0, "providerCalls": 0, "serviceActions": 0,
          "sdkImported": False, "productionRollbackQualified": False}


def read(path, cap):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    row = {"closeAttempts": 0, "closed": False}
    fds.append(row)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == 501
             and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= cap,
             "whole_worker_fixed_input_custody")
        raw = bytearray()
        while len(raw) <= before.st_size:
            need(time.monotonic() < UNTIL, "whole_worker_absolute_deadline")
            part = os.read(fd, min(65536, before.st_size + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        need(len(raw) == before.st_size and full9(before) == full9(os.fstat(fd)) == full9(path.lstat()),
             "whole_worker_complete_stable_input")
        return bytes(raw)
    finally:
        row["closeAttempts"] += 1
        os.close(fd)
        row["closed"] = True


try:
    os.umask(0o077)
    need(sys.platform == "darwin" and os.getuid() == 501 and START < UNTIL <= START + 30,
         "actual_mac_original_whole_worker_deadline")
    for name, flags in (("protected-read", os.O_RDONLY), ("protected-write", os.O_WRONLY)):
        try:
            fd = os.open(ROOT / name, flags | os.O_NOFOLLOW)
        except OSError as error:
            need(error.errno in (errno.EACCES, errno.EPERM), "whole_worker_kernel_file_refusal")
        else:
            os.close(fd)
            raise SnapshotRefused("whole_worker_kernel_protected_file_allowed")
    sock = socket.socket()
    try:
        sock.settimeout(min(1, UNTIL - time.monotonic()))
        try:
            sock.connect(("127.0.0.1", 9))
        except OSError as error:
            need(error.errno in (errno.EACCES, errno.EPERM), "whole_worker_kernel_network_refusal")
        else:
            raise SnapshotRefused("whole_worker_kernel_network_allowed")
    finally:
        sock.close()
    report["kernelReadWriteNetworkRefusalsObserved"] = True
    report["originalProbeSocketClosed"] = sock.fileno() == -1
    plan = json.loads(read(ROOT / "code/plan.public.json", 131072))
    need(plan["schema"] == "heptabao.synthetic-whole-sqlite-plan.r1"
         and plan["sourceVfs"] == "unix-posix" and plan["maximumDatabaseBytes"] == 67108864,
         "fixed_whole_database_plan")
    for name, pin in plan["sourcePins"].items():
        need(name in ("whole_sqlite_bundle_r1.py", "qualify_whole_sqlite_bundle_r1.py", "mac_whole_sqlite_worker_r1.py"),
             "fixed_three_whole_sources")
        need(hashlib.sha256(read(ROOT / "code" / name, 65536)).hexdigest() == pin,
             "same_whole_database_source_bytes")
    agent = read(ROOT / "code/agent-schema.sql", 65536)
    state = read(ROOT / "code/state-schema.sql", 65536)
    need(hashlib.sha256(agent).hexdigest() == plan["schemaPins"]["agent"]
         and hashlib.sha256(state).hexdigest() == plan["schemaPins"]["state"],
         "actual_installed_generated_sql_bytes")
    result = run_qualification(ROOT / "output/fixture", agent.decode(), state.decode(),
                               until=UNTIL, source_vfs="unix-posix")
    report["qualification"] = result
    report["pythonVersion"] = sys.version.split()[0]
    report["sqliteVersion"] = sqlite3.sqlite_version
    report["sourcePins"] = plan["sourcePins"]
    report["installedSchemaSourcePins"] = plan["installedSchemaSourcePins"]
    report["ok"] = result["ok"] and result["resources"]["restoreCompleted"]
except BaseException as error:
    report["ok"] = False
    report["errorType"] = type(error).__name__
    report["errorCode"] = str(error) if isinstance(error, SnapshotRefused) else "whole_worker_qualification_refused"
finally:
    report["explicitInputDescriptors"] = fds
    report["allExplicitInputDescriptorsClosedOnce"] = all(r["closeAttempts"] == 1 and r["closed"] for r in fds)
    report["elapsedSeconds"] = time.monotonic() - START
    if not report["allExplicitInputDescriptorsClosedOnce"] or time.monotonic() >= UNTIL:
        report["ok"] = False
    print(json.dumps(report, sort_keys=True, separators=(",", ":")), flush=True)
raise SystemExit(0 if report["ok"] else 1)
