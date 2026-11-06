#!/usr/bin/env python3
"""Fixed LAN endpoint identity and two bind-close observations; SOURCE proposal."""
import ctypes
import hashlib
import hmac
import json
import os
import re
import signal
import socket
import stat
import sys
import time

SCHEMA = "heptabao.final-lan-endpoint-identity.v1"
ROLE = {
    "mac": ("Darwin", "arm64", "192.168.0.8"),
    "rog": ("Linux", "x86_64", "192.168.0.10"),
    "pocket4": ("Linux", "x86_64", "192.168.0.9"),
}
PORTS = (46230, 46231)
SECONDS = 15
STDOUT_MAX = 8192
DOMAIN = b"heptabao.final-lan-endpoint-identity.20261106.r1\0"
START = time.monotonic_ns()
UNTIL = START + SECONDS * 1000000000
PENDING = []
HANDLERS = []
RESOURCES = []
READS = []
SYSCTLS = []
PHASE = "argument_admission"
REPORT = {
    "schema": SCHEMA, "status": "failed", "failure": None,
    "role": None, "identity": None, "local_ports": [],
    "probe_process": {
        "pid": os.getpid(), "ppid": os.getppid(),
        "pgid": os.getpgrp(), "sid": os.getsid(0),
        "children_started_by_probe": 0,
        "python_executable": sys.executable,
        "python_version": list(sys.version_info[:3]),
    },
    "started_monotonic_ns": str(START), "absolute_deadline_monotonic_ns": str(UNTIL),
    "deadline_seconds": SECONDS, "reads": READS, "sysctls": SYSCTLS,
    "resources": RESOURCES, "signals": PENDING,
    "filesystem_writes": 0, "listen_calls": 0, "connect_calls": 0,
    "machine_or_boot_identifier_raw_emitted": False,
    "hardware_serial_or_hardware_uuid_read": False,
    "all_probe_resources_closed": False,
}

class Refusal(Exception):
    pass

def guard(ok, code):
    if not ok:
        raise Refusal(code)

def checkpoint():
    guard(not PENDING, "signal_observed")
    guard(time.monotonic_ns() < UNTIL, "absolute_deadline_exceeded")

def mark_signal(number, frame):
    # The handler never raises in an acquire/close gap.
    if number not in PENDING:
        PENDING.append(number)

def full9(info):
    return [str(value) for value in (
        info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)]

def read_fixed(path, maximum):
    checkpoint()
    row = {"kind": "file", "path": path, "acquired": False,
           "close_attempted": False, "closed": False, "close_error": None}
    RESOURCES.append(row)
    fd = None
    before = after = named = None
    raw = b""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        row["acquired"] = True
        before = os.fstat(fd)
        guard(stat.S_ISREG(before.st_mode), "identity_input_not_regular")
        guard(before.st_uid == 0 and before.st_nlink == 1
              and not before.st_mode & 0o022, "identity_input_metadata_refused")
        # procfs/sysfs sizes are not content length. The returned byte cap and
        # explicit EOF apply to these three exact kernel/system inputs.
        raw = os.read(fd, maximum + 1)
        guard(0 < len(raw) <= maximum, "identity_input_size_refused")
        guard(os.read(fd, 1) == b"", "identity_input_not_complete")
        after = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        guard(full9(before) == full9(after) == full9(named), "identity_input_changed")
    finally:
        if fd is not None:
            row["close_attempted"] = True
            try:
                os.close(fd)
                row["closed"] = True
            except OSError as error:
                row["close_error"] = error.errno
    guard(row["close_error"] is None and row["closed"], "identity_input_close_failed")
    READS.append({"path": path, "bytes": len(raw), "maximum": maximum,
                  "eof": True, "metadata_before_after_name": full9(before)})
    checkpoint()
    return raw

def sysctl_text(libc, key, maximum):
    checkpoint()
    output = ctypes.create_string_buffer(maximum)
    length = ctypes.c_size_t(maximum)
    ctypes.set_errno(0)
    result = libc.sysctlbyname(
        key, ctypes.cast(output, ctypes.c_void_p), ctypes.byref(length), None, 0)
    if result != 0:
        raise OSError(ctypes.get_errno(), "sysctl_read_failed")
    guard(1 < length.value <= maximum, "sysctl_size_refused")
    raw = output.raw[:length.value]
    guard(raw.endswith(b"\0") and b"\0" not in raw[:-1], "sysctl_string_refused")
    SYSCTLS.append({"key": key.decode("ascii"), "bytes_including_nul": length.value,
                    "maximum": maximum})
    checkpoint()
    return raw[:-1]

def hash_identifier(kind, raw, pattern):
    guard(re.fullmatch(pattern, raw) is not None, "identifier_format_refused")
    guard(int(raw.replace(b"-", b""), 16) != 0, "zero_identifier_refused")
    return hmac.new(DOMAIN + kind, raw.lower(), hashlib.sha256).hexdigest()

def public_model(raw):
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    guard(0 < len(raw) <= 128 and all(32 <= value <= 126 for value in raw),
          "model_format_refused")
    return raw.decode("ascii")

def snapshot(role):
    checkpoint()
    actual = os.uname()
    expected_system, expected_machine, address = ROLE[role]
    guard(actual.sysname == expected_system and actual.machine == expected_machine,
          "role_platform_mismatch")
    hostname = socket.gethostname()
    guard(re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", hostname) is not None,
          "hostname_format_refused")
    boot_pattern = rb"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
    if actual.sysname == "Linux":
        model = public_model(read_fixed("/sys/devices/virtual/dmi/id/product_name", 256))
        machine = read_fixed("/etc/machine-id", 64)
        boot = read_fixed("/proc/sys/kernel/random/boot_id", 64)
        if machine.endswith(b"\n"):
            machine = machine[:-1]
        if boot.endswith(b"\n"):
            boot = boot[:-1]
        machine_value = {"source": "/etc/machine-id",
            "hmac_sha256": hash_identifier(b"linux-machine-id", machine, rb"[0-9a-f]{32}")}
        boot_value = {"source": "/proc/sys/kernel/random/boot_id",
            "hmac_sha256": hash_identifier(b"linux-boot-id", boot, boot_pattern)}
        model_source = "/sys/devices/virtual/dmi/id/product_name"
    else:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.sysctlbyname.argtypes = [
            ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_void_p, ctypes.c_size_t]
        libc.sysctlbyname.restype = ctypes.c_int
        model = public_model(sysctl_text(libc, b"hw.model", 256))
        boot = sysctl_text(libc, b"kern.bootsessionuuid", 64)
        boot_value = {"source": "sysctl:kern.bootsessionuuid",
            "hmac_sha256": hash_identifier(b"darwin-boot-session-uuid", boot, boot_pattern)}
        model_source = "sysctl:hw.model"
        machine_value = None
    checkpoint()
    return {
        "hostname": hostname, "os": actual.sysname, "architecture": actual.machine,
        "uid": os.getuid(), "euid": os.geteuid(), "gid": os.getgid(),
        "model": {"source": model_source, "name": model},
        "boot_identity": boot_value, "machine_identity": machine_value,
        "machine_identity_not_requested_on_darwin": actual.sysname == "Darwin",
        "declared_lan_ipv4": address,
    }

def bind_close(address, port):
    checkpoint()
    row = {"kind": "socket", "address": address, "port": port, "acquired": False,
           "close_attempted": False, "closed": False, "close_error": None}
    RESOURCES.append(row)
    endpoint = None
    bound = False
    try:
        endpoint = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        row["acquired"] = True
        # No SO_REUSEADDR/PORT, listen, connect, accept, or traffic.
        endpoint.bind((address, port))
        bound = True
    finally:
        if endpoint is not None:
            row["close_attempted"] = True
            try:
                endpoint.close()
                row["closed"] = True
            except OSError as error:
                row["close_error"] = error.errno
    guard(row["closed"] and row["close_error"] is None, "port_close_failed")
    REPORT["local_ports"].append({
        "address": address, "port": port, "bound": bound, "closed": True,
        "listen_called": False, "connect_called": False,
        "reservation_retained": False})
    checkpoint()

try:
    guard(len(sys.argv) == 2 and sys.argv[1] in ROLE, "fixed_role_required")
    role = sys.argv[1]
    REPORT["role"] = role
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGALRM):
        previous = signal.signal(number, mark_signal)
        HANDLERS.append((number, previous))
    checkpoint()
    previous_timer = signal.setitimer(signal.ITIMER_REAL, (UNTIL - time.monotonic_ns()) / 1000000000)
    guard(previous_timer == (0.0, 0.0), "preexisting_timer_refused")
    PHASE = "identity_before"
    before = snapshot(role)
    REPORT["identity"] = before
    PHASE = "fixed_ports"
    for port in PORTS:
        bind_close(before["declared_lan_ipv4"], port)
    PHASE = "identity_after"
    after = snapshot(role)
    guard(after == before, "identity_changed")
    REPORT["identity_stable_before_after"] = True
    checkpoint()
    REPORT["status"] = "passed"
except BaseException as error:
    REPORT["status"] = "failed"
    REPORT["failure"] = {
        "phase": PHASE,
        "code": str(error) if type(error) is Refusal else "observation_error",
        "error_type": type(error).__name__,
        "errno": error.errno if isinstance(error, OSError) else None,
    }
finally:
    # Every returned file/socket handle was closed exactly once in its own
    # non-throwing signal region. There is no second close/retry or fallback.
    closed = all(not row["acquired"] or
                 (row["close_attempted"] and row["closed"]
                  and row["close_error"] is None) for row in RESOURCES)
    REPORT["all_probe_resources_closed"] = closed
    if not closed or PENDING or time.monotonic_ns() >= UNTIL:
        REPORT["status"] = "failed"
        REPORT["failure"] = REPORT["failure"] or {
            "phase": "finalization", "code": "closure_signal_or_deadline_refused",
            "error_type": "Refusal", "errno": None}
    try:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for number, previous in reversed(HANDLERS):
            signal.signal(number, previous)
    except BaseException as error:
        REPORT["status"] = "failed"
        REPORT["failure"] = {
            "phase": "signal_restoration", "code": "signal_restoration_failed",
            "error_type": type(error).__name__, "errno": None}
    REPORT["finished_monotonic_ns"] = str(time.monotonic_ns())
    if int(REPORT["finished_monotonic_ns"]) >= UNTIL:
        REPORT["status"] = "failed"
        REPORT["failure"] = REPORT["failure"] or {
            "phase": "terminal_deadline", "code": "absolute_deadline_exceeded",
            "error_type": "Refusal", "errno": None}

raw = (json.dumps(REPORT, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
if len(raw) > STDOUT_MAX:
    raw = b'{"schema":"heptabao.final-lan-endpoint-identity.v1","status":"failed","failure":{"code":"public_report_cap"}}\n'
    REPORT["status"] = "failed"
try:
    offset = 0
    while offset < len(raw):
        count = os.write(1, raw[offset:offset + 4096])
        if count <= 0:
            raise OSError("stdout_write_failed")
        offset += count
except BaseException:
    raise SystemExit(2)
raise SystemExit(0 if REPORT["status"] == "passed" and time.monotonic_ns() < UNTIL else 1)
