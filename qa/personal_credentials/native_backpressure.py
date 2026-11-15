#!/usr/bin/env python3
"""Real Linux pipe regression: a stalled native reader cannot retain an unlocked vault.

This uses independently launched vault/native-host binaries and synthetic data.
It does not launch Chromium, use sockets, or qualify browser/platform adoption.
Only a newly created private fixture is removed; no existing vault is opened.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import stat
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = frozenset({
    "native_unlock_accepted", "backpressure_capacity_established",
    "native_exits_without_draining_stdout", "native_reports_bounded_output_failure",
    "independent_process_reopens_vault", "diagnostics_redact_synthetic_credentials",
    "original_process_reaped", "binary_identity_unchanged",
})


class Failure(Exception):
    """A fixed public case label, never a request or process payload."""


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def vault_call(binary: Path, root: Path, command: str, request: dict) -> tuple[int, dict, bytes]:
    completed = subprocess.run([str(binary), str(root), command],
        input=json.dumps(request).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    try:
        result = json.loads(completed.stdout or completed.stderr)
    except (ValueError, UnicodeError) as error:
        raise Failure("vault_response_not_json") from error
    if not isinstance(result, dict):
        raise Failure("vault_response_not_object")
    return completed.returncode, result, completed.stderr


def send_frame(process: subprocess.Popen, request: dict) -> None:
    raw = json.dumps({"id": 1, "request": request}).encode()
    process.stdin.write(struct.pack("=I", len(raw)) + raw)
    process.stdin.flush()


def read_exact(process: subprocess.Popen, size: int, deadline: float) -> bytes:
    result = bytearray()
    while len(result) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
            raise Failure("native_initial_reply_timeout")
        chunk = os.read(process.stdout.fileno(), size - len(result))
        if not chunk:
            raise Failure("native_initial_reply_incomplete")
        result.extend(chunk)
    return bytes(result)


def initial_reply(process: subprocess.Popen) -> dict:
    deadline = time.monotonic() + 10
    length = struct.unpack("=I", read_exact(process, 4, deadline))[0]
    if not 0 < length <= 131072:
        raise Failure("native_initial_reply_bound")
    try:
        value = json.loads(read_exact(process, length, deadline))
    except (ValueError, UnicodeError) as error:
        raise Failure("native_initial_reply_not_json") from error
    if not isinstance(value, dict):
        raise Failure("native_initial_reply_not_object")
    return value


def execute(bin_dir: Path, report: dict) -> None:
    binary = bin_dir / "heptabao-browser"
    vault_binary = bin_dir / "heptabao-vault"
    before = {path.name: sha(path) for path in (binary, vault_binary)}
    report["binary_sha256"] = before
    report["profile_sha256"] = sha(Path(__file__))
    process = None
    diagnostic_bytes = bytearray()

    def check(name: str, passed: bool) -> None:
        if name not in EXPECTED or any(row["case"] == name for row in report["checks"]):
            raise Failure("invalid_case_definition")
        report["checks"].append({"case": name, "passed": bool(passed)})
        if not passed and report.get("failure") is None:
            report["failure"] = name

    with tempfile.TemporaryDirectory(prefix="heptabao-native-backpressure-") as created:
        base = Path(created).resolve()
        base.chmod(0o700)
        vault = base / "vault"
        vault.mkdir(mode=0o700)
        password = "synthetic-native-master-" + secrets.token_urlsafe(24)
        marker = "synthetic-native-secret-" + secrets.token_hex(16)
        secret = marker + "x" * (65536 - len(marker))
        username = "synthetic-native-account"
        origin = "https://login.example.test"
        item_id = "synthetic-backpressure-item"
        code, value, diagnostics = vault_call(vault_binary, vault, "init", {
            "password": password, "output": str(base / "recovery.private.json")})
        diagnostic_bytes.extend(diagnostics)
        if code != 0 or value.get("ok") is not True:
            raise Failure("synthetic_vault_initialization")
        code, value, diagnostics = vault_call(vault_binary, vault, "put", {
            "password": password, "expected_revision": 0,
            "item": {"id": item_id, "kind": "login", "title": "Synthetic backpressure",
                "username": username, "origin": origin, "secret": secret, "notes": "", "totp": None}})
        diagnostic_bytes.extend(diagnostics)
        if code != 0 or value.get("ok") is not True:
            raise Failure("synthetic_vault_population")
        config = base / "native.private.json"
        descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump({"vault_root": str(vault), "extension_id": "a" * 32, "unlock_seconds": 2}, stream)
        try:
            process = subprocess.Popen([str(binary), "--config", str(config), "chrome-extension://" + "a" * 32 + "/"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            report["original_pid"] = process.pid
            # Operate only on our own pipe. A 4 KiB buffer makes the attempted
            # 64 KiB credential response deterministically hit backpressure.
            fcntl.fcntl(process.stdout.fileno(), fcntl.F_SETPIPE_SZ, 4096)
            capacity = fcntl.fcntl(process.stdout.fileno(), fcntl.F_GETPIPE_SZ)
            report["pipe_capacity_bytes"] = capacity
            check("backpressure_capacity_established", capacity < len(secret))
            send_frame(process, {"op": "unlock", "password": password})
            reply = initial_reply(process)
            check("native_unlock_accepted", reply.get("ok") is True and reply.get("result", {}).get("locked") is False)
            if not report["checks"][-1]["passed"]:
                raise Failure("native_unlock_accepted")
            send_frame(process, {"op": "fill", "origin": origin, "item_id": item_id, "top_frame": True})
            started = time.monotonic()
            try:
                process.wait(timeout=3)
                exited_without_drain = True
            except subprocess.TimeoutExpired:
                exited_without_drain = False
            report["exit_wait_ms"] = round((time.monotonic() - started) * 1000, 3)
            check("native_exits_without_draining_stdout", exited_without_drain)
            # Leave the unread fill frame in the pipe during this independent
            # process probe. Draining it would hide the original retention bug.
            code, value, diagnostics = vault_call(vault_binary, vault, "list", {"password": password})
            diagnostic_bytes.extend(diagnostics)
            check("independent_process_reopens_vault", code == 0 and value.get("ok") is True)
        finally:
            if process is not None:
                if process.poll() is None:
                    process.kill()  # Our original handle only, never a PID lookup.
                process.wait(timeout=3)
                native_stderr = process.stderr.read(131073)
                diagnostic_bytes.extend(native_stderr)
                report["exit_code"] = process.returncode
                check("native_reports_bounded_output_failure", process.returncode == 1 and native_stderr.strip() == b"output_unavailable")
                check("original_process_reaped", process.returncode is not None)
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()
        check("diagnostics_redact_synthetic_credentials", all(value.encode() not in diagnostic_bytes for value in (password, marker, username)))
    after = {path.name: sha(path) for path in (binary, vault_binary)}
    check("binary_identity_unchanged", before == after)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, default=ROOT / "target" / "debug")
    parser.add_argument("--report", type=Path, help="new report path in an existing owned 0700 directory")
    args = parser.parse_args()
    os.umask(0o077)
    if not hasattr(fcntl, "F_SETPIPE_SZ") or not hasattr(fcntl, "F_GETPIPE_SZ"):
        parser.error("this pipe-capacity regression requires Linux")
    output = args.report.absolute() if args.report else None
    if output:
        info = output.parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700 or os.path.lexists(output):
            parser.error("report requires an absent file in an owned private directory")
    report = {"schema": "heptabao.personal-credentials.native-backpressure.v1", "checks": [],
        "expected_count": len(EXPECTED), "required_cases": sorted(EXPECTED), "failure": None,
        "synthetic_only": True, "real_native_process_and_pipe": True, "real_browser": False,
        "fill_stdout_drained": False, "browser_or_production_qualified": False,
        "source_build_provenance_asserted": False, "configured_unlock_seconds": 2,
        "started_unix_ns": time.time_ns()}
    try:
        execute(args.bin_dir.resolve(strict=True), report)
    except Exception as error:
        report["failure"] = report.get("failure") or (str(error) if isinstance(error, Failure) else type(error).__name__)
    report["missing_cases"] = sorted(EXPECTED - {row["case"] for row in report["checks"]})
    report["passed_count"] = sum(row["passed"] for row in report["checks"])
    report["status"] = "passed" if report["failure"] is None and not report["missing_cases"] and report["passed_count"] == len(EXPECTED) else "failed"
    report["finished_unix_ns"] = time.time_ns()
    data = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if output:
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    print(data, end="")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
