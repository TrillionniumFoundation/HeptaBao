#!/usr/bin/env python3
"""Foreground owner for one synthetic native HA child; never restarts it.

The direct LAN caller selects only its observed Darwin/native node. This
helper changes process custody, not TLS, data, Raft, environment, cwd or argv.
Its stdin stays attached to one owned SSH client for the child's lifetime.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import select
import shlex
import signal
import stat
import subprocess
import sys
import threading
import time


START_SECONDS = 60.0       # The existing process_action SSH deadline.
STOP_SECONDS = 5.0         # The existing remote stop deadline; no success grace.
HEARTBEAT_SECONDS = 2.0
PARENT_SILENCE_SECONDS = 10.0
MAX_LINE = 16384
MIB = 1024 * 1024
SCHEMA = "heptabao.native-ha-foreground-owner.v1"


class Refusal(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refusal(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def new_file(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())


def owned_file(path, *, limit=MIB, collect=True, executable=False, private=True):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "canonical_file_required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid in ((os.geteuid(),) if private else (0, os.geteuid()))
             and before.st_nlink == 1 and not before.st_mode & (0o077 if private else 0o022)
             and 0 < before.st_size <= limit, "owned_file_required")
        if executable:
            need(before.st_mode & stat.S_IXUSR, "owned_executable_required")
        h, size, chunks = hashlib.sha256(), 0, []
        while True:
            part = os.read(fd, MIB)
            if not part:
                break
            h.update(part)
            size += len(part)
            need(size <= limit, "owned_file_bound_exceeded")
            if collect:
                chunks.append(part)
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                    info.st_ctime_ns, info.st_uid, info.st_mode, info.st_nlink)
        need(size == before.st_size and identity(before) == identity(os.fstat(fd))
             == identity(path.stat()), "owned_file_changed")
        return h.hexdigest(), b"".join(chunks)
    finally:
        os.close(fd)


def ps_rows(pid=None, *, seconds=0.5):
    argv = ["/bin/ps"]
    argv += ["-p", str(pid)] if pid is not None else ["-ax"]
    argv += ["-o", "pid=,ppid=,pgid=,uid=,stat=,lstart="]
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=dict(os.environ, LC_ALL="C"),
                            timeout=seconds)
    need(len(result.stdout) <= 2 * MIB and len(result.stderr) <= 65536,
         "process_projection_bound")
    if pid is not None and result.returncode == 1 and not result.stdout.strip():
        return []
    need(result.returncode == 0, "process_projection_unavailable")
    rows = []
    for line in result.stdout.decode("ascii").splitlines():
        fields = line.split(None, 5)
        need(len(fields) == 6, "process_projection_malformed")
        rows.append({"pid": int(fields[0]), "ppid": int(fields[1]),
                     "pgid": int(fields[2]), "uid": int(fields[3]),
                     "state": fields[4], "start": fields[5]})
    if pid is not None:
        need(len(rows) == 1 and rows[0]["pid"] == pid, "process_projection_ambiguous")
    return rows


def stable(row):
    return {key: row[key] for key in ("pid", "ppid", "pgid", "uid", "start")}


def require_waitid():
    need(all(hasattr(os, name) for name in ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT",
                                          "CLD_EXITED", "CLD_KILLED", "CLD_DUMPED")),
         "wnowait_required_no_child_started")
    need(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
         "direct_child_reaping_policy_changed")


def exit_observation(child):
    """This is an observation, never Popen.poll/wait/communicate."""
    need(child.returncode is None, "child_already_reaped_no_signal")
    event = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    if event is None:
        return None
    need(event.si_pid == child.pid and event.si_signo == signal.SIGCHLD
         and event.si_code in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED),
         "child_exit_identity_changed")
    # Darwin reports si_uid=0 even for an observed uid501 child. Actual UID is
    # bound independently by ps; si_uid never grants ownership here.
    return {"pid": event.si_pid, "signo": event.si_signo, "code": event.si_code, "status": event.si_status}


def capture_child(child):
    require_waitid()
    rows = ps_rows(child.pid)
    need(len(rows) == 1, "owned_child_identity_missing")
    row = rows[0]
    need(row["ppid"] == os.getpid() and row["pgid"] == child.pid
         and row["uid"] == os.geteuid(), "owned_child_scope_mismatch")
    # Darwin keeps an unreaped zombie in ps but getpgid/getsid return ESRCH.
    # Use the real live APIs only for a still-live child; otherwise independently
    # repeat WNOWAIT and retain ps plus Popen direct-parent custody.
    event, live_sid = exit_observation(child), None
    if event is None and not row["state"].startswith("Z"):
        try:
            need(os.getpgid(child.pid) == child.pid and os.getsid(child.pid) == child.pid,
                 "owned_live_session_mismatch")
            live_sid = child.pid
        except ProcessLookupError:
            # A fast exit between the first ps/waitid and a live API call is
            # not loss of Popen custody, nor proof that the group is empty.
            event = exit_observation(child)
            need(event is not None, "owned_live_api_failed_without_retained_exit")
    if event is not None or row["state"].startswith("Z"):
        event = exit_observation(child)
        fresh = ps_rows(child.pid)
        need(event is not None and len(fresh) == 1 and stable(fresh[0]) == stable(row)
             and fresh[0]["state"].startswith("Z") and exit_observation(child) == event,
             "owned_exit_not_retained")
        row = fresh[0]
    return {"ps": stable(row), "sid_observed_while_live": live_sid,
            "captured_exit": event}


def verify_unreaped(child, owner):
    event = exit_observation(child)
    rows = ps_rows(child.pid)
    need(len(rows) == 1 and stable(rows[0]) == owner["ps"]
         and rows[0]["ppid"] == os.getpid(), "owned_child_identity_changed_no_signal")
    if event is None and not rows[0]["state"].startswith("Z"):
        # Exact ps PGID/start plus direct Popen/WNOWAIT custody keeps the
        # originally observed session leader reserved. Do not race a normal
        # exit by consulting Darwin's zombie-unsupported getpgid/getsid here.
        need(owner["ps"]["pgid"] == child.pid, "owned_live_session_changed_no_signal")
    else:
        event = exit_observation(child)
        need(event is not None and rows[0]["state"].startswith("Z") and exit_observation(child) == event,
             "owned_zombie_identity_changed_no_signal")
    return event


def live_group(child, owner, *, until):
    need(time.monotonic() < until, "original_stop_deadline_expired")
    verify_unreaped(child, owner)
    rows = ps_rows(seconds=min(0.5, max(0.01, until - time.monotonic())))
    selected = [row for row in rows if row["pgid"] == child.pid and not row["state"].startswith("Z")]
    need(all(row["uid"] == os.geteuid() for row in selected), "owned_group_uid_changed_no_signal")
    return [stable(row) for row in selected]


def stop_unreaped(child, owner, *, until):
    """Original SIGKILL fault, with original PID reserved until group is empty."""
    need(time.monotonic() < until, "original_stop_deadline_expired")
    before = live_group(child, owner, until=until)
    receipt = {"leader_pid": child.pid, "pgid": child.pid, "ownership_verified": True,
               "leader_reaped": False, "owned_live_group_empty": False,
               "live_group_before": before, "signals": []}
    if before:
        verify_unreaped(child, owner)
        need(time.monotonic() < until, "original_stop_deadline_expired")
        os.killpg(child.pid, signal.SIGKILL)
        receipt["signals"].append("SIGKILL")
    while True:
        remaining = live_group(child, owner, until=until)
        event = exit_observation(child)
        if not remaining and event is not None:
            break
        need(time.monotonic() < until, "original_stop_deadline_expired")
        time.sleep(min(0.02, max(0, until - time.monotonic())))
    receipt.update(live_group_before_leader_reap=remaining, retained_exit=event,
                   owned_live_group_empty=True)
    # No group signal or membership inference follows this first reap.
    child.wait(timeout=max(0.001, until - time.monotonic()))
    receipt.update(leader_reaped=True, leader_exit_code=child.returncode,
                   within_original_deadline=time.monotonic() < until)
    need(receipt["within_original_deadline"], "original_stop_deadline_expired")
    return receipt


def public_parent_chain(pid):
    chain = []
    for _ in range(6):
        if pid <= 0 or any(row["pid"] == pid for row in chain):
            break
        rows = ps_rows(pid)
        if not rows:
            break
        chain.append(stable(rows[0]))
        pid = rows[0]["ppid"]
    return chain


def append_event(root, launch_id, pid, event):
    path = root / "pids.log"
    if path.exists():
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and not path.is_symlink()
             and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
             "owned_process_log_required")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a") as stream:
        stream.write(str(time.time()) + " " + str(pid) + " " + event + " " + launch_id + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def validate_payload(payload):
    need(isinstance(payload, dict) and set(payload) == {
        "schema", "root", "run_id", "launch_id", "binary_sha256", "helper_sha256",
        "source_commit", "source_tree", "expected_system", "expected_host",
        "python_path", "python_sha256"}, "owner_input_contract")
    need(payload["schema"] == SCHEMA and payload["expected_system"] in ("Darwin", "Linux")
         and platform.system() == payload["expected_system"] and platform.node() == payload["expected_host"],
         "owner_actual_host_mismatch")
    for key, length in (("run_id", 32), ("launch_id", 32), ("binary_sha256", 64),
                        ("helper_sha256", 64), ("python_sha256", 64),
                        ("source_commit", 40), ("source_tree", 40)):
        need(re.fullmatch("[0-9a-f]{" + str(length) + "}", payload[key]) is not None,
             "owner_exact_source_identity_required")
    root = Path(payload["root"])
    need(root.is_absolute() and root.resolve(strict=True) == root and not root.is_symlink(),
         "owner_canonical_root_required")
    info = root.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
         "owner_private_root_required")
    marker = json.loads(owned_file(root / "native-ha-fixture.json")[1])
    need(marker.get("run_id") == payload["run_id"] and marker.get("root") == str(root)
         and marker.get("production_authority") is False and marker.get("root_device") == info.st_dev
         and marker.get("root_inode") == info.st_ino, "owner_fixture_custody_mismatch")
    return root


def serve(payload):
    started = time.monotonic()
    require_waitid()  # Refuse before creating a child on an unsupported interpreter.
    root = validate_payload(payload)
    python_path = Path(sys.executable).resolve(strict=True)
    need(Path(payload["python_path"]).is_absolute()
         and Path(payload["python_path"]).resolve(strict=True) == python_path,
         "owner_python_path_changed")
    need(owned_file(python_path, limit=16 * MIB, collect=False, executable=True,
                    private=False)[0] == payload["python_sha256"], "owner_python_binary_changed")
    need(owned_file(Path(__file__).resolve())[0] == payload["helper_sha256"], "owner_helper_changed")
    need(owned_file(root / "heptabao-server", limit=2 * 1024 ** 3,
                    collect=False, executable=True)[0] == payload["binary_sha256"], "owner_binary_changed")
    for name in ("server.json", "ha.json"):
        owned_file(root / name)
    need(time.monotonic() < started + START_SECONDS, "original_start_deadline_expired")
    pid_path, identity_path = root / "process.pid", root / "process.identity.json"
    active_path = root / "foreground-watchdog.active.json"
    need(not any(path.exists() or path.is_symlink() for path in (pid_path, identity_path, active_path)),
         "existing_owned_process_or_unknown_start_no_retry")
    directory = root / "foreground-watchdog"
    if not directory.exists():
        directory.mkdir(mode=0o700)
    info = directory.lstat()
    need(stat.S_ISDIR(info.st_mode) and not directory.is_symlink() and info.st_uid == os.geteuid()
         and not info.st_mode & 0o077, "owner_launch_directory_invalid")
    phase = directory / payload["launch_id"]
    phase.mkdir(mode=0o700)  # A consumed launch ID can never run a second child.
    active = canonical({"run_id": payload["run_id"], "launch_id": payload["launch_id"],
                        "helper_sha256": payload["helper_sha256"]})
    new_file(active_path, active)
    argv = [str(root / "heptabao-server"), "--config", str(root / "server.json"),
            "--ha-config", str(root / "ha.json"), "--experimental-native-v6-ha"]
    intent = dict(payload, argv=argv, submission_count=1, automatic_restart=False,
                  production_authority=False, python_executable=sys.executable,
                  python_version=platform.python_version(), original_start_seconds=START_SECONDS,
                  original_stop_seconds=STOP_SECONDS, inherited_environment=True, inherited_cwd=True)
    intent["python_identity"] = {"invoked": payload["python_path"], "executable": sys.executable,
                               "realpath": str(python_path), "bytes": python_path.stat().st_size,
                               "sha256": payload["python_sha256"], "version": platform.python_version(),
                               "scope": "interpreter-binary-only-not-recursive-stdlib"}
    new_file(phase / "intent.json", canonical(intent))
    child, owner, identity_bytes = None, None, None
    receipt = dict(schema=SCHEMA, run_id=payload["run_id"], launch_id=payload["launch_id"],
                   helper_sha256=payload["helper_sha256"], binary_sha256=payload["binary_sha256"],
                   source_commit=payload["source_commit"], source_tree=payload["source_tree"],
                   ready=False, stopped=False, submission_count=0, automatic_restart=False,
                   production_authority=False, heartbeat_count=0,
                   python_identity=intent["python_identity"])
    def emit(value):
        raw = canonical(value)
        need(len(raw) <= MAX_LINE, "owner_protocol_output_bound")
        os.write(sys.stdout.fileno(), raw)
    reason, error_code = "owner_preflight_failed", None
    try:
        log_path = root / "process.log"
        fd = os.open(log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "ab") as output:
            info = os.fstat(output.fileno())
            need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
                 "owner_process_log_invalid")
            # These native argv/env/cwd/session flags match the original daemon.
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                     start_new_session=True, close_fds=True)
        receipt["submission_count"] = 1
        owner = capture_child(child)
        receipt["child_identity"] = owner
        new_file(phase / "child-identity.json", canonical(owner))
        identity_bytes = canonical({"platform": platform.system(), "pid": child.pid,
                                    "start": owner["ps"]["start"], "executable": argv[0],
                                    "command": " ".join(argv)})
        new_file(identity_path, identity_bytes)
        new_file(pid_path, (str(child.pid) + "\n").encode())
        time.sleep(0.4)  # Preserve the original readiness stabilization interval.
        need(verify_unreaped(child, owner) is None, "owned_child_exited_before_ready")
        receipt["parent_chain_at_ready"] = public_parent_chain(child.pid)
        need(time.monotonic() < started + START_SECONDS, "original_start_deadline_expired")
        receipt.update(ready=True, owner_pid=os.getpid(), owner_ppid=os.getppid(),
                       python_executable=sys.executable, python_version=platform.python_version())
        new_file(phase / "ready.json", canonical(receipt))
        append_event(root, payload["launch_id"], child.pid, "started")
        emit(dict(receipt, event="ready"))
        last_parent, pending = time.monotonic(), b""
        while True:
            if verify_unreaped(child, owner) is not None:
                reason = "native_child_exited_without_requested_stop"
                break
            if time.monotonic() - last_parent >= PARENT_SILENCE_SECONDS:
                reason = "foreground_parent_heartbeat_expired"
                break
            readable, _, _ = select.select([sys.stdin.fileno()], [], [], 0.1)
            if not readable:
                continue
            part = os.read(sys.stdin.fileno(), 4096)
            if not part:
                reason = "foreground_parent_stdin_eof"
                break
            pending += part
            need(len(pending) <= MAX_LINE, "owner_protocol_input_bound")
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                command = json.loads(line)
                need(isinstance(command, dict) and set(command) == {"op", "launch_id"}
                     and command["launch_id"] == payload["launch_id"]
                     and command["op"] in ("heartbeat", "kill"), "owner_protocol_command_refused")
                if command["op"] == "kill":
                    reason = "explicit_original_sigkill"
                    break
                last_parent = time.monotonic()
                receipt["heartbeat_count"] += 1
            if reason == "explicit_original_sigkill":
                break
    except BaseException as error:
        error_code = str(error) if isinstance(error, Refusal) else type(error).__name__
        reason = "owner_failure"
    finally:
        terminal_until = time.monotonic() + STOP_SECONDS
        receipt["stop_reason"] = reason
        if error_code is not None:
            receipt["error_code"] = error_code
        if child is not None:
            try:
                if owner is None:
                    owner = capture_child(child)
                    receipt["child_identity"] = owner
                receipt["cleanup"] = stop_unreaped(child, owner, until=terminal_until)
                for path, expected in ((pid_path, (str(child.pid) + "\n").encode()),
                                       (identity_path, identity_bytes)):
                    if path.exists():
                        need(expected is not None and owned_file(path)[1] == expected,
                             "owner_identity_file_changed_no_unlink")
                        path.unlink()
                need(owned_file(active_path)[1] == active, "owner_active_file_changed_no_unlink")
                active_path.unlink()
                append_event(root, payload["launch_id"], child.pid, "stopped")
                receipt["stopped"] = True
            except BaseException as error:
                receipt["cleanup_error_code"] = str(error) if isinstance(error, Refusal) else type(error).__name__
        else:
            # The retained active intent intentionally prevents uncertain reuse.
            receipt["cleanup"] = {"leader_reaped": False, "owned_live_group_empty": False,
                                  "no_child_created": True}
        # A file cannot attest the duration of its own unfinished fsync. This
        # retained record proves identity/cleanup only; it must never grant a
        # successful stop budget during later independent reconciliation.
        retained = dict(receipt, ok=False, terminal_within_original_stop_deadline=None,
                        qualification_scope="cleanup-observed-only; stop budget requires live controller delivery")
        new_file(phase / "terminal.json", canonical(retained))
        # Successful wire delivery is checked after this fsync and again by
        # the caller against its original absolute stop deadline.
        receipt["terminal_within_original_stop_deadline"] = time.monotonic() < terminal_until
        receipt["ok"] = bool(receipt["stopped"] and receipt["terminal_within_original_stop_deadline"]
                             and error_code is None and reason == "explicit_original_sigkill")
        try:
            emit(dict(receipt, event="terminal"))
        except (BrokenPipeError, OSError):
            pass  # Retained terminal.json is the independent reconciliation path.
    return 0 if receipt["ok"] else 1


class ForegroundSession:
    """One owned SSH child and one remote launch nonce; no automatic retry."""

    def __init__(self, node, run_id, work, expected_binary, helper, *, source_commit,
                 source_tree, actual_host, python_path, python_sha256):
        need(actual_host["system"] == "Darwin", "foreground_lane_requires_actual_darwin")
        self.node, self.work = node, Path(work)
        self.launch_id = secrets.token_hex(16)
        self.helper = Path(helper).resolve(strict=True)
        self.payload = {"schema": SCHEMA, "root": node.root, "run_id": run_id,
                        "launch_id": self.launch_id, "binary_sha256": expected_binary,
                        "helper_sha256": digest(self.helper.read_bytes()),
                        "source_commit": source_commit, "source_tree": source_tree,
                        "expected_system": actual_host["system"], "expected_host": actual_host["host"],
                        "python_path": python_path, "python_sha256": python_sha256}
        self.phase = self.work / ("foreground-node-" + str(node.node_id) + "-" + self.launch_id)
        self.phase.mkdir(mode=0o700)
        self.child = self.owner = self.thread = None
        self.ready = self.terminal = self.failure = self.local_cleanup = None
        self.eof = self.kill_sent = self.completed = False
        self.stop_started = self.stop_until = None
        self._lock, self._send_lock = threading.Lock(), threading.Lock()
        self._end, self._changed = threading.Event(), threading.Event()
        self._heartbeat = True
        self.receipt = {"schema": SCHEMA, "node": node.node_id, "alias": node.alias,
                        "run_id": run_id, "launch_id": self.launch_id,
                        "helper_sha256": self.payload["helper_sha256"],
                        "binary_sha256": expected_binary, "source_commit": source_commit,
                        "source_tree": source_tree, "submission_count": 0,
                        "automatic_restart": False, "original_start_seconds": START_SECONDS,
                        "original_stop_seconds": STOP_SECONDS, "production_authority": False}

    def _signal_change(self):
        self._changed.set()

    def _send(self, operation):
        with self._send_lock:
            if operation == "heartbeat" and not self._heartbeat:
                return
            if operation == "kill":
                need(not self.kill_sent, "original_sigkill_already_submitted_no_retry")
                self.kill_sent = True
                self._heartbeat = False
            raw = canonical({"op": operation, "launch_id": self.launch_id})
            need(self.child is not None and self.child.stdin is not None,
                 "foreground_channel_not_owned")
            written = os.write(self.child.stdin.fileno(), raw)
            need(written == len(raw), "foreground_command_ack_unknown_no_retry")

    def _read_loop(self):
        pending, total, next_heartbeat = b"", 0, time.monotonic()
        try:
            while not self._end.is_set():
                if self._heartbeat and time.monotonic() >= next_heartbeat:
                    self._send("heartbeat")
                    next_heartbeat = time.monotonic() + HEARTBEAT_SECONDS
                readable, _, _ = select.select([self.child.stdout.fileno()], [], [], 0.1)
                if not readable:
                    continue
                raw = os.read(self.child.stdout.fileno(), MAX_LINE)
                if not raw:
                    self.eof = True
                    self._signal_change()
                    return
                pending += raw
                total += len(raw)
                need(len(pending) <= 2 * MAX_LINE and total <= 4 * MAX_LINE,
                     "foreground_output_bound")
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    need(len(line) <= MAX_LINE, "foreground_output_line_bound")
                    value = json.loads(line)
                    need(isinstance(value, dict) and value.get("schema") == SCHEMA
                         and value.get("launch_id") == self.launch_id
                         and value.get("run_id") == self.payload["run_id"]
                         and value.get("binary_sha256") == self.payload["binary_sha256"]
                         and value.get("helper_sha256") == self.payload["helper_sha256"]
                         and value.get("source_commit") == self.payload["source_commit"]
                         and value.get("source_tree") == self.payload["source_tree"],
                         "foreground_response_identity_mismatch")
                    with self._lock:
                        if value.get("event") == "ready":
                            need(self.ready is None and self.terminal is None
                                 and value.get("ready") is True, "foreground_duplicate_ready")
                            self.ready = value
                            new_file(self.phase / "ready.json", canonical(value))
                        elif value.get("event") == "terminal":
                            need(self.terminal is None, "foreground_duplicate_terminal")
                            self.terminal = value
                            new_file(self.phase / "terminal.json", canonical({
                                "scope": "raw-remote-wire; controller-stop-deadline-not-certified", "report": value}))
                        else:
                            raise Refusal("foreground_unexpected_response")
                    self._signal_change()
        except BaseException as error:
            self.failure = str(error) if isinstance(error, Refusal) else type(error).__name__
            self._signal_change()

    def _wait_for(self, name, until):
        while time.monotonic() < until:
            value = getattr(self, name)
            if value is not None:
                need(time.monotonic() < until, "foreground_original_deadline_expired")
                return value
            if self.failure or self.eof:
                break
            self._changed.wait(min(0.1, max(0, until - time.monotonic())))
            self._changed.clear()
        raise Refusal("foreground_" + name + "_unknown_no_retry")

    def start(self):
        need(self.child is None and self.receipt["submission_count"] == 0,
             "foreground_start_already_submitted_no_retry")
        began = time.monotonic()
        require_waitid()
        remote = self.node.root + "/native_ha_foreground_watchdog.py"
        # The helper is installed during fixture preparation; stdin is reserved
        # for the live parent channel, not a heredoc that reaches EOF at start.
        payload = base64.b64encode(canonical(self.payload)).decode()
        loader = ("import hashlib,pathlib,runpy,sys;"
                  "p=pathlib.Path(sys.argv[1]);"
                  "assert p.is_file() and not p.is_symlink();"
                  "assert hashlib.sha256(p.read_bytes()).hexdigest()==sys.argv[2];"
                  "sys.argv=[str(p),'--serve',sys.argv[3]];"
                  "runpy.run_path(str(p),run_name='__main__')")
        command = "exec " + shlex.join([self.payload["python_path"], "-B", "-u", "-c", loader,
                                         remote, self.payload["helper_sha256"], payload])
        argv = ["ssh", "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1",
                "-o", "ServerAliveInterval=2", "-o", "ServerAliveCountMax=2",
                self.node.alias, command]
        new_file(self.phase / "launch-intent.json", canonical(dict(self.receipt,
                 payload=self.payload, argv=argv, submission_count=1)))
        # Mark the one submission before Popen. A lost acknowledgement cannot
        # authorize a second Popen or a replacement remote launch nonce.
        self.receipt["submission_count"] = 1
        with (self.phase / "ssh.stderr.log").open("xb") as stderr:
            os.chmod(self.phase / "ssh.stderr.log", 0o600)
            self.child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                          stderr=stderr, start_new_session=True, close_fds=True)
        self.owner = capture_child(self.child)
        self.receipt["local_ssh_identity"] = self.owner
        new_file(self.phase / "ssh-identity.json", canonical(self.owner))
        self.thread = threading.Thread(target=self._read_loop, name="native-foreground-" + self.launch_id,
                                       daemon=True)
        self.thread.start()
        ready = self._wait_for("ready", began + START_SECONDS)
        need(self.terminal is None and self.failure is None, "foreground_exited_after_ready")
        row = ready.get("child_identity", {}).get("ps", {})
        need(type(row.get("pid")) is int and row["pid"] > 0
             and row.get("ppid") == ready.get("owner_pid") and row.get("pgid") == row["pid"],
             "foreground_actual_child_custody_missing")
        self.receipt.update(native_pid=row["pid"], ready=True,
                            parent_chain_at_ready=ready.get("parent_chain_at_ready"),
                            python_identity=ready.get("python_identity"),
                            start_elapsed_seconds=time.monotonic() - began)
        need(time.monotonic() < began + START_SECONDS, "original_start_deadline_expired")
        return row["pid"]

    def assert_running(self):
        need(self.ready is not None and self.terminal is None and self.failure is None
             and not self.eof and self.thread is not None and self.thread.is_alive()
             and not self.kill_sent and exit_observation(self.child) is None,
             "foreground_parent_or_child_lost_no_new_request")

    def _close_parent_channel(self):
        with self._send_lock:
            self._heartbeat = False
            if self.child is not None and self.child.stdin is not None and not self.child.stdin.closed:
                self.child.stdin.close()

    def stop(self):
        if self.completed:
            return self.receipt.get("native_pid")
        if self.child is None:
            need(self.receipt["submission_count"] == 0, "foreground_popen_outcome_unknown_no_retry")
            return None
        if self.stop_started is None:
            self.stop_started = time.monotonic()
            self.stop_until = self.stop_started + STOP_SECONDS
        until = self.stop_until  # A cleanup re-entry must not reset the stop clock.
        prior_failure = self.ready is None or self.failure is not None or self.eof or self.terminal is not None
        try:
            if not prior_failure and not self.kill_sent:
                self._send("kill")
            elif prior_failure:
                self._close_parent_channel()
            terminal = self._wait_for("terminal", until)
            need(not prior_failure and terminal.get("ok") is True and terminal.get("stopped") is True
                 and terminal.get("stop_reason") == "explicit_original_sigkill"
                 and terminal.get("terminal_within_original_stop_deadline") is True
                 and terminal.get("cleanup", {}).get("leader_reaped") is True
                 and terminal.get("cleanup", {}).get("owned_live_group_empty") is True
                 and terminal.get("cleanup", {}).get("signals") == ["SIGKILL"],
                 "foreground_remote_stop_not_qualified")
            self._end.set()
            self.thread.join(timeout=max(0.001, until - time.monotonic()))
            need(not self.thread.is_alive(), "foreground_receiver_not_joined")
            self._close_parent_channel()
            if self.owner is None:
                self.owner = capture_child(self.child)
            self.local_cleanup = stop_unreaped(self.child, self.owner, until=until)
            need(time.monotonic() < until, "original_stop_deadline_expired")
            observed = dict(self.receipt, stopped=True, remote_cleanup=terminal["cleanup"],
                            local_ssh_cleanup=self.local_cleanup,
                            stop_elapsed_seconds=time.monotonic() - self.stop_started,
                            original_stop_deadline_satisfied=None,
                            qualification_scope="cleanup-observed-only; final controller clock not yet checked")
            new_file(self.phase / "complete.json", canonical(observed))
            need(time.monotonic() < until, "original_stop_deadline_expired")
            self.receipt.update(stopped=True, remote_cleanup=terminal["cleanup"],
                                local_ssh_cleanup=self.local_cleanup,
                                stop_elapsed_seconds=time.monotonic() - self.stop_started,
                                original_stop_deadline_satisfied=True)
            self.completed = True
            return self.receipt.get("native_pid")
        except BaseException as error:
            self.completed = False
            self.receipt.update(stopped=False, original_stop_deadline_satisfied=False,
                                failure_code=str(error) if isinstance(error, Refusal) else type(error).__name__)
            self._close_parent_channel()  # Owner EOF cleanup; never restart.
            self._end.set()
            if self.thread is not None:
                self.thread.join(timeout=0.5)
            # A failure-only bounded rescue never changes the original result.
            # Keep direct custody for the local SSH group until the last signal.
            if self.child.returncode is None:
                try:
                    if self.owner is None:
                        self.owner = capture_child(self.child)
                    self.local_cleanup = stop_unreaped(self.child, self.owner,
                                                       until=time.monotonic() + STOP_SECONDS)
                    self.receipt["failure_only_local_ssh_cleanup"] = self.local_cleanup
                except BaseException as cleanup_error:
                    self.receipt["local_cleanup_error"] = type(cleanup_error).__name__
            failure_path = self.phase / "failure.json"
            if not failure_path.exists():
                new_file(failure_path, canonical(self.receipt))
            raise


if __name__ == "__main__":
    need(len(sys.argv) == 3 and sys.argv[1] == "--serve", "owner_cli_contract")
    raw = base64.b64decode(sys.argv[2], validate=True)
    need(len(raw) <= MAX_LINE, "owner_cli_bound")
    raise SystemExit(serve(json.loads(raw)))
