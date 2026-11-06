"""Owned original subprocesses for disposable QA fixtures.

No API operation, request retry or authentication authority lives here. The
parent profile supplies its original absolute budget; cleanup never grants a
passing result after that budget. Receipts omit argv, environment and raw logs.
"""
from __future__ import annotations

import contextlib
import functools
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import selectors
import stat
import subprocess
import sys
import tempfile
import time

# The stdlib type is stable even when a fixture replaces the Popen factory.
# The standalone compatibility branch still grants no owned-process receipt.
_POPEN_TYPE = subprocess.Popen

_CURRENT = None
FIELDS = ("dev", "ino", "mode", "uid", "nlink", "size", "mtime_ns", "ctime_ns")
PROFILE_SECONDS = 360
PROFILES = frozenset((
    "core_isolation", "identity_live", "response_wrapping", "wrapping_revoke_self_live",
    "token_revoke_orphan_live", "transit_mldsa_live", "transit_asymmetric_live",
    "transit_derived_live", "mount_discovery_live", "external_keys_live",
    "consistency_headers_live", "client_consistency_live", "capabilities_live",
    "pki_live", "pkiext_live", "ssh_otp_live", "audit_file_live", "namespace_tree_live",
    "policy_parameters_live", "policy_templates_live", "policy_wrapping_ttl_live",
    "kv_metadata_cas_live", "kv_enumeration_live",
))


class OwnedFailure(RuntimeError):
    """A closed process-method label, never a command, credential or log."""


class OwnedCancelled(BaseException):
    pass


def fixed8(path):
    value = Path(path).lstat()
    return dict(zip(FIELDS, (value.st_dev, value.st_ino, value.st_mode,
                            value.st_uid, value.st_nlink, value.st_size,
                            value.st_mtime_ns, value.st_ctime_ns)))


def file_pin(path):
    path = Path(path).resolve(strict=True)
    before = fixed8(path)
    if not stat.S_ISREG(before["mode"]):
        raise OwnedFailure("owned_executable_not_regular")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if fixed8(path) != before:
        raise OwnedFailure("owned_executable_changed")
    return {"path": str(path), "SHA256": digest, "stat8": before}


def _snapshot(pid):
    root = Path("/proc") / str(pid)
    raw = (root / "stat").read_text()
    tail = raw[raw.rfind(") ") + 2:].split()
    uids = list(map(int, next(row for row in (root / "status").read_text().splitlines()
                             if row.startswith("Uid:")).split()[1:]))
    return {"PID": pid, "PPID": int(tail[1]), "PGID": int(tail[2]),
            "SID": int(tail[3]), "starttick": int(tail[19]), "UIDs": uids,
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "image": file_pin(root / "exe")}


def _sid_survivors(sid):
    rows, gaps = [], []
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            raw = (path / "stat").read_text()
            tail = raw[raw.rfind(") ") + 2:].split()
            if int(tail[3]) == sid:
                rows.append({"PID": int(path.name), "SID": int(tail[3]),
                             "starttick": int(tail[19]), "state": tail[0]})
        except (OSError, ValueError, IndexError) as error:
            if path.exists():
                gaps.append({"PID": int(path.name), "class": type(error).__name__})
    return rows, gaps


def _gate_main():
    # This original Popen starts as the pinned Python gate image. Its target
    # image is an independently pinned exec input, never misreported as the
    # image observed before admission.
    try:
        read_fd = int(sys.argv[2])
        ack_fd = int(sys.argv[3])
        expected = json.loads(sys.argv[4])
        arguments = json.loads(sys.argv[5])
        if not arguments or any(not isinstance(value, str) for value in arguments):
            os._exit(71)
        byte = os.read(read_fd, 2)
        os.close(read_fd)
        if byte != b"1":
            os.write(ack_fd, b"E")
            os._exit(70)
        if file_pin(expected["path"]) != expected:
            os.write(ack_fd, b"E")
            os._exit(71)
        environment = os.environ.copy()
        environment.pop("HB_QA_EXEC_GATE", None)
        os.set_inheritable(ack_fd, False)
        os.write(ack_fd, b"1")
        os.execve(expected["path"], arguments, environment)
    except BaseException:
        try:
            os.write(ack_fd, b"E")
        except BaseException:
            pass
        os._exit(71)


class _OwnedPopen(_POPEN_TYPE):
    def __init__(self, owner, arguments, *, label, kind, action, stop_timeout, **kwargs):
        self.owner = owner
        self.row = {"label": label, "kind": kind, "declared_stop_action": action,
                    "declared_stop_timeout": stop_timeout, "gaps": [], "signals": [],
                    "fallback": False, "completed_original_wait_count": 0,
                    "original_wait_attempts": [], "admission_released": False}
        self.pidfd = None
        self._done = False
        self._cleanup_wait = False
        self._admission_fd = None
        self._read_fd = None
        self._ack_read = None
        self._ack_write = None
        self._raw_wait = None
        if kwargs.get("start_new_session", True) is not True:
            raise OwnedFailure("owned_session_required")
        if "executable" in kwargs or kwargs.get("shell", False):
            raise OwnedFailure("owned_shell_not_supported")
        if not isinstance(arguments, (list, tuple)):
            raise OwnedFailure("owned_argument_array_required")
        if (not isinstance(label, str) or not 0 < len(label) <= 128
                or any(not (c.isascii() and (c.isalnum() or c in "._-")) for c in label)
                or kind not in ("server", "utility") or action not in ("TERM", "KILL")
                or type(stop_timeout) not in (int, float) or stop_timeout <= 0):
            raise OwnedFailure("owned_closed_operation_required")
        arguments = [os.fsdecode(os.fspath(value)) for value in arguments]
        if not arguments:
            raise OwnedFailure("owned_empty_command")
        environment = dict(os.environ if kwargs.get("env") is None else kwargs["env"])
        found = shutil.which(arguments[0], path=environment.get("PATH"))
        if found is None:
            raise FileNotFoundError(arguments[0])
        target = file_pin(found)
        self.row["target_exec_input"] = target
        self.row["argv_SHA256"] = hashlib.sha256(
            json.dumps(arguments, separators=(",", ":")).encode()).hexdigest()
        read_fd, write_fd = os.pipe()
        self._read_fd, self._admission_fd = read_fd, write_fd
        ack_read, ack_write = os.pipe()
        self._ack_read, self._ack_write = ack_read, ack_write
        kwargs["pass_fds"] = tuple(kwargs.get("pass_fds", ())) + (read_fd, ack_write)
        kwargs["start_new_session"] = True
        kwargs["env"] = environment
        owner.protected += 1
        created = False
        try:
            # Registration occurs immediately in this finally after the original
            # Popen exists, before poll, metadata, signal or the private FD release.
            try:
                super().__init__([sys.executable, "-B", str(Path(__file__).resolve()),
                                  "--owned-exec-gate", str(read_fd), str(ack_write),
                                  json.dumps(target, separators=(",", ":")),
                                  json.dumps(arguments, separators=(",", ":"))], **kwargs)
            finally:
                if getattr(self, "pid", None) is not None:
                    created = True
                    self._raw_wait = super().wait
                    owner.register(self)
            os.close(read_fd)
            self._read_fd = None
            os.close(ack_write)
            self._ack_write = None
            try:
                self.pidfd = os.pidfd_open(self.pid, 0)
                self.row["birth"] = owner.capture(self)
                birth = self.row["birth"]
                if (birth["PID"] != self.pid or birth["PPID"] != os.getpid()
                        or birth["PGID"] != self.pid or birth["SID"] != self.pid
                        or birth["UIDs"] != [os.geteuid()] * 4):
                    raise OwnedFailure("owned_birth_identity_mismatch")
                owner.remaining()
                if owner.interrupted:
                    raise OwnedCancelled()
                if os.write(write_fd, b"1") != 1:
                    raise OwnedFailure("owned_admission_write")
                self.row["admission_released"] = True
                self.row["admitted_ns"] = time.monotonic_ns()
                acknowledgement = bytearray()
                with selectors.DefaultSelector() as selector:
                    selector.register(ack_read, selectors.EVENT_READ)
                    while True:
                        if owner.interrupted:
                            raise OwnedCancelled()
                        if not selector.select(owner.remaining()):
                            raise OwnedFailure("owned_exec_ack_deadline")
                        chunk = os.read(ack_read, 3)
                        if not chunk:
                            break
                        acknowledgement.extend(chunk)
                        if len(acknowledgement) > 2:
                            raise OwnedFailure("owned_exec_ack_invalid")
                self.row["exec_input_guard_acknowledged"] = acknowledgement == b"1"
                if acknowledgement != b"1":
                    raise OwnedFailure("owned_exec_guard_rejected")
                owner.remaining()
            except BaseException as error:
                owner.gap(self, "birth_or_admission", error)
                raise
        finally:
            # EOF cancels the unadmitted gate; never dispatch an effect when
            # birth metadata is unavailable. Original wait remains registered.
            for name in ("_read_fd", "_admission_fd", "_ack_read", "_ack_write"):
                descriptor = getattr(self, name)
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError as error:
                        if created:
                            owner.gap(self, "admission_fd_close", error)
                    setattr(self, name, None)
            owner.protected -= 1

    def direct_failure_wait(self):
        # Last-resort failure cleanup still waits this same original Popen,
        # bypassing only a failed/injected wrapper, never replacing its PID.
        if self._done:
            return self.returncode
        value = _POPEN_TYPE.wait(self)
        self._done = True
        self.row["completed_original_wait_count"] += 1
        self.row["exit_code"] = value
        self.row["same_original_Popen_wait"] = True
        self.row["direct_failure_wait"] = True
        self.owner.failed = True
        return value

    def wait(self, timeout=None):
        if self._done:
            # This is the saved result of the already observed original wait,
            # not a fresh wait on a PID or replacement object.
            return self.returncode
        bounded = timeout if self._cleanup_wait else self.owner.bound_timeout(timeout)
        attempt = {"entered_ns": time.monotonic_ns(), "timeout": bounded}
        self.row["original_wait_attempts"].append(attempt)
        try:
            value = self._raw_wait(timeout=bounded)
        except BaseException as error:
            attempt["exception_class"] = type(error).__name__
            raise
        attempt["returned_ns"] = time.monotonic_ns()
        attempt["returncode"] = value
        self._done = True
        self.row["completed_original_wait_count"] += 1
        self.row["exit_code"] = value
        self.row["same_original_Popen_wait"] = True
        return value


class Owner:
    def __init__(self, work_parent, *, deadline_ns=None, profile="method_control"):
        self.children = []
        self.protected = 0
        self.failed = False
        self.interrupted = False
        self.controls = []
        self.finished = False
        self.profile = profile
        self.started_ns = time.monotonic_ns()
        self.deadline_ns = deadline_ns if deadline_ns is not None else (
            self.started_ns + PROFILE_SECONDS * 1_000_000_000)
        self.external_deadline = deadline_ns is not None
        if (type(self.deadline_ns) is not int or self.deadline_ns <= self.started_ns
                or self.deadline_ns > self.started_ns + PROFILE_SECONDS * 1_000_000_000):
            raise OwnedFailure("owned_original_deadline_invalid")
        parent = Path(work_parent).absolute()
        if parent.is_symlink() or not parent.is_dir():
            raise OwnedFailure("owned_work_parent_invalid")
        info = parent.stat()
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise OwnedFailure("owned_work_parent_not_private")
        self.root = Path(tempfile.mkdtemp(prefix="qa-owned-", dir=parent))
        self.root.chmod(0o700)

    def remaining(self):
        remaining = (self.deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if remaining <= 0:
            self.failed = True
            raise OwnedFailure("owned_original_profile_deadline")
        return remaining

    def bound_timeout(self, timeout):
        remaining = self.remaining()
        if timeout is None:
            return remaining
        return min(timeout, remaining)

    def register(self, child):
        if any(value is child for value in self.children):
            raise OwnedFailure("owned_duplicate_handle")
        self.children.append(child)
        child.row["original_PID"] = child.pid
        child.row["registered_ns"] = time.monotonic_ns()

    def capture(self, child):
        first = _snapshot(child.pid)
        second = _snapshot(child.pid)
        if first != second:
            raise OwnedFailure("owned_birth_changed")
        return first

    def gap(self, child, stage, error):
        self.failed = True
        child.row["gaps"].append({"stage": stage, "class": type(error).__name__})

    def send(self, child, signum, *, fallback=False):
        row = {"signal": int(signum), "requested_ns": time.monotonic_ns(),
               "fallback": fallback, "sent": False}
        child.row["signals"].append(row)
        if fallback:
            child.row["fallback"] = True
            self.failed = True
        if child.pidfd is not None:
            signal.pidfd_send_signal(child.pidfd, signum)
            row["authority"] = "original_kernel_pidfd"
        else:
            # Only the original direct child may be cleaned on a metadata gap.
            # Never signal a guessed group or a foreign/reused PID.
            child.row["fallback"] = True
            self.failed = True
            _POPEN_TYPE.send_signal(child, signum)
            row["authority"] = "original_Popen_failure_cleanup"
        row["sent"] = True

    def close(self, child, *, action=None, timeout=None, expected_codes=None):
        if child is None:
            return None
        if not any(value is child for value in self.children):
            raise OwnedFailure("owned_foreign_handle")
        if child._done:
            return child.returncode
        action = child.row["declared_stop_action"] if action is None else action
        timeout = child.row["declared_stop_timeout"] if timeout is None else timeout
        first = None
        self.protected += 1
        child._cleanup_wait = True
        try:
            try:
                alive = child.poll() is None
                if alive:
                    self.send(child, signal.SIGKILL if action == "KILL" else signal.SIGTERM)
                elif child.row["kind"] == "server":
                    child.row["premature_exit_before_stop"] = True
                    self.failed = True
            except BaseException as error:
                self.gap(child, "poll_or_declared_signal", error)
                first = error
            finally:
                try:
                    result = child.wait(timeout=timeout)
                except BaseException as error:
                    self.gap(child, "declared_original_wait", error)
                    if first is None:
                        first = error
                    try:
                        self.send(child, signal.SIGKILL, fallback=True)
                    except BaseException as signal_error:
                        self.gap(child, "fallback_original_KILL", signal_error)
                    finally:
                        try:
                            result = child.wait(timeout=timeout)
                        except BaseException as final_error:
                            self.gap(child, "fallback_bounded_wait", final_error)
                            # Failure cleanup must finish this original handle.
                            # This is not a new business or profile deadline.
                            result = child.direct_failure_wait()
            if expected_codes is not None and result not in expected_codes:
                self.failed = True
                child.row["unexpected_shutdown_code"] = True
            return result
        finally:
            child._cleanup_wait = False
            self.protected -= 1
            # Preserve the first failure in the receipt, while all remaining
            # originals are still closed by finish(). Do not mask caller errors.
            if first is not None:
                child.row["first_cleanup_error_class"] = type(first).__name__

    def interrupt(self, signum):
        self.interrupted = True
        self.failed = True
        self.controls.append({"signal": int(signum), "observed_ns": time.monotonic_ns()})
        if self.protected == 0:
            raise OwnedCancelled()

    def finish(self):
        self.protected += 1
        try:
            self._finish_all()
        finally:
            self.protected -= 1

    def _finish_all(self):
        if self.finished:
            return
        self.finished = True
        self.business_finished_ns = time.monotonic_ns()
        if self.business_finished_ns >= self.deadline_ns:
            self.failed = True
        # Every registered original is visited even if another original's
        # observation, signal, wait, retirement scan or close raises.
        for child in tuple(self.children):
            try:
                if not child._done:
                    self.close(child)
            except BaseException as error:
                self.gap(child, "finish_original", error)
                try:
                    self.send(child, signal.SIGKILL, fallback=True)
                except BaseException as signal_error:
                    self.gap(child, "finish_fallback_signal", signal_error)
                finally:
                    child._cleanup_wait = True
                    try:
                        child.direct_failure_wait()
                    except BaseException as wait_error:
                        self.gap(child, "finish_original_wait", wait_error)
                    finally:
                        child._cleanup_wait = False
            finally:
                try:
                    survivors, gaps = _sid_survivors(child.pid)
                    child.row["SID_survivors"] = survivors
                    child.row["SID_observation_gaps"] = gaps
                    child.row["original_SID_retired_observed"] = not survivors and not gaps
                    if survivors or gaps:
                        self.failed = True
                except BaseException as error:
                    self.gap(child, "SID_retirement", error)
                    child.row["original_SID_retired_observed"] = False
                if child.pidfd is not None:
                    try:
                        os.close(child.pidfd)
                    except OSError as error:
                        self.gap(child, "pidfd_close", error)
                    child.pidfd = None
        finished_ns = time.monotonic_ns()
        # Cleanup is part of the original process-method deadline. A business
        # return before it cannot qualify originals that only close afterward.
        if finished_ns >= self.deadline_ns:
            self.failed = True
        self.receipt = {
            "schema": "heptabao.qa.original-process.v1", "profile": self.profile,
            "profile_seconds": PROFILE_SECONDS, "original_deadline_ns": self.deadline_ns,
            "external_original_deadline": self.external_deadline,
            "started_ns": self.started_ns, "business_finished_ns": self.business_finished_ns,
            "finished_ns": finished_ns, "controls": self.controls,
            "children": [child.row for child in self.children],
            "same_originals_closed": all(child._done for child in self.children),
            "passed_process_method": not self.failed and all(
                child._done and child.row["completed_original_wait_count"] == 1
                and not child.row["gaps"] and not child.row["fallback"]
                and child.row.get("original_SID_retired_observed") is True
                for child in self.children),
            "business_scenarios_not_qualified_by_this_receipt": True,
        }
        destination = self.root / "original-process-receipt.json"
        with destination.open("x") as stream:
            json.dump(self.receipt, stream, indent=2, sort_keys=True)
            stream.write("\n")


@contextlib.contextmanager
def activated(owner):
    global _CURRENT
    if _CURRENT is not None:
        raise OwnedFailure("owned_nested_profile")
    _CURRENT = owner
    previous = {}
    try:
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, lambda number, frame: owner.interrupt(number))
        try:
            yield owner
        except BaseException:
            owner.failed = True
            raise
        finally:
            owner.finish()
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        _CURRENT = None


def profile_main(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        parent = os.environ.get("HB_QA_PROCESS_WORK_ROOT", os.environ.get("TMPDIR"))
        if parent is None:
            raise OwnedFailure("owned_private_work_root_required")
        raw_deadline = os.environ.get("HB_QA_ORIGINAL_PROFILE_DEADLINE_NS")
        deadline = None if raw_deadline is None else int(raw_deadline)
        profile = os.environ.get("HB_QA_PROFILE_NAME", Path(sys.argv[0]).stem)
        if profile not in PROFILES:
            raise OwnedFailure("owned_unknown_profile")
        owner = Owner(parent, deadline_ns=deadline, profile=profile)
        with activated(owner):
            result = function(*args, **kwargs)
        return result if owner.receipt["passed_process_method"] else 1
    return wrapped


def popen(arguments, *, label, kind="server", action="TERM", stop_timeout=5, **kwargs):
    if _CURRENT is None:
        # Other pre-existing QA entry points share Smoke/HA helpers. Preserve
        # their subprocess API without granting a canonical affine receipt.
        return subprocess.Popen(arguments, **kwargs)
    _CURRENT.remaining()
    return _OwnedPopen(_CURRENT, arguments, label=label, kind=kind,
                       action=action, stop_timeout=stop_timeout, **kwargs)


def wait(child, timeout=None):
    if _CURRENT is None and isinstance(child, _POPEN_TYPE) and not isinstance(child, _OwnedPopen):
        return child.wait(timeout=timeout)
    if not isinstance(child, _OwnedPopen) or child.owner is not _CURRENT:
        raise OwnedFailure("owned_foreign_wait")
    return child.wait(timeout=timeout)


def stop(child, *, action=None, timeout=None, expected_codes=None):
    if child is None:
        return None
    if _CURRENT is None:
        if not isinstance(child, _POPEN_TYPE) or isinstance(child, _OwnedPopen):
            raise OwnedFailure("owned_foreign_standalone_handle")
        # This compatibility branch is deliberately unqualified: no Owner,
        # private admission or kernel-birth claim. Even an already exited
        # original child is still waited; metadata/signal errors cannot skip it.
        first = None
        result = None
        try:
            try:
                if child.poll() is None:
                    child.kill() if action == "KILL" else child.terminate()
            except BaseException as error:
                first = error
            finally:
                try:
                    result = child.wait(timeout=timeout)
                except BaseException as error:
                    if first is None:
                        first = error
                    try:
                        child.kill()
                    except BaseException as kill_error:
                        if first is None:
                            first = kill_error
                    finally:
                        result = child.wait()
        finally:
            if first is not None:
                raise first
        if expected_codes is not None and result not in expected_codes:
            raise OwnedFailure("owned_standalone_shutdown_code")
        return result
    return _CURRENT.close(child, action=action, timeout=timeout, expected_codes=expected_codes)


def run(arguments, *, label, check=False, input=None, capture_output=False, timeout=None, **kwargs):
    if _CURRENT is None:
        # stdlib.run owns and waits its original child on normal and exceptional
        # paths. No canonical process-method receipt is produced here.
        return subprocess.run(arguments, check=check, input=input,
                              capture_output=capture_output, timeout=timeout, **kwargs)
    if input is not None:
        if "stdin" in kwargs:
            raise ValueError("stdin and input arguments may not both be used")
        kwargs["stdin"] = subprocess.PIPE
    if capture_output:
        if "stdout" in kwargs or "stderr" in kwargs:
            raise ValueError("stdout and stderr arguments may not be used with capture_output")
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    child = None
    try:
        child = popen(arguments, label=label, kind="utility", action="KILL", stop_timeout=5, **kwargs)
        bounded = child.owner.bound_timeout(timeout)
        stdout, stderr = child.communicate(input, timeout=bounded)
        result = subprocess.CompletedProcess(arguments, child.returncode, stdout, stderr)
        if check and result.returncode:
            raise subprocess.CalledProcessError(result.returncode, arguments,
                                                output=stdout, stderr=stderr)
        return result
    except subprocess.TimeoutExpired:
        if child is not None:
            child.owner.failed = True
        raise
    finally:
        if child is not None and not child._done:
            child.owner.failed = True
            stop(child, action="KILL", timeout=5)


def check_output(arguments, *, label, **kwargs):
    if "stdout" in kwargs:
        raise ValueError("stdout argument not allowed")
    return run(arguments, label=label, stdout=subprocess.PIPE, check=True, **kwargs).stdout


def interrupt(signum):
    if _CURRENT is None:
        raise OwnedCancelled()
    _CURRENT.interrupt(signum)


def abort(error, callbacks):
    # Close all registered resources, then preserve the original readiness or
    # constructor failure rather than replacing it with a cleanup exception.
    try:
        close_all(callbacks)
    except BaseException:
        pass
    raise error


def close_all(callbacks):
    first = None
    for callback in callbacks:
        try:
            callback()
        except BaseException as error:
            if _CURRENT is not None:
                _CURRENT.failed = True
            if first is None:
                first = error
    if first is not None:
        raise first


if __name__ == "__main__":
    if len(sys.argv) == 6 and sys.argv[1] == "--owned-exec-gate":
        _gate_main()
    raise SystemExit(71)
