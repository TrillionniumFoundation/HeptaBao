"""Original subprocess custody for the disposable DR controller.

Every target waits at an exec gate until its original child, process group and
session are observed. WNOWAIT keeps an exited leader waitable while its group is
checked: a recycled numeric PID is never permission to signal a group. Linux
uses /proc; Darwin uses numeric ps fields plus getsid, never ps's ``sess`` kernel
pointer. This is lifecycle evidence, not containment of hostile programs which
deliberately escape their session. It grants no storage or production authority.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

_REAL_POPEN = subprocess.Popen
_ACTIVE = None
_GATE = "--dr-owned-exec-gate"
_PROBE_SECONDS = 2.0
_CLEANUP_SECONDS = 5.0
_DEFAULT_UTILITY_SECONDS = 15.0


class CustodyFailure(RuntimeError):
    """A closed diagnostic label; never command text or credentials."""


class CustodyCancelled(BaseException):
    pass


def _need(condition, label):
    if not condition:
        raise CustodyFailure(label)


def _parse_linux_stat(raw, pid):
    tail = raw[raw.rfind(") ") + 2:].split()
    _need(len(tail) >= 20, "custody_proc_stat_shape")
    return {"pid": pid, "ppid": int(tail[1]), "pgid": int(tail[2]),
            "sid": int(tail[3]), "state": tail[0], "start_ticks": int(tail[19])}


def _linux_table():
    rows = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            row = _parse_linux_stat((entry / "stat").read_text(), int(entry.name))
            row["uid"] = entry.stat().st_uid
            rows.append(row)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError:
            if entry.exists():
                raise CustodyFailure("custody_proc_observation_gap") from None
    return rows


def _parse_darwin_ps(raw):
    rows = []
    _need(len(raw) <= 2 * 1024 * 1024, "custody_ps_output_bound")
    for line in raw.decode("ascii", "strict").splitlines():
        columns = line.split()
        if not columns:
            continue
        _need(len(columns) == 5 and all(v.isdecimal() for v in columns[:3])
              and (columns[3].isdecimal()
                   or columns[3].startswith("-") and columns[3][1:].isdecimal())
              and columns[4][0] in "RSDTIUZX?", "custody_ps_numeric_shape")
        pid, ppid, pgid = map(int, columns[:3])
        printed_uid = int(columns[3])
        # Real Darwin ps prints nobody as -2. uid_t is unsigned 32-bit;
        # normalize that numeric representation without discarding the row or
        # weakening the later exact effective-UID check on an owned original.
        _need(-(2 ** 31) <= printed_uid < 2 ** 32, "custody_ps_uid_range")
        uid = printed_uid % (2 ** 32)
        rows.append({"pid": pid, "ppid": ppid, "pgid": pgid,
                     "uid": uid, "state": columns[4][0]})
    _need(rows, "custody_ps_empty")
    return rows


def _darwin_table():
    # Apple adv_cmds/ps/keyword.c defines sess as KPTR, not a numeric SID.
    # https://github.com/apple-oss-distributions/adv_cmds/blob/main/ps/keyword.c
    # This bounded, fixed read-only probe bypasses target instrumentation to
    # avoid recursively spawning a probe for its own birth observation.
    child = _REAL_POPEN(["/bin/ps", "-axo", "pid=,ppid=,pgid=,uid=,state="],
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, start_new_session=True,
                        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    try:
        stdout, stderr = child.communicate(timeout=_PROBE_SECONDS)
        _need(child.returncode == 0 and not stderr, "custody_ps_failed")
        return _parse_darwin_ps(stdout)
    except subprocess.TimeoutExpired:
        raise CustodyFailure("custody_ps_deadline") from None
    finally:
        if child.returncode is None:
            child.kill()
            child.communicate(timeout=_CLEANUP_SECONDS)


def _table():
    if sys.platform.startswith("linux"):
        return _linux_table()
    if sys.platform == "darwin":
        return _darwin_table()
    raise CustodyFailure("custody_platform_unsupported")


def _snapshot(pid):
    matches = [row for row in _table() if row["pid"] == pid]
    _need(len(matches) == 1, "custody_original_not_observed")
    row = matches[0]
    row["sid"] = os.getsid(pid)
    _need(row["pgid"] == os.getpgid(pid), "custody_original_group_changed")
    return row


def _members(anchor):
    rows = []
    for row in _table():
        # A SID can contain a child-created group too. It is observed and
        # fails retirement, but is never silently treated as the owned PGID.
        if "sid" not in row:
            if row["uid"] != os.geteuid() and row["pgid"] != anchor:
                continue
            try:
                row["sid"] = os.getsid(row["pid"])
            except ProcessLookupError:
                continue
        if row["pgid"] == anchor or row["sid"] == anchor:
            _need(row["sid"] == anchor, "custody_foreign_group_observed")
            rows.append(row)
    return sorted(rows, key=lambda row: row["pid"])


def _live(rows, *, excluding=None):
    return [row for row in rows if row["pid"] != excluding and row["state"] not in ("Z", "X")]


class Owner:
    def __init__(self):
        self.children, self.rows, self.controls = [], [], []
        self.failed = self.interrupted = self.finished = self.finishing = False
        self.protected = 0

    def _register(self, child):
        _need(not any(original is child for original in self.children), "custody_duplicate_original")
        self.children.append(child)
        self.rows.append(child.custody)

    def _gap(self, child, label):
        self.failed = True
        child.custody["gaps"].append(label)

    def _interrupt(self, signum, _frame):
        self.interrupted = self.failed = True
        self.controls.append({"signal": int(signum)})
        if not self.protected and not self.finishing:
            raise CustodyCancelled()

    def assert_retired(self):
        """Observe previous originals; this never stops a still-running target."""
        first = None
        for child in tuple(self.children):
            try:
                _need(child.poll() is not None and child.custody["original_wait_completed"]
                      and child.custody.get("no_live_members_before_reap") is True,
                      "custody_original_not_retired")
            except BaseException as error:
                self.failed = True
                first = first or error
        if first is not None or self.failed:
            raise CustodyFailure("custody_retirement_failed") from first
        return self.receipt()

    def finish(self):
        """Idempotent failure cleanup of original handles, never a new target."""
        if self.finished:
            return self.receipt()
        self.finishing = True
        self.protected += 1
        try:
            for child in tuple(self.children):
                try:
                    if child.returncode is None:
                        observed = child._exit_info()
                        if observed is None:
                            self._gap(child, "custody_needed_final_cleanup")
                            child.kill()
                        child.wait(timeout=_CLEANUP_SECONDS)
                except BaseException as error:
                    self._gap(child, "custody_final_" + type(error).__name__)
                    # If group identity is unavailable, retain a failed receipt
                    # and signal only the original waitable direct child.
                    child._direct_failure_cleanup()
            self.finished = True
        finally:
            self.protected -= 1
            self.finishing = False
        return self.receipt()

    def receipt(self):
        passed = (not self.failed and all(row["original_wait_completed"]
                  and row.get("no_live_members_before_reap") is True
                  and not row["gaps"] for row in self.rows))
        return {"schema": "heptabao.dr-original-process-custody.v1",
                "platform": sys.platform, "passed_process_custody": passed,
                "failed": self.failed, "finished": self.finished,
                "interrupted": self.interrupted, "controls": copy.deepcopy(self.controls),
                "children": copy.deepcopy(self.rows), "original_count": len(self.rows),
                "unreaped_original_is_signal_anchor": True,
                "escaped_session_containment_claim": False,
                "storage_or_production_authority": False}


class _TrackedPopen(_REAL_POPEN):
    def __init__(self, arguments, **kwargs):
        owner = _ACTIVE
        _need(owner is not None and not owner.finished and not owner.interrupted,
              "custody_owner_not_active")
        _need(threading.current_thread() is threading.main_thread(), "custody_main_thread_required")
        _need(isinstance(arguments, (list, tuple)) and arguments, "custody_argument_array_required")
        _need(not kwargs.get("shell", False) and kwargs.get("executable") is None
              and kwargs.get("preexec_fn") is None
              and kwargs.get("process_group", -1) in (-1, None), "custody_unadmitted_spawn_options")
        arguments = [os.fsdecode(os.fspath(value)) for value in arguments]
        self.owner = owner
        self.custody = {"argv_sha256": hashlib.sha256(json.dumps(arguments, separators=(",", ":")).encode()).hexdigest(),
                        "gaps": [], "signals": [], "exec_admitted": False,
                        "original_wait_completed": False, "original_wait_count": 0}
        self._registered = False
        self._group_stop_requested = False
        self._reaping = False
        self._birth = None
        read_fd, write_fd = os.pipe()
        kwargs["start_new_session"] = True
        kwargs["pass_fds"] = tuple(kwargs.get("pass_fds", ())) + (read_fd,)
        owner.protected += 1
        try:
            try:
                super().__init__([sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()),
                                  _GATE, str(read_fd), json.dumps(arguments)], **kwargs)
            finally:
                if getattr(self, "pid", None) is not None:
                    self.custody["pid"] = self.pid
                    owner._register(self)
                    self._registered = True
            self.args = arguments
            os.close(read_fd)
            read_fd = None
            _need(self._exit_info() is None, "custody_gate_exited_before_admission")
            first, second = _snapshot(self.pid), _snapshot(self.pid)
            identity = ("pid", "ppid", "pgid", "sid", "uid")
            _need(all(first[key] == second[key] for key in identity)
                  and first.get("start_ticks") == second.get("start_ticks")
                  and first["pid"] == first["pgid"] == first["sid"] == self.pid
                  and first["ppid"] == os.getpid() and first["uid"] == os.geteuid(),
                  "custody_gate_birth_mismatch")
            self._birth = first
            self.custody["birth"] = dict(first)
            if owner.interrupted:
                raise CustodyCancelled()
            _need(os.write(write_fd, b"1") == 1, "custody_gate_release_failed")
            self.custody["exec_admitted"] = True
        except BaseException as error:
            if self._registered:
                owner._gap(self, "custody_admission_" + type(error).__name__)
            raise
        finally:
            for descriptor in (read_fd, write_fd):
                if descriptor is not None:
                    os.close(descriptor)
            owner.protected -= 1
        if owner.interrupted:
            raise CustodyCancelled()

    def _exit_info(self):
        try:
            return os.waitid(os.P_PID, self.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            self.owner._gap(self, "custody_original_reaped_elsewhere")
            raise CustodyFailure("custody_original_anchor_lost") from None

    def _anchor(self):
        # waitid returning None still proves this live PID is our child. An
        # already-exited child remains allocated because WNOWAIT did not reap it.
        self._exit_info()
        observed = _snapshot(self.pid)
        _need(self._birth is not None and all(observed[key] == self._birth[key]
              for key in ("pid", "ppid", "pgid", "sid", "uid"))
              and ("start_ticks" not in self._birth
                   or observed["start_ticks"] == self._birth["start_ticks"]),
              "custody_original_anchor_changed")

    def _signal_group(self, signum):
        self._anchor()
        observed = _members(self.pid)
        _need(all(row["pgid"] == self.pid for row in observed), "custody_child_changed_group")
        os.killpg(self.pid, signum)
        self.custody["signals"].append({"signal": int(signum), "pgid": self.pid,
                                         "authority": "original_unreaped_child"})

    def send_signal(self, sig):
        if self.returncode is not None:
            return
        self.owner.protected += 1
        try:
            if self._exit_info() is not None:
                self._complete_exit()
                return
            self._signal_group(sig)
            self._group_stop_requested = True
        except BaseException as error:
            self.owner._gap(self, "custody_signal_" + type(error).__name__)
            raise
        finally:
            self.owner.protected -= 1

    def kill(self):
        self.send_signal(signal.SIGKILL)

    def terminate(self):
        self.send_signal(signal.SIGTERM)

    def _complete_exit(self):
        if self.returncode is not None:
            return self.returncode
        unexpected = False
        self.owner.protected += 1
        self._reaping = True
        deadline = time.monotonic() + _CLEANUP_SECONDS
        try:
            self._anchor()
            members = _members(self.pid)
            alive = _live(members, excluding=self.pid)
            self.custody["members_at_leader_exit"] = members
            if alive:
                if not self._group_stop_requested:
                    unexpected = True
                    self.owner._gap(self, "custody_live_descendant_after_leader_exit")
                self._signal_group(signal.SIGKILL)
                while alive and time.monotonic() < deadline:
                    time.sleep(min(0.01, max(0, deadline - time.monotonic())))
                    self._anchor()
                    members = _members(self.pid)
                    alive = _live(members, excluding=self.pid)
            self.custody["members_before_original_reap"] = members
            self.custody["no_live_members_before_reap"] = not alive
            _need(not alive, "custody_live_members_remain")
            # Only this call releases the original leader's PID/PGID anchor.
            result = _REAL_POPEN.wait(self, timeout=max(0.001, deadline - time.monotonic()))
            self.custody.update(original_wait_completed=True,
                                original_wait_count=self.custody["original_wait_count"] + 1,
                                returncode=result)
        except BaseException as error:
            self.owner._gap(self, "custody_retirement_" + type(error).__name__)
            raise
        finally:
            self._reaping = False
            self.owner.protected -= 1
        if unexpected:
            raise CustodyFailure("custody_live_descendant_after_leader_exit")
        return result

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        if self._exit_info() is None:
            return None
        return self._complete_exit()

    def wait(self, timeout=None):
        if self.returncode is not None:
            return self.returncode
        limit = _DEFAULT_UTILITY_SECONDS if timeout is None else timeout
        deadline = time.monotonic() + limit
        while True:
            if self._exit_info() is not None:
                return self._complete_exit()
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(self.args, timeout)
            time.sleep(min(0.01, max(0, deadline - time.monotonic())))

    def communicate(self, input=None, timeout=None):
        return _REAL_POPEN.communicate(self, input=input,
                                      timeout=_DEFAULT_UTILITY_SECONDS if timeout is None else timeout)

    def _internal_poll(self, _deadstate=None):
        # CPython's destructor/_active sweep must not silently reap a tracked
        # original before its group observation. Owner retains every handle.
        if getattr(self, "_registered", False):
            return self.returncode
        return _REAL_POPEN._internal_poll(self, _deadstate)

    def _direct_failure_cleanup(self):
        if self.returncode is not None:
            return
        self.owner.protected += 1
        try:
            try:
                info = self._exit_info()
                if info is None:
                    # Still our unreaped direct child; never infer PGID here.
                    os.kill(self.pid, signal.SIGKILL)
                    self.custody["signals"].append({"signal": int(signal.SIGKILL), "pid": self.pid,
                                                     "authority": "original_child_failure_only"})
                result = _REAL_POPEN.wait(self, timeout=_CLEANUP_SECONDS)
                self.custody.update(original_wait_completed=True,
                                    original_wait_count=self.custody["original_wait_count"] + 1,
                                    returncode=result)
            except BaseException as error:
                self.owner._gap(self, "custody_direct_cleanup_" + type(error).__name__)
            self.custody["failure_cleanup_only"] = True
        finally:
            self.owner.protected -= 1


@contextlib.contextmanager
def activated():
    """Patch original Popen calls for one synchronous disposable DR run."""
    global _ACTIVE
    _need(_ACTIVE is None, "custody_nested_owner")
    _need(sys.platform.startswith("linux") or sys.platform == "darwin", "custody_platform_unsupported")
    _need(all(callable(getattr(os, name, None)) for name in ("waitid", "getsid", "getpgid"))
          and all(isinstance(getattr(os, name, None), int) and getattr(os, name) > 0
                  for name in ("P_PID", "WEXITED", "WNOHANG", "WNOWAIT")),
          "custody_wnowait_required")
    _need(threading.current_thread() is threading.main_thread(), "custody_main_thread_required")
    _need(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "custody_sigchld_must_not_reap")
    _need(subprocess.Popen is _REAL_POPEN, "custody_foreign_popen_patch")
    # Its compatibility isinstance guard must capture the real stdlib type,
    # not a temporarily patched constructor imported during the DR run.
    importlib.import_module("owned_process")
    owner, previous = Owner(), {}
    _ACTIVE = owner
    subprocess.Popen = _TrackedPopen
    try:
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, owner._interrupt)
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
        subprocess.Popen = _REAL_POPEN
        _ACTIVE = None


def _gate_main():
    # No target execution before the owner observes the original birth. An
    # admission failure closes the private pipe and the gate exits unexecuted.
    try:
        descriptor = int(sys.argv[2])
        arguments = json.loads(sys.argv[3])
        byte = os.read(descriptor, 2)
        os.close(descriptor)
        if byte != b"1" or not isinstance(arguments, list) or not arguments:
            os._exit(70)
        os.execvpe(arguments[0], arguments, os.environ)
    except BaseException:
        os._exit(71)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == _GATE:
        _gate_main()
    raise SystemExit(71)
