#!/usr/bin/env python3
"""Execute only AST-selected QA ownership methods with entirely in-memory fakes.

No target main, network, subprocess, product, credential, or fixture runs here.
The two source files are explicit offline inputs; only a JSON report is printed.
"""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path
import signal
import subprocess
import sys
import types
import os


def selected(raw, names, filename):
    tree = ast.parse(raw, filename=filename)
    nodes = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))
             and node.name in names]
    if {node.name for node in nodes} != set(names):
        raise AssertionError("selected source definitions")
    unit = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), *nodes], type_ignores=[])
    return compile(ast.fix_missing_locations(unit), filename, "exec")


class Model:
    def __init__(self, config):
        self.config = config
        self.now = 1_000_000_000
        self.owner = None
        self.created = []
        self.fd_values = {}
        self.next_fd = 300
        self.open_count = 0
        self.waitid_count = 0
        self.wait_count = 0
        self.stop_count = 0
        self.sleeps = []
        self.event_list = list(config.get("events", [(os.CLD_EXITED, 0)]))
        self.last_terminal = None

    def stat_bytes(self):
        values = ["0"] * 20
        values[0] = self.config.get("state", "Z")
        values[1] = str(self.config.get("ppid", 7))
        values[2] = str(self.config.get("pgid", 42))
        ticks = 100 + (1 if self.config.get("identity_change") and self.open_count > 1 else 0)
        values[19] = str(ticks)
        return ("42 (fixed-command) " + " ".join(values) + "\n").encode()

    def open(self, path, flags, mode):
        if str(path) != "/proc/42/stat" or flags != os.O_RDONLY | os.O_NOFOLLOW:
            raise AssertionError("unexpected filesystem access")
        self.open_count += 1
        fd = self.next_fd
        self.next_fd += 1
        self.fd_values[fd] = self.stat_bytes()
        return fd

    def read(self, fd, count):
        if self.config.get("read_error"):
            raise OSError("synthetic read error")
        value = self.fd_values[fd]
        out, self.fd_values[fd] = value[:count], value[count:]
        return out

    def close(self, fd):
        if self.config.get("close_error"):
            raise OSError("synthetic close error")
        del self.fd_values[fd]

    def waitid(self, idtype, pid, flags):
        if idtype != os.P_PID or pid != 42 or flags != os.WEXITED | os.WNOHANG | os.WNOWAIT:
            raise AssertionError("waitid contract")
        if not self.created or self.created[0].returncode is not None:
            raise ChildProcessError("already reaped")
        self.waitid_count += 1
        value = self.event_list[0]
        if len(self.event_list) > 1:
            self.event_list.pop(0)
        if isinstance(value, BaseException):
            raise value
        if value is None:
            return None
        code, status = value
        event = types.SimpleNamespace(si_pid=self.config.get("event_pid", 42),
                                      si_uid=self.config.get("event_uid", 1000),
                                      si_code=code, si_status=status)
        self.last_terminal = event
        return event

    def popen(self, argv, **options):
        if options.get("shell") is not False or options.get("close_fds") is not True:
            raise AssertionError("direct invocation flags")
        if self.config.get("popen_error"):
            raise OSError("synthetic exec error")
        model = self

        class Process:
            pid = 42
            args = argv
            returncode = None

            def poll(self):
                raise AssertionError("poll must not reap before the custody proof")

            def wait(self, timeout):
                if model.last_terminal is None or timeout <= 0:
                    raise AssertionError("wait before known WNOWAIT terminal")
                model.wait_count += 1
                event = model.last_terminal
                actual = event.si_status if event.si_code == os.CLD_EXITED else -event.si_status
                self.returncode = model.config.get("wait_returncode", actual)
                return self.returncode

        child = Process()
        self.created.append(child)
        if self.config.get("pending_signal"):
            self.owner.interrupted(signal.SIGTERM, None)
            if self.owner.pending_signal != signal.SIGTERM:
                raise AssertionError("creation signal must be deferred")
        return child

    def stop(self, child, captured=None):
        self.stop_count += 1
        child.returncode = 0 if child.returncode is None else child.returncode
        return {"pid": child.pid, "owned_stopped": True, "remaining": [],
                "start_ticks": captured.get("start_ticks") if captured else None,
                "wait_returncode": child.returncode}

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += max(1, int(seconds * 1_000_000_000))


def run_case(name, config, builder_code, reference_code, *, expected_error=None,
             expected_code=0, expire=False, invalid_argv=False):
    model = Model(config)

    class Refused(RuntimeError):
        pass

    class Base:
        def interrupted(self, signum, frame):
            if self.creating_child:
                if self.pending_signal is None:
                    self.pending_signal = signum
                return
            raise Refused("owner_signal_" + str(signum))

    cli = types.SimpleNamespace(Owner=Base, Refused=Refused,
                                stop_owned=model.stop, stop_provisional=model.stop)
    fake_os = types.SimpleNamespace(open=model.open, read=model.read, close=model.close,
        getpid=lambda: 7, getuid=lambda: 1000, fsencode=os.fsencode, waitid=model.waitid,
        P_PID=os.P_PID, WEXITED=os.WEXITED, WNOHANG=os.WNOHANG, WNOWAIT=os.WNOWAIT,
        CLD_EXITED=os.CLD_EXITED, CLD_KILLED=os.CLD_KILLED, CLD_DUMPED=os.CLD_DUMPED,
        O_RDONLY=os.O_RDONLY, O_NOFOLLOW=os.O_NOFOLLOW)
    fake_signal = types.SimpleNamespace(SIGCHLD=signal.SIGCHLD, SIG_DFL=signal.SIG_DFL,
        NSIG=signal.NSIG, getsignal=lambda signum: signal.SIG_IGN if config.get("sigchld_ignored") else signal.SIG_DFL)
    fake_subprocess = types.SimpleNamespace(Popen=model.popen, DEVNULL=subprocess.DEVNULL,
                                           TimeoutExpired=subprocess.TimeoutExpired)
    ns = {"__name__": "selected_qa_components", "Path": Path, "hashlib": hashlib,
          "os": fake_os, "signal": fake_signal, "subprocess": fake_subprocess,
          "time": types.SimpleNamespace(monotonic_ns=lambda: model.now, sleep=model.sleep),
          "ROOT": Path("/qa-mock-root"), "TOOL_ROOT": Path("/qa-mock-tools"),
          "OPEN_FDS": {201, 202}, "FD_CLOSE_FAILED": False}
    exec(builder_code, ns)
    ns["require"] = ns["need"]
    exec(reference_code, ns)
    reference = types.SimpleNamespace(owner_class=ns["owner_class"])
    owner = ns["qa_command_owner_class"](reference, cli)(ns["ROOT"])
    model.owner = owner
    until = model.now - 1 if expire else model.now + 5_000_000
    error = None
    code = None
    try:
        child = owner.start_child(["/not-allowed" if invalid_argv else "/usr/bin/git", "--version"],
            until=until, cwd=ns["ROOT"], stdin=subprocess.DEVNULL,
            stdout=201, stderr=202, env={}, start_new_session=True)
        code = owner.wait_child(child, until)
    except BaseException as caught:
        error = type(caught).__name__
    if error != expected_error:
        raise AssertionError(f"{name}: error {error!r}, expected {expected_error!r}")
    if expected_error is None and code != expected_code:
        raise AssertionError(f"{name}: exit code changed")
    if expected_error is None and not owner.child_provenance[0]["terminal_consumed"]:
        raise AssertionError(f"{name}: terminal not consumed")
    if expected_error is not None and owner.child_provenance and owner.child_provenance[0]["terminal_consumed"]:
        raise AssertionError(f"{name}: failure marked terminal success")
    first = owner.cleanup()
    second = owner.cleanup()
    if model.stop_count != len(model.created) or len(first) != len(second):
        raise AssertionError(f"{name}: shared cleanup retried")
    if config.get("close_error"):
        if not ns["FD_CLOSE_FAILED"] or ns["OPEN_FDS"] == {201, 202}:
            raise AssertionError("close error lost")
    elif ns["OPEN_FDS"] != {201, 202} or model.fd_values:
        raise AssertionError(f"{name}: proc descriptor leak")
    if (expire or invalid_argv or config.get("sigchld_ignored")) and model.created:
        raise AssertionError(f"{name}: denied input dispatched")
    return {"case": name, "passed": True, "popen_count": len(model.created),
            "waitid_count": model.waitid_count, "wait_count": model.wait_count,
            "stop_count": model.stop_count, "error_type": error,
            "returncode": code, "cleanup_collection_count": 2,
            "all_proc_fds_closed": not model.fd_values,
            "close_failure_preserved": ns["FD_CLOSE_FAILED"]}


def main():
    builder = Path(sys.argv[1]).read_text()
    reference = Path(sys.argv[2]).read_text()
    names = {"BindingError", "open_fd", "close_fd", "need", "remaining", "sha", "qa_command_owner_class"}
    builder_code = selected(builder, names, "selected_builder.py")
    reference_code = selected(reference, {"owner_class"}, "selected_owner_reference.py")
    cases = [
        ("terminal_before_capture_remains_waitable", {"events": [(os.CLD_EXITED, 0)]}, {}),
        ("running_then_terminal_once", {"events": [None, None, (os.CLD_EXITED, 0)], "state": "R"}, {}),
        ("nonzero_exit_preserved", {"events": [(os.CLD_EXITED, 7)]}, {"expected_code": 7}),
        ("signal_exit_preserved", {"events": [(os.CLD_KILLED, 9)]}, {"expected_code": -9}),
        ("no_terminal_event_cannot_succeed", {"events": [None]}, {"expected_error": "TimeoutExpired"}),
        ("echild_not_converted_to_zero", {"events": [ChildProcessError("synthetic no child")]}, {"expected_error": "ChildProcessError"}),
        ("wrong_parent_refused", {"ppid": 8}, {"expected_error": "BindingError"}),
        ("start_identity_change_refused", {"identity_change": True}, {"expected_error": "BindingError"}),
        ("waitid_terminal_change_refused", {"events": [(os.CLD_EXITED, 0), (os.CLD_EXITED, 7)]}, {"expected_error": "BindingError"}),
        ("popen_wait_disagreement_refused", {"wait_returncode": 1}, {"expected_error": "BindingError"}),
        ("expired_before_popen", {}, {"expected_error": "BindingError", "expire": True}),
        ("ignored_sigchld_refused", {"sigchld_ignored": True}, {"expected_error": "BindingError"}),
        ("pending_signal_preserves_registration", {"pending_signal": True}, {"expected_error": "Refused"}),
        ("stat_read_error_closes_fd", {"read_error": True}, {"expected_error": "OSError"}),
        ("stat_close_error_not_green", {"close_error": True}, {"expected_error": "OSError"}),
        ("unexpected_executable_refused", {}, {"expected_error": "BindingError", "invalid_argv": True}),
        ("wrong_waitid_pid_refused", {"event_pid": 43}, {"expected_error": "BindingError"}),
        ("failed_popen_no_registered_child", {"popen_error": True}, {"expected_error": "OSError"}),
    ]
    results = [run_case(name, config, builder_code, reference_code, **kwargs)
               for name, config, kwargs in cases]
    print(json.dumps({"schema": "qa-builder-custody-memory-components-v1",
        "builder_sha256": hashlib.sha256(builder.encode()).hexdigest(),
        "owner_reference_sha256": hashlib.sha256(reference.encode()).hexdigest(),
        "selected_definitions": sorted(names), "results": results,
        "passed": len(results), "actual_children": 0, "network_requests": 0,
        "product_or_target_main_executed": False,
        "scope": "In-memory injected OS/Popen only; does not prove real Linux or ROG syscall behavior."},
        sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
