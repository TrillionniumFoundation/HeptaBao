#!/usr/bin/env python3
"""NEW once-only Linux custody components; no product, Cargo, repository, or network.

The three public Git commands share one original tool-sized 15 s absolute
deadline. The retained owner supplies its one TERM5/KILL5 cleanup collection.
Only anonymous memfd output is written. All selected source is carried on stdin.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import types

SOURCE_PINS = {
    "builder": (42820, "c961a54dfc35332be035bb16fc1ae697199e35da496b0c9ea52c35dc3f8455d8"),
    "owner_reference": (61210, "10816d06fd5ad59175872ccb7db1337d7677e92405a26a7ab1cae2796ee0a86c"),
    "cli_reference": (46586, "18318841d3538e60fddf951708055a206402f5bf1ecdacc2bfceabec4f998dd9"),
}
TOOLS = {
    "python": {"path": "/usr/bin/python3.12", "bytes": 8020928,
               "sha256": "e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f",
               "uid": 0, "mode": 493},
    "git": {"path": "/usr/bin/git", "bytes": 4547768,
            "sha256": "ed8b2df973b28c0fb773b9c0dc0816d3ee2b3835bb932d9153c21417bb51b362",
            "uid": 0, "mode": 493},
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def selected(raw, names, label, namespace):
    tree = ast.parse(raw, filename=label)
    nodes = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))
             and node.name in names]
    require({node.name for node in nodes} == names, "selected_definitions_exact")
    unit = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), *nodes], type_ignores=[])
    exec(compile(ast.fix_missing_locations(unit), label, "exec"), namespace)


def main():
    started = time.monotonic_ns()
    until = started + 15_000_000_000
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-sha256", required=True)
    parser.add_argument("--carrier-sha256", required=True)
    args = parser.parse_args()
    require(sys.flags.isolated == sys.flags.no_site == sys.flags.dont_write_bytecode == 1,
            "python_I_S_B_required")
    require(sys.orig_argv.count("-c") == 1, "exact_c_source_required")
    source = sys.orig_argv[sys.orig_argv.index("-c") + 1].encode()
    require(digest(source) == args.self_sha256, "exact_component_source")
    require(os.getuid() == 1000 and os.uname().sysname == "Linux"
            and os.uname().machine == "x86_64", "fixed_linux_owner")
    require(str(Path(sys.executable).resolve(strict=True)) == TOOLS["python"]["path"],
            "same_pinned_python_path")
    raw = sys.stdin.buffer.read(524289)
    require(len(raw) <= 524288 and digest(raw) == args.carrier_sha256, "exact_bounded_carrier")
    carrier = json.loads(raw, object_pairs_hook=unique)
    require(type(carrier) is dict and set(carrier) == {"schema", "sources"}
            and carrier["schema"] == "qa-custody-components-source-v1"
            and set(carrier["sources"]) == set(SOURCE_PINS), "carrier_schema")
    recovered = {}
    for role, (size, expected) in SOURCE_PINS.items():
        text = carrier["sources"][role]
        require(type(text) is str and len(text.encode()) == size and digest(text.encode()) == expected,
                "exact_selected_source_pin")
        recovered[role] = text
    # No module main or top-level product/fixture code is executed.
    ns = {"__name__": "qa_custody_selected", "Path": Path, "hashlib": hashlib,
          "os": os, "signal": signal, "stat": stat, "subprocess": subprocess,
          "sys": sys, "time": time, "re": re,
          "ROOT": Path("/home/qian-qi"),
          "TOOL_ROOT": Path("/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin"),
          "OPEN_FDS": set(), "FD_CLOSE_FAILED": False}
    selected(recovered["builder"], {"BindingError", "open_fd", "close_fd", "need", "remaining",
        "sha", "identity", "exact_path", "no_symlink_ancestors", "read_file", "pin_file",
        "fixed_error", "qa_command_owner_class"}, "selected_builder.py", ns)
    cli_ns = {"__name__": "qa_custody_cli_selected", "Path": Path, "hashlib": hashlib,
              "os": os, "signal": signal, "subprocess": subprocess, "time": time}
    selected(recovered["cli_reference"], {"Refused", "process_identity", "group_members",
        "stop_owned", "stop_provisional", "Owner"}, "selected_cli_reference.py", cli_ns)
    cli = types.SimpleNamespace(**cli_ns)
    owner_ns = {"__name__": "qa_custody_owner_selected", "Path": Path, "require": ns["need"]}
    selected(recovered["owner_reference"], {"owner_class"}, "selected_owner_reference.py", owner_ns)
    reference = types.SimpleNamespace(owner_class=owner_ns["owner_class"])
    ActualOwner = ns["qa_command_owner_class"](reference, cli)

    class TerminalBeforeStat(ActualOwner):
        def __init__(self, root):
            super().__init__(root)
            self.force_terminal = False
            self.forced_pids = set()
            self.forced_observations = []

        def child_stat(self, process, original_until):
            # The actual start_child has already registered this exact Popen.
            # Delay only its first stat observation, without reaping or spawning.
            if self.force_terminal and process.pid not in self.forced_pids:
                require(any(child is process for child, _ in self.children), "registered_before_forcing_terminal")
                while True:
                    event = self.peek_child_exit(process, original_until)
                    if event is not None:
                        self.forced_pids.add(process.pid)
                        self.forced_observations.append(event)
                        break
                    time.sleep(min(0.001, ns["remaining"](original_until)))
            return super().child_stat(process, original_until)

    owner = TerminalBeforeStat(ns["ROOT"])
    memfds = set()

    def new_memfd(name):
        # Use the retained signal deferral while registering this owned fd.
        require(not owner.creating_child, "nested_owned_resource_creation")
        owner.creating_child = True
        try:
            fd = os.memfd_create(name, os.MFD_CLOEXEC)
            ns["OPEN_FDS"].add(fd)
            memfds.add(fd)
            return fd
        finally:
            owner.creating_child = False
            pending, owner.pending_signal = owner.pending_signal, None
            if pending is not None:
                raise cli.Refused("owner_signal_" + str(pending))

    def close_memfd(fd):
        require(fd in memfds, "actual_owned_memfd_required")
        memfds.remove(fd)  # A failed close is recorded, never retried.
        ns["close_fd"](fd)

    report = {"schema": "qa-custody-linux-owned-components-v1", "status": "failed",
              "source_sha256": args.self_sha256, "carrier_sha256": args.carrier_sha256,
              "started_monotonic_ns": started, "deadline_monotonic_ns": until,
              "shared_component_seconds": 15, "cleanup_term_seconds": 5, "cleanup_kill_seconds": 5,
              "cases": [], "product_or_cargo_requests": 0, "network_requests": 0,
              "on_disk_output_files": 0, "candidate_main_executed": False}
    signal.signal(signal.SIGTERM, owner.interrupted)
    signal.signal(signal.SIGINT, owner.interrupted)
    try:
        before = {name: ns["pin_file"](pin, until)[1] for name, pin in TOOLS.items()}
        report["tools_before"] = before
        env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C",
               "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
               "GIT_OPTIONAL_LOCKS": "0", "PYTHONDONTWRITEBYTECODE": "1"}
        for label, forced, suffix, positive in (
                ("ordinary_short_owned_git", False, "--version", True),
                ("already_terminal_unreaped_git", True, "--version", True),
                ("nonzero_terminal_preserved", True, "--qa-custody-no-such-option", False)):
            ns["remaining"](until)
            out = new_memfd("qa-custody-public-stdout")
            err = None
            try:
                err = new_memfd("qa-custody-public-stderr")
                owner.force_terminal = forced
                argv = ["/usr/bin/git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", suffix]
                child = owner.start_child(argv, until=until, cwd=ns["ROOT"], stdin=subprocess.DEVNULL,
                    stdout=out, stderr=err, env=env, start_new_session=True)
                code = owner.wait_child(child, until)
                stdout_stderr = []
                for fd in (out, err):
                    os.lseek(fd, 0, os.SEEK_SET)
                    value = os.read(fd, 8193)
                    require(len(value) <= 8192 and os.read(fd, 1) == b"", "bounded_public_command_output")
                    stdout_stderr.append(value)
                remaining_group = cli.group_members(child.pid)
                proof = owner.command_custody[id(child)]
                require(proof["custody_verified"] and proof["terminal_consumed"]
                        and child.returncode == code and not remaining_group, "complete_real_owned_command")
                require((code == 0) if positive else (code > 0), "expected_exit_class")
                if positive:
                    require(re.fullmatch(rb"git version [0-9A-Za-z.+_-]+\n", stdout_stderr[0]) is not None
                            and not stdout_stderr[1], "public_git_version_shape")
                if forced:
                    require(proof["identity_before"]["state"] == "Z"
                            and proof["terminal_event"] is not None, "terminal_before_capture_observed")
                report["cases"].append({"case": label, "passed": True, "pid": child.pid,
                    "returncode": code, "terminal_before_stat_forced": forced,
                    "remaining": remaining_group,
                    "stdout_bytes": len(stdout_stderr[0]), "stdout_sha256": digest(stdout_stderr[0]),
                    "stderr_bytes": len(stdout_stderr[1]), "stderr_sha256": digest(stdout_stderr[1]),
                    "custody": proof})
            finally:
                close_error = None
                for fd in (err, out):
                    if fd is not None:
                        try:
                            close_memfd(fd)
                        except BaseException as error:
                            if close_error is None:
                                close_error = error
                if close_error is not None:
                    raise close_error
        after = {name: ns["pin_file"](pin, until)[1] for name, pin in TOOLS.items()}
        require(before == after, "actual_pinned_tools_unchanged")
        report["tools_after"] = after
        ns["remaining"](until)
        report["status"] = "passed"
    except BaseException as error:
        report["failure_code"] = ns["fixed_error"](error)
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        report["cleanup"] = owner.cleanup()
        for fd in tuple(memfds):
            try:
                close_memfd(fd)
            except BaseException as error:
                report.setdefault("memfd_close_failures", []).append(type(error).__name__)
        report["all_owned_stopped"] = all(row.get("owned_stopped") and row.get("direct_child_reaped")
                                          for row in report["cleanup"])
        report["all_input_fds_closed"] = not ns["OPEN_FDS"] and not ns["FD_CLOSE_FAILED"]
        report["forced_terminal_observations"] = owner.forced_observations
        completed = time.monotonic_ns()
        report["completed_monotonic_ns"] = completed
        report["within_shared_15s"] = completed < until
        if not (report["all_owned_stopped"] and report["all_input_fds_closed"]
                and report["within_shared_15s"] and len(report["cases"]) == 3):
            report["status"] = "failed"
        print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report["status"] == "passed" and time.monotonic_ns() < until else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"schema": "qa-custody-linux-owned-components-preflight-failure-v1",
                          "status": "failed", "error_type": type(error).__name__,
                          "product_or_cargo_requests": 0}, sort_keys=True), flush=True)
        raise SystemExit(2) from None
