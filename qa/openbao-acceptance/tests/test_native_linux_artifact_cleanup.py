"""Real Linux sessions; other hosts exercise explicit synthetic kernel contracts.

Synthetic contracts never qualify a host's actual Linux process runtime. The
original four real-process branches remain required on a real Linux host.
"""
from contextlib import ExitStack
from functools import wraps
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "native_linux_artifact_run.py"
spec = importlib.util.spec_from_file_location("artifact_owned_cleanup", SCRIPT)
lane = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lane)


class SyntheticLinuxKernelContract:
    """Redirect /proc to owned data; never create or signal an actual process."""
    pid, descendant_pid = 432100005, 432100006

    def __init__(self, case):
        self.case = case
        self.clock = 1000.0
        self.descendant_ready = None
        self.started = False

    def __enter__(self):
        self.stack = ExitStack()
        try:
            return self.install()
        except BaseException:
            self.stack.close()
            raise

    def install(self):
        temporary = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="synthetic-linux-kernel-contract-"))
        self.root = Path(temporary).resolve()
        self.proc = self.root / "proc"
        self.proc.mkdir(mode=0o700)
        real_path, real_scandir = lane.Path, lane.os.scandir

        def path(value):
            actual = real_path(value)
            return self.proc if actual == real_path("/proc") else actual

        def scan(value):
            return real_scandir(self.proc if str(value) == "/proc" else value)

        for name, fallback in (("P_PID", 1), ("WEXITED", 4), ("WNOHANG", 1),
                               ("WNOWAIT", 0x1000000), ("CLD_EXITED", 1)):
            self.stack.enter_context(mock.patch.object(lane.os, name, getattr(lane.os, name, fallback), create=True))
        for target, name, replacement in (
                (lane, "Path", path), (lane.os, "scandir", scan),
                (lane.subprocess, "Popen", self.spawn), (lane.os, "waitid", self.waitid),
                (lane.os, "killpg", self.killpg), (lane.time, "monotonic", lambda: self.clock),
                (lane.time, "sleep", self.sleep)):
            self.stack.enter_context(mock.patch.object(target, name, side_effect=replacement, create=True))
        return self

    def __exit__(self, *exception):
        return self.stack.__exit__(*exception)

    def state(self, pid, state, ticks):
        directory = self.proc / str(pid)
        directory.mkdir(mode=0o700, exist_ok=True)
        fields = [state, str(os.getpid()), str(self.pid), str(self.pid), *(["0"] * 15), str(ticks)]
        (directory / "stat").write_text(str(pid) + " (synthetic-kernel-contract) " + " ".join(fields) + "\n")

    def spawn(self, argv, **options):
        if self.started or options.get("start_new_session") is not True:
            raise AssertionError("synthetic contract requires exactly one new owned session")
        self.started = True
        self.process = SimpleNamespace(pid=self.pid, args=argv, returncode=None, wait=self.wait)
        exited = self.case == "leader-exit-and-descendant" or argv[-1] == "pass"
        self.state(self.pid, "Z" if exited else "S", 100)
        if self.case == "leader-exit-and-descendant":
            if self.descendant_ready is None:
                raise AssertionError("synthetic descendant readiness path required")
            self.state(self.descendant_pid, "S", 101)
            self.descendant_ready.write_text(str(self.descendant_pid))
        return self.process

    def waitid(self, kind, pid, flags):
        if kind != lane.os.P_PID or pid != self.pid or self.process.returncode is not None:
            raise AssertionError("synthetic waitid must retain the original unreaped child")
        if lane.proc_identity(pid)["state"] == "Z":
            return SimpleNamespace(si_code=lane.os.CLD_EXITED, si_status=0)
        return None

    def killpg(self, pid, sig):
        if pid != self.pid or self.process.returncode is not None:
            raise AssertionError("synthetic signal must name the original unreaped session")
        if sig not in (signal.SIGTERM, signal.SIGKILL):
            raise AssertionError("unexpected synthetic signal")
        self.state(self.pid, "Z", 100)
        if self.case == "leader-exit-and-descendant" and sig == signal.SIGKILL:
            self.state(self.descendant_pid, "Z", 101)

    def wait(self, timeout):
        if timeout < 0 or lane.proc_identity(self.pid)["state"] != "Z":
            raise AssertionError("synthetic wait may reap only a terminated child within budget")
        self.process.returncode = 0
        return 0

    def sleep(self, seconds):
        if seconds < 0:
            raise AssertionError("negative synthetic sleep")
        self.clock += seconds


def linux_or_synthetic_kernel(case):
    def decorate(method):
        @wraps(method)
        def run(self):
            print("HEPTABAO-QA-RUNTIME-SCOPE " + json.dumps({
                "case": method.__name__, "host_system": platform.system(),
                "scope": "actual_linux_kernel" if platform.system() == "Linux"
                else "synthetic_kernel_contract_only",
            }, sort_keys=True), file=sys.stderr, flush=True)
            if platform.system() == "Linux":
                return method(self)
            with self.subTest(runtime_scope="synthetic_kernel_contract_only", host_system=platform.system()), \
                    SyntheticLinuxKernelContract(case) as kernel:
                self.synthetic_kernel_contract = kernel
                try:
                    return method(self)
                finally:
                    self.synthetic_kernel_contract = None
        return run
    return decorate


class LinuxArtifactOwnedCleanup(unittest.TestCase):
    synthetic_kernel_contract = None

    def launch(self, code):
        process = subprocess.Popen([sys.executable, "-B", "-c", code], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            return process, lane.retain_owned_session(process)
        except BaseException:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
            raise

    @linux_or_synthetic_kernel("leader-exit-and-descendant")
    def test_actual_execute_closes_descendant_after_successful_leader_exit(self):
        with tempfile.TemporaryDirectory(prefix="heptabao-artifact-owned-") as temporary:
            root = Path(temporary).resolve()
            descendant_ready = root / "descendant.pid"
            if self.synthetic_kernel_contract is not None:
                self.synthetic_kernel_contract.descendant_ready = descendant_ready
            descendant = ("import os,signal,time,pathlib;signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                          f"pathlib.Path({str(descendant_ready)!r}).write_text(str(os.getpid()));time.sleep(30)")
            leader = ("import pathlib,subprocess,sys,time;"
                      f"subprocess.Popen([sys.executable,'-B','-c',{descendant!r}]);"
                      f"ready=pathlib.Path({str(descendant_ready)!r});\nwhile not ready.exists():time.sleep(.01)\n")
            summary = {"commands": []}
            row, _ = lane.execute_command(root, "owned-synthetic-leader", [sys.executable, "-B", "-c", leader],
                                           root, lane.RUNTIME_ENV, summary, lambda: None)
            cleanup = row["owned_session_cleanup"]
            descendant_pid = int(descendant_ready.read_text())
            self.assertEqual(row["status"], "passed")
            self.assertEqual(row["exit_code"], 0)
            self.assertEqual(row["owned_child_exit_code"], 0)
            self.assertIn(descendant_pid, cleanup["live_group_before"])
            self.assertEqual(cleanup["signals"], ["SIGTERM", "SIGKILL"])
            self.assertTrue(cleanup["leader_reaped"])
            self.assertTrue(cleanup["owned_live_group_empty"])
            self.assertEqual(cleanup["live_group_before_leader_reap"], [])
            self.assertEqual((cleanup["term_seconds"], cleanup["kill_seconds"]), (5, 5))

    @linux_or_synthetic_kernel("original-wait-deadline")
    def test_original_wait_deadline_leaves_leader_owned_for_cleanup(self):
        process, owner = self.launch("import time;time.sleep(30)")
        try:
            with self.assertRaises(subprocess.TimeoutExpired):
                lane.wait_owned_exit(process, time.monotonic() + 0.03)
            self.assertIsNone(process.returncode)
            self.assertEqual(lane.retain_owned_session(process), owner)
        finally:
            receipt = lane.stop_owned(process, owner)
            self.assertTrue(receipt["leader_reaped"] and receipt["owned_live_group_empty"])

    @linux_or_synthetic_kernel("already-reaped-leader")
    def test_already_reaped_leader_refuses_group_signal(self):
        process, owner = self.launch("pass")
        process.wait(timeout=3)
        with self.assertRaisesRegex(lane.Refusal, "reaped_leader_refuses_numeric_group_signal"):
            lane.stop_owned(process, owner)

    @linux_or_synthetic_kernel("changed-owner-start-ticks")
    def test_changed_owner_start_ticks_refuses_group_signal(self):
        process, owner = self.launch("import time;time.sleep(30)")
        try:
            changed = dict(owner, start_ticks=owner["start_ticks"] + 1)
            with self.assertRaisesRegex(lane.Refusal, "identity_changed_no_signal"):
                lane.stop_owned(process, changed)
            self.assertIn(process.pid, lane.live_owned_group(owner, time.monotonic() + 1))
        finally:
            receipt = lane.stop_owned(process, owner)
            self.assertTrue(receipt["leader_reaped"] and receipt["owned_live_group_empty"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
