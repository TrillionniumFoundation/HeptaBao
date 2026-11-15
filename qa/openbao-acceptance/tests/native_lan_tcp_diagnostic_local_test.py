#!/usr/bin/env python3
"""Local process-custody regressions; these are not native/HA acceptance."""
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "native_lan_tcp_diagnostic_agent.py"
spec = importlib.util.spec_from_file_location("tcp_agent_under_test", SOURCE)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class OwnedCleanupTests(unittest.TestCase):
    def launch(self, code):
        child = subprocess.Popen([sys.executable, "-B", "-c", code], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            owner = agent.process_identity(child.pid)
            self.assertIsNotNone(owner)
        except BaseException:
            # This direct Popen has not been polled/reaped; reserve the PID
            # even if the test environment cannot observe its /proc namespace.
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=2)
            raise
        return child, owner

    def test_running_owned_session_is_stopped_then_reaped(self):
        child, owner = self.launch("import time;time.sleep(30)")
        try:
            result = agent.stop_unreaped_owned(child, owner)
            self.assertTrue(result["ownership_verified"])
            self.assertTrue(result["owned_live_group_empty"])
            self.assertTrue(result["leader_reaped"])
            self.assertEqual(result["leader_exit_code"], -signal.SIGTERM)
        finally:
            if child.returncode is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()

    def test_exited_leader_keeps_group_owned_until_term_resistant_child_stops(self):
        with tempfile.TemporaryDirectory(prefix="heptabao-tcp-custody-", dir=Path(__file__).resolve().parents[4]) as raw:
            ready = Path(raw) / "child.pid"
            descendant = ("import os,signal,time,pathlib;signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                          f"pathlib.Path({str(ready)!r}).write_text(str(os.getpid()));time.sleep(30)")
            leader = ("import subprocess,sys,time,pathlib;"
                      f"subprocess.Popen([sys.executable,'-B','-c',{descendant!r}]);"
                      f"p=pathlib.Path({str(ready)!r});\nwhile not p.exists():time.sleep(.01)\n")
            child, owner = self.launch(leader)
            try:
                deadline = time.monotonic() + 3
                while os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is None:
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(.01)
                descendant_pid = int(ready.read_text())
                self.assertIn(descendant_pid, agent.group_live_members(child.pid))
                self.assertIsNone(child.returncode)
                result = agent.stop_unreaped_owned(child, owner)
                self.assertIn(descendant_pid, result["live_group_before"])
                self.assertIn("SIGKILL", result["signals"])
                self.assertTrue(result["owned_live_group_empty"])
                self.assertTrue(result["leader_reaped"])
                self.assertEqual(result["leader_exit_code"], 0)
            finally:
                if child.returncode is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()

    def test_reaped_leader_refuses_numeric_group_signal(self):
        child, owner = self.launch("pass")
        child.wait(timeout=3)
        with self.assertRaisesRegex(agent.Refusal, "already_reaped_no_group_signal"):
            agent.stop_unreaped_owned(child, owner)

    def test_wrong_owner_identity_refuses_signal(self):
        child, owner = self.launch("import time;time.sleep(30)")
        try:
            wrong = dict(owner, start_identity="not-the-observed-start")
            with self.assertRaisesRegex(agent.Refusal, "identity_changed_no_signal"):
                agent.stop_unreaped_owned(child, wrong)
            self.assertIn(child.pid, agent.group_live_members(child.pid))
        finally:
            if child.returncode is None:
                result = agent.stop_unreaped_owned(child, owner)
                self.assertTrue(result["leader_reaped"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
