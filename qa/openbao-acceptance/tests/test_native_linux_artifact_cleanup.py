"""Real owned process failures only; no Cargo, HeptaBao, SSH or LAN run."""
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "native_linux_artifact_run.py"
spec = importlib.util.spec_from_file_location("artifact_owned_cleanup", SCRIPT)
lane = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lane)


class LinuxArtifactOwnedCleanup(unittest.TestCase):
    def launch(self, code):
        process = subprocess.Popen([sys.executable, "-B", "-c", code], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            return process, lane.retain_owned_session(process)
        except BaseException:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
            raise

    def test_actual_execute_closes_descendant_after_successful_leader_exit(self):
        with tempfile.TemporaryDirectory(prefix="heptabao-artifact-owned-") as temporary:
            root = Path(temporary).resolve()
            descendant_ready = root / "descendant.pid"
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

    def test_already_reaped_leader_refuses_group_signal(self):
        process, owner = self.launch("pass")
        process.wait(timeout=3)
        with self.assertRaisesRegex(lane.Refusal, "reaped_leader_refuses_numeric_group_signal"):
            lane.stop_owned(process, owner)

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
