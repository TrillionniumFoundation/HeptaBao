"""Original cleanup phase budgets with controlled kernel/clock observations.

These tests never create a process or send a real signal. The existing real
owned-process cleanup tests remain unchanged and are still required on Linux.
"""
import errno
import importlib.util
from pathlib import Path
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "native_linux_artifact_run.py"
spec = importlib.util.spec_from_file_location("artifact_cleanup_phase_boundary", SCRIPT)
lane = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lane)


class LinuxArtifactCleanupPhase(unittest.TestCase):
    def run_cleanup(self, observations):
        owner = {"pid": 432100005, "ppid": 432100001, "pgid": 432100005,
                 "sid": 432100005, "start_ticks": 100, "uid": 12345}
        clock = [100.0]
        scans, signals, waits = [], [], []

        class Process:
            pid = owner["pid"]
            returncode = None

            def wait(self, timeout):
                waits.append(timeout)
                self.returncode = 0
                return 0

        def scan(actual_owner, deadline):
            self.assertEqual(actual_owner, owner)
            self.assertLess(len(scans), len(observations), "unexpected extra observation")
            expected_deadline, completed_at, value = observations[len(scans)]
            self.assertEqual(deadline, expected_deadline)
            self.assertGreaterEqual(completed_at, clock[0])
            clock[0] = completed_at
            scans.append((deadline, completed_at))
            if isinstance(value, BaseException):
                raise value
            return list(value)

        def sleep(seconds):
            self.assertGreaterEqual(seconds, 0)
            clock[0] += seconds

        def signal_owned(pid, sig):
            self.assertEqual(pid, owner["pid"])
            signals.append(sig.name)

        with mock.patch.object(lane, "retain_owned_session", return_value=owner) as retain, \
                mock.patch.object(lane, "live_owned_group", side_effect=scan), \
                mock.patch.object(lane.os, "killpg", side_effect=signal_owned), \
                mock.patch.object(lane.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(lane.time, "sleep", side_effect=sleep):
            process = Process()
            receipt = lane.stop_owned(process, owner)
        retain.assert_called_once_with(process)
        self.assertEqual(len(scans), len(observations))
        self.assertEqual((receipt["term_seconds"], receipt["kill_seconds"]), (5, 5))
        self.assertEqual(receipt["signals"], signals)
        self.assertTrue(receipt["leader_reaped"])
        self.assertEqual(waits, [max(0, 110.0 - clock[0])])
        return receipt

    def expiration(self):
        return lane.Refusal("original_cleanup_observation_deadline_expired")

    def test_term_scan_deadline_escalates_then_requires_fresh_empty_group(self):
        receipt = self.run_cleanup([
            (105.0, 100.01, [432100006]),
            (105.0, 105.001, self.expiration()),
            (110.0, 105.02, []),
        ])
        self.assertTrue(receipt["owned_live_group_empty"])
        self.assertTrue(receipt["term_observation_deadline_expired"])
        self.assertEqual(receipt["signals"], ["SIGTERM", "SIGKILL"])
        self.assertEqual(receipt["live_group_before_leader_reap"], [])
        self.assertNotIn("group_observation_error", receipt)
        self.assertLess(receipt["elapsed_seconds"], 10)

    def test_initial_term_scan_deadline_preserves_original_total_budget(self):
        receipt = self.run_cleanup([
            (105.0, 105.001, self.expiration()),
            (110.0, 105.02, []),
        ])
        self.assertTrue(receipt["owned_live_group_empty"])
        self.assertTrue(receipt["term_observation_deadline_expired"])
        self.assertEqual(receipt["signals"], ["SIGTERM", "SIGKILL"])
        self.assertNotIn("group_observation_error", receipt)
        self.assertLess(receipt["elapsed_seconds"], 10)

    def test_term_deadline_cannot_admit_a_late_empty_kill_scan(self):
        receipt = self.run_cleanup([
            (105.0, 100.01, [432100006]),
            (105.0, 105.001, self.expiration()),
            (110.0, 110.001, []),
        ])
        self.assertEqual(receipt["live_group_before_leader_reap"], [])
        self.assertFalse(receipt["owned_live_group_empty"])

    def test_term_deadline_cannot_skip_fresh_kill_phase_observation(self):
        receipt = self.run_cleanup([
            (105.0, 100.01, [432100006]),
            (105.0, 110.001, self.expiration()),
        ])
        self.assertEqual(receipt["signals"], ["SIGTERM", "SIGKILL"])
        self.assertEqual(receipt["live_group_before_leader_reap"], [432100006])
        self.assertFalse(receipt["owned_live_group_empty"])

    def test_identity_and_io_errors_remain_fatal_after_phase_expiry_and_empty_scan(self):
        errors = [
            lane.Refusal("owned_leader_identity_changed_no_signal"),
            lane.Refusal("owned_group_member_identity_mismatch"),
            lane.Refusal("kernel_process_identity_malformed"),
            OSError(errno.EIO, "synthetic observation I/O failure"),
            PermissionError(errno.EPERM, "synthetic observation permission failure"),
        ]
        for error in errors:
            with self.subTest(error=repr(error)):
                receipt = self.run_cleanup([
                    (105.0, 100.01, error),
                    (105.0, 105.001, self.expiration()),
                    (110.0, 105.02, []),
                ])
                self.assertEqual(receipt["live_group_before_leader_reap"], [])
                self.assertFalse(receipt["owned_live_group_empty"])
                expected = str(error) if isinstance(error, lane.Refusal) else type(error).__name__
                self.assertEqual(receipt["group_observation_error"], expected)

    def test_deadline_label_before_actual_term_expiry_is_not_recoverable(self):
        receipt = self.run_cleanup([
            (105.0, 100.01, [432100006]),
            (105.0, 100.02, self.expiration()),
            (110.0, 100.03, []),
        ])
        self.assertFalse(receipt["owned_live_group_empty"])
        self.assertNotIn("term_observation_deadline_expired", receipt)
        self.assertEqual(receipt["group_observation_error"],
                         "original_cleanup_observation_deadline_expired")

    def test_kill_phase_observation_deadline_is_fatal(self):
        receipt = self.run_cleanup([
            (105.0, 100.01, [432100006]),
            (105.0, 105.001, self.expiration()),
            (110.0, 110.001, self.expiration()),
        ])
        self.assertFalse(receipt["owned_live_group_empty"])
        self.assertEqual(receipt["group_observation_error"],
                         "original_cleanup_observation_deadline_expired")

    def test_normal_term_completion_keeps_original_success_path(self):
        receipt = self.run_cleanup([
            (105.0, 100.01, [432100006]),
            (105.0, 100.02, []),
        ])
        self.assertEqual(receipt["signals"], ["SIGTERM"])
        self.assertTrue(receipt["owned_live_group_empty"])
        self.assertNotIn("term_observation_deadline_expired", receipt)
        self.assertNotIn("group_observation_error", receipt)


if __name__ == "__main__":
    unittest.main(verbosity=2)
