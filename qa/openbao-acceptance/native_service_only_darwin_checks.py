#!/usr/bin/env python3
"""Narrow Darwin custody regressions; optional two actual Mac child checks."""
import argparse
import copy
import hashlib
import json
import os
import pathlib
import signal
import sys
import types
import unittest
from unittest import mock


PARENT_PID = os.getpid()
CHILD_PID = 42420
START = "Mon Oct 19 07:05:16 2026"
CONTROLLER = OUTPUT = None


def leader(state="Z", **changes):
    row = {"pid": CHILD_PID, "ppid": PARENT_PID, "pgid": CHILD_PID,
           "state": state, "uid": os.geteuid(), "lstart": START}
    row.update(changes)
    return row


def event(status=0, pid=CHILD_PID):
    return os.waitid_result((pid, 0, signal.SIGCHLD, status, os.CLD_EXITED))


class DarwinIdentityChecks(unittest.TestCase):
    def setUp(self):
        self.process = types.SimpleNamespace(pid=CHILD_PID, returncode=None,
                                             wait=mock.Mock(name="Popen.wait"))
        self.stack = []
        for target, name, value in (
                (CONTROLLER.sys, "platform", "darwin"),
                (CONTROLLER.os, "getpid", mock.Mock(return_value=PARENT_PID)),
                (CONTROLLER.os, "getpgid", mock.Mock(return_value=CHILD_PID)),
                (CONTROLLER.os, "getsid", mock.Mock(return_value=CHILD_PID)),
                (CONTROLLER.os, "killpg", mock.Mock()),
                (CONTROLLER.os, "waitid", mock.Mock(return_value=event())),
                (CONTROLLER, "process_rows", mock.Mock(return_value=[leader()]))):
            patch = mock.patch.object(target, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def assert_no_signal_or_reap(self):
        CONTROLLER.os.killpg.assert_not_called()
        self.process.wait.assert_not_called()
        self.assertIsNone(self.process.returncode)

    def test_zombie_custody_keeps_the_live_same_group_child_visible(self):
        rows = [leader(), leader("S", pid=CHILD_PID + 1, ppid=1)]
        CONTROLLER.process_rows.return_value = rows
        CONTROLLER.os.getpgid.side_effect = ProcessLookupError(3, "zombie")
        CONTROLLER.os.getsid.side_effect = ProcessLookupError(3, "zombie")
        result = CONTROLLER.owned_group(self.process)
        self.assertEqual(result, rows)
        self.assertEqual([r["pid"] for r in CONTROLLER.live_group(result)], [CHILD_PID + 1])
        self.assertEqual(CONTROLLER.os.waitid.call_count, 2)
        for call in CONTROLLER.os.waitid.call_args_list:
            self.assertEqual(call.args, (os.P_PID, CHILD_PID, os.WEXITED | os.WNOHANG | os.WNOWAIT))
        CONTROLLER.os.getpgid.assert_not_called()
        CONTROLLER.os.getsid.assert_not_called()
        self.assertEqual(self.process._heptabao_darwin_leader_identity,
                         {k: leader()[k] for k in ("pid", "ppid", "pgid", "uid", "lstart")})
        self.assert_no_signal_or_reap()

    def test_zombie_without_an_original_child_event_fails_closed(self):
        for value in (None, event(pid=CHILD_PID + 1), ChildProcessError("already reaped")):
            with self.subTest(value=type(value).__name__):
                CONTROLLER.os.waitid.side_effect = value if isinstance(value, Exception) else None
                CONTROLLER.os.waitid.return_value = value
                with self.assertRaises((RuntimeError, ChildProcessError)):
                    CONTROLLER.finish_owned(self.process, True)
                self.assert_no_signal_or_reap()

    def test_second_waitid_must_be_the_same_unreaped_event(self):
        CONTROLLER.os.waitid.side_effect = [event(0), event(1)]
        with self.assertRaisesRegex(RuntimeError, "custody changed"):
            CONTROLLER.finish_owned(self.process, True)
        self.assert_no_signal_or_reap()

    def test_changed_parent_group_or_start_cannot_authorize_cleanup(self):
        original = {k: leader()[k] for k in ("pid", "ppid", "pgid", "uid", "lstart")}
        self.process._heptabao_darwin_leader_identity = original
        for change in ({"ppid": PARENT_PID + 1}, {"pgid": CHILD_PID + 1},
                       {"lstart": "Mon Oct 19 07:05:17 2026"}):
            with self.subTest(change=change):
                CONTROLLER.process_rows.return_value = [leader(**change)]
                with self.assertRaisesRegex(RuntimeError, "identity differs"):
                    CONTROLLER.finish_owned(self.process, True)
                self.assert_no_signal_or_reap()

    def test_identity_cannot_change_between_the_two_exit_events(self):
        CONTROLLER.process_rows.side_effect = [[leader()], [leader(lstart="Mon Oct 19 07:05:17 2026")]]
        with self.assertRaisesRegex(RuntimeError, "custody changed"):
            CONTROLLER.finish_owned(self.process, True)
        self.assert_no_signal_or_reap()

    def test_fresh_process_uid_must_equal_controller_even_when_waitid_uid_is_zero(self):
        CONTROLLER.process_rows.return_value = [leader(uid=os.geteuid() + 1)]
        with self.assertRaisesRegex(RuntimeError, "uid identity differs"):
            CONTROLLER.finish_owned(self.process, True)
        self.assert_no_signal_or_reap()

    def test_reaped_popen_is_rejected_before_any_group_observation(self):
        self.process.returncode = 0
        with self.assertRaisesRegex(RuntimeError, "reaped before"):
            CONTROLLER.owned_group(self.process)
        CONTROLLER.process_rows.assert_not_called()
        CONTROLLER.os.waitid.assert_not_called()
        CONTROLLER.os.killpg.assert_not_called()

    def test_live_leader_still_requires_the_original_sid(self):
        CONTROLLER.process_rows.return_value = [leader("Ss")]
        CONTROLLER.os.getsid.return_value = CHILD_PID + 1
        with self.assertRaisesRegex(RuntimeError, "PGID and SID"):
            CONTROLLER.finish_owned(self.process, True)
        CONTROLLER.os.getpgid.assert_called_once_with(CHILD_PID)
        CONTROLLER.os.getsid.assert_called_once_with(CHILD_PID)
        CONTROLLER.os.waitid.assert_not_called()
        self.assert_no_signal_or_reap()

    def test_live_to_zombie_syscall_race_requires_a_fresh_matching_exit_proof(self):
        CONTROLLER.process_rows.side_effect = [[leader("Ss")], [leader()], [leader()]]
        CONTROLLER.os.getsid.side_effect = ProcessLookupError(3, "just exited")
        result = CONTROLLER.owned_group(self.process)
        self.assertEqual(result, [leader()])
        self.assertEqual(CONTROLLER.os.waitid.call_count, 2)
        self.assert_no_signal_or_reap()

    def test_esrch_with_a_missing_or_still_live_leader_never_means_empty_group(self):
        for changed in ([], [leader("Ss")]):
            with self.subTest(changed=changed):
                CONTROLLER.process_rows.side_effect = [[leader("Ss")], changed]
                CONTROLLER.os.getpgid.side_effect = ProcessLookupError(3, "unresolved")
                with self.assertRaises(RuntimeError):
                    CONTROLLER.finish_owned(self.process, True)
                self.assert_no_signal_or_reap()

    def test_live_capture_binds_the_later_zombie_start_identity(self):
        CONTROLLER.process_rows.return_value = [leader("Ss")]
        self.assertEqual(CONTROLLER.owned_group(self.process), [leader("Ss")])
        CONTROLLER.process_rows.return_value = [leader(lstart="Mon Oct 19 07:05:17 2026")]
        with self.assertRaisesRegex(RuntimeError, "start identity differs"):
            CONTROLLER.finish_owned(self.process, True)
        self.assert_no_signal_or_reap()


class ActualMacCustodyChecks(unittest.TestCase):
    def run_owned(self, program):
        path = OUTPUT / self._testMethodName
        path.mkdir(mode=0o700)
        records = []

        def save():
            CONTROLLER.write_json(path / "command-receipt.json", {"commands": records})

        result = CONTROLLER.run_logged("synthetic-python", [sys.executable, "-c", program],
                                       path, os.environ.copy(), path, records, save, budget=10)
        self.assertEqual(result["darwin_leader_identity"]["pid"], result["pid"])
        self.assertEqual(result["darwin_leader_identity"]["ppid"], os.getpid())
        self.assertEqual(result["darwin_leader_identity"]["pgid"], result["pid"])
        self.assertEqual(result["darwin_leader_identity"]["uid"], os.geteuid())
        self.assertTrue(result["cleanup"]["leader_reaped"])
        self.assertTrue(result["cleanup"]["original_group_observed_without_live_members"])
        self.assertEqual(result["exit_code"], 0)
        return result

    def test_actual_mac_normal_exit_is_reaped_without_a_signal(self):
        result = self.run_owned("print('owned Darwin normal exit',flush=True)")
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["cleanup"]["signals"], [])
        self.assertFalse(result["cleanup"]["unexpected_live_descendants_after_exit"])

    def test_actual_mac_exited_leader_keeps_live_descendant_visible_until_cleanup(self):
        program = ("import subprocess,sys; p=subprocess.Popen([sys.executable,'-c',"
                   "'import time; time.sleep(60)']); print('child='+str(p.pid),flush=True)")
        result = self.run_owned(program)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["cleanup"]["unexpected_live_descendants_after_exit"])
        self.assertIn("SIGTERM", result["cleanup"]["signals"])


def main():
    global CONTROLLER, OUTPUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller", type=pathlib.Path, required=True)
    parser.add_argument("--expected-controller-sha256", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--mac-smoke", action="store_true")
    args = parser.parse_args()
    raw = args.controller.read_bytes()
    actual_sha = hashlib.sha256(raw).hexdigest()
    if actual_sha != args.expected_controller_sha256:
        parser.error("controller SHA256 differs from the exact candidate")
    if args.mac_smoke and sys.platform != "darwin":
        parser.error("actual Mac custody checks require Darwin; no mocked pass is permitted")
    OUTPUT = args.output.resolve()
    OUTPUT.mkdir(mode=0o700, parents=False, exist_ok=False)
    CONTROLLER = types.ModuleType("native_only_darwin_candidate")
    CONTROLLER.__file__ = str(args.controller.resolve())
    exec(compile(raw, CONTROLLER.__file__, "exec"), CONTROLLER.__dict__)
    selected = ActualMacCustodyChecks if args.mac_smoke else DarwinIdentityChecks
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(selected)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    CONTROLLER.write_json(OUTPUT / "summary.json", {
        "schema": "heptabao.native-only-darwin-custody-checks.v1",
        "status": "passed" if result.wasSuccessful() else "failed",
        "controller_sha256": actual_sha, "tests_run": result.testsRun,
        "failures": len(result.failures), "errors": len(result.errors),
        "platform": sys.platform, "python": sys.version,
        "actual_mac_processes_tested": args.mac_smoke,
        "mocked_darwin_identity_boundaries": not args.mac_smoke,
        "rust_compilation_performed": False, "rust_tests_executed": 0,
        "server_started": False, "production_mutation": False,
    })
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
