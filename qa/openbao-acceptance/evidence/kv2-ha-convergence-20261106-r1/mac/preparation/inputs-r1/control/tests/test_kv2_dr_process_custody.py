"""Disposable process-method tests; never start HeptaBao, OpenBao or a compiler."""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import kv2_dr_process_custody as custody


class ProcessCustodyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="dr-process-method-")
        self.root = Path(self.tmp.name)
        self.original_popen = subprocess.Popen

    def tearDown(self):
        self.assertIs(subprocess.Popen, self.original_popen)
        self.tmp.cleanup()

    def target(self, source, **kwargs):
        return subprocess.Popen([sys.executable, "-I", "-S", "-c", source], **kwargs)

    def test_real_target_executes_only_in_observed_original_session_and_waits_once(self):
        code = "import os,json;print(json.dumps([os.getpid(),os.getppid(),os.getpgrp(),os.getsid(0)]))"
        with custody.activated() as owner:
            child = self.target(code, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, errors = child.communicate(timeout=5)
            self.assertEqual(errors, b"")
            self.assertEqual(json.loads(output), [child.pid, os.getpid(), child.pid, child.pid])
            self.assertEqual(child.poll(), 0)
            self.assertEqual(child.wait(timeout=1), 0)
            owner.assert_retired()
        row = owner.rows[0]
        self.assertEqual(row["original_wait_count"], 1)
        self.assertTrue(row["exec_admitted"])
        self.assertTrue(row["no_live_members_before_reap"])
        self.assertTrue(owner.receipt()["passed_process_custody"])
        self.assertNotIn(code, json.dumps(owner.receipt()))

    def test_run_check_output_and_owned_process_compatibility_share_originals(self):
        import owned_process
        with custody.activated() as owner:
            self.assertEqual(subprocess.check_output([sys.executable, "-c", "print(7)"], timeout=5), b"7\n")
            server = owned_process.popen([sys.executable, "-c", "import time;time.sleep(30)"],
                                         label="dr-controller-test", action="KILL", stop_timeout=5)
            owned_process.stop(server, action="KILL", timeout=5, expected_codes=(-9,))
            owner.assert_retired()
        self.assertEqual(len(owner.rows), 2)
        self.assertTrue(owner.receipt()["passed_process_custody"])
        # Importing owned_process within/alongside custody cannot poison its
        # standalone isinstance guard after the temporary patch is restored.
        child = owned_process.popen([sys.executable, "-c", "pass"], label="after-custody")
        owned_process.wait(child, timeout=5)

    def test_gate_identity_failure_never_executes_target_or_signals_a_guessed_group(self):
        marker = self.root / "must-not-exist"
        real_snapshot = custody._snapshot

        def wrong_group(pid):
            row = real_snapshot(pid)
            row["pgid"] += 1
            return row

        with patch.object(custody, "_snapshot", side_effect=wrong_group), patch.object(custody.os, "killpg") as group:
            with custody.activated() as owner:
                with self.assertRaisesRegex(custody.CustodyFailure, "custody_gate_birth_mismatch"):
                    self.target("from pathlib import Path;Path(" + repr(str(marker)) + ").write_text('bad')")
            group.assert_not_called()
        self.assertFalse(marker.exists())
        self.assertTrue(owner.failed)
        self.assertTrue(owner.rows[0]["original_wait_completed"])
        self.assertFalse(owner.rows[0]["exec_admitted"])

    def test_wait_timeout_keeps_original_anchor_then_declared_stop_retires_it(self):
        with custody.activated() as owner:
            child = self.target("import time;time.sleep(30)")
            with self.assertRaises(subprocess.TimeoutExpired):
                child.wait(timeout=0.05)
            self.assertIsNone(child.returncode)
            self.assertIsNone(os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT))
            child.kill()
            self.assertEqual(child.wait(timeout=3), -signal.SIGKILL)
            owner.assert_retired()
        self.assertTrue(owner.receipt()["passed_process_custody"])

    def test_leader_exit_with_live_descendant_is_failure_and_only_owned_group_is_killed(self):
        marker = self.root / "descendant.pid"
        source = ("import os,time\nchild=os.fork()\n"
                  "if child==0:\n time.sleep(30)\n os._exit(0)\n"
                  "open(" + repr(str(marker)) + ",'w').write(str(child))\nos._exit(0)\n")
        foreign = self.original_popen([sys.executable, "-c", "import time;time.sleep(30)"], start_new_session=True)
        try:
            with custody.activated() as owner:
                child = self.target(source, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                with self.assertRaisesRegex(custody.CustodyFailure, "custody_live_descendant_after_leader_exit"):
                    child.wait(timeout=5)
                self.assertEqual(child.returncode, 0)
                self.assertIsNone(foreign.poll())
                with self.assertRaisesRegex(custody.CustodyFailure, "custody_retirement_failed"):
                    owner.assert_retired()
            descendant = int(marker.read_text())
            row = owner.rows[0]
            self.assertTrue(any(member["pid"] == descendant and member["state"] != "Z"
                                for member in row["members_at_leader_exit"]))
            self.assertFalse(custody._live(custody._members(child.pid), excluding=child.pid))
            self.assertEqual(row["original_wait_count"], 1)
            self.assertTrue(row["no_live_members_before_reap"])
            self.assertFalse(owner.receipt()["passed_process_custody"])
            self.assertEqual({item["pgid"] for item in row["signals"]}, {child.pid})
        finally:
            foreign.kill()
            foreign.wait(timeout=5)

    def test_cancel_enters_final_cleanup_and_restores_original_signal_handlers(self):
        handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
        started = time.monotonic()
        with self.assertRaises(custody.CustodyCancelled):
            with custody.activated() as owner:
                child = self.target("import time;time.sleep(30)")
                os.kill(os.getpid(), signal.SIGTERM)
        self.assertLess(time.monotonic() - started, 8)
        self.assertEqual(child.returncode, -signal.SIGKILL)
        self.assertTrue(owner.rows[0]["original_wait_completed"])
        self.assertTrue(owner.interrupted)
        self.assertFalse(owner.receipt()["passed_process_custody"])
        self.assertEqual(handlers, {sig: signal.getsignal(sig) for sig in handlers})

    def test_retirement_gate_does_not_stop_a_live_target(self):
        with custody.activated() as owner:
            child = self.target("import time;time.sleep(30)")
            with self.assertRaisesRegex(custody.CustodyFailure, "custody_retirement_failed"):
                owner.assert_retired()
            self.assertIsNone(child.poll())
            child.kill()
            child.wait(timeout=3)
        self.assertTrue(owner.failed)

    def test_foreign_reap_loses_authority_and_never_signals_recycled_group(self):
        with custody.activated() as owner:
            child = self.target("pass")
            _, _status = os.waitpid(child.pid, 0)
            with patch.object(custody.os, "killpg") as group:
                with self.assertRaisesRegex(custody.CustodyFailure, "custody_original_anchor_lost"):
                    child.kill()
                owner.finish()
                group.assert_not_called()
        self.assertTrue(owner.failed)
        self.assertFalse(owner.rows[0]["original_wait_completed"])

    def test_missing_wnowait_and_external_sigchld_reaper_refuse_before_spawn(self):
        with patch.object(custody.os, "WNOWAIT", 0):
            with self.assertRaisesRegex(custody.CustodyFailure, "custody_wnowait_required"):
                with custody.activated():
                    self.fail("admission must fail")
        previous = signal.getsignal(signal.SIGCHLD)
        try:
            signal.signal(signal.SIGCHLD, signal.SIG_IGN)
            with self.assertRaisesRegex(custody.CustodyFailure, "custody_sigchld_must_not_reap"):
                with custody.activated():
                    self.fail("admission must fail")
        finally:
            signal.signal(signal.SIGCHLD, previous)

    def test_darwin_numeric_parser_rejects_session_pointer_and_uses_kernel_sid(self):
        rows = custody._parse_darwin_ps(b" 501 100 501 1000 S+\n 502 501 501 1000 R\n")
        self.assertNotIn("sid", rows[0])
        with patch.object(custody, "_table", return_value=rows), patch.object(custody.os, "getsid", return_value=501):
            observed = custody._members(501)
        self.assertEqual([row["sid"] for row in observed], [501, 501])
        for malformed in (b"501 100 deadbeef 1000 S\n", b"501 100 501 1000 S deadbeef\n", b""):
            with self.assertRaises(custody.CustodyFailure):
                custody._parse_darwin_ps(malformed)

    def test_nested_owner_and_finished_owner_do_not_create_new_originals(self):
        with custody.activated() as owner:
            with self.assertRaisesRegex(custody.CustodyFailure, "custody_nested_owner"):
                with custody.activated():
                    self.fail("nested owner")
            owner.finish()
            with self.assertRaisesRegex(custody.CustodyFailure, "custody_owner_not_active"):
                self.target("pass")
        self.assertEqual(owner.rows, [])

    def test_prior_retirement_receipt_cannot_change_when_later_originals_run(self):
        with custody.activated() as owner:
            first = self.target("pass")
            first.wait(timeout=5)
            frozen = owner.assert_retired()
            serialized = json.dumps(frozen, sort_keys=True)
            second = self.target("pass")
            second.wait(timeout=5)
            owner.rows[0]["signals"].append({"synthetic_later_observation": True})
            self.assertEqual(json.dumps(frozen, sort_keys=True), serialized)
            self.assertEqual(frozen["original_count"], len(frozen["children"]))
            self.assertEqual(frozen["original_count"], 1)
            self.assertEqual(owner.receipt()["original_count"], 2)


if __name__ == "__main__":
    unittest.main()
