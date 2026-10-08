"""Real benign Popen controls for the same QA lifecycle methods; no service."""
from __future__ import annotations

import contextlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

import owned_process as owned


class OriginalProcessControls(unittest.TestCase):
    def setUp(self):
        parent = Path(os.environ["TMPDIR"])
        self.work = Path(tempfile.mkdtemp(prefix="owned-method-controls-", dir=parent))
        self.work.chmod(0o700)
        self.owners = []

    def tearDown(self):
        for owner in self.owners:
            owner.finish()
            self.assertTrue(all(child._done for child in owner.children))
            for child in owner.children:
                self.assertEqual(child.row["completed_original_wait_count"], 1)
                self.assertTrue(child.row["original_SID_retired_observed"])
        destination_root = Path(os.environ.get("HB_QA_CONTROL_RECEIPTS", str(self.work / "saved-control-receipts")))
        destination_root.mkdir(mode=0o700, exist_ok=True)
        for index, owner in enumerate(self.owners):
            original = owner.root / "original-process-receipt.json"
            destination = destination_root / (self.id() + "-" + str(index) + ".json")
            with destination.open("x") as stream:
                json.dump({"test": self.id(), "owner_index": index,
                           "original_process_receipt_file": owned.file_pin(original),
                           "receipt": json.loads(original.read_text())}, stream,
                          indent=2, sort_keys=True)
                stream.write("\n")
        # Preserve actual original identities, waits and private method receipts.

    def owner(self, cls=owned.Owner):
        result = cls(self.work, deadline_ns=time.monotonic_ns() + 60_000_000_000)
        self.owners.append(result)
        return result

    def sleeper(self, label):
        return owned.popen([sys.executable, "-c", "import time;time.sleep(30)"],
                           label=label, stop_timeout=.1)

    def test_original_utility_output_and_one_wait(self):
        owner = self.owner()
        with owned.activated(owner):
            result = owned.run([sys.executable, "-c", "print('synthetic')"],
                               label="utility.output", capture_output=True, check=True, timeout=5)
        self.assertEqual(result.stdout, b"synthetic\n")
        self.assertEqual(result.returncode, 0)
        self.assertTrue(owner.receipt["passed_process_method"])
        self.assertTrue(owner.children[0].row["exec_input_guard_acknowledged"])

    def test_input_bytes_and_text_output_preserved(self):
        owner = self.owner()
        with owned.activated(owner):
            result = owned.run([sys.executable, "-c", "import sys;sys.stdout.write(sys.stdin.read())"],
                               label="utility.input", input="synthetic\n", capture_output=True,
                               text=True, check=True, timeout=5)
        self.assertEqual(result.stdout, "synthetic\n")
        self.assertTrue(owner.receipt["passed_process_method"])

    def test_nonzero_cli_result_is_not_retried(self):
        owner = self.owner()
        counter = self.work / "invocations"
        code = "from pathlib import Path;p=Path(" + repr(str(counter)) + ");p.write_text('once');raise SystemExit(2)"
        with owned.activated(owner):
            result = owned.run([sys.executable, "-c", code], label="utility.expected2", timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(counter.read_text(), "once")
        self.assertEqual(len(owner.children), 1)
        self.assertTrue(owner.receipt["passed_process_method"])

    def test_constructor_metadata_failure_EOF_and_original_wait(self):
        class FaultOwner(owned.Owner):
            def capture(self, child):
                raise OSError("synthetic_metadata_fault")
        owner = self.owner(FaultOwner)
        marker = self.work / "must-not-execute"
        code = "from pathlib import Path;Path(" + repr(str(marker)) + ").write_text('forbidden')"
        with self.assertRaises(OSError):
            with owned.activated(owner):
                owned.popen([sys.executable, "-c", code], label="fault.metadata")
        self.assertFalse(marker.exists())
        self.assertFalse(owner.receipt["passed_process_method"])
        self.assertEqual(len(owner.children), 1)
        self.assertFalse(owner.children[0].row["admission_released"])

    def test_first_poll_failure_original_wait_and_false(self):
        owner = self.owner()
        with owned.activated(owner):
            child = self.sleeper("fault.firstpoll")
            original = child.poll
            calls = 0
            def fault():
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise OSError("synthetic_poll_fault")
                return original()
            child.poll = fault
            owned.stop(child, timeout=.1)
        self.assertFalse(owner.receipt["passed_process_method"])
        self.assertTrue(child.row["same_original_Popen_wait"])

    def test_declared_TERM_error_still_original_wait(self):
        owner = self.owner()
        with owned.activated(owner):
            child = self.sleeper("fault.TERM")
            original = owner.send
            first = True
            def fault(target, signum, *, fallback=False):
                nonlocal first
                if first:
                    first = False
                    raise OSError("synthetic_TERM_fault")
                return original(target, signum, fallback=fallback)
            owner.send = fault
            owned.stop(child, timeout=.1)
        self.assertFalse(owner.receipt["passed_process_method"])
        self.assertTrue(child.row["fallback"])

    def test_wait_fault_reaches_same_original_Popen(self):
        owner = self.owner()
        with owned.activated(owner):
            child = self.sleeper("fault.wait")
            original = child._raw_wait
            first = True
            def fault(timeout=None):
                nonlocal first
                if first:
                    first = False
                    raise OSError("synthetic_wait_fault")
                return original(timeout=timeout)
            child._raw_wait = fault
            owned.stop(child, timeout=.1)
        self.assertFalse(owner.receipt["passed_process_method"])
        self.assertTrue(child.row["same_original_Popen_wait"])

    def test_multiple_children_closed_after_first_error(self):
        owner = self.owner()
        with owned.activated(owner):
            first = self.sleeper("multiple.first")
            second = self.sleeper("multiple.second")
            original = owner.send
            injected = False
            def fault(child, signum, *, fallback=False):
                nonlocal injected
                if child is first and not injected:
                    injected = True
                    raise OSError("synthetic_first_close_fault")
                return original(child, signum, fallback=fallback)
            owner.send = fault
            owned.close_all([
                lambda: owned.stop(first, timeout=.1),
                lambda: owned.stop(second, timeout=.1),
            ])
        self.assertFalse(owner.receipt["passed_process_method"])
        self.assertTrue(first._done and second._done)
        self.assertEqual(len(owner.children), 2)

    def test_readiness_failure_keeps_first_error_and_closes(self):
        owner = self.owner()
        with self.assertRaisesRegex(owned.OwnedFailure, "^synthetic_readiness$"):
            with owned.activated(owner):
                child = self.sleeper("readiness.original")
                owned.abort(owned.OwnedFailure("synthetic_readiness"),
                            [lambda: owned.stop(child, timeout=.1)])
        self.assertFalse(owner.receipt["passed_process_method"])
        self.assertTrue(child._done)

    def test_already_exited_child_still_has_original_wait(self):
        owner = self.owner()
        with owned.activated(owner):
            child = owned.popen([sys.executable, "-c", "raise SystemExit(0)"],
                                label="early.server", stop_timeout=.1)
            deadline = time.monotonic() + 5
            while child.poll() is None:
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.01)
            self.assertFalse(child._done)
            owned.stop(child, timeout=.1)
        self.assertTrue(child.row["same_original_Popen_wait"])
        self.assertFalse(owner.receipt["passed_process_method"])
        self.assertTrue(child.row["premature_exit_before_stop"])

    def test_repeated_stop_uses_saved_terminal_not_replacement_wait(self):
        owner = self.owner()
        with owned.activated(owner):
            child = self.sleeper("terminal.original")
            result = owned.stop(child, timeout=1, expected_codes=(-signal.SIGTERM,))
            def forbidden(timeout=None):
                raise AssertionError("replacement_wait")
            child._raw_wait = forbidden
            self.assertEqual(owned.stop(child, timeout=1), result)
        self.assertTrue(owner.receipt["passed_process_method"])
        self.assertEqual(child.row["completed_original_wait_count"], 1)

    def test_real_signal_marks_false_and_closes_every_original(self):
        owner = self.owner()
        with self.assertRaises(owned.OwnedCancelled):
            with owned.activated(owner):
                self.sleeper("signal.first")
                self.sleeper("signal.second")
                os.kill(os.getpid(), signal.SIGTERM)
        self.assertTrue(owner.interrupted)
        self.assertFalse(owner.receipt["passed_process_method"])
        self.assertEqual(len(owner.children), 2)
        self.assertTrue(all(child._done for child in owner.children))

    def test_original_utility_timeout_never_replays_effect(self):
        owner = self.owner()
        counter = self.work / "counter"
        code = "from pathlib import Path;import time;Path(" + repr(str(counter)) + ").write_text('once');time.sleep(30)"
        with self.assertRaises(subprocess.TimeoutExpired):
            with owned.activated(owner):
                owned.run([sys.executable, "-c", code], label="utility.timeout", timeout=.25)
        self.assertEqual(counter.read_text(), "once")
        self.assertEqual(len(owner.children), 1)
        self.assertFalse(owner.receipt["passed_process_method"])

    def test_changed_exec_input_guard_never_executes(self):
        target = self.work / "true-copy"
        shutil.copyfile(shutil.which("true"), target)
        target.chmod(0o700)
        class FaultOwner(owned.Owner):
            def capture(self, child):
                result = super().capture(child)
                target.write_bytes(target.read_bytes() + b"changed")
                return result
        owner = self.owner(FaultOwner)
        with self.assertRaisesRegex(owned.OwnedFailure, "^owned_exec_guard_rejected$"):
            with owned.activated(owner):
                owned.popen([str(target)], label="fault.execinput", kind="utility")
        self.assertFalse(owner.receipt["passed_process_method"])
        self.assertFalse(owner.children[0].row.get("exec_input_guard_acknowledged", False))


    def test_shared_standalone_cli_keeps_unqualified_stdlib_result(self):
        self.assertIsNone(owned._CURRENT)
        result = owned.run([sys.executable, "-c", "print('synthetic')"],
                           label="standalone.utility", capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"synthetic\\n")
        self.assertIsNone(owned._CURRENT)

    def test_shared_standalone_server_first_poll_error_still_original_wait(self):
        self.assertIsNone(owned._CURRENT)
        child = owned.popen([sys.executable, "-c", "import time;time.sleep(30)"],
                            label="standalone.server", start_new_session=True)
        self.assertNotIsInstance(child, owned._OwnedPopen)
        original_poll, original_wait = child.poll, child.wait
        waits = []
        first = True
        def bad_poll():
            nonlocal first
            if first:
                first = False
                raise OSError("synthetic_standalone_poll")
            return original_poll()
        def tracked_wait(timeout=None):
            result = original_wait(timeout=timeout)
            waits.append(result)
            return result
        child.poll, child.wait = bad_poll, tracked_wait
        try:
            with self.assertRaisesRegex(OSError, "^synthetic_standalone_poll$"):
                owned.stop(child, action="TERM", timeout=.1)
        finally:
            if child.returncode is None:
                child.kill()
                child.wait()
        self.assertEqual(waits, [-signal.SIGKILL])
        survivors, gaps = owned._sid_survivors(child.pid)
        self.assertEqual(survivors, [])
        self.assertEqual(gaps, [])
        self.assertIsNone(owned._CURRENT)


if __name__ == "__main__":
    unittest.main()
