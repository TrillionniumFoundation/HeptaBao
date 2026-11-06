"""Wrapper-only local guards: short timer/child and explicitly stubbed DR entry.

No HeptaBao, OpenBao, real credential or provider is started by these tests.
"""
from contextlib import ExitStack, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import dr25_mac_fixed_wrapper as wrapper


class WrapperGuards(unittest.TestCase):
    def setUp(self):
        self.old_handler = signal.getsignal(signal.SIGALRM)
        self.old_timer = signal.getitimer(signal.ITIMER_REAL)
        self.assertEqual(self.old_timer, (0.0, 0.0))
        self.assertEqual(self.old_handler, signal.SIG_DFL)

    def tearDown(self):
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(signal.getsignal(signal.SIGALRM), self.old_handler)

    def test_same_entry_deadline_includes_preparation_and_restores_timer(self):
        start = time.monotonic()
        with wrapper.Deadline(start, prepare=1, work=2) as deadline:
            time.sleep(.005)
            deadline.enter_work()
            self.assertEqual(deadline.work_end, start + 2)
            self.assertLess(signal.getitimer(signal.ITIMER_REAL)[0], 1.999)
            self.assertTrue(deadline.eligible())
        self.assertFalse(deadline.fired)
        self.assertTrue(deadline.restored)

    def test_actual_alarm_cancels_in_process_work_and_is_not_a_pass(self):
        deadline = wrapper.Deadline(time.monotonic(), prepare=1, work=.02)
        with patch.object(wrapper, 'CUSTODY', None):
            with self.assertRaises(wrapper.DeadlineExpired):
                with deadline:
                    deadline.enter_work()
                    time.sleep(.1)
        self.assertTrue(deadline.fired)
        self.assertEqual(deadline.fired_phase, 'work')
        self.assertFalse(deadline.eligible())
        self.assertTrue(deadline.restored)

    def test_foreign_timer_and_handler_are_refused_without_being_replaced(self):
        handler = lambda *_: None
        signal.signal(signal.SIGALRM, handler)
        try:
            with self.assertRaisesRegex(wrapper.Failure, 'foreign_alarm_handler'):
                with wrapper.Deadline(time.monotonic()):
                    self.fail('foreign handler admitted')
            self.assertIs(signal.getsignal(signal.SIGALRM), handler)
            signal.setitimer(signal.ITIMER_REAL, 5)
            with self.assertRaisesRegex(wrapper.Failure, 'foreign_real_timer'):
                with wrapper.Deadline(time.monotonic()):
                    self.fail('foreign timer admitted')
            self.assertGreater(signal.getitimer(signal.ITIMER_REAL)[0], 4)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, self.old_handler)

    def test_native_inherited_output_is_private_and_descriptors_are_restored(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            before = [os.fstat(fd) for fd in (1, 2)]
            with wrapper.private_stdio(root):
                subprocess.run([sys.executable, '-I', '-S', '-B', '-c',
                    'import os; os.write(1,b"synthetic-root-value"); os.write(2,b"synthetic-unseal-value")'],
                    check=True, timeout=5, stdin=subprocess.DEVNULL)
            for fd, previous in zip((1, 2), before):
                observed = os.fstat(fd)
                self.assertEqual((observed.st_dev, observed.st_ino), (previous.st_dev, previous.st_ino))
            for name, value in (('controller.stdout.private', b'synthetic-root-value'),
                                ('controller.stderr.private', b'synthetic-unseal-value')):
                path = root / name
                self.assertEqual(path.read_bytes(), value)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def stub_run(self, root, callback, *, deadline_class=wrapper.Deadline, owner=None):
        out, work, backup, keys = (root / name for name in ('out', 'work', 'backup', 'keys'))
        binding = {'controller_guard_fixture': True}
        prepared = wrapper.sha(wrapper.encode(binding))
        def directory(path):
            # Deliberate filesystem-device double only; no real DR eligibility.
            return {'device': 2 if path == backup else 1, 'inode': 100, 'uid': os.geteuid(), 'mode': 0o700}
        fake_dr = SimpleNamespace(private_parent=directory, directory_identity=directory,
            disjoint=lambda _: True, CHECKS=('one-synthetic-check',), main=callback,
            full=SimpleNamespace(private_read=lambda *_: b'{}', decode=json.loads))
        env_before = dict(os.environ)
        try:
            with ExitStack() as stack:
                for name, value in (('ROOT', root), ('OUT', out), ('WORK', work), ('BACKUP', backup), ('KEYS', keys),
                                    ('Deadline', deadline_class), ('CUSTODY', SimpleNamespace(_ACTIVE=owner)),
                                    ('ENTRY_MONOTONIC', time.monotonic())):
                    stack.enter_context(patch.object(wrapper, name, value))
                stack.enter_context(patch.object(wrapper, 'load_modules', return_value=fake_dr))
                stack.enter_context(patch.object(wrapper, 'preparation', return_value=(binding, {})))
                # Force the independent deadline gate to carry its own rejection;
                # a hypothetical false controller pass cannot override it.
                stack.enter_context(patch.object(wrapper, 'qualify_summary', return_value={'stub_controller_claimed_pass': True}))
                with redirect_stdout(io.StringIO()) as stdout:
                    code = wrapper.main(['--run', prepared, '--build-receipt-sha256', 'a' * 64])
                result = json.loads((out / 'result.public.json').read_bytes())
                return code, result, stdout.getvalue(), out
        finally:
            os.environ.clear(); os.environ.update(env_before)

    def test_protected_cleanup_can_return_zero_but_deadline_cannot_pass(self):
        class Owner:
            protected, finishing, failed = 1, True, False
            def _interrupt(self, signum, frame):
                self.failed = True
                self.signal = signum
                # The actual owner defers cancellation while finishing a wait.
        owner = Owner()
        class ShortDeadline(wrapper.Deadline):
            def __init__(self, started):
                super().__init__(started, prepare=1, work=.03)
        def controller(_):
            time.sleep(.06)
            return 0
        with tempfile.TemporaryDirectory() as temporary:
            code, result, stdout, _ = self.stub_run(Path(temporary), controller, deadline_class=ShortDeadline, owner=owner)
        self.assertTrue(owner.failed)
        self.assertEqual(owner.signal, signal.SIGALRM)
        self.assertEqual(code, 1)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['failure'], 'job_absolute_deadline_failed')
        self.assertTrue(result['deadline']['fired'])
        self.assertEqual(result['controller_exit_code'], 0)
        self.assertNotIn('"status": "passed"', stdout)

    def test_controller_error_payload_and_guessable_fingerprint_stay_private(self):
        secret = 'synthetic-low-entropy-secret'
        def controller(_):
            os.write(2, secret.encode())
            raise RuntimeError(secret)
        with tempfile.TemporaryDirectory() as temporary:
            code, result, stdout, out = self.stub_run(Path(temporary), controller)
            self.assertEqual((out / 'controller.stderr.private').read_text(), secret)
            raw = (out / 'result.public.json').read_text() + stdout
        self.assertEqual(code, 1)
        self.assertEqual(result['failure'], 'RuntimeError')
        self.assertNotIn(secret, raw)
        self.assertNotIn(hashlib.sha256(secret.encode()).hexdigest(), raw)
        self.assertTrue(result['signal_and_timer_restored'])


if __name__ == '__main__':
    unittest.main()
