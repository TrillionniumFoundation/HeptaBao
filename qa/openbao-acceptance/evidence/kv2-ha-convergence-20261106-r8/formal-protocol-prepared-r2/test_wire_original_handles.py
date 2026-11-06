"""Narrow FD guards with ordinary short Python children; never network/TLS/data.

The retained 669e process owner is real. Only the private output birth/fstat/
close boundary is fault injected; a passing test is not protocol acceptance.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import signal
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest import mock

import formal_kv2_protocol as protocol
from lifecycle_contract import EndpointHandle


QA = Path(os.environ['HB_PURE_QA_REFERENCE_DIR'])
spec = importlib.util.spec_from_file_location('fixed_wire_guard_custody', QA / 'kv2_dr_process_custody.py')
custody = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = custody
spec.loader.exec_module(custody)


class WireOriginalHandleGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helpers = protocol.load_pure_helpers(QA)

    def setUp(self):
        self.temp = TemporaryDirectory(prefix='hb-wire-original-fd-guard-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ca, self.token = self.root / 'ca.synthetic', self.root / 'token.synthetic'
        self.helpers.private_write(self.ca, b'only a synthetic fixture')
        self.helpers.private_write(self.token, b'only a synthetic fixture token')
        self.leaf = self.root / 'short_python_leaf.py'
        # This is intentionally a no-network fixture, not the TLS wire leaf.
        self.helpers.private_write(self.leaf, b'''import base64,json,sys
p=json.loads(sys.stdin.buffer.read())
print(json.dumps({"status":200,"body":base64.b64encode(b"{}").decode(),
 "origin":p["origin"],"peer_leaf_sha256":p["leaf_sha256"],
 "ca_sha256":p["ca_pin"]["sha256"],"headers":{},"downloaded_file":None}),end="")
''')
        self.endpoint = EndpointHandle('https://127.0.0.1:8401', self.ca, self.token,
            'a' * 64, self.root / 'unused-data', 'synthetic-only', 'gui/501')
        self.serial = 0

    def wire(self, owner):
        self.serial += 1
        path = self.root / ('request-' + str(self.serial))
        path.mkdir(mode=0o700)
        raw = self.leaf.read_bytes()
        return protocol.OwnedWire(wire_file=protocol.PrivatePin(self.leaf, len(raw),
            hashlib.sha256(raw).hexdigest()), custody_module=custody, custody_owner=owner,
            helpers=self.helpers, evidence_dir=path, total_end=time.monotonic() + 10)

    def call(self, wire):
        return wire.exchange(self.endpoint, 'GET', 'sys/health', None,
            download=None, upload=None, maximum=4 * protocol.MIB,
            absolute_deadline=time.monotonic() + 5)

    def test_real_short_child_retires_two_original_log_handles_and_waits_once(self):
        with custody.activated() as owner:
            wire = self.wire(owner)
            reply = self.call(wire)
            self.assertEqual(reply.status, 200)
            self.assertEqual(reply.child_receipt['original_wait_count'], 1)
            self.assertTrue(reply.child_receipt['no_live_members_before_reap'])
            receipt = wire.handle_receipts[-1]
            self.assertEqual(receipt['birth_count'], 2)
            self.assertEqual(receipt['close_attempt_count'], 2)
            self.assertEqual(receipt['close_success_count'], 2)
            self.assertTrue(receipt['all_born_original_log_handles_retired'])
            self.assertEqual(owner.protected, 0)
            self.assertTrue(owner.assert_retired()['passed_process_custody'])

    def test_signal_at_each_log_birth_and_first_fstat_failure_retire_without_dispatch(self):
        for fault in ('stdout_signal', 'stderr_signal', 'first_fstat'):
            with self.subTest(fault=fault), custody.activated() as owner:
                wire = self.wire(owner)
                original_open, original_stat = os.open, os.fstat
                born = []
                fired = False
                def open_then_interrupt(path, *args, **kwargs):
                    fd = original_open(path, *args, **kwargs)
                    if Path(path).parent == wire.evidence_dir and str(path).endswith(('.stdout.private', '.stderr.private')):
                        born.append(fd)
                        if (fault == 'stdout_signal' and len(born) == 1
                                or fault == 'stderr_signal' and len(born) == 2):
                            os.kill(os.getpid(), signal.SIGTERM)
                    return fd
                def first_stat(fd):
                    nonlocal fired
                    if fault == 'first_fstat' and born and fd == born[0] and not fired:
                        fired = True
                        raise OSError('synthetic first-fstat failure')
                    return original_stat(fd)
                try:
                    with mock.patch.object(protocol.os, 'open', side_effect=open_then_interrupt), \
                         mock.patch.object(protocol.os, 'fstat', side_effect=first_stat):
                        with self.assertRaises((protocol.Refused, OSError)):
                            self.call(wire)
                    self.assertEqual(owner.rows, [])
                    self.assertEqual(owner.protected, 0)
                    receipt = wire.handle_receipts[-1]
                    self.assertEqual(receipt['birth_count'], len(born))
                    self.assertEqual(receipt['close_attempt_count'], len(born))
                    self.assertEqual(receipt['close_success_count'], len(born))
                    for fd in born:
                        with self.assertRaises(OSError):
                            original_stat(fd)
                finally:
                    # Only a failing old implementation could leave these open.
                    for fd in born:
                        try:
                            original_stat(fd)
                        except OSError:
                            continue
                        os.close(fd)

    def test_primary_survives_cleanup_signal_and_ambiguous_close_is_not_retried(self):
        with custody.activated() as owner:
            wire = self.wire(owner)
            original_communicate = custody._TrackedPopen.communicate
            original_close, original_stat, original_open = os.close, os.fstat, os.open
            replacement = None
            target_inode = None
            def communicate_then_primary(child, *args, **kwargs):
                original_communicate(child, *args, **kwargs)
                raise ValueError('synthetic original primary')
            def close_then_ambiguous(fd):
                nonlocal replacement, target_inode
                st = original_stat(fd)
                log = wire.evidence_dir / 'wire-000001.stdout.private'
                if log.exists() and target_inode is None and st.st_ino == log.stat().st_ino:
                    target_inode = st.st_ino
                    original_close(fd)
                    replacement = original_open(self.ca, os.O_RDONLY)
                    self.assertEqual(replacement, fd)
                    os.kill(os.getpid(), signal.SIGTERM)
                    raise OSError('synthetic ambiguous original close')
                original_close(fd)
            try:
                with mock.patch.object(custody._TrackedPopen, 'communicate', communicate_then_primary), \
                     mock.patch.object(protocol.os, 'close', side_effect=close_then_ambiguous):
                    with self.assertRaisesRegex(ValueError, 'synthetic original primary'):
                        self.call(wire)
                self.assertIsNotNone(replacement)
                self.assertEqual(original_stat(replacement).st_size, self.ca.stat().st_size)
                receipt = wire.handle_receipts[-1]
                self.assertEqual(receipt['close_attempt_count'], 2)
                self.assertEqual(receipt['close_success_count'], 1)
                self.assertFalse(receipt['all_born_original_log_handles_retired'])
                self.assertEqual(owner.protected, 0)
                self.assertTrue(owner.failed)
                self.assertTrue(owner.interrupted)
                self.assertEqual(len(owner.rows), 1)
                self.assertEqual(owner.rows[0]['original_wait_count'], 1)
                self.assertTrue(owner.rows[0]['no_live_members_before_reap'])
            finally:
                if replacement is not None:
                    original_close(replacement)


if __name__ == '__main__':
    unittest.main(verbosity=2)
