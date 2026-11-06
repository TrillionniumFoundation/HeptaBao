"""Local owned-fixture checks; never starts Bao, launchctl, or a network call."""
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import signal
import ssl
import tempfile
import time
import types
import unittest
from unittest import mock

import manager_runtime as m


class ManagerBoundaries(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='hb-manager-owned-fixture-')
        self.root = Path(self.tmp.name)
        self.patchers = [mock.patch.object(m, 'UID', os.geteuid()), mock.patch.object(m, 'GID', os.getegid()),
                         mock.patch.object(m.guard, 'UID', os.geteuid())]
        for patcher in self.patchers:
            patcher.start()
        self.clock = m.Clock(time.monotonic())
        self.io = m.PrivateIO(self.clock)
        self.parent = self.io.hold(self.root)

    def tearDown(self):
        self.clock.pending = None
        self.clock.cleaning = True
        self.io.close()
        self.assertEqual(self.io.handles, {})
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.tmp.cleanup()

    def test_actual_directory_publish_retains_original_fd_and_rejects_unproved_transition(self):
        old = self.io.mkdir(self.parent, 'data')
        replacement = self.root / 'init-stage'
        replacement.mkdir(mode=0o700)
        with self.assertRaises(m.Refused):
            self.io.initialized_directory_transition(old, actual_init_status=200, actual_response_validated=True)
        os.replace(replacement, self.root / 'data')
        with self.assertRaises(m.Refused):
            self.io.initialized_directory_transition(old, actual_init_status=503, actual_response_validated=True)
        current = self.io.initialized_directory_transition(old, actual_init_status=200, actual_response_validated=True)
        self.assertNotEqual(current['pin']['inode'], old['pin']['inode'])
        self.assertEqual(os.fstat(old['fd']).st_nlink, 0)
        self.assertIn(old['fd'], self.io.handles)
        self.assertEqual(len(self.io.transitions), 1)
        self.io.recheck()
        self.io.close()
        self.assertEqual(self.io.open_count, self.io.close_count)

    def test_binding_swap_is_single_named_transition_preserves_original_archive_and_closes_old_fds(self):
        initial = {'state': 'initial_empty', 'private': 'synthetic-only'}
        initial_bytes = m.encoded(initial)
        archive = self.io.put(self.parent, 'launch-binding.initial-empty.original.private.json', initial_bytes)
        active = self.io.put(self.parent, 'launch-binding.private.json', initial_bytes)
        old_fds = [r['fd'] for r in self.io.files if str(r['path']) == active['path']]
        updated = {'state': 'initialized', 'private': 'synthetic-only', 'new_inode': 17}
        result = self.io.publish_initialized_binding(self.parent, active, updated)
        self.assertEqual(Path(result['path']).read_bytes(), m.encoded(updated))
        self.assertEqual(Path(archive['path']).read_bytes(), initial_bytes)
        self.assertTrue(all(os.fstat(fd).st_nlink == 0 for fd in old_fds))
        self.assertNotEqual(result['identity']['inode'], active['identity']['inode'])
        with self.assertRaises(m.Refused):
            self.io.publish_initialized_binding(self.parent, result, updated)
        self.io.recheck()

    def test_partial_delivery_is_preserved_without_overwrite_and_original_fds_retire(self):
        real_write = os.write
        calls = 0
        def fail_second(fd, raw):
            nonlocal calls
            calls += 1
            if calls == 1:
                return real_write(fd, raw[:3])
            raise OSError('injected synthetic write failure')
        with mock.patch.object(os, 'write', side_effect=fail_second):
            with self.assertRaises(OSError):
                self.io.put(self.parent, 'root.token', b'synthetic-not-a-real-token')
        self.assertEqual((self.root / 'root.token').read_bytes(), b'syn')
        with self.assertRaises(m.Refused):
            self.io.put(self.parent, 'root.token', b'replacement')
        self.io.close()
        self.assertEqual(self.io.open_count, self.io.close_count)
        # A utility may have produced bytes before its wait fails. The exact
        # original output FDs must be synced before close, while a sync error
        # must not replace that original wait exception.
        clock = m.Clock(time.monotonic())
        io = m.PrivateIO(clock)
        output = io.hold(self.root)
        wire = object.__new__(m.ManagedWire)
        wire.io, wire.output, wire.service_root = io, output, self.root
        wire.ordinal, wire.commands, wire.command_cleanup_errors = 0, [], []
        written = []
        class Child:
            def __init__(self, argv, **kwargs):
                self.returncode, self.custody = 0, {'pid': 123, 'returncode': 0}
                for name in ('stdout', 'stderr'):
                    fd = kwargs[name]
                    os.write(fd, b'original-utility-bytes')
                    written.append(fd)
            def wait(self, timeout=None): raise ValueError('original-wait-failure')
        real_sync = os.fsync
        synced = []
        def fail_after_content(fd):
            if fd in written:
                synced.append(fd)
                self.assertGreater(os.fstat(fd).st_size, 0)
                raise OSError('synthetic fsync failure')
            return real_sync(fd)
        try:
            with mock.patch.object(m.subprocess, 'Popen', Child), mock.patch.object(os, 'fsync', side_effect=fail_after_content):
                with self.assertRaisesRegex(ValueError, 'original-wait-failure'):
                    wire.command('test_owned_output_sync', ['/bin/ps'])
            self.assertEqual(set(synced), set(written))
            self.assertEqual(wire.commands[0]['primary_error_type'], 'ValueError')
            self.assertEqual(wire.command_cleanup_errors, ['original_utility_output_sync_failed'] * 2)
        finally:
            io.close()
        self.assertEqual(io.open_count, io.close_count)

    def test_signal_after_fd_birth_counts_and_retires_registered_original(self):
        item = self.root / 'source'
        item.write_bytes(b'synthetic')
        real_open = os.open
        def signal_after_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            self.clock.interrupted(signal.SIGTERM, None)
            return fd
        with mock.patch.object(os, 'open', side_effect=signal_after_open):
            with self.assertRaises(m.Refused):
                self.io.open_fd(item, os.O_RDONLY)
        self.assertEqual(self.io.open_count, 2)
        self.assertEqual(len(self.io.handles), 2)
        self.clock.cleaning = True
        self.io.close()
        self.assertEqual(self.io.open_count, self.io.close_count)

    def test_signal_respects_custody_protected_birth_and_stays_sticky(self):
        owner = types.SimpleNamespace(protected=1, calls=[], _interrupt=lambda sig, frame: owner.calls.append(sig))
        clock = m.Clock(time.monotonic(), types.SimpleNamespace(_ACTIVE=owner))
        clock.interrupted(signal.SIGALRM, None)
        self.assertEqual(owner.calls, [signal.SIGALRM])
        self.assertEqual(clock.pending, signal.SIGALRM)
        with self.assertRaises(m.Refused):
            clock.check()

    def test_observed_absence_grammar_and_never_exited_are_not_forged_success(self):
        suffixes = {'gui/501': 'user gui: 501', 'user/501': 'uid: 501', 'system': 'system'}
        for domain, suffix in suffixes.items():
            error = ('Bad request.\nCould not find service "org.heptabao.kv2" in domain for ' + suffix + '\n').encode()
            self.assertTrue(m.exact_absence(113, b'', error, domain, 'org.heptabao.kv2'))
            self.assertFalse(m.exact_absence(0, b'', error, domain, 'org.heptabao.kv2'))
            self.assertFalse(m.exact_absence(113, b'', error.replace(b'kv2', b'other'), domain, 'org.heptabao.kv2'))
        raw = b'gui/501/org.heptabao.kv2 = {\n\tstate = running\n\tpid = 1234\n\tlast exit code = (never exited)\n}\n'
        result = m.parse_label(raw, 'gui/501', 'org.heptabao.kv2')
        self.assertIsNone(result['last exit code'])
        with self.assertRaises(m.Refused):
            m.parse_label(raw.replace(b'\tpid = 1234', b'\tpid = 1234\n\tpid = 5678'), 'gui/501', 'org.heptabao.kv2')

    def test_uncertain_init_is_one_attempt_and_no_combined_response_or_argv_digest_is_public(self):
        peer = b'public-test-certificate'
        state = {'requests': 0, 'closed': 0}
        class Connection:
            def __init__(self, *args, **kwargs):
                self.sock = types.SimpleNamespace(getpeercert=lambda **kw: peer, version=lambda: 'TLSv1.3')
            def connect(self): pass
            def request(self, *args, **kwargs): state['requests'] += 1
            def getresponse(self): raise ConnectionResetError('synthetic after-write loss')
            def close(self): state['closed'] += 1
        io = types.SimpleNamespace(clock=types.SimpleNamespace(request=lambda seconds: contextlib.nullcontext()))
        wire = object.__new__(m.ManagedWire)
        wire.io, wire.ca, wire.leaf_sha256 = io, self.root / 'ca.crt', hashlib.sha256(peer).hexdigest()
        wire.http_rows = []
        wire.http_connections_created = wire.http_connections_closed = 0
        with mock.patch.object(m.ssl, 'create_default_context', return_value=types.SimpleNamespace()), \
             mock.patch.object(m.http.client, 'HTTPSConnection', Connection):
            with self.assertRaises(ConnectionResetError):
                wire.http('POST', 'sys/init', {'secret_shares': 3, 'secret_threshold': 2,
                                              'recovery_nonce': base64.b64encode(b'x' * 32).decode()}, mutation=True)
        self.assertEqual(state, {'requests': 1, 'closed': 1})
        self.assertTrue(wire.http_rows[0]['outcome_unknown'])
        self.assertNotIn('body', wire.http_rows[0])
        private_receipt = {'original_count': 1, 'finished': True, 'passed_process_custody': True,
                           'failed': False, 'interrupted': False,
                           'children': [{'argv_sha256': 'secret-path-derived-digest', 'pid': 10}]}
        self.assertNotIn('secret-path', json.dumps(m.safe_custody(private_receipt)))


if __name__ == '__main__':
    unittest.main(verbosity=2)
