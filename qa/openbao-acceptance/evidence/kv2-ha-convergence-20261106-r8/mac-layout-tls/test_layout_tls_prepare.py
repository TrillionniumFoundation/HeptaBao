"""Bounded local guards; no product, service, live data or remote access."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import signal
import tempfile
import time
import unittest
from unittest import mock

import layout_tls_prepare as m


class PreparationGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='heptabao-layout-tls-guard-')
        self.base = Path(self.temp.name)
        self.base.chmod(0o700)
        self.clock = m.Clock(time.monotonic())
        self.fs = m.Filesystem(self.clock, os.geteuid(), os.getegid())
        self.parent = self.fs.directory(self.base, 'fixture')

    def tearDown(self):
        self.fs.close()
        self.temp.cleanup()

    def fixture(self, name='source', data=b'original', mode=0o600):
        path = self.base / name
        with path.open('xb') as h:
            h.write(data)
        path.chmod(mode)
        return path

    def test_create_only_private_directory_and_fsynced_readback(self):
        directory = self.fs.mkdir(self.parent, 'private', 'private')
        pin = self.fs.put(directory, 'a', b'fixture-value', 'fixture-file')
        self.assertEqual(pin['identity']['mode'], 0o600)
        self.assertEqual(pin['identity']['nlink'], 1)
        self.assertEqual(pin['identity']['bytes'], 13)
        self.assertEqual((directory.path / 'a').read_bytes(), b'fixture-value')
        # Legitimate child creation changes parent times/count, not its owner
        # identity. The original parent FD remains the same directory.
        self.fs.verify_directory(self.parent)
        self.fs.verify_all()
        insecure = self.base / 'not-private'
        insecure.mkdir(mode=0o700)
        insecure.chmod(0o775)
        with self.assertRaisesRegex(m.Rejected, 'private_directory_identity'):
            self.fs.directory(insecure, 'insecure')
        self.assertEqual(insecure.stat().st_mode & 0o777, 0o775)

    def test_existing_symlink_and_hardlink_targets_never_overwritten(self):
        original = self.fixture()
        (self.base / 'symlink').symlink_to(original)
        os.link(original, self.base / 'hardlink')
        for name in ('source', 'symlink', 'hardlink'):
            with self.assertRaisesRegex(m.Rejected, 'already_exists'):
                self.fs.put(self.parent, name, b'forbidden', 'forbidden-' + name)
        with self.assertRaisesRegex(m.Rejected, 'single_link'):
            self.fs.read(original, (8, hashlib.sha256(b'original').hexdigest()))
        self.assertEqual(original.read_bytes(), b'original')
        self.assertTrue((self.base / 'symlink').is_symlink())
        self.assertEqual(original.stat().st_nlink, 2)

    def test_path_swap_is_detected_and_only_original_directory_fd_is_closed(self):
        owned = self.fs.mkdir(self.parent, 'owned', 'owned')
        original_fd = owned.fd
        moved = self.base / 'moved'
        owned.path.rename(moved)
        owned.path.mkdir(mode=0o700)
        foreign_fd = os.open(owned.path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaisesRegex(m.Rejected, 'path_or_handle_changed'):
                self.fs.verify_directory(owned)
            errors = self.fs.close()
            self.assertIn('final_directory_identity_changed', errors)
            with self.assertRaises(OSError):
                os.fstat(original_fd)
            self.assertEqual(os.fstat(foreign_fd).st_ino, owned.path.stat().st_ino)
        finally:
            os.close(foreign_fd)

    def test_artifact_stream_copy_has_independent_inode_and_full_digest(self):
        data = bytes(range(251)) * 5000
        source = self.fixture('tool', data, 0o700)
        before = m.identity(source.stat())
        target = self.fs.mkdir(self.parent, 'runtime', 'runtime')
        expected = (len(data), hashlib.sha256(data).hexdigest())
        pin = self.fs.copy(source, target, 'copied', 'server', expected)
        self.assertEqual(pin['sha256'], expected[1])
        self.assertEqual(pin['bytes'], expected[0])
        self.assertNotEqual(pin['identity']['inode'], before['inode'])
        self.assertEqual(m.identity(source.stat()), before)
        self.assertEqual(pin['identity']['mode'], 0o700)
        self.fs.verify_all()
        self.assertEqual(self.fs.file_opened, self.fs.file_closed)

    def test_partial_write_failure_preserves_partial_file_and_closes_original(self):
        real_write = os.write
        count = 0

        def partial(fd, value):
            nonlocal count
            count += 1
            if count == 1:
                return real_write(fd, value[:3])
            raise OSError('synthetic_io_failure')

        with mock.patch.object(m.os, 'write', side_effect=partial):
            with self.assertRaises(OSError):
                self.fs.put(self.parent, 'partial', b'abcdefgh', 'partial')
        self.assertEqual((self.base / 'partial').read_bytes(), b'abc')
        self.assertEqual((self.base / 'partial').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.fs.file_opened, self.fs.file_closed)
        self.assertFalse(self.fs.file_fds)
        with self.assertRaisesRegex(m.Rejected, 'already_exists'):
            self.fs.put(self.parent, 'partial', b'new-attempt', 'partial')

    def test_registered_fd_birth_and_sticky_signal_survive_caller_interruption(self):
        source = self.fixture()
        foreign = os.open(source, os.O_RDONLY)
        original = self.fs._open_file(source, os.O_RDONLY)
        # Simulate interruption after the helper returned but before a caller
        # entered its own try/finally. Global custody still owns the original.
        with self.clock.critical():
            self.clock.interrupt(signal.SIGTERM, None)
        with self.assertRaises(m.Interrupted):
            self.clock.check()
        try:
            self.assertEqual(self.fs.close(), [])
            with self.assertRaises(OSError):
                os.fstat(original)
            self.assertEqual(os.fstat(foreign).st_ino, source.stat().st_ino)
            self.assertEqual(self.fs.file_opened, self.fs.file_closed)
            self.assertEqual(self.clock.signal_number, signal.SIGTERM)
        finally:
            os.close(foreign)
        # Rejection before this controller installs its timer must not cancel
        # an existing timer owned by another caller during final cleanup.
        rejected_clock = m.Clock(time.monotonic())
        with mock.patch.object(m.signal, 'getitimer', return_value=(7.0, 0.0)), \
                mock.patch.object(m.signal, 'setitimer') as setter:
            with self.assertRaisesRegex(m.Rejected, 'existing_timer_refused'):
                rejected_clock.start()
            rejected_clock.finish()
            setter.assert_not_called()
        # The original descriptor must be registered before its very first
        # fstat. An observation error cannot erase its retirement authority.
        real_fstat = os.fstat
        for operation in ('read_open', 'put_create', 'copy_create', 'mkdir'):
            with self.subTest(first_fstat_failure=operation):
                clock = m.Clock(time.monotonic())
                fs = m.Filesystem(clock, os.geteuid(), os.getegid())
                parent = fs.directory(self.base, 'original-parent')
                observed = {parent.fd}
                born = []
                failing_fd = None
                failing_observations = 0

                def fail_first_birth(fd):
                    nonlocal failing_fd, failing_observations
                    if fd not in observed:
                        observed.add(fd)
                        born.append(fd)
                        if len(born) == (2 if operation == 'copy_create' else 1):
                            failing_fd = fd
                    if fd == failing_fd:
                        failing_observations += 1
                        raise OSError('synthetic_first_fstat_failure')
                    return real_fstat(fd)

                executable = self.fixture('copy-source-' + operation, b'fixed-tool', 0o700)
                expected = (10, hashlib.sha256(b'fixed-tool').hexdigest())
                try:
                    with mock.patch.object(m.os, 'fstat', side_effect=fail_first_birth):
                        with self.assertRaises(OSError):
                            if operation == 'read_open':
                                fs._open_file(source, os.O_RDONLY)
                            elif operation == 'put_create':
                                fs.put(parent, 'put-first-stat', b'value', 'new-file')
                            elif operation == 'copy_create':
                                fs.copy(executable, parent, 'copy-first-stat', 'server', expected)
                            else:
                                fs.mkdir(parent, 'mkdir-first-stat', 'new-directory')
                        self.assertEqual(fs.close(), [])
                        self.assertEqual(failing_observations, 1)
                    self.assertIsNotNone(failing_fd)
                    with self.assertRaises(OSError):
                        real_fstat(failing_fd)
                    self.assertEqual(fs.file_opened, fs.file_closed)
                    self.assertFalse(fs.file_fds)
                    self.assertTrue(all(d.closed for d in fs.directories))
                finally:
                    fs.close()

    def test_real_tls_chain_key_separation_sans_lifetimes_and_wrong_key_rejection(self):
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtendedKeyUsageOID

        now = dt.datetime(2026, 11, 6, 15, 0, tzinfo=dt.timezone.utc)
        values, public = m.generate_tls(now)
        ca = x509.load_pem_x509_certificate(values['ca_certificate'])
        cert = x509.load_pem_x509_certificate(values['server_certificate'])
        ca_key = serialization.load_pem_private_key(values['ca_private_key'], password=None)
        server_key = serialization.load_pem_private_key(values['server_private_key'], password=None)
        self.assertEqual(ca_key.curve.name, 'secp256r1')
        self.assertEqual(server_key.curve.name, 'secp256r1')
        self.assertNotEqual(ca_key.public_key().public_numbers(), server_key.public_key().public_numbers())
        ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
        with self.assertRaises(InvalidSignature):
            server_key.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual([str(x) for x in san.get_values_for_type(x509.IPAddress)], ['127.0.0.1'])
        self.assertEqual(san.get_values_for_type(x509.DNSName), ['localhost'])
        self.assertEqual(list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value), [ExtendedKeyUsageOID.SERVER_AUTH])
        self.assertEqual(ca.not_valid_after_utc - now, dt.timedelta(days=3650))
        self.assertEqual(cert.not_valid_after_utc - now, dt.timedelta(days=365))
        self.assertEqual(cert.not_valid_before_utc, now - dt.timedelta(minutes=5))
        self.assertEqual(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length, 0)
        self.assertFalse(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        public_wire = json.dumps(public).encode()
        for key in ('ca_private_key', 'server_private_key'):
            self.assertNotIn(values[key], public_wire)
            self.assertNotIn(hashlib.sha256(values[key]).hexdigest().encode(), public_wire)
        self.assertFalse(public['remote_tls_endpoint_verified'])

    def test_input_json_rejects_ambiguous_fields_and_preserves_nanosecond_integers(self):
        with self.assertRaisesRegex(m.Rejected, 'duplicate_json_field'):
            m.parse(b'{"value":1,"value":2}')
        with self.assertRaisesRegex(m.Rejected, 'nonfinite_json'):
            m.parse(b'{"value":NaN}')
        large = 1793992319273570908
        self.assertEqual(m.parse(m.encoded({'mtime_ns': large}))['mtime_ns'], large)
        self.assertEqual(m.parse(m.encoded(m.fixed_inputs())), m.fixed_inputs())
        record = m.identity((self.fixture()).stat())
        self.assertEqual(set(m.file_binding(record)), {'dev', 'inode', 'uid', 'gid', 'mode', 'nlink', 'bytes', 'mtime_ns', 'ctime_ns', 'file_type'})
        self.assertEqual(m.file_binding(record)['file_type'], 32768)
        root = m.root_binding(self.base, m.identity(self.base.stat()))
        self.assertEqual(set(root), {'path', 'dev', 'inode', 'uid', 'gid', 'mode'})


if __name__ == '__main__':
    unittest.main(verbosity=2)
