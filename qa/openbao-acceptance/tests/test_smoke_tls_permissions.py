"""Synthetic TLS files have explicit safe modes, independent of the host umask."""
import importlib.util
import os
from pathlib import Path
import socket
import ssl
import threading
import sys
import tempfile
import unittest
from unittest.mock import patch
from cryptography import x509

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'clients/python'))
from heptabao.private_state import read_trusted_ca

spec = importlib.util.spec_from_file_location('tls_permission_smoke', ROOT / 'qa/single-node/smoke.py')
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class SmokeTlsPermissionTests(unittest.TestCase):
    def test_certificate_integrity_and_private_key_modes_ignore_umask(self):
        for mask in (0o000, 0o002, 0o022, 0o077):
            with self.subTest(umask=oct(mask)), tempfile.TemporaryDirectory() as tmp:
                previous = os.umask(mask)
                try:
                    node = smoke.Instance(Path('/not-started'), Path(tmp) / 'node')
                finally:
                    os.umask(previous)
                self.assertIsNone(node.process)
                self.assertGreaterEqual(node.context.minimum_version, ssl.TLSVersion.TLSv1_2)
                self.assertTrue(node.context.check_hostname)
                self.assertEqual(node.context.verify_mode, ssl.CERT_REQUIRED)
                for name in ('ca.crt', 'tls.crt'):
                    path = node.root / name
                    self.assertEqual(path.stat().st_mode & 0o777, 0o644)
                    self.assertTrue(read_trusted_ca(str(path)).startswith(b'-----BEGIN CERTIFICATE-----'))
                for name in ('ca.key', 'tls.key', 'server.json'):
                    self.assertEqual((node.root / name).stat().st_mode & 0o777, 0o600)
                self.assertEqual(node.root.stat().st_mode & 0o777, 0o700)


class SmokeStrictCertificateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.node = smoke.Instance(Path('/not-started'), self.root / 'node')
        # Exercise strict verification on Python 3.12 too, not only 3.13+.
        self.node.context.verify_flags |= ssl.VERIFY_X509_STRICT

    def handshake(self, client, hostname):
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.minimum_version = ssl.TLSVersion.TLSv1_2
        server.load_cert_chain(str(self.node.root / 'tls.crt'), str(self.node.root / 'tls.key'))
        self.assertTrue(client.check_hostname)
        self.assertEqual(client.verify_mode, ssl.CERT_REQUIRED)
        left, right = socket.socketpair()
        left.settimeout(5)
        right.settimeout(5)
        def serve():
            try:
                with server.wrap_socket(left, server_side=True) as stream:
                    stream.sendall(b'ok')
            except ssl.SSLError:
                # Invalid-name and untrusted-CA clients abort the handshake.
                pass
            finally:
                left.close()
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            with client.wrap_socket(right, server_hostname=hostname) as stream:
                self.assertEqual(stream.recv(2), b'ok')
        finally:
            right.close()
            thread.join(timeout=6)
            self.assertFalse(thread.is_alive())

    def test_real_strict_handshake_accepts_dns_and_ip_names(self):
        for name in ('localhost', '127.0.0.1'):
            with self.subTest(name=name):
                self.handshake(self.node.context, name)

    def test_real_strict_handshake_rejects_wrong_hostname(self):
        with self.assertRaises(ssl.SSLCertVerificationError) as failure:
            self.handshake(self.node.context, 'wrong.synthetic.invalid')
        # A malformed certificate must not masquerade as hostname rejection.
        self.assertEqual(failure.exception.verify_code, 62)

    def test_real_strict_handshake_rejects_an_unrelated_ca(self):
        unrelated = smoke.Instance(Path('/not-started'), self.root / 'unrelated')
        unrelated.context.verify_flags |= ssl.VERIFY_X509_STRICT
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.handshake(unrelated.context, 'localhost')

    def test_leaf_authority_identifier_matches_ca_subject_identifier(self):
        ca = x509.load_pem_x509_certificate((self.node.root / 'ca.crt').read_bytes())
        leaf = x509.load_pem_x509_certificate((self.node.root / 'tls.crt').read_bytes())
        subject = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        self.assertEqual(leaf.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier).value.key_identifier, subject)
        self.assertEqual(ca.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier).value.key_identifier, subject)
        self.assertIsNotNone(leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier))

    def test_certificate_failure_is_not_retried_as_listener_readiness(self):
        error = ssl.SSLCertVerificationError(1, 'synthetic-private-diagnostic')
        for failure in (error, smoke.urllib.error.URLError(error)):
            with self.subTest(wrapped=isinstance(failure, smoke.urllib.error.URLError)), \
                    patch.object(smoke.subprocess, 'Popen') as process, \
                    patch.object(self.node, 'call', side_effect=failure) as call, \
                    patch.object(smoke.time, 'sleep') as sleep:
                process.return_value.poll.return_value = None
                try:
                    with self.assertRaisesRegex(RuntimeError, '^TLS certificate verification failed during startup$'):
                        self.node.start()
                    call.assert_called_once_with('GET', 'sys/health')
                    sleep.assert_not_called()
                finally:
                    self.node.log.close()
                    self.node.process = None


if __name__ == '__main__':
    unittest.main()
