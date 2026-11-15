#!/usr/bin/env python3
"""Local synthetic contexts only; the Mac failed fixture is never accessed."""
import hashlib
import importlib.util
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'probe_original_tls_memorybio_r1.py'
SOURCE_RAW = SOURCE.read_bytes()
spec = importlib.util.spec_from_file_location('tls_memorybio_probe', SOURCE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class SyntheticCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='heptabao-memorybio-local-')
        cls.path = Path(cls.temporary.name)
        ext = cls.path / 'leaf.ext'
        ext.write_text('basicConstraints=critical,CA:FALSE\n'
                       'keyUsage=critical,digitalSignature,keyEncipherment\n'
                       'extendedKeyUsage=serverAuth,clientAuth\n'
                       'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n'
                       'subjectAltName=DNS:node-1.heptabao.synthetic,IP:192.168.0.13\n')
        commands = [
            ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
             '-keyout', 'ca.key', '-out', 'ca.crt', '-subj', '/CN=Local Synthetic Test CA',
             '-addext', 'basicConstraints=critical,CA:TRUE',
             '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
             '-addext', 'subjectKeyIdentifier=hash',
             '-addext', 'authorityKeyIdentifier=keyid:always'],
            ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'leaf.key',
             '-out', 'leaf.csr', '-subj', '/CN=node-1.heptabao.synthetic'],
            ['x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
             '-CAcreateserial', '-out', 'leaf.crt', '-days', '1', '-sha256',
             '-extfile', 'leaf.ext'],
        ]
        for argv in commands:
            child = subprocess.run(['/usr/bin/openssl', *argv], cwd=cls.path,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   timeout=15, check=False)
            assert child.returncode == 0, 'synthetic local certificate fixture failed'
        cls.der = ssl.PEM_cert_to_DER_cert((cls.path / 'leaf.crt').read_text())
        cls.server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.server.load_cert_chain(cls.path / 'leaf.crt', cls.path / 'leaf.key')
        cls.server.set_alpn_protocols(['h2', 'http/1.1'])

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def client(self):
        context = ssl.create_default_context(cafile=str(self.path / 'ca.crt'))
        context.verify_flags |= ssl.VERIFY_X509_STRICT
        return context

    def exercise(self, name='192.168.0.13', client=None, der=None, until=None):
        with patch('socket.socket', side_effect=AssertionError('socket forbidden')), \
             patch('socket.create_connection', side_effect=AssertionError('connection forbidden')), \
             patch('socket.getaddrinfo', side_effect=AssertionError('DNS forbidden')):
            return probe.memorybio_case(client or self.client(), self.server, name,
                                        self.der if der is None else der,
                                        time.monotonic() + 5 if until is None else until)

    def test_ip_strict_identity_and_application_records(self):
        row = self.exercise()
        self.assertTrue(row['passed'])
        self.assertTrue(row['peerLeafMatchesOriginal'])
        self.assertTrue(row['applicationRecordRoundTrip'])
        self.assertFalse(row['networkOpened'])
        self.assertFalse(row['rustTlsExercised'])
        self.assertIsNone(row['selectedAlpn'])

    def test_dns_strict_identity_and_application_records(self):
        self.assertTrue(self.exercise(name='node-1.heptabao.synthetic')['passed'])

    def test_wrong_hostname_fails_with_verify_code(self):
        row = self.exercise(name='wrong.heptabao.synthetic')
        self.assertFalse(row['passed'])
        self.assertEqual(row['error']['type'], 'SSLCertVerificationError')
        self.assertEqual(row['error']['sslReason'], 'CERTIFICATE_VERIFY_FAILED')
        self.assertIsInstance(row['error']['verifyCode'], int)

    def test_wrong_ca_fails_closed(self):
        row = self.exercise(client=ssl.create_default_context())
        self.assertFalse(row['passed'])
        self.assertEqual(row['error']['type'], 'SSLCertVerificationError')

    def test_same_chain_wrong_leaf_pin_rejected(self):
        row = self.exercise(der=b'wrong synthetic leaf')
        self.assertFalse(row['passed'])
        self.assertEqual(row['error']['code'], 'original_leaf_der_mismatch')

    def test_verification_disabled_is_refused(self):
        context = self.client()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with self.assertRaisesRegex(probe.Refused, 'original_strict_client_context_required'):
            self.exercise(client=context)

    def test_hostname_verification_disabled_is_refused(self):
        context = self.client()
        context.check_hostname = False
        with self.assertRaisesRegex(probe.Refused, 'original_strict_client_context_required'):
            self.exercise(client=context)

    def test_expired_shared_deadline_is_refused(self):
        with self.assertRaisesRegex(probe.Refused, 'memorybio_total_deadline'):
            self.exercise(until=time.monotonic() - 1)

    def test_context_verification_flags_are_never_mutated(self):
        context = self.client()
        before = (context.check_hostname, context.verify_mode, context.verify_flags)
        self.assertTrue(self.exercise(client=context)['passed'])
        self.assertEqual(before, (context.check_hostname, context.verify_mode, context.verify_flags))

    def test_private_key_is_not_a_public_pin(self):
        self.assertNotIn(probe.KEY, probe.PUBLIC_PINS)
        self.assertEqual(set(probe.PUBLIC_PINS), {probe.CA, probe.LEAF, probe.PYTHON})


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(SyntheticCases))
    assert SOURCE.read_bytes() == SOURCE_RAW
    print(json.dumps({'schema': 'heptabao.ha-memorybio-local-guards.r1',
                      'passed': result.wasSuccessful(), 'tests': result.testsRun,
                      'failures': len(result.failures), 'errors': len(result.errors),
                      'sourceBytes': len(SOURCE_RAW),
                      'sourceSha256': hashlib.sha256(SOURCE_RAW).hexdigest(),
                      'syntheticLocalOnly': True, 'remoteExecuted': False,
                      'macCertificatesAccessed': False, 'networkOpened': False,
                      'localFixtureOpenSslChildrenCompleted': 3,
                      'rustTlsQualified': False, 'lanQualified': False}, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
