"""Local gateway boundary tests; no real SDK, HeptaBao or external provider."""
from contextlib import contextmanager
from email.message import Message
from email.utils import formatdate
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
from urllib.parse import urlencode

import native_v6_authbus_openai_refresh_live as profile
from cert_auth_live import issue_leaf


class NativeDouble:
    """An explicit non-native oracle, used only for gateway unit boundaries."""
    def __init__(self, root):
        self.root = root
        self.token = 'synthetic-native-double-root'
        self.calls = 0
        self.document = None
        self.version = 2

    def wire(self, method, path, raw=None, *, token=''):
        self.calls += 1
        if method != 'GET' or token != self.token:
            raise AssertionError('unexpected_non_native_oracle_input')
        return profile.WireReply(200, profile.canonical({'data': {'data': self.document,
            'metadata': {'version': self.version}}}), formatdate(usegmt=True), 'application/json')


def unknown(item):
    return {'protocol': profile.PROTOCOL, 'refreshAttempts': [{'status': 'UNKNOWN',
        'credentialDigest': item['originalDigest'], 'scopeDigest': 'scope', 'bootId': 'boot', 'fenceEpoch': 4}],
        'assignments': [{'status': 'REFRESH_PENDING', 'scopeDigest': 'scope', 'bootId': 'boot', 'epoch': 4}]}


def form(item):
    return urlencode({'grant_type': 'refresh_token', 'client_id': 'app_EMoamEEZ73f0CkXaXp7hrann',
                      'refresh_token': item['original']['refresh']}).encode()


class GatewayBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='native-openai-local-unit-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.native = NativeDouble(self.root)
        self.cases = profile.make_cases('synthetic-local-only')
        self.native.document = unknown(self.cases[0])
        self.gateway = profile.FixtureGateway(self.native, self.root, self.cases, lambda: 10)
        self.gateway.phase = 'warm'

    def test_fixed_five_scenarios_and_original_deadline(self):
        self.assertEqual(tuple(profile.PROVIDER_COUNTS.values()), (1, 0, 1, 1, 0))
        self.assertEqual(profile.PROFILE_SECONDS, 180)
        self.assertEqual(profile.bounded_deadline(10, 100), 100)
        self.assertEqual(profile.bounded_deadline(10, 999_000_000_000), 180_000_000_010)
        with self.assertRaises(profile.CanaryFailure):
            profile.bounded_deadline(10, 10)

    def test_form_response_requires_independent_unknown_read(self):
        reply = self.gateway.provider('POST', '/oauth/token', 'application/x-www-form-urlencoded', form(self.cases[0]))
        self.assertEqual(reply.status, 200)
        self.assertEqual(self.native.calls, 1)
        self.assertEqual(self.gateway.counts['manager-success'],
            {'providerRequests': 1, 'unknownAtProvider': 1, 'unknownAckDrops': 0})
        self.assertEqual(reply.document()['refresh_token'], self.cases[0]['newRefresh'])
        self.assertEqual(len(self.gateway.events), 1)

    def test_duplicate_missing_foreign_and_wrong_route_never_read_control(self):
        valid = form(self.cases[0])
        variants = [
            ('GET', '/oauth/token', 'application/x-www-form-urlencoded', valid),
            ('POST', '/oauth/token?next=1', 'application/x-www-form-urlencoded', valid),
            ('POST', '/oauth/token', 'application/json', valid),
            ('POST', '/oauth/token', 'application/x-www-form-urlencoded', valid + b'&client_id=extra'),
            ('POST', '/oauth/token', 'application/x-www-form-urlencoded', b'grant_type=refresh_token&client_id=x&client_id=x'),
            ('POST', '/oauth/token', 'application/x-www-form-urlencoded', valid.replace(b'grant_type=refresh_token', b'grant_type=password')),
            ('POST', '/oauth/token', 'application/x-www-form-urlencoded', valid.replace(b'app_EMoamEEZ73f0CkXaXp7hrann', b'foreign-client')),
            ('POST', '/oauth/token', 'application/x-www-form-urlencoded', b'grant_type=refresh_token&client_id=app_EMoamEEZ73f0CkXaXp7hrann&refresh_token=foreign'),
            ('POST', '/oauth/token', 'application/x-www-form-urlencoded', b'\xff'),
        ]
        for variant in variants:
            with self.subTest(kind=variants.index(variant)):
                with self.assertRaises(profile.CanaryFailure):
                    self.gateway.provider(*variant)
        self.assertEqual(self.native.calls, 0)
        self.assertEqual(self.gateway.events, [])

    def test_published_or_mismatched_owner_never_produces_response(self):
        for section, field, value in [('refreshAttempts', 'status', 'PUBLISHED'),
              ('assignments', 'status', 'ASSIGNED'), ('refreshAttempts', 'credentialDigest', 'other'),
              ('refreshAttempts', 'scopeDigest', 'other'), ('refreshAttempts', 'bootId', 'other'),
              ('refreshAttempts', 'fenceEpoch', 3)]:
            self.native.document = unknown(self.cases[0])
            self.native.document[section][0][field] = value
            with self.subTest(section=section, field=field):
                with self.assertRaises(profile.CanaryFailure):
                    self.gateway.provider('POST', '/oauth/token', 'application/x-www-form-urlencoded', form(self.cases[0]))
        self.assertEqual(self.gateway.counts['manager-success']['providerRequests'], 0)

    def test_duplicate_and_cold_send_remain_closed(self):
        self.gateway.provider('POST', '/oauth/token', 'application/x-www-form-urlencoded', form(self.cases[0]))
        with self.assertRaises(profile.CanaryFailure):
            self.gateway.provider('POST', '/oauth/token', 'application/x-www-form-urlencoded', form(self.cases[0]))
        self.gateway.phase = 'cold-before-server'
        self.native.document = unknown(self.cases[2])
        with self.assertRaises(profile.CanaryFailure):
            self.gateway.provider('POST', '/oauth/token', 'application/x-www-form-urlencoded', form(self.cases[2]))
        self.assertEqual(self.native.calls, 1)

    def test_provider_ack_loss_is_after_unknown_and_counted_once(self):
        self.native.document = unknown(self.cases[2])
        self.assertIsNone(self.gateway.provider('POST', '/oauth/token', 'application/x-www-form-urlencoded', form(self.cases[2])))
        self.assertEqual(self.gateway.counts['provider-ack-lost']['unknownAtProvider'], 1)
        self.assertEqual(self.native.calls, 1)

    def test_original_deadline_rechecked_after_durable_observation(self):
        expired = False
        def remaining():
            if expired:
                raise profile.CanaryFailure('synthetic_original_deadline')
            return 1
        original = self.gateway.record
        def slow_observation(event):
            nonlocal expired
            original(event)
            expired = True
        self.gateway.remaining = remaining
        self.gateway.record = slow_observation
        with self.assertRaisesRegex(profile.CanaryFailure, 'synthetic_original_deadline'):
            self.gateway.provider('POST', '/oauth/token', 'application/x-www-form-urlencoded', form(self.cases[0]))
        self.assertEqual(self.gateway.counts['manager-success']['providerRequests'], 1)
        self.assertEqual(self.native.calls, 1)

    def test_framing_rejects_duplicate_chunked_and_oversized_before_read(self):
        for fields in [[('Content-Length', '1'), ('Content-Length', '1')],
                       [('Transfer-Encoding', 'chunked')], [('Content-Length', '65537')],
                       [('Content-Length', '-1')], [('Content-Length', '01')]]:
            headers = Message()
            for name, value in fields:
                headers[name] = value
            with self.subTest(fields=fields):
                with self.assertRaises(profile.CanaryFailure):
                    profile.request_length(headers, profile.MAX_PROVIDER_BYTES)


class ActualLoopbackTlsBoundaries(unittest.TestCase):
    """Real sockets and verified disposable TLS, with an explicitly fake Bao."""
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='native-openai-local-tls-')
        cls.cert_root = Path(cls.temp.name)
        def command(arguments):
            subprocess.run(arguments, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(cls.cert_root / 'ca.key'),
            '-out', str(cls.cert_root / 'ca.crt'), '-days', '1', '-subj', '/CN=synthetic-local-native-openai-ca'])
        for name, host in [('tls', '127.0.0.1')]:
            issue_leaf(cls.cert_root, name, '/CN=' + host, cls.cert_root / 'ca.crt', cls.cert_root / 'ca.key',
                'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
                'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:auth.openai.com,IP:127.0.0.1\n')
        owner = profile.owned_process.Owner(cls.cert_root, deadline_ns=time.monotonic_ns() + 20_000_000_000,
                                            profile='native_openai_local_provider_certificate_only')
        with profile.owned_process.activated(owner):
            profile.issue_owned_provider_leaf(cls.cert_root, owner.remaining)
        if (not owner.receipt['passed_process_method'] or len(owner.receipt['children']) != 2
                or not all(row['same_original_Popen_wait'] for row in owner.receipt['children'])):
            raise AssertionError('local_owned_provider_certificate_commands_not_qualified')

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory(prefix='native-openai-local-wire-') as folder:
            native = NativeDouble(self.cert_root)
            cases = profile.make_cases('synthetic-local-tls-only')
            native.document = unknown(cases[0])
            gateway = profile.FixtureGateway(native, Path(folder), cases, lambda: 3)
            gateway.phase = 'warm'
            _, port = gateway.start()
            try:
                yield gateway, native, cases, port
            finally:
                gateway.close()
                self.assertTrue(all(not thread.is_alive() for thread in gateway.threads))

    def request(self, port, body, *, hosts=('auth.openai.com',), sni='auth.openai.com', content_types=('application/x-www-form-urlencoded',), extra=()):
        context = ssl.create_default_context(cafile=str(self.cert_root / 'ca.crt'))
        context.set_alpn_protocols(['http/1.1'])
        with socket.create_connection(('127.0.0.1', port), timeout=2) as raw:
            with context.wrap_socket(raw, server_hostname=sni) as connection:
                self.assertEqual(connection.selected_alpn_protocol(), 'http/1.1')
                headers = [('Host', host) for host in hosts] + [('Content-Type', value) for value in content_types]
                headers += [('Content-Length', str(len(body))), ('Connection', 'close')] + list(extra)
                wire = ('POST /oauth/token HTTP/1.1\r\n' + ''.join(name + ': ' + value + '\r\n' for name, value in headers) + '\r\n').encode() + body
                connection.sendall(wire)
                result = b''
                while True:
                    block = connection.recv(4096)
                    if not block:
                        break
                    result += block
                    self.assertLess(len(result), 65536)
                return result

    def test_exact_sni_host_tls_and_form_positive(self):
        with self.fixture() as (gateway, native, cases, port):
            reply = self.request(port, form(cases[0]))
            self.assertTrue(reply.startswith(b'HTTP/1.1 200 '))
            self.assertEqual(native.calls, 1)
            self.assertEqual(gateway.counts['manager-success']['providerRequests'], 1)
            self.assertEqual(gateway.local_denials, 0)
            self.assertEqual(gateway.failures, [])

    def test_duplicate_or_foreign_host_rejected_before_native_read(self):
        for hosts in [('auth.openai.com', 'auth.openai.com'), ('foreign.invalid',)]:
            with self.subTest(hosts=hosts), self.fixture() as (gateway, native, cases, port):
                reply = self.request(port, form(cases[0]), hosts=hosts)
                self.assertTrue(reply.startswith(b'HTTP/1.1 502 '))
                self.assertEqual(native.calls, 0)
                self.assertEqual(gateway.counts['manager-success']['providerRequests'], 0)

    def test_duplicate_content_type_and_framing_rejected(self):
        for values in [('content_types', ('application/x-www-form-urlencoded', 'application/x-www-form-urlencoded')),
                       ('extra', (('Content-Length', '1'),)), ('extra', (('Transfer-Encoding', 'chunked'),))]:
            with self.subTest(kind=values[0]), self.fixture() as (gateway, native, cases, port):
                reply = self.request(port, form(cases[0]), **{values[0]: values[1]})
                self.assertTrue(reply.startswith(b'HTTP/1.1 502 '))
                self.assertEqual(native.calls, 0)

    def test_wrong_sni_fails_tls_before_http_or_native_read(self):
        with self.fixture() as (gateway, native, cases, port):
            with self.assertRaises(ssl.SSLError):
                self.request(port, form(cases[0]), sni='foreign.invalid')
            self.assertEqual(native.calls, 0)
            self.assertEqual(gateway.local_denials, 1)


if __name__ == '__main__':
    unittest.main()
