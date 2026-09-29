"""Regression coverage for explicit request prerequisites, never implicit retries."""
import base64
import email.message
import io
import json
from pathlib import Path
import socket
import sys
import time
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from heptabao.transport import BaoError, Client
from heptabao.proxy import read_request

INDEX = base64.b64encode(b'{"cluster":"synthetic","value":"heptabao-raft-v1:7"}').decode()

class Reply(io.BytesIO):
    def __init__(self, headers=(), code=200):
        super().__init__(b'{"data":{"accepted":true}}')
        self.code = code
        self.headers = email.message.Message()
        for name, value in headers:
            self.headers[name] = value

class ConsistencyTests(unittest.TestCase):
    def client(self, headers=(), code=200):
        c = object.__new__(Client)
        c.address = 'https://localhost:8200'; c._token = 'synthetic'
        c.namespace = ''; c.timeout = 1
        c._opener = Mock(); c._opener.open.return_value = Reply(headers, code)
        return c

    def test_response_retains_index_without_changing_body_or_replaying(self):
        c = self.client([('X-Vault-Index', INDEX)])
        result = c.request('POST', '/v1/secret/data/a', {'data': {'a': 1}})
        self.assertEqual(result.consistency_index, INDEX)
        self.assertTrue(result.consistency_valid)
        self.assertEqual(result.body, {'data': {'accepted': True}})
        c._opener.open.assert_called_once()

    def test_explicit_ordered_policy_pair_is_attached_to_one_request(self):
        c = self.client(code=429)
        result = c.request('POST', '/v1/secret/data/a', {}, consistency_index=INDEX,
                           inconsistent=('await-state', 'fail'))
        self.assertEqual(result.status, 429)
        c._opener.open.assert_called_once()
        req = c._opener.open.call_args.args[0]
        self.assertEqual(req.heptabao_consistency.headers(), (
            ('X-Vault-Index', INDEX), ('X-Vault-Inconsistent', 'await-state'),
            ('X-Vault-Inconsistent', 'fail')))

    def test_invalid_policy_fails_before_network(self):
        for policy in ['', 'await-state, fail', ('fail', 'await-state'),
                       ('await-state', 'await-state'), ('fail', 'fail')]:
            c = self.client()
            with self.subTest(policy=policy), self.assertRaises(BaoError):
                c.request('POST', '/v1/secret/data/a', {}, inconsistent=policy)
            c._opener.open.assert_not_called()

    def test_proxy_parses_ordered_prerequisite_without_accepting_credentials(self):
        a, b = socket.socketpair()
        try:
            a.sendall(('GET /v1/secret/data/a HTTP/1.1\r\nHost: localhost\r\n'
                'X-Vault-Index: '+INDEX+'\r\nX-Vault-Inconsistent: await-state\r\n'
                'X-Vault-Inconsistent: forward-active-node\r\n\r\n').encode())
            a.shutdown(socket.SHUT_WR)
            method, path, body, metadata = read_request(b, time.monotonic()+1, with_consistency=True)
            self.assertEqual((method, path, body), ('GET', 'secret/data/a', None))
            self.assertEqual(metadata.behavior, ('await-state', 'forward-active-node'))
            self.assertEqual(metadata.index, INDEX)
        finally:
            a.close(); b.close()

    def test_ambiguous_response_metadata_never_changes_acknowledged_result(self):
        for headers in [[('X-Vault-Index', 'invalid')],
                        [('X-Vault-Index', INDEX), ('X-Vault-Index', INDEX)]]:
            c = self.client(headers)
            result = c.request('POST', '/v1/secret/data/a', {})
            self.assertEqual(result.status, 200)
            self.assertEqual(result.body, {'data': {'accepted': True}})
            self.assertIsNone(result.consistency_index)
            self.assertFalse(result.consistency_valid)
            c._opener.open.assert_called_once()

    def test_absent_index_is_not_an_invented_prerequisite(self):
        result = self.client().request('GET', '/v1/sys/leader')
        self.assertIsNone(result.consistency_index)
        self.assertTrue(result.consistency_valid)

    def test_header_bytes_are_separate_ordered_lines_not_folded_or_joined(self):
        from heptabao.consistency import Metadata, _Connection
        conn = _Connection('localhost', consistency=Metadata(INDEX, ('await-state', 'fail')))
        sock = Mock(); conn.sock = sock
        conn.request('POST', '/v1/secret/data/a', b'{}', {'X-Vault-Token': 'synthetic'})
        raw = b''.join(c.args[0] for c in sock.sendall.call_args_list)
        self.assertEqual(raw.count(b'X-Vault-Token:'), 1)
        self.assertEqual(raw.count(b'X-Vault-Index:'), 1)
        self.assertIn(b'X-Vault-Inconsistent: await-state\r\nX-Vault-Inconsistent: fail\r\n', raw)
        self.assertNotIn(b'await-state,', raw)
        self.assertNotIn(b'\r\n\t', raw)
        self.assertTrue(raw.endswith(b'\r\n\r\n{}'))
        conn.close()

    def test_bad_indices_fail_before_network_without_echoing_input(self):
        for index in ['e30', 'invalid', 'x'*12289, 'a\r\nInjected: value',
                      base64.b64encode(b'[]').decode(),
                      base64.b64encode(b'{"CLUSTER":7}').decode(),
                      base64.b64encode(b'{"cluster":7,"cluster":"ok"}').decode()]:
            c = self.client()
            with self.subTest(length=len(index)), self.assertRaises(BaoError) as caught:
                c.request('POST', '/v1/secret/data/a', {}, consistency_index=index)
            self.assertEqual(str(caught.exception), 'invalid_consistency_index')
            c._opener.open.assert_not_called()

    def test_null_empty_and_foreign_indices_are_not_normalized(self):
        from heptabao.consistency import Metadata
        for index in ['', 'bnVsbA==', 'e30=', INDEX]:
            self.assertEqual(Metadata(index).headers(), (('X-Vault-Index', index),))

    def test_request_metadata_does_not_bleed_between_requests(self):
        c = self.client(); c._opener.open.side_effect = [Reply(), Reply()]
        c.request('GET', '/v1/secret/data/a', consistency_index=INDEX, inconsistent='fail')
        c.request('GET', '/v1/secret/data/a')
        requests = [call.args[0] for call in c._opener.open.call_args_list]
        self.assertTrue(hasattr(requests[0], 'heptabao_consistency'))
        self.assertFalse(hasattr(requests[1], 'heptabao_consistency'))

    def test_proxy_never_silently_discards_an_admitted_prerequisite(self):
        a, b = socket.socketpair()
        try:
            a.sendall(('GET /v1/secret/data/a HTTP/1.1\r\nHost: localhost\r\n'
                       'X-Vault-Index: '+INDEX+'\r\n\r\n').encode())
            a.shutdown(socket.SHUT_WR)
            with self.assertRaisesRegex(BaoError, 'proxy_consistency_context_required'):
                read_request(b, time.monotonic()+1)
        finally:
            a.close(); b.close()

    def test_proxy_reply_preserves_index_without_reflecting_request_headers(self):
        from heptabao.proxy import send_response
        a, b = socket.socketpair()
        try:
            send_response(a, 200, {'data': {}}, time.monotonic()+1, consistency_index=INDEX)
            raw = b.recv(8192)
            self.assertIn(('X-Vault-Index: '+INDEX+'\r\n').encode(), raw)
            self.assertNotIn(b'X-Vault-Token:', raw)
            with self.assertRaises(BaoError):
                send_response(a, 200, {}, time.monotonic()+1, consistency_index='bad\r\nheader')
        finally:
            a.close(); b.close()

    def test_connection_failure_is_one_attempt_with_unknown_mutation_outcome(self):
        c = self.client(); c._opener.open.side_effect = OSError('synthetic')
        with self.assertRaisesRegex(BaoError, 'transport_outcome_unknown'):
            c.request('POST', '/v1/secret/data/a', {}, consistency_index=INDEX,
                      inconsistent=('await-state', 'forward-active-node'))
        c._opener.open.assert_called_once()

    def test_retry_after_is_bounded_metadata_not_an_automatic_retry(self):
        c=self.client([('Retry-After','1')],code=429)
        result=c.request('POST','/v1/secret/data/a',{},inconsistent='fail')
        self.assertEqual(result.retry_after_seconds,1)
        c._opener.open.assert_called_once()
        for value in ['-1','999999999','1\r\nInjected: value']:
            c=self.client([('Retry-After',value)],code=429)
            self.assertIsNone(c.request('GET','/v1/secret/data/a').retry_after_seconds)

if __name__ == '__main__': unittest.main()
