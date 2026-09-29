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
from unittest.mock import Mock
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

if __name__ == '__main__': unittest.main()
