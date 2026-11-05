import hashlib
import os
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest.mock import Mock
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from heptabao.proxy import read_request,forward,configuration
from heptabao.agent import AgentConfig
from heptabao.private_state import StateDirectory
from heptabao.transport import BaoError,Response,private_write


class ProxyTests(unittest.TestCase):
    def request(self,raw):
        a,b=socket.socketpair()
        try:
            a.sendall(raw);a.shutdown(socket.SHUT_WR)
            return read_request(b,time.monotonic()+1)
        finally:a.close();b.close()
    def test_canonical_single_json_request(self):
        raw=b'POST /v1/transit/encrypt/key HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}'
        self.assertEqual(self.request(raw),('POST','transit/encrypt/key',{}))
    def test_incoming_authority_headers_cannot_be_forwarded(self):
        for extra in [b'X-Vault-Token: stolen\r\n',b'X-Vault-Namespace: outside\r\n',b'X-Vault-Wrap-TTL: 1s\r\n',b'Transfer-Encoding: chunked\r\n',b'Proxy-Authorization: private\r\n']:
            with self.subTest(extra=extra),self.assertRaises(BaoError):
                self.request(b'GET /v1/secret/data/a HTTP/1.1\r\nHost: localhost\r\n'+extra+b'\r\n')
    def test_smuggling_duplicate_length_percent_traversal_and_pipeline_reject(self):
        cases=[b'GET /v1/secret/data/a HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n',
               b'GET /v1/secret/data/a HTTP/1.1\r\nHost: localhost\r\n\r\nGET /v1/b HTTP/1.1\r\n\r\n',
               b'GET /v1/secret/%2Fa HTTP/1.1\r\nHost: localhost\r\n\r\n',
               b'GET /v1/../auth/token/create HTTP/1.1\r\nHost: localhost\r\n\r\n',
               b'GET https://attacker/ HTTP/1.1\r\nHost: localhost\r\n\r\n',
               b'GET /v1/secret/a HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n']
        for raw in cases:
            with self.subTest(raw=raw),self.assertRaises(BaoError):self.request(raw)
    def test_read_body_and_nonobject_json_reject(self):
        for method,payload in [('GET',b'{}'),('POST',b'[]'),('POST',b'{"a":1,"a":2}')]:
            raw=f'{method} /v1/secret/a HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\n\r\n'.encode()+payload
            with self.assertRaises(BaoError):self.request(raw)
    def test_exact_allowlist_before_token_or_upstream_access(self):
        factory=Mock()
        with self.assertRaisesRegex(BaoError,'route_not_admitted'):
            forward({'routes':[{'method':'GET','path':'secret/data/allowed','effectful':False}]},None,'GET','secret/data/allowed/extra',None,client_factory=factory)
        factory.assert_not_called()
    def test_fixed_namespace_and_ready_token_snapshot_are_used_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);state=root/'state';state.mkdir(mode=0o700)
            ca=root/'ca';ca.write_text('synthetic-ca');ca.chmod(0o600)
            cfg=AgentConfig('https://localhost:8200',str(ca),str(root/'role'),str(root/'secret'),str(state),namespace='team')
            with StateDirectory(state,writer=True) as directory:
                raw=b'synthetic-ready-token\n';directory.write('token',raw)
                directory.publish('state.json',{'schema':1,'phase':'ready','binding':cfg.binding(),'observed_wall':time.time()-1,'expires_at':time.time()+30,'token_sha256':hashlib.sha256(raw).hexdigest()})
            factory=Mock();factory.return_value.request.return_value=Response(200,{'data':{}})
            policy={'timeout':5,'routes':[{'method':'GET','path':'secret/data/a','effectful':False}]}
            forward(policy,cfg,'GET','secret/data/a',None,client_factory=factory)
            self.assertEqual(factory.call_args.args[2:4],('synthetic-ready-token','team'))
            factory.return_value.request.assert_called_once()
            with StateDirectory(state,writer=True) as directory:
                v=directory.json('state.json');v['phase']='renew_pending';directory.publish('state.json',v)
            with self.assertRaises(BaoError):forward(policy,cfg,'GET','secret/data/a',None,client_factory=factory)
            factory.return_value.request.assert_called_once()
    def test_writable_ca_rejects_before_token_or_upstream_access(self):
        for mode in (0o620, 0o602, 0o666):
            with self.subTest(mode=oct(mode)), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                ca = root / 'ca'
                ca.write_text('synthetic-ca')
                ca.chmod(mode)
                cfg = AgentConfig('https://localhost:8200', str(ca),
                    str(root / 'role'), str(root / 'secret'), str(root / 'absent-state'))
                factory = Mock()
                policy = {'timeout': 5, 'routes': [
                    {'method': 'GET', 'path': 'secret/data/a', 'effectful': False}]}
                with self.assertRaisesRegex(BaoError, 'trust_root_requires_bounded_nonwritable_regular_file'):
                    forward(policy, cfg, 'GET', 'secret/data/a', None, client_factory=factory)
                factory.assert_not_called()
                self.assertFalse((root / 'absent-state').exists())

    def test_missing_explicit_effect_admission_and_system_routes_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'proxy.json'
            for route in [{'method':'POST','path':'secret/data/a','effectful':False},
                          {'method':'POST','path':'secret/data/a','effectful':True},
                          {'method':'GET','path':'sys/seal','effectful':False}]:
                private_write(p,{'agent_config':'/config','socket_dir':'/private','routes':[route]})
                with self.assertRaises(BaoError):configuration(str(p))



    def test_expired_parser_budget_cannot_enter_upstream_or_read_token(self):
        factory = Mock()
        policy = {'timeout': 5, 'routes': [
            {'method': 'GET', 'path': 'secret/data/a', 'effectful': False}]}
        with self.assertRaisesRegex(BaoError, 'request_deadline'):
            forward(policy, None, 'GET', 'secret/data/a', None,
                    client_factory=factory, deadline=time.monotonic()-1)
        factory.assert_not_called()


if __name__=='__main__':unittest.main()
