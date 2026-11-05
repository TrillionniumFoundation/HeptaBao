import copy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import native_snapshot_redirect_live as f


class RedirectGuards(unittest.TestCase):
    def test_complete_requires_named_raw_cli_epoch_and_cleanup_phases(self):
        rows=[{'case':name,'passed':True} for name in sorted(f.REQUIRED-{'complete'})]+[{'case':'complete','passed':True}]
        self.assertTrue(f.complete(rows))
        for case in ('redirect_post_headers_only','redirect_uses_unchanged','redirect_local_artifacts_unchanged',
                     'successor_resolved','cli_restore','all_cli_restored','raw_epoch_two','all_reopened','processes_stopped'):
            self.assertFalse(f.complete([row for row in rows if row['case']!=case]))
        self.assertFalse(f.complete([]));self.assertFalse(f.complete(rows+[rows[-1]]))
        failed=copy.deepcopy(rows);failed[0]['passed']=False;self.assertFalse(f.complete(failed))

    def response(self, **changes):
        value={'status':307,'headers':[('Location','https://127.0.0.1:8200/v1/sys/storage/raft/snapshot?after=a%2Fb'),
            ('Content-Length','0'),('Connection','close'),('Cache-Control','no-store'),('X-Content-Type-Options','nosniff')],
            'body':b'','elapsed':10.0};value.update(changes)
        return value['status'],value['headers'],value['body'],value['elapsed']

    def test_redirect_requires_actual_empty_body_single_trusted_location_and_budget(self):
        valid=self.response();origin='https://127.0.0.1:8200';route='snapshot?after=a%2Fb'
        self.assertTrue(f.good_redirect(valid,origin,route))
        for bad in (self.response(status=200),self.response(status=503),self.response(body=b'secret'),
                    self.response(elapsed=5000),self.response(elapsed=-1),
                    self.response(headers=valid[1]+[('location',valid[1][0][1])]),
                    self.response(headers=[('Location','https://attacker.invalid/v1/sys/storage/raft/'+route)]+valid[1][1:]),
                    self.response(headers=[('Location',origin+'/v1/sys/storage/raft/snapshot?after=a/b')]+valid[1][1:]),
                    self.response(headers=[pair for pair in valid[1] if pair[0]!='Cache-Control']),
                    self.response(headers=valid[1]+[('Content-Type','application/gzip')])):
            self.assertFalse(f.good_redirect(bad,origin,route))

    def test_anonymous_resolution_only_accepts_original_configured_api_not_forwarded_self(self):
        nodes=[SimpleNamespace(node_id=i,http_port=8200+i) for i in (1,2,3)]
        cluster=SimpleNamespace(nodes=nodes,root=Path('/private'),root_token='credential-must-not-be-used')
        calls=[]
        class Endpoint:
            def __init__(self,*args):pass
            def call(self,*args,**kwargs):
                calls.append((args,kwargs));return 200,{'ha_enabled':True,'leader_address':'https://127.0.0.1:8201'}
        with patch.object(f,'Endpoint',Endpoint):self.assertIs(f.resolve_leader(cluster,nodes[1]),nodes[0])
        self.assertEqual(calls,[(('GET',),{})])
        for body in ({'ha_enabled':True,'leader_address':'https://attacker.invalid'},
                     {'ha_enabled':True,'leader_address':'https://127.0.0.1:8201','is_self':True},
                     {'ha_enabled':True,'leader_address':'https://127.0.0.1:8201','auth':{'client_token':'sentinel'}},
                     {'ha_enabled':False,'leader_address':'https://127.0.0.1:8201'}):
            with patch.object(f,'Endpoint') as endpoint:
                endpoint.return_value.call.return_value=(200,body)
                with self.assertRaises(f.FixtureError):f.resolve_leader(cluster,nodes[1])

    def test_cli_attempt_once_is_preserved_on_failed_or_ambiguous_result(self):
        node=SimpleNamespace(node_id=2,http_port=8202)
        cluster=SimpleNamespace(root=Path('/private'),root_token='synthetic-token')
        for result in (0,2):
            observations={}
            with patch.object(f,'cli',return_value=result) as cli:
                self.assertEqual(f.cli_once('bao',cluster,node,Path('/private'),'restore',Path('/private/input.snap'),observations,'restore'),result==0)
                cli.assert_called_once()
                self.assertEqual(cli.call_args.args[1].address,'https://127.0.0.1:8202')
                self.assertEqual(observations['restore']['exit_code'],result)
        observations={}
        with patch.object(f,'cli',side_effect=OSError('sensitive-sentinel')) as cli:
            with self.assertRaises(OSError):f.cli_once('bao',cluster,node,Path('/private'),'restore',Path('/private/input.snap'),observations,'restore')
            cli.assert_called_once()
        self.assertTrue(observations['restore']['attempted'])
        self.assertNotIn('sensitive-sentinel',repr(observations))

    def test_raw_upload_helper_sends_only_headers_and_reads_actual_wire_body_for_head(self):
        sent=[];reads=[]
        class Socket:
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def sendall(self,data):sent.append(data)
        class Body:
            def read(self,count):reads.append(count);return b''
        class Response:
            status=307
            def __init__(self,*_):self.fp=Body()
            def begin(self):pass
            def getheaders(self):return [('Content-Length','0')]
            def close(self):pass
        raw=Socket();context=SimpleNamespace(wrap_socket=lambda *args,**kwargs:raw)
        node=SimpleNamespace(http_port=8202,context=context)
        with patch.object(f.socket,'create_connection',return_value=raw),patch.object(f.http.client,'HTTPResponse',Response):
            for method,length in [('POST',25_000_000),('HEAD',None)]:
                f.raw_redirect(node,'synthetic-token',method,'snapshot',length)
        self.assertEqual(len(sent),2);self.assertEqual(reads,[4097,4097])
        self.assertTrue(all(data.endswith(b'\r\n\r\n') and len(data)<1024 for data in sent))
        self.assertIn(b'Content-Length: 25000000\r\n',sent[0])
        self.assertIn(b'Host: attacker.invalid:9\r\n',sent[0])
        self.assertNotIn(b'Content-Length:',sent[1])


if __name__=='__main__':unittest.main()
