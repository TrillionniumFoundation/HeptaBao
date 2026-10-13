from pathlib import Path
import socket
import sys
import time
import unittest
from unittest.mock import patch
from unittest.mock import Mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from heptabao.consistency import Metadata
from heptabao.local_api import LeaseCache
from heptabao.proxy import RequestHeaderRequired, read_request
from heptabao.transport import Response
from heptabao.transport import BaoError
from heptabao.deadline_transport import DeadlineClient
from heptabao.proxy import forward


class LocalAPIRegressionTests(unittest.TestCase):
    def test_keyword_client_parameters_and_get_timeout_never_infer_safe_retry(self):
        with patch('heptabao.deadline_transport.ssl.create_default_context') as context:
            client=DeadlineClient(address='https://localhost:8200',ca_file='/synthetic/ca',
                                  token='synthetic',deadline=time.monotonic()-1)
            context.assert_called_with(cafile='/synthetic/ca')
            with self.assertRaisesRegex(BaoError,'transport_outcome_unknown'):
                client.request('GET','/v1/database/creds/reader')

    def test_cache_never_extra_looks_up_finite_or_legacy_token_snapshot(self):
        policy={'routes':[{'method':'GET','path':'database/creds/reader','effectful':True}],
                'timeout':1,'cache_enabled':True}
        config=Mock();config.ca_file='/synthetic/ca';config.state_dir='/synthetic/state'
        config.address='https://localhost:8200';config.namespace=''
        for marker in (None,1,True):
            with self.subTest(marker=marker),patch('heptabao.proxy.read_trusted_ca',return_value=b'synthetic-ca'),\
                    patch('heptabao.proxy.StateDirectory'),patch('heptabao.proxy.token_snapshot',
                    return_value=('synthetic-token',{'expires_at':time.time()+10,'token_num_uses':marker})):
                factory=Mock();factory.return_value.request.return_value=Response(200,{
                    'renewable':True,'lease_id':'synthetic','lease_duration':2,'data':{}})
                cache=LeaseCache(policy)
                forward(policy,config,'GET','database/creds/reader',None,client_factory=factory,cache=cache)
                factory.return_value.request.assert_called_once_with('GET','/v1/database/creds/reader',None)
                self.assertEqual(cache.records,{})
    def test_header_guard_precedes_product_header_policy_and_control_json(self):
        first,second=socket.socketpair()
        try:
            first.sendall(b'POST /proxy/v1/cache-clear HTTP/1.1\r\nHost: localhost\r\n'
                b'Authorization: untrusted\r\nContent-Length: 8\r\n\r\nnot-json')
            with self.assertRaises(RequestHeaderRequired):
                read_request(second,time.monotonic()+1,with_controls=True,require_request_header=True)
        finally:first.close();second.close()

    def test_cache_deadline_is_request_start_and_never_extends_with_token_renewal(self):
        cache=LeaseCache({'cache_enabled':True})
        key=cache.key('owned-token','','GET','database/creds/reader',None,Metadata())
        response=Response(200,{'renewable':True,'lease_id':'owned-lease','lease_duration':10,'data':{'value':'synthetic'}})
        with patch('heptabao.local_api.time.time',return_value=100),patch('heptabao.local_api.time.monotonic',return_value=20):
            cache.put(key,response,{'expires_at':105},'owned-accessor',100,20)
        with patch('heptabao.local_api.time.time',return_value=104),patch('heptabao.local_api.time.monotonic',return_value=24):
            self.assertEqual(cache.get(key).body['lease_duration'],1)
        with patch('heptabao.local_api.time.time',return_value=105),patch('heptabao.local_api.time.monotonic',return_value=25):
            self.assertIsNone(cache.get(key))

    def test_cache_key_separates_token_namespace_body_and_consistency(self):
        base=LeaseCache.key('one','team','POST','database/creds/reader',{'role':'one'},Metadata())
        alternatives=[LeaseCache.key('two','team','POST','database/creds/reader',{'role':'one'},Metadata()),
            LeaseCache.key('one','other','POST','database/creds/reader',{'role':'one'},Metadata()),
            LeaseCache.key('one','team','POST','database/creds/reader',{'role':'two'},Metadata()),
            LeaseCache.key('one','team','POST','database/creds/reader',{'role':'one'},Metadata(None,('forward-active-node',)))]
        self.assertEqual(len(set([base,*alternatives])),5)


if __name__=='__main__':unittest.main()
