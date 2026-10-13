from pathlib import Path
import socket
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from heptabao.consistency import Metadata
from heptabao.local_api import LeaseCache
from heptabao.proxy import RequestHeaderRequired, read_request
from heptabao.transport import Response


class LocalAPIRegressionTests(unittest.TestCase):
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
