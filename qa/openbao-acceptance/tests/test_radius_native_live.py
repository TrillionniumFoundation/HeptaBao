"""Native RADIUS evidence must prove PAP/NAS and never reflect secrets."""
import hashlib
import hmac
import json
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from bao_http import Response
from core_isolation import ScenarioFailure
from radius_native_live import Trace,config_matches,complete_scenarios,MILESTONES,pap_response,md5,token_policy_shape

class Provider:
    def count(self):return 0
    def observed(self,start,*,accepted):return False
class Client:
    def __init__(self,status=200):self.status=status
    def request(self,*args,**kwargs):
        return Response(self.status,{'errors':['private-provider-error'],'auth':{'client_token':'private-token','entity_id':'private-entity'},'data':{'secret':'private-shared-secret'}})

def packet(with_ma=True,nas_port=10):
    secret=b'synthetic-key';password=b'synthetic-password';auth=bytes(range(16))
    padded=password+b'\0'*((-len(password))%16);encrypted=bytearray();previous=auth
    for offset in range(0,len(padded),16):
        block=bytes(a^b for a,b in zip(padded[offset:offset+16],md5(secret,previous)));encrypted.extend(block);previous=block
    attrs=bytes([1,7])+b'alice'+bytes([2,2+len(encrypted)])+encrypted+bytes([5,6])+struct.pack('!I',nas_port)
    if with_ma:attrs+=bytes([80,18])+b'\0'*16
    request=bytearray([1,5])+struct.pack('!H',20+len(attrs))+auth+attrs
    if with_ma:request[-16:]=hmac.new(secret,request,hashlib.md5).digest()
    return request

class NativeRadiusTests(unittest.TestCase):
    def test_wrong_status_cannot_reflect_provider_body(self):
        rows=[];trace=Trace(Client(503),Provider(),rows)
        with self.assertRaisesRegex(ScenarioFailure,'^radius_native.failure$'):trace.call('failure','POST','auth/radius/login',{'password':'private'},contact=True)
        self.assertFalse(rows[-1]['passed']);self.assertNotIn('private',json.dumps(rows))
    def test_cached_success_without_matching_pap_and_nas_cannot_pass(self):
        rows=[];trace=Trace(Client(),Provider(),rows)
        with self.assertRaises(ScenarioFailure):trace.call('cached','POST','auth/radius/login',contact=True)
        self.assertFalse(rows[-1]['provider_checked']);self.assertNotIn('private',json.dumps(rows))
    def test_trace_rejects_non_boolean_non_status_sensitive_details(self):
        rows=[];trace=Trace(Client(),Provider(),rows)
        with self.assertRaisesRegex(ValueError,'unsafe_trace_field'):trace.check('test',True,response='private-token')
        self.assertEqual(rows,[])
    def test_config_shape_requires_redaction_and_exact_types(self):
        self.assertTrue(config_matches({'nas_port':0,'port':1812},nas_port=0,port=1812))
        self.assertFalse(config_matches({'nas_port':False},nas_port=0))
        self.assertFalse(config_matches({'port':1812,'secret':'private'},port=1812))
    def test_pap_nas_and_message_authenticator_are_independently_verified(self):
        arguments=dict(secret=b'synthetic-key',username=b'alice',password=b'synthetic-password',allow=True,nas_port=10,nas_identifier=None)
        reply,observed=pap_response(packet(),require_ma=True,**arguments)
        self.assertEqual(reply[0],2);self.assertTrue(observed['nas_valid']);self.assertTrue(observed['credentials_valid'])
        _,wrong_nas=pap_response(packet(nas_port=11),require_ma=True,**arguments);self.assertFalse(wrong_nas['nas_valid'])
        with self.assertRaises(ValueError):pap_response(packet(with_ma=False),require_ma=True,**arguments)
        _,official=pap_response(packet(with_ma=False),require_ma=False,**arguments);self.assertFalse(official['message_authenticator_present']);self.assertTrue(official['credentials_valid'])
        damaged=packet();damaged[-1]^=1
        with self.assertRaises(ValueError):pap_response(damaged,require_ma=True,**arguments)
        self.assertNotIn('synthetic',json.dumps(observed))
    def test_lookup_metadata_cannot_be_missing_or_replaced_with_live_config(self):
        auth={'client_token':'private-token','accessor':'private-accessor',
              'metadata':{'username':'alice','policies':'issued'}}
        class LookupClient:
            def __init__(self,meta):self.meta=meta
            def request(self,*args,**kwargs):return Response(200,{'data':{'meta':self.meta}})
        for meta in (None,{}, {'username':'alice','policies':'current'}, {'username':'changed','policies':'issued'}):
            rows=[];trace=Trace(LookupClient(meta),Provider(),rows)
            with self.assertRaises(ScenarioFailure):trace.lookup_metadata('lookup',auth)
            self.assertFalse(rows[-1]['passed']);self.assertNotIn('private',json.dumps(rows))
        rows=[];trace=Trace(LookupClient(auth['metadata']),Provider(),rows)
        trace.lookup_metadata('lookup',auth)
        self.assertEqual(len(rows),6);self.assertTrue(all(r['passed'] for r in rows))
        self.assertNotIn('private',json.dumps(rows))
    def test_empty_native_policy_shape_must_not_gain_default_or_emit_token_policies(self):
        self.assertTrue(token_policy_shape({'policies':[]},[]))
        for auth in ({'policies':[],'token_policies':[]},{'policies':['default']},{'policies':None},{}):
            self.assertFalse(token_policy_shape(auth,[]))
        self.assertTrue(token_policy_shape({'policies':['default'],'token_policies':['default']},['default']))
        self.assertFalse(token_policy_shape({'policies':['default']},['default']))
    def test_completion_requires_all_milestones_without_duplicates(self):
        names=sorted(MILESTONES-{'complete'})+['complete'];rows=[{'case':'radius_native.'+n,'passed':True} for n in names]
        self.assertTrue(complete_scenarios(rows))
        for i in range(len(rows)):self.assertFalse(complete_scenarios(rows[:i]+rows[i+1:]))
        self.assertFalse(complete_scenarios(rows+[rows[-1]]));self.assertFalse(complete_scenarios([dict(rows[0],passed=False)]+rows[1:]))
        self.assertFalse(complete_scenarios([]))

if __name__=='__main__':unittest.main()
