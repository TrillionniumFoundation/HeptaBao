#!/usr/bin/env python3
"""Closed-scope and unknown-outcome guards; synthetic values, zero real network."""
import copy
import errno
import hashlib
import json
import time
import types
import unittest
from unittest import mock
import main3_source_fence as f
import main3_api_cycle as a

IDENT=['1','2','501','20','33152','1','4096','100','100']
def capsule():
    entries=[{'profileId':'synthetic-profile-'+str(i),'ownerAgent':'main',
        'ownerAgentDir':str(f.LIVE/'agents/main/agent'),'actualProvider':'openai',
        'credential':{'type':'oauth','provider':'openai','access':'synthetic-access-'+str(i),
                      'refresh':'synthetic-refresh-'+str(i),'expires':1}} for i in range(3)]
    return {'schema':'heptabao.actual-sdk-selected-owner-credentials.private.r1','host':'mac',
        'constraints':{'containsCredentialValues':True,'containsCredentialDigests':False,'selectedOwnerCount':3,
            'containsUnselectedCredentials':False,'productionChanged':False,'providerLivenessVerified':False,
            'oauthRefreshAttempted':False,'productionCutover':False},
        'ownerEntries':entries,'consumerBindings':[
          {'scopeAgent':agent,'scopeAgentDir':str(f.LIVE/'agents'/agent/'agent'),
           'profileId':entry['profileId'],'ownerAgent':'main','ownerAgentDir':str(f.LIVE/'agents/main/agent'),
           'persistedOwnerMatchesEffective':True,'selectedByActualSdkOrder':True,
           'actualSdkOrderRank':i,'configuredProfileId':False} for agent in f.AGENTS for i,entry in enumerate(entries)],
        'sourceGenerations':[{'agent':x} for x in f.AGENTS],
        'configurationIdentity':IDENT,'configurationSha256':'a'*64,
        'registeredMetadataFileBindings':[{} for _ in range(145)]}
def bundle():
    base=str(f.LIVE/'agents/main/agent/openclaw-agent.sqlite')
    return base,{'sourceIdentities':{base:IDENT},'sourceAbsences':[base+'-wal',base+'-shm',base+'-journal']}

class CapsuleGuards(unittest.TestCase):
    def test_valid_synthetic_shape_has_exact_three_and_fifteen(self):f.CapsuleFence.validate(capsule())
    def test_fourth_owner_rejected(self):
        value=capsule();value['ownerEntries'].append(copy.deepcopy(value['ownerEntries'][0]))
        with self.assertRaises(f.Refused):f.CapsuleFence.validate(value)
    def test_duplicate_owner_rejected(self):
        value=capsule();value['ownerEntries'][1]=copy.deepcopy(value['ownerEntries'][0])
        with self.assertRaises(f.Refused):f.CapsuleFence.validate(value)
    def test_nonmain_owner_rejected(self):
        value=capsule();value['ownerEntries'][0]['ownerAgent']='trnm'
        with self.assertRaises(f.Refused):f.CapsuleFence.validate(value)
    def test_unselected_consumer_rejected(self):
        value=capsule();value['consumerBindings'][0]['profileId']='unselected'
        with self.assertRaises(f.Refused):f.CapsuleFence.validate(value)
    def test_missing_consumer_rejected(self):
        value=capsule();value['consumerBindings'].pop()
        with self.assertRaises(f.Refused):f.CapsuleFence.validate(value)
    def test_duplicate_consumer_rejected(self):
        value=capsule();value['consumerBindings'][1]=copy.deepcopy(value['consumerBindings'][0])
        with self.assertRaises(f.Refused):f.CapsuleFence.validate(value)
    def test_wrong_actual_rank_rejected(self):
        value=capsule();value['consumerBindings'][0]['actualSdkOrderRank']=2
        with self.assertRaises(f.Refused):f.CapsuleFence.validate(value)
    def test_refreshed_provider_claim_is_not_admitted(self):
        value=capsule();value['constraints']['providerLivenessVerified']=True
        with self.assertRaises(f.Refused):f.CapsuleFence.validate(value)
    def test_secret_reference_rejected(self):
        value=capsule();value['ownerEntries'][0]['credential']['refreshRef']='secret'
        with self.assertRaises(f.Refused):f.CapsuleFence.validate(value)
    def test_numeric_identity_rejected_to_preserve_precision(self):
        value=capsule();value['configurationIdentity']=[int(x) for x in IDENT]
        with self.assertRaises(f.Refused):f.CapsuleFence.validate(value)
    def test_missing_metadata_rejected(self):
        value=capsule();value['registeredMetadataFileBindings'].pop()
        with self.assertRaises(f.Refused):f.CapsuleFence.validate(value)
    def test_exact_database_and_three_explicit_absences(self):
        base,value=bundle();self.assertEqual(len(f.CapsuleFence.exact_database_bundle(value,base)),4)
    def test_implicit_missing_journal_is_rejected(self):
        base,value=bundle();value['sourceAbsences'].remove(base+'-journal')
        with self.assertRaises(f.Refused):f.CapsuleFence.exact_database_bundle(value,base)
    def test_present_journal_is_rejected(self):
        base,value=bundle();value['sourceAbsences'].remove(base+'-journal');value['sourceIdentities'][base+'-journal']=IDENT
        with self.assertRaises(f.Refused):f.CapsuleFence.exact_database_bundle(value,base)
    def test_foreign_database_path_is_rejected(self):
        base,value=bundle();value['sourceIdentities']['/foreign/source.sqlite']=IDENT
        with self.assertRaises(f.Refused):f.CapsuleFence.exact_database_bundle(value,base)
    def test_absent_wal_existing_shm_is_rejected(self):
        base,value=bundle();value['sourceAbsences'].remove(base+'-shm');value['sourceIdentities'][base+'-shm']=IDENT
        with self.assertRaises(f.Refused):f.CapsuleFence.exact_database_bundle(value,base)
    def test_nonempty_wal_without_shm_is_rejected(self):
        base,value=bundle();value['sourceAbsences'].remove(base+'-wal');value['sourceIdentities'][base+'-wal']=IDENT
        with self.assertRaises(f.Refused):f.CapsuleFence.exact_database_bundle(value,base)
    def test_nonempty_wal_and_shm_allowed_as_separate_identities(self):
        base,value=bundle()
        for suffix in ('-wal','-shm'):value['sourceAbsences'].remove(base+suffix);value['sourceIdentities'][base+suffix]=IDENT
        self.assertEqual(len(f.CapsuleFence.exact_database_bundle(value,base)),4)
    def test_phase_deadline_cannot_be_replenished(self):
        fence=object.__new__(f.CapsuleFence);fence.clock=lambda:100;fence.phase_until=99;fence.until=145
        with self.assertRaises(f.Refused):fence.remaining()

class FakeSocket:
    def __init__(self):self.closed=False;self.sent=[]
    def settimeout(self,value):self.timeout=value
    def getpeercert(self,**kwargs):return b'synthetic-public-certificate'
    def version(self):return 'TLSv1.3'
    def sendall(self,value):self.sent.append(value)
    def close(self):self.closed=True
class Response:
    def __init__(self,body=b'{"ok":true}',status=200,length=None,transfer=None,complete=True):
        self.body=body;self.status=status;self.length=str(len(body)) if length is None else length
        self.transfer=transfer;self.complete=complete;self.closed=False
    def begin(self):pass
    def getheader(self,name):return self.transfer if name=='Transfer-Encoding' else self.length
    def read(self,size):return self.body
    def isclosed(self):return self.complete
    def close(self):self.closed=True

class HttpGuards(unittest.TestCase):
    def setUp(self):
        self.api=object.__new__(a.Api);self.api.plan={'port':45678,'certificateLeafSha256':hashlib.sha256(b'synthetic-public-certificate').hexdigest()}
        self.api.phase='initial';self.api.until=time.monotonic()+120;self.api.rows=[];self.api.checks=[]
        self.api.unknown=False;self.api.root_token=None;self.api.sensitive=[]
        self.api.journal=types.SimpleNamespace(append=mock.Mock())
        self.api.guard=types.SimpleNamespace(check=mock.Mock())
        self.sock=FakeSocket();self.api.context=types.SimpleNamespace(wrap_socket=mock.Mock(return_value=self.sock))
        self.connect=mock.patch.object(a.socket,'create_connection',return_value=self.sock).start()
        self.response=Response();self.response_factory=mock.patch.object(a.http.client,'HTTPResponse',return_value=self.response).start()
        self.addCleanup(mock.patch.stopall)
    def call(self,**kw):return self.api.call('synthetic.case','GET','/v1/sys/health',token='',category='health',**kw)
    def test_complete_verified_response_one_request(self):
        self.assertEqual(self.call(),{'ok':True});self.assertEqual(len(self.sock.sent),1)
        self.assertTrue(self.api.rows[0]['socketsClosed']);self.assertFalse(self.api.rows[0]['outcomeUnknown'])
    def test_private_body_and_bearer_never_in_public_or_journal(self):
        self.api.call('synthetic.private','POST','/v1/sys/unseal',{'key':'synthetic-private-value'},token='synthetic-private-bearer',category='unseal')
        public=json.dumps(self.api.public())+str(self.api.journal.append.call_args_list)
        self.assertNotIn('synthetic-private',public);self.assertNotIn('sha256',public)
    def test_unknown_dispatch_prevents_second_request(self):
        self.sock.sendall=mock.Mock(side_effect=OSError('synthetic-secret-error'))
        with self.assertRaises(f.Refused):self.call()
        self.assertTrue(self.api.rows[0]['outcomeUnknown'])
        with self.assertRaises(f.Refused):self.call()
        self.assertEqual(self.connect.call_count,1)
        self.assertNotIn('synthetic-secret-error',json.dumps(self.api.public()))
    def test_bad_leaf_prevents_send(self):
        self.api.plan['certificateLeafSha256']='f'*64
        with self.assertRaises(f.Refused):self.call()
        self.assertEqual(self.sock.sent,[]);self.assertTrue(self.sock.closed)
    def test_incomplete_body_is_unknown_and_no_retry(self):
        self.response.length='999'
        with self.assertRaises(f.Refused):self.call()
        self.assertTrue(self.api.rows[0]['outcomeUnknown']);self.assertEqual(self.connect.call_count,1)
    def test_chunked_response_is_rejected(self):
        self.response.transfer='chunked'
        with self.assertRaises(f.Refused):self.call()
        self.assertTrue(self.api.rows[0]['outcomeUnknown'])
    def test_redirect_is_observed_once_never_followed(self):
        self.response.status=302
        with self.assertRaises(f.Refused):self.call()
        self.assertEqual(self.connect.call_count,1);self.assertTrue(self.api.rows[0]['responseComplete'])
    def test_bad_json_complete_known_http_stops_business(self):
        self.response.body=b'BAD';self.response.length='3'
        with self.assertRaises(f.Refused):self.call()
        self.assertFalse(self.api.rows[0]['outcomeUnknown']);self.assertTrue(self.api.unknown)
    def test_health_only_refused_tcp_retry_one_tls_and_get(self):
        self.connect.side_effect=[ConnectionRefusedError(errno.ECONNREFUSED,'refused'),ConnectionRefusedError(errno.ECONNREFUSED,'refused'),self.sock]
        with mock.patch.object(a.time,'sleep'):self.call(readiness=True)
        self.assertEqual(self.api.rows[0]['connectionRefusals'],2);self.assertEqual(len(self.sock.sent),1)
        self.api.context.wrap_socket.assert_called_once()
    def test_api_write_never_retries_connection_refusal(self):
        self.connect.side_effect=ConnectionRefusedError(errno.ECONNREFUSED,'refused')
        with self.assertRaises(f.Refused):self.api.call('synthetic.write','POST','/v1/sys/unseal',{'key':'synthetic'},token='',category='unseal')
        self.assertEqual(self.connect.call_count,1)
    def test_non_refusal_tcp_failure_never_retries(self):
        self.connect.side_effect=PermissionError(errno.EACCES,'denied')
        with self.assertRaises(f.Refused):self.call(readiness=True)
        self.assertEqual(self.connect.call_count,1)
    def test_readiness_retry_cannot_be_applied_to_private_mutation(self):
        with self.assertRaises(f.Refused):self.api.call('synthetic.write','POST','/v1/sys/unseal',{'key':'synthetic'},token='',category='unseal',readiness=True)
        self.connect.assert_not_called()
    def test_expired_phase_does_not_dispatch(self):
        self.api.until=time.monotonic()-1
        with self.assertRaises(f.Refused):self.call()
        self.connect.assert_not_called();self.api.journal.append.assert_not_called()
    def test_empty_204_known_complete(self):
        self.response.body=b'';self.response.length='0';self.response.status=204
        self.assertEqual(self.api.call('synthetic.empty','POST','/v1/sys/auth/approle',{},expected=204,category='mount'),{})
    def test_header_injection_prevented(self):
        with self.assertRaises(f.Refused):self.api.call('synthetic.token','GET','/v1/sys/health',token='bad\r\nheader',category='health')
        self.connect.assert_not_called()
    def test_public_route_never_contains_private_key(self):
        self.call();row=self.api.public()['requests'][0]
        self.assertNotIn('path',row);self.assertNotIn('route',row);self.assertEqual(row['routeCategory'],'health')
    def test_fixed_request_bound_prevents_dispatch(self):
        self.api.rows=[{} for _ in range(a.MAX_HTTP)]
        with self.assertRaises(f.Refused):self.call()
        self.connect.assert_not_called()

if __name__=='__main__':unittest.main(verbosity=2)
