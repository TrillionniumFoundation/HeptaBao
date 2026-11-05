import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

import userpass_params_ha as fixture

class ParamsHaGuards(unittest.TestCase):
    def test_completion_requires_forwarding_transition_and_restart_not_case_count(self):
        rows=[{'case':name,'passed':True} for name in sorted(fixture.REQUIRED-{'complete'})]+[{'case':'complete','passed':True}]
        self.assertTrue(fixture.complete(rows))
        self.assertTrue(fixture.complete(rows[:-1]+[{'case':'additional_real_observation','passed':True}]+rows[-1:]))
        for case in ('spoofed_login_rejected','finite_not_consumed','former_leader_is_standby',
                     'stepdown_bound_denied_rejected','restart_empty_accessor_shape','all_voters_snapshot_agree'):
            self.assertFalse(fixture.complete([row for row in rows if row['case']!=case]))
        self.assertFalse(fixture.complete(rows+[{'case':'extra','passed':True}]))
        self.assertFalse(fixture.complete(rows[:-1]+[rows[0]]+rows[-1:]))
        self.assertFalse(fixture.complete(rows[:-1]+[{'case':'bad','passed':False}]+rows[-1:]))

    def test_root_managed_renewals_use_other_real_source_and_not_target_bearer(self):
        class Client:
            last_family=4
            def __init__(self):self.calls=[]
            def request(self,method,path,body,**kwargs):
                self.calls.append((path,body,kwargs));auth={'policies':[fixture.POLICY],'renewable':True}
                if path!='auth/token/renew-accessor':auth['client_token']='synthetic'
                return SimpleNamespace(status=200,body={'auth':auth})
        client=Client();t=fixture.Trace(client,[],[])
        t.renew('renew',{'client_token':'synthetic','accessor':'synthetic-accessor'},[fixture.POLICY])
        self.assertEqual([args['source'] for _,_,args in client.calls],['127.0.0.2','127.0.0.1','127.0.0.1'])
        self.assertEqual([args['token'] for _,_,args in client.calls],['synthetic',None,None])
        self.assertEqual(client.calls[-1][1]['accessor'],'synthetic-accessor')

    def test_spoof_is_only_negative_control_and_wrong_family_is_not_accepted(self):
        class Client:
            last_family=4
            def __init__(self):self.calls=[]
            def request(self,*args,**kwargs):
                self.calls.append((args,kwargs));return SimpleNamespace(status=403,body={'errors':['denied']})
        client=Client();rows=[];t=fixture.Trace(client,rows,[])
        t.login('denied','user','secret',[],source='127.0.0.1',status=403,spoof=True)
        self.assertEqual(client.calls[-1][1]['source'],'127.0.0.1')
        self.assertIs(client.calls[-1][1]['spoof'],True)
        self.assertEqual(len(client.calls),1)
        client.last_family=6
        with self.assertRaises(fixture.ScenarioFailure):t.call('wrong_family','GET','sys/health',status=403)
        self.assertEqual(rows[-1],{'case':'wrong_family_ipv4','passed':False})
        self.assertNotIn('secret',json.dumps(rows))

    def test_failed_login_must_not_emit_credentials_or_retry(self):
        class Client:
            last_family=4
            def __init__(self):self.count=0
            def request(self,*args,**kwargs):
                self.count+=1;return SimpleNamespace(status=403,body={'wrap_info':{'token':'private'}})
        client=Client();rows=[];t=fixture.Trace(client,rows,[])
        with self.assertRaises(fixture.ScenarioFailure):t.login('bad','user','password',[],status=403)
        self.assertEqual(client.count,1)
        self.assertEqual(rows[-1],{'case':'bad_rejected','passed':False})
        self.assertNotIn('private',json.dumps(rows))

    def test_projection_preserves_authorization_facts_and_absolute_expiry(self):
        original={'id':'synthetic','accessor':'synthetic-accessor','ttl':300,'expire_time':'fixed',
                  'policies':[fixture.POLICY],'bound_cidrs':['127.0.0.2'],'meta':{'username':'named'},'num_uses':0}
        self.assertEqual(fixture.projection(original),fixture.projection(original|{'ttl':299}))
        for changes in ({'expire_time':'other'},{'bound_cidrs':[]},{'policies':['default']},{'num_uses':1}):
            self.assertNotEqual(fixture.projection(original),fixture.projection(original|changes))

    def test_secret_scan_detects_chunk_boundary_without_loading_whole_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'artifact';sample='synthetic-private-token-for-test'
            path.write_bytes(b'x'*65530+sample.encode()+b'y'*65536)
            self.assertFalse(fixture.secret_free([path],[sample]))
            path.write_bytes(b'nonsecret-ciphertext')
            self.assertTrue(fixture.secret_free([path],[sample]))

if __name__=='__main__':unittest.main()
