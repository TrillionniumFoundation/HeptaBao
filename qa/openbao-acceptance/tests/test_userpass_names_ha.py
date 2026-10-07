import json
from types import SimpleNamespace
import unittest
import userpass_names_ha as fixture

class NamesHaGuards(unittest.TestCase):
    def test_account_and_alias_reads_keep_distinct_observation_ids(self):
        def request(method,path,body,**kwargs):
            data={'keys':['mixed']} if method=='LIST' else {'aliases':[{'name':'mixed'}]}
            return SimpleNamespace(status=200,body={'data':data})
        rows=[];trace=fixture.Trace(SimpleNamespace(request=request,last_family=4),rows,[])
        trace.one_account('initial');trace.alias('initial','synthetic-entity')
        names=[row['case'] for row in rows]
        self.assertEqual(len(names),len(set(names)))
        self.assertIn('initial_single_account',names)
        self.assertIn('initial_canonical_alias',names)

    def test_completion_uses_real_transition_and_semantic_milestones(self):
        rows=[{'case':name,'passed':True} for name in sorted(fixture.REQUIRED-{'complete'})]+[{'case':'complete','passed':True}]
        self.assertTrue(fixture.complete(rows))
        self.assertTrue(fixture.complete(rows[:-1]+[{'case':'extra_success','passed':True}]+rows[-1:]))
        for i in range(len(rows)):self.assertFalse(fixture.complete(rows[:i]+rows[i+1:]))
        self.assertFalse(fixture.complete([{'case':'case_'+str(i),'passed':True} for i in range(300)]+rows[-1:]))
        self.assertFalse(fixture.complete(rows+[rows[0]]))
    def test_forwarded_login_preserves_raw_path_and_requires_canonical_identity(self):
        requests=[]
        def request(method,path,body,**kwargs):
            requests.append((path,kwargs))
            return SimpleNamespace(status=200,body={'auth':{'client_token':'synthetic-sensitive-token','accessor':'synthetic-accessor',
                'entity_id':'synthetic-entity','metadata':{'username':'mixed'}}})
        client=SimpleNamespace(request=request,last_family=4);rows=[]
        trace=fixture.Trace(client,rows,[]);trace.login('login','MIXED','password')
        self.assertEqual(requests[0][0],'auth/ha-userpass-names/login/MIXED')
        self.assertEqual(requests[0][1],{'token':'','source':'127.0.0.1'})
        self.assertNotIn('synthetic-sensitive-token',json.dumps(rows))
    def test_denied_acl_cannot_return_auth_or_wrapper(self):
        for body in [{'auth':{'client_token':'secret'}},{'wrap_info':{'token':'secret'}}]:
            trace=fixture.Trace(SimpleNamespace(request=lambda *a,**kw:SimpleNamespace(status=403,body=body),last_family=4),[],[])
            with self.assertRaises(fixture.ScenarioFailure):trace.call('denied','POST','auth/path',{},status=403)
            self.assertNotIn('secret',json.dumps(trace.rows))
    def test_snapshot_projection_omits_only_countdown_not_absolute_expiry(self):
        data={'id':'synthetic-token','expire_time':'fixed','meta':{'username':'mixed'},'ttl':120}
        view=fixture.projection(data);self.assertNotIn('ttl',view)
        self.assertEqual(view['expire_time'],'fixed');self.assertEqual(view['meta'],{'username':'mixed'})
    def test_alias_read_must_be_single_and_canonical(self):
        for aliases in [[],[{'name':'MIXED'}],[{'name':'mixed'},{'name':'MIXED'}]]:
            trace=fixture.Trace(SimpleNamespace(request=lambda *a,**kw:SimpleNamespace(status=200,body={'data':{'aliases':aliases}}),last_family=4),[],[])
            with self.assertRaises(fixture.ScenarioFailure):trace.alias('identity','synthetic-entity')

if __name__=='__main__':unittest.main()
