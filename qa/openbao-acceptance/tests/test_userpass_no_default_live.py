import json
from types import SimpleNamespace
import unittest
import userpass_no_default_live as fixture
class NoDefaultGuards(unittest.TestCase):
    def test_completion_checks_semantics_not_fixed_totals(self):
        rows=[{'case':fixture.PREFIX+n,'passed':True} for n in sorted(fixture.REQUIRED-{'complete'})]+[{'case':fixture.PREFIX+'complete','passed':True}]
        self.assertTrue(fixture.complete(rows));self.assertTrue(fixture.complete(rows[:-1]+[{'case':fixture.PREFIX+'extra','passed':True}]+rows[-1:]))
        for i in range(len(rows)):self.assertFalse(fixture.complete(rows[:i]+rows[i+1:]))
        for bad in [rows+[rows[0]],rows[:-1]+[dict(rows[-1],passed=1)],rows[:-1]+[dict(rows[-1],token='secret')]]:self.assertFalse(fixture.complete(bad))
        self.assertFalse(fixture.complete([{'case':fixture.PREFIX+f'case_{i}','passed':True} for i in range(500)]+rows[-1:]))
    def test_empty_auth_omits_token_policies_not_policies(self):
        t=fixture.Trace(None,[]);auth={'client_token':'synthetic','accessor':'accessor','renewable':True,'policies':[]};t.shape('empty',auth,[])
        for changed in [dict(auth,token_policies=[]),dict(auth,policies=None)]:
            with self.assertRaises(fixture.ScenarioFailure):fixture.Trace(None,[]).shape('empty',changed,[])
        self.assertNotIn('synthetic',json.dumps(t.rows))
    def test_empty_self_authority_is_403_even_when_root_renew_succeeds(self):
        calls=[]
        def request(method,path,body,**kw):
            calls.append((path,kw['token']))
            auth={'accessor':'accessor','policies':[],'renewable':True}
            if not path.endswith('renew-accessor'):auth['client_token']='synthetic'
            return SimpleNamespace(status=403 if path.endswith('renew-self') else 200,body={} if path.endswith('renew-self') else {'auth':auth})
        t=fixture.Trace(SimpleNamespace(request=request),[]);t.renew('empty',{'client_token':'synthetic','accessor':'accessor'},[],self_status=403)
        self.assertEqual([actor for _,actor in calls],['synthetic',None,None]);self.assertNotIn('synthetic',json.dumps(t.rows))
    def test_failed_policy_change_must_not_publish_wrapped_credentials(self):
        for body in [{'auth':{'client_token':'secret'}},{'wrap_info':{'token':'secret'}}]:
            t=fixture.Trace(SimpleNamespace(request=lambda *a,**k:SimpleNamespace(status=500,body=body)),[])
            with self.assertRaises(fixture.ScenarioFailure):t.call('rejected','auth/token/renew-self',{},status=500,wrap_ttl='60s')
            self.assertNotIn('secret',json.dumps(t.rows))
if __name__=='__main__':unittest.main()
