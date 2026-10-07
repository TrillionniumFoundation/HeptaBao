import json
from types import SimpleNamespace
import unittest
import userpass_cidrs_live as fixture

class UserpassCidrGuards(unittest.TestCase):
    def test_completion_requires_real_source_lifecycle_milestones_not_case_count(self):
        rows=[{'case':fixture.PREFIX+n,'passed':True} for n in sorted(fixture.REQUIRED-{'complete'})]+[{'case':fixture.PREFIX+'complete','passed':True}]
        self.assertTrue(fixture.complete(rows))
        self.assertTrue(fixture.complete(rows[:-1]+[{'case':fixture.PREFIX+'extra','passed':True}]+rows[-1:]))
        for i in range(len(rows)):self.assertFalse(fixture.complete(rows[:i]+rows[i+1:]))
        for bad in [rows+[rows[0]],rows[:-1]+[dict(rows[-1],passed=1)],rows[:-1]+[dict(rows[-1],raw_token='sensitive')],rows[:-1]+[dict(rows[-1],source_family=5)]]:
            self.assertFalse(fixture.complete(bad))
        self.assertFalse(fixture.complete([{'case':fixture.PREFIX+f'case_{i}','passed':True} for i in range(1000)]+rows[-1:]))

    def test_denial_proves_no_auth_or_wrapper_and_receipt_excludes_body(self):
        client=SimpleNamespace(last_family=4,request=lambda *a,**k:SimpleNamespace(status=403,body={}))
        trace=fixture.Trace(client,[])
        trace.login('denied',source='127.0.0.2',status=403)
        self.assertNotIn(trace.password,json.dumps(trace.rows))
        for body in [{'auth':{'client_token':'never-log-this'}},{'wrap_info':{'token':'never-log-this'}}]:
            client.request=lambda *a,**k:SimpleNamespace(status=403,body=body)
            trace=fixture.Trace(client,[])
            with self.assertRaises(fixture.ScenarioFailure):trace.login('denied',status=403)
            self.assertNotIn('never-log-this',json.dumps(trace.rows))

    def test_three_renewal_routes_check_actor_source_not_target_source(self):
        calls=[]
        def request(method,path,body=None,**kw):
            calls.append((path,body,kw))
            auth={'accessor':'safe-accessor','policies':['default'],'token_policies':['default'],'lease_duration':120,'renewable':True,'token_type':'service'}
            if not path.endswith('renew-accessor'):auth['client_token']='safe-token'
            return SimpleNamespace(status=200,body={'auth':auth})
        trace=fixture.Trace(SimpleNamespace(last_family=4,request=request),[])
        trace.renew_all('renew',{'client_token':'safe-token','accessor':'safe-accessor'})
        self.assertEqual([c[2]['source'] for c in calls],['127.0.0.1','127.0.0.2','127.0.0.2'])
        self.assertEqual([c[2]['token'] for c in calls],['safe-token',None,None])
        self.assertNotIn('safe-token',json.dumps(trace.rows))

    def test_alias_readback_checks_deprecated_field_presence_not_empty_equivalence(self):
        client=SimpleNamespace(last_family=4,request=lambda *a,**k:SimpleNamespace(status=200,body={'data':{'token_bound_cidrs':[]}}))
        fixture.Trace(client,[]).read_bounds('clear',[],None)
        client.request=lambda *a,**k:SimpleNamespace(status=200,body={'data':{'token_bound_cidrs':[],'bound_cidrs':[]}})
        with self.assertRaises(fixture.ScenarioFailure):fixture.Trace(client,[]).read_bounds('clear',[],None)

if __name__=='__main__':unittest.main()
