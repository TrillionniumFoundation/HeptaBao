import json
from types import SimpleNamespace
import unittest
import userpass_alias_live as fixture

class AliasGuards(unittest.TestCase):
    def test_semantic_completion_accepts_extra_success_but_not_missing_failures_or_fake_counts(self):
        rows=[{'case':fixture.PREFIX+n,'passed':True} for n in sorted(fixture.REQUIRED-{'complete'})]
        rows.append({'case':fixture.PREFIX+'complete','passed':True})
        self.assertTrue(fixture.complete(rows))
        self.assertTrue(fixture.complete(rows[:-1]+[{'case':fixture.PREFIX+'extra','passed':True}]+rows[-1:]))
        for i in range(len(rows)):self.assertFalse(fixture.complete(rows[:i]+rows[i+1:]))
        for bad in [rows+[rows[0]],rows[:-1]+[dict(rows[-1],passed=1)],rows[:-1]+[dict(rows[-1],raw='secret')]]:
            self.assertFalse(fixture.complete(bad))
        self.assertFalse(fixture.complete([{'case':fixture.PREFIX+f'case_{i}','passed':True} for i in range(300)]+rows[-1:]))

    def test_body_username_is_sent_unchanged_and_metadata_must_name_the_path(self):
        requests=[]
        raw='synthetic-sensitive-token'
        def request(method,path,fields,**kwargs):
            requests.append((path,fields))
            return SimpleNamespace(status=200,body={'auth':{'client_token':raw,'accessor':'synthetic-accessor','metadata':{'username':'alice'}}})
        trace=fixture.Trace(SimpleNamespace(request=request),[])
        for label,username in fixture.USERNAME_CASES:
            trace.login('path.'+label,'alice',{'password':'credential','username':username})
        self.assertEqual([r[1]['username'] for r in requests],[v for _,v in fixture.USERNAME_CASES])
        self.assertTrue(all(r[0].endswith('/login/alice') for r in requests))
        self.assertNotIn(raw,json.dumps(trace.rows));self.assertNotIn('credential',json.dumps(trace.rows).replace('credentials',''))
        wrong=fixture.Trace(SimpleNamespace(request=lambda *a,**k:SimpleNamespace(status=200,body={
            'auth':{'client_token':raw,'accessor':'synthetic-accessor','metadata':{'username':'bob'}}})),[])
        with self.assertRaises(fixture.ScenarioFailure):wrong.login('wrong','alice',{'password':'credential','username':'bob'})

    def test_error_must_be_400_without_auth_or_wrapping(self):
        for status,body in [(500,{}),(400,{'auth':{'client_token':'secret'}}),(400,{'wrap_info':{'token':'secret'}})]:
            trace=fixture.Trace(SimpleNamespace(request=lambda *a,**k:SimpleNamespace(status=status,body=body)),[])
            with self.assertRaises(fixture.ScenarioFailure):trace.write('bad','alice',{'token_ttl':'bad-duration'},status=400)
            self.assertNotIn('secret',json.dumps(trace.rows))

    def test_observations_reject_sensitive_values(self):
        trace=fixture.Trace(None,[])
        for value in ['password',{},[],None]:
            with self.assertRaises(ValueError):trace.check('unsafe',True,value=value)
        with self.assertRaises(ValueError):trace.check('path/secret',True)
        self.assertEqual(trace.rows,[])

if __name__=='__main__':unittest.main()
