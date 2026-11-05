import json
from types import SimpleNamespace
import unittest
import userpass_names_live as fixture

class UserpassNameGuards(unittest.TestCase):
    def test_completion_requires_business_milestones_without_fixed_count(self):
        rows=[{'case':fixture.PREFIX+n,'passed':True} for n in sorted(fixture.REQUIRED-{'complete'})]
        rows.append({'case':fixture.PREFIX+'complete','passed':True})
        self.assertTrue(fixture.complete(rows))
        self.assertTrue(fixture.complete(rows[:-1]+[{'case':fixture.PREFIX+'new_case','passed':True}]+rows[-1:]))
        for index in range(len(rows)):self.assertFalse(fixture.complete(rows[:index]+rows[index+1:]))
        for bad in [rows+[rows[0]],rows[:-1]+[dict(rows[-1],passed=1)],rows[:-1]+[dict(rows[-1],raw='secret')]]:
            self.assertFalse(fixture.complete(bad))
        self.assertFalse(fixture.complete([{'case':fixture.PREFIX+f'case_{i}','passed':True} for i in range(500)]+rows[-1:]))

    def test_metadata_is_canonical_but_http_path_is_not_rewritten(self):
        requests=[]
        def request(method,path,fields,**kw):
            requests.append(path)
            return SimpleNamespace(status=200,body={'auth':{'client_token':'synthetic-sensitive-token',
                'accessor':'synthetic-accessor','metadata':{'username':'mixed'},'entity_id':'synthetic-entity'}})
        trace=fixture.Trace(SimpleNamespace(request=request),[])
        trace.login('upper','MIXED','sensitive-password')
        self.assertEqual(requests,['/v1/auth/native-names/login/MIXED'])
        self.assertNotIn('synthetic-sensitive-token',json.dumps(trace.rows))
        self.assertNotIn('sensitive-password',json.dumps(trace.rows))

    def test_raw_username_metadata_is_a_failure(self):
        trace=fixture.Trace(SimpleNamespace(request=lambda *a,**kw:SimpleNamespace(status=200,body={'auth':{
            'client_token':'synthetic-sensitive-token','accessor':'synthetic-accessor',
            'metadata':{'username':'MIXED'},'entity_id':'synthetic-entity'}})),[])
        with self.assertRaises(fixture.ScenarioFailure):trace.login('upper','MIXED','password')

    def test_error_credentials_cannot_escape(self):
        for body in [{'auth':{'client_token':'secret'}},{'wrap_info':{'token':'secret'}}]:
            trace=fixture.Trace(SimpleNamespace(request=lambda *a,**kw:SimpleNamespace(status=400,body=body)),[])
            with self.assertRaises(fixture.ScenarioFailure):trace.login('bad','mixed','password',status=400)
            self.assertNotIn('secret',json.dumps(trace.rows))

    def test_divergences_have_separate_required_observations(self):
        rows=[{'case':fixture.PREFIX+n,'passed':True} for n in sorted(fixture.DEVIATIONS)]
        self.assertTrue(fixture.complete_deviations(rows))
        self.assertFalse(fixture.complete(rows))
        for i in range(len(rows)):self.assertFalse(fixture.complete_deviations(rows[:i]+rows[i+1:]))
        self.assertFalse(fixture.complete_deviations(rows+[rows[0]]))
        self.assertFalse(fixture.complete_deviations(rows[:-1]+[dict(rows[-1],passed=False)]))

    def test_observation_values_never_include_credentials(self):
        trace=fixture.Trace(None,[])
        for value in ['secret',{},[],None]:
            with self.assertRaises(ValueError):trace.check('invalid',True,value=value)
        self.assertEqual(trace.rows,[])

if __name__=='__main__':unittest.main()
