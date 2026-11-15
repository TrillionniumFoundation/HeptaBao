import json
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import userpass_hash_live as fixture

class HashGuards(unittest.TestCase):
    def test_completion_is_semantic_and_allows_more_real_cases_not_arbitrary_counts(self):
        rows=[{'case':fixture.PREFIX+n,'passed':True} for n in sorted(fixture.REQUIRED-{'complete'})]
        rows.append({'case':fixture.PREFIX+'complete','passed':True})
        self.assertTrue(fixture.complete(rows))
        self.assertTrue(fixture.complete(rows[:-1]+[{'case':fixture.PREFIX+'extra','passed':True}]+rows[-1:]))
        for i in range(len(rows)):self.assertFalse(fixture.complete(rows[:i]+rows[i+1:]))
        for bad in [rows+[rows[0]],rows[:-1]+[dict(rows[-1],passed=1)],rows[:-1]+[dict(rows[-1],raw='secret')]]:
            self.assertFalse(fixture.complete(bad))
        self.assertFalse(fixture.complete([{'case':fixture.PREFIX+f'case_{i}','passed':True} for i in range(500)]+rows[-1:]))

    def test_preinstalled_generator_is_explicit_and_generates_actual_accepted_costs(self):
        calls=[]
        def salt(rounds):calls.append(rounds);return bytes([rounds])
        module=SimpleNamespace(__version__='5.0.0',gensalt=salt,hashpw=lambda password,salt:b'$2b$synthetic')
        with patch.dict(sys.modules,{'bcrypt':module}):
            self.assertEqual(fixture.generator_capability(),{'module':'bcrypt','version':'5.0.0','preinstalled':True})
            self.assertEqual(set(fixture.vectors('synthetic')),{5,10,12})
        self.assertEqual(calls,[5,10,12])
        with patch.dict(sys.modules,{'bcrypt':SimpleNamespace(__version__='unexpected secret')}):
            with self.assertRaises(ValueError):fixture.generator_capability()

    def test_go_formats_preserve_hash_body_and_exercise_noncanonical_header_and_salt(self):
        h='$2b$05$'+'.'*53
        variants=dict(fixture.formats(h))
        self.assertEqual(len(variants['two']),59)
        self.assertEqual(variants['two'][6:],h[7:])
        self.assertTrue(variants['plus_cost'].startswith('$2b$+5$'))
        self.assertEqual(variants['version_separator'][3],'!')
        self.assertEqual(variants['cost_separator'][6],'!')
        self.assertEqual(variants['noncanon_salt'][28],'/')
        self.assertEqual(variants['noncanon_salt'][29:],h[29:])
        self.assertTrue(variants['unicode_tail'].startswith(h))

    def test_accepted_bad_hash_can_fail_login_without_leaking_or_publishing_credentials(self):
        requests=[]
        def request(method,path,fields,**kwargs):
            requests.append(fields)
            return SimpleNamespace(status=204 if '/users/' in path else 400,body={})
        trace=fixture.Trace(SimpleNamespace(request=request),[])
        trace.write('bad.write','bad',{'password_hash':'sensitive imported hash'})
        trace.login('bad.login','bad',{'password':'sensitive password'},status=400)
        self.assertEqual(requests[0],{'password_hash':'sensitive imported hash'})
        self.assertNotIn('sensitive',json.dumps(trace.rows))
        for body in [{'auth':{'client_token':'secret'}},{'wrap_info':{'token':'secret'}}]:
            trace=fixture.Trace(SimpleNamespace(request=lambda *a,**k:SimpleNamespace(status=400,body=body)),[])
            with self.assertRaises(fixture.ScenarioFailure):trace.login('bad','user',{'password':'wrong'},status=400)
            self.assertNotIn('secret',json.dumps(trace.rows))

if __name__=='__main__':unittest.main()
