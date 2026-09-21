import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

import userpass_password_live as fixture


class UserpassPasswordGuards(unittest.TestCase):
    def test_completion_needs_all_semantic_milestones_without_case_count(self):
        rows=[{'case':fixture.PREFIX+name,'passed':True} for name in sorted(fixture.REQUIRED-{'complete'})]
        rows.append({'case':fixture.PREFIX+'complete','passed':True})
        self.assertTrue(fixture.complete(rows))
        self.assertTrue(fixture.complete(rows[:-1]+[{'case':fixture.PREFIX+'extra','passed':True}]+rows[-1:]))
        for i in range(len(rows)):
            self.assertFalse(fixture.complete(rows[:i]+rows[i+1:]))
        for damaged in [[],rows+[rows[0]],rows[:-1],rows[:-1]+[dict(rows[-1],passed=1)],
                        rows[:-1]+[dict(rows[-1],raw='credential')]]:
            self.assertFalse(fixture.complete(damaged))
        self.assertFalse(fixture.complete([{'case':fixture.PREFIX+f'case_{i}','passed':True} for i in range(1000)]+rows[-1:]))

    def test_empty_null_and_missing_are_distinct_wire_requests_and_errors_must_not_issue(self):
        requests=[]
        def request(method,path,fields,**kwargs):
            requests.append(fields)
            return SimpleNamespace(status=500,body={'errors':['omitted from receipt']})
        rows=[];trace=fixture.Trace(SimpleNamespace(request=request),rows)
        for label,fields in fixture.EMPTY:
            trace.login('empty.'+label,'user',fields,status=500)
        self.assertEqual(requests,[{}, {'password':''},{'password':None}])
        self.assertNotIn('password',json.dumps(rows).replace(fixture.PREFIX,''))
        for body in [{'auth':{'client_token':'secret'}},{'wrap_info':{'token':'secret'}}]:
            trace=fixture.Trace(SimpleNamespace(request=lambda *a,**k:SimpleNamespace(status=400,body=body)),[])
            with self.assertRaises(fixture.ScenarioFailure):trace.login('bad','user',{'password':'incorrect'},status=400)
            self.assertNotIn('secret',json.dumps(trace.rows))

    def test_success_retains_token_only_in_memory_and_validates_real_lookup(self):
        raw='synthetic-sensitive-token'
        def request(method,path,fields,**kwargs):
            if path.endswith('lookup-self'):
                self.assertEqual(kwargs['token'],raw)
                return SimpleNamespace(status=200,body={'data':{'id':raw,'ttl':120}})
            return SimpleNamespace(status=200,body={'auth':{'client_token':raw,'accessor':'synthetic-accessor','metadata':{'username':'alice'}}})
        trace=fixture.Trace(SimpleNamespace(request=request),[])
        token=trace.login('ok','alice',{'password':'短'})
        self.assertEqual(token,raw);trace.valid_token('old',token)
        self.assertIn(raw,trace.sensitive);self.assertNotIn(raw,json.dumps(trace.rows));self.assertNotIn('短',json.dumps(trace.rows))
        for value in ('raw-string',{},[],None):
            with self.assertRaises(ValueError):trace.check('unsafe',True,observation=value)

    def test_boundary_inputs_measure_utf8_bytes_and_both_73_cases_are_required(self):
        self.assertEqual([len(password.encode()) for _,password in fixture.BOUNDARIES],[71,72,73,71,72,73])
        self.assertLess(len(dict(fixture.BOUNDARIES)['unicode72']),72)
        for kind in ('ascii73','unicode73'):
            for endpoint in ('create','update','reset'):
                self.assertIn(f'bounds.{kind}.{endpoint}.status',fixture.REQUIRED)
            self.assertIn(f'bounds.{kind}.create.absent.status',fixture.REQUIRED)
            self.assertIn(f'bounds.{kind}.update.preserved.credentials',fixture.REQUIRED)
            self.assertIn(f'bounds.{kind}.reset.preserved.credentials',fixture.REQUIRED)

    def test_status_400_and_500_are_not_interchangeable(self):
        trace=fixture.Trace(SimpleNamespace(request=lambda *a,**k:SimpleNamespace(status=400,body={})),[])
        with self.assertRaises(fixture.ScenarioFailure):trace.login('empty','alice',{},status=500)
        self.assertFalse(trace.rows[-1]['passed']);self.assertEqual(trace.rows[-1]['status'],400)

    def test_login_comparison_requires_long_suffix_success_and_prefix_failure_after_restart(self):
        for label,password in fixture.COMPARE:
            self.assertEqual(len(password.encode()),72)
            for length in (73,80,1025):
                self.assertEqual(len((password+'x'*(length-72)).encode()),length)
                self.assertIn(f'compare.{label}.suffix{length}.credentials',fixture.REQUIRED)
            self.assertIn(f'compare.{label}.wrong_prefix.no_credentials',fixture.REQUIRED)
            self.assertIn(f'compare.{label}.restart_suffix1025.credentials',fixture.REQUIRED)
        split=('a'*71+'é').encode()[:72]
        with self.assertRaises(UnicodeDecodeError):split.decode()

    def test_short_literal_is_not_impossible_ciphertext_scan_but_structured_password_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix='guard-',dir=Path(fixture.__file__).parent) as directory:
            root=Path(directory);(root/'data').mkdir();(root/'data'/'sealed').write_bytes(b'ciphertext including x')
            self.assertTrue(fixture.safe_files(root,['x','long-sensitive-credential']))
            (root/'audit.jsonl').write_text(json.dumps({'request':{'password':'x'}})+'\n')
            self.assertFalse(fixture.safe_files(root,['x','long-sensitive-credential']))
            (root/'audit.jsonl').unlink()
            (root/'data'/'sealed').write_bytes(b'z'*65530+b'long-sensitive-credential')
            self.assertFalse(fixture.safe_files(root,['x','long-sensitive-credential']))

if __name__=='__main__':unittest.main()
