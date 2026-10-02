import tempfile
from pathlib import Path
import unittest
import jwt_remote_batch_live as f


class RemoteBatchGuards(unittest.TestCase):
    def test_lifecycle_completeness_rejects_missing_failed_duplicate_and_leaky_rows(self):
        rows = [{'case': name, 'passed': True} for name in sorted(f.REQUIRED-{'complete'})]
        rows.append({'case': 'complete', 'passed': True})
        self.assertTrue(f.complete(rows))
        for name in f.REQUIRED:
            self.assertFalse(f.complete([row for row in rows if row['case'] != name]), name)
        self.assertFalse(f.complete(rows+rows[-1:]))
        self.assertFalse(f.complete(rows[:-1]+[{'case':'complete','passed':1}]))
        self.assertFalse(f.complete(rows[:-1]+[{'case':'complete','passed':True,'body':'secret'}]))
        self.assertFalse(f.complete(rows[:-1]))
        self.assertTrue(f.complete(rows[:-1]+[{'case':'another_real_check','passed':True}]+rows[-1:]))

    def test_batch_shape_requires_backend_role_and_no_service_accessor(self):
        body = {'auth': {'client_token':'synthetic-batch', 'token_type':'batch', 'accessor':'',
                        'renewable':False, 'lease_duration':600, 'entity_id':'entity',
                        'metadata':{'role':'test'}}}
        self.assertTrue(f.batch_shape(body))
        for key, value in [('accessor','service-accessor'), ('renewable',True),
                           ('token_type','service'), ('metadata',{}), ('lease_duration',True),
                           ('entity_id',''), ('client_token','')]:
            changed = {'auth':dict(body['auth'], **{key:value})}
            self.assertFalse(f.batch_shape(changed), key)

    def test_expected_provider_failure_is_not_any_error_or_secret_bearing_success(self):
        self.assertTrue(f.denied(400, {'errors':['denied']}))
        self.assertTrue(f.denied(503, {'errors':['unavailable']}, 503))
        self.assertFalse(f.denied(503, {'errors':['unavailable']}))
        self.assertFalse(f.denied(400, {'errors':[], 'auth':{}}))
        self.assertFalse(f.denied(400, {'errors':['denied'], 'auth':{'client_token':'secret'}}))
        self.assertFalse(f.denied(400, {'errors':['denied'], 'wrap_info':{'token':'secret'}}))

    def test_bearer_verifier_uses_actual_target_token_and_checks_value_and_lookup(self):
        calls = []
        class Fake:
            corrupt = False
            def call(self, method, path, *, token):
                calls.append((method,path,token))
                if path == 'batch-values/value':
                    return 200, {'data':{'v':'wrong' if self.corrupt else 'expected'}}
                return 200, {'data':{'id':token,'type':'batch','accessor':'','renewable':False,'ttl':42}}
        def check(name, passed):
            if not passed: raise f.Failure(name)
        fake = Fake()
        f.verify_bearer(fake, 'synthetic-target', {'v':'expected'}, 'immediate', check)
        self.assertEqual(calls, [('GET','batch-values/value','synthetic-target'),
                                ('GET','auth/token/lookup-self','synthetic-target')])
        fake.corrupt = True
        with self.assertRaises(f.Failure):
            f.verify_bearer(fake, 'synthetic-target', {'v':'expected'}, 'immediate', check)

    def test_binary_secret_scan_detects_non_utf8_and_chunk_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'artifact'
            sample = b'\xff\x00private-signing-key\x80'
            path.write_bytes(b'a'*(1024*1024-3)+sample+b'b')
            self.assertTrue(f.contains_any(path, [sample]))
            self.assertFalse(f.contains_any(path, [b'absent-secret']))


if __name__ == '__main__': unittest.main()
