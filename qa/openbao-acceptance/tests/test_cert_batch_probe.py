import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
import cert_batch_probe as f


class CertBatchProbeTests(unittest.TestCase):
    def test_matrix_has_every_distinct_mount_role_pair_and_named_phases(self):
        matrix = {'matrix.'+mode.replace('-', '_')+'.'+kind for mode in f.MODES for kind in f.KINDS}
        self.assertEqual({name for name in f.SCENARIOS if name.startswith('matrix.')}, matrix)
        self.assertTrue({'identity', 'wrapping', 'lifecycle', 'restart', 'partial'} <= f.SCENARIOS)

    def test_missing_credential_cannot_fall_back_to_admin(self):
        for body in ({}, {'auth': {}}, {'auth': {'client_token': ''}}):
            trace = Mock()
            trace.call.return_value = (200, body)
            with self.assertRaises(f.ScenarioFailure):
                f.observe_login(trace, 'case', 'role')
            self.assertEqual(trace.call.call_count, 1)

    def test_rejected_login_records_no_bearer_and_skips_lookup_and_kv(self):
        trace = Mock()
        trace.call.return_value = (403, {'errors': ['synthetic']})
        f.observe_login(trace, 'case', 'role')
        trace.observe.assert_called_once_with('case.no_issued_bearer', credential_issued=False)
        self.assertEqual(trace.call.call_count, 1)

    def test_safe_projection_retains_shape_but_never_raw_credentials_or_errors(self):
        secret = 'synthetic-secret-do-not-print-abcdef'
        client = Mock()
        client.request.return_value = SimpleNamespace(status=200, body={
            'auth': {'client_token': secret, 'accessor': '', 'entity_id': secret+'-entity',
                     'token_type': 'batch', 'renewable': False, 'orphan': True,
                     'metadata': {'cert_name': 'held', 'common_name': 'client.example.test',
                                  'serial_number': secret+'-serial', 'subject_key_id': secret+'-skid',
                                  'authority_key_id': secret+'-akid'}},
            'errors': [secret+'-error']})
        trace = f.Trace(client)
        trace.call('safe.login', 'POST', 'auth/cert/login', {}, token='', role='held')
        row = trace.rows[0]
        self.assertNotIn(secret, json.dumps(row))
        self.assertIn(secret, trace.sensitive)
        self.assertTrue(row['certificate_metadata_keys_exact'] and row['cert_name_matches'])
        self.assertEqual(row['token_type'], 'batch')
        self.assertFalse(row['accessor'] or row['renewable'])
        self.assertTrue(row['errors'])

    def test_names_must_be_unique_and_every_phase_must_finish(self):
        trace = f.Trace(Mock())
        for name in sorted(f.SCENARIOS):
            trace.observe(name+'.observed', status=400)
            trace.finish(name)
        self.assertTrue(f.complete(trace))
        with self.assertRaises(ValueError):
            trace.observe(trace.rows[0]['case'], status=200)
        with self.assertRaises(ValueError):
            trace.finish(trace.finished[0])
        trace.finished.pop()
        self.assertFalse(f.complete(trace))


if __name__ == '__main__': unittest.main()
