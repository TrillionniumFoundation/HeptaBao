import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import approle_secretid_overrides_probe as f


class SecretIdOverrideProbeGuards(unittest.TestCase):
    def test_actual_pinned_official_receipt_is_complete_and_inputs_stable(self):
        path = Path(__file__).resolve().parents[1]/'evidence/approle-secretid-overrides-official-c54e9b0.json'
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), 'f3be3085aec18b4bc81b749e35b510de72b5645a6217170058d307d03b491a2e')
        receipt = json.loads(path.read_text())
        self.assertEqual(receipt['status'], 'observed')
        self.assertIsNone(receipt['failure'])
        self.assertTrue(f.complete(SimpleNamespace(rows=receipt['cases'], finished=receipt['completed_scenarios'])))
        for field in ('inputs_unchanged', 'secrets_absent', 'processes_stopped', 'oracle_only'):
            self.assertIs(receipt[field], True)
        self.assertEqual(receipt['oracle_binary_sha256'], '1c3f62018046ec72be8720b576a55105b64b4cbd634d98483a93c642e69dc153')
        self.assertEqual(receipt['frozen_helpers_source'], receipt['frozen_helpers_source_after'])
        self.assertIs(receipt['frozen_helpers_source']['source_dirty'], False)

    def test_safe_projection_distinguishes_null_empty_and_both_fields_without_secret(self):
        class Client:
            last_family = 4
            def request(self, *args, **kwargs):
                return SimpleNamespace(status=200, body={'data': {'cidr_list': None, 'token_bound_cidrs': [],
                    'secret_id': 'synthetic-private-sid-value', 'secret_id_accessor': 'synthetic-private-accessor',
                    'secret_id_num_uses': 2, 'creation_time': 'private-time'}})
        t = f.Trace(Client()); t.call('synthetic.lookup', 'POST', '/synthetic')
        row = t.rows[-1]
        self.assertEqual(row['sid_login_cidr_shape'], 'null')
        self.assertEqual(row['cidr_shape'], 'list'); self.assertEqual(row['cidrs'], [])
        self.assertEqual(row['secret_id_num_uses'], 2)
        self.assertNotIn('synthetic-private', json.dumps(t.rows)); self.assertNotIn('private-time', json.dumps(t.rows))
        self.assertIn('synthetic-private-sid-value', t.sensitive)

    def test_rejected_custom_issue_looks_up_known_input_but_random_does_not_invent_id(self):
        class T:
            def __init__(self): self.calls, self.sensitive = [], []
            def call(self, name, method, path, body):
                self.calls.append((name, method, path, body)); return 500, {'errors': ['synthetic failure']}
        for mode in f.MODES:
            t = T(); base = {'role': 'synthetic-role', 'role_id': 'private-role-id'}
            self.assertIsNone(f.issue(t, 'synthetic.issue', base, mode, {'cidr_list': ['127.0.0.1/33']}))
            self.assertEqual(len(t.calls), 2 if mode == 'custom' else 1)
            if mode == 'custom':
                supplied = t.calls[0][3]['secret_id']; self.assertIn(supplied, t.sensitive)
                self.assertEqual(t.calls[1][3], {'secret_id': supplied})
                self.assertTrue(t.calls[1][2].endswith('/secret-id/lookup'))

    def test_actual_api_matrix_keeps_omitted_null_and_empty_inputs_distinct(self):
        class T:
            def __init__(self): self.calls, self.sensitive, self.finished = [], [], []
            def require(self, name, method, path, body=None, **kwargs): return {'data': {'role_id': 'private-role-id'}}
            def call(self, name, method, path, body=None, **kwargs):
                self.calls.append((name, path, body)); return 400, {'errors': ['synthetic rejection']}
            def finish(self, name): self.finished.append(name)
        t = T(); f.api(t)
        requests = {name: body for name, _, body in t.calls}
        for mode in f.MODES:
            for field in f.FIELDS:
                prefix = f'api.{mode}.{field}.'
                self.assertNotIn(field, requests[prefix+'omitted.issue'])
                self.assertIsNone(requests[prefix+'null.issue'][field])
                self.assertEqual(requests[prefix+'empty_list.issue'][field], [])
                self.assertEqual(requests[prefix+'empty_string.issue'][field], '')
                self.assertEqual(requests[prefix+'host_bits.issue'][field], ['127.0.0.99/24'])
        self.assertEqual(set(t.finished), {s for s in f.SCENARIOS if s.startswith('api.')})

    def test_actual_consumption_schedule_uses_one_denied_call_not_automatic_retry(self):
        t = SimpleNamespace(finished=[], observe=lambda *a, **k: None)
        t.finish = t.finished.append
        with patch.object(f, 'role', return_value={'role': 'synthetic', 'role_id': 'private-role'}), \
             patch.object(f, 'issue', return_value={'secret_id': 'private-sid'}), \
             patch.object(f, 'lookups', return_value=(200, {'secret_id_num_uses': 0})), \
             patch.object(f, 'login', return_value={}) as login, patch.object(f, 'bearer'):
            f.consumption(t)
        denied = [call for call in login.call_args_list if call.args[1].endswith('.denied')]
        expected = {s for s in f.SCENARIOS if s.startswith('consume.')}
        self.assertEqual(set(t.finished), expected)
        self.assertEqual({call.args[1].removesuffix('.denied') for call in denied}, expected)
        self.assertEqual(len(denied), len(expected))
        self.assertTrue(all(call.args[3:] == ('127.0.0.2', True) for call in denied))

    def test_lookup_empty_pair_is_never_reported_as_equal_present_data(self):
        class T:
            def __init__(self): self.facts = []
            def call(self, *args): return 204, {}
            def observe(self, name, **facts): self.facts.append(facts)
        t = T(); f.lookups(t, 'absent', {'role': 'r', 'secret_id': 's', 'secret_id_accessor': 'a'})
        self.assertEqual(t.facts, [{'both_present': False, 'same_data': False}])

    def test_completion_requires_named_requests_and_every_scenario_not_a_count(self):
        t = SimpleNamespace(rows=[{'case': name} for name in sorted(f.REQUIRED)], finished=sorted(f.SCENARIOS))
        self.assertTrue(f.complete(t))
        for name in f.REQUIRED:
            self.assertFalse(f.complete(SimpleNamespace(rows=[r for r in t.rows if r['case'] != name], finished=t.finished)))
        self.assertFalse(f.complete(SimpleNamespace(rows=t.rows, finished=t.finished[:-1])))
        self.assertFalse(f.complete(SimpleNamespace(rows=t.rows+t.rows[:1], finished=t.finished)))
        t.rows.append({'case': 'extra.observation'}); self.assertTrue(f.complete(t))
        trace = f.Trace(None)
        with self.assertRaises(ValueError): trace.observe('bad', value='private-token')
        trace.observe('safe', true_value=True)
        with self.assertRaises(ValueError): trace.observe('safe', true_value=False)


if __name__ == '__main__': unittest.main()
