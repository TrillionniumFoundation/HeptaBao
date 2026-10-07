import json
from types import SimpleNamespace
import unittest

import approle_secret_cidrs_probe as f


class OfflineTrace:
    """Exercises only the request graph, never supplies behavior evidence."""
    def __init__(self, issued=True):
        self.calls, self.finished, self.rows = [], [], []
        self.issued, self.serial = issued, 0
    def call(self, name, method, path, body=None, **kwargs):
        self.calls.append((name, method, path, body, kwargs)); self.serial += 1
        if path.endswith('/role-id'): return 200, {'data': {'role_id': 'synthetic-role'}}
        if path.endswith('/secret-id'): return 200, {'data': {'secret_id': 'synthetic-sid'}}
        if path.endswith('/login'):
            return (200, {'auth': {'client_token': 'synthetic-token-'+str(self.serial)}}) if self.issued else (400, {'errors':['denied']})
        return 200, {'data': {}}
    def require(self, *args, status=200, **kwargs): return self.call(*args, **kwargs)[1]
    def finish(self, name):
        if name in self.finished: raise AssertionError('duplicate scenario')
        self.finished.append(name)


class SecretCidrProbeGuards(unittest.TestCase):
    def test_field_projection_preserves_nil_empty_alias_and_never_errors_or_secrets(self):
        body = {'data': {f.FIELD: None, f.ALIAS: [], 'secret_id': 'synthetic-sensitive',
                        'secret_id_num_uses': 1}, 'errors': ['private arbitrary error']}
        client = SimpleNamespace(last_family=4, request=lambda *a, **k: SimpleNamespace(status=400, body=body))
        t = f.Trace(client); t.call('projection', 'GET', 'path')
        self.assertEqual(t.rows[0]['role_login_cidr_shape'], 'null')
        self.assertEqual(t.rows[0]['legacy_alias_cidr_shape'], 'list')
        self.assertEqual(t.rows[0]['legacy_alias_cidrs'], [])
        self.assertEqual(t.rows[0]['secret_id_num_uses'], 1)
        self.assertIn('synthetic-sensitive', t.sensitive)
        self.assertNotIn('synthetic-sensitive', json.dumps(t.rows))
        self.assertNotIn('private arbitrary error', json.dumps(t.rows))
        with self.assertRaises(ValueError): t.call('projection', 'GET', 'path')
        client.last_family = 6
        with self.assertRaises(f.ScenarioFailure): t.call('wrong_family', 'GET', 'path')

    def test_consumption_observes_before_denial_after_denial_and_next_allowed_without_assumption(self):
        for issued in (True, False):
            for uses, label in ((1,'one'), (2,'two'), (0,'unlimited')):
                t = OfflineTrace(issued); f.consumption(t, 'service', label, uses)
                names = [call[0] for call in t.calls]; prefix = 'consume.service.'+label
                order = [prefix+suffix for suffix in ('.before', '.denied_login', '.after_denied',
                         '.allowed_login', '.after_allowed', '.next_allowed_login', '.after_next')]
                self.assertEqual(sorted(order, key=names.index), order)
                denied = next(call for call in t.calls if call[0] == prefix+'.denied_login')
                self.assertEqual(denied[-1], {'token':'', 'source':'127.0.0.2', 'spoof':True})
                self.assertEqual(t.finished, [prefix])
                if not issued:
                    self.assertEqual(t.rows, [{'case':prefix+'.issued_foreign_use_pending',
                        'not_run':True, 'reason':'no_issued_token'}])
                    self.assertNotIn(prefix+'.issued_foreign_use', names)

    def test_real_graph_has_unique_names_all_scenarios_and_one_restart(self):
        t = OfflineTrace(); restarts = []
        f.run(t, lambda: restarts.append(True))
        names = [call[0] for call in t.calls]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(t.finished), f.SCENARIOS)
        self.assertEqual(restarts, [True])
        calls = {name:(method,path,body,kwargs) for name,method,path,body,kwargs in t.calls}
        for kind in ('service','batch'):
            prefix = 'lifecycle.'+kind
            self.assertLess(names.index(prefix+'.initial_login'), names.index(prefix+'.move_login_constraint'))
            self.assertEqual(calls[prefix+'.move_login_constraint'][2], {f.FIELD:f.OTHER})
            self.assertEqual(calls[prefix+'.independent_token_constraint'][2],
                             {f.FIELD:f.BOUND, 'token_bound_cidrs':f.OTHER})
            self.assertEqual(calls[prefix+'.restricted_other_bearer'][3]['source'], '127.0.0.2')
            self.assertNotEqual(calls[prefix+'.old_bearer_other'][3]['token'],
                                calls[prefix+'.restricted_other_bearer'][3]['token'])
            for label in ('one','two','unlimited'):
                self.assertIn('consume.'+kind+'.'+label, t.finished)

    def test_api_graph_keeps_alias_priority_and_invalid_input_observations(self):
        t = OfflineTrace(); f.api_scenarios(t)
        calls = {name:(method,path,body,kwargs) for name,method,path,body,kwargs in t.calls}
        self.assertEqual(calls['api.alias_priority.native_null.write'][2], {f.FIELD:None,f.ALIAS:f.BOUND})
        self.assertEqual(calls['api.alias_priority.native_empty.write'][2], {f.FIELD:[],f.ALIAS:f.BOUND})
        for mode in ('whole','field','alias_field'):
            for case in ('null','empty_list','empty_string','bare_ip','port','bad_mask','object'):
                self.assertIn(f'api.{mode}.{case}.write', calls)
                self.assertIn(f'api.{mode}.{case}.whole', calls)
                self.assertIn(f'api.{mode}.{case}.field', calls)
                self.assertIn(f'api.{mode}.{case}.alias', calls)
        self.assertEqual(calls['constraints.delete.clear'][0], 'DELETE')
        self.assertEqual(calls['constraints.field.clear'][2], {f.FIELD:[]})


if __name__ == '__main__': unittest.main()
