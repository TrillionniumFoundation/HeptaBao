import json
from types import SimpleNamespace
import unittest

import approle_token_cidrs_probe as f


class AppRoleTokenCidrsProbeGuards(unittest.TestCase):
    def test_cidr_readback_preserves_missing_null_and_explicit_empty(self):
        self.assertEqual(f.cidr_projection({}, f.FIELD), {'cidr_shape': 'missing'})
        self.assertEqual(f.cidr_projection({f.FIELD: None}, f.FIELD), {'cidr_shape': 'null'})
        self.assertEqual(f.cidr_projection({f.FIELD: []}, f.FIELD), {'cidr_shape': 'list', 'cidrs': []})
        values = ['127.0.0.1', '127.0.0.2/24', '::1', '::ffff:127.0.0.1/128']
        self.assertEqual(f.cidr_projection({f.FIELD: values}, f.FIELD)['cidrs'], values)
        for bad in ('127.0.0.1', False, [True], ['synthetic-secret'], ['127.0.0.1\n']):
            with self.assertRaises(ValueError): f.cidr_projection({f.FIELD: bad}, f.FIELD)

    def test_trace_retains_only_safe_status_shape_and_consumption(self):
        body = {'data': {f.FIELD: None, 'secret_id': 'synthetic-sensitive', 'secret_id_num_uses': 2},
                'errors': ['must not copy arbitrary provider text']}
        client = SimpleNamespace(request=lambda *a, **k: SimpleNamespace(status=400, body=body))
        t = f.Trace(client); t.call('safe.case', 'GET', 'path')
        self.assertEqual(t.rows[0]['cidr_shape'], 'null')
        self.assertEqual(t.rows[0]['secret_id_num_uses'], 2)
        self.assertIn('synthetic-sensitive', t.sensitive)
        self.assertNotIn('synthetic-sensitive', json.dumps(t.rows))
        self.assertNotIn('must not copy', json.dumps(t.rows))
        with self.assertRaises(ValueError): t.call('safe.case', 'GET', 'path')

    def test_actual_phase_functions_preserve_source_and_separate_role_from_token_snapshots(self):
        t = OfflineTrace()
        restarts = []
        f.run(t, lambda: restarts.append(True))
        names = [r[0] for r in t.calls]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(t.finished), f.SCENARIOS)
        self.assertEqual(restarts, [True])
        for kind in ('service', 'batch'):
            prefix = 'lifecycle.'+kind
            calls = {name: (method, path, body, kwargs) for name, method, path, body, kwargs in t.calls}
            login = calls[prefix+'.foreign_login']
            self.assertEqual(login[3]['source'], '127.0.0.2')
            self.assertEqual(login[3]['token'], '')
            self.assertEqual(calls[prefix+'.foreign_read'][3]['source'], '127.0.0.2')
            self.assertTrue(calls[prefix+'.foreign_read'][3]['spoof'])
            self.assertEqual(calls[prefix+'.clear_role'][2], {f.FIELD: []})
            self.assertLess(names.index(prefix+'.snapshot'), names.index(prefix+'.clear_role'))
            self.assertLess(names.index(prefix+'.clear_role'), names.index(prefix+'.old_snapshot_after_clear'))
            self.assertLess(names.index(prefix+'.renew_after_clear'), names.index(prefix+'.old_snapshot_after_renew'))
            self.assertEqual(calls[prefix+'.fresh_login'][3]['source'], '127.0.0.2')
            self.assertNotEqual(calls[prefix+'.old_foreign_after_clear'][3]['token'],
                                calls[prefix+'.fresh_foreign_read'][3]['token'])
        for mode in ('whole', 'field'):
            for case in ('null', 'empty_list', 'empty_string'):
                self.assertIn('api.'+mode+'.'+case+'.field', names)
            self.assertIn('api.'+mode+'.after_delete_field', names)


class OfflineTrace:
    """Only verifies the real runner's request graph; no live behavior claimed."""
    def __init__(self): self.calls, self.finished, self.serial = [], [], 0
    def call(self, name, method, path, body=None, **kwargs):
        self.calls.append((name, method, path, body, kwargs))
        self.serial += 1
        if path.endswith('/role-id'): return 200, {'data': {'role_id': 'synthetic-role'}}
        if path.endswith('/secret-id'): return 200, {'data': {'secret_id': 'synthetic-sid'}}
        if path.endswith('/login') or path in ('auth/token/create', 'auth/token/create-orphan'):
            return 200, {'auth': {'client_token': 'synthetic-token-'+str(self.serial), 'accessor': 'synthetic-accessor'}}
        return 200, {'data': {}}
    def require(self, *args, status=200, **kwargs): return self.call(*args, **kwargs)[1]
    def finish(self, name):
        if name in self.finished: raise AssertionError('duplicate scenario')
        self.finished.append(name)


if __name__ == '__main__': unittest.main()
