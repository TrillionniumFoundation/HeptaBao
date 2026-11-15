from types import SimpleNamespace
import json
import unittest
import userpass_native_live as fixture


class UserpassNativeGuards(unittest.TestCase):
    def test_completion_requires_semantic_phases_unique_and_terminal_without_fixed_count(self):
        rows = [{'case': fixture.PREFIX + name, 'passed': True} for name in sorted(fixture.REQUIRED - {'complete'})]
        rows.append({'case': fixture.PREFIX + 'complete', 'passed': True})
        self.assertTrue(fixture.complete(rows))
        self.assertTrue(fixture.complete(rows[:-1] + [{'case': fixture.PREFIX + 'extra', 'passed': True}] + rows[-1:]))
        for i in range(len(rows)):
            self.assertFalse(fixture.complete(rows[:i] + rows[i+1:]), rows[i])
        for damaged in [[], rows + [rows[0]], rows[:-1], rows + [{'case': fixture.PREFIX + 'extra', 'passed': True}],
                        rows[:-1] + [dict(rows[-1], passed=1)], rows[:-1] + [dict(rows[-1], passed=False)],
                        rows[:-1] + [dict(rows[-1], secret='sentinel')]]:
            self.assertFalse(fixture.complete(damaged))

    def test_deleted_three_route_statuses_are_not_conflated_and_send_correct_identity(self):
        calls = []
        def request(method, path, fields, **kwargs):
            calls.append((path, fields, kwargs['token']))
            return SimpleNamespace(status=500 if path.endswith('renew-accessor') else 204, body={})
        rows = []
        trace = fixture.Trace(SimpleNamespace(request=request), rows, [])
        auth = {'client_token': 'sensitive-token', 'accessor': 'sensitive-accessor'}
        for via in fixture.ROUTES:
            trace.renew('deleted', auth, via=via, increment=300, status=500 if via == 'accessor' else 204)
        self.assertEqual([c[2] for c in calls], ['sensitive-token', None, None])
        self.assertEqual([c[1] for c in calls], [
            {'increment': 300}, {'increment': 300, 'token': 'sensitive-token'},
            {'increment': 300, 'accessor': 'sensitive-accessor'}])
        self.assertEqual([row['status'] for row in rows if 'status' in row], [204, 204, 500])
        self.assertNotIn('sensitive-', json.dumps(rows))
        wrong = fixture.Trace(SimpleNamespace(request=lambda *a, **k: SimpleNamespace(status=500, body={})), [], [])
        with self.assertRaises(fixture.ScenarioFailure):
            wrong.renew('deleted', auth, status=204)

    def test_rejected_or_empty_renew_must_not_return_auth_or_wrapping_credentials(self):
        for status in (204, 500):
            for body in ({'auth': {'client_token': 'sensitive'}}, {'wrap_info': {'token': 'sensitive'}}):
                trace = fixture.Trace(SimpleNamespace(request=lambda *a, **k: SimpleNamespace(status=status, body=body)), [], [])
                with self.assertRaises(fixture.ScenarioFailure):
                    trace.renew('deleted', {'client_token': 'synthetic'}, status=status)
                self.assertNotIn('sensitive', json.dumps(trace.rows))

    def test_no_extension_requires_same_real_expiry_and_positive_integer_ttl(self):
        before = {'expire_time': '2030-01-01T00:01:00Z', 'ttl': 60}
        self.assertTrue(fixture.no_extension(before, dict(before, ttl=59)))
        self.assertTrue(fixture.no_extension(before, before))
        for after in ({}, dict(before, expire_time='2030-01-01T00:02:00Z'),
                      dict(before, ttl=61), dict(before, ttl=True), dict(before, ttl=0), dict(before, ttl='59')):
            self.assertFalse(fixture.no_extension(before, after))
        self.assertFalse(fixture.no_extension({'ttl': 60}, {'ttl': 59}))

    def test_caps_reject_unsafe_duration_and_never_serialize_auth(self):
        for value in (121, 0, -1, True, 'sensitive'):
            rows, diagnostics = [], []
            trace = fixture.Trace(None, rows, diagnostics)
            with self.assertRaises(fixture.ScenarioFailure):
                trace.lease('cap', {'lease_duration': value, 'client_token': 'sensitive-token'}, maximum=120)
            self.assertFalse(rows[-1]['passed'])
            self.assertNotIn('sensitive', json.dumps([rows, diagnostics]))
        trace = fixture.Trace(None, [], [])
        trace.lease('cap', {'lease_duration': 119}, maximum=120)

    def test_successful_renew_echo_is_required_and_accessor_must_not_leak_bearer(self):
        auth = {'client_token': 'synthetic-token', 'accessor': 'synthetic-accessor'}
        for via, echo in [('self', None), ('token', 'wrong'), ('accessor', 'synthetic-token')]:
            body = {'auth': {'lease_duration': 60, 'renewable': True, 'client_token': echo}}
            trace = fixture.Trace(SimpleNamespace(request=lambda *a, **k: SimpleNamespace(status=200, body=body)), [], [])
            with self.assertRaises(fixture.ScenarioFailure):
                trace.renew('shape', auth, via=via, exact=60)

    def test_actual_initial_phases_execute_native_defaults_and_null_updates_with_unique_labels(self):
        class ReachedOrdinary(Exception):
            pass
        users, requests = {}, []
        def request(method, path, fields=None, **kwargs):
            requests.append((method, path, fields))
            if path.endswith('/users/alice'):
                raise ReachedOrdinary
            if '/users/' in path:
                name = path.rsplit('/', 1)[-1]
                if method == 'GET':
                    return SimpleNamespace(status=200, body={'data': users[name]})
                current = users.setdefault(name, {**dict.fromkeys(fixture.FIELDS, 0), 'token_policies': []})
                for field, value in fields.items():
                    if field in fixture.FIELDS and value is not None:
                        current[field] = value
                    elif field == 'token_num_uses' and value is None:
                        current[field] = 0
                    elif field == 'token_policies':
                        current[field] = value or []
                return SimpleNamespace(status=204, body={})
            if '/login/' in path:
                return SimpleNamespace(status=200, body={'auth': {
                    'client_token': 'synthetic-token', 'accessor': 'synthetic-accessor',
                    'lease_duration': 75, 'renewable': True, 'token_policies': ['default'],
                    'metadata': {'username': 'fresh'}}})
            if '/auth/token/renew' in path:
                auth = {'lease_duration': 95, 'renewable': True}
                if not path.endswith('renew-accessor'):
                    auth['client_token'] = 'synthetic-token'
                return SimpleNamespace(status=200, body={'auth': auth})
            return SimpleNamespace(status=204, body={})
        rows = []
        with self.assertRaises(ReachedOrdinary):
            fixture.run_scenarios(SimpleNamespace(request=request), lambda: None, rows, [], wait=lambda _: None)
        names = [r['case'] for r in rows]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(all(r['passed'] is True for r in rows))
        for expected in ('fresh.read.fields', 'nullable.partial.fields', 'nullable.null.fields', 'nullable.zero.fields'):
            self.assertIn(fixture.PREFIX + expected, names)
        null_write = next(fields for _, path, fields in requests
                          if path.endswith('/users/nullable') and isinstance(fields, dict)
                          and fields.get('token_ttl', 'absent') is None)
        self.assertEqual(set(null_write), set(fixture.FIELDS) | {'token_policies'})


if __name__ == '__main__':
    unittest.main()
