from types import SimpleNamespace
import json
import unittest
import approle_native_defaults_live as fixture


class AppRoleNativeDefaultsGuards(unittest.TestCase):
    def test_completion_requires_every_safety_phase_and_terminal_without_fixed_count(self):
        rows = [{'case': 'approle_native_defaults.' + name, 'passed': True} for name in sorted(fixture.REQUIRED - {'complete'})]
        rows.append({'case': 'approle_native_defaults.complete', 'passed': True})
        self.assertTrue(fixture.complete(rows))
        self.assertTrue(fixture.complete(rows[:-1] + [{'case': 'approle_native_defaults.extra', 'passed': True}] + rows[-1:]))
        for index in range(len(rows)):
            self.assertFalse(fixture.complete(rows[:index] + rows[index+1:]), rows[index])
        self.assertFalse(fixture.complete(rows + [rows[0]]))
        self.assertFalse(fixture.complete(rows + [{'case': 'approle_native_defaults.extra', 'passed': True}]))
        for value in [False, 1, 'true', None]:
            damaged = rows[:-1] + [{'case': 'approle_native_defaults.complete', 'passed': value}]
            self.assertFalse(fixture.complete(damaged))
        self.assertFalse(fixture.complete(rows[:-1] + [{'case': 'approle_native_defaults.complete', 'passed': True, 'secret': 'sentinel'}]))

    def test_candidate_expiry_denial_is_separate_and_cannot_be_an_infrastructure_error(self):
        for status in [400, 403]:
            self.assertTrue(fixture.expiry_denied(SimpleNamespace(status=status, body={'errors': ['synthetic']})))
        for status in [200, 204, 500, 503]:
            self.assertFalse(fixture.expiry_denied(SimpleNamespace(status=status, body={})))
        for body in [{'auth': {'client_token': 'sentinel'}}, {'wrap_info': {'token': 'sentinel'}}]:
            self.assertFalse(fixture.expiry_denied(SimpleNamespace(status=400, body=body)))
        rows = [{'case': 'approle_native_defaults.candidate_expiry.' + name, 'passed': True} for name in
                ['role.status', 'id.status', 'issue.status', 'finite_one_second', 'rejected', 'complete']]
        self.assertTrue(fixture.candidate_expiry_complete(rows))
        for index in range(len(rows)):
            self.assertFalse(fixture.candidate_expiry_complete(rows[:index] + rows[index+1:]))
        self.assertFalse(fixture.candidate_expiry_complete(rows + [rows[-1]]))
        self.assertFalse(fixture.candidate_expiry_complete(rows[:-1] + [dict(rows[-1], passed=1)]))

    def test_zero_expiry_is_specific_and_requires_real_time_shape(self):
        self.assertTrue(fixture.zero_expiry('0001-01-01T00:00:00Z'))
        for value in [None, '', '0000-01-01T00:00:00Z', '2030-01-01T00:00:00Z', 0]:
            self.assertFalse(fixture.zero_expiry(value))
        created = fixture.secret_timestamp('2030-01-01T00:00:00Z')
        expiry = fixture.secret_timestamp('2030-01-01T00:01:00Z')
        self.assertEqual((expiry - created).total_seconds(), 60)
        with self.assertRaises(ValueError):
            fixture.secret_timestamp(None)

    def test_three_routes_use_target_bearer_only_where_the_contract_allows(self):
        calls = []
        def request(method, path, body, **kwargs):
            calls.append((path, body, kwargs['token']))
            auth = {'lease_duration': 300, 'renewable': True}
            if not path.endswith('renew-accessor'):
                auth['client_token'] = 'sensitive-token'
            return SimpleNamespace(status=200, body={'auth': auth})
        rows, diagnostics = [], []
        trace = fixture.Trace(SimpleNamespace(request=request), rows, diagnostics)
        auth = {'client_token': 'sensitive-token', 'accessor': 'sensitive-accessor'}
        for via in fixture.ROUTES:
            trace.renew('grant', auth, via=via, exact=300)
        self.assertEqual([c[2] for c in calls], ['sensitive-token', None, None])
        self.assertEqual([c[1] for c in calls], [{}, {'token': 'sensitive-token'}, {'accessor': 'sensitive-accessor'}])
        self.assertNotIn('sensitive-', json.dumps([rows, diagnostics]))

    def test_zero_increment_remains_distinct_from_omission(self):
        calls = []
        def request(method, path, body, **kwargs):
            calls.append(body)
            return SimpleNamespace(status=200, body={'auth': {'client_token': 'synthetic-token', 'lease_duration': 75, 'renewable': True}})
        trace = fixture.Trace(SimpleNamespace(request=request), [], [])
        auth = {'client_token': 'synthetic-token', 'accessor': 'synthetic-accessor'}
        trace.renew('omitted', auth, exact=75)
        trace.renew('zero', auth, increment=0, exact=75)
        self.assertEqual(calls, [{}, {'increment': 0}])

    def test_failed_renew_cannot_pass_with_a_wrapper_or_target_auth(self):
        for leaked in [{'auth': {'client_token': 'sentinel'}}, {'wrap_info': {'token': 'sentinel'}}]:
            trace = fixture.Trace(SimpleNamespace(request=lambda *a, **k: SimpleNamespace(status=500, body=leaked)), [], [])
            with self.assertRaises(fixture.ScenarioFailure):
                trace.renew('denied', {'client_token': 'synthetic-token'}, status=500)
            self.assertNotIn('sentinel', str(trace.rows))

    def test_numeric_diagnostics_do_not_weaken_caps_or_log_sensitive_values(self):
        for value in [121, 'sensitive-duration', True]:
            rows, diagnostics = [], []
            trace = fixture.Trace(None, rows, diagnostics)
            with self.assertRaises(fixture.ScenarioFailure):
                trace.lease('cap', {'lease_duration': value, 'client_token': 'sensitive-token'}, maximum=120)
            self.assertFalse(rows[-1]['passed'])
            self.assertNotIn('lease_duration', rows[-1])
            self.assertNotIn('sensitive-', str(diagnostics))
            self.assertEqual('lease_duration' in diagnostics[0], type(value) is int)


if __name__ == '__main__':
    unittest.main()
