from types import SimpleNamespace
import json
import unittest
import token_mount_ttl_live as fixture


class TokenMountTtlGuards(unittest.TestCase):
    def test_credential_isolation_explicitly_enrolls_reusable_secret(self):
        fields = fixture.credential_role_fields()
        self.assertEqual(fields['secret_id_ttl'], 120)
        self.assertEqual(fields['secret_id_num_uses'], 0)
        self.assertEqual(fields['token_ttl'], 90)
        self.assertIn('approle.secret_reusable', fixture.REQUIRED)

    def test_completion_requires_every_safety_phase_and_terminal_without_fixed_count(self):
        rows = [{'case': 'token_mount_ttl.' + name, 'passed': True} for name in sorted(fixture.REQUIRED - {'complete'})]
        rows.append({'case': 'token_mount_ttl.complete', 'passed': True})
        self.assertTrue(fixture.complete(rows))
        self.assertTrue(fixture.complete(rows[:-1] + [{'case': 'token_mount_ttl.extra', 'passed': True}] + rows[-1:]))
        for index in range(len(rows)):
            self.assertFalse(fixture.complete(rows[:index] + rows[index+1:]), rows[index])
        self.assertFalse(fixture.complete(rows + [rows[0]]))
        self.assertFalse(fixture.complete(rows + [{'case': 'token_mount_ttl.extra', 'passed': True}]))
        for value in [False, 1, 'true', None]:
            damaged = rows[:-1] + [{'case': 'token_mount_ttl.complete', 'passed': value}]
            self.assertFalse(fixture.complete(damaged))
        self.assertFalse(fixture.complete(rows[:-1] + [{'case': 'token_mount_ttl.complete', 'passed': True, 'secret': 'sentinel'}]))

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
