from types import SimpleNamespace
import unittest
import jwt_native_ttl_live as fixture


class NativeJwtTtlGuards(unittest.TestCase):
    def test_matrix_distinguishes_omission_zero_and_independent_ttl_max(self):
        cases = {name: (fields, readback, lease) for name, fields, readback, lease in fixture.creation_matrix()}
        self.assertNotIn('token_ttl', cases['omitted'][0])
        self.assertEqual(cases['zero'][0], {'token_ttl': 0, 'token_max_ttl': 0})
        self.assertEqual(cases['ttl_only'][1:], ((120, 0, 0, 0), 120))
        self.assertEqual(cases['max_only'][1:], ((0, 90, 0, 0), 75))
        self.assertEqual(fixture.role_fields()['role_type'], 'jwt')
        self.assertNotIn('token_ttl', fixture.role_fields())

    def test_every_named_phase_is_required_without_fixed_counts(self):
        rows = [{'case': name, 'passed': True} for name in sorted(fixture.required_cases())]
        self.assertTrue(fixture.complete(rows))
        self.assertTrue(fixture.complete(rows + [{'case': 'jwt_native_ttl.extra', 'passed': True}]))
        for index in range(len(rows)):
            self.assertFalse(fixture.complete(rows[:index] + rows[index+1:]), rows[index])
        self.assertFalse(fixture.complete(rows + [rows[0]]))
        for value in [False, 1, 'true', None]:
            self.assertFalse(fixture.complete(rows + [{'case': 'jwt_native_ttl.extra', 'passed': value}]))
        self.assertFalse(fixture.complete(rows + [{'case': 'jwt_native_ttl.extra', 'passed': True, 'token': 'sentinel'}]))
        self.assertFalse(fixture.complete([None]))

    def test_partial_writes_explicitly_select_jwt_and_preserve_null(self):
        calls = []
        def request(method, path, body, **kwargs):
            calls.append(body)
            return SimpleNamespace(status=204, body={})
        t = fixture.Trace(SimpleNamespace(request=request), SimpleNamespace(calls=[]), 'static', [])
        t.write_role('null', 'auth/jwt/role/test', {'token_ttl': None, 'token_max_ttl': None})
        self.assertEqual(calls, [{'token_ttl': None, 'token_max_ttl': None, 'role_type': 'jwt'}])

    def test_three_renew_routes_require_no_provider_and_exact_bearer_shape(self):
        provider = SimpleNamespace(calls=[])
        observed = []
        def request(method, path, body, **kwargs):
            observed.append((path, body, kwargs['token']))
            auth = {'lease_duration': 75, 'renewable': True, 'client_token': 'synthetic-token'}
            if path.endswith('renew-accessor'):
                auth.pop('client_token')
            return SimpleNamespace(status=200, body={'auth': auth})
        rows = []
        t = fixture.Trace(SimpleNamespace(request=request), provider, 'remote', rows)
        t.renew('test', {'client_token': 'synthetic-token', 'accessor': 'synthetic-accessor'}, ttl=75)
        self.assertEqual([item[0] for item in observed], ['/v1/auth/token/renew-self', '/v1/auth/token/renew', '/v1/auth/token/renew-accessor'])
        self.assertEqual([item[2] for item in observed], ['synthetic-token', None, None])
        self.assertTrue(all(row['passed'] is True for row in rows))
        self.assertNotIn('synthetic-token', str(rows))
        def contacting(*args, **kwargs):
            provider.calls.append('/keys')
            return request(*args, **kwargs)
        t.client.request = contacting
        with self.assertRaises(fixture.ScenarioFailure):
            t.renew('unexpected_io', {'client_token': 'synthetic-token', 'accessor': 'synthetic-accessor'}, ttl=75)

    def test_lease_diagnostics_are_numeric_separate_and_survive_a_cap_failure(self):
        def client(lease):
            return SimpleNamespace(request=lambda *a, **k: SimpleNamespace(status=200, body={
                'auth': {'lease_duration': lease, 'renewable': True, 'client_token': 'sensitive-token',
                         'metadata': {'password': 'sensitive-password'}}}))
        rows, diagnostics = [], []
        t = fixture.Trace(client(121), SimpleNamespace(calls=[]), 'remote', rows, diagnostics)
        with self.assertRaises(fixture.ScenarioFailure):
            t.renew('cap', {'client_token': 'sensitive-token', 'accessor': 'sensitive-accessor'}, maximum=120, increment=700)
        self.assertEqual(diagnostics, [{'case': 'jwt_native_ttl.remote.cap.self', 'lease_is_integer': True,
                                       'lease_duration': 121, 'maximum_ttl': 120, 'increment': 700}])
        self.assertFalse(rows[-1]['passed'])
        self.assertNotIn('lease_duration', rows[-1])
        self.assertNotIn('sensitive-', str(diagnostics))
        diagnostics.clear()
        t = fixture.Trace(client('sensitive-malformed-lease'), SimpleNamespace(calls=[]), 'remote', [], diagnostics)
        with self.assertRaises(fixture.ScenarioFailure):
            t.renew('cap', {'client_token': 'sensitive-token', 'accessor': 'sensitive-accessor'}, maximum=120)
        self.assertFalse(diagnostics[0]['lease_is_integer'])
        self.assertNotIn('lease_duration', diagnostics[0])
        self.assertNotIn('sensitive-', str(diagnostics))

    def test_lookup_does_not_coerce_boolean_duration_or_hide_wrong_defaults(self):
        for fields in [(True, 0, 0, 0), (3600, 3600, 0, 0)]:
            result = {'role_type': 'jwt', **dict(zip(fixture.TTL_FIELDS, fields))}
            t = fixture.Trace(SimpleNamespace(request=lambda *a, **k: SimpleNamespace(status=200, body={'data': result})),
                              SimpleNamespace(calls=[]), 'static', [])
            with self.assertRaises(fixture.ScenarioFailure):
                t.read_role('default', 'auth/jwt/role/test', (0, 0, 0, 0))


if __name__ == '__main__':
    unittest.main()
