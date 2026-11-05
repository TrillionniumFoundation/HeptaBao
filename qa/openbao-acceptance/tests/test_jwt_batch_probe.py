import json
from types import SimpleNamespace
import unittest

import jwt_batch_probe as f


class JwtBatchProbeGuards(unittest.TestCase):
    def test_type_projection_preserves_absent_null_empty_and_only_fixed_names(self):
        self.assertEqual(f.type_projection({}, 'token_type'), {'shape': 'missing'})
        self.assertEqual(f.type_projection({'token_type': None}, 'token_type'), {'shape': 'null'})
        self.assertEqual(f.type_projection({'token_type': ''}, 'token_type'), {'shape': 'string', 'value': ''})
        for value in ('sensitive-bearer', {'token': 'sensitive'}, False, 0):
            self.assertEqual(f.type_projection({'token_type': value}, 'token_type'), {'shape': 'other'})

    def test_projection_does_not_copy_jwt_tokens_ids_errors_or_unrecognized_type(self):
        secret = 'synthetic-sensitive-token'
        body = {'auth': {'client_token': secret, 'accessor': 'synthetic-sensitive-accessor',
                'entity_id': 'synthetic-sensitive-entity', 'token_type': secret,
                'metadata': {'role': 'known', 'unexpected': secret}},
                'wrap_info': {'token': 'synthetic-sensitive-wrapper'}, 'errors': [secret]}
        t = f.Trace(SimpleNamespace(request=lambda *a, **k: SimpleNamespace(status=400, body=body)))
        t.call('safe.login', 'POST', 'auth/m/login', {'jwt': secret}, role='known')
        self.assertTrue(t.rows[0]['role_metadata'])
        self.assertEqual(t.rows[0]['auth_type'], {'shape': 'other'})
        self.assertIn(secret, t.sensitive)
        self.assertNotIn('synthetic-sensitive', json.dumps(t.rows))
        with self.assertRaises(ValueError): t.call('safe.login', 'GET', 'path')

    def test_real_request_graph_has_jwt_roles_matrix_and_distinct_forced_cases(self):
        client = OfflineClient(); t = f.Trace(client)
        private, jwk = f.signing_key('ES256', 'offline')
        restarts = []
        f.run(t, private, jwk, lambda: restarts.append(True))
        self.assertTrue(f.complete_scenarios(t)); self.assertEqual(restarts, [True])
        names = [row['case'] for row in t.rows]
        self.assertEqual(len(names), len(set(names)))
        writes = [c for c in client.calls if c[0] == 'POST' and '/role/' in c[1]]
        self.assertTrue(writes)
        self.assertTrue(all(call[2]['role_type'] == 'jwt' for call in writes))
        roles = {path.rsplit('/', 1)[1]: body for method, path, body, _ in writes
                 if path.rsplit('/', 1)[1] != 'partial'}
        for mode in f.MODES:
            for kind in f.ROLE_TYPES:
                role = 'matrix-'+mode.replace('-', '_')+'-'+kind
                self.assertEqual(roles[role]['token_type'], kind)
                self.assertIn('matrix.'+mode.replace('-', '_')+'.'+kind+'.login', names)
        self.assertEqual(roles['forced-period']['token_type'], 'service')
        self.assertEqual(roles['forced-period']['token_period'], 30)
        self.assertEqual(roles['explicit-period']['token_type'], 'batch')
        self.assertEqual(roles['forced-uses']['token_num_uses'], 2)
        partials = [body for _, path, body, _ in writes if path.endswith('/role/partial')]
        self.assertEqual(partials[1], {'role_type': 'jwt', 'token_ttl': 120})
        self.assertIn({'role_type': 'jwt', 'token_type': None}, partials)
        self.assertIn({'role_type': 'jwt', 'token_type': ''}, partials)
        self.assertNotIn('token_type', roles['type-omitted'])
        self.assertEqual(roles['alias-default_service']['token_type'], 'default-service')
        self.assertEqual(roles['alias-default_batch']['token_type'], 'default-batch')

    def test_real_lifecycle_uses_same_assertion_and_checks_bearer_after_revocation_and_restart(self):
        client = OfflineClient(); t = f.Trace(client)
        private, jwk = f.signing_key('ES256', 'offline')
        f.run(t, private, jwk, lambda: client.calls.append(('RESTART', '', None, {})))
        names = [row['case'] for row in t.rows]
        login_calls = [c for c in client.calls if c[1].endswith('/login')]
        valid = [c for c in login_calls if c[2]['role'] == 'lifecycle' and not c[3].get('wrap_ttl')]
        self.assertGreaterEqual(len(valid), 3)
        self.assertEqual(len({c[2]['jwt'] for c in valid}), 1)
        wrapped = [c for c in login_calls if c[3].get('wrap_ttl')]
        self.assertEqual(len(wrapped), 3)  # Good assertion plus bad signature and bad audience.
        self.assertEqual(len({c[2]['jwt'] for c in wrapped}), 3)
        for phase in ('batch.role_deleted', 'batch.mount_disabled', 'restart'):
            self.assertIn(phase+'.lookup', names)
            self.assertIn(phase+'.kv', names)
        self.assertLess(names.index('batch.mount_disabled.disable'), names.index('batch.mount_disabled.kv'))
        restart_pos = next(i for i, c in enumerate(client.calls) if c[0] == 'RESTART')
        after = client.calls[restart_pos+1:]
        self.assertEqual([c[1] for c in after], ['/v1/auth/token/lookup', '/v1/'+f.KV])
        self.assertTrue(after[1][3]['token'])
        self.assertIn('wrapped.second_unwrap', names)
        self.assertIn('rejected_assertions.entity_set', names)

    def test_completeness_does_not_accept_empty_missing_or_duplicate_scenarios(self):
        t = f.Trace(None)
        self.assertFalse(f.complete_scenarios(t))
        t.rows = [{'case': 'one'}]; t.finished = sorted(f.SCENARIOS)
        self.assertFalse(f.complete_scenarios(t))
        t.rows = [{'case': name} for name in sorted(f.REQUIRED_CASES)]
        self.assertTrue(f.complete_scenarios(t))
        t.finished.pop(); self.assertFalse(f.complete_scenarios(t))
        t.finished = sorted(f.SCENARIOS)+[sorted(f.SCENARIOS)[0]]
        self.assertFalse(f.complete_scenarios(t))
        t.finished = sorted(f.SCENARIOS); t.rows *= 2
        self.assertFalse(f.complete_scenarios(t))


class OfflineClient:
    """Request-graph guard only; these replies do not assert official behavior."""
    def __init__(self): self.calls, self.serial, self.roles = [], 0, {}
    def request(self, method, path, body=None, **kwargs):
        self.calls.append((method, path, body, kwargs)); self.serial += 1
        status, response = (204 if method in ('POST', 'PUT', 'DELETE') else 200), {'data': {}}
        if '/role/' in path:
            role = path.rsplit('/', 1)[1]
            if method == 'POST': self.roles.setdefault(role, {}).update(body)
            if method == 'GET': response = {'data': self.roles.get(role, {})}
        elif path.endswith('/login') or path.endswith('/unwrap'):
            role = (body or {}).get('role', 'lifecycle')
            if kwargs.get('wrap_ttl'):
                response = {'wrap_info': {'token': 'synthetic-wrapper'}}
            else:
                response = {'auth': {'client_token': 'synthetic-token-'+str(self.serial),
                    'entity_id': 'synthetic-entity', 'token_type': 'batch', 'metadata': {'role': role}}}
            status = 200
        elif path.endswith('/identity/entity/id'):
            response = {'data': {'keys': ['synthetic-entity']}}
        elif '/identity/entity/id/' in path and method == 'GET':
            response = {'data': {'aliases': [{'name': f.SUBJECT, 'metadata': {'role': 'lifecycle'}}]}}
        return SimpleNamespace(status=status, body=response)


if __name__ == '__main__': unittest.main()
