import json
from types import SimpleNamespace
import unittest

import approle_cidrs_ha as fixture


class AppRoleHaGuards(unittest.TestCase):
    def test_service_login_and_secret_id_accessors_join_private_secret_samples(self):
        class Client:
            last_family = 4
            def request(self, *args, **kwargs):
                return SimpleNamespace(status=200, body={'auth': {'client_token': 'private-token',
                    'token_type': 'service', 'accessor': 'private-accessor', 'renewable': True,
                    'metadata': {'role_name': 'service'}}})
        rows = []; sensitive = []; trace = fixture.Trace(Client(), rows, sensitive)
        trace.login('service_forwarded', 'service', {})
        trace.remember({'secret_id': 'private-sid', 'secret_id_accessor': 'private-sid-accessor'},
                       'secret_id', 'secret_id_accessor')
        trace.remember({'accessor': '', 'missing': None}, 'accessor', 'missing', 'absent')
        self.assertEqual(sensitive, ['private-token', 'private-accessor', 'private-sid', 'private-sid-accessor'])
        self.assertFalse(any(value in json.dumps(rows) for value in sensitive))

    def test_completion_requires_every_voter_and_transition_without_fixed_count(self):
        rows = [{'case': name, 'passed': True} for name in sorted(fixture.REQUIRED - {'complete'})]
        rows.append({'case': 'complete', 'passed': True})
        self.assertTrue(fixture.complete(rows))
        self.assertTrue(fixture.complete(rows[:-1] + [{'case': 'new_observation', 'passed': True}] + rows[-1:]))
        for case in ('forwarder_confirmed', 'batch_sid_consumed_once', 'former_leader_standby',
                     'initial_n3_batch_spoofed_kv_rejected', 'restarted_n2_service_new_allowed_value'):
            self.assertFalse(fixture.complete([row for row in rows if row['case'] != case]))
        self.assertFalse(fixture.complete(rows[:-1] + [rows[0]] + rows[-1:]))
        self.assertFalse(fixture.complete(rows[:-1] + [{'case': 'failed_observation', 'passed': False}] + rows[-1:]))
        self.assertFalse(fixture.complete(rows + [{'case': 'too_late', 'passed': True}]))

    def test_login_uses_disallowed_real_source_without_spoof_or_root_bearer(self):
        class Client:
            last_family = 4
            def __init__(self): self.calls = []
            def request(self, method, path, body, **kwargs):
                self.calls.append((method, path, body, kwargs))
                return SimpleNamespace(status=200, body={'auth': {'client_token': 'synthetic-token',
                    'token_type': 'batch', 'accessor': '', 'renewable': False, 'metadata': {'role_name': 'batch'}}})
        client = Client(); rows = []; sensitive = []
        trace = fixture.Trace(client, rows, sensitive)
        credentials = {'role_id': 'synthetic-role-id', 'secret_id': 'synthetic-secret-id'}
        trace.login('batch_forwarded', 'batch', credentials)
        self.assertEqual(len(client.calls), 1)
        _, path, body, args = client.calls[0]
        self.assertEqual(path, f'auth/{fixture.MOUNT}/login')
        self.assertEqual(body, credentials)
        self.assertEqual(args, {'token': '', 'source': '127.0.0.2', 'spoof': False})
        self.assertEqual(sensitive, ['synthetic-token'])
        self.assertNotIn('synthetic-token', json.dumps(rows))
        client.last_family = 6
        with self.assertRaises(fixture.ScenarioFailure): trace.login('wrong_family', 'batch', credentials)

    def test_denied_bearer_is_not_retried_or_replaced_by_root_target_lookup(self):
        class Client:
            last_family = 4
            def __init__(self): self.calls = []
            def request(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                return SimpleNamespace(status=403, body={'errors': ['denied']})
        client = Client(); trace = fixture.Trace(client, [], [])
        trace.read('denied', {'client_token': 'synthetic-token'}, source='127.0.0.2', status=403, spoof=True)
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(client.calls[0][1], {'token': 'synthetic-token', 'source': '127.0.0.2', 'spoof': True})
        trace.call('root_target', 'POST', 'auth/token/lookup', {'token': 'synthetic-token'}, source='127.0.0.2', status=403)
        self.assertIsNone(client.calls[-1][1]['token'])
        self.assertEqual(client.calls[-1][0][2], {'token': 'synthetic-token'})
        class Leaking(Client):
            def request(self, *args, **kwargs): return SimpleNamespace(status=403, body={'errors': ['denied'], 'auth': {'client_token': 'private'}})
        with self.assertRaises(fixture.ScenarioFailure):
            fixture.Trace(Leaking(), [], []).read('leaked', {'client_token': 'input'}, status=403)

    def test_lookup_shape_requires_credential_kind_snapshot_and_positive_lifetime(self):
        auth = {'client_token': 'synthetic-token'}
        data = {'id': auth['client_token'], 'type': 'batch', 'bound_cidrs': ['127.0.0.1'],
                'ttl': 300, 'meta': {'role_name': 'batch'}, 'accessor': '', 'renewable': False}
        self.assertTrue(fixture.lookup_shape(data, auth, 'batch', ['127.0.0.1']))
        for change in ({'ttl': 0}, {'ttl': True}, {'type': 'service'}, {'accessor': 'unexpected'},
                       {'bound_cidrs': []}, {'meta': {'role_name': 'service'}}, {'renewable': True}):
            self.assertFalse(fixture.lookup_shape(data | change, auth, 'batch', ['127.0.0.1']))
        service = data | {'type': 'service', 'meta': {'role_name': 'service'}, 'accessor': 'a', 'renewable': True}
        self.assertTrue(fixture.lookup_shape(service, auth, 'service', ['127.0.0.1']))


if __name__ == '__main__': unittest.main()
