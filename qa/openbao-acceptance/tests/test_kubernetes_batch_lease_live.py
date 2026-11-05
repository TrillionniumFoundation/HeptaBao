import base64
import copy
import json
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import kubernetes_batch_lease_live as fixture


class KubernetesBatchLeaseEvidenceTests(unittest.TestCase):
    def test_actual_last_use_phase_checks_control_consumption_retirement_and_no_retry(self):
        client, cluster = LastUseClient(), LastUseCluster()
        rows = []
        fixture.last_use_scenarios(fixture.Trace(client, cluster, rows, []))
        names = [row['case'] for row in rows]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue({name for name in fixture.REQUIRED if name.startswith('last_use.')} <= set(names))
        self.assertTrue(all(row['passed'] for row in rows))
        self.assertEqual(client.credential_calls, ['finite-1', 'finite-1', 'finite-2', 'finite-2', 'finite-2'])
        self.assertEqual(client.root_reads, ['finite-1', 'finite-2', 'finite-2'])
        self.assertEqual(client.remaining, {'finite-1': 0, 'finite-2': 0})
        self.assertEqual(client.lease_lookups, ['synthetic-known-lease'])
        self.assertEqual(cluster.reviewed, ['synthetic-provider-jwt'])
        self.assertNotIn('synthetic-provider-jwt', json.dumps(rows))

    def test_last_use_phase_rejects_wrong_error_leaked_credentials_and_double_consumption(self):
        for changes in ({'last_error': 'wrong error'}, {'remaining_observation': 0},
                        {'remaining_observation': True}, {'final_status': 200},
                        *({'leak_field': field} for field in ('auth', 'data', 'wrap_info'))):
            rows = []
            client = LastUseClient(**changes)
            with self.assertRaises(fixture.ScenarioFailure):
                fixture.last_use_scenarios(fixture.Trace(client, LastUseCluster(), rows, []))
            self.assertTrue(any(row['passed'] is False for row in rows))
            self.assertNotIn('synthetic-leaked-value', json.dumps(rows))

    def test_retirement_status_cannot_carry_credentials(self):
        for path, status in (('auth/token/lookup', 403), ('sys/leases/lookup', 400)):
            for field in ('auth', 'data', 'wrap_info'):
                response = SimpleNamespace(status=status, body={field: {'secret': 'synthetic-sensitive-sentinel'}})
                client = SimpleNamespace(request=lambda *args, **kwargs: response)
                rows = []
                trace = fixture.Trace(client, None, rows, [])
                with self.assertRaises(fixture.ScenarioFailure):
                    trace.absent('retired', path, {})
                self.assertEqual(rows, [{'case': 'retired', 'passed': False, 'status': status}])
                self.assertNotIn('synthetic-sensitive-sentinel', json.dumps(rows))
            rows = []
            client = SimpleNamespace(request=lambda *args, **kwargs: SimpleNamespace(status=status, body={'errors': ['absent']}))
            fixture.Trace(client, None, rows, []).absent('retired', path, {})
            self.assertEqual(rows, [{'case': 'retired', 'passed': True, 'status': status}])

    def test_signal_handlers_raise_controlled_exception_and_restore_prior_handlers(self):
        originals = {fixture.signal.SIGTERM: object(), fixture.signal.SIGINT: object()}
        observed = []
        def register(kind, handler):
            observed.append((kind, handler))
            return originals[kind]
        with patch.object(fixture.signal, 'signal', register):
            previous = fixture.install_signal_handlers()
            try:
                with self.assertRaises(fixture.FixtureInterrupted):
                    fixture.interrupted(fixture.signal.SIGTERM, None)
            finally:
                fixture.restore_signal_handlers(previous)
        self.assertEqual(previous, originals)
        self.assertEqual(observed[:2], [(k, fixture.interrupted) for k in originals])
        self.assertEqual(observed[2:], list(originals.items()))

    def test_bao_lifetime_and_provider_jwt_are_independent_required_observations(self):
        payload = base64.urlsafe_b64encode(json.dumps({'exp': 1600}).encode()).decode().rstrip('=')
        response = {'data': {'service_account_token': 'header.' + payload + '.signature'},
                    'lease_duration': 30, 'renewable': False}
        lookup = {'data': {'expire_time': '1970-01-01T00:17:10Z'}}
        token = {'data': {'expire_time': '1970-01-01T00:17:10Z'}}
        self.assertTrue(fixture.separate_expiries(response, lookup, token, 1000, 30))
        long_lease = {'data': {'expire_time': '1970-01-01T00:26:40Z'}}
        self.assertFalse(fixture.separate_expiries(response, long_lease, token, 1000, 30))
        short = copy.deepcopy(response)
        payload = base64.urlsafe_b64encode(json.dumps({'exp': 1030}).encode()).decode().rstrip('=')
        short['data']['service_account_token'] = 'header.' + payload + '.signature'
        self.assertFalse(fixture.separate_expiries(short, lookup, token, 1000, 30))
        for update in ({'lease_duration': 600}, {'lease_duration': True}, {'renewable': True},
                       {'data': {}}, {'data': {'service_account_token': 'not-a-token'}}):
            self.assertFalse(fixture.separate_expiries({**response, **update}, lookup, token, 1000, 30))
        self.assertFalse(fixture.separate_expiries(response, {'data': {'expire_time': 'invalid'}}, token, 1000, 30))

    def test_missing_retirement_or_jwt_observation_cannot_pass_from_case_count(self):
        rows = [{'case': name, 'passed': True} for name in sorted(fixture.REQUIRED - {'complete'})]
        rows.append({'case': 'complete', 'passed': True})
        self.assertTrue(fixture.complete(rows))
        for name in fixture.REQUIRED:
            self.assertFalse(fixture.complete([row for row in rows if row['case'] != name]))
        self.assertFalse(fixture.complete(rows + [rows[-1]]))
        for update in ({'passed': 1}, {'passed': False}, {'status': True}, {'token': 'must-not-enter-receipt'}):
            broken = copy.deepcopy(rows)
            broken[0].update(update)
            self.assertFalse(fixture.complete(broken))


class LastUseCluster:
    def __init__(self): self.reviewed = []
    def await_token_review(self, token, authenticated):
        if authenticated is not True: raise AssertionError('expected live existing-SA JWT')
        self.reviewed.append(token)


class LastUseClient:
    """Offline response model, not evidence of real provider activity."""
    def __init__(self, *, last_error=fixture.LAST_USE_ERROR, remaining_observation=1,
                 final_status=400, leak_field=None):
        self.last_error, self.remaining_observation = last_error, remaining_observation
        self.final_status, self.leak_field = final_status, leak_field
        self.remaining, self.credential_calls, self.root_reads, self.lease_lookups = {}, [], [], []

    def request(self, method, path, body=None, *, token=None):
        status, response = 200, {}
        if path == '/v1/auth/token/create':
            actor = 'finite-' + str(body['num_uses'])
            self.remaining[actor] = body['num_uses']
            response = {'auth': {'client_token': actor}}
        elif path == '/v1/' + fixture.MOUNT + '/creds/worker':
            self.credential_calls.append(token)
            uses = self.remaining[token]
            if uses == 0:
                status, response = 403, {'errors': ['spent']}
            else:
                self.remaining[token] -= 1
                if uses == 1:
                    status, response = self.final_status, {'errors': [self.last_error]}
                    if self.leak_field: response[self.leak_field] = {'secret': 'synthetic-leaked-value'}
                else:
                    response = {'lease_id': 'synthetic-known-lease', 'renewable': False,
                                'data': {'service_account_token': 'synthetic-provider-jwt'}}
        elif path == '/v1/auth/token/lookup':
            self.root_reads.append(body['token'])
            if self.remaining[body['token']]:
                response = {'data': {'num_uses': self.remaining_observation}}
            else:
                status, response = 403, {'errors': ['absent']}
        elif path == '/v1/sys/leases/lookup':
            self.lease_lookups.append(body['lease_id'])
            status, response = 400, {'errors': ['absent']}
        else:
            raise AssertionError('unexpected offline request')
        return SimpleNamespace(status=status, body=response)


if __name__ == '__main__':
    unittest.main()
