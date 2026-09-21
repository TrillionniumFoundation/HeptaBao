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


if __name__ == '__main__':
    unittest.main()
