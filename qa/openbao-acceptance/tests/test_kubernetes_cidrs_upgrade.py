from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import kubernetes_cidrs_upgrade as fixture


class KubernetesCidrUpgradeGuards(unittest.TestCase):
    def pins(self):
        context = ExitStack()
        for name, value in [('LEGACY_SOURCE', '1'*40), ('LEGACY_HARNESS', '2'*40),
                            ('LEGACY_SHA256', '3'*64), ('LEGACY_RECEIPT', Path('synthetic-receipt'))]:
            context.enter_context(patch.object(fixture, name, value))
        return context

    def receipt(self):
        return {'status': 'passed', 'build_source_commit': '1'*40, 'source_and_binary_unchanged': True,
                'runner_unchanged': True, 'cases_match': True,
                'candidate_source': {'source_commit': '2'*40, 'binary_sha256': '3'*64, 'source_dirty': False}}

    def test_unpinned_historical_build_cannot_run(self):
        for name in ['LEGACY_SOURCE', 'LEGACY_HARNESS', 'LEGACY_SHA256', 'LEGACY_RECEIPT']:
            with self.pins(), patch.object(fixture, name, None):
                with self.assertRaises(ValueError):
                    fixture.admit_legacy_receipt('3'*64, self.receipt())

    def test_exact_build_clean_harness_and_observation_pins_required(self):
        with self.pins():
            fixture.admit_legacy_receipt('3'*64, self.receipt())
            for field, value in [('status', 'failed'), ('build_source_commit', '0'*40),
                                 ('source_and_binary_unchanged', 1), ('runner_unchanged', False), ('cases_match', False)]:
                with self.assertRaises(ValueError):
                    fixture.admit_legacy_receipt('3'*64, self.receipt() | {field: value})
            for field, value in [('source_commit', '1'*40), ('source_dirty', True),
                                 ('source_dirty', 0), ('binary_sha256', '0'*64)]:
                receipt = self.receipt()
                receipt['candidate_source'][field] = value
                with self.assertRaises(ValueError):
                    fixture.admit_legacy_receipt('3'*64, receipt)
            with self.assertRaises(ValueError):
                fixture.admit_legacy_receipt('0'*64, self.receipt())

    def test_historical_role_is_frozen_without_new_cidr_and_ca_is_explicit(self):
        role = fixture.old_role()
        self.assertNotIn('token_bound_cidrs', role)
        self.assertEqual(role['bound_service_account_names'], ['worker'])
        self.assertEqual(role['bound_service_account_namespaces'], ['workload'])
        role['token_policies'].append('unwanted-mutation')
        self.assertNotIn('unwanted-mutation', fixture.old_role()['token_policies'])
        config = fixture.old_configuration(SimpleNamespace(origin='https://localhost:123', reviewer='synthetic'), 'synthetic-ca')
        self.assertEqual(config['kubernetes_ca_cert'], 'synthetic-ca')
        self.assertIs(config['disable_local_ca_jwt'], True)

    def test_every_named_upgrade_milestone_is_required_and_new_checks_are_allowed(self):
        for prepare in [False, True]:
            rows = [{'case': name, 'passed': True} for name in sorted(fixture.required_cases(prepare))]
            self.assertTrue(fixture.complete(rows, prepare))
            self.assertTrue(fixture.complete(rows + [{'case': fixture.PREFIX + 'new_observation', 'passed': True}], prepare))
            for index in range(len(rows)):
                self.assertFalse(fixture.complete(rows[:index] + rows[index+1:], prepare), rows[index])
            self.assertFalse(fixture.complete(rows + [rows[0]], prepare))
            for value in [False, 1, 'true', None]:
                self.assertFalse(fixture.complete(rows + [{'case': fixture.PREFIX + 'extra', 'passed': value}], prepare))
            self.assertFalse(fixture.complete(rows + [{'case': fixture.PREFIX + 'extra', 'passed': True, 'secret': 'sentinel'}], prepare))
        self.assertFalse(fixture.complete([None], False))
        self.assertFalse(fixture.complete([], False))
        prepared = [{'case': name, 'passed': True} for name in fixture.required_cases(True)]
        self.assertFalse(fixture.complete(prepared, False))

    def test_trace_requires_actual_provider_count_and_strict_boolean_pass(self):
        reviewer = SimpleNamespace(calls=[], request_valid=True, presented="synthetic-jwt")
        client = SimpleNamespace(last_family=4, request=lambda *a, **k: SimpleNamespace(status=200, body={}))
        rows = []
        trace = fixture.Trace(client, reviewer, rows)
        with self.assertRaises(fixture.ScenarioFailure):
            trace.call('expected_provider', 'auth/login', reviews=1)
        self.assertEqual(rows[-1]['tokenreviews'], 0)
        self.assertIs(rows[-1]['passed'], False)
        with self.assertRaises(fixture.ScenarioFailure):
            trace.check('truthy_is_not_pass', 1)
        with self.assertRaises(ValueError):
            trace.check('safe', True, credential='sentinel')
        self.assertNotIn('sentinel', str(rows))

    def test_unexpected_provider_call_during_cidr_denial_is_not_success(self):
        reviewer = SimpleNamespace(calls=[], request_valid=True, presented="synthetic-jwt")
        def bad_request(*args, **kwargs):
            reviewer.calls.append('synthetic-review')
            return SimpleNamespace(status=403, body={})
        trace = fixture.Trace(SimpleNamespace(last_family=4, request=bad_request), reviewer, [])
        with self.assertRaises(fixture.ScenarioFailure):
            trace.login('cidr_denied', expected=403, reviews=0)


if __name__ == '__main__':
    unittest.main()
