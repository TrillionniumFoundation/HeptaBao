import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import approle_secretid_overrides_live as f


class SecretIdOverridesComparisonTests(unittest.TestCase):
    def calibration(self):
        value = json.loads(f.CALIBRATION_PATH.read_text())
        return f.calibrated_rows(), value['completed_scenarios']

    def test_actual_receipt_pins_named_scenarios_and_retains_all_observations(self):
        rows, finished = self.calibration()
        self.assertEqual(f.file_hash(f.CALIBRATION_PATH), f.CALIBRATION_SHA256)
        self.assertEqual(set(finished), f.contract.SCENARIOS)
        self.assertTrue(f.complete(rows, finished, rows))
        self.assertEqual([r['case'] for r in rows if r.get('credential_issued') is False],
            [f'consume.{mode}.{kind}.one.issued_bearer.not_issued'
             for mode in f.contract.MODES for kind in f.contract.KINDS])
        self.assertTrue(any(r.get('unchanged') is False for r in rows))
        self.assertFalse(any('passed' in r for r in rows))

    def test_exact_consumption_subset_hostbits_fallback_and_restart_are_not_filtered(self):
        expected, finished = self.calibration()
        changes = [
            ('api.random.cidr_list.null.lookup.raw', {'sid_login_cidr_shape': 'null', 'sid_login_cidrs': None}),
            ('api.custom.token_bound_cidrs.host_bits.lookup.raw', {'cidrs': ['127.0.0.0/24']}),
            ('subset.random.cidr_list.union_parent.issue', {'status': 200, 'errors': False}),
            ('consume.random.service.two.after_denied.raw', {'secret_id_num_uses': 2}),
            ('source_change.custom.two.current_subset_denial', {'status': 400}),
            ('source_change.custom.two.current_subset_denial', {'subset_error': False}),
            ('override.random.batch.changed_bearer.from_one', {'status': 200, 'errors': False}),
            ('fallback.custom.changed_bearer.from_two', {'status': 403, 'errors': True}),
            ('restart.override.custom.batch.snapshot', {'unchanged': False}),
        ]
        for name, update in changes:
            actual = copy.deepcopy(expected)
            next(row for row in actual if row['case'] == name).update(update)
            self.assertFalse(f.complete(actual, finished, expected), name)
            # Two equal failing implementations cannot replace the oracle calibration.
            other = copy.deepcopy(actual)
            self.assertEqual(actual, other)
            self.assertFalse(f.complete(other, finished, expected), name)

    def test_one_use_denial_does_not_become_a_fictitious_successful_bearer_test(self):
        expected, finished = self.calibration()
        self.assertFalse(f.complete([r for r in expected if 'credential_issued' not in r], finished, expected))
        for update in ({'credential_issued': True}, {'credential_issued': 0}, {'passed': True}, {'status': 200}):
            rows = copy.deepcopy(expected)
            next(r for r in rows if 'credential_issued' in r).update(update)
            self.assertFalse(f.safe_rows(rows))
        rows = copy.deepcopy(expected)
        next(r for r in rows if 'credential_issued' in r)['case'] = 'consume.random.service.two.issued_bearer.not_issued'
        self.assertFalse(f.safe_rows(rows))

    def test_rows_and_scenarios_must_match_without_a_separate_count_gate(self):
        rows, finished = self.calibration()
        for actual in ([], rows[:-1], rows+rows[:1], list(reversed(rows))):
            self.assertFalse(f.complete(actual, finished, rows))
        for phases in (None, finished[:-1], finished+finished[:1], [True]):
            self.assertFalse(f.complete(rows, phases, rows))
        # Future qualified additions need a calibrated row, not a second count constant.
        extra = {'case': 'new.snapshot', 'unchanged': True}
        self.assertTrue(f.complete(rows+[extra], finished, rows+[extra]))

    def test_untrusted_fields_error_bodies_and_non_socket_source_claims_are_rejected(self):
        expected, _ = self.calibration()
        for update in ({'status': True}, {'source_ipv4': False}, {'source_error': 'private'},
                       {'subset_error': 1}, {'raw_errors': ['secret']}, {'token': 'secret'},
                       {'sid_login_cidr_shape': 'list', 'sid_login_cidrs': ['not-public']}):
            rows = copy.deepcopy(expected); rows[0].update(update)
            self.assertFalse(f.safe_rows(rows), update)
        for row in ({'case': 'unrelated', 'unchanged': True},
                    {'case': 'test.pair', 'both_present': True},
                    {'case': 'test.snapshot', 'unchanged': 1}):
            self.assertFalse(f.safe_rows([row]))

    def test_calibration_rejects_unqualified_or_changed_provenance(self):
        original = json.loads(f.CALIBRATION_PATH.read_text())
        def digest(path):
            return f.CONTRACT_SHA256 if Path(path) == Path(f.contract.__file__) else f.CALIBRATION_SHA256
        for key, value in [('status', 'passed'), ('oracle_only', False), ('candidate_executed', True),
                           ('source_qualified', True), ('inputs_unchanged', False), ('secrets_absent', False),
                           ('processes_stopped', False), ('failure', 'failed'), ('failure_at', 'case'),
                           ('runner_sha256', '0'*64), ('completed_scenarios', [])]:
            changed = copy.deepcopy(original); changed[key] = value
            with patch.object(f, 'file_hash', digest), patch.object(Path, 'read_text', return_value=json.dumps(changed)):
                with self.assertRaises(ValueError, msg=key): f.calibrated_rows()
        with patch.object(f, 'file_hash', return_value='0'*64):
            with self.assertRaises(ValueError): f.calibrated_rows()


if __name__ == '__main__': unittest.main()
