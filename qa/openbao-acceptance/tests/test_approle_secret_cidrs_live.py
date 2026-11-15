import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import approle_secret_cidrs_live as f


class SecretCidrComparisonTests(unittest.TestCase):
    def calibration(self):
        value = json.loads(f.CALIBRATION_PATH.read_text())
        return f.calibrated_rows(), value['completed_scenarios']

    def test_calibration_pins_actual_receipt_and_keeps_all_observations(self):
        rows, finished = self.calibration()
        self.assertEqual(f.file_hash(f.CALIBRATION_PATH), f.CALIBRATION_SHA256)
        self.assertTrue(f.complete(rows, finished, rows))
        self.assertEqual([row for row in rows if row.get('not_run')], [
            {'case': 'consume.service.one.issued_foreign_use_pending', 'not_run': True, 'reason': 'no_issued_token'},
            {'case': 'consume.batch.one.issued_foreign_use_pending', 'not_run': True, 'reason': 'no_issued_token'}])
        self.assertNotIn('passed', rows[0])

    def test_failure_consumption_nil_alias_priority_and_status_are_not_filtered(self):
        expected, finished = self.calibration()
        changes = [
            ('api.whole.initial.field', {'role_login_cidr_shape': 'list', 'role_login_cidrs': []}),
            ('api.whole.null.write', {'status': 400, 'errors': True}),
            ('api.field.null.write', {'status': 204, 'errors': False}),
            ('api.alias_priority.native_null.whole', {'role_login_cidr_shape': 'list', 'role_login_cidrs': ['127.0.0.1/32']}),
            ('api.alias_field.after_delete.field', {'role_login_cidr_shape': 'null'}),
            ('constraints.delete.clear', {'status': 204, 'errors': False}),
            ('consume.service.two.after_denied', {'secret_id_num_uses': 2}),
            ('consume.batch.one.after_denied', {'status': 200, 'data': True}),
            ('lifecycle.service.restricted_other_bearer', {'status': 403, 'data': False, 'errors': True}),
            ('restart.batch.restricted_original', {'status': 200, 'data': True, 'errors': False}),
        ]
        for name, update in changes:
            actual = copy.deepcopy(expected)
            next(row for row in actual if row['case'] == name).update(update)
            self.assertEqual(len(actual), len(expected))
            self.assertFalse(f.complete(actual, finished, expected), name)

    def test_absent_issuance_branch_cannot_be_removed_or_claimed_as_executed(self):
        expected, finished = self.calibration()
        removed = [row for row in expected if not row.get('not_run')]
        self.assertFalse(f.complete(removed, finished, expected))
        for update in ({'not_run': False}, {'passed': True}, {'reason': 'skipped'}, {'status': 200}):
            actual = copy.deepcopy(expected)
            next(row for row in actual if row.get('not_run')).update(update)
            self.assertFalse(f.safe_rows(actual), update)
        actual = copy.deepcopy(expected)
        row = next(row for row in actual if row.get('not_run'))
        row['case'] = 'consume.service.two.issued_foreign_use_pending'
        self.assertFalse(f.safe_rows(actual))

    def test_secret_or_untrusted_projection_and_incomplete_graph_fail_closed(self):
        expected, finished = self.calibration()
        for rows in ([], expected[:-1], expected+expected[:1], list(reversed(expected))):
            self.assertFalse(f.complete(rows, finished, expected))
        for phases in (None, finished[:-1], finished+finished[:1], [True]):
            self.assertFalse(f.complete(expected, phases, expected))
        for update in ({'status': True}, {'source_ipv4': False}, {'warnings': 'private-error'},
                       {'token': 'synthetic-secret'}, {'role_login_cidr_shape': 'list', 'role_login_cidrs': ['not-public']},
                       {'role_login_cidr_shape': 'null', 'role_login_cidrs': []}):
            rows = copy.deepcopy(expected); rows[0].update(update)
            self.assertFalse(f.safe_rows(rows), update)

    def test_calibration_rejects_changed_evidence_provenance_or_pending_branch(self):
        original = json.loads(f.CALIBRATION_PATH.read_text())
        def digest(path):
            return f.CONTRACT_SHA256 if Path(path) == Path(f.contract.__file__) else f.CALIBRATION_SHA256
        for key, value in [('status', 'passed'), ('oracle_only', False), ('source_qualified', True),
                           ('inputs_unchanged', False), ('secrets_absent', False), ('processes_stopped', False),
                           ('failure', 'failed'), ('failure_at', 'case'), ('pending_cases', []),
                           ('runner_sha256', '0'*64)]:
            changed = copy.deepcopy(original); changed[key] = value
            with patch.object(f, 'file_hash', digest), patch.object(Path, 'read_text', return_value=json.dumps(changed)):
                with self.assertRaises(ValueError, msg=key): f.calibrated_rows()
        with patch.object(f, 'file_hash', return_value='0'*64):
            with self.assertRaises(ValueError): f.calibrated_rows()


if __name__ == '__main__': unittest.main()
