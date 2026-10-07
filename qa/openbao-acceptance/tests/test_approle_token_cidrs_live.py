import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import approle_token_cidrs_live as f


class AppRoleTokenCidrsEvidenceTests(unittest.TestCase):
    def test_actual_official_calibration_has_complete_named_scenarios_and_exact_digest(self):
        rows = f.calibrated_rows()
        receipt = json.loads(f.CALIBRATION_PATH.read_text())
        self.assertEqual(f.file_hash(f.CALIBRATION_PATH), f.CALIBRATION_SHA256)
        self.assertTrue(f.complete(rows, receipt['completed_scenarios'], rows))
        self.assertTrue(f.safe_rows(rows))

    def test_equal_case_counts_cannot_hide_nil_empty_constraint_or_source_behavior_changes(self):
        expected = f.calibrated_rows()
        finished = json.loads(f.CALIBRATION_PATH.read_text())['completed_scenarios']
        changes = [
            ('api.whole.initial_field', {'cidr_shape': 'list', 'cidrs': []}),
            ('api.field.null.field', {'cidr_shape': 'null', 'cidrs': None}),
            ('constraints.fresh_omitted.write', {'status': 204, 'errors': False}),
            ('constraints.existing_empty.after_whole', {'bind_secret_id': False}),
            ('lifecycle.service.foreign_login', {'status': 403, 'auth': False}),
            ('lifecycle.batch.sid_after_login', {'secret_id_num_uses': 3}),
            ('lifecycle.service.service_child.foreign_read', {'status': 200}),
            ('lifecycle.service.batch_orphan.foreign_read', {'status': 403}),
            ('lifecycle.service.old_snapshot_after_renew', {'cidrs': []}),
        ]
        for name, update in changes:
            actual = copy.deepcopy(expected)
            next(row for row in actual if row['case'] == name).update(update)
            self.assertEqual(len(actual), len(expected))
            self.assertFalse(f.complete(actual, finished, expected), name)

    def test_missing_duplicate_unfinished_or_untrusted_rows_cannot_pass(self):
        expected = f.calibrated_rows()
        finished = json.loads(f.CALIBRATION_PATH.read_text())['completed_scenarios']
        for actual in ([], expected[:-1], expected+expected[:1], list(reversed(expected))):
            self.assertFalse(f.complete(actual, finished, expected))
        for phases in (None, [], finished[:-1], finished+finished[:1], [True]):
            self.assertFalse(f.complete(expected, phases, expected))
        for update in ({'status': True}, {'auth': 1}, {'cidr_shape': 'list', 'cidrs': None},
                       {'cidr_shape': 'null', 'cidrs': []}, {'token': 'synthetic-secret'},
                       {'cidr_shape': 'list', 'cidrs': ['synthetic-sensitive-value']}):
            rows = copy.deepcopy(expected); rows[0].update(update)
            self.assertFalse(f.safe_rows(rows))

    def test_calibration_fails_closed_if_artifact_or_provenance_contract_changes(self):
        original = json.loads(f.CALIBRATION_PATH.read_text())
        def digest(path):
            return f.CONTRACT_SHA256 if Path(path) == Path(f.contract.__file__) else f.CALIBRATION_SHA256
        for key, value in [('status', 'passed'), ('target_version', '2.6.3'), ('oracle_only', False),
                           ('source_qualified', True), ('inputs_unchanged', False),
                           ('secrets_absent', False), ('processes_stopped', False),
                           ('runner_sha256', '0'*64), ('failure', 'failed'), ('failure_at', 'case')]:
            changed = copy.deepcopy(original); changed[key] = value
            with patch.object(f, 'file_hash', digest), patch.object(Path, 'read_text', return_value=json.dumps(changed)):
                with self.assertRaises(ValueError, msg=key): f.calibrated_rows()
        with patch.object(f, 'file_hash', return_value='0'*64):
            with self.assertRaises(ValueError): f.calibrated_rows()


if __name__ == '__main__': unittest.main()
