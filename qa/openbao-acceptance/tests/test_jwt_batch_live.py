import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import jwt_batch_live as f


class JwtBatchComparisonGuards(unittest.TestCase):
    def test_actual_official_calibration_is_complete_and_bound_to_frozen_probe(self):
        rows = f.calibrated_rows()
        receipt = json.loads(f.CALIBRATION_PATH.read_text())
        self.assertEqual(f.file_hash(f.CALIBRATION_PATH), f.CALIBRATION_SHA256)
        self.assertTrue(f.complete(rows, receipt['completed_scenarios'], rows))
        self.assertTrue(f.safe_rows(rows))

    def test_same_count_cannot_hide_null_mount_forcing_metadata_or_lifecycle_differences(self):
        expected = f.calibrated_rows()
        finished = json.loads(f.CALIBRATION_PATH.read_text())['completed_scenarios']
        for name, change in [
            ('type.null.write', {'status': 400, 'errors': True}),
            ('partial.null.read', {'configured_type': {'shape': 'string', 'value': 'batch'}}),
            ('alias.default_batch.write', {'status': 204, 'errors': False}),
            ('matrix.service.batch.login', {'auth_type': {'shape': 'string', 'value': 'batch'}}),
            ('forced.period.login', {'lease_le_30': False}),
            ('forced.uses.lookup', {'num_uses': 2}),
            ('explicit.cap.lookup', {'explicit_max_ttl': 20}),
            ('identity.binding', {'alias_role_metadata': False}),
            ('reuse.relationship', {'fresh_bearer': False}),
            ('wrapped.second_unwrap', {'status': 200}),
            ('rejected_assertions.entity_set', {'readable': False, 'unchanged': True}),
            ('batch.mount_disabled.kv', {'status': 403}),
            ('restart.lookup', {'lookup_role_metadata': False}),
        ]:
            rows = copy.deepcopy(expected)
            next(row for row in rows if row['case'] == name).update(change)
            self.assertEqual(len(rows), len(expected))
            self.assertFalse(f.complete(rows, finished, expected), name)

    def test_empty_duplicate_unfinished_and_unsafe_values_cannot_pass(self):
        expected = f.calibrated_rows()
        finished = json.loads(f.CALIBRATION_PATH.read_text())['completed_scenarios']
        for rows in ([], expected[:-1], expected+expected[:1], list(reversed(expected))):
            self.assertFalse(f.complete(rows, finished, expected))
        for phases in (None, [], finished[:-1], finished+finished[:1], [True]):
            self.assertFalse(f.complete(expected, phases, expected))
        for values in ({'status': True}, {'auth': 1}, {'token_num_uses': False},
                {'response_absent': True}, {'token': 'synthetic-sensitive'},
                {'auth_type': {'shape': 'string', 'value': 'synthetic-sensitive'}},
                {'auth_type': {'shape': 'null', 'value': 'batch'}}):
            rows = copy.deepcopy(expected); rows[0].update(values)
            self.assertFalse(f.safe_rows(rows))
        relationship = next(row for row in expected if row['case'] == 'reuse.relationship')
        self.assertFalse(f.safe_rows([dict(relationship, same_entity='synthetic-sensitive')]))

    def test_calibration_rejects_changed_provenance_and_probe_hash(self):
        original = json.loads(f.CALIBRATION_PATH.read_text())
        def digest(path):
            return f.CONTRACT_SHA256 if Path(path) == Path(f.contract.__file__) else f.CALIBRATION_SHA256
        for key, value in [('status', 'passed'), ('target_version', '2.6.3'), ('oracle_only', False),
                ('source_qualified', True), ('inputs_unchanged', False), ('secrets_absent', False),
                ('processes_stopped', False), ('runner_sha256', '0'*64), ('failure', 'failed'),
                ('failure_at', 'failed')]:
            changed = copy.deepcopy(original); changed[key] = value
            with patch.object(f, 'file_hash', digest), patch.object(Path, 'read_text', return_value=json.dumps(changed)):
                with self.assertRaises(ValueError, msg=key): f.calibrated_rows()
        with patch.object(f, 'file_hash', return_value='0'*64):
            with self.assertRaises(ValueError): f.calibrated_rows()

    def test_only_exact_static_key_config_is_adapted_once_other_requests_are_unchanged(self):
        private, jwk = f.signing_key('ES256', 'offline')
        calls = []
        client = f.StaticConfigClient(SimpleNamespace(request=lambda *a, **k: calls.append((a, k))), private, jwk)
        config = {'bound_issuer': f.contract.ISSUER, 'jwt_validation_pubkeys': [client.pem],
                  'jwt_supported_algs': ['ES256']}
        target = '/v1/auth/'+f.contract.MOUNT+'/config'
        client.request('POST', target, config, token='synthetic-root', wrap_ttl=None)
        self.assertEqual(calls[0], (('POST', target, {'issuer': f.contract.ISSUER,
            'audiences': ['heptabao-test'], 'jwks': {'keys': [jwk]}}), {'token': 'synthetic-root', 'wrap_ttl': None}))
        role = {'role_type': 'jwt', 'token_type': None}
        client.request('POST', '/v1/auth/'+f.contract.MOUNT+'/role/test', role, token='', wrap_ttl='60s')
        self.assertIs(calls[1][0][2], role)
        self.assertEqual(calls[1][1], {'token': '', 'wrap_ttl': '60s'})
        self.assertEqual(client.adaptations, 1)
        with self.assertRaises(ValueError): client.request('POST', target, config)
        other = f.StaticConfigClient(SimpleNamespace(request=lambda *a, **k: self.fail('must not send')), private, jwk)
        with self.assertRaises(ValueError): other.request('POST', target, dict(config, jwks_url='https://wrong.invalid'))


if __name__ == '__main__': unittest.main()
