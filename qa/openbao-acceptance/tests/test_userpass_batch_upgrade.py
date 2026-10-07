import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import userpass_batch_upgrade as fixture


class UpgradeGuards(unittest.TestCase):
    def receipt(self):
        return json.loads(fixture.LEGACY_RECEIPT.read_text())

    def test_actual_qualified_default_binary_receipt_is_admitted_and_bound(self):
        receipt = self.receipt()
        fixture.admit_legacy_receipt(receipt)
        for field, value in [('status', 'failed'), ('oracle_only', True), ('cases_match', False),
                             ('helpers_unchanged', False), ('runner_unchanged', False),
                             ('build_source_commit', 'a'*40)]:
            altered = copy.deepcopy(receipt)
            altered[field] = value
            with self.assertRaises(ValueError):
                fixture.admit_legacy_receipt(altered)
        for field, value in [('binary_sha256', 'a'*64), ('source_commit', 'a'*40), ('source_dirty', True)]:
            altered = copy.deepcopy(receipt)
            altered['candidate_source'][field] = value
            altered['candidate_source_after'] = copy.deepcopy(altered['candidate_source'])
            with self.assertRaises(ValueError):
                fixture.admit_legacy_receipt(altered)

    def test_receipt_cannot_drop_actual_profile_or_hide_known_deviations(self):
        for mode in ('early', 'arbitrary', 'missing_deviations', 'failed_deviation'):
            altered = self.receipt()
            if mode == 'early':
                for side in altered['cases'].values():
                    side.pop()
            elif mode == 'arbitrary':
                altered['cases'] = {side: [{'case': 'arbitrary', 'passed': True}] for side in ('oracle', 'candidate')}
            elif mode == 'missing_deviations':
                altered['deliberate_divergences'] = {}
            else:
                altered['deliberate_divergences']['candidate'][0]['passed'] = False
            with self.assertRaises(ValueError):
                fixture.admit_legacy_receipt(altered)

    def test_only_new_default_readback_field_may_differ_from_old_config(self):
        old = {'token_ttl': 900, 'token_max_ttl': 1200, 'token_policies': ['reader']}
        self.assertTrue(fixture.retained_config(old, old))
        self.assertTrue(fixture.retained_config(dict(old, token_type='default'), old))
        for current in [dict(old, token_type='batch'), dict(old, token_ttl=0), dict(old, invented=True), None]:
            self.assertFalse(fixture.retained_config(current, old))

    def test_sensitive_trace_names_and_values_are_not_printed(self):
        t = object.__new__(fixture.Trace)
        t.rows = []
        with self.assertRaises(ValueError):
            t.check('secret/raw-password', True)
        with self.assertRaises(ValueError):
            t.check('safe', True, status='sensitive-response')
        self.assertEqual(t.rows, [])
        t.check('safe', True, status=200)
        self.assertEqual(t.rows, [{'case': 'safe', 'passed': True, 'status': 200}])

    def test_batch_response_requires_no_accessor_and_service_token_requires_accessor(self):
        t = object.__new__(fixture.Trace)
        t.rows, t.sensitive = [], []
        body = {'auth': {'client_token': 'hvb.synthetic', 'accessor': '', 'token_type': 'batch',
                         'lease_duration': 60, 'renewable': False}}
        t.issued('batch', body, 'batch')
        for field, value in [('accessor', 'leaked-accessor'), ('renewable', True),
                             ('lease_duration', True), ('client_token', 'hvs.synthetic')]:
            bad = copy.deepcopy(body)
            bad['auth'][field] = value
            with self.assertRaises(fixture.ScenarioFailure):
                t.issued('bad_'+field, bad, 'batch')
        service = copy.deepcopy(body)
        service['auth'].update(client_token='hvs.synthetic', token_type='service')
        with self.assertRaises(fixture.ScenarioFailure):
            t.issued('missing_service_accessor', service, 'service')

    def test_real_scenario_function_case_names_are_unique_and_fresh_backup_precedes_issue(self):
        # An offline response model runs the actual scenario functions solely
        # to check flow/milestone labels. It is not binary/HTTP qualification.
        class Instance:
            def __init__(self):
                self.root, self.binary, self.token = Path('/fixture-not-accessed'), Path('/old'), ''
            def start(self): pass
            def stop(self): pass
            def call(self, method, path, body):
                return 200, {'root_token': 'hvs.root-synthetic', 'keys_base64': ['synthetic-unseal']}

        class ModelTrace(fixture.Trace):
            orders = []
            def __init__(self, instance, rows):
                super().__init__(instance, rows)
                self.tokens, self.modes, self.sequence = {}, {}, 0
            def auth(self, kind):
                self.sequence += 1
                auth = {'client_token': ('hvb.' if kind == 'batch' else 'hvs.')+str(self.sequence),
                        'accessor': '' if kind == 'batch' else 'accessor-'+str(self.sequence),
                        'token_type': kind, 'lease_duration': 900, 'renewable': kind != 'batch'}
                self.tokens[auth['client_token']] = auth
                return {'auth': auth}
            def call(self, name, method, path, body=None, *, token=None, namespace='', status=200):
                self.orders.append((name, method, path))
                self.check(name+'_status', True, status=status)
                if status >= 400:
                    self.check(name+'_no_credentials', True)
                    return {}
                if path.endswith('/users/alice'):
                    if method == 'GET':
                        return {'data': {'token_ttl': 900, 'token_max_ttl': 1200}}
                    if body.get('token_type'):
                        self.modes[namespace] = body['token_type']
                if '/login/' in path:
                    return self.auth(self.modes.get(namespace, 'service'))
                if path == 'auth/token/create-orphan':
                    return self.auth('batch')
                if path == 'auth/token/lookup-self':
                    auth = self.tokens[token]
                    return {'data': {'id': token, 'accessor': auth['accessor'], 'type': auth['token_type'],
                                     'ttl': 600, 'renewable': auth['renewable']}}
                if path == 'secret/data/upgrade':
                    return {'data': {'data': {'value': 'synthetic-upgrade-value'}}}
                if path == 'upgrade-ssh/creds/deploy':
                    self.sequence += 1
                    return {'data': {'key': 'synthetic-otp-'+str(self.sequence)},
                            'lease_id': 'upgrade-ssh/creds/deploy/'+str(self.sequence), 'lease_duration': 600}
                if path == 'sys/leases/lookup':
                    return {'data': {'id': body['lease_id'], 'renewable': False, 'ttl': 600}}
                if path == 'upgrade-ssh/verify':
                    return {'data': {'ip': '127.0.0.1', 'username': 'deploy', 'role_name': 'deploy'}}
                if path == 'sys/storage/raft/snapshot':
                    return {'data': {'snapshot': 'encrypted-fixture-placeholder', 'format': 'heptabao-encrypted-backup-v1'}}
                return {}

        rows = []
        with patch.object(fixture, 'Trace', ModelTrace), patch.object(fixture, 'durable_manifest', return_value='same'), patch.object(fixture, 'safe_files', return_value=True):
            fixture.run_upgrade(Instance(), Path('/new'), Path('/old'), rows)
            fixture.run_ssh(Instance(), Path('/new'), rows)
            fixture.run_fresh(Instance(), Path('/new'), rows)
            ModelTrace(Instance(), rows).check('complete', True)
        names = [row['case'] for row in rows]
        self.assertEqual(fixture.REQUIRED-set(names), set())
        self.assertEqual(len(names), len(set(names)), [name for name in set(names) if names.count(name) > 1])
        self.assertTrue(fixture.complete(rows))
        orders = [name for name, _, _ in ModelTrace.orders]
        self.assertLess(orders.index('fresh_pre_batch_archive'), orders.index('fresh_issue'))
        self.assertLess(orders.index('fresh_issue'), orders.index('fresh_restore'))
        self.assertLess(orders.index('fresh_restore'), orders.index('fresh_after_restore_batch'))
        for milestone in fixture.REQUIRED:
            self.assertFalse(fixture.complete([row for row in rows if row['case'] != milestone]))
        self.assertFalse(fixture.complete(rows+[rows[0]]))
        leaked = copy.deepcopy(rows)
        leaked[0]['raw_body'] = 'synthetic-secret'
        self.assertFalse(fixture.complete(leaked))

    def test_old_reader_claim_only_follows_actual_attempt_row(self):
        self.assertFalse(fixture.old_reader_observed([]))
        self.assertFalse(fixture.old_reader_observed([{'case': 'old_read_control_unseal_status', 'passed': True}]))
        self.assertTrue(fixture.old_reader_observed([{'case': 'downgrade_unseal_status', 'passed': False}]))
        self.assertTrue(fixture.old_reader_observed([{'case': 'first_batch_downgrade_unseal_status', 'passed': True}]))


if __name__ == '__main__':
    unittest.main()
