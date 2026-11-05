import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import approle_kubernetes_batch_upgrade as f


class Batch42UpgradeGuards(unittest.TestCase):
    def test_real_qualified_schema41_receipt_and_binary_pin_required(self):
        receipt = json.loads(f.LEGACY_RECEIPT.read_text())
        digest = f.file_hash(f.LEGACY_RECEIPT)
        f.admit_legacy(receipt, digest)
        for field, value in (('status', 'failed'), ('build_source_commit', '0'*40),
                             ('runner_unchanged', False), ('source_and_binary_unchanged', 1),
                             ('helpers_unchanged', False), ('cases_match', False)):
            wrong = copy.deepcopy(receipt); wrong[field] = value
            with self.assertRaises(ValueError): f.admit_legacy(wrong, digest)
        with self.assertRaises(ValueError): f.admit_legacy(receipt, '0'*64)
        wrong = copy.deepcopy(receipt); wrong['cases']['candidate'].pop()
        with self.assertRaises(ValueError): f.admit_legacy(wrong, digest)
        wrong = copy.deepcopy(receipt); wrong['candidate_source']['binary_sha256'] = '0'*64
        with self.assertRaises(ValueError): f.admit_legacy(wrong, digest)

    def test_named_milestones_reject_missing_duplicate_or_secret_rows(self):
        rows = [{'case': k, 'passed': True} for k in sorted(f.REQUIRED-{'complete'})]+[{'case': 'complete', 'passed': True}]
        self.assertTrue(f.complete(rows))
        for name in f.REQUIRED:
            self.assertFalse(f.complete([row for row in rows if row['case'] != name]), name)
        for bad in ([], rows+rows[-1:], rows[:-1], rows[:-1]+[{'case': 'complete', 'passed': 1}],
                    rows[:-1]+[{'case': 'complete', 'passed': True, 'token': 'sensitive-sentinel'}]):
            self.assertFalse(f.complete(bad))

    def test_role_readback_preserves_native_fields_and_only_removes_invented_period_alias(self):
        old = {'token_ttl': 300, 'token_max_ttl': 600, 'secret_id_num_uses': 3}
        self.assertTrue(f.retained_role(old, old))
        self.assertTrue(f.retained_role({**old, 'token_type': 'default'}, old))
        for wrong in ({**old, 'token_type': 'batch'}, {**old, 'token_type': None},
                      {**old, 'token_ttl': 0}, {**old, 'unexplained': True}):
            self.assertFalse(f.retained_role(wrong, old))
        for period in (0, 30):
            current = {**old, 'token_period': period, 'token_type': 'default'}
            legacy = {**old, 'token_period': period, 'period': period}
            self.assertTrue(f.retained_role(current, legacy))
            self.assertFalse(f.retained_role({**current, 'token_period': 999}, legacy))
            self.assertFalse(f.retained_role(current, {**legacy, 'period': period+1}))
            self.assertFalse(f.retained_role(current, {**legacy, 'period': False}))
            self.assertFalse(f.retained_role({**current, 'period': period}, legacy))

    def test_pending_requires_explicit_nonretryable_outcome_without_credentials(self):
        body = {'lease_id': 'pending-kube/creds/worker/synthetic', 'reconcile_required': True, 'retry_allowed': False}
        self.assertTrue(f.unknown_pending(body))
        for field, value in (('lease_id', ''), ('reconcile_required', False), ('retry_allowed', True),
                             ('auth', {'client_token': 'sensitive-sentinel'}), ('data', {'token': 'sensitive-sentinel'}),
                             ('wrap_info', {'token': 'sensitive-sentinel'})):
            self.assertFalse(f.unknown_pending({**body, field: value}))

    def test_synthetic_tokenrequest_binds_path_bearer_ttl_and_audience(self):
        body = {'apiVersion': 'authentication.k8s.io/v1', 'kind': 'TokenRequest',
                'spec': {'audiences': [f.AUDIENCE], 'expirationSeconds': 600}}
        self.assertTrue(f.valid_token_request(f.REQUEST_PATH, ['Bearer synthetic-manager'], body, 'synthetic-manager'))
        for path, header in ((f.REQUEST_PATH+'/', ['Bearer synthetic-manager']),
                             (f.REQUEST_PATH, ['Bearer other']), (f.REQUEST_PATH, ['Bearer synthetic-manager']*2)):
            self.assertFalse(f.valid_token_request(path, header, body, 'synthetic-manager'))
        for spec in ({'audiences': ['wrong'], 'expirationSeconds': 600},
                     {'audiences': [f.AUDIENCE], 'expirationSeconds': 120}):
            self.assertFalse(f.valid_token_request(f.REQUEST_PATH, ['Bearer synthetic-manager'], {**body, 'spec': spec}, 'synthetic-manager'))

    def test_actual_approle_phase_functions_keep_names_unique_and_fence_before_new_login(self):
        all_rows, events = [], []
        class Instance:
            root = Path('/synthetic-offline/store')
            binary = 'legacy'
            token = 'hvs.synthetic-root'
            def stop(self): events.append(('stop', self.binary))
            def start(self): events.append(('start', self.binary))
        class Trace(f.Trace):
            def __init__(self, instance, rows):
                super().__init__(instance, rows); self.logins = 0
            def call(self, name, method, path, body=None, *, token=None, status=200, **kwargs):
                events.append(('call', name, path, body, status))
                self.check(name+'_status', True, status=status)
                if status >= 400: return {'errors': ['synthetic offline rejection']}
                if path == f.APP_ROLE and method == 'GET': return {'data': {'token_ttl': 300}}
                if path.endswith('/role-id'): return {'data': {'role_id': 'synthetic-role-id'}}
                if path.endswith('/secret-id'): return {'data': {'secret_id': 'synthetic-secret-id', 'secret_id_accessor': 'synthetic-accessor'}}
                if path.endswith('/secret-id/lookup'): return {'data': {'secret_id_num_uses': 3-self.logins}}
                if path == 'auth/approle/login':
                    self.logins += 1
                    kind = 'service' if self.logins == 1 else 'batch'
                    return {'auth': {'client_token': 'hvs.synthetic' if kind == 'service' else 'hvb.synthetic',
                        'token_type': kind, 'accessor': 'synthetic-accessor' if kind == 'service' else '',
                        'renewable': kind == 'service', 'lease_duration': 300, 'entity_id': 'synthetic-entity',
                        'metadata': {'role_name': 'preserved'}}}
                if path == 'auth/token/renew-self':
                    return {'auth': {'client_token': 'hvs.synthetic', 'token_type': 'service',
                                     'accessor': 'synthetic-accessor', 'lease_duration': 90}}
                if path == 'auth/token/lookup-self':
                    batch = token.startswith('hvb.')
                    return {'data': {'id': token, 'type': 'batch' if batch else 'service', 'ttl': 300,
                                     'accessor': '' if batch else 'synthetic-accessor', 'renewable': not batch}}
                if path == 'secret/data/upgrade' and method == 'GET': return {'data': {'data': f.VALUE}}
                return {}
        def initialize(instance, rows, phase): return Trace(instance, rows), 'synthetic-key'
        with (patch.object(f, 'initialize', initialize),
              patch.object(f, 'durable_manifest', return_value='unchanged'),
              patch.object(f, 'safe_files', return_value=True)):
            for mode in ('role', 'mount'):
                f.run_approle(Instance(), 'candidate', 'legacy', all_rows, mode)
                names = [row['case'] for row in all_rows]
                self.assertEqual(len(names), len(set(names)))
                required = {name for name in f.REQUIRED if name.startswith(mode+'_')}
                self.assertTrue(required <= set(names))
                labels = [event[1] for event in events if event[0] == 'call']
                self.assertLess(labels.index(mode+'_format_trigger'), labels.index(mode+'_downgrade_unseal'))
                self.assertLess(labels.index(mode+'_downgrade_unseal'), labels.index(mode+'_new_login'))

    def test_actual_kubernetes_phases_keep_legacy_requests_and_new_owner_fence_separate(self):
        rows, events = [], []
        provider = SimpleNamespace(manager='synthetic-manager', calls=0, valid=True,
                                   mode='normal', tokens=[], last_expiry=None, origin='https://localhost:12345')
        class Instance:
            root = Path('/synthetic-offline/kubernetes')
            binary = 'legacy'
            token = 'hvs.synthetic-root'
            def start(self): pass
            def stop(self): pass
        class Trace(f.Trace):
            def call(self, name, method, path, body=None, *, token=None, status=200, **kwargs):
                events.append((name, method, path, self.instance.binary))
                self.check(name+'_status', True, status=status)
                if '/creds/worker' in path:
                    provider.calls += 1
                    if provider.mode != 'normal':
                        return {'lease_id': 'pending-kube/creds/worker/synthetic',
                                'reconcile_required': True, 'retry_allowed': False}
                    provider.last_expiry = 1600
                    provider.tokens.append('synthetic-tokenrequest-'+str(provider.calls))
                    return {'lease_id': path+'/synthetic', 'renewable': False, 'lease_duration': 120,
                            'data': {'service_account_token': provider.tokens[-1]}}
                if status >= 400: return {'errors': ['synthetic offline rejection']}
                if path == 'auth/token/create-orphan':
                    return {'auth': {'client_token': 'hvb.synthetic', 'token_type': 'batch',
                                     'accessor': '', 'renewable': False, 'lease_duration': 120}}
                if path == 'auth/token/lookup-self':
                    return {'data': {'id': token, 'type': 'batch', 'ttl': 120, 'renewable': False,
                                     'accessor': '', 'expire_time': '1970-01-01T00:18:40Z'}}
                if path == 'sys/leases/lookup':
                    old = body['lease_id'].startswith('legacy-kube/')
                    return {'data': {'issue_time': None if old else '1970-01-01T00:16:40Z',
                                     'expire_time': '1970-01-01T00:26:40Z' if old else '1970-01-01T00:18:20Z'}}
                return {'data': {}}
        with (patch.object(f, 'initialize', lambda i, r, p: (Trace(i, r), 'synthetic-key')),
              patch.object(f, 'durable_manifest', return_value='unchanged'),
              patch.object(f, 'safe_files', return_value=True), patch.object(f.time, 'time', return_value=1000)):
            f.run_kube_legacy(Instance(), 'candidate', rows, provider)
            self.assertEqual(provider.calls, 2)
            provider.calls = 0; provider.tokens = []; provider.last_expiry = None
            f.run_kube_typed(Instance(), 'candidate', 'legacy', rows, provider)
            self.assertEqual(provider.calls, 1)
        names = [r['case'] for r in rows]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue({k for k in f.REQUIRED if k.startswith('kube_')} <= set(names))
        labels = [event[0] for event in events]
        self.assertLess(labels.index('kube_typed_old_issue'), labels.index('kube_typed_issue'))
        self.assertLess(labels.index('kube_typed_issue'), labels.index('kube_typed_downgrade_unseal'))
        calls = [event for event in events if event[2].endswith('/creds/worker')]
        self.assertEqual([event[3] for event in calls], ['legacy', 'legacy', 'candidate'])


if __name__ == '__main__': unittest.main()
