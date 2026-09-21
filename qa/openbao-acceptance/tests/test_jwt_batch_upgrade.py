import copy
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import jwt_batch_upgrade as f


class JwtBatchUpgradeGuards(unittest.TestCase):
    def test_actual_legacy_receipt_and_binary_are_pinned(self):
        receipt = json.loads(f.LEGACY_RECEIPT.read_text())
        f.admit_legacy(receipt, f.file_hash(f.LEGACY_RECEIPT))
        for key, value in [('status', 'failed'), ('build_source_commit', '0'*40),
            ('oracle_only', True), ('source_and_binary_unchanged', False), ('inputs_unchanged', False),
            ('cases_match', False), ('secrets_absent', {'candidate': True}), ('failures', {'candidate': 'failed'})]:
            changed = copy.deepcopy(receipt); changed[key] = value
            with self.assertRaises(ValueError, msg=key): f.admit_legacy(changed, f.LEGACY_RECEIPT_SHA256)
        changed = copy.deepcopy(receipt); changed['candidate_source']['binary_sha256'] = '0'*64
        with self.assertRaises(ValueError): f.admit_legacy(changed, f.LEGACY_RECEIPT_SHA256)
        with self.assertRaises(ValueError): f.admit_legacy(receipt, '0'*64)

    def test_retained_role_only_permits_new_default_readback(self):
        old = {'token_ttl': 900, 'token_max_ttl': 1800, 'token_policies': ['legacy']}
        self.assertTrue(f.retained_role(dict(old, token_type='default'), old))
        for changed in (old, dict(old, token_type='batch'), dict(old, token_type='default', token_ttl=0)):
            self.assertFalse(f.retained_role(changed, old))
        self.assertFalse(f.retained_role(dict(old, token_type='default'), dict(old, token_type='default')))

    def test_old_service_only_allows_ttl_countdown_and_derived_role_metadata(self):
        old = {'ttl': 900, 'creation_time': 1000, 'expire_time_unix': 1900,
               'display_name': 'jwt-historical-hash', 'explicit_max_ttl': 1200, 'type': 'service'}
        current = dict(old, ttl=899, meta={'role': f.ROLE})
        self.assertTrue(f.retained_service(current, old))
        for change in ({'display_name': f.MOUNT+'-'+f.SUBJECT}, {'creation_time': 1001},
            {'expire_time_unix': 1901}, {'explicit_max_ttl': 1800}, {'type': 'batch'},
            {'meta': {'role': 'other'}}, {'ttl': 0}, {'ttl': True}):
            self.assertFalse(f.retained_service(dict(current, **change), old), change)
        self.assertFalse(f.retained_service(current, dict(old, meta={'role': f.ROLE})))

    def test_each_first_transition_is_one_request_and_alias_does_not_configure_types(self):
        for mode in f.MODES:
            t = Model(SimpleNamespace(binary='candidate'), [])
            t.role = {'token_ttl': 900}; old = {'assertion': 'private-assertion'}
            f.first_mutation(t, mode, old)
            self.assertEqual(len(t.calls), 1)
            name, method, route, body, kwargs = t.calls[0]
            self.assertEqual(name, mode+'_first_mutation'); self.assertEqual(method, 'POST')
            if mode == 'role':
                self.assertEqual((route, body), (f.ROLE_PATH, {'role_type': 'jwt', 'token_type': 'batch'}))
            elif mode == 'mount':
                self.assertEqual((route, body), ('sys/auth/'+f.MOUNT+'/tune', {'token_type': 'batch'}))
            else:
                self.assertEqual((route, body), (f.LOGIN_PATH, {'role': f.ROLE, 'jwt': 'private-assertion'}))
                self.assertEqual(kwargs.get('token'), '')

    def test_real_store_phases_keep_reader_fence_immediate_and_names_unique(self):
        rows = []
        for mode in f.MODES:
            instance = SimpleNamespace(binary='legacy', root=f.Path('/unused-test-store'),
                start=lambda: None, stop=lambda: None)
            t = Model(instance, rows)
            with patch.object(f, 'initialize', return_value=(t, 'private-unseal')), \
                 patch.object(f, 'durable_manifest', return_value='fixed-files'), \
                 patch.object(f, 'safe_files', return_value=True):
                f.run_store(instance, 'candidate', 'legacy', rows, mode)
            names = [call[0] for call in t.calls]
            first = names.index(mode+'_first_mutation')
            self.assertEqual(names[first+1], mode+'_first_downgrade_unseal')
            self.assertEqual(names[first-1], mode+'_before_first_mutation_unseal')
            # The actual old seed request contains no future role/mount type.
            seed_calls = {name: (route, body) for name, method, route, body, _ in t.calls
                          if method == 'POST' and name in (mode+'_role', mode+'_tune')}
            self.assertTrue(seed_calls)
            self.assertTrue(all('token_type' not in body for route, body in seed_calls.values()))
            if mode == 'alias':
                posts = [body for name, method, route, body, _ in t.calls
                         if method == 'POST' and route in (f.ROLE_PATH, 'sys/auth/'+f.MOUNT+'/tune')]
                self.assertTrue(all('token_type' not in body for body in posts))
                self.assertIn('alias_retained_downgrade_unseal', names)
            required = {name for name in f.REQUIRED if name.startswith(mode+'_')}
            self.assertTrue(required <= {row['case'] for row in rows}, required-{row['case'] for row in rows})
        rows.extend([{'case': 'processes_stopped', 'passed': True}, {'case': 'complete', 'passed': True}])
        self.assertTrue(f.complete(rows)); self.assertEqual(len(rows), len({r['case'] for r in rows}))
        self.assertNotIn('private-unseal', json.dumps(rows))
        for malformed in ([], rows[:-1], rows+rows[:1], rows[:-2]+rows[-1:]): self.assertFalse(f.complete(malformed))


class Model(f.Trace):
    """Offline request-order model, not a substitute for either real binary."""
    def __init__(self, instance, rows):
        super().__init__(instance, rows)
        self.calls, self.role, self.tokens, self.serial, self.mount_type = [], {}, {}, 0, 'default-service'
        self.alias = {'id': 'opaque-alias', 'canonical_id': 'opaque-entity', 'name': f.SUBJECT,
                      'mount_accessor': 'opaque-accessor', 'custom_metadata': {}, 'metadata': {}}

    def call(self, name, method, route, body=None, **kwargs):
        self.calls.append((name, method, route, copy.deepcopy(body), kwargs))
        self.check(name+'_status', True, status=kwargs.get('status', 200))
        current = self.instance.binary == 'candidate'
        if route == f.ROLE_PATH:
            if method == 'POST': self.role.update(body)
            if method == 'GET':
                value = dict(self.role)
                if current: value.setdefault('token_type', 'default')
                return {'data': value}
        elif route == 'sys/auth/'+f.MOUNT+'/tune':
            if method == 'POST': self.mount_type = body.get('token_type', self.mount_type)
            if method == 'GET': return {'data': {'token_type': self.mount_type}}
        elif route == f.LOGIN_PATH:
            batch = current and (self.mount_type == 'batch' or self.role.get('token_type') == 'batch')
            kind = 'batch' if batch else 'service'; self.serial += 1
            raw = ('hvb.' if batch else 'hvs.')+'synthetic-token-'+str(self.serial)
            auth = {'client_token': raw, 'accessor': '' if batch else 'accessor-'+str(self.serial),
                'token_type': kind, 'lease_duration': 900, 'renewable': not batch, 'entity_id': 'opaque-entity', 'orphan': True}
            if current:
                auth['metadata'] = {'role': f.ROLE}; self.alias['metadata'] = {'role': f.ROLE}
            self.tokens[raw] = {'id': raw, 'accessor': auth['accessor'], 'type': kind, 'ttl': 900,
                'renewable': not batch, 'creation_time': 1000, 'expire_time_unix': 1900,
                'explicit_max_ttl': 1200, 'entity_id': 'opaque-entity',
                'display_name': f.MOUNT+'-'+f.SUBJECT if current else 'jwt-historical-hash'}
            return {'auth': auth}
        elif route.startswith('identity/entity-alias/id/'):
            if method == 'POST': self.alias.update(body)
            if method == 'GET': return {'data': copy.deepcopy(self.alias)}
        elif route.startswith('identity/entity/id/'):
            return {'data': {'aliases': [copy.deepcopy(self.alias)]}}
        elif route == 'auth/token/lookup-self':
            info = dict(self.tokens[kwargs['token']])
            if current: info['meta'] = {'role': f.ROLE}
            return {'data': info}
        elif route.startswith('auth/token/renew') and kwargs.get('status', 200) == 200:
            raw = kwargs.get('token') or body.get('token')
            if raw is None:
                raw = next(raw for raw, info in self.tokens.items() if info['accessor'] == body['accessor'])
            auth = {'client_token': None if route.endswith('renew-accessor') else raw,
                    'token_type': 'service', 'renewable': True, 'lease_duration': 600}
            return {'auth': auth}
        elif route == 'secret/data/upgrade':
            return {'data': {'data': {'value': 'synthetic-upgrade-value'}}}
        return {}


if __name__ == '__main__': unittest.main()
