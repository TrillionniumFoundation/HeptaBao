import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import approle_cidrs_upgrade as f


class AppRoleCidrUpgradeGuards(unittest.TestCase):
    def test_actual_legacy_receipt_requires_exact_binary_clean_source_and_complete_both_lanes(self):
        receipt = json.loads(f.LEGACY_RECEIPT.read_text())
        digest = f.file_hash(f.LEGACY_RECEIPT)
        f.admit_legacy(receipt, digest)
        for field, value in (('status', 'failed'), ('build_source_commit', '0'*40),
                             ('source_and_binary_unchanged', 1), ('equal_lane_matches', False),
                             ('helpers_unchanged', False), ('oracle_binary_unchanged', False)):
            bad = copy.deepcopy(receipt); bad[field] = value
            with self.assertRaises(ValueError): f.admit_legacy(bad, digest)
        bad = copy.deepcopy(receipt); bad['cases']['candidate'].pop()
        with self.assertRaises(ValueError): f.admit_legacy(bad, digest)
        bad = copy.deepcopy(receipt); bad['candidate_source']['binary_sha256'] = '0'*64
        with self.assertRaises(ValueError): f.admit_legacy(bad, digest)
        with self.assertRaises(ValueError): f.admit_legacy(receipt, '0'*64)

    def test_named_required_safety_phases_cannot_be_removed_or_secret_material_added(self):
        rows = [{'case': k, 'passed': True} for k in sorted(f.REQUIRED-{'complete'})]+[{'case': 'complete', 'passed': True}]
        self.assertTrue(f.complete(rows))
        for name in f.REQUIRED:
            self.assertFalse(f.complete([row for row in rows if row['case'] != name]), name)
        for bad in (rows+rows[-1:], rows[:-1], rows[:-1]+[{'case': 'complete', 'passed': 1}],
                    rows[:-1]+[{'case': 'complete', 'passed': True, 'token': 'private-sentinel'}]):
            self.assertFalse(f.complete(bad))

    def test_old_role_comparison_allows_only_new_empty_readback_not_new_stored_state(self):
        old = {'bind_secret_id': True, 'token_type': 'batch', 'token_ttl': 900}
        self.assertTrue(f.retained_role({**old, f.FIELD: []}, old))
        for current in (old, {**old, f.FIELD: None}, {**old, f.FIELD: f.CANONICAL},
                        {**old, f.FIELD: [], 'token_ttl': 901}):
            self.assertFalse(f.retained_role(current, old))
        self.assertFalse(f.retained_role({**old, f.FIELD: []}, {**old, f.FIELD: []}))

    def test_denied_bearer_is_real_other_socket_and_spoofs_allowed_source_not_root(self):
        observed = []
        class Client:
            def __init__(self, address, ca, root): self.root = root
            def request(self, method, path, body=None, **kwargs):
                observed.append((method, path, kwargs))
                return SimpleNamespace(status=200, body={'data': {'data': f.VALUE}}) if kwargs['source'].endswith('.1') else SimpleNamespace(status=403, body={'errors': ['denied']})
        instance = SimpleNamespace(root=Path('/synthetic'), address='https://localhost:1234', token='private-root')
        trace = f.Trace(instance, [])
        with patch.object(f, 'SourceClient', Client):
            trace.bearer('snapshot', {'client_token': 'private-target'}, restricted=True)
        self.assertEqual([v[2]['source'] for v in observed], ['127.0.0.1', '127.0.0.2'])
        self.assertTrue(observed[-1][2]['spoof'])
        self.assertTrue(all(v[2]['token'] == 'private-target' for v in observed))
        self.assertNotIn('private-target', json.dumps(trace.rows))
        class WrongClient(Client):
            def request(self, *args, **kwargs): return SimpleNamespace(status=503, body={'errors': ['unavailable']})
        with patch.object(f, 'SourceClient', WrongClient), self.assertRaises(f.ScenarioFailure):
            trace.bearer('unavailable', {'client_token': 'private-target'}, restricted=True)

    def test_actual_phase_program_downgrades_immediately_after_each_distinct_first_cidr_write(self):
        rows, events = [], []
        class Instance:
            root = Path('/synthetic/store'); binary = 'legacy'; token = 'private-root'
            def stop(self): events.append(('stop', self.binary))
            def start(self): events.append(('start', self.binary))
        class Trace(f.Trace):
            def __init__(self, instance, rows):
                super().__init__(instance, rows); self.roles = {}; self.uses = {}; self.auths = {}; self.next = 0
            def call(self, name, method, route, body=None, *, token=None, namespace='', status=200, source='127.0.0.1', spoof=False):
                events.append(('call', name, method, route, body, status, self.instance.binary))
                self.check(name+'_status', True, status=status)
                if status >= 400:
                    self.check(name+'_no_credentials', True)
                    return {'errors': ['synthetic rejection']}
                if route == 'auth/approle/login':
                    role = body['role_id']; entry = self.roles[role]; self.next += 1
                    if entry['bind_secret_id']: self.uses[role] -= 1
                    kind = entry['token_type']; auth = {'client_token': ('hvb.' if kind == 'batch' else 'hvs.')+str(self.next),
                        'accessor': '' if kind == 'batch' else 'a.'+str(self.next), 'token_type': kind,
                        'lease_duration': 900, 'renewable': kind == 'service'}
                    self.auths[auth['client_token']] = (auth, entry.get(f.FIELD) or [])
                    return {'auth': auth}
                if route in ('auth/token/lookup-self', 'auth/token/lookup'):
                    bearer = body['token'] if body else token
                    auth, bounds = self.auths[bearer]
                    return {'data': {'id': bearer, 'type': auth['token_type'], 'ttl': 900,
                        'accessor': auth['accessor'], 'renewable': auth['renewable'], 'bound_cidrs': bounds}}
                if route == 'secret/data/upgrade': return {'data': {'data': f.VALUE}}
                if route.startswith('auth/approle/role/'):
                    pieces = route.split('/'); role = pieces[3]; tail = '/'.join(pieces[4:])
                    if tail == 'role-id': return {'data': {'role_id': role}}
                    if tail == 'secret-id':
                        self.uses[role] = self.roles[role].get('secret_id_num_uses', 0)
                        return {'data': {'secret_id': 'sid-'+role, 'secret_id_accessor': 'accessor-'+role}}
                    if tail == 'secret-id/lookup': return {'data': {'secret_id_num_uses': self.uses[role]}}
                    if tail == 'token-bound-cidrs':
                        if method == 'GET': return {'data': {f.FIELD: self.roles[role].get(f.FIELD)}}
                        self.roles[role][f.FIELD] = None if method == 'DELETE' else ([] if not body[f.FIELD] else f.CANONICAL)
                        return {}
                    if method == 'GET':
                        result = dict(self.roles[role])
                        if self.instance.binary != 'legacy': result[f.FIELD] = result.get(f.FIELD) or []
                        return {'data': result}
                    entry = self.roles.setdefault(role, {'bind_secret_id': True, 'token_type': 'service'})
                    entry.update(body)
                    if f.FIELD in body: entry[f.FIELD] = f.CANONICAL if body[f.FIELD] else []
                    return {}
                return {}
        # seed creates a new Trace after initialize. Keep that actual object/model.
        original_seed = f.seed
        def seed(instance, checks, mode):
            with patch.object(f, 'Trace', side_effect=lambda *args: active[0]):
                return original_seed(instance, checks, mode)
        for mode in ('empty', 'bound'):
            instance = Instance(); active = [Trace(instance, rows)]
            with (patch.object(f, 'initialize', lambda *args: (active[0], 'private-unseal')),
                  patch.object(f, 'seed', seed), patch.object(f, 'durable_manifest', return_value='same'),
                  patch.object(f, 'safe_files', return_value=True)):
                f.run_store(instance, 'candidate', 'legacy', rows, mode)
            calls = [e for e in events if e[0] == 'call']
            names = [e[1] for e in calls]
            first, deny = names.index(mode+'_first_cidr'), names.index(mode+'_downgrade_unseal')
            self.assertEqual(deny, first+1)
            self.assertEqual(calls[first][4], {f.FIELD: [] if mode == 'empty' else f.BOUND})
            # Before the trigger, candidate requests can only read/unseal; no login
            # can independently migrate the store and hide a missing CIDR gate.
            current = names.index(mode+'_current_unseal')
            self.assertEqual(first, current+1)
            for e in calls:
                if e[1].startswith(mode+'_') and '_new_login' in e[1]:
                    self.assertGreater(names.index(e[1]), deny)
            required = {r for r in f.REQUIRED if r.startswith(mode+'_')}
            self.assertTrue(required <= {r['case'] for r in rows}, required-{r['case'] for r in rows})
        names = [r['case'] for r in rows]
        self.assertEqual(len(names), len(set(names)))
        self.assertNotIn('private-unseal', json.dumps(rows))


if __name__ == '__main__': unittest.main()
