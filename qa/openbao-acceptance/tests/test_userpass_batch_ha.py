import copy
import hashlib
from types import SimpleNamespace
import unittest

import userpass_batch_ha as f


class BatchHaGuards(unittest.TestCase):
    def test_named_milestones_reject_missing_duplicate_failed_or_unsafe_rows(self):
        rows = [{'case': name, 'passed': True} for name in sorted(f.REQUIRED-{'complete'})]
        rows.append({'case': 'complete', 'passed': True})
        self.assertTrue(f.complete(rows))
        for name in f.REQUIRED:
            self.assertFalse(f.complete([row for row in rows if row['case'] != name]), name)
        for bad in ([], rows+rows[-1:], rows[:-1], rows[:-1]+[{'case': 'complete', 'passed': 1}],
                    rows[:-1]+[{'case': 'complete', 'passed': False}],
                    rows[:-1]+[{'case': 'complete', 'passed': True, 'token': 'sensitive-sentinel'}]):
            self.assertFalse(f.complete(bad))
        self.assertTrue(f.complete(rows[:-1]+[{'case': 'additional_real_observation', 'passed': True}]+rows[-1:]))

    def test_denial_is_authentication_rejection_not_transport_or_missing_data(self):
        self.assertTrue(f.rejected(403, {'errors': ['permission denied']}))
        for status in (None, 200, 400, 404, 500, 503):
            self.assertFalse(f.rejected(status, {'errors': ['permission denied']}))
        for body in (None, {}, {'errors': []}, {'errors': 'denied'},
                     {'errors': ['denied'], 'auth': {'client_token': 'sensitive-sentinel'}},
                     {'errors': ['denied'], 'data': {'value': 'sensitive-sentinel'}},
                     {'errors': ['denied'], 'wrap_info': {'token': 'sensitive-sentinel'}}):
            self.assertFalse(f.rejected(403, body))

    def test_batch_lookup_requires_exact_bearer_real_ttl_and_no_service_accessor(self):
        data = {'id': 'hvb.synthetic', 'type': 'batch', 'accessor': '', 'renewable': False, 'ttl': 90}
        self.assertTrue(f.lookup_matches(200, {'data': data}, data['id'], alive=True))
        for field, value in (('id', 'hvb.other'), ('type', 'service'), ('accessor', 'service-accessor'),
                             ('renewable', True), ('ttl', True), ('ttl', 0), ('ttl', '90')):
            changed = dict(data); changed[field] = value
            self.assertFalse(f.lookup_matches(200, {'data': changed}, data['id'], alive=True), field)
        for malformed in (None, [], {}, {'data': None}, {'data': []}):
            self.assertFalse(f.lookup_matches(200, malformed, data['id'], alive=True))
        self.assertFalse(f.lookup_matches(503, {'data': data}, data['id'], alive=True))
        self.assertFalse(f.lookup_matches(200, {'data': data}, data['id'], alive=False))

    def fixture(self, denied=frozenset(), corrupt=None):
        tokens = {name: 'hvb.synthetic_'+name for name in f.BATCH_NAMES}
        names = {token: name for name, token in tokens.items()}
        value = {'value': 'original synthetic value', 'revision': 'archived'}
        digest = hashlib.sha256(f.canonical(value)).hexdigest()
        calls, rows = [], []
        class Node:
            def __init__(self, node_id): self.node_id = node_id
            def call(self, method, path, *, token):
                calls.append((self.node_id, method, path, token))
                if token == 'hvs.parent_b' or names.get(token) in denied:
                    response = (403, {'errors': ['permission denied']})
                elif path == f.MOUNT+'/later':
                    response = (404, {'errors': []})
                elif path == f.PATH:
                    response = (200, {'data': dict(value)})
                elif path == 'auth/token/lookup-self':
                    response = (200, {'data': {'id': token, 'type': 'batch', 'accessor': '',
                                'renewable': False, 'ttl': 90, 'entity_id': 'archived-entity' if names[token] == 'userpass' else ''}})
                else:
                    raise AssertionError('unexpected fixture request')
                return corrupt(self.node_id, path, token, copy.deepcopy(response)) if corrupt else response
        cluster = SimpleNamespace(nodes=[Node(n) for n in (1, 2, 3)], root_token='hvs.root')
        def check(case, passed):
            rows.append({'case': case, 'passed': passed})
            if passed is not True: raise f.FixtureError(case)
        return cluster, tokens, digest, check, calls, rows

    def test_real_verifier_visits_every_voter_token_and_restore_identity(self):
        for phase in f.PHASES:
            denied = (frozenset() if phase == 'pre_restore' else frozenset({'child_b'}))
            if phase in ('parent_revoked', 'revoked_restart'): denied |= {'pre_child_a', 'post_child_a'}
            cluster, tokens, digest, check, calls, rows = self.fixture(denied)
            parent = 'hvs.parent_b' if phase == 'restored' else None
            f.verify_voters(cluster, tokens, digest, phase, check, userpass_entity='archived-entity', denied=denied, parent_b=parent)
            for node_id in (1, 2, 3):
                for token in tokens.values():
                    for path in (f.PATH, 'auth/token/lookup-self'):
                        self.assertEqual(calls.count((node_id, 'GET', path, token)), 1)
            self.assertEqual(len({row['case'] for row in rows}), len(rows))
            self.assertTrue({row['case'] for row in rows}.issubset(f.REQUIRED))
            self.assertEqual(rows[-1], {'case': phase+'_all_voters', 'passed': True})

    def test_verifier_rejects_wrong_restored_value_identity_and_missing_parent_denial(self):
        def changed(which):
            def corrupt(node_id, path, token, response):
                if node_id == 2 and path == f.PATH and token.endswith('post_orphan') and which == 'value':
                    return 200, {'data': {'value': 'not restored'}}
                if node_id == 2 and path == 'auth/token/lookup-self' and token.endswith('userpass') and which == 'identity':
                    response[1]['data']['entity_id'] = 'different-entity'
                if node_id == 2 and token == 'hvs.parent_b' and which == 'parent':
                    return 200, {'data': {'id': token}}
                return response
            return corrupt
        for which in ('value', 'identity', 'parent'):
            cluster, tokens, digest, check, _, rows = self.fixture(frozenset({'child_b'}), changed(which))
            with self.assertRaises(f.FixtureError):
                f.verify_voters(cluster, tokens, digest, 'restored', check, userpass_entity='archived-entity',
                                denied=frozenset({'child_b'}), parent_b='hvs.parent_b')
            self.assertFalse(rows[-1]['passed'])
            self.assertNotIn({'case': 'restored_all_voters', 'passed': True}, rows)

    def test_matrix_cannot_omit_or_duplicate_a_voter_or_batch_identity(self):
        for mutation in ('missing_token', 'missing_node', 'duplicate_node', 'unknown_denial', 'missing_entity'):
            cluster, tokens, digest, check, calls, _ = self.fixture()
            if mutation == 'missing_token': tokens.pop('post_orphan')
            if mutation == 'missing_node': cluster.nodes.pop()
            if mutation == 'duplicate_node': cluster.nodes.append(cluster.nodes[0])
            with self.assertRaises(f.FixtureError):
                f.verify_voters(cluster, tokens, digest, 'restored', check,
                    userpass_entity='' if mutation == 'missing_entity' else 'archived-entity',
                    denied=frozenset({'not-a-token'}) if mutation == 'unknown_denial' else frozenset())
            self.assertEqual(calls, [])


if __name__ == '__main__': unittest.main()
