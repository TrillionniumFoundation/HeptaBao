import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import jwt_batch_ha as f


ENTITY, ALIAS = 'synthetic-entity', 'synthetic-alias'


def lookup(raw):
    return {'id': raw, 'type': 'batch', 'accessor': '', 'renewable': False,
        'orphan': True, 'entity_id': ENTITY, 'meta': {'role': f.ROLE},
        'display_name': f.MOUNT+'-'+f.SUBJECT, 'ttl': 90, 'creation_time': 100,
        'expire_time_unix': 190, 'num_uses': 0}


def alias():
    return {'id': ALIAS, 'canonical_id': ENTITY, 'name': f.SUBJECT,
        'mount_accessor': 'auth_synthetic', 'metadata': {'role': f.ROLE},
        'custom_metadata': copy.deepcopy(f.CUSTOM)}


class JwtBatchHaGuards(unittest.TestCase):
    def test_lookup_requires_real_bearer_metadata_entity_lifetime_and_batch(self):
        raw = 'hvb.synthetic-original-token'
        auth = {'client_token': raw}
        data = lookup(raw)
        self.assertTrue(f.batch_lookup(200, {'data': data}, auth, ENTITY))
        for field, value in (('id', 'other'), ('type', 'service'), ('accessor', 'service-accessor'),
                             ('renewable', True), ('orphan', False), ('entity_id', 'other'),
                             ('meta', {}), ('display_name', 'jwt-hash'), ('ttl', 0), ('ttl', True)):
            changed = dict(data); changed[field] = value
            self.assertFalse(f.batch_lookup(200, {'data': changed}, auth, ENTITY), field)
        for body in (None, [], {}, {'data': []}, {'data': None}):
            self.assertFalse(f.batch_lookup(200, body, auth, ENTITY))
        self.assertFalse(f.batch_lookup(503, {'data': data}, auth, ENTITY))

    def matrix(self, phase, corruption=None):
        calls, rows = [], []
        tokens = {kind: {'client_token': 'hvb.synthetic-'+kind} for kind in f.names_for(phase)}
        value = {'value': 'real phase value'}
        digest = hashlib.sha256(f.canonical(value)).hexdigest()
        class Node:
            def __init__(self, node_id): self.node_id = node_id
            def call(self, method, path, *, token):
                calls.append((self.node_id, method, path, token))
                if token != 'root' and phase == 'disabled':
                    response = (403, {'errors': ['permission denied']})
                elif path == f.KV:
                    response = (200, {'data': value})
                elif path == 'auth/token/lookup-self':
                    response = (200, {'data': {**lookup(token), 'ttl': 90-self.node_id}})
                elif path == 'identity/entity-alias/id/'+ALIAS:
                    response = (200, {'data': alias()})
                else: raise AssertionError('unexpected request')
                return corruption(self.node_id, path, copy.deepcopy(response)) if corruption else response
        cluster = SimpleNamespace(nodes=[Node(i) for i in (1, 2, 3)], root_token='root')
        def check(case, passed):
            rows.append({'case': case, 'passed': passed})
            if passed is not True: raise f.ScenarioFailure(case)
        return cluster, tokens, digest, calls, rows, check

    def test_actual_verifier_visits_each_voter_and_credential_through_all_phases(self):
        for phase in f.PHASES:
            cluster, tokens, digest, calls, rows, check = self.matrix(phase)
            f.verify_voters(cluster, tokens, ENTITY, ALIAS, digest, phase, check)
            for node in (1, 2, 3):
                for auth in tokens.values():
                    for path in (f.KV, 'auth/token/lookup-self'):
                        self.assertEqual(calls.count((node, 'GET', path, auth['client_token'])), 1)
                self.assertEqual(calls.count((node, 'GET', 'identity/entity-alias/id/'+ALIAS, 'root')), 1)
            self.assertEqual(len(rows), len({row['case'] for row in rows}))
            self.assertTrue({row['case'] for row in rows} <= f.REQUIRED)
            self.assertEqual(rows[-1], {'case': phase+'_all_voters', 'passed': True})

    def test_value_metadata_expiry_and_denial_regressions_cannot_pass(self):
        for fault in ('value', 'backend', 'custom', 'expiry', 'disabled_credential', 'disabled_transport'):
            def corrupt(node, path, response):
                if node != 2: return response
                if fault == 'value' and path == f.KV: return 200, {'data': {'value': 'wrong'}}
                if fault in ('backend', 'custom') and path.startswith('identity/'):
                    response[1]['data']['metadata' if fault == 'backend' else 'custom_metadata'] = {}
                if fault == 'expiry' and path == 'auth/token/lookup-self':
                    response[1]['data']['expire_time_unix'] += 1
                if fault == 'disabled_credential' and path == f.KV:
                    return 403, {'errors': ['denied'], 'auth': {'client_token': 'leaked'}}
                if fault == 'disabled_transport' and path == f.KV: return 503, {'errors': ['unavailable']}
                return response
            phase = 'disabled' if fault.startswith('disabled') else 'restarted'
            cluster, tokens, digest, _, rows, check = self.matrix(phase, corrupt)
            with self.assertRaises(f.ScenarioFailure):
                f.verify_voters(cluster, tokens, ENTITY, ALIAS, digest, phase, check)
            self.assertFalse(rows[-1]['passed'])

    def test_matrix_missing_token_voter_or_identity_rejected_before_requests(self):
        for fault in ('voter', 'duplicate', 'token', 'entity', 'alias'):
            cluster, tokens, digest, calls, _, check = self.matrix('reused')
            if fault == 'voter': cluster.nodes.pop()
            if fault == 'duplicate': cluster.nodes[2] = cluster.nodes[1]
            if fault == 'token': tokens.pop('reused')
            with self.assertRaises(f.ScenarioFailure):
                f.verify_voters(cluster, tokens, '' if fault == 'entity' else ENTITY,
                    '' if fault == 'alias' else ALIAS, digest, 'reused', check)
            self.assertEqual(calls, [])

    def test_binary_and_text_secret_scans_cover_stream_boundary_without_decoding_keys(self):
        text = 'synthetic-sensitive-text-0123456789'
        key = b'\xff\x00binary-replication-key-0123456789'
        self.assertEqual(f.samples_bytes([text, key, 'short']), [text.encode(), key])
        self.assertTrue(f.report_secret_free({'passed': True}, [text, key]))
        self.assertFalse(f.report_secret_free({'value': text}, [text, key]))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'ciphertext'
            path.write_bytes(b'x'*(64*1024-10)+key+b'end')
            self.assertFalse(f.secret_free([path], f.samples_bytes([text, key])))
            path.write_bytes(b'actual-safe-fixture-bytes')
            self.assertTrue(f.secret_free([path], f.samples_bytes([text, key])))
        with self.assertRaises(ValueError): f.samples_bytes([object()])

    def test_real_orchestration_emits_complete_unique_cases_and_reuses_signed_assertion(self):
        instances = []
        class Cluster:
            def __init__(self, binary, root):
                instances.append(self)
                self.root_token, self.unseal_key = 'hvs.synthetic-root-token', 'synthetic-unseal-share'
                self.replication_key = b'\xff\x00synthetic-replication-key'
                self.scenarios = [{'case': 'model_bootstrap', 'passed': True}]
                self.leader_id, self.disabled, self.role, self.mount = 1, False, True, True
                self.tokens, self.assertions, self.alias = {}, [], alias()
                self.alias['custom_metadata'] = {}
                self.nodes = [Node(self, i, root/str(i)) for i in (1, 2, 3)]
            def bootstrap(self): pass
            def leader(self): return self.nodes[self.leader_id-1]
            def running(self): return [n for n in self.nodes if n.process is not None]
            def close(self):
                for n in self.nodes: n.stop()
            def wait_quorum(self): pass
        class Node:
            def __init__(self, cluster, node, root):
                self.cluster, self.node_id, self.root, self.http_port = cluster, node, root, 10000+node
                self.data_dir = root/'data'; self.data_dir.mkdir(parents=True)
                (root/'raft').mkdir(); (root/'process.log').write_bytes(b'')
                (root/'server.json').write_text(json.dumps({'timeout_seconds': 5}))
                self.process = object()
            def stop(self): self.process = None
            def start(self, wait=True): self.process = object()
            def wait_ready(self): pass
            def call(self, method, path, body=None, token=''):
                c = self.cluster
                if path == 'sys/leader': return 200, {'ha_enabled': True, 'leader_address': f'https://127.0.0.1:{c.leader().http_port}'}
                if path == 'sys/step-down': c.leader_id = 2; return 204, {}
                if path == 'sys/unseal': return 200, {}
                if path == f.KV and method == 'PUT': c.value = body; return 204, {}
                if path == 'identity/entity/id/'+ENTITY and method == 'POST':
                    c.disabled = body['disabled']; return 204, {}
                if path == 'identity/entity/id/'+ENTITY: return 200, {'data': {'aliases': [c.alias]}}
                if path == 'identity/entity-alias/id/'+ALIAS:
                    if method == 'POST': c.alias['custom_metadata'] = body['custom_metadata']
                    return 200, {'data': copy.deepcopy(c.alias)}
                if path == 'auth/'+f.MOUNT+'/login':
                    c.assertions.append(body['jwt'])
                    if c.disabled: return 403, {'errors': ['permission denied']}
                    if not c.mount or not c.role: raise AssertionError('login after removing issuer')
                    raw = 'hvb.synthetic-batch-token-'+str(len(c.tokens))
                    auth = {'client_token': raw, 'token_type': 'batch', 'accessor': '',
                        'renewable': False, 'orphan': True, 'entity_id': ENTITY,
                        'metadata': {'role': f.ROLE}, 'lease_duration': 1800}
                    c.tokens[raw] = auth; return 200, {'auth': auth}
                if token in c.tokens:
                    if c.disabled: return 403, {'errors': ['permission denied']}
                    if path == f.KV: return 200, {'data': c.value}
                    if path == 'auth/token/lookup-self': return 200, {'data': lookup(token)}
                if method == 'DELETE' and path == 'auth/'+f.MOUNT+'/role/'+f.ROLE:
                    c.role = False; return 204, {}
                if method == 'DELETE' and path == 'sys/auth/'+f.MOUNT:
                    c.mount = False; return 204, {}
                if method in ('PUT', 'POST') and (path.startswith('sys/') or path.startswith('auth/')): return 204, {}
                raise AssertionError('unexpected model call')
        rows, bootstrap, observations, samples = [], [], {}, []
        with tempfile.TemporaryDirectory() as temporary, patch.object(f, 'SaveCluster', Cluster):
            f.run(Path('/synthetic/binary'), Path(temporary), rows, bootstrap, observations, samples)
        self.assertTrue(f.complete(rows))
        self.assertEqual(len(rows), len({r['case'] for r in rows}))
        self.assertEqual(len(instances[0].assertions), 3)
        self.assertEqual(len(set(instances[0].assertions)), 1)
        self.assertEqual(len(instances[0].tokens), 2)
        self.assertTrue(all(n.process is None for n in instances[0].nodes))
        for required in f.REQUIRED:
            self.assertFalse(f.complete([row for row in rows if row['case'] != required]), required)
        self.assertFalse(f.complete(rows+rows[-1:]))
        self.assertFalse(f.complete(rows[:-1]+[{'case': 'complete', 'passed': 1}]))
        self.assertTrue(f.complete(rows[:-1]+[{'case': 'additional_safe_observation', 'passed': True}]+rows[-1:]))


if __name__ == '__main__': unittest.main()
