import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import approle_secret_cidrs_ha as f


class SecretCidrHaGuards(unittest.TestCase):
    def test_rejected_forwarded_login_has_real_foreign_source_and_never_retries(self):
        class Client:
            last_family = 4
            def __init__(self, status=400, body=None):
                self.calls, self.status, self.body = [], status, body or {'errors': ['denied']}
            def request(self, *args, **kwargs):
                self.calls.append((args, kwargs)); return SimpleNamespace(status=self.status, body=self.body)
        credentials = {'role_id': 'private-role-id', 'secret_id': 'private-secret-id', 'secret_id_accessor': 'private-accessor'}
        client = Client(); rows = []; t = f.Trace(client, rows, [])
        self.assertIsNone(t.login('foreign', 'service', 'two', credentials, source='127.0.0.2', status=400, spoof=True))
        self.assertEqual(client.calls, [(('POST', 'auth/'+f.MOUNT+'/login',
            {'role_id': credentials['role_id'], 'secret_id': credentials['secret_id']}),
            {'token': '', 'source': '127.0.0.2', 'spoof': True})])
        for status, body in ((503, {'errors': ['unavailable']}), (400, {'errors': []}),
            (400, {'errors': ['denied'], 'auth': {'client_token': 'leaked'}}),
            (400, {'errors': ['denied'], 'data': {'secret_id': 'leaked'}}),
            (400, {'errors': ['denied'], 'wrap_info': {'token': 'leaked'}})):
            client = Client(status, body)
            with self.assertRaises(f.ScenarioFailure):
                f.Trace(client, [], []).login('bad', 'batch', 'one', credentials, source='127.0.0.2', status=400, spoof=True)
            self.assertEqual(len(client.calls), 1)

    def test_exhaustion_requires_raw_empty_204_and_accessor_404(self):
        class Client:
            last_family = 4
            def __init__(self, statuses, body=None): self.statuses, self.body, self.calls = iter(statuses), body or {}, []
            def request(self, *args, **kwargs):
                self.calls.append((args, kwargs)); status = next(self.statuses)
                return SimpleNamespace(status=status, body=self.body if status == 204 else {'errors': ['not found']})
        creds = {'secret_id': 'private-secret-id', 'secret_id_accessor': 'private-accessor'}
        client = Client((204, 404))
        self.assertIsNone(f.Trace(client, [], []).sid('gone', 'batch', 'one', creds, uses=None))
        self.assertEqual(len(client.calls), 2)
        for statuses, body in (((404,), {}), ((204, 200), {}), ((204,), {'data': {'secret_id_num_uses': 0}})):
            with self.assertRaises(f.ScenarioFailure):
                f.Trace(Client(statuses, body), [], []).sid('wrong', 'batch', 'one', creds, uses=None)

    def test_bearer_source_snapshot_is_independent_and_metadata_exact(self):
        auth = {'client_token': 'private-batch-token'}
        data = {'id': auth['client_token'], 'type': 'batch', 'bound_cidrs': ['127.0.0.2'],
            'ttl': 100, 'meta': {'role_name': 'batch-split'}, 'accessor': '', 'renewable': False}
        self.assertTrue(f.lookup_shape(data, auth, 'batch', 'split', ['127.0.0.2']))
        for fields in ({'bound_cidrs': ['127.0.0.1']}, {'meta': {'role_name': 'batch'}},
                       {'accessor': 'service-accessor'}, {'ttl': True}, {'renewable': True}):
            self.assertFalse(f.lookup_shape(data | fields, auth, 'batch', 'split', ['127.0.0.2']))
        self.assertTrue(f.rows_secret_free({'checks': []}, [b'\xffbinary-private-key', 'private-bearer']))
        self.assertFalse(f.rows_secret_free({'value': 'private-bearer'}, [b'\xffbinary-private-key', 'private-bearer']))

    def test_complete_matrix_rejects_missing_duplicate_voter_and_credential(self):
        for fault in ('voter', 'duplicate', 'credential', 'snapshot', 'token', 'phase'):
            nodes = [SimpleNamespace(node_id=i) for i in (1, 2, 3)]
            credentials = {k: {label: {} for label in (*f.LABELS, 'split')} for k in f.KINDS}
            snapshots = {k: dict.fromkeys(f.LABELS) for k in f.KINDS}
            tokens = {k: dict.fromkeys(f.token_names('denied')) for k in f.KINDS}
            if fault == 'voter': nodes.pop()
            if fault == 'duplicate': nodes[-1] = nodes[0]
            if fault == 'credential': credentials['service'].pop('one')
            if fault == 'snapshot': snapshots['batch'].pop('unlimited')
            if fault == 'token': tokens['batch'].pop('split')
            touched = []
            def trace(node): touched.append(node); raise AssertionError('must not issue any request')
            with self.assertRaises(f.ScenarioFailure):
                f.verify_voters(SimpleNamespace(nodes=nodes), trace, credentials, snapshots, tokens,
                    'unknown' if fault == 'phase' else 'denied')
            self.assertEqual(touched, [])

    def test_actual_run_model_checks_consumption_once_and_all_named_milestones(self):
        with tempfile.TemporaryDirectory() as temporary:
            cluster, rows = run_model(Path(temporary))
        self.assertTrue(f.complete(rows))
        self.assertEqual(len(rows), len({r['case'] for r in rows}))
        self.assertTrue(all(node.process is None for node in cluster.nodes))
        self.assertEqual(cluster.restarts, 2)
        self.assertEqual(cluster.stepdowns, 1)
        for kind in f.KINDS:
            denied = [call for call in cluster.logins if call['role'] == kind+'-two' and call['source'] == '127.0.0.2']
            self.assertEqual(len(denied), 1)
            self.assertTrue(denied[0]['spoof'])
            self.assertNotEqual(denied[0]['node'], denied[0]['leader'])
            succeeded = [call for call in cluster.logins if call['role'] == kind+'-two' and call['issued']]
            self.assertEqual(len(succeeded), 1)
            self.assertEqual(succeeded[0]['source'], '127.0.0.1')
            unlimited = next(v for v in cluster.secrets.values() if v['role'] == kind+'-unlimited')
            self.assertEqual(unlimited['uses'], 0)
            self.assertEqual(unlimited['updated'], 1)
        for case in f.REQUIRED:
            self.assertFalse(f.complete([row for row in rows if row['case'] != case]), case)
        self.assertFalse(f.complete(rows+rows[-1:]))
        self.assertFalse(f.complete(rows[:-1]+[{'case': 'complete', 'passed': 1}]))
        self.assertTrue(f.complete(rows[:-1]+[{'case': 'new_safe_observation', 'passed': True}]+rows[-1:]))

    def test_real_phase_verifier_catches_repeat_consumption_unlimited_mutation_and_wrong_peer(self):
        for fault in ('second_consumption', 'unlimited_changed', 'drop_peer', 'split_unbound'):
            with tempfile.TemporaryDirectory() as temporary, self.assertRaises(f.ScenarioFailure, msg=fault):
                run_model(Path(temporary), fault=fault)


def run_model(work, fault=None):
    """Exercise the actual run() request order; not real HA or provider evidence."""
    saved = []
    class Cluster:
        def __init__(self, binary, root):
            saved.append(self); self.root = root
            self.root_token, self.unseal_key = 'hvs.synthetic-root-secret', 'synthetic-unseal-share'
            self.replication_key = b'\xff\x00synthetic-replication-key'
            self.scenarios = [{'case': 'model_bootstrap', 'passed': True}]
            self.leader_id, self.serial, self.stepdowns, self.restarts = 1, 0, 0, 0
            self.roles, self.secrets, self.tokens, self.logins = {}, {}, {}, []
            self.nodes = [Node(self, n, root/str(n)) for n in (1, 2, 3)]
        def bootstrap(self): pass
        def leader(self): return self.nodes[self.leader_id-1]
        def running(self): return [n for n in self.nodes if n.process is not None]
        def close(self):
            for n in self.nodes: n.stop()
        def wait_quorum(self): self.restarts += 1
    class Node:
        def __init__(self, cluster, node_id, root):
            self.cluster, self.node_id, self.root, self.http_port = cluster, node_id, root, 10000+node_id
            self.data_dir = root/'data'; self.data_dir.mkdir(parents=True); (root/'raft').mkdir()
            (root/'process.log').write_bytes(b''); (root/'server.json').write_text(json.dumps({'timeout_seconds': 5}))
            self.process = object()
        def stop(self): self.process = None
        def start(self, wait=True): self.process = object()
        def wait_ready(self): pass
        def call(self, method, path, body=None, **kwargs):
            if path == 'sys/leader': return 200, {'ha_enabled': True, 'leader_address': f'https://127.0.0.1:{self.cluster.leader().http_port}'}
            if path == 'sys/unseal': return 200, {}
            if path == 'sys/health': return 200, {'sealed': False}
            raise AssertionError('unexpected direct node API')
    class Client:
        last_family = 4
        def __init__(self, address, *args, **kwargs):
            self.node = next(n for n in saved[0].nodes if address.endswith(':'+str(n.http_port)))
        def request(self, method, path, body=None, token=None, source='127.0.0.1', spoof=False):
            status, result = self.handle(method, path, body, token, source, spoof)
            return SimpleNamespace(status=status, body=copy.deepcopy(result))
        def handle(self, method, path, body, token, source, spoof):
            c = self.node.cluster
            if path == 'sys/step-down':
                c.stepdowns += 1; c.leader_id = 2
                if fault == 'second_consumption':
                    for key in list(c.secrets):
                        if c.secrets[key]['role'].endswith('-two'): del c.secrets[key]
                return 204, {}
            if path == 'auth/'+f.MOUNT+'/login':
                name = next(name for name, role in c.roles.items() if role['role_id'] == body['role_id'])
                role = c.roles[name]; sid = c.secrets.get(body['secret_id'])
                record = {'role': name, 'source': source, 'spoof': spoof, 'node': self.node.node_id,
                    'leader': c.leader_id, 'issued': False}; c.logins.append(record)
                if sid is None: return 400, {'errors': ['invalid role or secret ID']}
                if sid['uses']:
                    sid['uses'] -= 1; sid['updated'] += 1
                    if sid['uses'] == 0: del c.secrets[body['secret_id']]
                elif fault == 'unlimited_changed' and source == '127.0.0.2': sid['updated'] += 1
                observed_source = '127.0.0.1' if fault == 'drop_peer' else source
                if role.get(f.FIELD) and observed_source != '127.0.0.1': return 400, {'errors': ['source rejected']}
                c.serial += 1; kind = role['token_type']; raw = 'hv'+('b.' if kind == 'batch' else 's.')+'synthetic-token-'+str(c.serial)
                auth = {'client_token': raw, 'token_type': kind, 'renewable': kind == 'service',
                    'accessor': 'private-token-accessor-'+str(c.serial) if kind == 'service' else '',
                    'metadata': {'role_name': name}, 'lease_duration': 1800}
                c.tokens[raw] = dict(auth, bound_cidrs=[] if fault == 'split_unbound' else role.get('token_bound_cidrs', []))
                record['issued'] = True; return 200, {'auth': auth}
            if token in c.tokens:
                auth = c.tokens[token]
                if auth['bound_cidrs'] and source != '127.0.0.2': return 403, {'errors': ['permission denied']}
                if path == f.KV+'/item': return 200, {'data': {'value': 'synthetic'}}
                if path == 'auth/token/lookup-self':
                    return 200, {'data': {'id': token, 'type': auth['token_type'], 'accessor': auth['accessor'],
                        'renewable': auth['renewable'], 'meta': auth['metadata'], 'ttl': 1700,
                        'bound_cidrs': ['127.0.0.2'] if auth['bound_cidrs'] else [],
                        'creation_time': 1, 'expire_time': 'same-fixed-expiry', 'num_uses': 0}}
            prefix = 'auth/'+f.MOUNT+'/role/'
            if path.startswith(prefix):
                name, _, suffix = path[len(prefix):].partition('/')
                if suffix == '':
                    if method == 'POST': c.roles.setdefault(name, {'role_id': 'private-role-'+name}).update(body); return 204, {}
                    return 200, {'data': c.roles[name]}
                if suffix == 'role-id': return 200, {'data': {'role_id': c.roles[name]['role_id']}}
                if suffix == 'secret-id':
                    c.serial += 1; raw, accessor = 'private-sid-'+str(c.serial), 'private-sid-accessor-'+str(c.serial)
                    c.secrets[raw] = {'role': name, 'accessor': accessor, 'uses': c.roles[name]['secret_id_num_uses'], 'updated': 1}
                    return 200, {'data': {'secret_id': raw, 'secret_id_accessor': accessor}}
                if suffix.endswith('/lookup'):
                    by_accessor = suffix.startswith('secret-id-accessor')
                    sid = next((s for s in c.secrets.values() if s['accessor'] == body['secret_id_accessor']), None) if by_accessor else c.secrets.get(body['secret_id'])
                    if sid is None: return (404, {'errors': ['not found']}) if by_accessor else (204, {})
                    return 200, {'data': {'secret_id_accessor': sid['accessor'], 'secret_id_num_uses': sid['uses'],
                        'creation_time': 1, 'last_updated_time': sid['updated'], 'expiration_time': 'no-expiry'}}
            if method in ('POST', 'PUT') and (path.startswith('sys/') or path == f.KV+'/item'): return 204, {}
            raise AssertionError('unexpected model request')
    rows = []
    with patch.object(f, 'SaveCluster', Cluster), patch.object(f, 'SourceClient', Client):
        f.run(Path('/synthetic/binary'), work, rows, [], [], [])
    return saved[0], rows


if __name__ == '__main__': unittest.main()
