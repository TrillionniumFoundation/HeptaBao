import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import userpass_native_ha as fixture


class UserpassHaGuards(unittest.TestCase):
    def test_adapter_preserves_explicit_actor_and_root_management(self):
        calls = []
        node = SimpleNamespace(call=lambda *a, **k: (calls.append((a, k)) or (204, {})))
        client = fixture.NodeClient(node, 'root-sensitive')
        client.request('POST', '/v1/auth/token/renew-self', {}, token='issued-sensitive')
        client.request('POST', '/v1/auth/token/renew', {'token': 'issued-sensitive'})
        self.assertEqual([k['token'] for _, k in calls], ['issued-sensitive', 'root-sensitive'])
        self.assertEqual(calls[0][0][:2], ('POST', 'auth/token/renew-self'))
        with self.assertRaises(fixture.FixtureError):
            client.request('GET', '/auth/token/lookup-self')

    def test_expiry_agreement_ignores_only_countdown_and_requires_identity(self):
        base = {'creation_time': 100, 'expire_time': '2030-01-01T00:10:00Z', 'ttl': 600,
                'meta': {'username': 'alice'}, 'policies': ['default'], 'explicit_max_ttl': 0}
        self.assertEqual(fixture.expiry_projection(base), fixture.expiry_projection(dict(base, ttl=598)))
        self.assertNotEqual(fixture.expiry_projection(base), fixture.expiry_projection(dict(base, expire_time='later')))
        for damaged in ({}, dict(base, ttl=True), dict(base, ttl=0), dict(base, meta={}), dict(base, expire_time='')):
            self.assertIsNone(fixture.expiry_projection(damaged))
        self.assertFalse(fixture.no_extension(base, dict(base, expire_time='later')))

    def test_completion_requires_named_routes_not_a_fixed_count_or_only_milestones(self):
        checks = [{'case': n, 'passed': True} for n in sorted(fixture.REQUIRED - {'complete'})]
        checks.append({'case': 'complete', 'passed': True})
        api = [{'case': n, 'passed': True} for n in sorted(fixture.REQUIRED_API)]
        self.assertTrue(fixture.complete(checks, api))
        self.assertTrue(fixture.complete(checks[:-1] + [{'case': 'extra', 'passed': True}] + checks[-1:], api))
        for i in range(len(checks)):
            self.assertFalse(fixture.complete(checks[:i] + checks[i+1:], api))
        for i in range(len(api)):
            self.assertFalse(fixture.complete(checks, api[:i] + api[i+1:]))
        for invalid in ([], api + [api[0]], api + [{'case': 'userpass_native.secret', 'passed': True, 'value': 'secret'}]):
            self.assertFalse(fixture.complete(checks, invalid))
        self.assertFalse(fixture.complete(checks + [checks[0]], api))

    def test_real_scenario_labels_and_transitions_reject_then_observe_before_recovery_renew(self):
        events = []
        class FakeCluster:
            def __init__(self, binary, root):
                self.root_token, self.unseal_key = 'synthetic-root-credential', 'synthetic-unseal-credential'
                self.replication_key = b'synthetic-replication-secret-1234'
                self.scenarios, self.version, self.current_user, self.expiry = [], 0, None, 'expiry-0'
                self.blocked, self.closed = False, False
                self.nodes = [FakeNode(self, root / str(i), i) for i in range(3)]
                self.links = {'mesh': SimpleNamespace(set_blocked=self.block)}
            def bootstrap(self):
                for n in self.nodes: n.start()
            def running(self): return [n for n in self.nodes if n.process is not None]
            def leader(self): return self.running()[0]
            def restart(self, node): node.start()
            def wait_quorum(self): pass
            def block(self, value): self.blocked = value; events.append(('block', value))
            def _heal(self): self.block(False)
            def close(self): self.closed = True
        class FakeNode:
            def __init__(self, cluster, root, node_id):
                self.cluster, self.root, self.node_id = cluster, root, node_id
                self.data_dir, self.process = root / 'data', None
                self.data_dir.mkdir(parents=True)
            def start(self, **kwargs): self.process = object()
            def stop(self): self.process = None
            def wait_ready(self): pass
            def call(self, method, path, body=None, **kwargs):
                c = self.cluster
                events.append((path, method, c.blocked))
                if path == 'sys/unseal': return 200, {}
                if path == 'sys/auth/' + fixture.MOUNT: return 204, {}
                if path.endswith('/users/alice'):
                    if method == 'DELETE': c.current_user = None
                    elif c.current_user is None: c.current_user = dict(body)
                    else: c.current_user.update(body)
                    return 204, {}
                if path.endswith('/login/alice'):
                    return 200, {'auth': {'client_token': 'synthetic-issued-credential',
                        'accessor': 'synthetic-accessor', 'lease_duration': 300, 'renewable': True,
                        'metadata': {'username': 'alice'}, 'token_policies': ['default', 'ha-userpass-old']}}
                if path == 'auth/token/lookup':
                    return 200, {'data': {'ttl': 600, 'creation_time': 100, 'expire_time': c.expiry,
                        'explicit_max_ttl': 0, 'meta': {'username': 'alice'}, 'policies': ['default', 'ha-userpass-old']}}
                if path.startswith('auth/token/renew'):
                    if c.blocked: return 503, {}
                    if c.current_user is None: return (500 if path.endswith('accessor') else 204), {}
                    if c.current_user['token_policies'] != ['ha-userpass-old']: return 500, {}
                    c.version += 1; c.expiry = 'expiry-' + str(c.version)
                    auth = {'lease_duration': 600, 'renewable': True}
                    if not path.endswith('accessor'): auth['client_token'] = 'synthetic-issued-credential'
                    return 200, {'auth': auth}
                raise AssertionError('unexpected fixture route')
        checks, api, diagnostics = [], [], []
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(fixture, 'PartitionCluster', FakeCluster), patch.object(fixture.time, 'sleep'):
                fixture.run(Path('unused'), Path(directory), checks, api, diagnostics, [])
        self.assertTrue(fixture.complete(checks, api))
        self.assertEqual(len(api), len({r['case'] for r in api}))
        healed = events.index(('block', False))
        after_heal = events[healed + 1:]
        first_renew = next(i for i, row in enumerate(after_heal) if row[0].startswith('auth/token/renew'))
        self.assertTrue(all(row[0] == 'auth/token/lookup' for row in after_heal[:first_renew]))
        self.assertGreaterEqual(first_renew, 4)
        self.assertNotIn('synthetic-issued-credential', json.dumps([checks, api, diagnostics]))


if __name__ == '__main__': unittest.main()
