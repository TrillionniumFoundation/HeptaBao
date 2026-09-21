import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import approle_secretid_overrides_ha as f


class SecretIdOverridesHaGuards(unittest.TestCase):
    def test_one_shot_denials_use_actual_foreign_source_and_subset_error(self):
        class Client:
            last_family = 4
            def __init__(self, status, body): self.status, self.body, self.calls = status, body, []
            def request(self, *args, **kwargs):
                self.calls.append((args, kwargs)); return SimpleNamespace(status=self.status, body=self.body)
        creds = {'role_id': 'synthetic-private-role', 'secret_id': 'synthetic-private-secret'}
        for kind in f.KINDS:
            client = Client(400, {'errors': ['source address denied']})
            f.Trace(client, [], []).login('denied', kind, 'finite', creds,
                source='127.0.0.2', status=400, spoof=True)
            self.assertEqual(client.calls, [(('POST', 'auth/'+f.MOUNT+'/login', creds),
                {'token': '', 'source': '127.0.0.2', 'spoof': True})])
            client = Client(500, {'errors': ['CIDRs not a subset']})
            rows = []; f.Trace(client, rows, []).login('subset', kind, 'subset', creds, status=500)
            self.assertEqual(len(client.calls), 1)
            self.assertIn({'case': 'subset_subset_error', 'passed': True}, rows)
            for status, body in ((503, {'errors': ['unavailable']}), (500, {'errors': ['unrelated']}),
                (500, {'errors': ['subset'], 'auth': {'client_token': 'private-bearer'}}),
                (500, {'errors': ['subset'], 'data': {'private': True}}),
                (500, {'errors': ['subset'], 'wrap_info': {'token': 'private-wrapper'}})):
                client = Client(status, body)
                with self.assertRaises(f.ScenarioFailure):
                    f.Trace(client, [], []).login('bad', kind, 'subset', creds, status=500)
                self.assertEqual(len(client.calls), 1)

    def test_full_sid_snapshots_detect_repeat_consumption_and_unlimited_changes(self):
        cluster = SimpleNamespace(nodes=[SimpleNamespace(node_id=n) for n in (1, 2, 3)])
        credentials = {k: {label: {} for label in f.SID_LABELS} for k in f.KINDS}
        snapshots = {k: {label: None if label == 'one' else {
            'secret_id_num_uses': 0 if label == 'unlimited' else 1,
            'last_updated_time': 'fixed', 'cidr_list': ['127.0.0.1/32']} for label in f.SID_LABELS} for k in f.KINDS}
        def execute(fault=None, consumed=False):
            calls, rows = [], []
            class View:
                def __init__(self, node): self.node = node
                def check(self, name, ok): f.Trace(None, rows, []).check(name, ok)
                def sid(self, name, kind, label, creds, *, uses):
                    calls.append((self.node.node_id, kind, label, uses))
                    value = copy.deepcopy(snapshots[kind][label])
                    if consumed and label != 'unlimited': value = None
                    if self.node.node_id == 3 and kind == 'batch':
                        if fault == 'consumed_twice' and label == 'finite': value = None
                        if fault == 'unlimited_changed' and label == 'unlimited': value['last_updated_time'] = 'changed'
                        if fault == 'lost_override' and label == 'unlimited': value['cidr_list'] = []
                    return value
            f.verify_credentials(cluster, View, credentials, snapshots,
                'final_sids' if consumed else 'restarted', consumed=consumed)
            return calls, rows
        calls, rows = execute()
        self.assertEqual({n for n, *_ in calls}, {1, 2, 3})
        self.assertTrue(all(uses == (0 if label == 'unlimited' else None if label == 'one' else 1)
            for _, _, label, uses in calls))
        self.assertEqual(rows[-1], {'case': 'restarted_all_voters', 'passed': True})
        execute(consumed=True)
        for fault in ('consumed_twice', 'unlimited_changed', 'lost_override'):
            with self.assertRaises(f.ScenarioFailure, msg=fault): execute(fault)

    def test_incomplete_voter_or_credential_matrix_sends_no_requests(self):
        for fault in ('missing_node', 'duplicate_node', 'missing_kind', 'missing_sid', 'snapshot', 'phase'):
            cluster = SimpleNamespace(nodes=[SimpleNamespace(node_id=n) for n in (1, 2, 3)])
            creds = {k: {label: {} for label in f.SID_LABELS} for k in f.KINDS}
            snapshots = copy.deepcopy(creds); calls = []
            if fault == 'missing_node': cluster.nodes.pop()
            if fault == 'duplicate_node': cluster.nodes[2] = cluster.nodes[1]
            if fault == 'missing_kind': creds.pop('batch')
            if fault == 'missing_sid': creds['service'].pop('one')
            if fault == 'snapshot': snapshots['batch'].pop('unlimited')
            def view(node): calls.append(node); raise AssertionError('unexpected request')
            with self.assertRaises(f.ScenarioFailure, msg=fault):
                f.verify_credentials(cluster, view, creds, snapshots, 'bad' if fault == 'phase' else 'successor')
            self.assertEqual(calls, [])

    def test_issued_bearers_are_checked_from_both_real_sources_on_every_voter(self):
        cluster = SimpleNamespace(nodes=[SimpleNamespace(node_id=n) for n in (1, 2, 3)])
        tokens = {k: {label: {'client_token': k+'-'+label} for label in f.TOKEN_LABELS} for k in f.KINDS}
        def execute(fault=None):
            reads, rows = [], []
            class View:
                def __init__(self, node): self.node = node
                def check(self, name, ok): f.Trace(None, rows, []).check(name, ok)
                def read(self, name, auth, *, source='127.0.0.2', status=200, spoof=False):
                    reads.append((self.node.node_id, auth['client_token'], source, status))
                def call(self, name, method, path, **kwargs):
                    kind, label = kwargs['token'].split('-', 1); role, bounds = f.TOKEN_CONTRACT[label]
                    self.check(name+'_actual_request', method == 'GET' and path == 'auth/token/lookup-self'
                        and kwargs['source'] == '127.0.0.2')
                    data = {'id': kwargs['token'], 'type': kind, 'bound_cidrs': bounds, 'ttl': 100,
                        'meta': {'role_name': kind+'-'+role}, 'accessor': 'private-accessor' if kind == 'service' else '',
                        'renewable': kind == 'service'}
                    if self.node.node_id == 3 and kind == 'batch' and label == 'override_cleared':
                        if fault == 'rebound': data['bound_cidrs'] = []
                        if fault == 'metadata': data['meta'] = {'role_name': 'other'}
                    return {'data': data}
            f.verify_tokens(cluster, View, tokens)
            return reads, rows
        reads, rows = execute()
        for node in (1, 2, 3):
            for kind in f.KINDS:
                for label in f.TOKEN_LABELS:
                    token = tokens[kind][label]['client_token']; bounds = f.TOKEN_CONTRACT[label][1]
                    self.assertEqual([(src, status) for n, tok, src, status in reads if n == node and tok == token],
                        [('127.0.0.2', 200), ('127.0.0.1', 403 if bounds else 200)])
        self.assertEqual(rows[-1], {'case': 'final_tokens_all_voters', 'passed': True})
        for fault in ('rebound', 'metadata'):
            with self.assertRaises(f.ScenarioFailure, msg=fault): execute(fault)

    def test_named_milestones_reject_missing_phase_duplicates_nonbool_and_premature_complete(self):
        rows = [{'case': name, 'passed': True} for name in sorted(f.REQUIRED-{'complete'})] + [{'case': 'complete', 'passed': True}]
        self.assertTrue(f.complete(rows))
        for name in f.REQUIRED:
            self.assertFalse(f.complete([row for row in rows if row['case'] != name]), name)
        self.assertFalse(f.complete(rows+rows[:1]))
        self.assertFalse(f.complete(rows[:-1]+[{'case': 'complete', 'passed': 1}]))
        self.assertFalse(f.complete([rows[-1]]+rows[:-1]))
        self.assertFalse(f.complete(rows[:-1]+[{'case': 'exception', 'passed': False}]+rows[-1:]))
        self.assertTrue(f.complete(rows[:-1]+[{'case': 'new_observation', 'passed': True}]+rows[-1:]))

    def test_issue_sends_overrides_once_and_retains_all_sensitive_identifiers_for_scanning(self):
        calls = []; sensitive = []
        class View:
            def __init__(self): self.sensitive = sensitive
            def remember(self, value, *keys): self.sensitive.extend(value[k] for k in keys)
            def call(self, name, method, path, body=None, **kwargs):
                calls.append((method, path, body, kwargs))
                if path.endswith('/role-id'): return {'data': {'role_id': 'private-role-id'}}
                if path.endswith('/secret-id'): return {'data': {'secret_id': 'private-secret-id', 'secret_id_accessor': 'private-accessor'}}
                return {}
        fields = {'cidr_list': f.FIRST, f.TOKEN_FIELD: f.SECOND}
        result = f.issue(View(), 'batch', 'finite', 2, fields)
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[-1], ('POST', f.role_path('batch', 'finite')+'/secret-id', fields, {}))
        self.assertEqual(set(sensitive), {'private-role-id', 'private-secret-id', 'private-accessor'})
        self.assertEqual(result['role_id'], 'private-role-id')
        for value in sensitive:
            self.assertFalse(f.rows_secret_free({'unexpected': value}, sensitive))
        self.assertFalse(f.rows_secret_free({'unexpected': 'binary-private-key'}, [b'binary-private-key']))

    def test_bootstrap_failure_still_stops_owned_cluster(self):
        closed = []
        class Cluster:
            def __init__(self, *args): pass
            def bootstrap(self): raise f.ScenarioFailure('synthetic_bootstrap_failure')
            def running(self): return []
            def close(self): closed.append(True)
        with patch.object(f, 'SaveCluster', Cluster), self.assertRaises(f.ScenarioFailure):
            f.run(Path('/synthetic'), Path('/synthetic-private'), [], [], [], [])
        self.assertEqual(closed, [True])

    def test_official_calibration_and_all_used_helpers_are_bound(self):
        hashes = f.helpers()
        self.assertEqual(hashes['official_secretid_overrides_calibration'], f.CALIBRATION_SHA)
        self.assertIn('approle_secret_cidrs_ha', hashes)
        self.assertIn('radius_cidrs_live', hashes)
        with patch.object(f, 'file_hash', return_value='0'*64), self.assertRaises(f.ScenarioFailure): f.helpers()


if __name__ == '__main__': unittest.main()
