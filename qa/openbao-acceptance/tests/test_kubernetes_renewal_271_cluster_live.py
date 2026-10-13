import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import kubernetes_renewal_271_cluster_live as live


class GenuineRenewalBoundary(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.cluster = live.AuditCluster(Path('/fixture/kind'), Path(self.directory.name))
        self.cluster.name = 'hb-accept-0123456789abcdef'
        self.cluster.attempted = True
        self.cid = 'a' * 64
        self.node = {
            'Id': self.cid, 'Name': '/' + self.cluster.name + '-control-plane',
            'Config': {'Image': live.kube.NODE_IMAGE,
                       'Labels': {'io.x-k8s.kind.cluster': self.cluster.name}},
            'State': {'Running': True, 'Pid': 100, 'StartedAt': 'same-instance'},
            'Mounts': [{'Source': str(self.cluster.root / 'metadata-audit-policy.json'),
                        'Destination': '/etc/kubernetes/hb-audit-policy.json', 'RW': False,
                        'Type': 'bind'}],
        }

    def response(self, stdout='', code=0, stderr=''):
        return subprocess.CompletedProcess([], code, stdout, stderr)

    def reject_identity(self, field, value):
        node = copy.deepcopy(self.node)
        target = node
        for key in field[:-1]:
            target = target[key]
        target[field[-1]] = value
        with patch.object(self.cluster, 'docker', return_value=self.response(json.dumps([node]))) as docker:
            with self.assertRaises(live.kube.FixtureFailure):
                self.cluster.owned_node(self.cid)
            self.assertEqual([call.args[0] for call in docker.call_args_list], ['inspect'])

    def test_wrong_cluster_never_authorizes_stop(self):
        self.reject_identity(('Config', 'Labels', 'io.x-k8s.kind.cluster'), 'production')

    def test_changed_full_id_never_authorizes_stop(self):
        self.reject_identity(('Id',), 'b' * 64)

    def test_wrong_node_name_never_authorizes_stop(self):
        self.reject_identity(('Name',), '/openclaw-syncthing')

    def test_wrong_image_never_authorizes_stop(self):
        self.reject_identity(('Config', 'Image'), 'kindest/node:latest')

    def test_foreign_policy_mount_never_authorizes_stop(self):
        self.reject_identity(('Mounts', 0, 'Source'), '/some/other/fixture.json')

    def test_node_restart_during_stop_denies_removal(self):
        restarted = copy.deepcopy(self.node)
        restarted['State'] = {'Running': False, 'Pid': 0, 'StartedAt': 'new-instance'}
        responses = iter([self.response(self.cid + '\n'), self.response(json.dumps([self.node])),
                          self.response(self.cid + '\n'), self.response(json.dumps([restarted]))])
        with patch.object(self.cluster, 'docker', side_effect=lambda *a, **k: next(responses)) as docker:
            with self.assertRaisesRegex(live.kube.FixtureFailure, 'restart_identity_changed'):
                self.cluster.close()
            self.assertNotIn('rm', [call.args[0] for call in docker.call_args_list])
        self.assertFalse(json.loads((self.cluster.root / 'owned-cleanup.json').read_text())['passed'])

    def test_stop_error_can_only_reconcile_observed_same_exited_node(self):
        exited = copy.deepcopy(self.node)
        exited['State'] = {'Running': False, 'Pid': 0, 'StartedAt': 'same-instance'}
        responses = iter([self.response(self.cid + '\n'), self.response(json.dumps([self.node])),
                          self.response(code=1, stderr='exit event delayed'),
                          self.response(json.dumps([exited])), self.response(self.cid + '\n'), self.response()])
        with patch.object(self.cluster, 'docker', side_effect=lambda *a, **k: next(responses)) as docker:
            self.cluster.close()
            removal = next(call for call in docker.call_args_list if call.args[0] == 'rm')
            self.assertEqual(removal.args, ('rm', '-v', self.cid))
            self.assertFalse(any('prune' in call.args or '-f' in call.args for call in docker.call_args_list))
        receipt = json.loads((self.cluster.root / 'owned-cleanup.json').read_text())
        self.assertTrue(receipt['passed'])
        self.assertEqual(receipt['operations'][0]['exit_code'], 1)

    def test_multiple_nodes_fail_before_any_mutation(self):
        with patch.object(self.cluster, 'docker', return_value=self.response(self.cid + '\n' + 'b' * 64)) as docker:
            with self.assertRaisesRegex(live.kube.FixtureFailure, 'unexpected_owned_node_count'):
                self.cluster.close()
            self.assertEqual(len(docker.call_args_list), 1)

    def test_required_genuine_gate_has_all_twenty_four_negative_routes(self):
        self.assertEqual(len(live.REQUIRED), 79)
        denied = {case for case in live.REQUIRED if case.endswith('_denied')}
        self.assertEqual(len(denied), 24)
        self.assertIn('actual_tokenreview_metadata_audit_enabled', live.REQUIRED)
        self.assertIn('owned_cluster_and_services_cleaned', live.REQUIRED)
        self.assertIn('fixed_denominator_complete', live.REQUIRED)

    def test_metadata_body_fails_instead_of_becoming_genuine_proof(self):
        result = subprocess.CompletedProcess([], 0, json.dumps({'requestObject': {'token': 'secret'}}).encode(), b'')
        with patch.object(live.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(live.kube.FixtureFailure, 'contains_request_or_response_body'):
                self.cluster.audit()


if __name__ == '__main__':
    unittest.main()
