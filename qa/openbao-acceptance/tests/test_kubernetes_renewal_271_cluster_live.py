import copy
import hashlib
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


class GenuineRenewalCustody(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.receipt = {
            'schema': 'heptabao.native-build.v1', 'source_commit': 'c' * 40,
            'source_tree': 'd' * 40, 'binary_sha256': 'e' * 64,
            'build_exit_code': 0, 'source_freeze_verified': True,
            'native_abi': 'linux-x86_64',
        }
        self.event = {
            'auditID': 'owned-review-1', 'stage': 'ResponseComplete', 'verb': 'create',
            'requestURI': '/apis/authentication.k8s.io/v1/tokenreviews',
            'user': {'username': 'system:serviceaccount:hb-review:reviewer', 'uid': 'reviewer-uid'},
            'objectRef': {'apiGroup': 'authentication.k8s.io', 'apiVersion': 'v1', 'resource': 'tokenreviews'},
            'responseStatus': {'code': 201},
        }

    def bind(self, receipt):
        return live.validate_build_receipt(receipt, 'c' * 40, 'd' * 40, 'e' * 64)

    def test_build_receipt_requires_exact_source_tree_and_binary(self):
        self.assertEqual(self.bind(self.receipt), 'linux-x86_64')
        for field in ('schema', 'source_commit', 'source_tree', 'binary_sha256'):
            with self.subTest(field=field):
                altered = dict(self.receipt); altered[field] = 'foreign'
                with self.assertRaisesRegex(live.kube.FixtureFailure, 'binding_invalid'):
                    self.bind(altered)

    def test_build_receipt_requires_actual_success_and_frozen_source(self):
        for field, values in [('build_exit_code', [False, True, '0', 1, None]),
                              ('source_freeze_verified', [False, 1, 'true', None]),
                              ('native_abi', ['', 'linux x86', 'a' * 81, None])]:
            for value in values:
                with self.subTest(field=field, value=value):
                    altered = dict(self.receipt); altered[field] = value
                    with self.assertRaisesRegex(live.kube.FixtureFailure, 'binding_invalid'):
                        self.bind(altered)

    def test_build_receipt_digest_binds_the_actual_parsed_bytes(self):
        path = self.root / 'build.json'
        raw = json.dumps(self.receipt).encode(); path.write_bytes(raw)
        expected = hashlib.sha256(raw).hexdigest()
        self.assertEqual(live.read_build_receipt(path, expected, 'c' * 40, 'd' * 40, 'e' * 64), 'linux-x86_64')
        path.write_bytes(raw + b' ')
        with self.assertRaisesRegex(live.kube.FixtureFailure, 'digest_mismatch'):
            live.read_build_receipt(path, expected, 'c' * 40, 'd' * 40, 'e' * 64)

    def test_build_receipt_symlink_and_oversized_files_are_rejected(self):
        path = self.root / 'build.json'; path.write_text(json.dumps(self.receipt))
        link = self.root / 'link.json'; link.symlink_to(path)
        with self.assertRaises(OSError):
            live.read_build_receipt(link, 'a' * 64, 'c' * 40, 'd' * 40, 'e' * 64)
        path.write_bytes(b' ' * 65537)
        with self.assertRaisesRegex(live.kube.FixtureFailure, 'oversized'):
            live.read_build_receipt(path, 'a' * 64, 'c' * 40, 'd' * 40, 'e' * 64)

    def test_foreign_or_admin_review_cannot_satisfy_a_fresh_operation(self):
        for field, value in [('username', 'kubernetes-admin'), ('uid', 'other-reviewer'), ('uid', '')]:
            event = copy.deepcopy(self.event); event['user'][field] = value
            with self.subTest(field=field, value=value):
                self.assertFalse(live.owned_review_events([event], 'reviewer-uid', set(), 201))

    def test_review_requires_exact_route_resource_stage_verb_and_response(self):
        for field, value in [('requestURI', '/apis/authentication.k8s.io/v1/other'),
                              ('stage', 'RequestReceived'), ('verb', 'get')]:
            event = copy.deepcopy(self.event); event[field] = value
            with self.subTest(field=field):
                self.assertFalse(live.owned_review_events([event], 'reviewer-uid', set(), 201))
        for field in ('apiGroup', 'apiVersion', 'resource'):
            event = copy.deepcopy(self.event); event['objectRef'][field] = 'other'
            with self.subTest(field=field):
                self.assertFalse(live.owned_review_events([event], 'reviewer-uid', set(), 201))
        self.assertFalse(live.owned_review_events([self.event], 'reviewer-uid', set(), 403))

    def test_replayed_missing_or_multiple_audit_ids_do_not_pass(self):
        seen = set()
        self.assertTrue(live.owned_review_events([self.event], 'reviewer-uid', seen, 201))
        self.assertFalse(live.owned_review_events([self.event], 'reviewer-uid', seen, 201))
        self.assertFalse(live.owned_review_events([], 'reviewer-uid', set(), 201))
        self.assertFalse(live.owned_review_events([self.event, self.event], 'reviewer-uid', set(), 201))
        missing = dict(self.event); missing.pop('auditID')
        self.assertFalse(live.owned_review_events([missing], 'reviewer-uid', set(), 201))

    def test_user_agent_is_metadata_and_never_review_authority(self):
        for ua in [None, '', 'Go-http-client/2.0', 'Python-urllib/3.12']:
            event = dict(self.event, userAgent=ua)
            self.assertTrue(live.owned_review_events([event], 'reviewer-uid', set(), 201))
        foreign = copy.deepcopy(self.event); foreign['user']['uid'] = 'foreign'
        foreign['userAgent'] = 'Go-http-client/2.0'
        self.assertFalse(live.owned_review_events([foreign], 'reviewer-uid', set(), 201))

    def test_positive_renewal_requires_the_original_renewable_token(self):
        result = {'auth': {'client_token': 'issued', 'renewable': True}}
        self.assertTrue(live.renewed_token(result, 'issued'))
        self.assertFalse(live.renewed_token(result, 'other'))
        self.assertFalse(live.renewed_token({'auth': {'client_token': 'issued', 'renewable': 1}}, 'issued'))
        self.assertFalse(live.renewed_token({'auth': {}}, 'issued'))

    def test_accessor_renewal_binds_the_accessor_without_returning_a_bearer(self):
        result = {'auth': {'accessor': 'issued-accessor', 'client_token': '', 'renewable': True}}
        self.assertTrue(live.renewed_token(result, 'issued', 'accessor', 'issued-accessor'))
        result['auth'].pop('client_token')
        self.assertTrue(live.renewed_token(result, 'issued', 'accessor', 'issued-accessor'))
        self.assertFalse(live.renewed_token(result, 'issued', 'accessor', 'other-accessor'))
        result['auth']['client_token'] = 'issued'
        self.assertFalse(live.renewed_token(result, 'issued', 'accessor', 'issued-accessor'))

    def test_first_positive_requires_an_actual_expiry_extension(self):
        before = '2026-10-13T18:14:00Z'
        self.assertTrue(live.expiry_extended(before, '2026-10-13T18:17:00+00:00'))
        self.assertFalse(live.expiry_extended(before, before))
        self.assertFalse(live.expiry_extended(before, '2026-10-13T18:13:00Z'))
        self.assertFalse(live.expiry_extended(before, '2026-10-13T18:17:00'))
        self.assertFalse(live.expiry_extended(before, 'invalid'))

    def test_final_capture_failure_cannot_be_lifecycle_success(self):
        report = {}; destination = self.root / 'final.json'
        with patch.object(live.AuditCluster, 'audit', side_effect=RuntimeError('unavailable')):
            cluster = live.AuditCluster(Path('/fixture/kind'), self.root)
            self.assertFalse(live.capture_final_metadata(cluster, destination, [], report, {'owned-review-1'}))
        self.assertEqual(report['metadata_capture_failure'], 'RuntimeError')
        self.assertFalse(destination.exists())

    def test_final_capture_requires_every_previously_observed_audit_id(self):
        cluster = live.AuditCluster(Path('/fixture/kind'), self.root)
        report = {}; destination = self.root / 'final.json'
        with patch.object(cluster, 'audit', return_value=[self.event]):
            self.assertFalse(live.capture_final_metadata(cluster, destination, [], report, {'missing-review'}))
            self.assertTrue(live.capture_final_metadata(cluster, destination, [], {}, {'owned-review-1'}))
        self.assertEqual(report['metadata_capture_failure'], 'FixtureFailure')

    def test_final_capture_credentials_fail_closed(self):
        cluster = live.AuditCluster(Path('/fixture/kind'), self.root)
        event = dict(self.event, accidental='synthetic-runtime-credential')
        with patch.object(cluster, 'audit', return_value=[event]):
            self.assertFalse(live.capture_final_metadata(cluster, self.root / 'final.json',
                                                       ['synthetic-runtime-credential'], {}, {'owned-review-1'}))

    def test_full_denominator_cannot_override_missing_final_evidence(self):
        # Synthetic contract data exercise final admission, never a live pass.
        report = {'checks': [{'case': case, 'passed': True} for case in live.REQUIRED]}
        self.assertTrue(live.qualification_passed(report))
        report['metadata_capture_failure'] = 'RuntimeError'
        self.assertFalse(live.qualification_passed(report))
        report.pop('metadata_capture_failure')
        next(row for row in report['checks'] if row['case'] == 'owned_cluster_and_services_cleaned')['passed'] = False
        self.assertFalse(live.qualification_passed(report))

    def test_incomplete_or_duplicate_denominator_never_passes(self):
        checks = [{'case': case, 'passed': True} for case in sorted(live.REQUIRED)]
        self.assertFalse(live.qualification_passed({'checks': checks[:-1]}))
        self.assertFalse(live.qualification_passed({'checks': checks[:-1] + [checks[0]]}))


if __name__ == '__main__':
    unittest.main()
