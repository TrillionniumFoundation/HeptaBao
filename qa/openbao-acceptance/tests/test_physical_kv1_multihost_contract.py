"""Fail-closed contract tests for optional physical KV1 Raft record-scale fixture."""
from pathlib import Path
import hashlib
import inspect
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ha_multihost_live as ha
import physical_kv1_multihost_live as scale


class FakeNode:
    node_id = 1


class PhysicalRecordScaleContracts(unittest.TestCase):
    def test_original_snapshot_route_is_still_the_default(self):
        self.assertEqual(
            ha.snapshot_strategy(None),
            ('GET', 'sys/storage/raft/snapshot', None, 20)
        )
        self.assertEqual(
            ha.snapshot_strategy(object()),
            ('GET', 'sys/storage/raft/snapshot', None, 20)
        )

    def test_large_record_snapshot_uses_real_compaction_not_backup_export(self):
        self.assertEqual(
            ha.snapshot_strategy(scale.PhysicalKV1Scale()),
            ('POST', 'sys/storage/raft/compact', {}, 60)
        )

    def test_large_record_denominator_does_not_replace_baseline(self):
        run = scale.PhysicalKV1Scale()
        self.assertEqual(len(run.required_checks), 15)
        self.assertFalse(run.required_checks & ha.REQUIRED_CHECKS)
        self.assertEqual(len(run.required_checks | ha.REQUIRED_CHECKS), 69)
        self.assertGreater(scale.TARGET, 16 * 1024 * 1024)
        self.assertEqual(scale.PAYLOAD, 224 * 1024)
        self.assertTrue(run.runner_path.is_file())

    def test_controller_only_invokes_optional_growth_after_offline(self):
        source = inspect.getsource(ha.main)
        self.assertIn('extension.majority_after_offline(initial, offline)', source)
        self.assertLess(source.index('extension.majority_after_offline(initial, offline)'),
                        source.index('status, snapshot = api(context, initial, method, endpoint, payload,'))
        self.assertIn('extension is not None and hasattr(extension, "majority_after_offline")', source)

    def test_fingerprint_verification_rejects_successful_stale_value(self):
        run = scale.PhysicalKV1Scale()
        value = {'ordinal': 0, 'payload': 'test-value-not-a-secret'}
        run.expected['0000'] = scale.digest(value)
        run._call = lambda node, method, path, body=None, timeout=25: (200, {'data': value})
        run._verify(FakeNode())
        stale = {'ordinal': 0, 'payload': 'stale'}
        run._call = lambda node, method, path, body=None, timeout=25: (200, {'data': stale})
        with self.assertRaises(ha.FixtureError):
            run._verify(FakeNode())

    def test_deleted_keys_must_stay_absent_even_if_http_is_successful(self):
        run = scale.PhysicalKV1Scale()
        run._call = lambda node, method, path, body=None, timeout=25: (404, {'errors': ['missing']})
        run._absent(FakeNode(), '0001')
        run._call = lambda node, method, path, body=None, timeout=25: (200, {'data': {}})
        with self.assertRaises(ha.FixtureError):
            run._absent(FakeNode(), '0001')

    def test_payload_generation_has_exact_cap_and_fresh_randomness(self):
        run = scale.PhysicalKV1Scale()
        first = run._new_value(5)
        second = run._new_value(5)
        self.assertEqual(len(first['payload']), scale.PAYLOAD)
        self.assertEqual(len(second['payload']), scale.PAYLOAD)
        self.assertNotEqual(hashlib.sha256(scale.canonical(first)).digest(),
                            hashlib.sha256(scale.canonical(second)).digest())


if __name__ == '__main__':
    unittest.main()
