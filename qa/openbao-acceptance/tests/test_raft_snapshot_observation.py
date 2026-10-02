import base64
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from raft_snapshot_observation import inspect_bundle, MAGIC, COMPACT_MILESTONES, complete_compact_scenarios
import raft_snapshot_upgrade as upgrade
from online_evidence import complete_checks


class RaftSnapshotObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)/'bundle.bin'
        self.material = 'secret-material-must-not-appear-in-observation'
        self.state = {'last_applied_log': {'index': 4}, 'last_membership': {}, 'client_status': {'opaque': self.material}}
        self.raw = json.dumps(self.state).encode()
        self.bundle = {'format_version': 2, 'state': self.state, 'current_snapshot': {
            'meta': {'last_log_id': {'index': 4}, 'last_membership': {}},
            'data': base64.b64encode(self.raw).decode().rstrip('=')}}
    def tearDown(self):self.temp.cleanup()
    def write(self, bundle=None):
        payload = json.dumps(self.bundle if bundle is None else bundle).encode()
        self.path.write_bytes(MAGIC + len(payload).to_bytes(8, 'little') + payload + zlib.crc32(payload).to_bytes(4, 'little'))
    def test_actual_frame_verification_returns_only_safe_metadata(self):
        self.write()
        value = inspect_bundle(self.path)
        self.assertEqual(set(value), {'format_version', 'artifact_bytes', 'artifact_sha256', 'snapshot_bytes', 'canonical_representation', 'checksum_verified', 'metadata_matches_snapshot'})
        self.assertEqual(value['snapshot_bytes'], len(self.raw))
        self.assertEqual(value['artifact_bytes'], self.path.stat().st_size)
        self.assertNotIn(self.material, json.dumps(value))
    def test_legacy_array_and_compact_formats_are_not_interchangeable(self):
        self.bundle['format_version'] = 1
        self.bundle['current_snapshot']['data'] = list(self.raw)
        self.write()
        self.assertEqual(inspect_bundle(self.path, 1)['format_version'], 1)
        with self.assertRaises(ValueError):inspect_bundle(self.path, 2)
        self.bundle['format_version'] = 2
        self.write()
        with self.assertRaises(ValueError):inspect_bundle(self.path, 2)
    def test_records_v5_requires_format3_and_compact_encoding(self):
        records = {"objects": {}, "published": None}
        state = dict(self.state, records_v5=records)
        raw = json.dumps({"format_version": 3, "state": state}).encode()
        self.bundle["format_version"] = 3
        self.bundle["state"] = state
        self.bundle["current_snapshot"]["data"] = base64.b64encode(raw).decode().rstrip("=")
        self.write()
        self.assertEqual(inspect_bundle(self.path)["format_version"], 3)
        self.assertEqual(inspect_bundle(self.path, 3)["format_version"], 3)
        with self.assertRaises(ValueError): inspect_bundle(self.path, 2)
        direct = json.dumps(state).encode()
        self.bundle["current_snapshot"]["data"] = base64.b64encode(direct).decode().rstrip("=")
        self.write()
        with self.assertRaises(ValueError): inspect_bundle(self.path)
        wrong = json.dumps({"format_version": 2, "state": state}).encode()
        self.bundle["current_snapshot"]["data"] = base64.b64encode(wrong).decode().rstrip("=")
        self.write()
        with self.assertRaises(ValueError): inspect_bundle(self.path)
        self.bundle["current_snapshot"]["data"] = base64.b64encode(raw).decode().rstrip("=")
        self.bundle["state"] = self.state
        self.write()
        with self.assertRaises(ValueError): inspect_bundle(self.path)

    def test_corrupt_checksum_metadata_and_noncanonical_base64_fail(self):
        self.write()
        frame = bytearray(self.path.read_bytes());frame[-1] ^= 1;self.path.write_bytes(frame)
        with self.assertRaises(ValueError):inspect_bundle(self.path)
        for data in ['Zg==', 'Zh', 'not_base64!', 'AA\n', '\u4f60']:
            self.bundle['current_snapshot']['data'] = data
            self.write()
            with self.assertRaises(ValueError):inspect_bundle(self.path)
        self.bundle['current_snapshot']['data'] = base64.b64encode(self.raw).decode().rstrip('=')
        self.bundle['current_snapshot']['meta']['last_log_id'] = {'index': 5}
        self.write()
        with self.assertRaises(ValueError):inspect_bundle(self.path)
    def test_no_write_or_link_follow_during_observation(self):
        self.write();before = self.path.read_bytes()
        inspect_bundle(self.path)
        self.assertEqual(self.path.read_bytes(), before)
        link = self.path.parent/'link';link.symlink_to(self.path)
        with self.assertRaises(ValueError):inspect_bundle(link)
    def test_required_actual_phases_cannot_be_replaced_by_count(self):
        names = sorted(COMPACT_MILESTONES - {'compact_snapshot_complete'}) + ['compact_snapshot_complete']
        self.assertTrue(complete_compact_scenarios(names))
        self.assertTrue(complete_compact_scenarios(names[:-1] + ['additional_check'] + names[-1:]))
        for bad in [names[1:], names[:-1], names + names[:1], names[:-1] + [True]]:
            self.assertFalse(complete_compact_scenarios(bad))
        rows = [{'case': n, 'passed': True} for n in upgrade.REQUIRED]
        self.assertTrue(complete_checks(rows, required_cases=upgrade.REQUIRED))
        self.assertFalse(complete_checks([dict(r, passed=1) for r in rows], required_cases=upgrade.REQUIRED))
        self.assertFalse(complete_checks([r for r in rows if r['case'] != 'old_rejection_preserves_all_raft_files'], required_cases=upgrade.REQUIRED))
    def test_legacy_admission_requires_fixed_clean_build_receipt(self):
        source, digest = '1'*40, '2'*64
        receipt = {'status': 'passed', 'build_source_commit': source, 'source_and_binary_unchanged': True, 'cases_match': True, 'runner_unchanged': True,
                   'candidate_source': {'source_commit': source, 'binary_sha256': digest, 'source_dirty': False}}
        with patch.object(upgrade, 'LEGACY_SOURCE', source), patch.object(upgrade, 'LEGACY_SHA256', digest), patch.object(upgrade, 'LEGACY_RECEIPT', self.path):
            upgrade.admit_legacy(receipt, digest)
            for invalid in [dict(receipt, status='failed'), dict(receipt, source_and_binary_unchanged=False),
                            dict(receipt, candidate_source=dict(receipt['candidate_source'], source_dirty=True))]:
                with self.assertRaises(ValueError):upgrade.admit_legacy(invalid, digest)
            with self.assertRaises(ValueError):upgrade.admit_legacy(receipt, '3'*64)
        with patch.object(upgrade, 'LEGACY_SOURCE', None):
            with self.assertRaises(ValueError):upgrade.admit_legacy(receipt, digest)


if __name__ == '__main__':unittest.main()
