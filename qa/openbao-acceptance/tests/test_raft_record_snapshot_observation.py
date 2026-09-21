import base64
from copy import deepcopy
import json
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zlib
import raft_record_snapshot_observation as fixture


def compact(value): return base64.b64encode(value).decode().rstrip('=')
def encoded(value): return json.dumps(value, separators=(',', ':')).encode()
def descriptor(number, kind, size, records, payload):
    return {'id': [number] * 32, 'kind': kind, 'encoded_bytes': size,
            'record_count': records, 'payload_bytes': payload}
def object_value(ref, children=()):
    return {'reference': ref, 'children': list(children), 'sealed': compact(b'\x97' * (ref['encoded_bytes'] + 33))}


class RecordSnapshotGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'bundle.bin'
        block = descriptor(1, 'Block', 41, 0, 16)
        value = descriptor(2, 'Value', 80, 1, 16)
        leaf = descriptor(3, 'Leaf', 100, 1, 16)
        branch = descriptor(4, 'Branch', 100, 1, 16)
        owner = descriptor(5, 'OwnerChunk', 30, 0, 5)
        staged = descriptor(6, 'Block', 29, 0, 4)
        self.refs = [block, value, leaf, branch, owner, staged]
        objects = {bytes(ref['id']).hex(): object_value(ref, children) for ref, children in
                   [(block, []), (value, [block]), (leaf, [value]), (branch, [leaf]), (owner, []), (staged, [])]}
        self.secret = 'synthetic-secret-never-exported'
        self.state = {'last_applied_log': {'leader_id': {'term': 2, 'node_id': 1}, 'index': 42},
            'last_membership': {'log_id': None, 'membership': {'configs': [[1, 2, 3]], 'nodes': {'1': None, '2': None, '3': None}}},
            'client_status': {'opaque-synthetic-client': self.secret},
            'records_v5': {'objects': objects, 'published': {'base': {'Legacy': [7] * 32},
                'envelope': 'hbr3:4:root:' + '08' * 32 + ':' + compact(b'encrypted-root-sentinel'),
                'direct_refs': [branch, owner]}}}
    def tearDown(self): self.temp.cleanup()
    def bundle(self, state=None, snapshot_state=None):
        state = deepcopy(self.state if state is None else state)
        snapshot_state = deepcopy(state if snapshot_state is None else snapshot_state)
        return {'format_version': 3, 'journal_format': 1, 'generation': 44, 'state': state,
                'current_snapshot': {'meta': {'last_log_id': snapshot_state['last_applied_log'],
                    'last_membership': snapshot_state['last_membership'], 'snapshot_id': 'synthetic-42'},
                    'data': compact(encoded({'format_version': 3, 'state': snapshot_state}))}}
    def write(self, bundle=None):
        payload = encoded(self.bundle() if bundle is None else bundle)
        self.path.write_bytes(fixture.MAGIC + len(payload).to_bytes(8, 'little') + payload
                              + zlib.crc32(payload).to_bytes(4, 'little'))
    def inspect(self, minimum=42): return fixture.inspect_record_bundle(self.path, minimum_index=minimum)
    def reject(self, state):
        self.write(self.bundle(state))
        with self.assertRaises(ValueError): self.inspect()

    def test_real_frame_returns_bounded_safe_structural_observations_without_claiming_crypto(self):
        self.write(); before = self.path.read_bytes(); report = self.inspect()
        self.assertEqual(before, self.path.read_bytes())
        self.assertEqual(report['snapshot_index'], 42)
        self.assertEqual(report['snapshot_state']['object_count'], 6)
        self.assertEqual(report['snapshot_state']['reachable_object_count'], 5)
        self.assertEqual(report['snapshot_state']['staged_unreachable_object_count'], 1)
        self.assertEqual(report['snapshot_state']['maximum_graph_depth'], 4)
        self.assertEqual(report['snapshot_state']['published_payload_bytes'], 16)
        self.assertEqual(report['snapshot_state']['published_record_count'], 1)
        self.assertFalse(report['cryptographic_authenticity_verified'])
        self.assertFalse(report['plaintext_key_order_verified'])
        dumped = json.dumps(report)
        for forbidden in (self.secret, 'opaque-synthetic-client', 'hbr3:', compact(b'encrypted-root-sentinel'), '01' * 32):
            self.assertNotIn(forbidden, dumped)

    def test_all_objects_and_both_current_and_snapshot_graphs_are_checked(self):
        broken = deepcopy(self.state)
        del broken['records_v5']['objects']['01' * 32]
        for current, snapshot in [(broken, self.state), (self.state, broken)]:
            self.write(self.bundle(current, snapshot))
            with self.assertRaises(ValueError): self.inspect()
        broken = deepcopy(self.state)
        broken['records_v5']['objects']['02' * 32]['children'][0]['encoded_bytes'] += 1
        self.reject(broken)
        broken = deepcopy(self.state)
        broken['records_v5']['objects']['06' * 32]['reference']['id'] = [8] * 32
        self.reject(broken)
        broken = deepcopy(self.state)
        broken['records_v5']['published']['direct_refs'][0]['record_count'] += 1
        self.reject(broken)

    def test_aggregates_kinds_bounds_and_noncanonical_encodings_are_rejected(self):
        for mutation in (
            lambda s: s['records_v5']['objects']['03' * 32]['reference'].update(payload_bytes=17),
            lambda s: s['records_v5']['objects']['02' * 32]['reference'].update(encoded_bytes=81),
            lambda s: s['records_v5']['objects']['06' * 32]['reference'].update(record_count=True),
            lambda s: s['records_v5']['objects']['06' * 32]['reference'].update(kind=['Block']),
            lambda s: s['records_v5']['objects']['06' * 32].update(sealed='Zg=='),
            lambda s: s['records_v5']['objects']['06' * 32].update(sealed='Zh'),
            lambda s: s['records_v5']['objects']['06' * 32].update(unexpected='field'),
            lambda s: s['records_v5']['published'].update(envelope='hbr3:4:root:' + '00' * 32 + ':Zg'),
        ):
            broken = deepcopy(self.state); mutation(broken); self.reject(broken)
        self.write()
        for name, bound in [('MAX_OBJECTS', 5), ('MAX_APPLICATION_BYTES', 100), ('MAX_ARTIFACT_BYTES', 64)]:
            with patch.object(fixture, name, bound), self.assertRaises(ValueError): self.inspect()

    def test_cycles_and_excessive_depth_in_unreachable_staged_graph_are_not_ignored(self):
        broken = deepcopy(self.state)
        circular = descriptor(7, 'Branch', 25, 0, 0)
        broken['records_v5']['objects']['07' * 32] = object_value(circular, [circular])
        self.reject(broken)
        broken = deepcopy(self.state); child = self.refs[3]
        for number in range(7, 23):
            parent = descriptor(number, 'Branch', 100, 1, 16)
            broken['records_v5']['objects'][bytes(parent['id']).hex()] = object_value(parent, [child])
            child = parent
        self.reject(broken)

    def test_missing_version_fence_metadata_and_corrupt_old_frontier_fail_instead_of_pending(self):
        for which in ('bundle', 'wrapper', 'metadata', 'membership', 'checksum', 'padded'):
            bundle = self.bundle()
            if which == 'bundle': bundle['format_version'] = 2
            elif which == 'wrapper': bundle['current_snapshot']['data'] = compact(encoded(self.state))
            elif which == 'metadata': bundle['current_snapshot']['meta']['last_log_id']['index'] -= 1
            elif which == 'membership': bundle['current_snapshot']['meta']['last_membership'] = {}
            elif which == 'padded': bundle['current_snapshot']['data'] += '='
            self.write(bundle)
            if which == 'checksum':
                value = bytearray(self.path.read_bytes()); value[-1] ^= 1; self.path.write_bytes(value)
            with self.assertRaises(ValueError, msg=which): self.inspect(minimum=99)

    def test_only_real_missing_or_older_valid_snapshot_is_pending(self):
        self.write()
        with self.assertRaises(fixture.SnapshotPending): self.inspect(minimum=43)
        bundle = self.bundle(); bundle['current_snapshot'] = None; self.write(bundle)
        with self.assertRaises(fixture.SnapshotPending): self.inspect()
        legacy = {k: deepcopy(v) for k, v in self.state.items() if k != 'records_v5'}
        legacy['last_applied_log']['index'] = 1
        bundle = self.bundle(); bundle['current_snapshot']['meta'] = {
            'last_log_id': legacy['last_applied_log'], 'last_membership': legacy['last_membership']}
        bundle['current_snapshot']['data'] = compact(encoded(legacy))
        self.write(bundle)
        with self.assertRaises(fixture.SnapshotPending): self.inspect()
        with self.assertRaises(ValueError): self.inspect(minimum=1)
        # A legitimate stage-only current state is structurally valid; it cannot
        # qualify as the required published snapshot after reaching the frontier.
        staged = deepcopy(self.state); staged['records_v5']['published'] = None
        self.write(self.bundle(staged))
        with self.assertRaises(ValueError): self.inspect()
        with self.assertRaises(fixture.SnapshotPending): self.inspect(minimum=43)

    def prepared(self):
        state = deepcopy(self.state)
        status = 'hbr3:8:old-root:' + '09'*32 + ':' + compact(b'synthetic-encrypted-old-root')
        state['client_status']['heptabao-production-ha'] = status
        state['records_v5'] = {'objects': {}, 'published': None, 'legacy_migration_prepared': {
            'digest': [9]*32, 'status_sha256': list(hashlib.sha256(status.encode()).digest())}}
        return state

    def test_prepared_marker_matches_exact_old_status_and_cannot_claim_published_snapshot(self):
        state = self.prepared()
        report = fixture.inspect_state(state)
        self.assertTrue(report['legacy_migration_prepared'])
        self.assertFalse(report['publication_present'])
        self.write(self.bundle(state))
        with self.assertRaises(ValueError): self.inspect()
        with self.assertRaises(fixture.SnapshotPending): self.inspect(minimum=43)
        for mutation in (
            lambda s: s['records_v5']['legacy_migration_prepared'].update(digest=[8]*32),
            lambda s: s['records_v5']['legacy_migration_prepared'].update(status_sha256=[8]*32),
            lambda s: s['records_v5']['legacy_migration_prepared'].update(digest=[0]*32),
            lambda s: s['records_v5']['legacy_migration_prepared'].update(unexpected='field'),
            lambda s: s['records_v5'].update(published=self.state['records_v5']['published']),
            lambda s: s['client_status'].update({'heptabao-production-ha':'hbr3:8:old-root:'+'09'*32+':YQ'}),
        ):
            broken = deepcopy(state); mutation(broken)
            with self.assertRaises(ValueError): fixture.inspect_state(broken)

    def test_only_empty_prepared_records_allow_oversized_retained_legacy_map(self):
        state = self.prepared()
        with patch.object(fixture, 'MAX_APPLICATION_BYTES', 100):
            self.assertGreater(fixture.inspect_state(state)['charged_application_bytes'], 100)
            unprepared = deepcopy(state); del unprepared['records_v5']['legacy_migration_prepared']
            with self.assertRaises(ValueError): fixture.inspect_state(unprepared)
            state['records_v5']['objects']['06'*32] = deepcopy(self.state['records_v5']['objects']['06'*32])
            with self.assertRaises(ValueError): fixture.inspect_state(state)

    def test_prepared_status_identity_accepts_old_envelopes_but_not_malformed_aliases(self):
        for status in ('hbr1:root:'+'09'*32+':abcd', 'hbr2:4:root:'+'09'*32+':abcd'):
            self.assertEqual(fixture.legacy_status_digest(status), '09'*32)
        for status in ('hbr1:root:'+'AB'*32+':ABCD', 'hbr2:'+'0'*5000+'4:root:'+'AB'*32+':ABCD',
                       'hbr3:00004:root:'+'AB'*32+':YQ'):
            self.assertEqual(fixture.legacy_status_digest(status), 'ab'*32)
        for status in ('hbr1:root:ambiguous:'+'09'*32+':abcd', 'hbr2:1:root:'+'09'*32+':abcd',
                       'hbr2:4:root:'+'09'*32+':abc', 'hbr3:4:root:'+'09'*32+':YQ=='):
            with self.assertRaises(ValueError): fixture.legacy_status_digest(status)

    def test_duplicate_json_fields_and_symlinks_are_not_accepted(self):
        self.write(); link = self.path.parent / 'link'; link.symlink_to(self.path)
        with self.assertRaises(ValueError): fixture.inspect_record_bundle(link, minimum_index=42)
        bundle = self.bundle()
        data = encoded({'format_version': 3, 'state': self.state})
        data = data.replace(b'"format_version":3', b'"format_version":3,"format_version":3', 1)
        bundle['current_snapshot']['data'] = compact(data); self.write(bundle)
        with self.assertRaises(ValueError): self.inspect()
        for invalid in (b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1,"x":1}'):
            with self.assertRaises(ValueError): fixture.strict_json(invalid)


if __name__ == '__main__': unittest.main()
