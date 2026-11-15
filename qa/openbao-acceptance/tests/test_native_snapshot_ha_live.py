import gzip
import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import native_snapshot_ha_live as fixture


def tar_bytes(*, corrupt_value=False, padding_byte=b'\0', tail=b''):
    state = b'HBB2' + b'synthetic-not-authenticated' * 4
    metadata = json.dumps({'format': 'heptabao-native-snapshot-v2',
        'state_format': 'heptabao-encrypted-backup-v1/HBB2', 'generation': 7,
        'state_bytes': len(state), 'seal_identity': {
            'format': 'heptabao-seal-metadata-digest-v1', 'sha256': 'a' * 64}},
        separators=(',', ':')).encode()
    sums = (hashlib.sha256(metadata).hexdigest() + '  meta.json\n' +
            hashlib.sha256(state).hexdigest() + '  state.bin\n').encode()
    if corrupt_value:
        state = state[:-1] + bytes([state[-1] ^ 1])
    result = bytearray()
    for name, body in zip(fixture.NAMES, (metadata, state, sums, b'opaque-sealed-sums')):
        member = tarfile.TarInfo(name); member.size = len(body); member.mode = 0o600
        result += member.tobuf(format=tarfile.USTAR_FORMAT) + body
        result += padding_byte * ((-len(body)) % 512)
    return bytes(result) + b'\0' * 1024 + tail


class NativeSnapshotHaGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def archive(self, data):
        path = self.root / 'test.snap'
        path.write_bytes(data)
        return path

    def test_complete_requires_real_milestones_unique_final_success(self):
        rows = [{'case': name, 'passed': True} for name in sorted(fixture.REQUIRED - {'complete'})]
        rows.append({'case': 'complete', 'passed': True})
        self.assertTrue(fixture.complete(rows))
        for phase in ('leader_archive_complete', 'finite_final_head', 'quorum_save_denied',
                      'successor_addresses', 'all_final', 'processes_stopped'):
            self.assertFalse(fixture.complete([row for row in rows if row['case'] != phase]))
        self.assertFalse(fixture.complete([]))
        self.assertFalse(fixture.complete(rows + [rows[-1]]))
        self.assertFalse(fixture.complete(rows[:-1]))
        self.assertFalse(fixture.complete([*rows[:-1], {'case': 'complete', 'passed': False}]))

    def test_real_config_hook_preserves_five_second_listener_and_api_targets(self):
        nodes = []
        peers = {}
        for number in (1, 2, 3):
            root = self.root / str(number); root.mkdir(mode=0o700)
            (root / 'server.json').write_text(json.dumps({'timeout_seconds': 5, 'listen': 'unused'}))
            (root / 'server.json').chmod(0o600)
            node = SimpleNamespace(node_id=number, http_port=8000 + number,
                                   raft_port=9000 + number, root=root)
            nodes.append(node)
            peers[str(number)] = {'address': f'127.0.0.1:{node.raft_port}'}
        cluster = fixture.SaveCluster.__new__(fixture.SaveCluster)
        def configure(instance):
            instance.nodes, instance.peers = nodes, peers
        with patch.object(fixture.PartitionCluster, 'configure', configure):
            cluster.configure()
        for node in nodes:
            self.assertEqual(peers[str(node.node_id)]['api_address'], f'https://127.0.0.1:{node.http_port}')
            self.assertEqual(peers[str(node.node_id)]['address'], f'127.0.0.1:{node.raft_port}')
            self.assertEqual(json.loads((node.root / 'server.json').read_text())['timeout_seconds'], 5)

    def test_actual_address_phase_uses_public_api_and_requires_successor(self):
        checked, calls = [], []
        nodes = []
        for number in (1, 2, 3):
            def call(method, path, *, token, number=number):
                calls.append((method, path, token))
                return 200, {'leader_address': 'https://127.0.0.1:8102', 'is_self': number == 2}
            nodes.append(SimpleNamespace(node_id=number, call=call, http_port=8100 + number))
        fixture.assert_addresses(SimpleNamespace(nodes=nodes, root_token='synthetic-root'), nodes[1],
            lambda case, passed: checked.append({'case': case, 'passed': passed}), 'successor_addresses')
        self.assertEqual([row['case'] for row in checked], ['successor_addresses_leader', 'successor_addresses'])
        self.assertTrue(all(row['passed'] for row in checked))
        self.assertEqual(calls, [('GET', 'sys/leader', 'synthetic-root')])

    def test_rejection_does_not_accept_archives_success_or_auth_payload(self):
        error = {'content-type': 'application/json'}
        self.assertTrue(fixture.denied((503, error, b'{"errors":["unavailable"]}'), 503))
        for response in ((200, error, b'{"errors":["bad"]}'),
                         (503, {'content-type': 'application/gzip'}, b''),
                         (503, error, b'{"errors":["bad"],"auth":{"client_token":"sentinel"}}'),
                         (503, error, b'{"errors":["bad"],"wrap_info":{"token":"sentinel"}}'),
                         (503, error, b'')):
            self.assertFalse(fixture.denied(response, 503))
        self.assertTrue(fixture.denied((503, error, b''), 503, head=True))
        self.assertFalse(fixture.denied((503, error, b'x'), 503, head=True))

    def test_head_requires_actual_empty_wire_body_and_archive_headers(self):
        headers = {'content-type': 'application/gzip', 'content-length': '1234'}
        self.assertTrue(fixture.good_head((200, headers, b'')))
        self.assertFalse(fixture.good_head((200, headers, b'unexpected')))
        self.assertFalse(fixture.good_head((503, headers, b'')))
        self.assertFalse(fixture.good_head((200, {'content-type': 'application/json'}, b'')))

    def test_full_parser_reports_no_independent_aead_claim(self):
        result = fixture.strict_archive(self.archive(gzip.compress(tar_bytes(), mtime=0)))
        self.assertEqual(result['generation'], 7)
        self.assertEqual(result['members'], fixture.NAMES)
        self.assertIs(result['cryptographic_authenticity_verified'], False)

    def test_full_parser_rejects_ignored_trailing_compressed_and_tar_data(self):
        valid = gzip.compress(tar_bytes(), mtime=0)
        for data in (valid + b'junk', valid + gzip.compress(b'', mtime=0),
                     gzip.compress(tar_bytes(tail=b'ignored'), mtime=0), valid[:-4]):
            with self.subTest(length=len(data)), self.assertRaises((ValueError, EOFError, OSError)):
                fixture.strict_archive(self.archive(data))

    def test_full_parser_rejects_payload_corruption_and_nonzero_padding(self):
        for raw in (tar_bytes(corrupt_value=True), tar_bytes(padding_byte=b'x')):
            with self.assertRaises(ValueError):
                fixture.strict_archive(self.archive(gzip.compress(raw, mtime=0)))


if __name__ == '__main__':
    unittest.main()
