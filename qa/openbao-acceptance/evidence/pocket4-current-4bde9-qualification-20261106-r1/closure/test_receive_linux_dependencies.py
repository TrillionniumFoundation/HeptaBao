import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('receiver', Path(__file__).with_name('receive_linux_dependencies.py'))
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)


class PublicDependencyReceiverTests(unittest.TestCase):
    def setUp(self):
        self.crate = b'public synthetic crate fixture'
        self.checksum = receiver.sha(self.crate)
        self.lock = ('version = 4\n\n[[package]]\nname = "example"\nversion = "1.2.3"\n'
                     'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                     'checksum = "' + self.checksum + '"\n').encode()
        self.contents = {
            'crates/example-1.2.3.crate': self.crate,
            'indexes/ex/am/example': b'\x03\x02\x00\x00\x00etag: fixture\x001.2.3\x00'
                + json.dumps({'name': 'example', 'vers': '1.2.3', 'cksum': self.checksum}).encode() + b'\x00',
            'registry-config.json': b'{"dl":"https://static.crates.io/crates","api":"https://crates.io"}',
        }
        self.entries = [
            {'member': 'crates/example-1.2.3.crate', 'kind': 'linux_selected_crate',
             'crate': 'example', 'version': '1.2.3'},
            {'member': 'indexes/ex/am/example', 'kind': 'selected_package_sparse_index',
             'crate': 'example', 'locked_versions': ['1.2.3']},
            {'member': 'registry-config.json', 'kind': 'public_registry_config'},
        ]
        self.manifest_changes = {}
        self.member_changes = {}

    def packet(self, extra=None, omit=None, duplicate=False):
        entries = copy.deepcopy(self.entries)
        for entry in entries:
            raw = self.contents[entry['member']]
            entry.update(bytes=len(raw), sha256=receiver.sha(raw))
        entries.sort(key=lambda x: x['member'])
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as tar:
            order = [e for e in entries if e['member'] != omit]
            if duplicate:
                order.append(entries[0])
            if extra:
                order.append(extra)
            for entry in order:
                name = entry['member']
                data = self.contents.get(name, b'extra')
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o600
                info.uid = info.gid = 0
                info.mtime = 0
                for key, value in self.member_changes.get(name, {}).items():
                    setattr(info, key, value)
                tar.addfile(info, io.BytesIO(data))
        payload = stream.getvalue()
        manifest = {
            'schema': 'heptabao.closed-linux-registry-transfer.v1',
            'source_commit': receiver.COMMIT, 'source_tree': receiver.TREE,
            'cargo_lock_sha256': receiver.sha(self.lock),
            'user_cargo_config_or_credentials_included': False, 'source_cache_modified': False,
            'rust_compilation_executed': False, 'normal107_qualified': False,
            'production_changed': False, 'cargo_network_downloads_executed': False,
            'payload': {'bytes': len(payload), 'sha256': receiver.sha(payload)},
            'entries': entries, 'linux_selected_registry_package_count': 1,
            'metadata_resolver_additional_archive_count': 0, 'sparse_index_count': 1,
            'metadata_resolver_additional_index_count': 0,
        }
        manifest.update(self.manifest_changes)
        raw = json.dumps(manifest, sort_keys=True).encode()
        return raw, payload

    def validate(self, **kwargs):
        raw, payload = self.packet(**kwargs)
        return receiver.validate_packet(raw, payload, self.lock, receiver.sha(raw), receiver.sha(payload))

    def test_complete_packet_is_public_closed_and_lock_bound(self):
        rows, counts = self.validate()
        self.assertEqual(len(rows), 3)
        self.assertEqual(counts['linux_selected_crate'], 1)

    def test_missing_member_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'tar_missing_extra'):
            self.validate(omit='registry-config.json')

    def test_extra_member_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'tar_missing_extra'):
            self.validate(extra={'member': 'credentials.toml'})

    def test_duplicate_tar_member_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'tar_missing_extra'):
            self.validate(duplicate=True)

    def test_parent_traversal_member_is_rejected(self):
        self.contents['../outside'] = self.contents.pop('registry-config.json')
        self.entries[2]['member'] = '../outside'
        with self.assertRaisesRegex(RuntimeError, 'relative_canonical'):
            self.validate()

    def test_absolute_member_is_rejected(self):
        self.contents['/outside'] = self.contents.pop('registry-config.json')
        self.entries[2]['member'] = '/outside'
        with self.assertRaisesRegex(RuntimeError, 'relative_canonical'):
            self.validate()

    def test_symlink_member_is_rejected(self):
        self.member_changes['registry-config.json'] = {'type': tarfile.SYMTYPE, 'linkname': '/tmp/outside'}
        with self.assertRaisesRegex(RuntimeError, 'fixed_regular_tar'):
            self.validate()

    def test_hardlink_member_is_rejected(self):
        self.member_changes['registry-config.json'] = {'type': tarfile.LNKTYPE, 'linkname': '/tmp/outside'}
        with self.assertRaisesRegex(RuntimeError, 'fixed_regular_tar'):
            self.validate()

    def test_wrong_archive_content_cannot_bypass_lock_checksum(self):
        self.contents['crates/example-1.2.3.crate'] = b'changed but packet hashes recomputed'
        with self.assertRaisesRegex(RuntimeError, 'crate_not_exact'):
            self.validate()

    def test_wrong_sparse_index_checksum_is_rejected(self):
        self.contents['indexes/ex/am/example'] = b'\x00' + json.dumps(
            {'name': 'example', 'vers': '1.2.3', 'cksum': '0' * 64}).encode() + b'\x00'
        with self.assertRaisesRegex(RuntimeError, 'sparse_index_locked'):
            self.validate()

    def test_sparse_index_duplicate_version_is_rejected(self):
        self.contents['indexes/ex/am/example'] *= 2
        with self.assertRaisesRegex(RuntimeError, 'duplicate_version'):
            self.validate()

    def test_sparse_index_other_package_is_rejected(self):
        self.contents['indexes/ex/am/example'] = b'\x00' + json.dumps(
            {'name': 'unrelated', 'vers': '1.2.3', 'cksum': self.checksum}).encode() + b'\x00'
        with self.assertRaisesRegex(RuntimeError, 'sparse_index_name'):
            self.validate()

    def test_registry_auth_configuration_is_rejected(self):
        self.contents['registry-config.json'] = b'{"dl":"https://static.crates.io","api":"https://crates.io","auth-required":true}'
        with self.assertRaisesRegex(RuntimeError, 'anonymous_registry'):
            self.validate()

    def test_registry_url_credentials_are_rejected(self):
        self.contents['registry-config.json'] = b'{"dl":"https://user:secret@static.crates.io","api":"https://crates.io"}'
        with self.assertRaisesRegex(RuntimeError, 'anonymous_public'):
            self.validate()

    def test_unknown_entry_kind_is_rejected(self):
        self.entries[2]['kind'] = 'user_credentials'
        with self.assertRaisesRegex(RuntimeError, 'unsupported_member_kind'):
            self.validate()

    def test_wrong_source_identity_is_rejected(self):
        self.manifest_changes['source_commit'] = '0' * 40
        with self.assertRaisesRegex(RuntimeError, 'canonical_source'):
            self.validate()

    def test_declared_count_mismatch_is_rejected(self):
        self.manifest_changes['linux_selected_registry_package_count'] = 2
        with self.assertRaisesRegex(RuntimeError, 'declared_closed_counts'):
            self.validate()

    def test_payload_pin_mismatch_is_rejected(self):
        raw, payload = self.packet()
        with self.assertRaisesRegex(RuntimeError, 'packet_sha256'):
            receiver.validate_packet(raw, payload, self.lock, receiver.sha(raw), '0' * 64)

    def test_nonprivate_tar_mode_is_rejected(self):
        self.member_changes['registry-config.json'] = {'mode': 0o644}
        with self.assertRaisesRegex(RuntimeError, 'fixed_regular_tar'):
            self.validate()

    def test_install_reads_back_only_new_cache_and_rejects_existing_destination(self):
        entries, _ = self.validate()
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'private-cargo-home'
            receiver.write_new_cache(dest, 'index.crates.io-0123456789abcdef', entries)
            first = {str(p.relative_to(dest)): p.read_bytes() for p in dest.rglob('*') if p.is_file()}
            with self.assertRaises(FileExistsError):
                receiver.write_new_cache(dest, 'index.crates.io-0123456789abcdef', entries)
            self.assertEqual(first, {str(p.relative_to(dest)): p.read_bytes() for p in dest.rglob('*') if p.is_file()})

    def test_symlink_parent_is_rejected_without_writing(self):
        entries, _ = self.validate()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'real').mkdir()
            (root / 'alias').symlink_to(root / 'real', target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, 'owned_real_parent'):
                receiver.write_new_cache(root / 'alias' / 'cargo-home', 'index.crates.io-0123456789abcdef', entries)
            self.assertFalse((root / 'real' / 'cargo-home').exists())

    def test_existing_input_symlink_and_hardlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / 'target'
            target.write_bytes(b'public')
            (root / 'link').symlink_to(target)
            with self.assertRaises(OSError):
                receiver.read_regular(root / 'link')
            os.link(target, root / 'hardlink')
            with self.assertRaisesRegex(RuntimeError, 'bounded_single_link'):
                receiver.read_regular(target)


if __name__ == '__main__':
    unittest.main(verbosity=2)
