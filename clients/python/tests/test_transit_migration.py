import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from heptabao.private_state import StateDirectory
from heptabao.transport import BaoError, Response
from heptabao.transit_migration import TransitMigrator, _configuration, records_from

PLAIN = base64.b64encode(b'synthetic-do-not-persist-plaintext').decode()
CIPHER = 'vault:v1:' + base64.b64encode(b'S' * 32).decode()
OUTPUT = 'vault:v1:' + base64.b64encode(b'T' * 32).decode()


class FakeClient:
    def __init__(self, cluster):
        self.cluster = cluster
        self.calls = []
        self.fail = None
        self.plaintext = PLAIN
        self.metadata = {'type': 'aes256-gcm96', 'derived': False, 'latest_version': 1}
        self.disable_upsert = True

    def health(self):
        return {'cluster_id': self.cluster, 'version': 'test-model'}

    def request(self, method, path, payload=None):
        self.calls.append((method, path, copy.deepcopy(payload)))
        if self.fail and self.fail in path:
            raise BaoError('synthetic_transport_outcome_unknown')
        if path.endswith('/config/keys'):
            value = {'disable_upsert': self.disable_upsert}
        elif '/keys/' in path:
            value = self.metadata
        elif '/encrypt/' in path:
            value = {'ciphertext': OUTPUT}
        else:
            value = {'plaintext': self.plaintext}
        return Response(200, {'data': copy.deepcopy(value)})


class TransitMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.config = {'target_key_version': 1}
        for side, port in [('source', 19000), ('target', 19001)]:
            self.config[side] = {'address': f'https://localhost:{port}', 'ca_file': '/private/ca',
                'token_file': '/private/token', 'namespace': '', 'mount': 'transit', 'key': 'test'}
        self.records = [{'id': 'one', 'ciphertext': CIPHER}]
        self.source = FakeClient('source-cluster')
        self.target = FakeClient('target-cluster')
        self.directory = StateDirectory(self.root, writer=True)
        self.filename = 'transit-' + hashlib.sha256(b'one').hexdigest() + '.json'

    def tearDown(self):
        self.directory.close()
        self.temp.cleanup()

    def migrator(self):
        return TransitMigrator(self.directory, self.config, self.records,
            clients=(self.source, self.target, '1' * 64, '2' * 64))

    def test_reencrypt_verify_restart_and_no_plaintext_files(self):
        result = self.migrator().migrate()
        self.assertEqual(result['converted'], 1)
        self.assertFalse(result['full_format_migration'])
        for path in self.root.iterdir():
            raw = path.read_bytes()
            self.assertNotIn(PLAIN.encode(), raw)
            self.assertNotIn(base64.b64decode(PLAIN), raw)
        self.directory.close()
        self.directory = StateDirectory(self.root, writer=True)
        self.assertEqual(self.migrator().migrate()['reused'], 1)
        self.assertEqual(sum('/encrypt/' in c[1] for c in self.target.calls), 1)

    def test_target_timeout_is_pending_and_never_reencrypted(self):
        self.target.fail = '/encrypt/'
        with self.assertRaises(BaoError):
            self.migrator().migrate()
        self.assertEqual(self.directory.json(self.filename)['phase'], 'encrypt_pending')
        self.target.fail = None
        with self.assertRaisesRegex(BaoError, 'no_automatic_retry'):
            self.migrator().migrate()
        self.assertEqual(sum('/encrypt/' in c[1] for c in self.target.calls), 1)

    def test_source_failure_cannot_create_destination_effect(self):
        self.source.fail = '/decrypt/'
        with self.assertRaises(BaoError):
            self.migrator().migrate()
        self.assertEqual(self.directory.json(self.filename)['phase'], 'source_pending')
        self.assertFalse(any('/encrypt/' in c[1] for c in self.target.calls))

    def test_verification_failure_resumes_saved_ciphertext_only(self):
        self.target.fail = '/decrypt/'
        with self.assertRaises(BaoError):
            self.migrator().migrate()
        self.assertEqual(self.directory.json(self.filename)['phase'], 'encrypted')
        self.target.fail = None
        self.assertEqual(self.migrator().migrate()['converted'], 1)
        self.assertEqual(sum('/encrypt/' in c[1] for c in self.target.calls), 1)

    def test_readback_mismatch_cannot_mark_verified(self):
        self.target.plaintext = base64.b64encode(b'wrong').decode()
        with self.assertRaisesRegex(BaoError, 'mismatch'):
            self.migrator().migrate()
        self.assertEqual(self.directory.json(self.filename)['phase'], 'encrypted')

    def test_failed_checkpoint_before_encrypt_never_dispatches_target(self):
        original = self.directory.publish
        def publish(name, value):
            if value.get('phase') == 'encrypt_pending':
                raise BaoError('synthetic_disk_failure')
            original(name, value)
        self.directory.publish = publish
        with self.assertRaises(BaoError):
            self.migrator().migrate()
        self.assertFalse(any('/encrypt/' in c[1] for c in self.target.calls))

    def test_failed_ciphertext_publication_is_not_retryable(self):
        original = self.directory.publish
        def publish(name, value):
            if value.get('phase') == 'encrypted':
                raise BaoError('synthetic_disk_failure')
            original(name, value)
        self.directory.publish = publish
        with self.assertRaises(BaoError):
            self.migrator().migrate()
        self.directory.publish = original
        with self.assertRaisesRegex(BaoError, 'no_automatic_retry'):
            self.migrator().migrate()
        self.assertEqual(sum('/encrypt/' in c[1] for c in self.target.calls), 1)

    def test_changed_input_or_cluster_refuses_resume(self):
        self.migrator().migrate()
        self.records[0]['ciphertext'] = OUTPUT
        with self.assertRaisesRegex(BaoError, 'binding_or_input'):
            self.migrator()
        self.records[0]['ciphertext'] = CIPHER
        self.source.cluster = 'changed'
        with self.assertRaisesRegex(BaoError, 'binding_or_input'):
            self.migrator()

    def test_equal_cluster_and_origin_rejected(self):
        self.target.cluster = self.source.cluster
        with self.assertRaisesRegex(BaoError, 'distinct_migration_clusters'):
            self.migrator()
        self.config['target']['address'] = self.config['source']['address']
        with self.assertRaisesRegex(BaoError, 'distinct_migration_endpoints'):
            self.migrator()

    def test_upsert_derived_or_wrong_version_refused(self):
        self.target.disable_upsert = False
        with self.assertRaisesRegex(BaoError, 'disable_key_upsert'):
            self.migrator()
        self.target.disable_upsert = True
        self.target.metadata['derived'] = True
        with self.assertRaisesRegex(BaoError, 'profile_or_version'):
            self.migrator()
        self.target.metadata['derived'] = False
        self.config['target_key_version'] = 2
        with self.assertRaisesRegex(BaoError, 'profile_or_version'):
            self.migrator()
        self.assertFalse(any('/encrypt/' in c[1] for c in self.target.calls))

    def test_checkpoint_ciphertext_tamper_rejected(self):
        self.migrator().migrate()
        checkpoint = self.directory.json(self.filename)
        checkpoint['target_ciphertext'] = CIPHER
        self.directory.publish(self.filename, checkpoint)
        with self.assertRaisesRegex(BaoError, 'checkpoint_binding'):
            self.migrator().migrate()

    def test_missing_ciphertext_and_unknown_fields_reject(self):
        self.migrator().migrate()
        checkpoint = self.directory.json(self.filename)
        checkpoint['extra'] = True
        self.directory.publish(self.filename, checkpoint)
        with self.assertRaisesRegex(BaoError, 'checkpoint_binding'):
            self.migrator().migrate()

    def test_empty_duplicate_or_secret_fields_rejected_before_network(self):
        for value in [[], self.records * 2, [{'id': 'one', 'ciphertext': CIPHER, 'plaintext': PLAIN}],
                      [{'id': '../escape', 'ciphertext': CIPHER}], [{'id': 'one', 'ciphertext': 'invalid'}]]:
            with self.assertRaises(BaoError):
                records_from(value)
        self.assertEqual(self.source.calls, [])

    def test_boolean_version_and_secret_in_url_rejected(self):
        self.config['target_key_version'] = True
        with self.assertRaises(BaoError):
            _configuration(self.config)
        self.config['target_key_version'] = 1
        self.config['source']['address'] = 'https://secret@localhost:19000'
        with self.assertRaises(BaoError):
            _configuration(self.config)

    def test_second_writer_and_symlink_checkpoint_rejected(self):
        with self.assertRaises(BaoError):
            StateDirectory(self.root, writer=True)
        (self.root / self.filename).symlink_to('/dev/null')
        with self.assertRaises(BaoError):
            self.migrator().migrate()
        self.assertFalse(any('/encrypt/' in c[1] for c in self.target.calls))

    def test_aad_and_derived_source_context_are_not_silently_dropped(self):
        self.records[0].update(context='Y3R4', associated_data='YWFk')
        self.migrator().migrate()
        source_payload = next(c[2] for c in self.source.calls if '/decrypt/' in c[1])
        target_payload = next(c[2] for c in self.target.calls if '/encrypt/' in c[1])
        self.assertEqual(source_payload['context'], 'Y3R4')
        self.assertEqual(target_payload['associated_data'], 'YWFk')
        self.assertNotIn('context', target_payload)

    def test_verified_resume_rechecks_plaintext_without_new_encryption(self):
        self.migrator().migrate()
        self.target.plaintext = base64.b64encode(b'changed-key-or-value').decode()
        with self.assertRaisesRegex(BaoError, 'mismatch'):
            self.migrator().migrate()
        self.assertEqual(sum('/encrypt/' in c[1] for c in self.target.calls), 1)

    def test_target_decryption_minimum_cannot_exclude_output_version(self):
        self.target.metadata['min_decryption_version'] = 2
        with self.assertRaisesRegex(BaoError, 'profile_or_version'):
            self.migrator()
