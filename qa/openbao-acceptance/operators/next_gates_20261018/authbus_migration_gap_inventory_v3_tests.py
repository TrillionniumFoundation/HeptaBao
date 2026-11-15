"""Synthetic, local-only safety checks for the bounded metadata scanner."""
import copy
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest import mock


SCANNER_PATH = Path(__file__).with_name('authbus_migration_gap_inventory_v3.py')
SPEC = importlib.util.spec_from_file_location('authbus_gap_v3', SCANNER_PATH)
SCANNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCANNER)


class MetadataSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='authbus-gap-metadata-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'owner'
        self.home.mkdir(mode=0o700)
        self.config = self.home / 'openclaw.json'
        self.backup = self.home / 'backups'
        self.backup.mkdir(mode=0o700)
        self.secret = self.home / 'credentials' / 'secretrefs' / 'gateway-token.secret'
        self.secret.parent.mkdir(parents=True, mode=0o700)
        self.secret.write_text('SYNTHETIC_SECRET_FILE_PAYLOAD_MUST_NOT_APPEAR')
        self.secret.chmod(0o600)
        self.selected = {
            'expected_home': str(self.home), 'expected_uid': os.geteuid(),
            'expected_platform': 'Linux', 'receipt': {'name': 'synthetic', 'sha256': '0' * 64, 'created_at': 'synthetic'},
            'config': {'path': str(self.config), 'sha256': '0' * 64},
            'secretrefs': [{'id': 'gateway-token', 'source': 'file', 'path': str(self.secret)}],
            'backup_runtime': [{'path': str(self.backup), 'kind': 'backup_reference', 'baseline': {}}],
            'missing_agents': [], 'binding_files': [], 'relay_startups': [], 'relay_dependencies': [],
            'reused_existing_store_metadata': [], 'reused_entrypoint_metadata': [],
        }
        self.bounds = copy.deepcopy(SCANNER.PLAN['bounds'])
        self.config.write_text(json.dumps({'secrets': {'providers': {'gateway-token': {'source': 'file', 'path': str(self.secret)}}}}))

    def inspector(self):
        return SCANNER.Inspector(self.selected, self.bounds)

    def test_secret_and_key_files_cannot_be_opened_even_as_config(self):
        key = self.backup / 'operator.key'
        key.write_text('SYNTHETIC_KEY_MUST_NOT_BE_READ')
        fs = self.inspector().fs
        with mock.patch.object(SCANNER.os, 'open', side_effect=AssertionError('prohibited content opened')):
            for path in (self.secret, key):
                with self.assertRaises(SCANNER.Refused):
                    fs.read(str(path), 1024, 'approved_config')
        self.assertEqual(fs.content_reads, [])

    def test_config_projection_omits_inline_secrets_and_url_userinfo(self):
        value = {
            'gateway': {'auth': {'token': 'INLINE_CONFIG_SECRET_SENTINEL'}},
            'plugins': {'entries': {'openclaw-authbus': {'enabled': True, 'config': {
                'address': 'https://USERINFO_SENTINEL:PASSWORD_SENTINEL@j3160:8200/SECRET_PATH?token=QUERY_SENTINEL#SECRET_FRAGMENT',
                'secretId': 'INLINE_SECRET_ID_SENTINEL', 'hostId': 'synthetic-host'}}}},
            'secrets': {'providers': {'gateway-token': {'source': 'file', 'path': str(self.secret)}}},
            'channels': {'test': {'token': {'source': 'file', 'provider': 'gateway-token', 'id': 'SELECTOR_SENTINEL'}}},
            'agents': {'list': [{'id': 'test-agent', 'agentDir': str(self.home / 'agent'), 'model': 'openai/test'}]},
        }
        self.config.write_text(json.dumps(value))
        inspector = self.inspector()
        result = inspector.run('rog', 'a' * 64)
        encoded = json.dumps(result)
        for sentinel in ('INLINE_CONFIG_SECRET_SENTINEL', 'USERINFO_SENTINEL', 'PASSWORD_SENTINEL',
                         'SECRET_PATH', 'QUERY_SENTINEL', 'SECRET_FRAGMENT', 'INLINE_SECRET_ID_SENTINEL',
                         'SELECTOR_SENTINEL', 'SYNTHETIC_SECRET_FILE_PAYLOAD_MUST_NOT_APPEAR'):
            self.assertNotIn(sentinel, encoded)
        auth = result['configuration_references']['projection']['authbus']['endpoint']
        self.assertEqual((auth['host'], auth['port']), ('j3160', 8200))
        self.assertEqual(result['secretref_metadata'][0]['consumer_locations'], ['/channels/test/token'])
        self.assertFalse(result['qualification']['allClientsAndBackupsMigrated'])
        self.assertFalse(result['secretref_metadata'][0]['payload_opened'])
        self.assertTrue(result['secretref_metadata'][0]['private_regular_file_metadata'])

    def test_new_config_path_is_reported_but_never_followed(self):
        new_path = self.root / 'unapproved-new.secret'
        new_path.write_text('NEW_SECRET_PAYLOAD_SENTINEL')
        self.config.write_text(json.dumps({'secrets': {'providers': {'gateway-token': {'source': 'file', 'path': str(new_path)}}}}))
        inspector = self.inspector()
        result = inspector.run('rog', 'b' * 64)
        observed = result['secretref_metadata'][0]['current_configuration']
        self.assertEqual(observed['path'], str(new_path))
        self.assertFalse(observed['original_path_matches'])
        self.assertFalse(observed['new_reference_followed'])
        self.assertTrue(all(read['path'] != str(new_path) for read in inspector.fs.content_reads))
        self.assertNotIn('NEW_SECRET_PAYLOAD_SENTINEL', json.dumps(result))

    def test_symlink_and_outside_allowlist_never_followed(self):
        outside = self.root / 'outside.sqlite'
        outside.write_bytes(b'SQLite format 3\x00' + b'PRIVATE_ROWS_SENTINEL')
        link = self.backup / 'linked.sqlite'
        link.symlink_to(outside)
        inspector = self.inspector()
        info = inspector.projected_file(str(link), 'database_header_only')
        self.assertTrue(info['symlink'])
        self.assertNotIn('sqlite_header_matches', info)
        with self.assertRaises(SCANNER.Refused):
            inspector.fs.read(str(outside), 16, 'database_magic', prefix=True)
        self.assertEqual(inspector.fs.content_reads, [])
        directory_link = self.backup / 'linked-dir'
        directory_link.symlink_to(self.root, target_is_directory=True)
        blocked = inspector.fs.metadata(str(directory_link / 'outside.sqlite'))
        self.assertIsNone(blocked['exists'])
        self.assertIn(blocked['scan_error'], ('NotADirectoryError', 'OSError'))

    def test_database_reads_only_magic_and_wal_never_read(self):
        database = self.backup / 'openclaw-agent.sqlite'
        database.write_bytes(b'SQLite format 3\x00' + b'SYNTHETIC_PRIVATE_DATABASE_ROWS' * 100)
        wal = self.backup / 'openclaw-agent.sqlite-wal'
        wal.write_bytes(b'SYNTHETIC_PRIVATE_WAL_ROWS')
        inspector = self.inspector()
        result = inspector.backup_tree(self.selected['backup_runtime'][0])
        self.assertEqual([r['bytes'] for r in inspector.fs.content_reads], [16])
        self.assertTrue(inspector.fs.content_reads[0]['header_only'])
        encoded = json.dumps(result)
        self.assertNotIn('SYNTHETIC_PRIVATE_DATABASE_ROWS', encoded)
        self.assertNotIn('SYNTHETIC_PRIVATE_WAL_ROWS', encoded)
        self.assertFalse(result['restore_qualified'])

    def test_original_deadline_and_total_read_bound_are_not_extended(self):
        inspector = self.inspector()
        inspector.budget.deadline = 0
        with mock.patch.object(SCANNER.os, 'open', side_effect=AssertionError('I/O after deadline')):
            result = inspector.projected_file(str(self.config), 'openclaw_config_projection')
        self.assertEqual(result['scan_error'], 'BudgetExceeded')
        self.assertEqual(inspector.fs.content_reads, [])
        bounds = copy.deepcopy(self.bounds)
        bounds['total_read_bytes'] = 7
        inspector = SCANNER.Inspector(self.selected, bounds)
        with self.assertRaises(SCANNER.BudgetExceeded):
            inspector.fs.read(str(self.config), 4096, 'approved_config')
        self.assertEqual(inspector.budget.bytes_read, 7)

    def test_read_returning_after_deadline_is_charged_and_not_qualified(self):
        self.config.write_text('{}')
        inspector = self.inspector()
        original_read = SCANNER.os.read
        actual = []
        def late_read(fd, size):
            value = original_read(fd, size)
            actual.append(len(value))
            inspector.budget.deadline = 0
            return value
        with mock.patch.object(SCANNER.os, 'read', side_effect=late_read):
            with self.assertRaises(SCANNER.BudgetExceeded):
                inspector.fs.read(str(self.config), 4096, 'approved_config')
        self.assertEqual(actual, [2])
        self.assertEqual(inspector.budget.bytes_read, sum(actual))
        self.assertEqual(inspector.fs.content_reads, [])
        self.assertIn('original_time_budget', inspector.budget.hits)

    def test_tree_depth_and_entry_bounds_are_visible(self):
        for i in range(12):
            (self.backup / ('metadata-' + str(i))).touch()
        self.bounds['per_directory_entries'] = 3
        inspector = self.inspector()
        result = inspector.backup_tree(self.selected['backup_runtime'][0])
        self.assertEqual(len(result['entries']), 3)
        self.assertIn(str(self.backup), result['bounded_directories'])
        self.assertIn('per_directory_entries', inspector.budget.hits)
        self.assertFalse(result['full_tree_enumerated'])

    def test_plist_projection_drops_secret_args_and_environment_values(self):
        raw = plistlib.dumps({'Label': 'test.relay', 'ProgramArguments': [str(self.home / 'relay'),
            '--listen', '127.0.0.1:8145', '--token', 'SECRET_ARG_SENTINEL', '--password', '/ABSOLUTE_SECRET_SENTINEL'],
            'EnvironmentVariables': {'MANAGEMENT_PASSWORD': 'SECRET_ENV_SENTINEL',
                                     'HTTPS_PROXY': 'http://USER_SENTINEL:PASS_SENTINEL@127.0.0.1:7890/path?key=QUERY_SENTINEL'}})
        projection = SCANNER.plist_projection(raw, self.selected, self.inspector().budget)
        encoded = json.dumps(projection)
        for sentinel in ('SECRET_ARG_SENTINEL', 'SECRET_ENV_SENTINEL', 'USER_SENTINEL', 'PASS_SENTINEL', 'QUERY_SENTINEL', 'ABSOLUTE_SECRET_SENTINEL'):
            self.assertNotIn(sentinel, encoded)
        self.assertEqual(len(projection['endpoints']), 1)
        self.assertTrue(all(not x['field'].startswith('EnvironmentVariables/') for x in projection['endpoints']))
        self.assertIn('MANAGEMENT_PASSWORD', projection['environment_field_names'])

    def test_endpoint_projection_does_not_walk_credential_containers(self):
        data = {'auth': {'tokens': {'PRIVATE_DYNAMIC_FIELD_SENTINEL': {'endpoint': 'https://private-token.invalid'}}},
                'relay': {'upstream': 'https://user:pass@backend.invalid:8443/path'}}
        projection = SCANNER.endpoint_projection(data, self.inspector().budget, str(self.home))
        encoded = json.dumps(projection)
        self.assertNotIn('PRIVATE_DYNAMIC_FIELD_SENTINEL', encoded)
        self.assertNotIn('private-token.invalid', encoded)
        self.assertEqual(len(projection['endpoints']), 1)
        self.assertEqual(projection['endpoints'][0]['endpoint']['host'], 'backend.invalid')

    def test_legacy_service_entrypoint_projects_config_path_without_running_command(self):
        raw = b'[Service]\nExecStart=/opt/openbao/bao server -config /etc/openbao/bao.hcl --token PRIVATE_ARGUMENT_SENTINEL\nEnvironment=BAO_TOKEN=PRIVATE_ENV_SENTINEL\n'
        projection = SCANNER.text_endpoint_projection(raw, self.inspector().budget, str(self.home))
        self.assertEqual(projection['command_entrypoints'][0]['executable'], '/opt/openbao/bao')
        self.assertEqual(projection['command_entrypoints'][0]['path_references'][0]['path'], '/etc/openbao/bao.hcl')
        self.assertFalse(projection['command_entrypoints'][0]['command_executed'])
        self.assertNotIn('PRIVATE_ARGUMENT_SENTINEL', json.dumps(projection))
        self.assertNotIn('PRIVATE_ENV_SENTINEL', json.dumps(projection))

    def test_replaced_file_is_rejected_after_actual_held_descriptor_read(self):
        inspector = self.inspector()
        original_read = SCANNER.os.read
        replacement = self.home / 'replacement.json'
        replacement.write_text('{}')
        replaced = False
        def replace_after_read(fd, size):
            nonlocal replaced
            value = original_read(fd, size)
            if not replaced:
                replacement.replace(self.config)
                replaced = True
            return value
        with mock.patch.object(SCANNER.os, 'read', side_effect=replace_after_read):
            with self.assertRaisesRegex(SCANNER.Refused, '^file_changed_during_read$'):
                inspector.fs.read(str(self.config), 4096, 'approved_config')
        self.assertEqual(inspector.fs.content_reads, [])

    def test_embedded_plan_matches_reviewed_allowlist_and_exact_denominators(self):
        path = SCANNER_PATH.with_name('authbus_migration_gap_allowlist_v3.json')
        plan = json.loads(path.read_text())
        self.assertEqual(plan, SCANNER.PLAN)
        self.assertEqual(sum(len(v['secretrefs']) for v in plan['hosts'].values()), 19)
        self.assertEqual(sum(len(v['backup_runtime']) for v in plan['hosts'].values()), 38)
        self.assertEqual(sum(len(v['missing_agents']) for v in plan['hosts'].values()), 2)
        self.assertEqual(len(plan['hosts']['macbook-pro']['relay_startups']), 4)
        self.assertEqual(len(plan['hosts']['macbook-pro']['relay_dependencies']), 8)
        self.assertNotIn('x230', plan['hosts'])
        self.assertNotIn('ai395', plan['hosts'])
        self.assertTrue(all(not v['paths'] for v in plan['pending_boundaries']))

    def test_host_owner_mismatch_fails_before_any_allowlisted_path_io(self):
        capture = io.StringIO()
        with mock.patch('sys.argv', ['scanner', '--host', 'macbook-pro']), \
                mock.patch.object(SCANNER.Path, 'home', return_value=self.home), \
                mock.patch.object(SCANNER.NoFollowFilesystem, 'parent', side_effect=AssertionError('host paths inspected')), \
                contextlib.redirect_stdout(capture):
            status = SCANNER.main()
        self.assertEqual(status, 2)
        receipt = json.loads(capture.getvalue())
        self.assertEqual(receipt['error_class'], 'HostOwnerContextMismatch')
        self.assertEqual(receipt['paths_inspected'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
