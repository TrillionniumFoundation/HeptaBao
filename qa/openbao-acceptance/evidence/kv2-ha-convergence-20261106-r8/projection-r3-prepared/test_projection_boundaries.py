"""Eight focused local guards; no real data, remote host, provider or service."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('projection_draft', HERE / 'mac_formal_kv2_allrows_projection.py')
controller = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = controller
spec.loader.exec_module(controller)
PROTOCOL = Path('/tmp/heptabao-formal-kv2-protocol-20261106-r1/formal_kv2_protocol.py')


class ProjectionBoundaries(unittest.TestCase):
    def test_real_readonly_sqlite_allrows_preserves_text_null_blob_and_source_time(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'synthetic.sqlite'
            connection = sqlite3.connect(path)
            connection.execute('CREATE TABLE auth_profile_store(store_key TEXT PRIMARY KEY,store_json BLOB,updated_at REAL)')
            connection.execute('CREATE TABLE auth_profile_state(state_key TEXT PRIMARY KEY,state_json BLOB,updated_at REAL)')
            connection.executemany('INSERT INTO auth_profile_store VALUES(?,?,?)', [
                ('primary', '{"synthetic":"中文"}', 1.25), ('secondary', b'\x00\xff', None)])
            connection.execute('INSERT INTO auth_profile_state VALUES(?,?,?)', ('state', None, 4))
            connection.commit()
            original = controller.query_allrows(connection)
            schema = connection.execute('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name').fetchall()
            pages = connection.execute('PRAGMA page_count').fetchone()[0]
            connection.close()
            before = path.read_bytes()
            row = {'kind': 'agent', 'agent': 'synthetic', 'present': True,
                   'schema_sha256': hashlib.sha256(controller.encoded(schema)).hexdigest(), 'page_count': pages,
                   'auth_rows_sha256': hashlib.sha256(controller.encoded(original)).hexdigest(),
                   'auth_store_rows': 2, 'auth_state_rows': 1}
            normalized = controller.cold_database(path, row)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(normalized['auth_profile_store'], [
                ['primary', '{"synthetic":"中文"}', 1.25], ['secondary', {'blobHex': '00ff'}, None]])
            self.assertEqual(normalized['auth_profile_state'], [['state', None, 4.0]])
            parsed = controller.extract_protocol(PROTOCOL.read_bytes(), PROTOCOL)
            projection = {'schema': 'heptabao.current-sqlite-allrows-to-kv2.private.v1',
                          'capture_sha256': 'a' * 64, 'rows': []}
            for table, columns in controller.TABLES.items():
                for values in normalized[table]:
                    record = 'row-' + str(len(projection['rows']))
                    projection['rows'].append({'record_id': record, 'agent_slot': 0, 'table': table,
                        'row_fields': dict(zip(columns, values)), 'kv_mount': 'business', 'kv_key': record})
            capture = {'schema': 'heptabao.closed-current-sqlite-capture.v1', 'ok': True,
                       'configured_agent_count': 2, 'database_rows': [row,
                           {'kind': 'agent', 'agent': 'absent-synthetic', 'present': False}]}
            records, counts = parsed['projection_rows'](capture, projection, 'business', 'a' * 64)
            self.assertEqual(len(records), 3)
            self.assertEqual(counts['auth_profile_store_rows'], 2)
            self.assertEqual(counts['auth_profile_state_rows'], 1)
            self.assertEqual(controller.OPENED, controller.CLOSED)
            self.assertFalse(controller.ALLOWED_URIS)
            self.assertFalse(any(Path(str(path) + suffix).exists() for suffix in controller.FAMILY[1:]))

    def test_changed_protocol_source_is_rejected_before_extraction(self):
        raw = PROTOCOL.read_bytes()
        controller.extract_protocol(raw, PROTOCOL)
        with self.assertRaises(controller.Refused):
            controller.extract_protocol(raw + b'\n', PROTOCOL)


class OriginalResourceBoundaries(unittest.TestCase):
    def setUp(self):
        names = ('FIRED', 'INTERRUPTED', 'FINISHING', 'TIMER_OWNED', 'OPENED', 'CLOSED',
                 'WORK_END', 'TOTAL_END', 'UID', 'DEST', 'DIRECTORIES', 'INPUTS', 'DATABASES',
                 'CHECKS', 'ALLOWED_READS', 'ALLOWED_WRITES', 'ALLOWED_MKDIRS', 'ALLOWED_URIS',
                 'CLEANUP_ERRORS', 'RESOURCES')
        self.old = {key: getattr(controller, key) for key in names}
        for key in ('FIRED', 'INTERRUPTED', 'FINISHING', 'TIMER_OWNED'):
            setattr(controller, key, False)
        controller.OPENED = controller.CLOSED = 0
        controller.WORK_END = time.monotonic() + 5
        controller.TOTAL_END = time.monotonic() + 10
        controller.UID = os.geteuid()
        for key in ('DIRECTORIES', 'INPUTS'):
            setattr(controller, key, {})
        for key in ('DATABASES', 'CHECKS', 'CLEANUP_ERRORS'):
            setattr(controller, key, [])
        for key in ('ALLOWED_READS', 'ALLOWED_WRITES', 'ALLOWED_MKDIRS', 'ALLOWED_URIS'):
            setattr(controller, key, set())
        controller.RESOURCES = controller.OwnedResources()
        self.temp = tempfile.TemporaryDirectory(prefix='hb-projection-owned-fixture-')
        self.directory = Path(self.temp.name)
        self.file = self.directory / 'synthetic'
        self.file.write_bytes(b'synthetic-only')

    def tearDown(self):
        controller.FINISHING = True
        controller.RESOURCES.close_all()
        for key, value in self.old.items():
            setattr(controller, key, value)
        self.temp.cleanup()

    def test_signal_at_fd_birth_is_sticky_and_original_is_registered_and_closed_once(self):
        real = os.open
        def after_birth(*args, **kwargs):
            fd = real(*args, **kwargs)
            controller.interrupt(signal.SIGTERM, None)
            return fd
        with mock.patch.object(controller.os, 'open', side_effect=after_birth):
            with self.assertRaises(controller.Refused):
                controller.RESOURCES.open(self.file, os.O_RDONLY)
        self.assertTrue(controller.INTERRUPTED)
        self.assertEqual(controller.RESOURCES.summary()['fd_birth_count'], 1)
        controller.RESOURCES.close_all()
        result = controller.RESOURCES.summary()
        self.assertEqual(result['fd_close_attempt_count'], 1)
        self.assertEqual(result['fd_close_success_count'], 1)
        with self.assertRaises(controller.Refused):
            controller.check()

    def test_first_fstat_failure_keeps_registered_original_for_cleanup(self):
        with mock.patch.object(controller.os, 'fstat', side_effect=OSError('synthetic first fstat')):
            with self.assertRaises(OSError):
                controller.RESOURCES.open(self.file, os.O_RDONLY)
        self.assertEqual(controller.RESOURCES.summary()['fd_first_fstat_failure_count'], 1)
        fd = controller.RESOURCES.fds[0]['fd']
        controller.RESOURCES.close_all()
        self.assertEqual(controller.RESOURCES.summary()['fd_close_success_count'], 1)
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_ambiguous_close_is_not_retried_after_numeric_fd_is_reused(self):
        fd = controller.RESOURCES.open(self.file, os.O_RDONLY)
        real_close = os.close
        def closes_then_fails(number):
            real_close(number)
            raise OSError('synthetic close outcome failure')
        with mock.patch.object(controller.os, 'close', side_effect=closes_then_fails):
            controller.RESOURCES.close(fd)
        replacement = os.open(self.file, os.O_RDONLY)
        try:
            self.assertEqual(replacement, fd)
            controller.RESOURCES.close_all()
            self.assertEqual(os.fstat(replacement).st_size, len(b'synthetic-only'))
            result = controller.RESOURCES.summary()
            self.assertEqual(result['fd_close_attempt_count'], 1)
            self.assertEqual(result['fd_close_success_count'], 0)
            self.assertFalse(result['all_original_handles_and_stdio_retired'])
        finally:
            real_close(replacement)

    def test_signal_at_dup_and_sqlite_birth_keeps_both_owned_resources(self):
        base = os.open(self.file, os.O_RDONLY)
        real_dup = os.dup
        def dup_then_signal(number):
            fd = real_dup(number); controller.interrupt(signal.SIGINT, None); return fd
        try:
            with mock.patch.object(controller.os, 'dup', side_effect=dup_then_signal):
                with self.assertRaises(controller.Refused):
                    controller.RESOURCES.dup(base)
            controller.RESOURCES.close_all()
            self.assertEqual(controller.RESOURCES.summary()['fd_births_by_kind']['stdio_saved'], 1)
        finally:
            os.close(base)
        controller.INTERRUPTED = False
        db = self.directory / 'synthetic.sqlite'
        created = sqlite3.connect(db); created.close()
        real_connect, returned = sqlite3.connect, []
        def connect_then_signal(*args, **kwargs):
            value = real_connect(*args, **kwargs)
            returned.append(value); controller.interrupt(signal.SIGTERM, None); return value
        with mock.patch.object(controller.sqlite3, 'connect', side_effect=connect_then_signal):
            with self.assertRaises(controller.Refused):
                controller.RESOURCES.connect(db.as_uri() + '?mode=ro&immutable=1')
        self.assertEqual(controller.OPENED, 1)
        controller.RESOURCES.close_all()
        self.assertEqual(controller.CLOSED, 1)
        with self.assertRaises(sqlite3.ProgrammingError):
            returned[0].execute('SELECT 1')

    def test_stdio_cleanup_preserves_primary_and_records_sync_failure(self):
        controller.DEST = self.directory
        controller.hold_directory(self.directory)
        with mock.patch.object(controller.os, 'fsync', side_effect=OSError('synthetic sync failure')):
            with self.assertRaisesRegex(ValueError, 'original primary'):
                with controller.private_stdio():
                    raise ValueError('original primary')
        self.assertIn('private_stdio_sync_failed', controller.CLEANUP_ERRORS)
        controller.RESOURCES.close_all()
        result = controller.RESOURCES.summary()
        self.assertEqual(result['fd_birth_count'], result['fd_close_success_count'])
        self.assertEqual(result['stdio_restore_completed_count'], 2)
        self.assertFalse(result['all_original_handles_and_stdio_retired'])

    def test_timer_ownership_survives_immediate_signal_and_set_failure(self):
        calls = []
        def fail_once(which, seconds):
            calls.append(seconds)
            if len(calls) == 1:
                controller.interrupt(signal.SIGALRM, None)
                raise OSError('synthetic immediate timer failure')
        with mock.patch.object(controller.signal, 'setitimer', side_effect=fail_once):
            with self.assertRaises(OSError):
                controller.arm_work_timer()
            self.assertTrue(controller.TIMER_OWNED)
            controller.disarm_owned_timer()
        self.assertFalse(controller.TIMER_OWNED)
        self.assertTrue(controller.FIRED)
        self.assertEqual(calls[-1], 0)
        with self.assertRaises(controller.Refused):
            controller.check()


if __name__ == '__main__':
    unittest.main(verbosity=2)
