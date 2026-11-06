"""Narrow r2 guards using owned directories; no host, DB, product or subprocess."""
import contextlib
import copy
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('volume_guard_outer', HERE / 'mac_current_sqlite_data_protection_outer.py')
outer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(outer)
INITIAL_PUBLIC = copy.deepcopy(outer.PUBLIC)
MOUNT = Path('/Volumes/T5')


class VolumeAndFailureGuards(unittest.TestCase):
    def setUp(self):
        self.saved = {key: getattr(outer, key) for key in (
            'UID', 'DIRECTORIES', 'PUBLIC', 'PRIVATE', 'OWNER', 'CONTROL', 'FIRED', 'INTERRUPTED',
            'FINISHING', 'FS_PROTECTED', 'FAILURE_CLEANUP', 'PHASE')}
        outer.UID = os.geteuid()
        outer.DIRECTORIES = []
        outer.PUBLIC = copy.deepcopy(INITIAL_PUBLIC)
        outer.PRIVATE = {}
        outer.OWNER = outer.CONTROL = None
        outer.FIRED = outer.INTERRUPTED = outer.FINISHING = outer.FS_PROTECTED = outer.FAILURE_CLEANUP = False
        outer.PHASE = 'startup'
        self.temp = tempfile.TemporaryDirectory(prefix='heptabao-volume-guard-')
        self.directory = Path(self.temp.name)

    def tearDown(self):
        for row in outer.DIRECTORIES:
            try:
                os.close(row['fd'])
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
        self.temp.cleanup()
        for key, value in self.saved.items():
            setattr(outer, key, value)

    @contextlib.contextmanager
    def fixed_mount_fixture(self):
        """Map only the fixed mount pathname to a real owned directory/FD."""
        os.chmod(self.directory, 0o775)
        st = self.directory.lstat()
        expected = {'path': str(MOUNT), 'dev': st.st_dev, 'inode': st.st_ino,
                    'uid': st.st_uid, 'gid': st.st_gid, 'mode': 0o775}
        real_resolve, real_lstat, real_open = Path.resolve, Path.lstat, os.open
        directory = self.directory
        def resolve(path, *args, **kwargs):
            return path if path == MOUNT else real_resolve(path, *args, **kwargs)
        def lstat(path, *args, **kwargs):
            return real_lstat(directory if path == MOUNT else path, *args, **kwargs)
        def opened(path, *args, **kwargs):
            return real_open(directory if path == MOUNT else path, *args, **kwargs)
        with mock.patch.object(Path, 'resolve', resolve), mock.patch.object(Path, 'lstat', lstat), \
                mock.patch.object(outer.os, 'open', opened):
            yield expected

    def test_exact_0775_fixed_volume_keeps_real_fd_and_generic_parent_stays_refused(self):
        with self.fixed_mount_fixture() as expected:
            with self.assertRaises(outer.Refused):
                outer.directory_identity(MOUNT, private=False)
            with self.assertRaises(outer.Refused):
                outer.hold_directory(self.directory)
            row = outer.hold_volume_directory('T5', MOUNT, expected)
            self.assertEqual(outer.fd_directory(MOUNT, row['fd']), expected)
            self.assertEqual(row['volume_binding'], {'alias': 'T5', 'expected': expected})
            outer.verify_directories()
            self.assertEqual(len(outer.DIRECTORIES), 1)
            self.assertIs(outer.hold_volume_directory('T5', MOUNT, expected), row)

    def test_unknown_alias_wrong_mount_and_child_path_never_gain_volume_exception(self):
        with self.fixed_mount_fixture() as expected:
            for alias, path in [('Unknown', MOUNT), ('Data', MOUNT), ('T5', MOUNT / 'child'), ('T5', self.directory)]:
                with self.subTest(alias=alias, path=str(path)):
                    with self.assertRaises(outer.Refused):
                        outer.hold_volume_directory(alias, path, expected)
            self.assertEqual(outer.DIRECTORIES, [])

    def test_each_original_identity_field_and_boolean_metadata_are_rejected(self):
        with self.fixed_mount_fixture() as expected:
            for field in ('dev', 'inode', 'uid', 'gid', 'mode'):
                changed = dict(expected, **{field: expected[field] + 1})
                with self.subTest(field=field):
                    with self.assertRaises(outer.Refused):
                        outer.volume_directory_identity('T5', MOUNT, changed)
            with self.assertRaises(outer.Refused):
                outer.volume_directory_identity('T5', MOUNT, dict(expected, dev=True))
            with self.assertRaises(outer.Refused):
                outer.volume_directory_identity('T5', MOUNT, dict(expected, path='/Volumes/Other'))

    def test_retained_original_volume_fd_does_not_hide_real_mode_drift(self):
        with self.fixed_mount_fixture() as expected:
            row = outer.hold_volume_directory('T5', MOUNT, expected)
            os.chmod(self.directory, 0o755)
            self.assertEqual(os.fstat(row['fd']).st_ino, expected['inode'])
            with self.assertRaises(outer.Refused):
                outer.verify_directories()

    def run_failure_main(self, directory_also_fails=False):
        os.chmod(self.directory, 0o700)
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        pin = outer.directory_identity(self.directory)
        row = {'path': self.directory, 'pin': pin, 'fd': fd, 'private': True}
        class FailedOwner:
            def __init__(self):
                self.finishes = 0
            def finish(self):
                self.finishes += 1
            def receipt(self):
                return {'original_count': 0, 'children': [], 'finished': True,
                        'passed_process_custody': False, 'failed': True, 'interrupted': False}
        owner = FailedOwner()
        def hold(path):
            self.assertEqual(path, outer.INPUT)
            outer.DIRECTORIES.append(row)
            return row
        def fail_run(inputs, controller_pin):
            outer.OWNER = owner
            outer.PHASE = 'verify_volume_T5'
            raise outer.Refused('controlled_directory')
        observed = []
        real_verify = outer.verify_directories
        def verify():
            observed.append('directory_observed_after_owner_failure')
            real_verify()
            if directory_also_fails:
                raise outer.Refused('original_directory_identity_changed')
        out = io.StringIO()
        with mock.patch.object(outer, 'hold_directory', hold), \
                mock.patch.object(outer, 'create_output'), \
                mock.patch.object(outer, 'private_stdio', return_value=contextlib.nullcontext()), \
                mock.patch.object(outer, 'read_file', return_value=(b'{}\n', {})), \
                mock.patch.object(outer, 'run', fail_run), \
                mock.patch.object(outer, 'verify_directories', verify), \
                mock.patch.object(outer.sys, 'addaudithook'), \
                mock.patch.object(outer.signal, 'getitimer', return_value=(0.0, 0.0)), \
                mock.patch.object(outer.signal, 'setitimer'), \
                mock.patch.object(outer.signal, 'signal'), \
                contextlib.redirect_stdout(out):
            code = outer.main(['--inputs-sha256', hashlib.sha256(b'{}\n').hexdigest(),
                               '--controller-sha256', '0' * 64])
        result = json.loads(out.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(owner.finishes, 1)
        self.assertEqual(observed, ['directory_observed_after_owner_failure'])
        self.assertEqual(result['primary_failure'], {'phase': 'verify_volume_T5', 'code': 'controlled_directory'})
        self.assertEqual(result['failure_code'], 'controlled_directory')
        self.assertEqual(result['failure_phase'], 'verify_volume_T5')
        self.assertFalse(result['owned_native_metadata_processes']['passed_process_custody'])
        self.assertTrue(result['owned_native_metadata_processes']['failed'])
        self.assertEqual(result['owned_directory_handles_closed'], 1)
        self.assertTrue(result['all_owned_directory_handles_retired'])
        with self.assertRaises(OSError) as closed:
            os.fstat(fd)
        self.assertEqual(closed.exception.errno, errno.EBADF)
        return result

    def test_primary_survives_failed_owner_and_directory_evidence_and_close_still_complete(self):
        result = self.run_failure_main()
        self.assertTrue(result['original_directory_paths_and_handles_preserved'])
        self.assertEqual(result['cleanup_failures'], [
            {'phase': 'process_custody', 'code': 'final_original_process_custody'}])

    def test_multiple_cleanup_failures_never_overwrite_primary_or_skip_real_fd_close(self):
        result = self.run_failure_main(directory_also_fails=True)
        self.assertFalse(result['original_directory_paths_and_handles_preserved'])
        self.assertEqual(result['cleanup_failures'], [
            {'phase': 'process_custody', 'code': 'final_original_process_custody'},
            {'phase': 'directory_identity', 'code': 'original_directory_identity_changed'}])

    def test_four_unused_roots_require_actual_absence_and_do_not_hide_observation_errors(self):
        paths = {role: self.directory / role for role in ('capture', 'archive', 'key', 'restore')}
        outer.verify_attempt_roots_absent(paths)
        self.assertEqual(outer.PUBLIC['unused_data_roots_observed_absent_before_capture'], dict.fromkeys(paths, True))
        paths['archive'].mkdir()
        with self.assertRaises(outer.Refused):
            outer.verify_attempt_roots_absent(paths)
        paths['archive'].rmdir()
        original = Path.lstat
        def denied(path, *args, **kwargs):
            if path == paths['capture']:
                raise PermissionError('synthetic denied observation')
            return original(path, *args, **kwargs)
        with mock.patch.object(Path, 'lstat', denied):
            with self.assertRaises(PermissionError):
                outer.verify_attempt_roots_absent(paths)


if __name__ == '__main__':
    unittest.main(verbosity=2)
