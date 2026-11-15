#!/usr/bin/env python3
"""Local synthetic rejection guards; never import the real SDK or observer."""
import ast
import hashlib
import io
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'observe_registered_rog_r3.py'
OLD = ROOT.parents[1] / 'rog-client-work/observe_registered_rog_r2.py'
RAW = SOURCE.read_bytes()
MODULE = ast.parse(RAW)
SDK = Path('/home/qian-qi/.npm-global/lib/node_modules/openclaw')
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
IDENTITY = ['66306', '28718589', '1000', '1000', '33204', '1', '116017',
            '1784858778581475684', '1784858778581475684']
NAMES = ('identity', 'observed_sdk_package_shape', 'observe_sdk_package_metadata')
FUNCTIONS = [n for n in MODULE.body if isinstance(n, ast.FunctionDef) and n.name in NAMES]
assert len(FUNCTIONS) == len(NAMES)


class ObservationalCases(unittest.TestCase):
    def setUp(self):
        self.info = SimpleNamespace(**dict(zip(FIELDS, map(int, IDENTITY))))
        self.closed = []
        self.rows = []
        self.held = [(91, {'closed': False}), (92, {'closed': False})]
        self.stream = io.BytesIO(b' ' * self.info.st_size)
        self.fake_os = SimpleNamespace(
            getuid=lambda: 1000, O_RDONLY=0, O_NOFOLLOW=131072, O_NONBLOCK=2048,
            open=lambda *a, **kw: 99, fstat=lambda fd: self.info,
            read=lambda fd, count: self.stream.read(count), close=self.closed.append)

        def need(value, code):
            if not value:
                raise ValueError(code)

        def tracked(fd, kind):
            row = {'kind': kind, 'closed': False}
            self.rows.append(row)
            return row

        def anchor(path, public):
            self.assertFalse(public)
            self.assertEqual(path, SDK / 'package.json')
            return path

        self.scope = dict(SDK=SDK, SDK_PACKAGE_IDENTITY=IDENTITY, os=self.fake_os,
                          stat=stat, hashlib=hashlib, remaining=lambda: None,
                          need=need, anchor=anchor,
                          open_regular_parent=lambda p: (92, self.held),
                          track_fd=tracked)
        exec(compile(ast.Module(body=FUNCTIONS, type_ignores=[]),
                     'source-extracted-observational-sdk-guards', 'exec'), self.scope)

    def shape(self, path=None):
        return self.scope['observed_sdk_package_shape'](path or SDK / 'package.json', self.info)

    def read(self):
        with patch.object(Path, 'lstat', return_value=self.info):
            return self.scope['observe_sdk_package_metadata']()

    def assert_closed(self):
        self.assertEqual(self.closed, [99, 92, 91])
        self.assertTrue(all(row['closed'] for row in self.rows))
        self.assertTrue(all(row['closed'] for _, row in self.held))

    def test_exact_observed_file_can_only_be_observed(self):
        self.assertTrue(self.shape())
        pin, raw = self.read()
        self.assertEqual(len(raw), 116017)
        self.assertEqual(pin['sourceAuthority'], 'untrusted_group_writable_observation_only')
        self.assertIs(pin['trustedForSdkExecution'], False)
        self.assertIs(pin['sdkOwnerSourceEstablished'], False)
        self.assert_closed()

    def test_other_leaf_private_input_and_relative_alias_rejected(self):
        for path in (SDK / 'index.js', SDK / 'other/package.json',
                     Path('/home/qian-qi/.openclaw/openclaw.json'),
                     SDK / '../openclaw/package.json', Path('package.json')):
            with self.subTest(path=str(path)):
                self.assertFalse(self.shape(path))

    def test_every_observed_identity_field_is_bound(self):
        for field in FIELDS:
            previous = getattr(self.info, field)
            setattr(self.info, field, previous + 1)
            with self.subTest(field=field):
                self.assertFalse(self.shape())
            setattr(self.info, field, previous)

    def test_other_caller_uid_rejected(self):
        self.fake_os.getuid = lambda: 1001
        self.assertFalse(self.shape())

    def test_ordinary_private_reader_and_original_fences_unchanged(self):
        old = ast.parse(OLD.read_bytes())
        names = {'read_regular', 'anchor', 'open_regular_parent', 'verify_anchors',
                 'proc_read', 'lifetime', 'enclosed_public_parent'}
        def selected(tree):
            return {n.name: ast.dump(n, include_attributes=False) for n in tree.body
                    if isinstance(n, ast.FunctionDef) and n.name in names}
        self.assertEqual(selected(old), selected(MODULE))
        self.assertEqual(set(selected(MODULE)), names)

    def test_file_grow_is_bounded_and_all_handles_close(self):
        self.stream = io.BytesIO(b' ' * (self.info.st_size + 1))
        with self.assertRaisesRegex(ValueError, 'bounded_observed_sdk_package_read'):
            self.read()
        self.assert_closed()

    def test_short_file_rejected_and_handles_close(self):
        self.stream = io.BytesIO(b' ' * (self.info.st_size - 1))
        with self.assertRaisesRegex(ValueError, 'stable_observed_sdk_package'):
            self.read()
        self.assert_closed()

    def test_changed_open_file_rejected_and_handles_close(self):
        changed = SimpleNamespace(**vars(self.info))
        changed.st_ctime_ns += 1
        values = iter((self.info, changed))
        self.fake_os.fstat = lambda fd: next(values)
        with self.assertRaisesRegex(ValueError, 'stable_observed_sdk_package'):
            self.read()
        self.assert_closed()

    def test_changed_leaf_rejected_and_handles_close(self):
        changed = SimpleNamespace(**vars(self.info))
        changed.st_ino += 1
        with patch.object(Path, 'lstat', return_value=changed):
            with self.assertRaisesRegex(ValueError, 'stable_observed_sdk_package'):
                self.scope['observe_sdk_package_metadata']()
        self.assert_closed()

    def test_alias_rejected_before_open(self):
        self.scope['anchor'] = lambda *a: SDK / 'different.json'
        with self.assertRaisesRegex(ValueError, 'observed_sdk_package_no_alias'):
            self.read()
        self.assertEqual(self.closed, [])
        self.assertEqual(self.rows, [])

    def test_wrong_initial_metadata_rejected_before_content_read(self):
        self.info.st_mode = stat.S_IFREG | 0o666
        self.fake_os.read = lambda *a: self.fail('unqualified content read')
        with self.assertRaisesRegex(ValueError, 'exact_observed_public_sdk_metadata'):
            self.read()
        self.assert_closed()

    def test_open_failure_closes_held_parents(self):
        def fail(*a, **kw):
            raise OSError('synthetic open failure')
        self.fake_os.open = fail
        with self.assertRaises(OSError):
            self.read()
        self.assertEqual(self.closed, [92, 91])
        self.assertTrue(all(row['closed'] for _, row in self.held))


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(ObservationalCases))
    assert SOURCE.read_bytes() == RAW
    print(json.dumps({'schema': 'heptabao.rog-observational-sdk-guards.r3',
                      'passed': result.wasSuccessful(), 'tests': result.testsRun,
                      'failures': len(result.failures), 'errors': len(result.errors),
                      'sourceBytes': len(RAW), 'sourceSha256': hashlib.sha256(RAW).hexdigest(),
                      'syntheticLocalOnly': True, 'remoteExecution': False,
                      'sdkImported': False, 'credentialSourceQualified': False}, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
