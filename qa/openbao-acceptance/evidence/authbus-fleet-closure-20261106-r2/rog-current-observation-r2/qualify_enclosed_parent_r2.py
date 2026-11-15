#!/usr/bin/env python3
"""Pure admission cases; no remote source, service or credential access."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'observe_registered_rog_r2.py'
raw = SOURCE.read_bytes()
module = ast.parse(raw)
functions = [n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'enclosed_public_parent']
assert len(functions) == 1
LIVE = Path('/home/qian-qi/.openclaw')
PLUGIN = LIVE / 'extensions/openclaw-authbus'

class AdmissionCases(unittest.TestCase):
    def setUp(self):
        self.private = {'identity': ['66306', '27003080', '1000', '1000', str(stat.S_IFDIR | 0o700)], 'symlink': False, 'target': None}
        self.scope = {'LIVE': LIVE, 'PLUGIN': PLUGIN, 'anchors': {str(LIVE): self.private}, 'stat': stat, 'os': SimpleNamespace(getuid=lambda: 1000)}
        exec(compile(ast.Module(body=functions, type_ignores=[]), 'source-extracted-admission', 'exec'), self.scope)
        self.s = SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=1000, st_gid=1000)

    def allow(self, path=None, parent=None, public=True):
        return self.scope['enclosed_public_parent'](path or PLUGIN / 'index.js', parent or LIVE / 'extensions', self.s, public)

    def test_exact_observed_public_directory(self):
        self.assertTrue(self.allow())

    def test_no_private_input_exception(self):
        self.assertFalse(self.allow(public=False))

    def test_only_registered_plugin_subtree(self):
        for path in [LIVE / 'extensions/other/index.js', LIVE / 'extensions-other/index.js', LIVE / 'openclaw.json', Path('/tmp/openclaw-authbus/index.js'), PLUGIN / '../other/index.js']:
            with self.subTest(path=str(path)): self.assertFalse(self.allow(path=path))

    def test_only_one_exact_ancestor(self):
        for parent in [LIVE, PLUGIN, LIVE.parent, LIVE / 'extensions-other']:
            with self.subTest(parent=str(parent)): self.assertFalse(self.allow(parent=parent))

    def test_exact_directory_mode(self):
        for mode in [0o777, 0o770, 0o755, 0o1775, 0o2775]:
            with self.subTest(mode=mode):
                self.s.st_mode = stat.S_IFDIR | mode
                self.assertFalse(self.allow())

    def test_directory_symlink_or_file_refused(self):
        for kind in [stat.S_IFLNK, stat.S_IFREG]:
            self.s.st_mode = kind | 0o775
            self.assertFalse(self.allow())

    def test_exact_directory_owner_and_group(self):
        for attribute, value in [('st_uid', 0), ('st_uid', 1001), ('st_gid', 0), ('st_gid', 1001)]:
            with self.subTest(attribute=attribute, value=value):
                original = getattr(self.s, attribute)
                setattr(self.s, attribute, value)
                self.assertFalse(self.allow())
                setattr(self.s, attribute, original)

    def test_actual_observer_uid_required(self):
        self.scope['os'] = SimpleNamespace(getuid=lambda: 1001)
        self.assertFalse(self.allow())

    def test_no_unbound_private_ancestor(self):
        self.scope['anchors'].clear()
        self.assertFalse(self.allow())

    def test_exact_0700_private_boundary(self):
        for mode in [0o710, 0o750, 0o755, 0o770, 0o775, 0o777]:
            with self.subTest(mode=mode):
                self.private['identity'][4] = str(stat.S_IFDIR | mode)
                self.assertFalse(self.allow())

    def test_private_boundary_owner_and_group(self):
        for position, value in [(2, '0'), (2, '1001'), (3, '0'), (3, '1001')]:
            original = self.private['identity'][position]
            self.private['identity'][position] = value
            self.assertFalse(self.allow())
            self.private['identity'][position] = original

    def test_private_boundary_alias_refused(self):
        self.private['symlink'] = True
        self.assertFalse(self.allow())
        self.private['symlink'] = False
        self.private['target'] = str(LIVE)
        self.assertFalse(self.allow())

    def test_private_boundary_identity_shape(self):
        for value in [None, {}, [], ['66306', '27003080', '1000', '1000'], ['66306', '27003080', '1000', '1000', str(stat.S_IFDIR | 0o700), 'extra']]:
            self.private['identity'] = value
            self.assertFalse(self.allow())

    def test_original_held_parent_and_final_fences_unchanged(self):
        old = ast.parse((ROOT / 'observe_registered_rog_r1.py').read_bytes())
        names = ('open_regular_parent', 'verify_anchors', 'read_regular', 'proc_read', 'lifetime')
        def selected(tree):
            return {n.name: ast.dump(n, include_attributes=False) for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names}
        self.assertEqual(selected(old), selected(module))
        self.assertEqual(set(selected(module)), set(names))

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(AdmissionCases))
    assert SOURCE.read_bytes() == raw
    print(json.dumps({'schema': 'heptabao.rog-enclosed-public-parent-admission.r2', 'passed': result.wasSuccessful(),
                      'tests': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
                      'sourceBytes': len(raw), 'sourceSha256': hashlib.sha256(raw).hexdigest(),
                      'remoteExecution': False, 'productionChanged': False}, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
