"""Exercise only the new public receipt publisher on isolated local files."""
import ast
import json
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name('prepare_source.py')

class ReceiptPublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=SOURCE.parent)
        self.root = Path(self.tmp.name)
        module = ast.parse(SOURCE.read_text())
        chosen = [node for node in module.body if isinstance(node, (ast.ClassDef, ast.FunctionDef))
                  and node.name in {'Refused', 'need', 'identity', 'new_json'}]
        self.ns = {'os': os, 'json': json, 'stat': stat, 'time': time,
                   'OUT': self.root, 'END': time.monotonic() + 10, 'FDS': []}
        exec(compile(ast.Module(body=chosen, type_ignores=[]), str(SOURCE), 'exec'), self.ns)
        self.target = self.root / 'preparation.result.public.json'

    def tearDown(self):
        self.tmp.cleanup()

    def test_complete_readback_file_and_parent_sync_with_all_three_fds_closed(self):
        actual_fsync = os.fsync
        kinds = []
        def syncing(fd):
            kinds.append('directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file')
            return actual_fsync(fd)
        with patch.object(os, 'fsync', side_effect=syncing):
            self.ns['new_json'](self.target, {'status': 'synthetic', 'count': 2})
        self.assertEqual(kinds, ['file', 'directory'])
        self.assertEqual(json.loads(self.target.read_bytes()), {'status': 'synthetic', 'count': 2})
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o600)
        self.assertEqual(len(self.ns['FDS']), 3)
        self.assertTrue(all(r['attempts'] == 1 and r['closed'] for r in self.ns['FDS']))

    def test_existing_receipt_never_overwritten_and_parent_still_closed(self):
        self.ns['new_json'](self.target, {'original': True})
        before = self.target.read_bytes()
        with self.assertRaises(FileExistsError):
            self.ns['new_json'](self.target, {'replacement': True})
        self.assertEqual(self.target.read_bytes(), before)
        self.assertTrue(all(r['attempts'] == 1 and r['closed'] for r in self.ns['FDS']))

    def test_close_error_continues_other_original_closes_and_never_claims_complete(self):
        actual_close = os.close
        calls = []
        def closing(fd):
            calls.append(fd)
            actual_close(fd)
            if len(calls) == 1:
                raise OSError('synthetic post-close uncertainty')
        with patch.object(os, 'close', side_effect=closing):
            with self.assertRaises(OSError):
                self.ns['new_json'](self.target, {'synthetic': True})
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(set(calls)), 3)
        self.assertTrue(all(r['attempts'] == 1 for r in self.ns['FDS']))
        self.assertEqual(sum(r['closed'] for r in self.ns['FDS']), 2)

if __name__ == '__main__':
    unittest.main(verbosity=2)
