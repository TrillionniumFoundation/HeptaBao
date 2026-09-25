"""Synthetic TLS files have explicit safe modes, independent of the host umask."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'clients/python'))
from heptabao.private_state import read_trusted_ca

spec = importlib.util.spec_from_file_location('tls_permission_smoke', ROOT / 'qa/single-node/smoke.py')
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class SmokeTlsPermissionTests(unittest.TestCase):
    def test_certificate_integrity_and_private_key_modes_ignore_umask(self):
        for mask in (0o000, 0o002, 0o022, 0o077):
            with self.subTest(umask=oct(mask)), tempfile.TemporaryDirectory() as tmp:
                previous = os.umask(mask)
                try:
                    node = smoke.Instance(Path('/not-started'), Path(tmp) / 'node')
                finally:
                    os.umask(previous)
                self.assertIsNone(node.process)
                for name in ('ca.crt', 'tls.crt'):
                    path = node.root / name
                    self.assertEqual(path.stat().st_mode & 0o777, 0o644)
                    self.assertTrue(read_trusted_ca(str(path)).startswith(b'-----BEGIN CERTIFICATE-----'))
                for name in ('ca.key', 'tls.key', 'server.json'):
                    self.assertEqual((node.root / name).stat().st_mode & 0o777, 0o600)
                self.assertEqual(node.root.stat().st_mode & 0o777, 0o700)


if __name__ == '__main__':
    unittest.main()
