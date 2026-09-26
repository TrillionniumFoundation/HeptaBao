"""No database model can satisfy the real PostgreSQL acceptance boundary."""
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

QA = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(QA))
spec = importlib.util.spec_from_file_location('postgres_live', QA / 'postgres_live.py')
pg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pg)


class PostgreSQLBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def environment(self, password='synthetic:password\\only'):
        return pg.psql_environment(self.root, port=34567, database='app', user='reader',
                                   password=password, ca=self.root / 'ca.crt')

    def test_passfile_is_private_escaped_and_removed(self):
        with self.environment() as env:
            path = Path(env['PGPASSFILE'])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.read_text(), 'localhost:34567:app:reader:synthetic\\:password\\\\only\n')
            self.assertNotIn('PGPASSWORD', env)
            self.assertEqual(env['PGREQUIREAUTH'], 'scram-sha-256')
        self.assertFalse(path.exists())

    def test_inherited_service_routing_and_credentials_are_removed(self):
        inherited = {'PGSERVICE':'production','PGSERVICEFILE':'/foreign',
                     'PGPASSWORD':'never-forward','PGHOST':'foreign','PGSSLKEY':'/foreign'}
        with patch.dict(os.environ, inherited), self.environment() as env:
            for key in ('PGSERVICE','PGSERVICEFILE','PGPASSWORD','PGSSLKEY'):
                self.assertNotIn(key, env)
            self.assertEqual(env['PGHOSTADDR'],'127.0.0.1')
            self.assertEqual(env['PGSSLMODE'],'verify-full')

    def test_cleanup_also_occurs_after_failure(self):
        with self.assertRaises(RuntimeError):
            with self.environment() as env:
                path = Path(env['PGPASSFILE'])
                raise RuntimeError('synthetic')
        self.assertFalse(path.exists())

    def test_newline_and_nul_injection_never_creates_passfile(self):
        for password in ('a\nb','a\rb','a\0b'):
            with self.subTest(password=repr(password)), self.assertRaises(ValueError):
                with self.environment(password):
                    self.fail('invalid credential accepted')
        self.assertEqual(list(self.root.iterdir()), [])

    def test_missing_real_postgresql_is_exit_77_not_success(self):
        import json
        output = self.root / 'result.json'
        result = subprocess.run([sys.executable, str(QA / 'postgres_live.py'),
            '--binary', str(self.root / 'missing-server'), '--postgres-bin',str(self.root / 'missing-pg'),
            '--output', str(output)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode,77)
        report=json.loads(output.read_text())
        self.assertEqual(report['status'],'blocked_prerequisite')
        self.assertIs(report['real_postgresql_executed'],False)
        self.assertIs(report['provider_sql_executed'],False)
        self.assertEqual(report['check_count'],0)
