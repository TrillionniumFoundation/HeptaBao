"""Launcher selection tests only; no processes or HTTP compatibility evidence."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import agent_proxy_helper_live as runner


class AgentProxyOracleVersionTests(unittest.TestCase):
    def test_historical_default_and_explicit_version_reach_launcher_and_identity(self):
        for version, extra in (('2.6.2', []), ('2.7.0', ['--oracle-version', '2.7.0'])):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                root.chmod(0o700)
                output = root / 'report.json'
                argv = ['runner', '--binary', '/synthetic/binary', '--output', str(output), '--oracle', *extra]
                with patch.object(sys, 'argv', argv), patch.object(runner, 'file_hash', return_value='c' * 64), \
                     patch.object(runner, 'start_oracle', side_effect=RuntimeError('fixture-not-started')) as start:
                    self.assertEqual(runner.main(), 1)
                self.assertEqual(start.call_args.kwargs, {'version': version})
                report = json.loads(output.read_text())
                self.assertEqual(report['target'], 'official-openbao-' + version)
                self.assertEqual(report['oracle_version'], version)
                self.assertEqual(report['schema'], 'heptabao.operational-process-evidence.v2')
                self.assertEqual(report['cases'], [])
                self.assertFalse(report['production_authority'])

    def test_unpinned_version_rejected_before_fixture_allocation(self):
        argv = ['runner', '--binary', '/synthetic/binary', '--output', '/synthetic/report',
                '--oracle', '--oracle-version', 'latest']
        with patch.object(sys, 'argv', argv), patch.object(runner.tempfile, 'mkdtemp') as allocate, \
             patch.object(runner, 'start_oracle') as start:
            with self.assertRaises(SystemExit) as error:
                runner.main()
            self.assertEqual(error.exception.code, 2)
        allocate.assert_not_called()
        start.assert_not_called()


if __name__ == '__main__':
    unittest.main()
