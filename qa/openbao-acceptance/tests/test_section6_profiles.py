from pathlib import Path
import os
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import capacity_live
import kv_read_scaling_live
import transit_migration_live
from bao_http import BaoError


class SectionSixProfileGuards(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)

    def arguments(self, name='result.json'):
        return ['--binary', '/not-executed', '--output', str(self.root / name)]

    def test_public_output_parent_blocks_before_service_allocation(self):
        self.root.chmod(0o755)
        for module in (capacity_live, kv_read_scaling_live, transit_migration_live):
            with self.subTest(module=module.__name__), patch.object(module, 'run') as run:
                with self.assertRaises(BaoError):
                    module.main(self.arguments())
                run.assert_not_called()

    def test_setgid_parent_not_silently_accepted(self):
        self.root.chmod(0o2700)
        # macOS strips a non-root caller's setgid bit; Linux keeps the guard
        # below meaningful while macOS must not report a false failure.
        if stat.S_IMODE(self.root.lstat().st_mode) != 0o2700:
            return
        for module in (capacity_live, kv_read_scaling_live, transit_migration_live):
            with patch.object(module, 'run') as run:
                with self.assertRaises(BaoError):
                    module.main(self.arguments())
                run.assert_not_called()

    def test_existing_partial_result_is_never_overwritten(self):
        target = self.root / 'result.json'
        target.write_text('partial receipt')
        target.chmod(0o600)
        for module in (capacity_live, kv_read_scaling_live, transit_migration_live):
            with patch.object(module, 'run') as run:
                with self.assertRaises(BaoError):
                    module.main(self.arguments())
                run.assert_not_called()
        self.assertEqual(target.read_text(), 'partial receipt')

    def test_dangling_result_symlink_blocks_before_service_allocation(self):
        (self.root / 'result.json').symlink_to(self.root / 'missing')
        for module in (capacity_live, kv_read_scaling_live, transit_migration_live):
            with patch.object(module, 'run') as run:
                with self.assertRaises(BaoError):
                    module.main(self.arguments())
                run.assert_not_called()

    def test_intermediate_parent_symlink_cannot_redirect_result(self):
        directory = self.root / 'actual'
        directory.mkdir(mode=0o700)
        (self.root / 'redirect').symlink_to(directory, target_is_directory=True)
        for module in (capacity_live, kv_read_scaling_live, transit_migration_live):
            with patch.object(module, 'run') as run:
                with self.assertRaises(BaoError):
                    module.main(self.arguments('redirect/result.json'))
                run.assert_not_called()

    def test_missing_official_input_is_not_substituted_by_a_model(self):
        with patch.dict(os.environ, {'HB_ORACLE_BINARY': '/absent', 'HB_ORACLE_ARCHIVE': '/absent'}):
            with self.assertRaises(FileNotFoundError):
                transit_migration_live.run(Path('/absent'), self.root / 'result.json')
        self.assertFalse((self.root / 'result.json').exists())

    def test_failure_is_propagated_not_converted_to_a_success_receipt(self):
        for module in (capacity_live, kv_read_scaling_live, transit_migration_live):
            with patch.object(module, 'run', side_effect=BaoError('fixture fault')):
                with self.assertRaises(BaoError):
                    module.main(self.arguments())
        self.assertFalse((self.root / 'result.json').exists())


if __name__ == '__main__':
    unittest.main()
