from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / 'scripts/validate_module_documentation_v1_4_4.py'


class ModuleDocumentationV144Tests(unittest.TestCase):
    def run_validator(self, root: Path):
        return subprocess.run(
            [sys.executable, str(root / 'scripts/validate_module_documentation_v1_4_4.py'), '--root', str(root)],
            cwd=root,
            text=True,
            capture_output=True,
        )

    def copy_repo(self):
        temp = Path(tempfile.mkdtemp(prefix='heptabao-doc-test-'))
        self.addCleanup(lambda: shutil.rmtree(temp, ignore_errors=True))
        shutil.copytree(
            ROOT,
            temp,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns('.git', 'target', '__pycache__'),
        )
        return temp

    def test_current_repository_validates(self):
        result = self.run_validator(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_module_document_fails_closed(self):
        temp = self.copy_repo()
        (temp / 'docs/modules/heptabao-protocol.md').unlink()
        self.assertNotEqual(self.run_validator(temp).returncode, 0)

    def test_missing_required_section_fails_closed(self):
        temp = self.copy_repo()
        path = temp / 'docs/modules/heptabao-storage-api.md'
        path.write_text(
            path.read_text(encoding='utf-8').replace('## Known gaps', '## Removed gaps'),
            encoding='utf-8',
        )
        self.assertNotEqual(self.run_validator(temp).returncode, 0)

    def test_authority_promotion_fails_closed(self):
        temp = self.copy_repo()
        path = temp / 'planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml'
        obj = yaml.safe_load(path.read_text(encoding='utf-8'))
        obj['claims']['production_authority'] = True
        path.write_text(yaml.safe_dump(obj, sort_keys=False), encoding='utf-8')
        self.assertNotEqual(self.run_validator(temp).returncode, 0)

    def test_duplicate_historical_document_path_fails_closed(self):
        temp = self.copy_repo()
        path = temp / 'planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml'
        obj = yaml.safe_load(path.read_text(encoding='utf-8'))
        obj['modules'][1]['document'] = obj['modules'][0]['document']
        path.write_text(yaml.safe_dump(obj, sort_keys=False), encoding='utf-8')
        self.assertNotEqual(self.run_validator(temp).returncode, 0)

    def test_historical_count_drift_fails_closed(self):
        temp = self.copy_repo()
        path = temp / 'planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml'
        obj = yaml.safe_load(path.read_text(encoding='utf-8'))
        obj['documented_module_count'] = 18
        path.write_text(yaml.safe_dump(obj, sort_keys=False), encoding='utf-8')
        self.assertNotEqual(self.run_validator(temp).returncode, 0)

    def test_additional_v3_guide_does_not_rewrite_historical_baseline(self):
        temp = self.copy_repo()
        (temp / 'docs/modules/heptabao-future-v3.md').write_text(
            '# future V3 guide\n',
            encoding='utf-8',
        )
        result = self.run_validator(temp)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
