# Historical V1.4.7 evidence must not override current V2.1 entry points.
from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "entry_renderer", ROOT / "scripts/render_plan_v1_4_7.py"
)
assert SPEC and SPEC.loader
RENDERER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENDERER)


def section(text: str, title: str) -> str:
    heading = "## " + title + "\n"
    if text.count(heading) != 1:
        raise AssertionError("expected one section: " + title)
    return text.split(heading, 1)[1].split("\n## ", 1)[0].strip()


class CurrentEntryTests(unittest.TestCase):
    def test_current_entry_remains_v2_1(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        portal = (ROOT / "docs/CURRENT_DOCUMENTATION.md").read_text(encoding="utf-8")
        for value in (readme, portal):
            self.assertIn("HEPTABAO-PLAN-2026-09-07-V2.1", value)
            self.assertNotIn("Status: `V1.4.7 / CURRENT`", value)
        self.assertIn("**45 packages**", readme)
        self.assertIn("all 45 workspace packages", portal)

    def test_historical_renderer_does_not_generate_current_entry(self) -> None:
        values = RENDERER.static_files()
        self.assertNotIn(Path("README.md"), values)
        self.assertNotIn(Path("docs/CURRENT_DOCUMENTATION.md"), values)
        truth = RENDERER.build_truth(ROOT)
        paths = set(RENDERER.normative_paths(truth))
        self.assertNotIn(Path("README.md"), paths)
        self.assertNotIn(Path("docs/CURRENT_DOCUMENTATION.md"), paths)

    def test_historical_manifest_does_not_claim_current_entry(self) -> None:
        manifest = yaml.safe_load((ROOT / RENDERER.MANIFEST_PATH).read_text())
        indexed = {entry["path"] for entry in manifest["files"]}
        self.assertNotIn("README.md", indexed)
        self.assertNotIn("docs/CURRENT_DOCUMENTATION.md", indexed)
        self.assertIn(
            "docs/plan/HEPTABAO_PLAN_V1_4_7_POST_MERGE_TRUTH_AND_EXTERNAL_ADMISSION.md",
            indexed,
        )
        self.assertIn("tests/plan/test_current_entry_v1_4_7.py", indexed)

    def _candidate(self, temporary: str) -> Path:
        root = Path(temporary) / "source"
        shutil.copytree(
            ROOT,
            root,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "target"),
        )
        return root

    def test_check_mode_does_not_read_current_entry_as_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._candidate(temporary)
            readme = root / "README.md"
            portal = root / "docs/CURRENT_DOCUMENTATION.md"
            readme.write_text("# independently owned current README\n", encoding="utf-8")
            portal.write_text("# independently owned current portal\n", encoding="utf-8")
            before = (readme.read_bytes(), portal.read_bytes())
            result = subprocess.run(
                [sys.executable, "scripts/render_plan_v1_4_7.py", "--check"],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual(before, (readme.read_bytes(), portal.read_bytes()))

    def test_missing_current_entry_is_not_recreated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._candidate(temporary)
            readme = root / "README.md"
            portal = root / "docs/CURRENT_DOCUMENTATION.md"
            readme.unlink()
            portal.unlink()
            result = subprocess.run(
                [sys.executable, "scripts/render_plan_v1_4_7.py", "--check"],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertFalse(readme.exists())
            self.assertFalse(portal.exists())

    def test_module_index_labels_current_workspace_truth(self) -> None:
        module_index = (ROOT / "docs/modules/README.md").read_text(encoding="utf-8")
        self.assertNotIn("V1.4.4 documentation-coverage baseline:", module_index)
        self.assertNotIn("\nSource baseline:", module_index)
        current_truth = section(module_index, "V1.4.7 machine-verified module truth")
        self.assertIn(
            "planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml", current_truth
        )
        truth = yaml.safe_load(
            (ROOT / "planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml").read_text()
        )
        self.assertIn(
            f"All `{truth['module_count']}` Cargo workspace crates", current_truth
        )
        self.assertEqual(len(truth["modules"]), truth["module_count"])


if __name__ == "__main__":
    unittest.main()
