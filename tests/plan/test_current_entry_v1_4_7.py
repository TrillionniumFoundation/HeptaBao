"""Current documentation must describe this source tree, not an older tranche."""
from __future__ import annotations

import hashlib
import importlib.util
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("entry_renderer", ROOT / "scripts/render_plan_v1_4_7.py")
assert SPEC and SPEC.loader
RENDERER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENDERER)


def section(text: str, title: str) -> str:
    heading = "## " + title + "\n"
    if text.count(heading) != 1:
        raise AssertionError("expected one section: " + title)
    return text.split(heading, 1)[1].split("\n## ", 1)[0].strip()


class CurrentEntryTests(unittest.TestCase):
    def test_current_plan_agrees_with_status_and_portal(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        status = RENDERER.status_document()
        self.assertEqual(1, readme.count("- Current plan:"))
        self.assertIn("- Current plan: **V" + status["revision"], section(readme, "Current truth"))
        self.assertIn(status["current_plan"], section(readme, "Current normative entry points"))
        self.assertIn(status["current_plan"], section(RENDERER.current_documentation(), "Current normative set"))

    def test_current_entry_table_is_the_complete_portal_table(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        expected = section(RENDERER.current_documentation(), "Current normative set")
        current = section(readme, "Current normative entry points")
        self.assertIn(expected, current)
        targets = re.findall(r"\| `([^`]+)` \|", expected)
        self.assertEqual(11, len(targets))
        for path in targets:
            self.assertTrue((ROOT / path).is_file(), path)
        self.assertNotIn("MODULE_DOCUMENTATION_STANDARD_V1.md", current)

    def test_inherited_foundations_are_not_the_current_plan(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        inherited = section(readme, "Inherited foundations")
        self.assertIn("V1.4.6 authoritative recovery closure", inherited)
        self.assertIn(RENDERER.BASELINE_COMMIT, inherited)
        self.assertIn("V1.4.5 security invariant closure", inherited)
        self.assertIn("HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml", inherited)
        self.assertNotIn("V1.4.6", section(readme, "Current truth"))

    def test_development_commands_include_the_current_gate(self) -> None:
        development = section((ROOT / "README.md").read_text(encoding="utf-8"), "Development")
        for command in (
            "python -m pip install --requirement requirements-plan.txt",
            "python scripts/render_plan_v1_4_7.py --check",
            "python scripts/validate_plan_v1_4_7.py",
            "python -m unittest discover -s tests/plan -p 'test_*v1_4_7.py' -v",
            "python -m unittest discover -s tests/plan -p 'test_external_completion_evidence_v1.py' -v",
            "cargo +1.98.0 test --locked --workspace --all-targets",
        ):
            self.assertIn(command, development)
        self.assertIn("not production-deployable", (ROOT / "README.md").read_text())
        self.assertIn("Qualification: **false**", (ROOT / "README.md").read_text())

    def test_readme_is_generated_without_reading_existing_readme(self) -> None:
        values = RENDERER.static_files()
        self.assertIn(Path("README.md"), values)
        self.assertEqual((ROOT / "README.md").read_bytes(), values[Path("README.md")].encode("utf-8"))

    def test_readme_and_regressions_are_normatively_bound(self) -> None:
        manifest = yaml.safe_load((ROOT / RENDERER.MANIFEST_PATH).read_text())
        indexed = {entry["path"]: entry["sha256"] for entry in manifest["files"]}
        for name in ("README.md", "tests/plan/test_current_entry_v1_4_7.py"):
            self.assertIn(name, indexed)
            self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), indexed[name])

    def _candidate(self, temporary: str) -> Path:
        root = Path(temporary) / "source"
        shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns(".git", "__pycache__", "target"))
        return root

    def test_rehashing_stale_readme_does_not_make_check_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._candidate(temporary)
            readme = root / "README.md"
            readme.write_bytes(readme.read_bytes().replace(b"# HeptaBao\n", b"# HeptaBao stale entry\n", 1))
            manifest = root / RENDERER.MANIFEST_PATH
            value = yaml.safe_load(manifest.read_text())
            for entry in value["files"]:
                if entry["path"] == "README.md":
                    entry["sha256"] = hashlib.sha256(readme.read_bytes()).hexdigest()
            manifest.write_text(RENDERER.dump_yaml(value), encoding="utf-8")
            before = (readme.read_bytes(), manifest.read_bytes())
            result = subprocess.run([sys.executable, "scripts/render_plan_v1_4_7.py", "--check"],
                                    cwd=root, capture_output=True, text=True, check=False, timeout=60)
            self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("README.md", result.stdout + result.stderr)
            self.assertEqual(before, (readme.read_bytes(), manifest.read_bytes()))

    def test_missing_readme_is_rejected_without_recreating_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._candidate(temporary)
            (root / "README.md").unlink()
            result = subprocess.run([sys.executable, "scripts/render_plan_v1_4_7.py", "--check"],
                                    cwd=root, capture_output=True, text=True, check=False, timeout=60)
            self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("README.md", result.stdout + result.stderr)
            self.assertFalse((root / "README.md").exists())


    def test_module_index_labels_historical_coverage_baseline(self) -> None:
        module_index = (ROOT / "docs/modules/README.md").read_text(encoding="utf-8")
        self.assertIn("V1.4.4 documentation-coverage baseline:", module_index)
        self.assertNotIn("\nSource baseline:", module_index)
        current_truth = section(module_index, "V1.4.7 machine-verified module truth")
        self.assertIn("planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml", current_truth)
        truth = yaml.safe_load((ROOT / "planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml").read_text())
        self.assertEqual(19, truth["module_count"])


if __name__ == "__main__":
    unittest.main()
