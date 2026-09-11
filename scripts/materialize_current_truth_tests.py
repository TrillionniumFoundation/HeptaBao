#!/usr/bin/env python3
'''Bind frozen V1.4.7 evidence to the exact current Cargo workspace.

The V1.4.7 renderer remains byte-pinned and fail-closed for the historical
artifacts it owns. It must not overwrite the current V2.1 README or current
documentation portal. Inherited validators are normalized only where they
confuse namespace spelling or a historical module count with current semantics.
'''

from __future__ import annotations

import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "scripts/_render_plan_v1_4_7_baseline.py"
WRAPPER = ROOT / "scripts/render_plan_v1_4_7.py"
V145_VALIDATOR = ROOT / "scripts/validate_plan_v1_4_5.py"
CURRENT_ENTRY_TEST = ROOT / "tests/plan/test_current_entry_v1_4_7.py"
MODULE_TRUTH_TEST = ROOT / "tests/plan/test_module_source_truth_v1_4_7.py"


def replace_exact(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"source anchor drift for {path.relative_to(ROOT)}: "
            f"expected one match, found {count}"
        )
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"PATCHED {path.relative_to(ROOT)}")


def replace_anchored_file(path: Path, required: tuple[str, ...], content: str) -> None:
    original = path.read_text(encoding="utf-8")
    missing = [token for token in required if token not in original]
    if missing:
        raise SystemExit(
            f"source anchor drift for {path.relative_to(ROOT)}: missing {missing!r}"
        )
    path.write_text(content, encoding="utf-8")
    print(f"PATCHED {path.relative_to(ROOT)}")


def patch_baseline_and_wrapper() -> None:
    replace_exact(
        BASELINE,
        '        self.assertEqual(19, actual["module_count"])\n',
        '        self.assertEqual(len(actual["modules"]), actual["module_count"])\n',
    )

    # Historical V1.4.7 owns its own plan/manifests/module evidence, not the
    # active V2 repository entry pages.
    replace_exact(
        BASELINE,
        '''    values: dict[Path, str] = {
        Path("docs/CURRENT_DOCUMENTATION.md"): current_documentation(),
        Path("docs/modules/MODULE_DOCUMENTATION_STANDARD_V2.md"): module_standard_v2(),
''',
        '''    values: dict[Path, str] = {
        Path("docs/modules/MODULE_DOCUMENTATION_STANDARD_V2.md"): module_standard_v2(),
''',
    )
    replace_exact(
        BASELINE,
        '''    paths = [
        Path("docs/CURRENT_DOCUMENTATION.md"),
        Path("docs/plan/HEPTABAO_PLAN_V1_4_7_POST_MERGE_TRUTH_AND_EXTERNAL_ADMISSION.md"),
''',
        '''    paths = [
        Path("docs/plan/HEPTABAO_PLAN_V1_4_7_POST_MERGE_TRUTH_AND_EXTERNAL_ADMISSION.md"),
''',
    )
    replace_exact(
        BASELINE,
        '''    current = (ROOT / "docs/CURRENT_DOCUMENTATION.md").read_text(encoding="utf-8")
    for token in (
        "HEPTABAO_PLAN_V1_4_7_POST_MERGE_TRUTH_AND_EXTERNAL_ADMISSION.md",
        "HEPTABAO_V1_4_6_POST_MERGE_CLOSURE_RECEIPT.yaml",
        "MODULE_DOCUMENTATION_STANDARD_V2.md",
        "HEPTABAO_EXTERNAL_COMPLETION_ADMISSION_PROTOCOL_V1.md",
    ):
        if token not in current:
            raise SystemExit(f"current documentation missing {token}")
''',
        '''    current = (ROOT / "docs/CURRENT_DOCUMENTATION.md").read_text(encoding="utf-8")
    for token in (
        "HEPTABAO-PLAN-2026-09-07-V2.1",
        "planning/HEPTABAO_CANONICAL_PROJECT_STATE_V2_0.yaml",
        "planning/HEPTABAO_PRODUCT_CAPABILITY_MATRIX_V2_0.yaml",
        "planning/HEPTABAO_BLOCKER_REGISTER_V2_0.yaml",
        "docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V2_1.md",
    ):
        if token not in current:
            raise SystemExit(f"current V2 documentation missing {token}")
    if "Status: `V1.4.7 / CURRENT`" in current:
        raise SystemExit("historical V1.4.7 renderer reclaimed the current portal")
''',
    )

    replace_exact(
        WRAPPER,
        '''def static_files() -> dict[Path, str]:
    values = _ORIGINAL_STATIC_FILES()
    values[Path("README.md")] = readme_source()
    return values
''',
        '''def static_files() -> dict[Path, str]:
    # V1.4.7 is retained as historical exact-source evidence. Current entry
    # pages are owned by the active V2 repository truth and are never rewritten
    # or read back as expected output by this historical renderer.
    return _ORIGINAL_STATIC_FILES()
''',
    )
    replace_exact(
        WRAPPER,
        '''    additions = {
        Path("README.md"),
        Path("tests/plan/test_current_entry_v1_4_7.py"),
''',
        '''    additions = {
        Path("tests/plan/test_current_entry_v1_4_7.py"),
''',
    )

    digest = hashlib.sha256(BASELINE.read_bytes()).hexdigest()
    wrapper_text = WRAPPER.read_text(encoding="utf-8")
    updated, count = re.subn(
        r'^BASELINE_SHA256 = "[0-9a-f]{64}"$',
        f'BASELINE_SHA256 = "{digest}"',
        wrapper_text,
        count=1,
        flags=re.MULTILINE,
    )
    if count != 1:
        raise SystemExit("baseline SHA-256 pin anchor drift")
    WRAPPER.write_text(updated, encoding="utf-8")
    print(f"PINNED baseline_sha256={digest}")


def patch_inherited_validator() -> None:
    # Keep the exact V1.4.6-pinned V1.4.5 semantic tokens in place. Add a
    # namespace-insensitive fallback after the inherited exact comparison.
    replace_exact(
        V145_VALIDATOR,
        '    compact_value = "".join(value.split()) if path.endswith(".rs") else value\n',
        '    compact_value = "".join(value.split()) if path.endswith(".rs") else value\n'
        '    normalized_compact_value = (\n'
        '        compact_value.replace("libc::", "")\n'
        '        if path.endswith(".rs")\n'
        '        else compact_value\n'
        '    )\n',
    )
    replace_exact(
        V145_VALIDATOR,
        '        if path.endswith(".rs") and "".join(token.split()) in compact_value:\n'
        '            continue\n',
        '        if path.endswith(".rs") and "".join(token.split()) in compact_value:\n'
        '            continue\n'
        '        if (\n'
        '            path.endswith(".rs")\n'
        '            and "".join(token.split()).replace("libc::", "")\n'
        '            in normalized_compact_value\n'
        '        ):\n'
        '            continue\n',
    )
    replace_exact(
        V145_VALIDATOR,
        '        "19 / 19",\n',
        '        "Current Cargo workspace documentation:",\n',
    )


CURRENT_ENTRY_TEST_SOURCE = r'''# Historical V1.4.7 evidence must not override current V2.1 entry points.
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
'''


def patch_current_tests() -> None:
    replace_anchored_file(
        CURRENT_ENTRY_TEST,
        (
            '"""Current documentation must describe this source tree, not an older tranche."""',
            "def test_current_plan_agrees_with_status_and_portal",
            "def test_readme_is_generated_without_reading_existing_readme",
            "def test_missing_readme_is_rejected_without_recreating_it",
            "def test_module_index_labels_historical_coverage_baseline",
        ),
        CURRENT_ENTRY_TEST_SOURCE,
    )
    replace_exact(
        MODULE_TRUTH_TEST,
        '        self.assertEqual(19, actual["module_count"])\n',
        '        self.assertEqual(len(actual["modules"]), actual["module_count"])\n',
    )


def main() -> int:
    patch_baseline_and_wrapper()
    patch_inherited_validator()
    patch_current_tests()
    print("PASS_HEPTABAO_FROZEN_TEMPLATE_REPAIR")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
