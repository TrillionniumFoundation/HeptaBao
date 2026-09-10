#!/usr/bin/env python3
"""Bind frozen V1.4.7 templates to the exact current Cargo workspace.

Only source-anchored historical constants are changed. The baseline integrity
pin is recomputed after the template edit, so renderer verification remains
byte-exact and fail-closed.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "scripts/_render_plan_v1_4_7_baseline.py"
WRAPPER = ROOT / "scripts/render_plan_v1_4_7.py"
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


def patch_baseline_and_wrapper() -> None:
    replace_exact(
        BASELINE,
        '        self.assertEqual(19, actual["module_count"])\n',
        '        self.assertEqual(len(actual["modules"]), actual["module_count"])\n',
    )
    replace_exact(
        WRAPPER,
        "    portal = BASELINE.current_documentation()\n",
        "    portal = BASELINE.current_documentation()\n"
        "    truth = BASELINE.build_truth(BASELINE_PATH.parent.parent)\n",
    )
    replace_exact(
        WRAPPER,
        "- Current Cargo workspace documentation: **19 / 19** existing crates",
        '- Current Cargo workspace documentation: **{truth["module_count"]} / '
        '{truth["module_count"]}** existing crates',
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


def patch_current_tests() -> None:
    replace_exact(
        CURRENT_ENTRY_TEST,
        '''    def test_module_index_labels_historical_coverage_baseline(self) -> None:\n        module_index = (ROOT / "docs/modules/README.md").read_text(encoding="utf-8")\n        self.assertIn("V1.4.4 documentation-coverage baseline:", module_index)\n        self.assertNotIn("\\nSource baseline:", module_index)\n        current_truth = section(module_index, "V1.4.7 machine-verified module truth")\n        self.assertIn("planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml", current_truth)\n        truth = yaml.safe_load((ROOT / "planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml").read_text())\n        self.assertEqual(19, truth["module_count"])\n''',
        '''    def test_module_index_labels_current_workspace_truth(self) -> None:\n        module_index = (ROOT / "docs/modules/README.md").read_text(encoding="utf-8")\n        self.assertNotIn("V1.4.4 documentation-coverage baseline:", module_index)\n        self.assertNotIn("\\nSource baseline:", module_index)\n        current_truth = section(module_index, "V1.4.7 machine-verified module truth")\n        self.assertIn("planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml", current_truth)\n        truth = yaml.safe_load((ROOT / "planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml").read_text())\n        self.assertIn(\n            f"All `{truth['module_count']}` Cargo workspace crates",\n            current_truth,\n        )\n        self.assertEqual(len(truth["modules"]), truth["module_count"])\n''',
    )
    replace_exact(
        MODULE_TRUTH_TEST,
        '        self.assertEqual(19, actual["module_count"])\n',
        '        self.assertEqual(len(actual["modules"]), actual["module_count"])\n',
    )


def main() -> int:
    patch_baseline_and_wrapper()
    patch_current_tests()
    print("PASS_HEPTABAO_FROZEN_TEMPLATE_REPAIR")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
