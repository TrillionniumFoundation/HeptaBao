#!/usr/bin/env python3
"""Repair V1.4.7 regressions that were frozen to the pre-expansion workspace.

The V1.4.7 renderer derives module truth from the exact Cargo workspace. The
source tests still hard-coded the historical 19-crate snapshot and an index
label that the same frozen renderer no longer emits. Apply only the two exact
source-anchored replacements and fail closed on any drift.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PATCHES = {
    Path("tests/plan/test_current_entry_v1_4_7.py"): (
        '''    def test_module_index_labels_historical_coverage_baseline(self) -> None:\n        module_index = (ROOT / "docs/modules/README.md").read_text(encoding="utf-8")\n        self.assertIn("V1.4.4 documentation-coverage baseline:", module_index)\n        self.assertNotIn("\\nSource baseline:", module_index)\n        current_truth = section(module_index, "V1.4.7 machine-verified module truth")\n        self.assertIn("planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml", current_truth)\n        truth = yaml.safe_load((ROOT / "planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml").read_text())\n        self.assertEqual(19, truth["module_count"])\n''',
        '''    def test_module_index_labels_current_workspace_truth(self) -> None:\n        module_index = (ROOT / "docs/modules/README.md").read_text(encoding="utf-8")\n        self.assertNotIn("V1.4.4 documentation-coverage baseline:", module_index)\n        self.assertNotIn("\\nSource baseline:", module_index)\n        current_truth = section(module_index, "V1.4.7 machine-verified module truth")\n        self.assertIn("planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml", current_truth)\n        truth = yaml.safe_load((ROOT / "planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml").read_text())\n        self.assertIn(\n            f"All `{truth['module_count']}` Cargo workspace crates",\n            current_truth,\n        )\n        self.assertEqual(len(truth["modules"]), truth["module_count"])\n''',
    ),
    Path("tests/plan/test_module_source_truth_v1_4_7.py"): (
        '''        self.assertEqual(19, actual["module_count"])\n''',
        '''        self.assertEqual(len(actual["modules"]), actual["module_count"])\n''',
    ),
}


def main() -> int:
    for relative, (old, new) in PATCHES.items():
        path = ROOT / relative
        text = path.read_text(encoding="utf-8")
        count = text.count(old)
        if count != 1:
            raise SystemExit(
                f"source anchor drift for {relative}: expected one match, found {count}"
            )
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
        print(f"PATCHED {relative}")
    print("PASS_HEPTABAO_CURRENT_TRUTH_TEST_PATCHES")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
