from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("renderer", ROOT / "scripts/render_plan_v1_4_7.py")
assert SPEC and SPEC.loader
RENDERER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENDERER)


class ModuleSourceTruthTests(unittest.TestCase):
    def test_snapshot_matches_exact_workspace(self) -> None:
        expected = RENDERER.build_truth(ROOT)
        actual = yaml.safe_load((ROOT / RENDERER.TRUTH_PATH).read_text(encoding="utf-8"))
        self.assertEqual(expected, actual)
        self.assertEqual(19, actual["module_count"])

    def test_every_module_guide_generated_sections_are_current(self) -> None:
        truth = RENDERER.build_truth(ROOT)
        for module in truth["modules"]:
            path = ROOT / module["module_guide"]
            self.assertEqual(RENDERER.module_doc_expected(ROOT, module), path.read_text(encoding="utf-8"))

    def test_workspace_dependency_and_public_surface_are_nonempty(self) -> None:
        truth = RENDERER.build_truth(ROOT)
        self.assertTrue(any(module["internal_dependencies"] for module in truth["modules"]))
        self.assertTrue(all(module["source_files"] for module in truth["modules"]))
        self.assertTrue(any(module["public_items"] for module in truth["modules"]))
        self.assertTrue(any(module["test_functions"] for module in truth["modules"]))


if __name__ == "__main__":
    unittest.main()
