"""A regenerated source hash must not bless stale coverage prose."""
from __future__ import annotations
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("coverage_projection", ROOT / "scripts/current_compatibility_coverage.py")
assert SPEC and SPEC.loader
COVERAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COVERAGE)

class CurrentCompatibilityCoverageTests(unittest.TestCase):
    def fixture(self, root: Path) -> None:
        corpus = root / COVERAGE.CORPUS
        corpus.parent.mkdir(parents=True)
        corpus.write_text(json.dumps({"surfaces": [
            {"surface_id": "a", "fixture_state": "IMPLEMENTED_SCOPED", "fixture_case_ids": ["a.one", "a.two"]},
            {"surface_id": "b", "fixture_state": "DEFINED_NOT_IMPLEMENTED", "fixture_case_ids": []},
        ], "coverage_summary": {"fixture_case_count": 999}}))
        guide = root / COVERAGE.GUIDE
        guide.parent.mkdir(parents=True)
        guide.write_text(COVERAGE.render(root))

    def test_current_repository_projection(self) -> None:
        self.assertEqual([], COVERAGE.validate(ROOT))

    def test_projection_uses_rows_not_summary_constants(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            self.assertIn("| Scoped fixture cases | 2 |", COVERAGE.render(root))
            self.assertNotIn("999", COVERAGE.render(root))
            self.assertEqual([], COVERAGE.validate(root))

    def test_stale_counts_and_missing_or_duplicate_projection_reject(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            guide = root / COVERAGE.GUIDE
            current = guide.read_text()
            for changed in [current.replace("cases | 2", "cases | 38"), "", current + current,
                            COVERAGE.END + "\n" + COVERAGE.BEGIN]:
                guide.write_text(changed)
                self.assertTrue(COVERAGE.validate(root))

    def test_corpus_change_requires_documentation_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            path = root / COVERAGE.CORPUS
            corpus = json.loads(path.read_text())
            corpus["surfaces"][1].update(fixture_state="IMPLEMENTED_SCOPED", fixture_case_ids=["b.one"])
            path.write_text(json.dumps(corpus))
            self.assertTrue(COVERAGE.validate(root))
            (root / COVERAGE.GUIDE).write_text(COVERAGE.render(root))
            self.assertEqual([], COVERAGE.validate(root))

    def test_duplicate_surface_or_case_and_unknown_state_reject(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            path = root / COVERAGE.CORPUS
            original = path.read_text()
            for field, value in [("surface_id", "a"), ("fixture_case_ids", ["a.one"]),
                                 ("fixture_state", "COMPLETE")]:
                corpus = json.loads(original)
                corpus["surfaces"][1][field] = value
                path.write_text(json.dumps(corpus))
                self.assertTrue(COVERAGE.validate(root))

if __name__ == "__main__":
    unittest.main()
