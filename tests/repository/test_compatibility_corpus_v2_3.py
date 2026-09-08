"""Hostile regressions for the exact OpenBao compatibility denominator."""
from __future__ import annotations

import ast
import copy
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "scripts" / "validate_compatibility_corpus.py"
SPEC = importlib.util.spec_from_file_location("validate_compatibility_corpus", VALIDATOR_PATH)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)

REPOSITORY_SPEC = importlib.util.spec_from_file_location(
    "validate_repository_v2", ROOT / "scripts" / "validate_repository_v2.py"
)
assert REPOSITORY_SPEC and REPOSITORY_SPEC.loader
REPOSITORY_VALIDATOR = importlib.util.module_from_spec(REPOSITORY_SPEC)
REPOSITORY_SPEC.loader.exec_module(REPOSITORY_VALIDATOR)

CORPUS_PATH = ROOT / "qa" / "openbao-acceptance" / "complete_surface_corpus_v1.json"
INVENTORY_PATH = ROOT / "oracle" / "inventory" / "openbao-v2.6.2" / "surface-catalog.yaml"
ACCEPTANCE_PATH = ROOT / "qa" / "openbao-acceptance" / "acceptance.py"
SOURCE_PATH = ROOT / "crates" / "heptabao-compatibility" / "src" / "lib.rs"


def load_corpus() -> dict:
    value = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def acceptance_case_ids() -> set[str]:
    module = ast.parse(ACCEPTANCE_PATH.read_text(encoding="utf-8"))
    assignment = next(
        node
        for node in module.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "CASES" for target in node.targets)
    )
    cases = ast.literal_eval(assignment.value)
    return {f"{group}.{case}" for group, names in cases.items() for case in names}


class CompatibilityCorpusV23Tests(unittest.TestCase):
    def test_current_exact_denominator_passes(self) -> None:
        self.assertEqual([], VALIDATOR.validate(ROOT))
        self.assertEqual([], REPOSITORY_VALIDATOR.validate_compatibility_corpus())

    def test_inventory_and_case_mapping_are_closed_world(self) -> None:
        corpus = load_corpus()
        surfaces = corpus["surfaces"]
        self.assertEqual(60, len(surfaces))
        self.assertEqual(60, len({entry["surface_id"] for entry in surfaces}))
        mapped = {
            case
            for entry in surfaces
            for case in entry.get("fixture_case_ids", [])
        }
        self.assertEqual(acceptance_case_ids(), mapped)
        self.assertEqual(38, len(mapped))
        self.assertEqual(
            0,
            corpus["coverage_summary"][
                "independently_observed_current_exact_head_surface_count"
            ],
        )

    def _validate_mutation(self, mutate) -> list[str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "qa/openbao-acceptance").mkdir(parents=True)
            (root / "oracle/inventory/openbao-v2.6.2").mkdir(parents=True)
            shutil.copy2(ACCEPTANCE_PATH, root / "qa/openbao-acceptance/acceptance.py")
            shutil.copy2(
                INVENTORY_PATH,
                root / "oracle/inventory/openbao-v2.6.2/surface-catalog.yaml",
            )
            corpus = copy.deepcopy(load_corpus())
            mutate(corpus)
            (root / "qa/openbao-acceptance/complete_surface_corpus_v1.json").write_text(
                json.dumps(corpus, indent=2, sort_keys=False) + "\n",
                encoding="utf-8",
            )
            return VALIDATOR.validate(root)

    def test_duplicate_surface_and_case_rebinding_fail_closed(self) -> None:
        def mutate(corpus: dict) -> None:
            duplicate = copy.deepcopy(corpus["surfaces"][0])
            duplicate["fixture_case_ids"] = ["kv.mount"]
            duplicate["fixture_state"] = "IMPLEMENTED_SCOPED"
            duplicate["minimum_observations"] = 1
            corpus["surfaces"].append(duplicate)

        errors = self._validate_mutation(mutate)
        self.assertTrue(any("duplicates surface" in error for error in errors), errors)
        self.assertTrue(any("mapped to multiple surfaces" in error for error in errors), errors)

    def test_inventory_digest_and_false_claims_cannot_be_forged(self) -> None:
        def mutate(corpus: dict) -> None:
            corpus["inventory"]["sha256"] = "00" * 32
            corpus["claims"]["compatibility_claim"] = True
            corpus["claims"]["authority_effect"] = "PRODUCTION"

        errors = self._validate_mutation(mutate)
        self.assertTrue(any("inventory SHA-256" in error for error in errors), errors)
        self.assertTrue(any("compatibility_claim=False" in error for error in errors), errors)
        self.assertTrue(any("authority_effect='NONE'" in error for error in errors), errors)

    def test_missing_fixture_and_self_issued_independent_observation_fail_closed(self) -> None:
        def mutate(corpus: dict) -> None:
            entry = next(
                item
                for item in corpus["surfaces"]
                if item["fixture_state"] == "IMPLEMENTED_SCOPED"
            )
            entry["fixture_case_ids"] = []
            entry["minimum_observations"] = 1
            entry["independent_observation_state"] = "PASSED"

        errors = self._validate_mutation(mutate)
        self.assertTrue(any("implemented without an executable case" in error for error in errors), errors)
        self.assertTrue(any("must remain EXTERNAL_REQUIRED" in error for error in errors), errors)

    def test_compatibility_core_requires_exact_independent_binding(self) -> None:
        source = SOURCE_PATH.read_text(encoding="utf-8")
        for marker in (
            "pub struct SurfaceCatalog",
            "pub struct EvidenceBinding",
            "pub struct CoverageReport",
            "IndependentEvidenceRequired",
            "InventoryBindingMismatch",
            "IncompleteCoverage",
            "UnknownSurface",
        ):
            self.assertIn(marker, source)
        self.assertIn("self.catalog.inventory_sha256", source)
        self.assertIn("evidence.origin != EvidenceOrigin::Independent", source)


if __name__ == "__main__":
    unittest.main()
