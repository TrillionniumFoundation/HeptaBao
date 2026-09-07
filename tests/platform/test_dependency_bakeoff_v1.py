from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

SPEC = importlib.util.spec_from_file_location(
    "validate_dependency_bakeoff_v1",
    SCRIPTS / "validate_dependency_bakeoff_v1.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DependencyBakeoffValidationTests(unittest.TestCase):
    def test_seed_catalog_is_complete_but_unselected(self):
        candidate_count, capability_count = MODULE.validate()
        self.assertEqual(candidate_count, 25)
        self.assertEqual(capability_count, 16)

    def test_main_returns_success_for_the_checked_in_seed(self):
        self.assertEqual(MODULE.main(), 0)

    def test_selected_candidate_requires_non_null_scores(self):
        catalog = yaml.safe_load(
            (ROOT / "planning" / "HEPTABAO_H02_DEPENDENCY_BAKEOFF_V1.yaml").read_text(
                encoding="utf-8"
            )
        )
        schema = json.loads(
            (ROOT / "schemas" / "heptabao_dependency_candidate_v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        candidate = copy.deepcopy(catalog["candidates"][0])
        candidate["state"] = "SELECTED_FOR_PROTOTYPE"
        candidate["project"]["license_status"] = "ACCEPTABLE"
        candidate["pin"] = {
            "version": "synthetic-v1",
            "commit_sha": "1" * 40,
            "source_digest_sha256": "2" * 64,
        }
        for field, value in candidate["evidence"].items():
            if isinstance(value, bool):
                candidate["evidence"][field] = True
        candidate["evidence"]["critical_findings_open"] = 0
        candidate["evidence"]["high_findings_open"] = 0
        candidate["evidence"]["unclassified_findings"] = 0
        candidate["evidence"]["evidence_refs"] = ["synthetic://evidence"]
        candidate["qualification"]["selection_receipt"] = "HB-DSR-SYNTHETIC01"

        errors = list(Draft202012Validator(schema).iter_errors(candidate))
        self.assertTrue(errors, "selected candidate with null score criteria must be rejected")

    def test_fully_scored_synthetic_selection_is_structurally_valid(self):
        catalog = yaml.safe_load(
            (ROOT / "planning" / "HEPTABAO_H02_DEPENDENCY_BAKEOFF_V1.yaml").read_text(
                encoding="utf-8"
            )
        )
        schema = json.loads(
            (ROOT / "schemas" / "heptabao_dependency_candidate_v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        candidate = copy.deepcopy(catalog["candidates"][0])
        candidate["state"] = "SELECTED_FOR_PROTOTYPE"
        candidate["project"]["license_status"] = "ACCEPTABLE"
        candidate["pin"] = {
            "version": "synthetic-v1",
            "commit_sha": "1" * 40,
            "source_digest_sha256": "2" * 64,
        }
        for field in candidate["criteria"]:
            candidate["criteria"][field] = 4
        for field, value in candidate["evidence"].items():
            if isinstance(value, bool):
                candidate["evidence"][field] = True
        candidate["evidence"]["critical_findings_open"] = 0
        candidate["evidence"]["high_findings_open"] = 0
        candidate["evidence"]["unclassified_findings"] = 0
        candidate["evidence"]["evidence_refs"] = ["synthetic://evidence"]
        candidate["qualification"]["selection_receipt"] = "HB-DSR-SYNTHETIC01"

        errors = list(Draft202012Validator(schema).iter_errors(candidate))
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
