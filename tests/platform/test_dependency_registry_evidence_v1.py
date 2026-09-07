from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

SPEC = importlib.util.spec_from_file_location(
    "validate_dependency_registry_evidence_v1",
    SCRIPTS / "validate_dependency_registry_evidence_v1.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DependencyRegistryEvidenceTests(unittest.TestCase):
    def test_three_registry_checksums_are_bound_but_unexecuted(self):
        self.assertEqual(MODULE.validate(), 3)

    def test_main_returns_success_for_checked_in_evidence(self):
        self.assertEqual(MODULE.main(), 0)

    def test_unexecuted_evidence_cannot_claim_downloaded_checksum(self):
        schema = json.loads(
            (ROOT / "schemas" / "heptabao_dependency_registry_evidence_v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        evidence = MODULE.load_yaml(
            ROOT
            / "planning"
            / "evidence"
            / "h02"
            / "registry"
            / "HB-DEP-ASYNC-TOKIO.registry.yaml"
        )
        mutated = copy.deepcopy(evidence)
        mutated["byte_verification"]["crate_download_sha256"] = "1" * 64
        errors = list(Draft202012Validator(schema).iter_errors(mutated))
        self.assertTrue(errors)

    def test_selection_or_qualification_is_rejected(self):
        schema = json.loads(
            (ROOT / "schemas" / "heptabao_dependency_registry_evidence_v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        evidence = MODULE.load_yaml(
            ROOT
            / "planning"
            / "evidence"
            / "h02"
            / "registry"
            / "HB-DEP-TLS-RUSTLS.registry.yaml"
        )
        for field, value in (("selection_state", "SELECTED_FOR_PROTOTYPE"), ("qualification", True)):
            mutated = copy.deepcopy(evidence)
            mutated[field] = value
            self.assertTrue(list(Draft202012Validator(schema).iter_errors(mutated)))


if __name__ == "__main__":
    unittest.main()
