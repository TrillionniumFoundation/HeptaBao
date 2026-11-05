from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/validate_openbao_replacement_admission.py"
SPEC = importlib.util.spec_from_file_location("replacement_admission", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def contract(status: str = "OPEN", authority: bool = False, overall: str = "NOT_ADMITTED") -> dict:
    return {
        "schema": MOD.EXPECTED_SCHEMA,
        "baseline": {
            "product": "OpenBao",
            "version": "2.6.2",
            "scope": "complete-replacement",
            "frozen": True,
        },
        "replacement_authority": authority,
        "status": overall,
        "required_gates": [
            {
                "id": "example",
                "status": status,
                "owner": "test",
                "requirement": "bounded requirement",
                "evidence": "exact evidence",
            }
        ],
    }


class ReplacementAdmissionTests(unittest.TestCase):
    def test_open_gate_is_valid_only_without_authority(self):
        self.assertEqual([], MOD.validate(contract()))

    def test_open_gate_cannot_self_grant_replacement_authority(self):
        errors = MOD.validate(contract(authority=True, overall="ADMITTED"))
        self.assertTrue(any("replacement_authority" in error for error in errors))

    def test_all_gates_require_explicit_authority_transition(self):
        errors = MOD.validate(contract(status="ADMITTED"))
        self.assertTrue(any("explicit authority transition" in error for error in errors))
        self.assertEqual([], MOD.validate(contract("ADMITTED", True, "ADMITTED")))

    def test_baseline_cannot_drift_silently(self):
        document = contract()
        document["baseline"]["version"] = "latest"
        self.assertTrue(MOD.validate(document))

    def test_workflow_evidence_must_point_to_a_current_file(self):
        document = contract()
        document["required_gates"][0]["evidence"] = (
            "receipt emitted by .github/workflows/missing.yml"
        )
        errors = MOD.validate(document)
        self.assertTrue(any("missing workflow" in error for error in errors))

        document["required_gates"][0]["evidence"] = (
            "receipt emitted by .github/workflows/codex-openbao-replacement-ci.yml"
        )
        self.assertEqual([], MOD.validate(document))


if __name__ == "__main__":
    unittest.main()
