from __future__ import annotations

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
REGISTER = ROOT / "planning" / "HEPTABAO_EXTERNAL_EVIDENCE_ADMISSION_REGISTER_V2_5.yaml"


class ExternalEvidenceRegisterV25Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = yaml.safe_load(REGISTER.read_text(encoding="utf-8"))

    def test_mechanism_is_review_required_and_non_authoritative(self) -> None:
        self.assertEqual(
            self.document["status"], "IMPLEMENTED_REVIEW_REQUIRED"
        )
        self.assertEqual(self.document["authority_effect"], "NONE")
        for key in (
            "qualification",
            "compatibility_claim",
            "migration_authority",
            "release_authority",
            "production_authority",
        ):
            self.assertIs(self.document[key], False)
        mechanism = self.document["repository_mechanism"]
        self.assertEqual(
            mechanism["state"], "IMPLEMENTED_REVIEW_REQUIRED"
        )
        self.assertEqual(
            mechanism["admission_result"],
            "ADMISSIBLE_EVIDENCE_NOT_AUTHORITY",
        )

    def test_all_control_and_external_gates_remain_open(self) -> None:
        gates = self.document["admission_gates"]
        self.assertEqual(
            {item["id"] for item in gates},
            {
                "HB-BLK-CTRL-001",
                "HB-BLK-EXT-001",
                "HB-BLK-EXT-002",
                "HB-BLK-EXT-003",
                "HB-BLK-EXT-004",
                "HB-BLK-EXT-005",
                "HB-BLK-EXT-006",
                "HB-BLK-EXT-007",
            },
        )
        for gate in gates:
            self.assertEqual(
                gate["state"], "OPEN_EXTERNAL_EVIDENCE_REQUIRED"
            )
            self.assertGreaterEqual(len(gate["evidence_denominator"]), 5)
            self.assertEqual(
                len(gate["evidence_denominator"]),
                len(set(gate["evidence_denominator"])),
            )

    def test_register_points_to_real_normative_assets(self) -> None:
        mechanism = self.document["repository_mechanism"]
        for key in (
            "entrypoint",
            "validation_core",
            "io_boundary",
            "crypto_boundary",
            "evidence_schema",
            "trust_store_schema",
        ):
            self.assertTrue((ROOT / mechanism[key]).is_file(), mechanism[key])
        for path in mechanism["tests"]:
            self.assertTrue((ROOT / path).is_file(), path)


if __name__ == "__main__":
    unittest.main()
