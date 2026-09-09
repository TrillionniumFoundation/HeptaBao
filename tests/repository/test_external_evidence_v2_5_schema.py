from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas" / "heptabao-external-evidence-v2.5.schema.json"
VALIDATOR = ROOT / "scripts" / "validate_external_evidence_v2_5.py"
DOC = ROOT / "docs" / "plan" / "HEPTABAO_EXTERNAL_EVIDENCE_ADMISSION_V2_5.md"


class ExternalEvidenceSchemaBindingTests(unittest.TestCase):
    def test_schema_is_closed_and_non_authoritative(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["authority_effect"]["const"], "NONE")
        claims = schema["properties"]["claims"]["properties"]
        self.assertEqual(
            set(claims),
            {
                "qualification",
                "compatibility_claim",
                "production_authority",
                "migration_authority",
                "release_authority",
            },
        )
        self.assertTrue(all(item["const"] is False for item in claims.values()))

    def test_schema_and_validator_have_identical_gate_denominator(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        schema_gates = set(schema["properties"]["gate_id"]["enum"])
        source = VALIDATOR.read_text(encoding="utf-8")
        for gate in schema_gates:
            self.assertIn(f'"{gate}"', source)
        self.assertEqual(len(schema_gates), 8)

    def test_documentation_names_all_executable_assets(self) -> None:
        text = DOC.read_text(encoding="utf-8")
        for path in (SCHEMA, VALIDATOR):
            self.assertIn(str(path.relative_to(ROOT)), text)
        for gate in (
            "HB-BLK-CTRL-001",
            "HB-BLK-EXT-001",
            "HB-BLK-EXT-002",
            "HB-BLK-EXT-003",
            "HB-BLK-EXT-004",
            "HB-BLK-EXT-005",
            "HB-BLK-EXT-006",
            "HB-BLK-EXT-007",
        ):
            self.assertIn(gate, text)


if __name__ == "__main__":
    unittest.main()
