from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CURRENT_REPOSITORY = "TrillionniumFoundation/HeptaBao"
HISTORICAL_REPOSITORY = "ProfHepta/HeptaBao"


class CurrentRepositoryIdentitySchemaTests(unittest.TestCase):
    """Current evidence schemas bind the transferred repository without rewriting history."""

    SCHEMA_PATHS = (
        "schemas/heptabao_blocker_closure_receipt_v1.schema.json",
        "schemas/heptabao_dependency_probe_evidence_v1.schema.json",
        "schemas/heptabao_h02_blocker_closure_evidence_v1.schema.json",
        "schemas/heptabao_h02_openraft_cluster_evidence_v1.schema.json",
        "schemas/heptabao_h02_openraft_fault_lab_evidence_v1.schema.json",
        "schemas/heptabao_h02_seeded_behavior_evidence_v1.schema.json",
        "schemas/heptabao_pr40_reconciliation_status_v1.schema.json",
        "schemas/heptabao_qualification_receipt_v2.schema.json",
        "schemas/heptabao_release_attestation_v1.schema.json",
    )

    def test_current_schemas_bind_current_repository(self) -> None:
        for relative in self.SCHEMA_PATHS:
            with self.subTest(schema=relative):
                schema = json.loads((ROOT / relative).read_text(encoding="utf-8"))
                repository = schema
                # All schemas place the binding under one of these source locations.
                for key in ("source", "source_binding", "source_input"):
                    candidate = schema.get("properties", {}).get(key, {})
                    if candidate:
                        repository = candidate
                        break
                value = repository.get("properties", {}).get("repository", {}).get("const")
                self.assertEqual(value, CURRENT_REPOSITORY)

    def test_no_schema_accepts_historical_repository_name(self) -> None:
        for path in (ROOT / "schemas").glob("*.json"):
            with self.subTest(schema=path.name):
                self.assertNotIn(HISTORICAL_REPOSITORY, path.read_text(encoding="utf-8"))

    def test_historical_evidence_identity_is_retained_as_lineage(self) -> None:
        validator = (ROOT / "scripts/validate_repository_identity_v1.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(f'HISTORICAL_REPOSITORY = "{HISTORICAL_REPOSITORY}"', validator)
        protocol = (ROOT / "docs/execution/HEPTABAO_V1_3_1_FINAL_CLOSURE_PROTOCOL.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(f"Historical full name `{HISTORICAL_REPOSITORY}` is retained only as audit lineage", protocol)
        historical_status = (ROOT / "planning/HEPTABAO_PR40_RECONCILIATION_STATUS_V1.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn(f"repository: {HISTORICAL_REPOSITORY}", historical_status)


if __name__ == "__main__":
    unittest.main()
