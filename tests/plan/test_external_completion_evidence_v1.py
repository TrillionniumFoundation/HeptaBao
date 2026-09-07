from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "external_validator", ROOT / "scripts/validate_external_completion_evidence_v1.py"
)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)
DIGEST = "sha256:" + "a" * 64
EXPECTED = {
    "commit": "1" * 40,
    "tree": "2" * 40,
    "merge_commit": "3" * 40,
    "merge_tree": "4" * 40,
}


def accepted_ext007() -> dict:
    return {
        "schema": "heptabao.external-completion-evidence.v1",
        "blocker_id": "HB-BLK-EXT-007",
        "state": "ACCEPTED",
        "repository": {"id": 1349115072, "full_name": "TrillionniumFoundation/HeptaBao"},
        "source": {**EXPECTED, "plan_digest": DIGEST, "manifest_digest": DIGEST},
        "scope": ["exact head and prospective merge full reproduction"],
        "actors": [
            {"stable_id": "operator-001", "role": "independent_reproduction_operator", "organization": "Lab A", "independent": True, "conflicts": []},
            {"stable_id": "reviewer-002", "role": "independent_reproduction_reviewer", "organization": "Lab B", "independent": True, "conflicts": []},
        ],
        "separation": {
            "credential_root": "credential-root-a",
            "runner_admin": "runner-admin-a",
            "cache_admin": "cache-admin-a",
            "artifact_custody": "custody-a",
            "signing_root": "signing-root-a",
            "network_egress": "egress-a",
        },
        "checks": [{"case_id": "full-matrix", "status": "PASS", "evidence_digest": DIGEST}],
        "artifacts": [{"name": "raw execution bundle", "digest": DIGEST, "custody_uri": "urn:lab-a:bundle:1", "classification": "RESTRICTED_REFERENCE"}],
        "findings": [],
        "signatures": [
            {"signer_id": "operator-001", "role": "operator", "key_id": "key-operator-001", "algorithm": "test-ed25519-profile", "signed_at": "2026-09-01T00:00:00Z", "expires_at": "2027-09-01T00:00:00Z", "signature": "a" * 64, "verification": "VALID"},
            {"signer_id": "reviewer-002", "role": "reviewer", "key_id": "key-reviewer-002", "algorithm": "test-ed25519-profile", "signed_at": "2026-09-01T00:00:00Z", "expires_at": "2027-09-01T00:00:00Z", "signature": "b" * 64, "verification": "VALID"},
        ],
        "claims": {
            "qualification": False,
            "compatibility_claim": False,
            "selected_candidates": [],
            "selection_effect": "NONE",
            "production_authority": False,
            "migration_authority": False,
            "release_authority": False,
            "authority_effect": "NONE",
        },
    }


class ExternalCompletionEvidenceTests(unittest.TestCase):
    def validate(self, value: dict) -> None:
        VALIDATOR.validate_envelope(
            value,
            require_closure=True,
            expected_source=EXPECTED,
            now=datetime(2026, 9, 2, tzinfo=timezone.utc),
        )

    def test_bounded_valid_closure_envelope_passes(self) -> None:
        self.validate(accepted_ext007())

    def test_templates_are_schema_shaped_but_not_closure(self) -> None:
        for path in sorted((ROOT / "qualifications/external/templates").glob("*.json")):
            value = json.loads(path.read_text(encoding="utf-8"))
            VALIDATOR.validate_envelope(value, require_closure=False)
            with self.assertRaises(ValueError):
                self.validate(value)

    def test_non_pass_case_fails_closed(self) -> None:
        value = accepted_ext007()
        value["checks"][0]["status"] = "UNKNOWN"
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_shared_actor_identity_fails_closed(self) -> None:
        value = accepted_ext007()
        value["actors"][1]["stable_id"] = value["actors"][0]["stable_id"]
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_source_drift_fails_closed(self) -> None:
        value = accepted_ext007()
        value["source"]["tree"] = "f" * 40
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_expired_or_revoked_signature_fails_closed(self) -> None:
        for field, replacement in (("expires_at", "2026-09-01T00:00:00Z"), ("verification", "REVOKED")):
            value = accepted_ext007()
            value["signatures"][0][field] = replacement
            with self.assertRaises(ValueError):
                self.validate(value)

    def test_authority_elevation_fails_closed(self) -> None:
        value = accepted_ext007()
        value["claims"]["production_authority"] = True
        with self.assertRaises(ValueError):
            self.validate(value)


if __name__ == "__main__":
    unittest.main()
