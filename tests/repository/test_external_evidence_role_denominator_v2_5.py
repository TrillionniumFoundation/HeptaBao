from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import admit_external_evidence_v2_5 as admission
from heptabao_external_evidence_io_v2_5 import EvidenceIoError


class ExternalEvidenceRoleDenominatorV25Tests(unittest.TestCase):
    def test_required_role_sets_cover_every_gate(self) -> None:
        self.assertEqual(
            set(admission.REQUIRED_SIGNER_ROLES),
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
        self.assertEqual(
            admission.REQUIRED_SIGNER_ROLES["HB-BLK-CTRL-001"],
            {"repository-administrator", "control-auditor"},
        )
        self.assertEqual(
            admission.REQUIRED_SIGNER_ROLES["HB-BLK-EXT-004"],
            {"release-custodian", "hsm-custodian"},
        )
        self.assertEqual(
            admission.REQUIRED_SIGNER_ROLES["HB-BLK-EXT-005"],
            {"oracle-custodian", "compatibility-reviewer"},
        )

    def test_duplicate_allowed_role_cannot_replace_missing_required_role(self) -> None:
        evidence = {
            "signatures": [
                {"role": "oracle-custodian"},
                {"role": "oracle-custodian"},
            ]
        }
        with self.assertRaisesRegex(
            EvidenceIoError, "compatibility-reviewer"
        ):
            admission._require_signer_role_denominator(
                evidence, "HB-BLK-EXT-005"
            )

    def test_all_required_roles_are_accepted_at_denominator_stage(self) -> None:
        for gate, roles in admission.REQUIRED_SIGNER_ROLES.items():
            evidence = {
                "signatures": [
                    {"role": role} for role in sorted(roles)
                ]
            }
            admission._require_signer_role_denominator(evidence, gate)

    def test_absent_or_non_object_signature_is_rejected(self) -> None:
        with self.assertRaisesRegex(EvidenceIoError, "signatures are absent"):
            admission._require_signer_role_denominator(
                {}, "HB-BLK-EXT-002"
            )
        with self.assertRaisesRegex(EvidenceIoError, "not an object"):
            admission._require_signer_role_denominator(
                {"signatures": ["legal-counsel"]},
                "HB-BLK-EXT-002",
            )


if __name__ == "__main__":
    unittest.main()
