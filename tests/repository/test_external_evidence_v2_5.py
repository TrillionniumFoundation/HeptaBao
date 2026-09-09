from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "validate_external_evidence_v2_5.py"
SPEC = importlib.util.spec_from_file_location("validate_external_evidence_v2_5", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

COMMIT = "1" * 40
TREE = "2" * 40
NOW = dt.datetime(2026, 9, 9, 12, 30, tzinfo=dt.timezone.utc)
CREATED = "2026-09-09T12:00:00Z"
EXPIRES = "2026-10-09T12:00:00Z"
ARTIFACT_A = "a" * 64
ARTIFACT_B = "b" * 64
SIGNATURE = base64.b64encode(b"s" * 64).decode("ascii")


def valid_document(gate_id: str = "HB-BLK-EXT-005") -> dict:
    document = {
        "schema_id": validator.SCHEMA_ID,
        "gate_id": gate_id,
        "subject": {
            "repository": "TrillionniumFoundation/HeptaBao",
            "commit": COMMIT,
            "tree": TREE,
            "profile": "openbao-2.6.2-complete-surface-v1",
        },
        "issuer": {
            "actor_id": "oracle-issuer-01",
            "role": "oracle-custodian",
            "organization": "independent-oracle-lab",
            "public_key_id": "oracle-issuer-key-01",
        },
        "separation": {
            "source_author_ids": ["source-author-01", "source-author-02"],
            "implementation_control_root": "control-root-implementation",
            "evidence_control_root": "control-root-evidence",
            "runner_control_root": "control-root-runner",
            "signing_control_root": "control-root-signing",
        },
        "artifacts": [
            {
                "path": "oracle/openbao-observations.json",
                "sha256": ARTIFACT_A,
                "bytes": 1024,
                "media_type": "application/json",
            },
            {
                "path": "candidate/heptabao-observations.json",
                "sha256": ARTIFACT_B,
                "bytes": 2048,
                "media_type": "application/json",
            },
        ],
        "cases": [
            {
                "id": case_id,
                "status": "PASS",
                "artifact_sha256": ARTIFACT_A if index % 2 == 0 else ARTIFACT_B,
                "observed_at": CREATED,
            }
            for index, case_id in enumerate(sorted(validator.REQUIRED_CASES[gate_id]))
        ],
        "signatures": [],
        "created_at": CREATED,
        "expires_at": EXPIRES,
        "authority_effect": "NONE",
        "claims": {
            "qualification": False,
            "compatibility_claim": False,
            "production_authority": False,
            "migration_authority": False,
            "release_authority": False,
        },
    }
    digest = hashlib.sha256(validator._canonical_payload(document)).hexdigest()
    document["signatures"] = [
        {
            "signer_actor_id": "oracle-signer-02",
            "role": "oracle-custodian",
            "public_key_id": "oracle-signer-key-02",
            "signed_at": "2026-09-09T12:10:00Z",
            "algorithm": "ed25519",
            "signature": SIGNATURE,
            "payload_sha256": digest,
        },
        {
            "signer_actor_id": "compat-signer-03",
            "role": "compatibility-reviewer",
            "public_key_id": "compat-signer-key-03",
            "signed_at": "2026-09-09T12:15:00Z",
            "algorithm": "ecdsa-p256-sha256",
            "signature": SIGNATURE,
            "payload_sha256": digest,
        },
    ]
    return document


def admit(document: dict):
    return validator.validate_document(
        document,
        expected_repository="TrillionniumFoundation/HeptaBao",
        expected_commit=COMMIT,
        expected_tree=TREE,
        expected_gate=document["gate_id"],
        now=NOW,
    )


class ExternalEvidenceV25Tests(unittest.TestCase):
    def assert_rejected(self, document: dict, message: str) -> None:
        with self.assertRaisesRegex(validator.EvidenceError, message):
            admit(document)

    def test_complete_role_separated_evidence_is_admissible_but_not_authority(self) -> None:
        result = admit(valid_document())
        self.assertEqual(result.gate_id, "HB-BLK-EXT-005")
        self.assertEqual(result.case_count, 6)
        self.assertEqual(result.signer_count, 2)

    def test_source_author_cannot_issue_evidence(self) -> None:
        document = valid_document()
        document["issuer"]["actor_id"] = "source-author-01"
        self.assert_rejected(document, "issuer is a source author")

    def test_source_author_cannot_sign_evidence(self) -> None:
        document = valid_document()
        document["signatures"][0]["signer_actor_id"] = "source-author-02"
        self.assert_rejected(document, "signature is not role-separated")

    def test_issuer_cannot_countersign_own_evidence(self) -> None:
        document = valid_document()
        document["signatures"][0]["signer_actor_id"] = document["issuer"]["actor_id"]
        self.assert_rejected(document, "signature is not role-separated")

    def test_failed_or_unknown_case_is_rejected(self) -> None:
        for status in ("FAIL", "UNKNOWN"):
            document = valid_document()
            document["cases"][0]["status"] = status
            self.assert_rejected(document, "every required case must be PASS")

    def test_missing_denominator_case_is_rejected(self) -> None:
        document = valid_document()
        document["cases"].pop()
        self.assert_rejected(document, "case denominator mismatch")

    def test_extra_denominator_case_is_rejected(self) -> None:
        document = valid_document()
        extra = copy.deepcopy(document["cases"][0])
        extra["id"] = "repository-invented-extra"
        document["cases"].append(extra)
        self.assert_rejected(document, "case denominator mismatch")

    def test_unbound_artifact_reference_is_rejected(self) -> None:
        document = valid_document()
        document["cases"][0]["artifact_sha256"] = "c" * 64
        self.assert_rejected(document, "unbound artifact")

    def test_wrong_exact_source_binding_is_rejected(self) -> None:
        document = valid_document()
        with self.assertRaisesRegex(validator.EvidenceError, "commit binding mismatch"):
            validator.validate_document(
                document,
                expected_repository="TrillionniumFoundation/HeptaBao",
                expected_commit="3" * 40,
                expected_tree=TREE,
                expected_gate=document["gate_id"],
                now=NOW,
            )

    def test_duplicate_signer_or_key_is_rejected(self) -> None:
        document = valid_document()
        document["signatures"][1]["signer_actor_id"] = document["signatures"][0]["signer_actor_id"]
        self.assert_rejected(document, "signers and signing keys must be unique")
        document = valid_document()
        document["signatures"][1]["public_key_id"] = document["signatures"][0]["public_key_id"]
        self.assert_rejected(document, "signers and signing keys must be unique")

    def test_signature_payload_digest_must_bind_unsigned_payload(self) -> None:
        document = valid_document()
        document["artifacts"][0]["bytes"] += 1
        self.assert_rejected(document, "signature payload digest mismatch")

    def test_authority_and_qualification_cannot_be_self_asserted(self) -> None:
        for name in document_claim_names():
            document = valid_document()
            document["claims"][name] = True
            self.assert_rejected(document, "cannot self-assert")
        document = valid_document()
        document["authority_effect"] = "GRANT"
        self.assert_rejected(document, "cannot grant authority")

    def test_control_roots_must_be_distinct(self) -> None:
        document = valid_document()
        document["separation"]["runner_control_root"] = document["separation"]["evidence_control_root"]
        self.assert_rejected(document, "roots must be distinct")

    def test_expired_or_excessively_long_evidence_is_rejected(self) -> None:
        document = valid_document()
        document["expires_at"] = "2026-09-09T12:20:00Z"
        self.assert_rejected(document, "not currently valid")
        document = valid_document()
        document["expires_at"] = "2027-09-09T12:00:00Z"
        self.assert_rejected(document, "invalid evidence validity window")

    def test_unknown_keys_are_rejected(self) -> None:
        document = valid_document()
        document["repository_override"] = True
        self.assert_rejected(document, "unknown keys")


def document_claim_names() -> tuple[str, ...]:
    return (
        "qualification", "compatibility_claim", "production_authority",
        "migration_authority", "release_authority",
    )


if __name__ == "__main__":
    unittest.main()
