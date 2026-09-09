from __future__ import annotations

import base64
import contextlib
import datetime as dt
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import admit_external_evidence_v2_5 as admission_cli
import heptabao_external_evidence_io_v2_5 as evidence_io
from tests.repository import test_external_evidence_v2_5 as fixture

ORACLE_BYTES = b"openbao-oracle-observations-v2.5\n"
CANDIDATE_BYTES = b"heptabao-candidate-observations-v2.5\n"


def utc(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def write_json(path: Path, value: object) -> bytes:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path.write_bytes(raw)
    return raw


def signed_package(artifact_root: Path) -> tuple[dict, dict]:
    oracle = artifact_root / "oracle" / "openbao-observations.json"
    candidate = artifact_root / "candidate" / "heptabao-observations.json"
    oracle.parent.mkdir(parents=True)
    candidate.parent.mkdir(parents=True)
    oracle.write_bytes(ORACLE_BYTES)
    candidate.write_bytes(CANDIDATE_BYTES)

    now = dt.datetime.now(dt.timezone.utc)
    created = now - dt.timedelta(minutes=2)
    expires = now + dt.timedelta(days=7)
    document = fixture.valid_document()
    document["created_at"] = utc(created)
    document["expires_at"] = utc(expires)
    for case in document["cases"]:
        case["observed_at"] = utc(created)
    document["artifacts"] = [
        {
            "path": "oracle/openbao-observations.json",
            "sha256": hashlib.sha256(ORACLE_BYTES).hexdigest(),
            "bytes": len(ORACLE_BYTES),
            "media_type": "application/json",
        },
        {
            "path": "candidate/heptabao-observations.json",
            "sha256": hashlib.sha256(CANDIDATE_BYTES).hexdigest(),
            "bytes": len(CANDIDATE_BYTES),
            "media_type": "application/json",
        },
    ]
    document["signatures"] = []
    canonical = fixture.validator._canonical_payload(document)
    digest = hashlib.sha256(canonical).hexdigest()
    signed_at_a = utc(now - dt.timedelta(minutes=1))
    signed_at_b = utc(now - dt.timedelta(seconds=30))
    document["signatures"] = [
        {
            "signer_actor_id": "oracle-signer-02",
            "role": "oracle-custodian",
            "public_key_id": "oracle-signer-key-02",
            "signed_at": signed_at_a,
            "algorithm": "ed25519",
            "signature": base64.b64encode(
                fixture.sign(fixture.SIGNER_A_SEED, canonical)
            ).decode("ascii"),
            "payload_sha256": digest,
        },
        {
            "signer_actor_id": "compat-signer-03",
            "role": "compatibility-reviewer",
            "public_key_id": "compat-signer-key-03",
            "signed_at": signed_at_b,
            "algorithm": "ed25519",
            "signature": base64.b64encode(
                fixture.sign(fixture.SIGNER_B_SEED, canonical)
            ).decode("ascii"),
            "payload_sha256": digest,
        },
    ]

    trust = fixture.trust_store()
    trust_from = utc(now - dt.timedelta(days=1))
    trust_until = utc(now + dt.timedelta(days=30))
    for key in trust["keys"]:
        key["valid_from"] = trust_from
        key["valid_until"] = trust_until
    return document, trust


class EvidenceIoV25Tests(unittest.TestCase):
    def test_duplicate_json_members_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_text('{"a":1,"a":2}', encoding="utf-8")
            with self.assertRaisesRegex(evidence_io.EvidenceIoError, "duplicate JSON"):
                evidence_io.load_json_file(path)

    def test_json_symlink_is_rejected(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            link = root / "link.json"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlink creation denied")
            with self.assertRaisesRegex(evidence_io.EvidenceIoError, "non-symlink"):
                evidence_io.load_json_file(link)

    def test_bound_artifacts_are_rehashed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            document, _ = signed_package(root)
            evidence_io.verify_artifacts(document, root)
            (root / "candidate" / "heptabao-observations.json").write_bytes(
                b"tampered\n"
            )
            with self.assertRaisesRegex(
                evidence_io.EvidenceIoError, "byte count|SHA-256"
            ):
                evidence_io.verify_artifacts(document, root)

    def test_parent_symlink_and_path_escape_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            outside = Path(temporary) / "outside"
            root.mkdir()
            outside.mkdir()
            payload = outside / "payload.json"
            payload.write_bytes(b"payload")
            if hasattr(os, "symlink"):
                try:
                    (root / "linked").symlink_to(outside, target_is_directory=True)
                except OSError:
                    pass
                else:
                    evidence = {
                        "artifacts": [
                            {
                                "path": "linked/payload.json",
                                "sha256": hashlib.sha256(b"payload").hexdigest(),
                                "bytes": len(b"payload"),
                            }
                        ]
                    }
                    with self.assertRaisesRegex(
                        evidence_io.EvidenceIoError, "real directory"
                    ):
                        evidence_io.verify_artifacts(evidence, root)
            escape = {
                "artifacts": [
                    {
                        "path": "../outside/payload.json",
                        "sha256": hashlib.sha256(b"payload").hexdigest(),
                        "bytes": len(b"payload"),
                    }
                ]
            }
            with self.assertRaisesRegex(evidence_io.EvidenceIoError, "escapes"):
                evidence_io.verify_artifacts(escape, root)

    def test_end_to_end_admission_binds_trust_digest_and_artifact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact_root = root / "artifacts"
            artifact_root.mkdir()
            document, trust = signed_package(artifact_root)
            evidence_path = root / "evidence.json"
            trust_path = root / "trust.json"
            write_json(evidence_path, document)
            trust_raw = write_json(trust_path, trust)
            digest = hashlib.sha256(trust_raw).hexdigest()
            arguments = [
                "--evidence", str(evidence_path),
                "--trust-store", str(trust_path),
                "--expected-trust-store-sha256", digest,
                "--artifact-root", str(artifact_root),
                "--expected-repository", "TrillionniumFoundation/HeptaBao",
                "--expected-commit", fixture.COMMIT,
                "--expected-tree", fixture.TREE,
                "--expected-gate", "HB-BLK-EXT-005",
            ]
            with contextlib.redirect_stdout(None):
                self.assertEqual(admission_cli.main(arguments), 0)
            bad = list(arguments)
            bad[bad.index(digest)] = "0" * 64
            with contextlib.redirect_stderr(None):
                self.assertEqual(admission_cli.main(bad), 1)
            (artifact_root / "oracle" / "openbao-observations.json").write_bytes(
                b"changed"
            )
            with contextlib.redirect_stderr(None):
                self.assertEqual(admission_cli.main(arguments), 1)


if __name__ == "__main__":
    unittest.main()
