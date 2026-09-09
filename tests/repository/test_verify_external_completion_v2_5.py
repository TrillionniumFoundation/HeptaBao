from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "verify_external_completion_v2_5.py"
SPEC = importlib.util.spec_from_file_location("verify_external_completion_v2_5", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


def _encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _public_key(seed: bytes) -> bytes:
    expanded = hashlib.sha512(seed).digest()
    scalar_bytes = bytearray(expanded[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    return _encode_point(verifier._scalar_mul(scalar, verifier._BASE))


def _sign(seed: bytes, message: bytes) -> bytes:
    expanded = hashlib.sha512(seed).digest()
    scalar_bytes = bytearray(expanded[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    prefix = expanded[32:]
    public_key = _encode_point(verifier._scalar_mul(scalar, verifier._BASE))
    nonce = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % verifier._L
    encoded_r = _encode_point(verifier._scalar_mul(nonce, verifier._BASE))
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(), "little"
    ) % verifier._L
    s = (nonce + challenge * scalar) % verifier._L
    return encoded_r + s.to_bytes(32, "little")


class CompletionFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.artifact_root = root / "artifacts"
        self.artifact_root.mkdir()
        self.evidence_path = root / "evidence.json"
        self.trust_path = root / "trust.json"
        self.repository = "TrillionniumFoundation/HeptaBao"
        self.commit = "1" * 40
        self.tree = "2" * 40
        self.profile = "HB-OPENBAO-REPLACEMENT-V2.5"
        self.signers: list[tuple[str, str, str, bytes]] = []
        index = 1
        for gate_id, roles in verifier._REQUIRED_ROLE_COUNTS.items():
            for role, count in roles.items():
                for ordinal in range(count):
                    seed = hashlib.sha256(f"{gate_id}:{role}:{ordinal}".encode()).digest()
                    self.signers.append(
                        (f"key-{index}", f"actor-{index}", role, seed)
                    )
                    index += 1

    def build(self) -> tuple[dict[str, object], dict[str, object], str]:
        artifacts: list[dict[str, object]] = []
        gates: list[dict[str, object]] = []
        for gate_id, required_cases in verifier._REQUIRED_CASES.items():
            cases: list[dict[str, object]] = []
            for case_id in sorted(required_cases):
                relative = f"{gate_id}/{case_id}.txt"
                path = self.artifact_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                payload = f"evidence:{gate_id}:{case_id}\n".encode()
                path.write_bytes(payload)
                artifacts.append(
                    {
                        "path": relative,
                        "bytes": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                )
                cases.append({"id": case_id, "result": "PASS", "artifacts": [relative]})
            gates.append({"id": gate_id, "cases": cases, "signatures": []})
        evidence: dict[str, object] = {
            "schema": verifier.SCHEMA,
            "repository": self.repository,
            "commit": self.commit,
            "tree": self.tree,
            "profile": self.profile,
            "issued_at": "2026-09-09T04:00:00Z",
            "artifacts": artifacts,
            "gates": gates,
        }
        trust: dict[str, object] = {
            "schema": verifier.TRUST_SCHEMA,
            "generated_at": "2026-09-09T03:00:00Z",
            "keys": [
                {
                    "key_id": key_id,
                    "actor": actor,
                    "role": role,
                    "public_key_hex": _public_key(seed).hex(),
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_through": "2027-01-01T00:00:00Z",
                    "revoked": False,
                }
                for key_id, actor, role, seed in self.signers
            ],
        }
        unsigned = verifier._unsigned_evidence(evidence)
        signer_iter = iter(self.signers)
        for gate in evidence["gates"]:  # type: ignore[index]
            gate_id = gate["id"]  # type: ignore[index]
            signatures = []
            for role, count in verifier._REQUIRED_ROLE_COUNTS[gate_id].items():
                for _ in range(count):
                    key_id, actor, observed_role, seed = next(signer_iter)
                    assert observed_role == role
                    message = verifier._canonical(
                        {
                            "evidence": unsigned,
                            "gate_id": gate_id,
                            "key_id": key_id,
                            "actor": actor,
                            "role": role,
                        }
                    )
                    signatures.append(
                        {
                            "key_id": key_id,
                            "actor": actor,
                            "role": role,
                            "signature_hex": _sign(seed, message).hex(),
                        }
                    )
            gate["signatures"] = signatures  # type: ignore[index]
        trust_bytes = json.dumps(
            trust, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        self.trust_path.write_bytes(trust_bytes)
        self.evidence_path.write_text(
            json.dumps(evidence, sort_keys=True, separators=(",", ":")), encoding="utf-8"
        )
        return evidence, trust, hashlib.sha256(trust_bytes).hexdigest()

    def verify(self, trust_digest: str) -> dict[str, object]:
        return verifier.verify(
            evidence_path=self.evidence_path,
            trust_store_path=self.trust_path,
            artifact_root=self.artifact_root,
            expected_repository=self.repository,
            expected_commit=self.commit,
            expected_tree=self.tree,
            expected_profile=self.profile,
            expected_trust_store_sha256=trust_digest,
        )


class ExternalCompletionVerifierTests(unittest.TestCase):
    def test_rfc8032_empty_message_vector(self) -> None:
        public_key = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        signature = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        self.assertTrue(verifier.verify_ed25519(public_key, b"", signature))
        changed = bytearray(signature)
        changed[0] ^= 1
        self.assertFalse(verifier.verify_ed25519(public_key, b"", bytes(changed)))

    def test_rejects_noncanonical_scalar(self) -> None:
        public_key = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        signature = bytes(32) + verifier._L.to_bytes(32, "little")
        self.assertFalse(verifier.verify_ed25519(public_key, b"", signature))

    def test_complete_fixture_is_admitted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CompletionFixture(Path(directory))
            _evidence, _trust, digest = fixture.build()
            result = fixture.verify(digest)
            self.assertTrue(result["admitted"])
            self.assertEqual(result["gate_count"], 8)
            self.assertEqual(result["authority_effect"], "NONE_UNTIL_SEPARATE_GRANT")

    def test_missing_denominator_case_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CompletionFixture(Path(directory))
            evidence, _trust, digest = fixture.build()
            evidence["gates"][0]["cases"].pop()  # type: ignore[index]
            fixture.evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            with self.assertRaisesRegex(verifier.EvidenceError, "denominator mismatch"):
                fixture.verify(digest)

    def test_artifact_tampering_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CompletionFixture(Path(directory))
            evidence, _trust, digest = fixture.build()
            relative = evidence["artifacts"][0]["path"]  # type: ignore[index]
            (fixture.artifact_root / relative).write_text("tampered", encoding="utf-8")
            with self.assertRaisesRegex(verifier.EvidenceError, "size mismatch|digest mismatch"):
                fixture.verify(digest)

    def test_trust_store_pin_is_mandatory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CompletionFixture(Path(directory))
            fixture.build()
            with self.assertRaisesRegex(verifier.EvidenceError, "out-of-band pin"):
                fixture.verify("0" * 64)

    def test_revoked_key_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CompletionFixture(Path(directory))
            _evidence, trust, _digest = fixture.build()
            trust["keys"][0]["revoked"] = True  # type: ignore[index]
            trust_bytes = json.dumps(
                trust, sort_keys=True, separators=(",", ":")
            ).encode()
            fixture.trust_path.write_bytes(trust_bytes)
            digest = hashlib.sha256(trust_bytes).hexdigest()
            with self.assertRaisesRegex(verifier.EvidenceError, "revoked signing key"):
                fixture.verify(digest)

    def test_duplicate_json_members_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schema":"one","schema":"two"}', encoding="utf-8")
            with self.assertRaisesRegex(verifier.EvidenceError, "duplicate JSON member"):
                verifier._read_regular_json(path)

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links are unavailable")
    def test_symlink_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = CompletionFixture(Path(directory))
            evidence, _trust, digest = fixture.build()
            relative = Path(evidence["artifacts"][0]["path"])  # type: ignore[index]
            target = fixture.artifact_root / relative
            replacement = target.with_suffix(".real")
            target.rename(replacement)
            target.symlink_to(replacement.name)
            with self.assertRaisesRegex(verifier.EvidenceError, "non-symlink"):
                fixture.verify(digest)


if __name__ == "__main__":
    unittest.main()
