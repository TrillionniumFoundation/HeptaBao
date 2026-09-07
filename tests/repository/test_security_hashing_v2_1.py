from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
PACKAGES = ["heptabao-durable-service", "heptabao-runtime-service"]


class SecurityHashingV21Tests(unittest.TestCase):
    def test_both_runtime_packages_pin_reviewed_sha2_family(self) -> None:
        for package in PACKAGES:
            manifest = (
                ROOT / "crates" / package / "Cargo.toml"
            ).read_text(encoding="utf-8")
            self.assertIn('sha2 = "=0.10.9"', manifest, package)

    def test_digest_implementation_is_sha256_and_length_delimited(self) -> None:
        for package in PACKAGES:
            source = (
                ROOT / "crates" / package / "src" / "lib.rs"
            ).read_text(encoding="utf-8")
            self.assertIn("use sha2::{Digest, Sha256};", source, package)
            self.assertEqual(1, source.count("fn digest32("), package)
            start = source.index("fn digest32(")
            end = source.find("\n}", start) + 2
            body = source[start:end]
            for required in (
                "Sha256::new()",
                "domain_len.to_le_bytes()",
                "hasher.update(domain)",
                "bytes_len.to_le_bytes()",
                "hasher.update(bytes)",
                "hasher.finalize().into()",
            ):
                self.assertIn(required, body, package)

    def test_custom_fnv_like_digest_is_absent(self) -> None:
        forbidden = (
            "0xcbf2_9ce4_8422_2325_u64",
            "0x0000_0100_0000_01b3",
            "state ^= state.rotate_left(17)",
        )
        for package in PACKAGES:
            source = (
                ROOT / "crates" / package / "src" / "lib.rs"
            ).read_text(encoding="utf-8")
            for marker in forbidden:
                self.assertNotIn(marker, source, package)

    def test_security_docs_state_sha256_non_signature_boundary(self) -> None:
        paths = [
            ROOT / "docs/modules/heptabao-durable-service.md",
            ROOT / "docs/modules/heptabao-runtime-service.md",
            ROOT
            / "docs/architecture/HEPTABAO_V2_1_DURABLE_RUNTIME_PIPELINE.md",
            ROOT
            / "docs/architecture/HEPTABAO_V2_1_AUTHORIZED_DURABLE_PIPELINE.md",
        ]
        for path in paths:
            text = path.read_text(encoding="utf-8")
            self.assertIn("domain-separated SHA-256", text, str(path))
            self.assertRegex(text, re.compile(r"not a signature", re.IGNORECASE))
            self.assertRegex(text, re.compile(r"Barrier", re.IGNORECASE))


if __name__ == "__main__":
    unittest.main()
