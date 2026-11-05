from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "release_candidate_sbom", ROOT / "scripts" / "release_candidate_sbom.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ReleaseCandidateSbomTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path, str]:
        lock = root / "Cargo.lock"
        lock.write_text(
            """version = 4

[[package]]
name = "alpha"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[package]]
name = "heptabao-server"
version = "0.1.0"
""",
            encoding="utf-8",
        )
        binary = root / "heptabao-server"
        binary.write_bytes(b"synthetic candidate binary")
        return lock, binary, "1" * 40

    def test_generation_is_deterministic_and_binary_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            lock, binary, source = self.fixture(Path(directory))
            first = MODULE.generate(lock, binary, source)
            second = MODULE.generate(lock, binary, source)
            self.assertEqual(first, second)
            MODULE.validate(first, lock, binary, source)
            binding = json.loads(first["documentComment"])
            self.assertEqual(binding["source_commit"], source)
            self.assertEqual(binding["server_binary_sha256"], MODULE.sha256(binary))
            self.assertFalse(binding["release_authority"])
            self.assertFalse(binding["production_authority"])

    def test_lock_drift_and_binary_drift_fail_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock, binary, source = self.fixture(root)
            document = MODULE.generate(lock, binary, source)
            binary.write_bytes(b"different binary")
            with self.assertRaisesRegex(ValueError, "source/binary binding"):
                MODULE.validate(document, lock, binary, source)
            binary.write_bytes(b"synthetic candidate binary")
            lock.write_text(lock.read_text() + '\n[[package]]\nname = "extra"\nversion = "9.9.9"\n')
            with self.assertRaisesRegex(ValueError, "denominator"):
                MODULE.validate(document, lock, binary, source)

    def test_source_identity_must_be_exact_git_sha(self):
        with tempfile.TemporaryDirectory() as directory:
            lock, binary, _ = self.fixture(Path(directory))
            with self.assertRaisesRegex(ValueError, "source SHA"):
                MODULE.generate(lock, binary, "main")


if __name__ == "__main__":
    unittest.main()
