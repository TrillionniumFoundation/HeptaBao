"""Keep completion admission on the one strict, verification-only primitive."""
from __future__ import annotations

import hashlib
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import heptabao_ed25519_v2_5 as primitive

SPEC = importlib.util.spec_from_file_location(
    "completion_signature_boundary", SCRIPTS / "verify_external_completion_v2_5.py"
)
assert SPEC and SPEC.loader
completion = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(completion)


class CompletionSignatureBoundaryTests(unittest.TestCase):
    def test_adapter_uses_shared_strict_primitive_and_preserves_boolean_api(self):
        key, message, signature = bytes(32), b"message", bytes(64)
        with patch.object(primitive, "verify", return_value=None) as verify:
            self.assertTrue(completion.verify_ed25519(key, message, signature))
            verify.assert_called_once_with(key, signature, message)
        with patch.object(primitive, "verify", side_effect=primitive.Ed25519Error("rejected")):
            self.assertFalse(completion.verify_ed25519(key, message, signature))

    def test_invalid_lengths_and_scalar_reject_before_curve_work(self):
        with patch.object(primitive, "verify") as verify:
            self.assertFalse(completion.verify_ed25519(b"", b"", bytes(64)))
            self.assertFalse(completion.verify_ed25519(bytes(32), b"", b""))
            self.assertFalse(completion.verify_ed25519(
                bytes(32), b"", bytes(32) + primitive.ORDER.to_bytes(32, "little")))
            verify.assert_not_called()

    def test_wrong_python_types_do_not_become_a_cryptographic_verdict(self):
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        public = key.public_key().public_bytes_raw()
        signature = key.sign(b"message")
        for args in ((None, b"message", signature), (public, None, signature),
                     (public, b"message", None)):
            with self.subTest(args=args), self.assertRaises(TypeError):
                completion.verify_ed25519(*args)

    def test_cli_runs_from_an_unrelated_directory_with_its_verification_module(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            for filename in ("verify_external_completion_v2_5.py", "heptabao_ed25519_v2_5.py"):
                shutil.copyfile(SCRIPTS / filename, bundle / filename)
            result = subprocess.run(
                [sys.executable, "-I", str(bundle / "verify_external_completion_v2_5.py"), "--help"],
                cwd=root, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("--expected-trust-store-sha256", result.stdout)

    def test_independent_signatures_and_tampering(self):
        # Synthetic test seeds only. Signing uses the pinned independent provider,
        # never the arithmetic under test or a production signing entrypoint.
        for size in (0, 1, 31, 32, 63, 64, 127, 128, 255, 1024):
            with self.subTest(size=size):
                seed = hashlib.sha256(f"completion-test:{size}".encode()).digest()
                key = Ed25519PrivateKey.from_private_bytes(seed)
                public = key.public_key().public_bytes_raw()
                message = bytes(index % 256 for index in range(size))
                signature = key.sign(message)
                self.assertTrue(completion.verify_ed25519(public, message, signature))
                self.assertFalse(completion.verify_ed25519(public, message + b"!", signature))
                other = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed).digest())
                self.assertFalse(completion.verify_ed25519(other.public_key().public_bytes_raw(), message, signature))
                for index in (0, 31, 32, 63):
                    changed = bytearray(signature)
                    changed[index] ^= 1
                    self.assertFalse(completion.verify_ed25519(public, message, bytes(changed)))
                noncanonical = signature[:32] + (
                    int.from_bytes(signature[32:], "little") + primitive.ORDER
                ).to_bytes(32, "little")
                self.assertFalse(completion.verify_ed25519(public, message, noncanonical))

    def test_noncanonical_small_order_and_mixed_order_points_are_rejected(self):
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        public = key.public_key().public_bytes_raw()
        signature = key.sign(b"strict")
        order_two = (0, primitive.FIELD - 1, 1, 0)
        mixed = primitive.encode_point(primitive.point_add(primitive.decode_point(public), order_two))
        encodings = [
            # Fixed curve encodings, independent of the arithmetic under test:
            # y=0 has order four; y=1 is identity; y=-1 has order two.
            bytes(32), (1).to_bytes(32, "little"),
            (primitive.FIELD - 1).to_bytes(32, "little"),
            primitive.FIELD.to_bytes(32, "little"), bytes([255]) * 32,
            (1 | (1 << 255)).to_bytes(32, "little"), mixed,
        ]
        for encoded in encodings:
            with self.subTest(encoded=encoded.hex()):
                with self.assertRaises(primitive.Ed25519Error):
                    primitive.decode_point(encoded)
                self.assertFalse(completion.verify_ed25519(encoded, b"strict", signature))
                self.assertFalse(completion.verify_ed25519(public, b"strict", encoded + signature[32:]))

    def test_invalid_lengths_are_rejected(self):
        for key_length, signature_length in ((0, 64), (31, 64), (33, 64), (32, 0), (32, 63), (32, 65)):
            self.assertFalse(completion.verify_ed25519(bytes(key_length), b"", bytes(signature_length)))


if __name__ == "__main__":
    unittest.main()
