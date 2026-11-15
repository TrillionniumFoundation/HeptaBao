from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core_isolation import file_hash
from identity_upgrade import validate_binary_pins


class IdentityUpgradeHarnessTests(unittest.TestCase):
    def test_changed_identical_or_unpinned_legacy_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy, candidate = root / "legacy", root / "candidate"
            legacy.write_bytes(b"synthetic-legacy")
            candidate.write_bytes(b"synthetic-candidate")
            pin = file_hash(legacy)
            self.assertEqual(validate_binary_pins(candidate, legacy, pin), (file_hash(candidate), pin))
            for invalid in ["0" * 64, "wrong", pin.upper()]:
                with self.subTest(invalid=invalid):
                    with self.assertRaises(ValueError):
                        validate_binary_pins(candidate, legacy, invalid)
            with self.assertRaises(ValueError):
                validate_binary_pins(legacy, legacy, pin)
            legacy.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                validate_binary_pins(candidate, legacy, pin)


if __name__ == "__main__":
    unittest.main()
