"""Native token expiry retains exact nanoseconds and rejects malformed values."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from native_token_expiry import expiry_nanoseconds


class NativeTokenExpiryTests(unittest.TestCase):
    def test_fractional_expiry_never_rounds_or_extends(self):
        base = expiry_nanoseconds("2026-10-06T00:00:00Z")
        self.assertEqual(expiry_nanoseconds("2026-10-06T00:00:00.000000001Z"), base + 1)
        self.assertEqual(expiry_nanoseconds("2026-10-06T00:00:00.999999999Z"), base + 999_999_999)
        self.assertEqual(expiry_nanoseconds("2026-10-06T00:00:00.1Z"), base + 100_000_000)
        self.assertEqual(expiry_nanoseconds("2026-10-06T00:00:00.100000000Z"),
                         expiry_nanoseconds("2026-10-06T00:00:00.1Z"))
        self.assertEqual(expiry_nanoseconds("1970-01-01T00:00:00Z"), 0)

    def test_invalid_or_non_native_values_cannot_prove_expiry(self):
        for value in (None, True, 1780000000, 1.0, "", "2026-02-30T00:00:00Z",
                      "2026-10-06T00:00:60Z", "2026-10-06T00:00:00.0000000001Z",
                      "2026-10-06T00:00:00+00:00", "2026-10-06 00:00:00Z",
                      "2026-10-06T00:00:00Z\n"):
            with self.subTest(value=value):
                self.assertIsNone(expiry_nanoseconds(value))


if __name__ == "__main__":
    unittest.main()
