from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = ROOT / "crates/heptabao-protocol/src/lib.rs"


class SensitiveParseRejectionHygieneTests(unittest.TestCase):
    def test_query_parse_failures_are_owned_by_a_zeroizing_guard(self) -> None:
        source = PROTOCOL.read_text(encoding="utf-8")
        for marker in (
            "struct SensitiveQueryMap(BTreeMap<String, String>);",
            "impl Drop for SensitiveQueryMap",
            "zeroize_string(&mut name);",
            "zeroize_string(&mut value);",
            "let mut values = SensitiveQueryMap::default();",
            "if values.contains_key(name)",
            "Ok(values.into_pairs())",
        ):
            self.assertIn(marker, source)
        self.assertNotIn(
            "values.insert(name.to_owned(), value.to_owned()).is_some()", source
        )

    def test_duplicate_header_is_detected_before_allocating_replacement_value(self) -> None:
        source = PROTOCOL.read_text(encoding="utf-8")
        duplicate_check = "if headers.0.contains_key(&canonical_name)"
        insertion = ".insert(canonical_name, value.as_bytes().to_vec());"
        self.assertIn(duplicate_check, source)
        self.assertIn(insertion, source)
        self.assertLess(source.index(duplicate_check), source.index(insertion))


if __name__ == "__main__":
    unittest.main()
