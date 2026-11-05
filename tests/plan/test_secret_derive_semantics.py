from __future__ import annotations

import re
import unittest

try:
    from tests.plan.historical import historical_only
except ModuleNotFoundError:  # direct `python tests/plan/test_*.py` execution
    from historical import historical_only
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = ROOT / "crates/heptabao-protocol/src/lib.rs"


class SecretDeriveSemanticsTests(unittest.TestCase):
    def test_secret_bytes_cannot_derive_debug_in_any_trait_order(self) -> None:
        source = PROTOCOL.read_text(encoding="utf-8")
        match = re.search(
            r"#\[derive\(([^)]*)\)\]\s*pub struct SecretBytes", source
        )
        if match is None:
            return
        traits = {item.strip() for item in match.group(1).split(",")}
        self.assertNotIn("Debug", traits)

    @historical_only
    def test_secret_bytes_has_explicit_redacted_debug_and_drop_zeroization(self) -> None:
        source = PROTOCOL.read_text(encoding="utf-8")
        for marker in (
            "impl fmt::Debug for SecretBytes",
            'formatter.write_str("SecretBytes([REDACTED])")',
            "impl Drop for SecretBytes",
            "self.0.fill(0);",
        ):
            self.assertIn(marker, source)


if __name__ == "__main__":
    unittest.main()
