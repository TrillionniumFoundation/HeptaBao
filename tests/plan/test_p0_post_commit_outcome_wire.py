from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
P0_SOURCE = ROOT / "crates/heptabao-p0-server/src/lib.rs"


class P0PostCommitOutcomeWireTests(unittest.TestCase):
    def test_post_commit_audit_failure_is_explicit_on_the_wire(self) -> None:
        source = P0_SOURCE.read_text(encoding="utf-8")
        committed = source.index(r'\"committed\":true')
        recovery = source.index(r'\"recovery_reference\":', committed)
        self.assertLess(committed, recovery)
        self.assertIn(
            "response_audit_failure_preserves_commit_and_returns_recovery_reference",
            source,
        )
        self.assertIn(
            'contains("\\\"committed\\\":true")',
            source,
        )


if __name__ == "__main__":
    unittest.main()
