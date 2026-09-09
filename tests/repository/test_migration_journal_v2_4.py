from pathlib import Path
import unittest


class MigrationJournalV24Tests(unittest.TestCase):
    def test_authenticated_journal_and_reconciliation_are_materialized(self):
        source = Path("crates/heptabao-migration-journal/src/lib.rs").read_text(encoding="utf-8")
        for marker in ("HMAC_SHA256", "previous_tag", "CommitPending", "ReconciliationProof", "WriterBusy", "OutcomeUnknown"):
            self.assertIn(marker, source)

    def test_module_guide_declares_open_boundaries(self):
        guide = Path("docs/modules/heptabao-migration-journal.md").read_text(encoding="utf-8")
        self.assertIn("Independent cutover and rollback evidence is still required", guide)
        self.assertIn("It does not itself claim full OpenBao object coverage", guide)


if __name__ == "__main__":
    unittest.main()
