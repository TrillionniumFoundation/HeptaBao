"""Upgrade evidence pins actual binaries and compares the complete store."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from provider_renewal_upgrade import (CANDIDATE_SOURCE, CANDIDATE_SHA256,
    LEGACY_SOURCE, LEGACY_SHA256, admit_candidate, admit_legacy, durable_manifest)


def receipt(source, digest):
    return {"source_commit": source, "candidate_binary_sha256": digest,
            "source_worktree_dirty": False, "candidate_binary_unchanged": True, "status": "passed"}


class ProviderUpgradeTests(unittest.TestCase):
    def test_legacy_pin_requires_clean_matching_commit_receipt(self):
        expected = receipt(LEGACY_SOURCE, LEGACY_SHA256)
        for key, value in [("source_commit", "other"), ("source_worktree_dirty", True),
                           ("status", "failed"), ("candidate_binary_unchanged", False)]:
            with self.assertRaises(ValueError):
                admit_legacy(Path("unused-current"), Path("unused-legacy"), LEGACY_SHA256,
                             dict(expected, **{key: value}))
        with self.assertRaises(ValueError):
            admit_legacy(Path("unused-current"), Path("unused-legacy"), "0" * 64, expected)
        with patch("provider_renewal_upgrade.validate_binary_pins", return_value=("current", "legacy")) as pin:
            self.assertEqual(admit_legacy(Path("a"), Path("b"), LEGACY_SHA256, expected), ("current", "legacy"))
            pin.assert_called_once_with(Path("a"), Path("b"), LEGACY_SHA256)

    def test_current_build_identity_cannot_be_inferred_from_active_checkout(self):
        expected = receipt(CANDIDATE_SOURCE, CANDIDATE_SHA256)
        admit_candidate(CANDIDATE_SHA256, expected)
        for digest, bound in [("0" * 64, expected),
                              (CANDIDATE_SHA256, dict(expected, source_commit="active-dirty-source")),
                              (CANDIDATE_SHA256, dict(expected, source_worktree_dirty=True))]:
            with self.assertRaises(ValueError):
                admit_candidate(digest, bound)

    def test_manifest_detects_journal_changes_additions_deletions_and_modes(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            (folder / "state.hbs").write_bytes(b"synthetic-checkpoint")
            journal = folder / "journal.hbj"
            journal.write_bytes(b"synthetic-journal")
            baseline = durable_manifest(folder)
            self.assertEqual(baseline, durable_manifest(folder))
            journal.write_bytes(b"synthetic-journal-mutated")
            self.assertNotEqual(baseline, durable_manifest(folder))
            journal.write_bytes(b"synthetic-journal")
            self.assertEqual(baseline, durable_manifest(folder))
            (folder / "extra").mkdir()
            self.assertNotEqual(baseline, durable_manifest(folder))
            (folder / "extra").rmdir()
            old_mode = journal.stat().st_mode & 0o777
            journal.chmod(old_mode ^ 0o100)
            self.assertNotEqual(baseline, durable_manifest(folder))
            journal.chmod(old_mode)
            journal.unlink()
            self.assertNotEqual(baseline, durable_manifest(folder))

    def test_manifest_rejects_symlinks_without_following_private_target(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            (folder / "state.hbs").symlink_to("/private-synthetic-target")
            with self.assertRaisesRegex(ValueError, "^store_manifest_nonregular_entry$"):
                durable_manifest(folder)

    def test_reopen_exception_is_only_root_replay_ledger_and_never_journal(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            ledger = folder / "ledger.hbl"
            journal = folder / "journal.hbj"
            ledger.write_bytes(b"synthetic-ledger")
            journal.write_bytes(b"synthetic-journal")
            full, application = durable_manifest(folder), durable_manifest(folder, application_only=True)
            ledger.write_bytes(b"synthetic-resealed-ledger")
            self.assertNotEqual(full, durable_manifest(folder))
            self.assertEqual(application, durable_manifest(folder, application_only=True))
            journal.write_bytes(b"synthetic-mutated-journal")
            self.assertNotEqual(application, durable_manifest(folder, application_only=True))
            ledger.unlink()
            ledger.symlink_to("/private-synthetic-target")
            with self.assertRaisesRegex(ValueError, "^store_manifest_nonregular_entry$"):
                durable_manifest(folder, application_only=True)


if __name__ == "__main__":
    unittest.main()
