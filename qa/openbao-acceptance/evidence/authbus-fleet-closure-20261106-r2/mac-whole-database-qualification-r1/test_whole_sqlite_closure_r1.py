#!/usr/bin/env python3
"""Failure-path closure and page-boundary tests with original OS resources."""
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest

from whole_sqlite_bundle_r1 import WholeStore, SnapshotRefused, page_image


class CloseFailureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(__file__).parent, prefix="whole-close-negative-")
        root = Path(self.tmp.name)
        (root / "source").mkdir(mode=0o700)
        (root / "archive").mkdir(mode=0o700)
        self.store = WholeStore(root=root / "archive", source_root=root / "source",
                                until=time.monotonic() + 10, source_vfs="unix")

    def tearDown(self):
        self.tmp.cleanup()

    def test_first_unknown_sqlite_close_does_not_skip_any_other_handle(self):
        first = sqlite3.connect(":memory:")
        other = sqlite3.connect(":memory:")

        class CloseThenUnknown:
            def close(self):
                first.close()
                raise OSError("synthetic-close-outcome-unknown")

        good = {"db": other, "closeAttempts": 0, "closed": False}
        unknown = {"db": CloseThenUnknown(), "closeAttempts": 0, "closed": False}
        self.store.connections.extend([good, unknown])
        fd = self.store.open(self.store.root / "marker", os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        with self.assertRaises(OSError):
            self.store.close()
        self.assertTrue(good["closed"])
        self.assertTrue(fd["closed"])
        self.assertFalse(unknown["closed"])
        self.assertEqual([r["closeAttempts"] for r in (good, unknown, fd)], [1, 1, 1])
        with self.assertRaisesRegex(SnapshotRefused, "previous_close_unknown"):
            self.store.close()
        self.assertEqual(unknown["closeAttempts"], 1)

    def test_unknown_file_close_does_not_skip_earlier_owned_fd(self):
        good = self.store.open(self.store.root / "one", os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        failed = self.store.open(self.store.root / "two", os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        os.close(failed["fd"])
        with self.assertRaises(OSError):
            self.store.close()
        self.assertTrue(good["closed"])
        self.assertFalse(failed["closed"])
        self.assertEqual(good["closeAttempts"], 1)
        self.assertEqual(failed["closeAttempts"], 1)

    def test_partial_database_page_image_is_rejected(self):
        db = sqlite3.connect(":memory:")
        try:
            db.execute("CREATE TABLE t(x)").close()
            raw = db.serialize()
            with self.assertRaisesRegex(SnapshotRefused, "whole_sqlite_pages_only"):
                page_image(raw[:-1], 1048576)
            with self.assertRaisesRegex(SnapshotRefused, "bounded_complete"):
                page_image(raw, 512)
        finally:
            db.close()
        self.store.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
