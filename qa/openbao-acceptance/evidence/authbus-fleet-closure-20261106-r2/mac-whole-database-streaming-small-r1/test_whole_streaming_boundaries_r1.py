#!/usr/bin/env python3
"""Actual small SQLite/file regressions for the new bounded implementation."""
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from whole_sqlite_streaming_r1 import WholeStore, SnapshotRefused, full9

HERE = Path(__file__).resolve().parent
os.umask(0o077)


class StreamingBoundaries(unittest.TestCase):
    def setUp(self):
        self.parent = Path(tempfile.mkdtemp(prefix="local-boundary-", dir=HERE))
        self.live, self.archive = self.parent / "live", self.parent / "archive"
        self.live.mkdir(mode=0o700)
        self.archive.mkdir(mode=0o700)
        self.store = WholeStore(root=self.archive, source_root=self.live,
                                until=time.monotonic() + 10, source_vfs="unix")

    def tearDown(self):
        self.store.close()
        value = self.store.public()
        self.assertTrue(value["allFileDescriptorsClosedOnce"])
        self.assertTrue(value["allSqliteHandlesClosedOnce"])
        self.assertTrue(value["allExplicitCursorsClosed"])

    def database(self, name="source.sqlite", large=False):
        path = self.live / name
        self.store.create(path, b"")
        row = self.store.connect(path, readonly=False, role="synthetic-writer")
        self.store.query(row, "CREATE TABLE opaque (id INTEGER PRIMARY KEY, value TEXT, payload BLOB)")
        self.store.query(row, "INSERT INTO opaque VALUES(1,'old',zeroblob(?))", (2 * 1048576 if large else 1024,))
        return path, row

    def two_closed_files(self):
        source, row = self.database(large=True)
        self.store.close_connection(row)
        first = self.archive / "first.sqlite"
        second = self.archive / "second.sqlite"
        original = self.store.stream_identity(source)
        for path in (first, second):
            self.store.stream_copy(source, path, expected=original["full9"],
                                   expected_sha256=original["sha256"])
        return first, second

    def alter_byte(self, path, offset):
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            before = os.pread(fd, 1, offset)
            self.assertEqual(len(before), 1)
            os.pwrite(fd, bytes((before[0] ^ 1,)), offset)
            os.fsync(fd)
        finally:
            os.close(fd)

    def test_late_page_corruption_is_refused(self):
        first, second = self.two_closed_files()
        self.alter_byte(second, 1048576 + 8192)
        with self.assertRaises(SnapshotRefused):
            self.store.stream_compare_pages(first, second)

    def test_only_original_header_words_are_normalized(self):
        first, second = self.two_closed_files()
        self.alter_byte(second, 40)
        value = self.store.stream_compare_pages(first, second)
        self.assertNotEqual(value["leftSha256"], value["rightSha256"])
        self.alter_byte(second, 68)
        with self.assertRaises(SnapshotRefused):
            self.store.stream_compare_pages(first, second)

    def test_source_generation_drift_refused(self):
        first, _ = self.two_closed_files()
        pin = full9(first.lstat())
        self.alter_byte(first, 1048576 + 4096)
        with self.assertRaises(SnapshotRefused):
            self.store.stream_identity(first, expected=pin)

    def test_copy_does_not_overwrite_existing_name(self):
        first, second = self.two_closed_files()
        original = self.store.stream_identity(first)
        before = self.store.stream_identity(second)
        with self.assertRaises(FileExistsError):
            self.store.stream_copy(first, second, expected=original["full9"],
                                   expected_sha256=original["sha256"])
        self.assertEqual(self.store.stream_identity(second), before)

    def test_wrong_original_digest_refuses_and_retains_partial_output(self):
        first, _ = self.two_closed_files()
        original = self.store.stream_identity(first)
        destination = self.archive / "refused.sqlite"
        with self.assertRaises(SnapshotRefused):
            self.store.stream_copy(first, destination, expected=original["full9"], expected_sha256="0" * 64)
        self.assertTrue(destination.exists())
        self.assertEqual(self.store.stream_identity(first), original)
        self.assertFalse(self.store.restore_started)

    def test_oversize_refused_before_materialization(self):
        path = self.live / "over-limit.private"
        self.store.create(path, b"")
        os.truncate(path, 4097)
        self.store.maximum = 4096
        with self.assertRaises(SnapshotRefused):
            self.store.stream_identity(path)

    def test_deadline_refuses_before_io(self):
        self.store.until = time.monotonic() - 1
        with self.assertRaises(SnapshotRefused):
            self.store.stream_identity(self.live / "not-opened")
        self.assertEqual(len(self.store.fds), 0)

    def test_fresh_absent_and_empty_wal_snapshots(self):
        path, row = self.database()
        self.store.close_connection(row)
        absent = self.store.namespace(path)
        self.assertIsNone(absent["-wal"])
        first = self.store.capture(path, absent, slot=0, phase="baseline")
        self.assertTrue(first["twoCompleteBackupOutputsEqual"])
        self.store.create(Path(str(path) + "-wal"), b"")
        self.store.create(Path(str(path) + "-shm"), b"\x00" * 32768)
        empty = self.store.namespace(path)
        self.assertEqual(empty["-wal"][6], "0")
        second = self.store.capture(path, empty, slot=0, phase="candidate")
        self.assertTrue(second["twoCompleteBackupOutputsEqual"])
        self.assertEqual(self.store.namespace(path), empty)

    def test_each_close_is_attempted_after_another_close_raises(self):
        first, second = self.two_closed_files()
        one = self.store.open(first, os.O_RDONLY)
        two = self.store.open(second, os.O_RDONLY)
        original_close = os.close
        calls = []

        def once_then_throw(fd):
            calls.append(fd)
            original_close(fd)
            if fd == two["fd"]:
                raise OSError("synthetic failure after consumed close")

        with patch("whole_sqlite_streaming_r1.os.close", once_then_throw):
            with self.assertRaises(OSError):
                self.store.close()
        self.assertEqual(calls.count(two["fd"]), 1)
        self.assertTrue(one["closed"])
        self.assertEqual(one["closeAttempts"], 1)
        # Keep the refused original state; bypass normal successful tearDown.
        self.store = WholeStore(root=self.archive, source_root=self.live,
                                until=time.monotonic() + 10, source_vfs="unix")

    def test_same_fresh_begin_snapshot_survives_external_writer_between_backups(self):
        path, writer = self.database()
        self.assertEqual(self.store.query(writer, "PRAGMA journal_mode=WAL"), [("wal",)])
        self.store.query(writer, "PRAGMA wal_autocheckpoint=0")
        self.store.query(writer, "UPDATE opaque SET value='read-snapshot' WHERE id=1")
        source = self.store.connect(path, readonly=True, role="fresh-source")
        self.store.query(source, "BEGIN")
        source["transaction"] = True
        self.assertEqual(self.store.query(source, "SELECT value FROM opaque"), [("read-snapshot",)])
        pages = self.store.query(source, "PRAGMA page_count")[0][0]
        outputs = []
        for ordinal in range(2):
            destination = self.archive / ("snapshot-" + str(ordinal) + ".sqlite")
            self.store.create(destination, b"")
            target = self.store.connect(destination, readonly=False, role="distinct-output")
            self.store._backup_once(source, target, pages, purpose="independent-snapshot-test")
            self.assertEqual(self.store.query(target, "SELECT value FROM opaque"), [("read-snapshot",)])
            self.store.close_connection(target)
            outputs.append(destination)
            if ordinal == 0:
                self.store.query(writer, "UPDATE opaque SET value='new-external-commit' WHERE id=1")
        self.assertTrue(self.store.stream_compare_pages(*outputs)["bytes"] > 0)
        newest = self.store.connect(path, readonly=True, role="independent-latest-reader")
        self.assertEqual(self.store.query(newest, "SELECT value FROM opaque"), [("new-external-commit",)])
        self.store.query(source, "ROLLBACK")
        source["transaction"] = False

    def test_busy_backup_stops_on_first_callback(self):
        path, writer = self.database()
        source = self.store.connect(path, readonly=True, role="source")
        self.store.query(source, "BEGIN")
        source["transaction"] = True
        pages = self.store.query(source, "PRAGMA page_count")[0][0]
        destination = self.archive / "busy.sqlite"
        self.store.create(destination, b"")
        target = self.store.connect(destination, readonly=False, role="target")
        blocker = self.store.connect(destination, readonly=False, role="explicit-exclusive-blocker")
        self.store.query(blocker, "BEGIN EXCLUSIVE")
        blocker["transaction"] = True
        with self.assertRaises(SnapshotRefused):
            self.store._backup_once(source, target, pages, purpose="busy-no-retry")
        record = self.store.backup_records[-1]
        self.assertEqual(record["progressCalls"], 1)
        self.assertEqual(record["lastStatus"], sqlite3.SQLITE_BUSY)
        self.assertFalse(record["completed"])
        self.store.query(blocker, "ROLLBACK")
        blocker["transaction"] = False
        self.store.query(source, "ROLLBACK")
        source["transaction"] = False


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(StreamingBoundaries)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {"schema": "heptabao.whole-sqlite-streaming-boundary-qualification.r1",
              "testsRun": result.testsRun, "passed": result.wasSuccessful(),
              "platform": "local-linux", "sqlite": sqlite3.sqlite_version,
              "productionInputsRead": False, "macExecution": False}
    (HERE / "local-boundary-result.original.json").write_text(json.dumps(report, sort_keys=True) + "\n")
    raise SystemExit(0 if result.wasSuccessful() else 1)
