#!/usr/bin/env python3
"""Whole SQLite snapshots and an offline, once-only namespace replacement.

No command line entry point, service actions, provider calls or import-time I/O.
The executable outer owns source admission, all consumer/writer retirement and
the fresh post-provider epoch. This library is not a production actuator by
itself. The first qualification uses only a new synthetic root and complete
schemas extracted from the pinned installed SDK.

One fresh read transaction, including current WAL, is copied twice through
SQLite's incremental backup API into two independent private disk files. An old
keeper is never accepted as the latest source. Every page of the two outputs is
compared with 1 MiB buffers, excluding only the original header bookkeeping
words at 24..27, 40..43 and 92..99. This is a comparison of two SQLite API
outputs, not an independent raw-source-page oracle. Each new destination's
schema cookie must be 1, with exact source schema, capacity and integrity.
The standalone archive is bound by a complete streamed SHA-256. Restore copies
its exact bytes and preserves old base/sidecar names in private quarantine.
No whole-database serialize call or materialization is used. The caller must
use a dedicated owned Python process because SQLite's allocator ceiling is
process-global. All content digests and namespace records remain private.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time
from urllib.parse import quote

SUFFIXES = ("", "-wal", "-shm", "-journal")
MIB = 1048576
MAX_DATABASE_BYTES = 4 * 1024 * MIB
STREAM_BLOCK_BYTES = MIB
MAX_METADATA_BYTES = 8 * MIB
SQLITE_CACHE_KIB = 8192
SQLITE_HEAP_LIMIT_BYTES = 256 * MIB
BOOKKEEPING_RANGES = ((24, 28), (40, 44), (92, 100))


class SnapshotRefused(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise SnapshotRefused(code)


def full9(info):
    return tuple(str(getattr(info, name)) for name in (
        "st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
        "st_size", "st_mtime_ns", "st_ctime_ns"))


def stable_after_owned_link(before, after, links):
    return (before[:5] == after[:5] and after[5] == str(links)
            and before[6:8] == after[6:8])


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class WholeStore:
    """Caller-admitted fixed roots; every created file is private and exclusive.

    The outer must hold and verify complete parent chains. It must never pass
    user-input paths, reopen arbitrary registered paths or resume a partial
    restore by creating another operation directory.
    """

    def __init__(self, *, root, source_root, until, maximum=MAX_DATABASE_BYTES, source_vfs="unix-posix"):
        self.root, self.source_root = Path(root), Path(source_root)
        self.until, self.maximum = until, maximum
        need(source_vfs in ("unix-posix", "unix"), "explicit_fixed_sqlite_vfs")
        self.source_vfs = source_vfs
        need(type(maximum) is int and 512 <= maximum <= MAX_DATABASE_BYTES,
             "fixed_whole_database_byte_bound")
        need(self.root.is_absolute() and self.source_root.is_absolute()
             and ".." not in self.root.parts and ".." not in self.source_root.parts,
             "absolute_fixed_snapshot_roots")
        self.uid, self.gid = os.getuid(), os.getgid()
        self.fds, self.connections, self.steps = [], [], []
        self.close_errors = []
        self.darwin_xattr_queries = []
        self.stream_records = []
        self.backup_records = []
        self.query_bytes_maximum = 0
        self.failed, self.restore_started, self.restore_complete = False, False, False
        self._check_directory(self.root)
        self._check_directory(self.source_root)
        need(self.root.lstat().st_dev == self.source_root.lstat().st_dev,
             "same_filesystem_private_quarantine")

    def remaining(self):
        need(time.monotonic() < self.until, "original_whole_database_deadline")

    def _check_directory(self, path):
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == self.uid
             and not stat.S_IMODE(info.st_mode) & 0o077,
             "private_whole_database_directory")
        return full9(info)

    def _path(self, path, *, archive=False):
        path = Path(path)
        root = self.root if archive else self.source_root
        need(path.is_absolute() and ".." not in path.parts and path != root
             and path.is_relative_to(root), "fixed_whole_database_path_scope")
        # Complete parent descriptor custody belongs to the outer. Check
        # every additional owned directory here without resolving symlinks.
        self._check_directory(root)
        current = root
        for name in path.parent.relative_to(root).parts:
            current /= name
            self._check_directory(current)
        return path

    def open(self, path, flags, mode=0o600):
        fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
        row = {"fd": fd, "closeAttempts": 0, "closed": False}
        self.fds.append(row)
        return row

    def close_fd(self, row):
        if row["closeAttempts"]:
            return row["closed"]
        row["closeAttempts"] = 1
        try:
            os.close(row["fd"])
            row["closed"] = True
        except BaseException:
            self.failed = True
            raise
        return True

    def fsync_dir(self, path):
        row = self.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(row["fd"])
        finally:
            self.close_fd(row)

    def bytes(self, path, *, maximum=None):
        self.remaining()
        maximum = MAX_METADATA_BYTES if maximum is None else maximum
        need(type(maximum) is int and 0 <= maximum <= MAX_METADATA_BYTES,
             "whole_database_materialization_not_permitted")
        row = self.open(path, os.O_RDONLY | os.O_NONBLOCK)
        try:
            before = os.fstat(row["fd"])
            need(stat.S_ISREG(before.st_mode) and before.st_uid == self.uid
                 and before.st_gid == self.gid and stat.S_IMODE(before.st_mode) == 0o600
                 and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
                 "private_bounded_whole_database_file")
            result = bytearray()
            while len(result) <= before.st_size:
                self.remaining()
                part = os.read(row["fd"], min(65536, before.st_size + 1 - len(result)))
                if not part:
                    break
                result.extend(part)
            need(len(result) == before.st_size
                 and full9(before) == full9(os.fstat(row["fd"])) == full9(Path(path).lstat()),
                 "whole_database_file_unchanged")
            return bytes(result)
        finally:
            self.close_fd(row)

    def create(self, path, data):
        need(isinstance(data, bytes) and len(data) <= MAX_METADATA_BYTES,
             "bounded_private_archive_write")
        row = self.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            view = memoryview(data)
            while view:
                self.remaining()
                count = os.write(row["fd"], view)
                need(count > 0, "private_archive_write_progress")
                view = view[count:]
            os.fsync(row["fd"])
        finally:
            self.close_fd(row)
        self.fsync_dir(Path(path).parent)

    def _stream_file(self, row, path, expected=None):
        before = os.fstat(row["fd"])
        need(stat.S_ISREG(before.st_mode) and before.st_uid == self.uid
             and before.st_gid == self.gid and stat.S_IMODE(before.st_mode) == 0o600
             and before.st_nlink == 1 and 0 <= before.st_size <= self.maximum,
             "private_bounded_stream_file")
        identity = full9(before)
        need(identity == full9(Path(path).lstat())
             and (expected is None or identity == tuple(expected)),
             "stream_original_file_generation")
        return before

    def stream_identity(self, path, *, expected=None, sqlite_pages=False):
        """Hash every byte using a bounded buffer; never materialize the file."""
        self.remaining()
        row = self.open(path, os.O_RDONLY | os.O_NONBLOCK)
        entry = {"operation": "hash", "bytes": 0, "maximumBlockBytes": 0,
                 "completed": False, "descriptorClosedOnce": False}
        self.stream_records.append(entry)
        try:
            before = self._stream_file(row, path, expected)
            digest, normalized = hashlib.sha256(), hashlib.sha256()
            count, page_size = 0, None
            while count < before.st_size:
                self.remaining()
                part = os.read(row["fd"], min(STREAM_BLOCK_BYTES, before.st_size - count))
                need(bool(part), "complete_stream_file_before_eof")
                entry["maximumBlockBytes"] = max(entry["maximumBlockBytes"], len(part))
                digest.update(part)
                if sqlite_pages and count == 0:
                    need(len(part) >= 100 and part[:16] == b"SQLite format 3\x00",
                         "stream_sqlite_file_header")
                    page_size = int.from_bytes(part[16:18], "big")
                    page_size = 65536 if page_size == 1 else page_size
                    need(page_size in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)
                         and before.st_size >= page_size and before.st_size % page_size == 0,
                         "stream_complete_sqlite_pages")
                    header = bytearray(part[:100])
                    for first, last in BOOKKEEPING_RANGES:
                        header[first:last] = bytes(last - first)
                    normalized.update(header)
                    normalized.update(memoryview(part)[100:])
                elif sqlite_pages:
                    normalized.update(part)
                count += len(part)
            need(os.read(row["fd"], 1) == b""
                 and full9(before) == full9(os.fstat(row["fd"])) == full9(Path(path).lstat()),
                 "stream_file_stable_through_eof")
            entry.update(bytes=count, completed=True)
            return {"bytes": count, "full9": full9(before), "sha256": digest.hexdigest(),
                    "pageImageSha256": normalized.hexdigest() if sqlite_pages else None,
                    "pageSize": page_size}
        finally:
            self.close_fd(row)
            entry["descriptorClosedOnce"] = row["closed"] and row["closeAttempts"] == 1

    def stream_copy(self, source, destination, *, expected, expected_sha256):
        """Create one private exact staging file; partial output is retained."""
        self.remaining()
        source_row, destination_row = None, None
        entry = {"operation": "copy", "bytes": 0, "maximumBlockBytes": 0,
                 "completed": False, "descriptorClosedOnce": False}
        self.stream_records.append(entry)
        try:
            source_row = self.open(source, os.O_RDONLY | os.O_NONBLOCK)
            before = self._stream_file(source_row, source, expected)
            destination_row = self.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            destination_initial = os.fstat(destination_row["fd"])
            need(stat.S_ISREG(destination_initial.st_mode)
                 and destination_initial.st_uid == self.uid and destination_initial.st_gid == self.gid
                 and stat.S_IMODE(destination_initial.st_mode) == 0o600
                 and destination_initial.st_nlink == 1 and destination_initial.st_size == 0,
                 "new_empty_stream_destination")
            digest, count = hashlib.sha256(), 0
            while count < before.st_size:
                self.remaining()
                part = os.read(source_row["fd"], min(STREAM_BLOCK_BYTES, before.st_size - count))
                need(bool(part), "complete_stream_copy_before_eof")
                entry["maximumBlockBytes"] = max(entry["maximumBlockBytes"], len(part))
                digest.update(part)
                view = memoryview(part)
                while view:
                    self.remaining()
                    written = os.write(destination_row["fd"], view)
                    need(written > 0, "stream_copy_write_progress")
                    view = view[written:]
                count += len(part)
            need(os.read(source_row["fd"], 1) == b"" and digest.hexdigest() == expected_sha256
                 and full9(before) == full9(os.fstat(source_row["fd"])) == full9(Path(source).lstat()),
                 "stream_copy_complete_original_pin")
            os.fsync(destination_row["fd"])
            after = os.fstat(destination_row["fd"])
            need(full9(after) == full9(Path(destination).lstat()) and after.st_size == count
                 and full9(after)[:6] == full9(destination_initial)[:6],
                 "stream_copy_same_owned_destination")
            entry.update(bytes=count, completed=True)
        finally:
            first_error = None
            for original in (destination_row, source_row):
                if original is not None:
                    try:
                        self.close_fd(original)
                    except BaseException as error:
                        if first_error is None:
                            first_error = error
            entry["descriptorClosedOnce"] = all(original is None
                or original["closed"] and original["closeAttempts"] == 1
                for original in (source_row, destination_row))
            if first_error is not None:
                raise first_error
        self.fsync_dir(Path(destination).parent)
        verified = self.stream_identity(destination)
        need(verified["bytes"] == before.st_size and verified["sha256"] == expected_sha256,
             "closed_stream_copy_exact_original")
        return verified

    def stream_compare_pages(self, left, right):
        """Compare two closed SQLite outputs; this is not a raw source oracle."""
        first, second = None, None
        entry = {"operation": "compare-pages", "bytes": 0, "maximumBlockBytes": 0,
                 "completed": False, "descriptorClosedOnce": False}
        self.stream_records.append(entry)
        try:
            first = self.open(left, os.O_RDONLY | os.O_NONBLOCK)
            second = self.open(right, os.O_RDONLY | os.O_NONBLOCK)
            before = self._stream_file(first, left)
            other = self._stream_file(second, right)
            need(before.st_size == other.st_size and before.st_size >= 512,
                 "whole_backup_outputs_equal_bounded_sizes")
            count, page_size = 0, None
            left_hash, right_hash, normalized = hashlib.sha256(), hashlib.sha256(), hashlib.sha256()
            while count < before.st_size:
                self.remaining()
                size = min(STREAM_BLOCK_BYTES, before.st_size - count)
                a, b = os.read(first["fd"], size), os.read(second["fd"], size)
                need(len(a) == len(b) == size, "both_complete_backup_stream_blocks")
                entry["maximumBlockBytes"] = max(entry["maximumBlockBytes"], size)
                left_hash.update(a)
                right_hash.update(b)
                if count == 0:
                    need(a[:16] == b[:16] == b"SQLite format 3\x00" and a[16:18] == b[16:18],
                         "two_backup_outputs_same_sqlite_header")
                    page_size = int.from_bytes(a[16:18], "big")
                    page_size = 65536 if page_size == 1 else page_size
                    need(page_size in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)
                         and before.st_size % page_size == 0, "two_backup_outputs_complete_pages")
                    ah, bh = bytearray(a[:100]), bytearray(b[:100])
                    for start, end in BOOKKEEPING_RANGES:
                        ah[start:end] = bytes(end - start)
                        bh[start:end] = bytes(end - start)
                    need(ah == bh and memoryview(a)[100:] == memoryview(b)[100:],
                         "two_backup_outputs_page_one_equal")
                    normalized.update(ah)
                    normalized.update(memoryview(a)[100:])
                else:
                    need(a == b, "two_backup_outputs_every_page_equal")
                    normalized.update(a)
                count += size
            need(os.read(first["fd"], 1) == os.read(second["fd"], 1) == b""
                 and full9(before) == full9(os.fstat(first["fd"])) == full9(Path(left).lstat())
                 and full9(other) == full9(os.fstat(second["fd"])) == full9(Path(right).lstat()),
                 "two_closed_backup_outputs_stable")
            entry.update(bytes=count, completed=True)
            return {"bytes": count, "pageSize": page_size,
                    "pageImageSha256": normalized.hexdigest(),
                    "leftFull9": full9(before), "rightFull9": full9(other),
                    "leftSha256": left_hash.hexdigest(), "rightSha256": right_hash.hexdigest()}
        finally:
            first_error = None
            for original in (second, first):
                if original is not None:
                    try:
                        self.close_fd(original)
                    except BaseException as error:
                        if first_error is None:
                            first_error = error
            entry["descriptorClosedOnce"] = all(original is None
                or original["closed"] and original["closeAttempts"] == 1 for original in (first, second))
            if first_error is not None:
                raise first_error

    def namespace(self, path):
        path = self._path(path)
        result = {}
        for suffix in SUFFIXES:
            name = Path(str(path) + suffix)
            try:
                info = name.lstat()
            except FileNotFoundError:
                result[suffix] = None
                continue
            need(stat.S_ISREG(info.st_mode) and info.st_uid == self.uid
                 and info.st_gid == self.gid and stat.S_IMODE(info.st_mode) == 0o600
                 and info.st_nlink == 1 and 0 <= info.st_size <= self.maximum,
                 "exact_whole_database_namespace_custody")
            need(getattr(info, "st_flags", 0) == 0 and self.no_xattrs(name, full9(info)),
                 "unqualified_database_flags_or_xattrs")
            result[suffix] = full9(info)
        need(result[""] is not None and result["-journal"] is None,
             "whole_database_main_and_no_rollback_journal")
        if result["-wal"] is None:
            need(result["-shm"] is None, "whole_database_orphan_shm_refused")
        elif int(result["-wal"][6]) > 0:
            need(int(result["-wal"][6]) >= 32 and result["-shm"] is not None
                 and int(result["-shm"][6]) > 0, "whole_database_existing_wal_and_shm")
        return result

    def no_xattrs(self, path, expected):
        if sys.platform != "darwin":
            return not os.listxattr(path, follow_symlinks=False)
        # Python's Darwin os module does not expose listxattr. Query the same
        # held regular-file descriptor through the native four-argument ABI.
        # Only absence is admitted; no attribute name or value is read.
        original = self.open(path, os.O_RDONLY | os.O_NONBLOCK)
        record = {"returnValue": None, "errno": None, "sameHeldFileBeforeAfter": False,
                  "descriptorClosedOnce": False}
        self.darwin_xattr_queries.append(record)
        try:
            before = os.fstat(original["fd"])
            need(full9(before) == tuple(expected) == full9(Path(path).lstat())
                 and getattr(before, "st_flags", 0) == 0, "darwin_xattr_original_held_file")
            libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            native = libc.flistxattr
            native.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            native.restype = ctypes.c_ssize_t
            ctypes.set_errno(0)
            result = native(original["fd"], None, 0, 0)
            error = ctypes.get_errno()
            record.update(returnValue=result, errno=error)
            need(result == 0 and error == 0, "darwin_xattr_nonempty_or_native_error_refused")
            after = os.fstat(original["fd"])
            need(full9(after) == tuple(expected) == full9(Path(path).lstat())
                 and getattr(after, "st_flags", 0) == 0, "darwin_xattr_same_held_file_after_query")
            record["sameHeldFileBeforeAfter"] = True
            return True
        finally:
            self.close_fd(original)
            record["descriptorClosedOnce"] = original["closed"] and original["closeAttempts"] == 1

    def connect(self, path, *, readonly, immutable=False, role):
        self.remaining()
        need(not immutable or readonly, "immutable_snapshot_is_readonly")
        uri = "file:" + quote(str(path), safe="/") + "?mode=" + ("ro" if readonly else "rw")
        if immutable:
            uri += "&immutable=1"
        elif readonly:
            uri += "&cache=private&vfs=" + self.source_vfs + "&readonly_shm=1"
        db = sqlite3.connect(uri, uri=True, timeout=0, isolation_level=None)
        row = {"db": db, "role": role, "closeAttempts": 0, "closed": False,
               "cursorsOpened": 0, "cursorsClosed": 0, "transaction": False}
        self.connections.append(row)
        db.enable_load_extension(False)
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_METADATA_BYTES)
        db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, MAX_METADATA_BYTES)
        db.set_progress_handler(lambda: int(time.monotonic() >= self.until), 1000)
        # The executable outer must use a dedicated owned Python process.
        # This SQLite allocator limit is process-global, not a database write.
        self.query(row, "PRAGMA hard_heap_limit=" + str(SQLITE_HEAP_LIMIT_BYTES), limit=1)
        need(self.query(row, "PRAGMA hard_heap_limit", limit=1) == [(SQLITE_HEAP_LIMIT_BYTES,)],
             "dedicated_process_fixed_sqlite_heap_budget")
        if readonly:
            self.query(row, "PRAGMA query_only=ON")
        self.query(row, "PRAGMA cache_size=-" + str(SQLITE_CACHE_KIB))
        need(self.query(row, "PRAGMA cache_size", limit=1) == [(-SQLITE_CACHE_KIB,)],
             "fixed_sqlite_connection_cache_budget")
        self.query(row, "PRAGMA mmap_size=0", limit=1)
        need(self.query(row, "PRAGMA mmap_size", limit=1) == [(0,)],
             "whole_database_mmap_disabled")
        self.query(row, "PRAGMA temp_store=MEMORY")
        return row

    def query(self, row, sql, args=(), limit=1024):
        self.remaining()
        cursor = row["db"].cursor()
        row["cursorsOpened"] += 1
        try:
            cursor.execute(sql, args)
            values, returned_bytes = [], 0
            if cursor.description:
                while True:
                    self.remaining()
                    value = cursor.fetchone()
                    if value is None:
                        break
                    need(type(value) is tuple and len(value) <= 16,
                         "bounded_whole_database_sql_columns")
                    for cell in value:
                        need(cell is None or type(cell) in (str, bytes, int, float),
                             "typed_whole_database_sql_scalar")
                        returned_bytes += len(cell.encode()) if type(cell) is str else (
                            len(cell) if type(cell) is bytes else 16)
                    need(returned_bytes <= MAX_METADATA_BYTES and len(values) < limit,
                         "bounded_whole_database_sql_result")
                    values.append(value)
            self.query_bytes_maximum = max(self.query_bytes_maximum, returned_bytes)
            return values
        finally:
            cursor.close()
            row["cursorsClosed"] += 1

    def close_connection(self, row):
        if row["closeAttempts"]:
            return row["closed"]
        row["closeAttempts"] = 1
        try:
            row["db"].close()
            row["closed"] = True
        except BaseException:
            self.failed = True
            raise
        return True

    def _backup_once(self, source, target, pages, *, purpose):
        self.remaining()
        need(source["transaction"] and source["db"].in_transaction,
             "same_fresh_source_read_transaction_still_active")
        record = {"purpose": purpose, "calls": 1, "progressCalls": 0,
                  "pageCount": pages, "remaining": pages, "completed": False,
                  "lastStatus": None}
        self.backup_records.append(record)

        def progress(status, remaining, total):
            record["progressCalls"] += 1
            record["lastStatus"] = status if type(status) is int else None
            self.remaining()
            need(type(status) is int and status in (sqlite3.SQLITE_OK, sqlite3.SQLITE_DONE),
                 "backup_busy_or_error_no_retry")
            need(type(total) is type(remaining) is int and total == pages
                 and remaining == max(0, record["remaining"] - 128),
                 "original_backup_incremental_page_progress_no_restart")
            need(record["progressCalls"] <= (pages + 127) // 128,
                 "original_backup_fixed_number_of_steps")
            record["remaining"] = remaining
            if status == sqlite3.SQLITE_DONE:
                need(remaining == 0, "original_backup_done_at_zero_remaining")
                record["completed"] = True
            else:
                need(remaining > 0, "original_backup_continues_with_remaining_pages")

        source["db"].backup(target["db"], pages=128, progress=progress, sleep=0)
        need(record["completed"] and record["remaining"] == 0,
             "original_backup_completed")
        need(source["transaction"] and source["db"].in_transaction,
             "original_backup_did_not_end_source_transaction")
        return record

    def capture(self, path, expected, *, slot, phase):
        """Two independent outputs from one fresh read transaction, including WAL.

        SQLite's backup API is the source-content copying authority. This
        compares its two complete closed outputs; it does not claim a separate
        direct-source-page or custom WAL decoder as an oracle.
        """
        need(type(slot) is int and 0 <= slot < 6 and phase in ("baseline", "candidate"),
             "closed_six_database_snapshot_slots")
        path = self._path(path)
        archive = self._path(self.root / (phase + "-" + str(slot) + ".sqlite"), archive=True)
        verification = self._path(self.root / (phase + "-" + str(slot) + ".verification.sqlite"), archive=True)
        need(self.namespace(path) == expected, "snapshot_exact_current_generation")
        self.create(archive, b"")
        self.create(verification, b"")
        source, target, verify_target, result = None, None, None, None
        try:
            nonempty = expected["-wal"] is not None and int(expected["-wal"][6]) > 0
            source = self.connect(path, readonly=True, immutable=not nonempty, role=phase + "-source")
            self.query(source, "BEGIN")
            source["transaction"] = True
            self.query(source, "SELECT name FROM sqlite_schema ORDER BY name LIMIT 1025", limit=1024)
            pages = self.query(source, "PRAGMA page_count", limit=1)
            sizes = self.query(source, "PRAGMA page_size", limit=1)
            need(len(pages) == len(sizes) == 1 and len(pages[0]) == len(sizes[0]) == 1
                 and type(pages[0][0]) is int and type(sizes[0][0]) is int
                 and sizes[0][0] in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)
                 and 0 < pages[0][0] * sizes[0][0] <= self.maximum,
                 "whole_snapshot_size_bound_before_backup")
            need(self.namespace(path) == expected, "snapshot_generation_after_begin")
            objects = self.query(source, "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")
            target = self.connect(archive, readonly=False, role=phase + "-archive")
            first_backup = self._backup_once(source, target, pages[0][0], purpose=phase + "-archive")
            # SQLite's backup invalidates statements on the destination by
            # incrementing that empty destination's own schema cookie (0->1).
            # Preserve this expected API behavior; do not write schema_version.
            need(self.query(target, "PRAGMA schema_version", limit=1) == [(1,)],
                 "new_backup_destination_schema_cookie_one")
            need(self.query(target, "PRAGMA integrity_check", limit=1) == [("ok",)],
                 "complete_snapshot_integrity")
            need(objects == self.query(target, "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")
                 and self.query(target, "PRAGMA page_count", limit=1) == pages
                 and self.query(target, "PRAGMA page_size", limit=1) == sizes,
                 "whole_source_and_backup_schema_exact")
            self.close_connection(target)
            need(target["closed"], "first_backup_target_known_closed")
            need(self.namespace(path) == expected, "source_stable_between_two_original_backups")
            verify_target = self.connect(verification, readonly=False, role=phase + "-verification")
            second_backup = self._backup_once(source, verify_target, pages[0][0],
                                               purpose=phase + "-verification")
            need(self.query(verify_target, "PRAGMA schema_version", limit=1) == [(1,)]
                 and self.query(verify_target, "PRAGMA integrity_check", limit=1) == [("ok",)]
                 and self.query(verify_target, "PRAGMA page_count", limit=1) == pages
                 and self.query(verify_target, "PRAGMA page_size", limit=1) == sizes
                 and objects == self.query(verify_target,
                     "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name"),
                 "second_independent_backup_complete_and_integral")
            self.close_connection(verify_target)
            need(verify_target["closed"], "second_backup_target_known_closed")
            need(self.namespace(path) == expected, "snapshot_source_unchanged_before_close")
            self.query(source, "ROLLBACK")
            source["transaction"] = False
            result = {"slot": slot, "phase": phase, "sourcePath": str(path),
                      "sourceNamespace": expected, "archivePath": str(archive),
                      "verificationArchivePath": str(verification), "sqliteObjects": objects,
                      "headerBookkeepingWordsOnlyMayDiffer": True,
                      "freshIndependentTransaction": True, "keeperUsedAsLatestSource": False,
                      "sourceContentCopyAuthority": "sqlite_online_backup_api",
                      "directSourcePageOracleClaimed": False,
                      "twoBackupsUseSameFreshReadTransaction": True,
                      "backupCalls": 2,
                      "backupProgressCalls": first_backup["progressCalls"] + second_backup["progressCalls"]}
        finally:
            close_error = None
            for original in (verify_target, target, source):
                if original is not None:
                    try:
                        self.close_connection(original)
                    except BaseException as caught:
                        if close_error is None:
                            close_error = caught
            if close_error is not None:
                raise close_error
        need(self.namespace(path) == expected, "snapshot_source_unchanged_after_close")
        need(all(not Path(str(file) + suffix).exists()
                 for file in (archive, verification) for suffix in SUFFIXES[1:]),
             "standalone_snapshot_sidecars_absent")
        compared = self.stream_compare_pages(archive, verification)
        need(compared["bytes"] == pages[0][0] * sizes[0][0] and compared["pageSize"] == sizes[0][0],
             "both_closed_backup_outputs_match_original_capacity")
        for file in (archive, verification):
            durable = self.open(file, os.O_RDONLY)
            try:
                os.fsync(durable["fd"])
            finally:
                self.close_fd(durable)
        self.fsync_dir(archive.parent)
        need(compared["leftFull9"] == full9(archive.lstat())
             and compared["rightFull9"] == full9(verification.lstat()),
             "both_closed_backup_outputs_stable_after_durability")
        result.update(archiveFull9=compared["leftFull9"], archiveBytes=compared["bytes"],
                      archiveSha256=compared["leftSha256"], pageImageSha256=compared["pageImageSha256"],
                      verificationArchiveFull9=compared["rightFull9"],
                      verificationArchiveSha256=compared["rightSha256"],
                      twoCompleteBackupOutputsEqual=True)
        self.create(self.root / (phase + "-" + str(slot) + ".private.json"),
                    (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode())
        return result

    def _intent(self, operation, value):
        self.remaining()
        name = "%03d-%s.private.json" % (len(self.steps), operation)
        self.create(self.root / "restore-once" / name,
                    (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())
        self.steps.append({"operation": operation, "completed": False})
        return self.steps[-1]

    def restore(self, baselines, expected_candidates):
        """Offline six-file replacement. Unknown/partial state never auto-resumes.

        Every old source/sidecar remains in quarantine. Hard-link plus unlink
        uses exclusive destination creation, avoiding overwrite-on-rename.
        The outer must keep all consumers stopped across the entire bundle.
        """
        need(not self.restore_started and len(baselines) == len(expected_candidates) == 6,
             "one_complete_six_database_restore")
        need([item["slot"] for item in baselines] == list(range(6)), "ordered_six_snapshot_slots")
        paths = [self._path(item["sourcePath"]) for item in baselines]
        need(len(set(paths)) == 6, "unique_six_restore_paths")
        for path, expected, item in zip(paths, expected_candidates, baselines):
            need(self.namespace(path) == expected, "pre_restore_exact_candidate_generation")
            archive = self._path(item["archivePath"], archive=True)
            original = self.stream_identity(archive, expected=item["archiveFull9"])
            need(original["sha256"] == item["archiveSha256"], "whole_baseline_archive_pin")
        operation = self.root / "restore-once"
        operation.mkdir(mode=0o700, exist_ok=False)
        self.fsync_dir(self.root)
        self.restore_started = True
        # Stage every exact baseline before mutating any source namespace.
        staged = []
        for slot, (path, item) in enumerate(zip(paths, baselines)):
            stage = path.parent / (".hepta-whole-restore-stage-" + str(slot))
            self.stream_copy(Path(item["archivePath"]), stage,
                             expected=item["archiveFull9"], expected_sha256=item["archiveSha256"])
            staged.append(stage)
        for slot, (path, stage, item, expected) in enumerate(zip(paths, staged, baselines, expected_candidates)):
            need(self.namespace(path) == expected, "restore_slot_still_exact_candidate")
            for number, suffix in enumerate(SUFFIXES):
                old = Path(str(path) + suffix)
                if expected[suffix] is None:
                    need(not old.exists(), "restore_expected_name_still_absent")
                    continue
                before = tuple(expected[suffix])
                quarantine = operation / ("old-%d-%d.private" % (slot, number))
                step = self._intent("retain-old", {"slot": slot, "suffix": suffix, "expected": before})
                need(full9(old.lstat()) == before, "restore_old_name_exact_before_link")
                os.link(old, quarantine, follow_symlinks=False)
                linked = full9(old.lstat())
                need(linked == full9(quarantine.lstat()) and stable_after_owned_link(before, linked, 2),
                     "retained_old_inode_exact")
                self.fsync_dir(operation)
                step["completed"] = True
                step = self._intent("retire-old-name", {"slot": slot, "suffix": suffix, "linked": linked})
                need(full9(old.lstat()) == linked == full9(quarantine.lstat()),
                     "old_link_exact_before_unlink")
                os.unlink(old)
                need(not old.exists() and stable_after_owned_link(linked, full9(quarantine.lstat()), 1),
                     "old_name_retired_with_original_retained")
                self.fsync_dir(path.parent)
                step["completed"] = True
            stage_pin = full9(stage.lstat())
            step = self._intent("publish-baseline", {"slot": slot, "stage": stage_pin,
                                                     "archiveSha256": item["archiveSha256"]})
            need(all(not Path(str(path) + suffix).exists() for suffix in SUFFIXES)
                 and self.stream_identity(stage, expected=stage_pin)["sha256"] == item["archiveSha256"],
                 "only_empty_exact_restore_namespace")
            os.link(stage, path, follow_symlinks=False)
            linked = full9(path.lstat())
            need(linked == full9(stage.lstat()) and stable_after_owned_link(stage_pin, linked, 2),
                 "published_baseline_exact_inode")
            self.fsync_dir(path.parent)
            step["completed"] = True
            step = self._intent("retire-stage-name", {"slot": slot, "linked": linked})
            need(full9(stage.lstat()) == linked == full9(path.lstat()), "stage_exact_before_unlink")
            os.unlink(stage)
            self.fsync_dir(path.parent)
            need(self.stream_identity(path)["sha256"] == item["archiveSha256"],
                 "restored_whole_file_exact")
            step["completed"] = True
        final = [self.namespace(path) for path in paths]
        need(all(all(item[suffix] is None for suffix in SUFFIXES[1:]) for item in final),
             "restored_cold_sidecar_names_absent")
        self.create(operation / "complete.private.json",
                    (json.dumps({"newNamespaces": final, "steps": self.steps}, sort_keys=True) + "\n").encode())
        self.restore_complete = True
        return final

    def close(self):
        first_error = None
        for row in reversed(self.connections):
            try:
                self.close_connection(row)
            except BaseException as caught:
                self.close_errors.append("sqlite_close_unknown")
                if first_error is None:
                    first_error = caught
        for row in reversed(self.fds):
            try:
                self.close_fd(row)
            except BaseException as caught:
                self.close_errors.append("file_close_unknown")
                if first_error is None:
                    first_error = caught
        if first_error is not None:
            raise first_error
        need(all(row["closed"] for row in self.connections + self.fds),
             "whole_database_previous_close_unknown")

    def public(self):
        return {"fileDescriptorsOpened": len(self.fds),
                "allFileDescriptorsClosedOnce": all(row["closeAttempts"] == 1 and row["closed"] for row in self.fds),
                "sqliteHandlesOpened": len(self.connections),
                "allSqliteHandlesClosedOnce": all(row["closeAttempts"] == 1 and row["closed"] for row in self.connections),
                "allExplicitCursorsClosed": all(row["cursorsOpened"] == row["cursorsClosed"] for row in self.connections),
                "restoreStarted": self.restore_started, "restoreCompleted": self.restore_complete,
                "restoreOperationCount": len(self.steps),
                "allRestoreOperationsCompleted": all(step["completed"] for step in self.steps),
                "streamBlockByteLimit": STREAM_BLOCK_BYTES,
                "streamOperations": [dict(item) for item in self.stream_records],
                "allStreamOperationsCompleteAndClosed": all(item["completed"]
                    and item["descriptorClosedOnce"] and item["maximumBlockBytes"] <= STREAM_BLOCK_BYTES
                    for item in self.stream_records),
                "maximumSqlResultBytes": self.query_bytes_maximum,
                "sqlResultByteLimit": MAX_METADATA_BYTES,
                "sqliteCacheKibPerHandle": SQLITE_CACHE_KIB,
                "sqliteProcessHeapLimitBytes": SQLITE_HEAP_LIMIT_BYTES,
                "databaseByteLimit": self.maximum,
                "backupCalls": len(self.backup_records),
                "backupSteps": sum(row["progressCalls"] for row in self.backup_records),
                "allOriginalBackupsCompleted": all(row["completed"] for row in self.backup_records),
                "databaseSerializeCalls": 0,
                "directSourcePageOracleClaimed": False,
                "closeErrors": list(self.close_errors),
                "darwinXattrQueryCount": len(self.darwin_xattr_queries),
                "allDarwinXattrQueriesClosedAndAbsent": all(row["returnValue"] == 0 and row["errno"] == 0
                    and row["sameHeldFileBeforeAfter"] and row["descriptorClosedOnce"] for row in self.darwin_xattr_queries),
                "contentValuesOrDigestsPublished": False,
                "productionConsumerQuiescenceEstablishedByThisLibrary": False,
                "providerEpochEstablishedByThisLibrary": False,
                "productionRollbackQualified": False}
