#!/usr/bin/env python3
"""Whole SQLite snapshots and an offline, once-only namespace replacement.

No command line entry point, service actions, provider calls or import-time I/O.
The executable outer owns source admission, all consumer/writer retirement and
the fresh post-provider epoch. This library is not a production actuator by
itself. The first qualification uses only a new synthetic root and complete
schemas extracted from the pinned installed SDK.

The source's current WAL transaction is copied through SQLite's backup API.
An old keeper connection is never accepted as the backup source. All page bytes
are compared, excluding only documented SQLite header bookkeeping words at
24..27, 40..43 and 92..99. The new empty destination's schema cookie must be
exactly 1 after backup, and its complete sqlite_schema must equal the source.
The resulting standalone private archive is then bound by an
exact whole-file SHA256. Restore copies that exact archive, never regenerates
only known tables, and preserves old base/sidecar names in private quarantine.
All content-derived digests and namespace records are private.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import time
from urllib.parse import quote

SUFFIXES = ("", "-wal", "-shm", "-journal")
MIB = 1048576
MAX_DATABASE_BYTES = 64 * MIB
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


def page_image(data, maximum):
    need(isinstance(data, bytes) and 512 <= len(data) <= maximum
         and data[:16] == b"SQLite format 3\x00", "bounded_complete_sqlite_page_image")
    page_size = int.from_bytes(data[16:18], "big")
    page_size = 65536 if page_size == 1 else page_size
    need(512 <= page_size <= 65536 and page_size & (page_size - 1) == 0
         and len(data) % page_size == 0, "whole_sqlite_pages_only")
    normalized = bytearray(data)
    for first, last in BOOKKEEPING_RANGES:
        normalized[first:last] = bytes(last - first)
    return bytes(normalized)


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
        maximum = self.maximum if maximum is None else maximum
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
        need(isinstance(data, bytes) and len(data) <= self.maximum,
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
            need(getattr(info, "st_flags", 0) == 0 and not os.listxattr(name, follow_symlinks=False),
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
        db.set_progress_handler(lambda: int(time.monotonic() >= self.until), 1000)
        if readonly:
            self.query(row, "PRAGMA query_only=ON")
        self.query(row, "PRAGMA temp_store=MEMORY")
        return row

    def query(self, row, sql, args=(), limit=1024):
        self.remaining()
        cursor = row["db"].cursor()
        row["cursorsOpened"] += 1
        try:
            cursor.execute(sql, args)
            values = cursor.fetchmany(limit + 1) if cursor.description else []
            need(len(values) <= limit, "bounded_whole_database_sql_result")
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

    def capture(self, path, expected, *, slot, phase):
        """Copy a fresh independent read transaction, including current WAL."""
        need(type(slot) is int and 0 <= slot < 6 and phase in ("baseline", "candidate"),
             "closed_six_database_snapshot_slots")
        path = self._path(path)
        archive = self._path(self.root / (phase + "-" + str(slot) + ".sqlite"), archive=True)
        need(self.namespace(path) == expected, "snapshot_exact_current_generation")
        self.create(archive, b"")
        source, target, result = None, None, None
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
                 and 0 < pages[0][0] * sizes[0][0] <= self.maximum,
                 "whole_snapshot_size_bound_before_backup")
            need(self.namespace(path) == expected, "snapshot_generation_after_begin")
            target = self.connect(archive, readonly=False, role=phase + "-archive")
            states = []

            def progress(status, remaining, total):
                self.remaining()
                need(status in (sqlite3.SQLITE_OK, sqlite3.SQLITE_DONE),
                     "backup_busy_or_error_no_retry")
                need(type(total) is int and 0 < total <= self.maximum // 512,
                     "bounded_backup_page_count")
                states.append((status, remaining, total))

            source["db"].backup(target["db"], pages=128, progress=progress, sleep=0)
            need(states and states[-1][0] == sqlite3.SQLITE_DONE
                 and states[-1][1] == 0, "original_backup_completed")
            # SQLite's backup invalidates statements on the destination by
            # incrementing that empty destination's own schema cookie (0->1).
            # Preserve this expected API behavior; do not write schema_version.
            need(self.query(target, "PRAGMA schema_version", limit=1) == [(1,)],
                 "new_backup_destination_schema_cookie_one")
            source_image = source["db"].serialize()
            target_image = target["db"].serialize()
            need(page_image(source_image, self.maximum) == page_image(target_image, self.maximum),
                 "complete_snapshot_page_image_matches")
            need(self.query(target, "PRAGMA integrity_check", limit=1) == [("ok",)],
                 "complete_snapshot_integrity")
            objects = self.query(target, "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")
            need(objects == self.query(source, "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name"),
                 "whole_source_and_backup_schema_exact")
            need(self.namespace(path) == expected, "snapshot_source_unchanged_before_close")
            self.query(source, "ROLLBACK")
            source["transaction"] = False
            result = {"slot": slot, "phase": phase, "sourcePath": str(path),
                      "sourceNamespace": expected, "archivePath": str(archive),
                      "sqliteObjects": objects, "pageImageSha256": sha(page_image(source_image, self.maximum)),
                      "headerBookkeepingWordsOnlyMayDiffer": True,
                      "freshIndependentTransaction": True, "keeperUsedAsLatestSource": False,
                      "backupCalls": 1, "backupProgressCalls": len(states)}
        finally:
            close_error = None
            for original in (target, source):
                if original is not None:
                    try:
                        self.close_connection(original)
                    except BaseException as caught:
                        if close_error is None:
                            close_error = caught
            if close_error is not None:
                raise close_error
        need(self.namespace(path) == expected, "snapshot_source_unchanged_after_close")
        need(all(not Path(str(archive) + suffix).exists() for suffix in SUFFIXES[1:]),
             "standalone_snapshot_sidecars_absent")
        raw = self.bytes(archive)
        need(page_image(raw, self.maximum) == page_image(source_image, self.maximum),
             "closed_snapshot_whole_image_matches")
        durable = self.open(archive, os.O_RDONLY)
        try:
            os.fsync(durable["fd"])
        finally:
            self.close_fd(durable)
        self.fsync_dir(archive.parent)
        result.update(archiveFull9=full9(archive.lstat()), archiveBytes=len(raw), archiveSha256=sha(raw))
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
            need(full9(archive.lstat()) == tuple(item["archiveFull9"])
                 and sha(self.bytes(archive)) == item["archiveSha256"], "whole_baseline_archive_pin")
        operation = self.root / "restore-once"
        operation.mkdir(mode=0o700, exist_ok=False)
        self.fsync_dir(self.root)
        self.restore_started = True
        # Stage every exact baseline before mutating any source namespace.
        staged = []
        for slot, (path, item) in enumerate(zip(paths, baselines)):
            stage = path.parent / (".hepta-whole-restore-stage-" + str(slot))
            self.create(stage, self.bytes(Path(item["archivePath"])))
            need(sha(self.bytes(stage)) == item["archiveSha256"], "staged_exact_whole_baseline")
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
                 and sha(self.bytes(stage)) == item["archiveSha256"], "only_empty_exact_restore_namespace")
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
            need(sha(self.bytes(path)) == item["archiveSha256"], "restored_whole_file_exact")
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
                "closeErrors": list(self.close_errors),
                "contentValuesOrDigestsPublished": False,
                "productionConsumerQuiescenceEstablishedByThisLibrary": False,
                "providerEpochEstablishedByThisLibrary": False,
                "productionRollbackQualified": False}
