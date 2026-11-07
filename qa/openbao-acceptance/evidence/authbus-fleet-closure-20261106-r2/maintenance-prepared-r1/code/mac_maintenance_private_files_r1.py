#!/usr/bin/env python3
"""Fixed private records for one original maintenance parent, without retries."""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import time

ROOT = Path('/Users/qianqi/heptabao-authbus-writer-maintenance-20261106-r1')
LEDGER = Path('/Users/qianqi/heptabao-authbus-refresh-once-ledger-20261106')
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
RECORDS = frozenset(('intent.private.json', 'dispatch-unknown.private.json',
    'provider-response.private.bin', 'provider-response.private.json',
    'normalized-credential.private.json', 'outcome.private.json'))


class PrivateFilesRefused(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise PrivateFilesRefused(code)


def full(value):
    return tuple(getattr(value, key) for key in FIELDS)


class MaintenancePrivateFiles:
    def __init__(self, *, until, source_fence, clock=time.monotonic):
        need(clock() < until <= clock() + 600 and callable(source_fence) and os.getuid() == 501,
             'private_files_original_owner_and_deadline')
        self.until, self.source_fence, self.clock = until, source_fence, clock
        # Declared once with the original business deadline. This narrow
        # interval records only already-finished child cleanup, never another
        # provider/launch/service/CAS intent. The outer supervisor includes it.
        self.cleanup_until, self.in_closure = until + 15, False
        self.rows, self.parents, self.consumed, self.observations = [], {}, set(), {}
        self.closed = self.failed = False
        self.report = {'schema': 'heptabao.maintenance-private-files.public.r1',
            'privateValuesPathsOrDigestsPublished': False, 'sourceDatabaseReads': 0,
            'fileCreateAttempts': 0, 'fileFsyncs': 0, 'directoryFsyncs': 0,
            'completeWholeReads': 0, 'automaticRetries': 0}

    def within(self):
        need(not self.closed and self.clock() < (self.cleanup_until if self.in_closure else self.until),
             'private_files_original_deadline')

    def track(self, fd, path):
        row = {'fd': fd, 'path': path, 'closeAttempts': 0, 'closed': False}
        self.rows.append(row)
        row['identity'] = full(os.fstat(fd))
        return row

    def close_one(self, row):
        need(row['closeAttempts'] == 0, 'private_files_original_close_once')
        row['closeAttempts'] += 1
        try:
            os.close(row['fd'])
            row['closed'] = True
        except BaseException:
            self.failed = True
            raise

    def directory(self, path):
        self.within()
        if path in self.parents:
            self.verify_parents()
            return self.parents[path]
        if path == path.parent:
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        else:
            parent = self.directory(path.parent)
            descriptor = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent['fd'])
        row = self.track(descriptor, path)
        value = os.fstat(descriptor)
        need(stat.S_ISDIR(value.st_mode) and value.st_uid in (0, 501)
             and not stat.S_IMODE(value.st_mode) & 0o022 and full(value) == full(path.lstat()),
             'private_files_nonalias_original_directory_chain')
        if path == ROOT or ROOT in path.parents or path == LEDGER or LEDGER in path.parents:
            need(value.st_uid == 501 and value.st_gid == 20 and stat.S_IMODE(value.st_mode) == 0o700,
                 'private_files_staged_private_directory')
        self.parents[path] = row
        self.verify_parents()
        return row

    def verify_parents(self):
        self.within()
        for path, row in self.parents.items():
            # Only these staged maintenance/ledger subtrees receive our own
            # create-only records. No production source directory is rebased.
            width = 5 if path == ROOT or ROOT in path.parents or path == LEDGER or LEDGER in path.parents else 9
            need(not row['closeAttempts'] and full(os.fstat(row['fd']))[:width]
                 == row['identity'][:width] == full(path.lstat())[:width],
                 'private_files_same_held_named_parent')

    def read_allowed(self, path):
        if path == LEDGER / 'scope.private.json':
            return True
        for ordinal in range(1, 4):
            if path == ROOT / 'captures' / ('owner-0%d' % ordinal) / 'output/selected-owner-credentials.private.json':
                return True
            if path.parent == LEDGER / ('owner-0%d' % ordinal) and path.name in RECORDS:
                return True
        return False

    def read(self, filename, maximum, *, expected=None):
        path = Path(filename)
        need(self.read_allowed(path) and path.is_absolute() and str(path) == os.path.normpath(str(path))
             and type(maximum) is int and 0 < maximum <= 2 * 1048576,
             'private_files_exact_read_scope')
        self.within()
        self.source_fence()
        parent = self.directory(path.parent)
        row = self.track(os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 dir_fd=parent['fd']), path)
        try:
            before = os.fstat(row['fd'])
            need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_gid == 20
                 and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                 and 0 <= before.st_size <= maximum and full(before) == full(path.lstat()),
                 'private_files_existing_owned_record')
            if expected is not None:
                need(full(before) == tuple(map(int, expected)), 'private_files_expected_whole_generation')
            chunks, count = [], 0
            while count <= before.st_size:
                self.within()
                block = os.read(row['fd'], min(65536, before.st_size + 1 - count))
                if not block:
                    break
                chunks.append(block)
                count += len(block)
            need(count == before.st_size and full(os.fstat(row['fd'])) == full(before) == full(path.lstat()),
                 'private_files_complete_named_whole_read')
            self.verify_parents()
            raw = b''.join(chunks)
            prior = self.observations.get(path)
            need(prior is None or prior == (full(before), raw), 'private_files_original_record_never_rebound')
            self.observations[path] = (full(before), raw)
            self.report['completeWholeReads'] += 1
            return raw
        finally:
            self.close_one(row)

    def write(self, name, raw):
        return self._write(name, raw, closure=False)

    def write_closure(self, name, raw):
        need(re.fullmatch(r'owner-0[123]\.original[.-](?:stdout\.private|stderr\.private|custody\.private\.json)', name)
             and ROOT / 'output' in self.parents,
             'private_files_only_original_closure_artifacts_after_business')
        return self._write(name, raw, closure=True)

    def _write(self, name, raw, *, closure):
        need(not self.failed and isinstance(name, str) and re.fullmatch(r'[a-z0-9.-]{1,180}', name)
             and name not in self.consumed and isinstance(raw, bytes) and len(raw) <= 2 * 1048576,
             'private_files_create_once_fixed_output')
        self.in_closure = closure
        try:
            self.within()
            if not closure:
                self.source_fence()
            return self._write_original(name, raw)
        finally:
            self.in_closure = False

    def _write_original(self, name, raw):
        self.consumed.add(name)
        parent = self.directory(ROOT / 'output')
        path = ROOT / 'output' / name
        self.report['fileCreateAttempts'] += 1
        row = self.track(os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=parent['fd']), path)
        try:
            before = os.fstat(row['fd'])
            need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_gid == 20
                 and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1,
                 'private_files_created_owned_record')
            view = memoryview(raw)
            while view:
                self.within()
                count = os.write(row['fd'], view)
                need(count > 0, 'private_files_original_write_progress')
                view = view[count:]
            os.fsync(row['fd'])
            self.report['fileFsyncs'] += 1
            after = full(os.fstat(row['fd']))
            need(after[:6] == full(before)[:6] and after[6] == len(raw)
                 and os.pread(row['fd'], len(raw) + 1, 0) == raw
                 and full(os.fstat(row['fd'])) == after == full(path.lstat()),
                 'private_files_durable_whole_record_readback')
            os.fsync(parent['fd'])
            self.report['directoryFsyncs'] += 1
            self.verify_parents()
        except BaseException:
            self.failed = True
            raise
        finally:
            self.close_one(row)

    def close(self):
        if self.closed:
            return self.report
        errors = []
        for row in reversed(self.rows):
            if not row['closeAttempts']:
                try:
                    self.close_one(row)
                except BaseException as error:
                    errors.append(type(error).__name__)
        self.closed = True
        self.report.update(originalDescriptorsOpened=len(self.rows), closeErrorTypes=errors,
            allOriginalDescriptorsClosedOnce=all(row['closed'] and row['closeAttempts'] == 1 for row in self.rows))
        return self.report
