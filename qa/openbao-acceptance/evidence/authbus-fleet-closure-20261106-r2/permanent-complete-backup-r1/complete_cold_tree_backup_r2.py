"""Copy every file of one stopped encrypted store under a directory writer lock.

No service, command, network, JSON credential parser, exclusion pattern or
source mutation exists here. The caller binds the fixed source/destination and
retains the returned manifest privately, outside the copied data directory.
The manifest is required to restore; an incomplete destination is never reused.
"""
from __future__ import annotations

from contextlib import nullcontext
import fcntl
import hashlib
import os
from pathlib import Path
import stat


class BackupRefused(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise BackupRefused(code)


def identity(info):
    return tuple(str(getattr(info, name)) for name in ('st_dev', 'st_ino', 'st_uid',
        'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


class CompleteColdCopy:
    """An original source generation, one new destination, no resume or retry."""

    def __init__(self, source, destination, *, check, critical=nullcontext,
                 expected_manifest=None, public_executables=None, max_files=4096, max_directories=256,
                 max_file_bytes=128 * 1024 * 1024, max_total_bytes=1024 * 1024 * 1024):
        self.source, self.destination = Path(source), Path(destination)
        need(self.source.is_absolute() and self.destination.is_absolute()
             and self.source != self.destination
             and self.source not in self.destination.parents
             and self.destination not in self.source.parents, 'disjoint_absolute_copy_roots')
        need(callable(check) and callable(critical), 'explicit_caller_custody_callbacks')
        self.check, self.critical = check, critical
        self.expected = expected_manifest
        self.public_executables = dict(public_executables or {})
        need(len(self.public_executables) <= 1 and all(
            isinstance(name, str) and name and not name.startswith('/')
            and all(part not in ('', '.', '..') for part in name.split('/'))
            and type(pin) is tuple and len(pin) == 2 and type(pin[0]) is int
            and 0 < pin[0] <= 128 * 1024 * 1024 and isinstance(pin[1], str)
            and len(pin[1]) == 64 and all(c in '0123456789abcdef' for c in pin[1])
            for name, pin in self.public_executables.items()), 'one_explicit_public_executable_pin')
        self.max_files, self.max_dirs = max_files, max_directories
        self.max_file, self.max_total = max_file_bytes, max_total_bytes
        need(1 <= max_files <= 4096 and 1 <= max_directories <= 256
             and 1 <= max_file_bytes <= 128 * 1024 * 1024
             and 1 <= max_total_bytes <= 1024 * 1024 * 1024, 'finite_backup_limits')
        self.fds, self.parents, self.source_dirs, self.dest_dirs = [], [], {}, {}
        self.entries, self.children = {}, {}
        self.total = 0
        self.lock_fd = None
        self.destination_lock_fd = None
        self.used = False
        self.result = {'schema': 'heptabao.complete-cold-copy-public.r2', 'ok': False,
            'sourceWrites': 0, 'sourceFilesExcluded': 0, 'automaticRetry': False,
            'destinationReused': False, 'readBlockBytes': 1048576,
            'directoryWriterLockHeldDuringAllCopies': False,
            'sameWriterLockAsActualServerQualified': False,
            'cryptographicRestoreQualified': False, 'manifestPublic': False}

    def opened(self, name, flags, *, parent=None, mode=0o600):
        self.check()
        with self.critical():
            fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                mode, **({} if parent is None else {'dir_fd': parent}))
            row = {'fd': fd, 'attempts': 0, 'closed': False}
            self.fds.append(row)
        return row

    def close(self, row):
        if row['attempts']:
            return
        with self.critical():
            row['attempts'] = 1
            os.close(row['fd'])
            row['closed'] = True

    def open_chain(self, path):
        need(path.is_absolute() and all(part not in ('.', '..') for part in path.parts[1:]),
             'canonical_absolute_parent_chain')
        parent = None
        current = Path('/')
        for part in ('/', *path.parts[1:]):
            if part != '/':
                current = current / part
            row = self.opened(part, os.O_RDONLY | os.O_DIRECTORY,
                              parent=None if parent is None else parent['fd'])
            info = os.fstat(row['fd'])
            need(stat.S_ISDIR(info.st_mode) and identity(info) == identity(current.lstat()),
                 'same_nofollow_parent_directory')
            self.parents.append((current, row, identity(info)[:5]))
            parent = row
        return parent

    def parents_unchanged(self):
        self.check()
        for path, row, stamp in self.parents:
            need(identity(path.lstat())[:5] == identity(os.fstat(row['fd']))[:5] == stamp,
                 'held_parent_namespace_changed')

    @staticmethod
    def private_directory(info):
        return stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() \
            and info.st_gid == os.getegid() and stat.S_IMODE(info.st_mode) == 0o700

    @staticmethod
    def private_file(info):
        return stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() \
            and info.st_gid == os.getegid() and info.st_nlink == 1 \
            and stat.S_IMODE(info.st_mode) in (0o400, 0o600)

    def scan(self, relative, row, depth=0):
        self.check()
        need(depth <= 8 and len(self.source_dirs) < self.max_dirs, 'bounded_data_tree_depth_and_directories')
        before = os.fstat(row['fd'])
        need(self.private_directory(before), 'private_source_directory')
        self.source_dirs[relative] = (row, identity(before))
        names = sorted(os.listdir(row['fd']))
        need(len(names) <= self.max_files + self.max_dirs, 'bounded_directory_entries')
        need(all(isinstance(name, str) and name not in ('', '.', '..')
                 and '/' not in name and '\x00' not in name
                 and len(name.encode('utf-8', errors='strict')) <= 240 for name in names),
             'bounded_plain_relative_leaf_names')
        self.children[relative] = names
        for name in names:
            self.check()
            selected = name if relative == '' else relative + '/' + name
            info = os.stat(name, dir_fd=row['fd'], follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = self.opened(name, os.O_RDONLY | os.O_DIRECTORY, parent=row['fd'])
                need(identity(info) == identity(os.fstat(child['fd'])), 'source_subdirectory_open_identity')
                self.scan(selected, child, depth + 1)
            else:
                public_executable = selected in self.public_executables
                executable_ok = public_executable and stat.S_ISREG(info.st_mode) \
                    and info.st_uid == os.geteuid() and info.st_gid == os.getegid() \
                    and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o500 \
                    and info.st_size == self.public_executables[selected][0]
                need(executable_ok if public_executable else self.private_file(info),
                     'private_data_or_explicit_pinned_public_executable')
                need(len(self.entries) < self.max_files and 0 <= info.st_size <= self.max_file,
                     'bounded_data_file_count_and_size')
                self.total += info.st_size
                need(self.total <= self.max_total, 'bounded_complete_tree_bytes')
                self.entries[selected] = {'sourceIdentity': identity(info), 'bytes': info.st_size,
                    'mode': stat.S_IMODE(info.st_mode), 'parent': relative, 'name': name}
        need(identity(before) == identity(os.fstat(row['fd'])), 'source_directory_changed_during_scan')

    def source_unchanged(self):
        self.parents_unchanged()
        for relative, (row, before) in self.source_dirs.items():
            need(identity(os.fstat(row['fd'])) == before and sorted(os.listdir(row['fd'])) == self.children[relative],
                 'complete_source_directory_generation_changed')
            if relative:
                parent, _, name = relative.rpartition('/')
                need(identity(os.stat(name, dir_fd=self.source_dirs[parent][0]['fd'], follow_symlinks=False)) == before,
                     'source_directory_name_changed')
        for entry in self.entries.values():
            parent = self.source_dirs[entry['parent']][0]['fd']
            need(identity(os.stat(entry['name'], dir_fd=parent, follow_symlinks=False)) == entry['sourceIdentity'],
                 'source_file_generation_changed')

    def create_directory(self, relative, parent, name):
        self.parents_unchanged()
        self.check()
        with self.critical():
            os.mkdir(name, 0o700, dir_fd=parent['fd'])
        row = self.opened(name, os.O_RDONLY | os.O_DIRECTORY, parent=parent['fd'])
        info = os.fstat(row['fd'])
        need(self.private_directory(info) and identity(info) == identity(os.stat(name, dir_fd=parent['fd'], follow_symlinks=False)),
             'new_private_destination_directory')
        os.fsync(row['fd']); os.fsync(parent['fd'])
        self.dest_dirs[relative] = (row, identity(info)[:5], parent, name)

    def destination_unchanged(self):
        self.parents_unchanged()
        for row, first5, parent, name in self.dest_dirs.values():
            need(identity(os.fstat(row['fd']))[:5] == first5
                 == identity(os.stat(name, dir_fd=parent['fd'], follow_symlinks=False))[:5],
                 'destination_directory_namespace_changed')
        for entry in self.entries.values():
            if 'destinationIdentity' in entry:
                parent = self.dest_dirs[entry['parent']][0]['fd']
                need(identity(os.stat(entry['name'], dir_fd=parent, follow_symlinks=False))
                     == entry['destinationIdentity'], 'completed_destination_file_changed')

    def copy_file(self, relative, entry):
        self.source_unchanged(); self.destination_unchanged()
        source_parent = self.source_dirs[entry['parent']][0]['fd']
        destination_parent = self.dest_dirs[entry['parent']][0]['fd']
        source = self.opened(entry['name'], os.O_RDONLY, parent=source_parent)
        target = None
        try:
            need(identity(os.fstat(source['fd'])) == entry['sourceIdentity'], 'original_open_source_file')
            target = self.opened(entry['name'], os.O_WRONLY | os.O_CREAT | os.O_EXCL, parent=destination_parent)
            info = os.fstat(target['fd'])
            need(self.private_file(info) and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == 0,
                 'new_empty_private_copy_file')
            created = identity(info)[:6]
            digest, copied = hashlib.sha256(), 0
            while True:
                self.check()
                block = os.read(source['fd'], min(1048576, entry['bytes'] + 1 - copied))
                if not block:
                    break
                copied += len(block)
                need(copied <= entry['bytes'], 'source_file_size_increased')
                digest.update(block)
                offset = 0
                while offset < len(block):
                    self.check()
                    count = os.write(target['fd'], block[offset:])
                    need(count > 0, 'destination_copy_write_progress')
                    offset += count
            need(copied == entry['bytes'] and identity(os.fstat(source['fd'])) == entry['sourceIdentity'],
                 'original_source_complete_unchanged_bytes')
            os.fsync(target['fd'])
            before_chmod = os.fstat(target['fd'])
            need(identity(before_chmod)[:6] == created and before_chmod.st_size == copied,
                 'original_destination_file_identity')
            os.fchmod(target['fd'], entry['mode']); os.fsync(target['fd']); os.fsync(destination_parent)
            final = identity(os.fstat(target['fd']))
            need(final == identity(os.stat(entry['name'], dir_fd=destination_parent, follow_symlinks=False)),
                 'same_complete_destination_name')
            if relative in self.public_executables:
                need((copied, digest.hexdigest()) == self.public_executables[relative],
                     'complete_public_executable_source_pin')
            entry['sha256'] = digest.hexdigest()
            entry['destinationIdentity'] = final
        finally:
            if target is not None:
                self.close(target)
            self.close(source)
        reread = self.opened(entry['name'], os.O_RDONLY, parent=destination_parent)
        try:
            need(identity(os.fstat(reread['fd'])) == entry['destinationIdentity'], 'reopened_exact_destination_file')
            digest, count = hashlib.sha256(), 0
            while True:
                self.check()
                block = os.read(reread['fd'], min(1048576, entry['bytes'] + 1 - count))
                if not block:
                    break
                count += len(block); digest.update(block)
                need(count <= entry['bytes'], 'destination_readback_size')
            need(count == entry['bytes'] and digest.hexdigest() == entry['sha256']
                 and identity(os.fstat(reread['fd'])) == entry['destinationIdentity'],
                 'complete_destination_readback_exact')
        finally:
            self.close(reread)
        self.source_unchanged(); self.destination_unchanged()

    def manifest(self):
        return {'schema': 'heptabao.complete-cold-encrypted-tree-manifest.r1',
            'sourceDirectoryIdentity': self.source_dirs[''][1],
            'directories': [{'path': relative, 'mode': 0o700} for relative in sorted(self.source_dirs)],
            'files': [{'path': relative, 'bytes': row['bytes'], 'mode': row['mode'], 'sha256': row['sha256']}
                      for relative, row in sorted(self.entries.items())],
            'completeFileCount': len(self.entries), 'completeBytes': self.total,
            'sourceFilesExcluded': 0, 'keyMaterialClaim': 'Caller-selected private runtime tree; seal/unseal custody is separate and required.',
            'allCopiedFilesSyncedAndReadBack': True, 'cryptographicAdmissionClaim': False}

    def run(self):
        need(not self.used, 'one_original_copy_attempt')
        self.used = True
        manifest = None
        error = None
        try:
            source = self.open_chain(self.source)
            need(self.private_directory(os.fstat(source['fd'])), 'original_private_source_root')
            with self.critical():
                fcntl.flock(source['fd'], fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.lock_fd = source
            self.result['directoryWriterLockHeldDuringAllCopies'] = True
            self.scan('', source)
            need(self.entries, 'complete_encrypted_store_not_empty')
            need(set(self.public_executables).issubset(self.entries), 'every_pinned_executable_present')
            self.source_unchanged()
            parent = self.open_chain(self.destination.parent)
            need(self.private_directory(os.fstat(parent['fd'])), 'private_destination_parent')
            # The only admissible publication creates a new root. Existing
            # complete or partial output is never removed or overwritten.
            self.create_directory('', parent, self.destination.name)
            with self.critical():
                fcntl.flock(self.dest_dirs[''][0]['fd'], fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.destination_lock_fd = self.dest_dirs[''][0]
            self.result['destinationDirectoryLockHeldDuringAllCopies'] = True
            for relative in sorted(self.source_dirs, key=lambda value: (value.count('/'), value)):
                if not relative:
                    continue
                parent_relative, _, name = relative.rpartition('/')
                self.create_directory(relative, self.dest_dirs[parent_relative][0], name)
            for relative, entry in sorted(self.entries.items()):
                self.copy_file(relative, entry)
            for row, _, _, _ in reversed(list(self.dest_dirs.values())):
                os.fsync(row['fd'])
            self.source_unchanged(); self.destination_unchanged()
            for relative, (row, _, _, _) in self.dest_dirs.items():
                need(sorted(os.listdir(row['fd'])) == self.children[relative], 'complete_destination_namespace_exact')
            manifest = self.manifest()
            if self.expected is not None:
                need(isinstance(self.expected, dict) and self.expected.get('schema') == manifest['schema']
                     and self.expected.get('sourceFilesExcluded') == 0
                     and self.expected.get('allCopiedFilesSyncedAndReadBack') is True
                     and all(self.expected.get(key) == manifest[key] for key in
                         ('directories', 'files', 'completeFileCount', 'completeBytes')),
                     'restored_complete_manifest_exact')
            self.result.update(ok=True, copiedFiles=len(self.entries), copiedDirectories=len(self.source_dirs),
                copiedBytes=self.total, completeNamespaceAndReadbackExact=True)
        except BaseException as caught:
            error = caught
        finally:
            close_errors = []
            for row in reversed(self.fds):
                try:
                    self.close(row)
                except BaseException:
                    close_errors.append('descriptor_close_failed')
            self.result.update(explicitDescriptors=len(self.fds), closeErrors=close_errors,
                allDescriptorsClosedOnce=all(row['attempts'] == 1 and row['closed'] for row in self.fds),
                originalDirectoryLockReleased=self.lock_fd is None or self.lock_fd['closed'],
                destinationDirectoryLockReleased=self.destination_lock_fd is None or self.destination_lock_fd['closed'])
            self.result['ok'] = bool(self.result['ok'] and not close_errors
                and self.result['allDescriptorsClosedOnce'] and self.result['originalDirectoryLockReleased']
                and self.result['destinationDirectoryLockReleased'])
            if error is not None:
                self.result['errorType'] = type(error).__name__
                self.result['errorCode'] = str(error) if isinstance(error, BackupRefused) else 'original_copy_refused'
            if not self.result['ok'] and error is None:
                error = BackupRefused('original_copy_closure_incomplete')
        if error is not None:
            raise error
        return manifest
