#!/usr/bin/env python3
"""Read exactly the two observed default Codex candidate files, privately.

No Keychain, SQL, provider, process launch or service action. The four original
process identities and finite selectors are owned by the caller. No candidate
file content, pathname, digest, profile ID or environment value is public.
This observation alone does not grant a current-main3 or writer exclusion.
"""
from __future__ import annotations

import base64
import copy
import os
from pathlib import Path
import stat
import time

import mac_codex_candidate_backend_r1 as classifier

HOME = Path('/Users/qianqi')
SOURCE = HOME / '.codex'
UID, GID = 501, 20
SYSTEM_UID = 0
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
NAMES = ('config.toml', 'auth.json')
MAXIMUM = (1048576, 131072)


class InputsRefused(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise InputsRefused(code)


def full(value):
    return tuple(getattr(value, name) for name in FIELDS)


class FixedCandidateInputs:
    def __init__(self, *, until, source_fence, private_write, clock=time.monotonic):
        need(clock() < until <= clock() + 20 and os.getuid() == UID
             and callable(source_fence) and callable(private_write),
             'candidate_inputs_original_twenty_second_parent')
        self.until, self.clock = until, clock
        self.source_fence, self.private_write = source_fence, private_write
        self.rows, self.directories, self.files, self.absences = [], {}, {}, []
        self.attempted = self.failed = self.closed = False
        self.report = {'schema': 'heptabao.fixed-codex-candidate-inputs.public.r1', 'ok': False,
            'sourceFileOpenAttempts': 0, 'sourceFileContentsRead': 0,
            'authFileContentsRead': False,
            'currentMain3CredentialReads': 0, 'privateCandidateComparisonPerformed': False,
            'keychainAccessed': False, 'higherConfigurationLayersRead': False,
            'sourceMutationCount': 0, 'childCount': 0, 'providerCalls': 0,
            'credentialValuesPathsOrDigestsPublished': False,
            'effectiveRuntimeBackendQualified': False, 'productionRefreshAdmission': False}

    def remaining(self):
        need(not self.closed and not self.failed and self.clock() < self.until,
             'candidate_inputs_original_lifetime')

    def track(self, fd, path):
        row = {'fd': fd, 'path': path, 'closeAttempts': 0, 'closed': False}
        self.rows.append(row)
        return row

    def directory(self, path, *, optional=False):
        self.remaining()
        if path in self.directories:
            self.verify_names()
            return self.directories[path]
        need(path in (*SOURCE.parents, SOURCE), 'candidate_exact_directory_chain')
        parent = None if path == Path('/') else self.directory(path.parent)
        try:
            value = path.lstat() if parent is None else os.stat(path.name,
                dir_fd=parent['fd'], follow_symlinks=False)
        except FileNotFoundError:
            need(optional and path == SOURCE, 'candidate_only_codex_directory_may_be_absent')
            self.absences.append(path)
            return None
        wanted = SYSTEM_UID if path in (Path('/'), Path('/Users')) else UID
        need(stat.S_ISDIR(value.st_mode) and value.st_uid == wanted
             and not stat.S_IMODE(value.st_mode) & 0o022,
             'candidate_private_nonsymlink_owned_directory')
        fd = os.open(str(path) if parent is None else path.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            **({} if parent is None else {'dir_fd': parent['fd']}))
        row = self.track(fd, path)
        need(full(os.fstat(fd)) == full(value), 'candidate_original_directory_name_and_fd')
        row.update(expected=full(value), parent=parent)
        self.directories[path] = row
        self.verify_names()
        return row

    def verify_names(self):
        self.remaining()
        for path, row in self.directories.items():
            named = path.lstat() if row['parent'] is None else os.stat(path.name,
                dir_fd=row['parent']['fd'], follow_symlinks=False)
            need(not row['closeAttempts'] and full(named) == full(os.fstat(row['fd'])) == row['expected'],
                 'candidate_full_source_directory_generation_exact')
        for path in self.absences:
            parent = self.directories[path.parent]
            try:
                os.stat(path.name, dir_fd=parent['fd'], follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise InputsRefused('candidate_source_absence_changed')
        for path, row in self.files.items():
            need(not row['closeAttempts'] and full(os.fstat(row['fd'])) == row['expected']
                 == full(os.stat(path.name, dir_fd=row['parent']['fd'], follow_symlinks=False)),
                 'candidate_full_source_file_generation_exact')

    def whole(self, row, maximum):
        self.remaining()
        expected = row['expected']
        need(0 <= expected[6] <= maximum, 'candidate_exact_initial_read_bound')
        chunks, count = [], 0
        while count <= expected[6]:
            self.remaining()
            block = os.pread(row['fd'], min(65536, expected[6] + 1 - count), count)
            if not block:
                break
            chunks.append(block)
            count += len(block)
        need(count == expected[6], 'candidate_complete_bounded_source_read')
        self.verify_names()
        return b''.join(chunks)

    def capture(self, selections):
        need(not self.attempted and type(selections) is list and len(selections) == 4,
             'candidate_fixed_four_capture_once')
        self.attempted = True
        try:
            self.remaining(); self.source_fence()
            for item in selections:
                need(classifier.fixed_candidate_paths(item) == tuple(str(SOURCE / name) for name in NAMES),
                     'candidate_four_current_selectors_same_exact_default_scope')
            parent = self.directory(SOURCE, optional=True)
            raw_values = []
            for ordinal, name in enumerate(NAMES):
                path = SOURCE / name
                if parent is None:
                    raw_values.append(None)
                    continue
                try:
                    named = os.stat(name, dir_fd=parent['fd'], follow_symlinks=False)
                except FileNotFoundError:
                    self.absences.append(path); raw_values.append(None)
                    continue
                self.report['sourceFileOpenAttempts'] += 1
                need(stat.S_ISREG(named.st_mode) and named.st_uid == UID and named.st_gid == GID
                     and named.st_nlink == 1 and not stat.S_IMODE(named.st_mode) & 0o022
                     and (ordinal == 0 or stat.S_IMODE(named.st_mode) == 0o600)
                     and 0 <= named.st_size <= MAXIMUM[ordinal], 'candidate_exact_owned_source_file')
                row = self.track(os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=parent['fd']), path)
                need(full(named) == full(os.fstat(row['fd'])), 'candidate_opened_original_named_inode')
                row.update(expected=full(named), parent=parent, ordinal=ordinal)
                self.files[path] = row
                row['raw'] = self.whole(row, MAXIMUM[ordinal])
                raw_values.append(row['raw'])
                self.report['sourceFileContentsRead'] += 1
                if ordinal == 1:
                    self.report['authFileContentsRead'] = True
            self.verify()
            packet = {'schema': 'heptabao.fixed-codex-candidate-files.private.r1',
                'originalParentPid': os.getpid(), 'candidateDirectory': str(SOURCE),
                'sourceDirectoryIdentities': {str(path): row['expected'] for path, row in self.directories.items()},
                'sourceAbsences': list(map(str, self.absences)),
                'files': [{'path': str(SOURCE / name), 'identity': self.files[SOURCE / name]['expected']
                           if SOURCE / name in self.files else None,
                           'bytesBase64': None if raw is None else base64.b64encode(raw).decode('ascii')}
                          for name, raw in zip(NAMES, raw_values)],
                'candidateContentsParsedAtPublication': False,
                'effectiveRuntimeBackendQualified': False, 'currentMain3ComparisonPerformed': False}
            self.private_write('candidate-files.private.json', packet)
            self.report['candidateCopiesDurablyStoredPrivately'] = True
            self.verify(); self.source_fence()
            # Keep the bounded original bytes privately before parsing them.
            # A fixed safe diagnostic can then inspect this original attempt
            # without rereading a changed live source after a format refusal.
            configurations = [classifier.configuration_view(raw_values[0], value) for value in selections]
            auth_shape = {'candidateAuthPresent': raw_values[1] is not None, 'refreshFieldPresent': False}
            if raw_values[1] is not None:
                auth = classifier.strict_json(raw_values[1])
                tokens = auth.get('tokens')
                need(tokens is None or type(tokens) is dict, 'candidate_current_tokens_shape')
                refresh = tokens.get('refresh_token') if type(tokens) is dict else None
                need(refresh is None or type(refresh) is str and len(refresh.encode('utf-8')) <= 131072,
                     'candidate_current_refresh_shape')
                auth_shape.update(refreshFieldPresent=bool(refresh), authModeDeclared='auth_mode' in auth,
                    apiKeyFieldPresent=bool(auth.get('OPENAI_API_KEY')), agentIdentityFieldPresent=bool(auth.get('agent_identity')))
            self.report.update(ok=True, distinctDefaultCandidateDirectoryCount=1,
                selectedProcessesCovered=4, candidateConfigurationViews=configurations,
                candidateAuthShape=auth_shape, sourceGenerationsAndCompleteBytesVerified=True,
                candidateCopiesDurablyStoredPrivately=True, allSourceDescriptorsStillHeld=True)
            return copy.deepcopy(self.report)
        except BaseException:
            self.failed = True
            raise

    def verify(self):
        self.remaining(); self.source_fence(); self.verify_names()
        for row in self.files.values():
            need(self.whole(row, MAXIMUM[row['ordinal']]) == row['raw'],
                 'candidate_complete_source_bytes_unchanged')
        self.verify_names()
        return True

    def close(self):
        errors = []
        if not self.closed:
            for row in reversed(self.rows):
                if row['closeAttempts']:
                    continue
                row['closeAttempts'] = 1
                try:
                    os.close(row['fd']); row['closed'] = True
                except BaseException:
                    errors.append('candidate_descriptor_close_failed')
            self.closed = True
        self.report.update(allSourceDescriptorsStillHeld=False,
            sourceDescriptorClosures=[{'closeAttempts': row['closeAttempts'], 'closed': row['closed']} for row in self.rows],
            sourceDescriptorCount=len(self.rows), allSourceDescriptorsClosedOnce=all(
                row['closeAttempts'] == 1 and row['closed'] for row in self.rows), closeErrors=errors)
        if self.report['ok'] and not errors:
            try:
                need(self.clock() < self.until, 'candidate_close_within_original_deadline')
                for path, row in (*self.directories.items(), *self.files.items()):
                    need(full(path.lstat()) == row['expected'], 'candidate_closed_source_name_generation_exact')
                for path in self.absences:
                    try:
                        path.lstat()
                    except FileNotFoundError:
                        continue
                    raise InputsRefused('candidate_closed_source_absence_changed')
                self.source_fence()
                self.report['closedSourceNamesStillExact'] = True
            except BaseException:
                self.report['closedSourceNamesStillExact'] = False
                self.report['ok'] = False
        if errors or not self.report['allSourceDescriptorsClosedOnce']:
            self.report['ok'] = False
        return copy.deepcopy(self.report)
