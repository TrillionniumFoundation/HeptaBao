#!/usr/bin/env python3
"""Compare only timestamps already held in the successful R2 private artifacts.

No live credential/config/database source is opened. No child, SQL, network,
service, or signal-to-consumer action. Times and source values remain private.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time

ROOT = Path('/Users/qianqi/heptabao-authbus-current-main3-candidate-relation-20261107-r2')
OUTPUT = ROOT / 'output'
NAMES = ('candidate-files.private.json', 'selectors-first.private.json', 'selectors-second.private.json')
LIMITS = (2097152, 131072, 131072)
SOURCE = Path('/Users/qianqi/.codex')
PIDS = (66414, 66687, 89324, 89325)
EXPECTED_BIRTHS = ((1793754254, 283080), (1793754286, 107754),
                   (1793690098, 48673), (1793690098, 720405))
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
START = time.monotonic()
UNTIL = START + 20
rows, directories, files, signals = [], {}, {}, []
report = {'schema': 'heptabao.current-main3-candidate-original-time-relations.public.r1',
          'ok': False, 'originalJobId': '1a1b4214deb-fc05-8668',
          'originalEvidenceMap': 'ffc935445ca0a8c51991fe03c20cae71e0b11f31',
          'privateArtifactsRead': 0, 'liveSourceReads': 0, 'sqlQueries': 0,
          'childProcesses': 0, 'providerCalls': 0, 'serviceActions': 0,
          'productionWrites': 0, 'consumerSignals': 0, 'automaticRetry': False,
          'rawTimesIdsPathsValuesOrDigestsPublished': False,
          'timestampOrderProvesCredentialIssuance': False,
          'timestampOrderProvesRuntimeRead': False,
          'effectiveBackendQualified': False, 'cachedCredentialRelation': 'unknown',
          'productionRefreshAdmission': False, 'maximumSeconds': 20}


class Refused(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def remaining():
    need(not signals and time.monotonic() < UNTIL, 'original_projection_deadline_or_signal')


def full(value):
    return tuple(getattr(value, name) for name in FIELDS)


def track(fd):
    row = {'fd': fd, 'closeAttempts': 0, 'closed': False}
    rows.append(row)
    return row


def verify():
    remaining()
    for path, row in (*directories.items(), *files.items()):
        named = path.lstat() if row['parent'] is None else os.stat(
            path.name, dir_fd=row['parent']['fd'], follow_symlinks=False)
        need(row['closeAttempts'] == 0 and full(named) == full(os.fstat(row['fd'])) == row['expected'],
             'original_private_artifact_namespace_exact')


def directory(path):
    remaining()
    need(path in (OUTPUT, *OUTPUT.parents), 'original_fixed_private_parent_scope')
    if path in directories:
        return directories[path]
    parent = None if path == Path('/') else directory(path.parent)
    named = path.lstat() if parent is None else os.stat(path.name,
        dir_fd=parent['fd'], follow_symlinks=False)
    uid = 0 if path in (Path('/'), Path('/Users')) else 501
    need(stat.S_ISDIR(named.st_mode) and named.st_uid == uid
         and not stat.S_IMODE(named.st_mode) & 0o022, 'original_private_parent_custody')
    row = track(os.open(str(path) if parent is None else path.name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        **({} if parent is None else {'dir_fd': parent['fd']})))
    need(full(named) == full(os.fstat(row['fd'])), 'original_private_parent_open_identity')
    row.update(parent=parent, expected=full(named))
    directories[path] = row
    verify()
    return row


def whole(row):
    remaining()
    count, chunks = 0, []
    while count <= row['expected'][6]:
        remaining()
        block = os.pread(row['fd'], min(65536, row['expected'][6] + 1 - count), count)
        if not block:
            break
        count += len(block)
        chunks.append(block)
    need(count == row['expected'][6], 'original_private_artifact_complete_bounded_read')
    verify()
    return b''.join(chunks)


def read(name, maximum):
    need(name in NAMES, 'original_exact_private_artifact')
    parent = directory(OUTPUT)
    named = os.stat(name, dir_fd=parent['fd'], follow_symlinks=False)
    need(stat.S_ISREG(named.st_mode) and named.st_uid == 501 and named.st_gid == 20
         and stat.S_IMODE(named.st_mode) == 0o600 and named.st_nlink == 1
         and 0 < named.st_size <= maximum, 'original_private_artifact_custody_and_bound')
    row = track(os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=parent['fd']))
    need(full(named) == full(os.fstat(row['fd'])), 'original_private_artifact_open_identity')
    row.update(parent=parent, expected=full(named))
    files[OUTPUT / name] = row
    row['raw'] = whole(row)
    report['privateArtifactsRead'] += 1
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'original_duplicate_private_json_key')
            value[key] = item
        return value
    def nonfinite(_):
        raise Refused('original_nonfinite_private_json')
    value = json.loads(row['raw'].decode('utf-8', 'strict'),
                       object_pairs_hook=pairs, parse_constant=nonfinite)
    need(type(value) is dict, 'original_private_json_object')
    return value


def identity(value):
    need(type(value) is list and len(value) == 9
         and all(type(v) is int and v >= 0 for v in value), 'recorded_full9_shape')
    return value


def relation(value, birth):
    return 'before' if value < birth else 'after' if value > birth else 'equal'


try:
    need(sys.platform == 'darwin' and os.getuid() == os.geteuid() == 501 and os.getgid() == 20,
         'exact_original_mac_caller')
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda number, _frame: signals.append(number))
    candidate, first, second = [read(name, limit) for name, limit in zip(NAMES, LIMITS)]
    need(candidate.get('schema') == 'heptabao.fixed-codex-candidate-files.private.r1'
         and candidate.get('originalParentPid') == 29575
         and candidate.get('candidateDirectory') == str(SOURCE), 'original_same_parent_candidate_packet')
    need(first == second and first.get('schema') == 'heptabao.finite-selectors.private.r1',
         'original_two_selector_packets_equal')
    observed = first.get('observations')
    need(type(observed) is list and len(observed) == 4, 'original_four_observations')
    births = []
    for i, row in enumerate(observed):
        value = row.get('identity') if type(row) is dict else None
        need(type(value) is dict and row.get('ordinal') == i and row.get('pid') == PIDS[i]
             and value.get('pid') == PIDS[i] and value.get('uid') == 501
             and (value.get('birthSec'), value.get('birthUsec')) == EXPECTED_BIRTHS[i],
             'original_exact_full_birth_values')
        need(all(type(value[k]) is int for k in ('birthSec', 'birthUsec')),
             'original_typed_full_birth')
        births.append(value['birthSec'] * 1000000000 + value['birthUsec'] * 1000)
    recorded = candidate.get('files')
    need(type(recorded) is list and len(recorded) == 2
         and [row.get('path') for row in recorded] == [str(SOURCE / n) for n in ('config.toml','auth.json')],
         'original_two_fixed_candidate_file_records')
    directory_identity = identity(candidate.get('sourceDirectoryIdentities', {}).get(str(SOURCE)))
    times = []
    for ordinal, row in enumerate(recorded):
        value = identity(row.get('identity'))
        times.append({'sourceKind': 'candidate-configuration' if ordinal == 0 else 'candidate-auth',
                      'ordinal': ordinal,
                      'processRelations': [{'processOrdinal': i,
                          'mtimeRelativeToBirth': relation(value[7], birth),
                          'ctimeRelativeToBirth': relation(value[8], birth)} for i, birth in enumerate(births)]})
    times.append({'sourceKind': 'candidate-directory', 'ordinal': 2,
                  'directoryMetadataDoesNotIdentifyChangedEntry': True,
                  'processRelations': [{'processOrdinal': i,
                      'mtimeRelativeToBirth': relation(directory_identity[7], birth),
                      'ctimeRelativeToBirth': relation(directory_identity[8], birth)} for i, birth in enumerate(births)]})
    for row in files.values():
        need(whole(row) == row['raw'], 'original_complete_private_artifact_bytes_unchanged')
    verify()
    report.update(ok=True, recordedOriginalPacketTimesCompared=True,
                  originalFourBirthsCompared=True, originalPacketsCompleteAndStable=True,
                  relations=times)
except BaseException as error:
    report['ok'] = False
    report['errorClass'] = type(error).__name__ if type(error).__name__ in (
        'Refused','OSError','PermissionError','FileNotFoundError','UnicodeDecodeError','JSONDecodeError') else 'OtherException'
    report['errorCode'] = str(error) if type(error) is Refused else 'original_private_projection_refused'
finally:
    close_errors = []
    for row in reversed(rows):
        if row['closeAttempts']:
            continue
        row['closeAttempts'] = 1
        try:
            os.close(row['fd'])
            row['closed'] = True
        except BaseException:
            close_errors.append('original_descriptor_close_failed')
    report['allOriginalDescriptorsClosedOnce'] = all(row['closeAttempts'] == 1 and row['closed'] for row in rows)
    report['originalDescriptorCount'] = len(rows)
    report['closeErrors'] = close_errors
    if close_errors or not report['allOriginalDescriptorsClosedOnce']:
        report['ok'] = False
    if report['ok']:
        try:
            remaining()
            need(all(full(path.lstat()) == row['expected'] for path, row in (*directories.items(), *files.items())),
                 'closed_original_private_artifact_names_exact')
            report['closedOriginalNamesExact'] = True
        except BaseException:
            report['ok'] = False
            report['closedOriginalNamesExact'] = False
    report['elapsedSeconds'] = time.monotonic() - START
    print(json.dumps(report, sort_keys=True, separators=(',', ':'), allow_nan=False), flush=True)
sys.exit(0 if report['ok'] else 1)
