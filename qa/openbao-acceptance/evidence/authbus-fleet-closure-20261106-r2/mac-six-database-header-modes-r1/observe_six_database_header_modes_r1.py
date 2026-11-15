#!/usr/bin/env python3
"""Read exactly 20 header bytes from each of the six already registered DBs.

No SQLite connection, child, network, credential row, sidecar creation or source
write. The public report contains only ordinal format enums and sidecar shape.
The file-header format bytes are offsets 18/19, not the page-size bytes 16/17.
"""
import json
import os
from pathlib import Path
import stat
import sys
import time

START = time.monotonic()
UNTIL = START + 15
LIVE = Path('/Users/qianqi/.openclaw')
PATHS = tuple(LIVE / 'agents' / name / 'agent/openclaw-agent.sqlite'
              for name in ('main', 'trnm', 'hepta-ui', 'hepta', 'hepta-backend')) + (
                  LIVE / 'state/openclaw.sqlite',)
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
rows, parents, captures = [], {}, []
report = {'schema': 'heptabao.six-database-header-modes.public.r1', 'ok': False,
          'fixedDatabases': 6, 'headerBytesPerRead': 20, 'headerReadPasses': 2,
          'fileFormatOffsetsZeroBased': [18, 19], 'sqlConnections': 0,
          'childCount': 0, 'networkCalls': 0, 'providerCalls': 0,
          'serviceActions': 0, 'sourceWrites': 0, 'credentialRowsRead': 0,
          'rawHeaderOrFileIdentitiesPublished': False,
          'journalModePragmaInferredFromHeader': False, 'slots': []}


def need(value, code):
    if not value:
        raise RuntimeError(code)


def within():
    need(time.monotonic() < UNTIL, 'header_original_deadline')


def full(value):
    return tuple(getattr(value, key) for key in FIELDS)


def track(fd, path):
    row = {'fd': fd, 'path': path, 'closeAttempts': 0, 'closed': False}
    rows.append(row)
    row['identity'] = full(os.fstat(fd))
    return row


def directory(path):
    within()
    if path in parents:
        return parents[path]
    if path == path.parent:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    else:
        parent = directory(path.parent)
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                     dir_fd=parent['fd'])
    row = track(fd, path)
    info = os.fstat(fd)
    need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, 501)
         and not stat.S_IMODE(info.st_mode) & 0o022
         and full(info) == full(path.lstat()), 'header_original_parent_custody')
    parents[path] = row
    return row


def sidecars(path, parent):
    result = {}
    for suffix in ('-wal', '-shm', '-journal'):
        try:
            info = os.stat(path.name + suffix, dir_fd=parent['fd'], follow_symlinks=False)
        except FileNotFoundError:
            result[suffix] = None
        else:
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 501 and info.st_gid == 20
                 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
                 'header_exact_private_sidecar_custody')
            result[suffix] = full(info)
    return result


def shape(value):
    return 'absent' if value is None else ('empty' if value[6] == 0 else 'nonempty')


try:
    need(sys.platform == 'darwin' and os.getuid() == 501, 'header_actual_mac_owner')
    for ordinal, path in enumerate(PATHS):
        within()
        parent = directory(path.parent)
        before_sidecars = sidecars(path, parent)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=parent['fd'])
        row = track(fd, path)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 501 and info.st_gid == 20
             and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
             and info.st_size >= 100 and full(info) == full(path.lstat()),
             'header_exact_private_database_custody')
        raw = os.pread(fd, 20, 0)
        need(len(raw) == 20 and raw[:16] == b'SQLite format 3\x00'
             and raw[18] in (1, 2) and raw[19] in (1, 2), 'header_fixed_sqlite_format')
        captures.append((row, raw, parent, before_sidecars))
        report['slots'].append({'ordinal': ordinal,
            'writeFileFormat': 'rollback' if raw[18] == 1 else 'wal',
            'readFileFormat': 'rollback' if raw[19] == 1 else 'wal',
            'wal': shape(before_sidecars['-wal']), 'shm': shape(before_sidecars['-shm']),
            'journal': shape(before_sidecars['-journal'])})
    for row, raw, parent, expected_sidecars in captures:
        within()
        need(os.pread(row['fd'], 20, 0) == raw
             and full(os.fstat(row['fd'])) == row['identity'] == full(row['path'].lstat())
             and sidecars(row['path'], parent) == expected_sidecars,
             'header_database_and_sidecars_full9_stable')
    for row in parents.values():
        need(full(os.fstat(row['fd'])) == row['identity'] == full(row['path'].lstat()),
             'header_all_original_parent_full9_stable')
    report.update(ok=True, observedDatabaseCount=len(captures),
                  bytesRead=40 * len(captures), allSourceFull9AndAbsencesStable=True)
except BaseException as error:
    code = str(error)
    report.update(ok=False, errorType=type(error).__name__,
                  refusalCode=code if code.startswith('header_') else 'header_original_io_refused')
finally:
    for row in reversed(rows):
        row['closeAttempts'] += 1
        try:
            os.close(row['fd'])
            row['closed'] = True
        except BaseException:
            report['closeUnknown'] = True
    report.update(descriptorsOpened=len(rows), descriptorsClosed=sum(row['closed'] for row in rows),
                  allOriginalDescriptorsClosedOnce=all(row['closed'] and row['closeAttempts'] == 1 for row in rows),
                  elapsedSeconds=time.monotonic() - START)
    if not report['allOriginalDescriptorsClosedOnce'] or time.monotonic() >= UNTIL:
        report['ok'] = False
print(json.dumps(report, sort_keys=True, separators=(',', ':')))
raise SystemExit(0 if report['ok'] else 1)
