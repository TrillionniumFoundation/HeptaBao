#!/usr/bin/env python3
"""Read-only metadata for the finite proposed permanent AuthBus destinations."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

START = time.monotonic()
UNTIL = START + 10
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
PIN = (34640, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13')
PARENTS = (Path('/Volumes/T5'), Path('/Users/qianqi'), Path('/Users/qianqi/Library/LaunchAgents'))
TARGETS = (
    Path('/Volumes/T5/heptabao-authbus-production'),
    Path('/Users/qianqi/heptabao-authbus-production-backups'),
    Path('/Users/qianqi/heptabao-authbus-production-custody'),
    Path('/Users/qianqi/Library/LaunchAgents/org.heptabao.authbus.plist'),
)
rows = []
fd_rows = []
report = {'schema': 'heptabao.permanent-target-metadata.r1', 'ok': False,
          'children': 0, 'networkOperations': 0, 'fileWrites': 0,
          'serviceActions': 0, 'credentialReads': 0,
          'provisioned': False, 'productionReady': False}

def need(value, code):
    if not value:
        raise RuntimeError(code)
    if time.monotonic() >= UNTIL:
        raise RuntimeError('target_metadata_original_deadline')

def identity(info):
    return [str(getattr(info, field)) for field in ('st_dev', 'st_ino', 'st_uid',
            'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')]

def inspect_parent(path):
    before = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISDIR(before.st_mode)
         and before.st_uid in (0, os.getuid()) and not before.st_mode & 0o022,
         'canonical_protected_parent')
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    row = {'closeAttempted': False, 'closed': False}
    fd_rows.append(row)
    try:
        need(identity(os.fstat(fd)) == identity(before), 'same_open_parent')
        space = os.fstatvfs(fd)
        need(identity(os.fstat(fd)) == identity(path.lstat()) == identity(before),
             'parent_metadata_unchanged')
        rows.append((path, identity(before)))
        return {'path': str(path), 'identityDecimalStrings': identity(before),
                'availableBytes': space.f_bavail * space.f_frsize,
                'filesystemBytes': space.f_blocks * space.f_frsize,
                'readOnlyFilesystem': bool(space.f_flag & os.ST_RDONLY)}
    finally:
        row['closeAttempted'] = True
        os.close(fd)
        row['closed'] = True

def run():
    try:
        need(os.getuid() == 501 and Path(sys.executable) == PYTHON, 'exact_native_python_identity')
        fd = os.open(PYTHON, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        row = {'closeAttempted': False, 'closed': False}
        fd_rows.append(row)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and not before.st_mode & 0o022 and before.st_size == PIN[0], 'public_python_regular')
            raw = os.read(fd, PIN[0] + 1)
            need((len(raw), hashlib.sha256(raw).hexdigest()) == PIN
                 and identity(before) == identity(os.fstat(fd)) == identity(PYTHON.lstat()),
                 'whole_native_python_pin')
        finally:
            row['closeAttempted'] = True
            os.close(fd)
            row['closed'] = True
        report['parents'] = [inspect_parent(path) for path in PARENTS]
        targets = []
        for path in TARGETS:
            need(path.parent in PARENTS, 'finite_proposed_target')
            try:
                info = path.lstat()
                target = {'path': str(path), 'exists': True,
                          'kind': 'directory' if stat.S_ISDIR(info.st_mode) else
                                  'regular' if stat.S_ISREG(info.st_mode) else 'other'}
            except FileNotFoundError:
                target = {'path': str(path), 'exists': False}
            targets.append(target)
        for path, expected in rows:
            need(identity(path.lstat()) == expected, 'final_parent_generation')
        report['targets'] = targets
        report['proposedNamesAllAbsent'] = all(not row['exists'] for row in targets)
        report['dataBackupDifferentFilesystems'] = rows[0][1][0] != rows[1][1][0]
        report['ok'] = True
    except BaseException as error:
        report['errorClass'] = type(error).__name__
        report['errorCode'] = str(error) if isinstance(error, RuntimeError) else 'native_metadata_error'
    finally:
        report['descriptorCount'] = len(fd_rows)
        report['allDescriptorsClosedOnce'] = all(row['closeAttempted'] and row['closed'] for row in fd_rows)
        report['ok'] = report['ok'] and report['allDescriptorsClosedOnce']
        report['elapsedSeconds'] = time.monotonic() - START
        print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report['ok'] else 1

if __name__ == '__main__':
    raise SystemExit(run())
