#!/usr/bin/env python3
"""Only lstat the already observed ROG SDK package and its fixed ancestors."""
import json
import os
from pathlib import Path
import stat
import sys
import time

PACKAGE = Path('/home/qian-qi/.npm-global/lib/node_modules/openclaw/package.json')
PATHS = tuple(reversed(PACKAGE.parents)) + (PACKAGE,)
START = time.monotonic()
UNTIL = START + 5


def observe():
    rows = []
    for path in PATHS:
        if time.monotonic() >= UNTIL:
            raise RuntimeError('metadata_deadline')
        info = path.lstat()
        rows.append({
            'path': str(path),
            'uid': info.st_uid,
            'gid': info.st_gid,
            'mode': oct(stat.S_IMODE(info.st_mode)),
            'nlink': info.st_nlink,
            'bytes': info.st_size,
            'isRegular': stat.S_ISREG(info.st_mode),
            'isDirectory': stat.S_ISDIR(info.st_mode),
            'isSymlink': stat.S_ISLNK(info.st_mode),
            'ownerMatches': info.st_uid in (0, os.getuid()),
            'groupOrWorldWrite': bool(info.st_mode & 0o022),
            'identity': [str(value) for value in (
                info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                info.st_mode, info.st_nlink, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)],
        })
    return rows


report = {
    'schema': 'heptabao.rog-selected-public-sdk-metadata.r1',
    'ok': False,
    'uid': os.getuid(),
    'sourceFileContentsRead': False,
    'symlinkTargetsRead': False,
    'permissionsChanged': False,
    'credentialDatabaseContentsRead': False,
    'credentialValuesOrDigestsPublished': False,
    'productionChanged': False,
    'childProcesses': 0,
    'networkOpened': False,
    'serviceActions': 0,
    'priorFailedJob': '1a1b298b70e-fc05-7ed6',
    'priorFailureReclassified': False,
    'newSdkQualificationClaimed': False,
}
try:
    if sys.platform != 'linux' or os.getuid() != 1000:
        raise RuntimeError('expected_rog_linux_account')
    before = observe()
    after = observe()
    report.update(rows=before, metadataUnchanged=before == after)
    if before != after:
        raise RuntimeError('fixed_metadata_changed')
    report['ok'] = True
except BaseException as error:
    report['errorType'] = type(error).__name__
    report['errorCode'] = str(error) if str(error) in {
        'metadata_deadline', 'expected_rog_linux_account',
        'fixed_metadata_changed'} else 'fixed_public_sdk_metadata_unavailable'
finally:
    report['elapsedSeconds'] = time.monotonic() - START
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))
raise SystemExit(0 if report['ok'] else 1)
