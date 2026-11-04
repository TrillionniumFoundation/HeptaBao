#!/usr/bin/env python3
"""Read-only installed-service/client/backup-path inventory, never retirement authority.

Credential files and process arguments/environments are not read. Live SDK stores
are listed as paths only; this is not a committed backup or a migration proof.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
import urllib.parse

PATTERN = re.compile(r'openbao|heptabao|authbus|openclaw', re.I)
START = time.monotonic()
REPORT = {'schema': 'heptabao.retirement-boundaries-readonly.v1',
    'host': socket.gethostname(), 'uid': os.getuid(), 'platform': sys.platform,
    'started_unix_ns': time.time_ns(), 'changes': [], 'errors': [],
    'credential_files_read': False, 'process_arguments_read': False, 'process_environment_read': False,
    'complete_asset_inventory': False, 'committed_backup_qualified': False,
    'all_clients_migrated': False, 'retirement_authorized_by_this_report': False}


def metadata(path, *, digest=False):
    path = Path(path)
    try:
        before = path.lstat()
        result = {'path': str(path), 'mode': stat.S_IMODE(before.st_mode), 'uid': before.st_uid,
                  'gid': before.st_gid, 'device': before.st_dev, 'inode': before.st_ino,
                  'bytes': before.st_size, 'mtime_ns': before.st_mtime_ns}
        if stat.S_ISLNK(before.st_mode):
            result.update(kind='symlink', target=os.readlink(path))
        elif stat.S_ISREG(before.st_mode):
            result['kind'] = 'file'
            if digest and before.st_size <= 256 * 1024 * 1024:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    h = hashlib.sha256()
                    with os.fdopen(fd, 'rb', closefd=False) as stream:
                        for block in iter(lambda: stream.read(1048576), b''):
                            h.update(block)
                    after = os.fstat(fd)
                    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                    result['stable_read'] = identity(before) == identity(after)
                    result['sha256'] = h.hexdigest()
                finally:
                    os.close(fd)
        elif stat.S_ISDIR(before.st_mode):
            result['kind'] = 'directory'
        else:
            result['kind'] = 'other'
        return result
    except OSError as exc:
        return {'path': str(path), 'unavailable': type(exc).__name__}


def safe_rows(argv, pattern=PATTERN):
    try:
        p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                           timeout=min(6, max(.01, 50 - (time.monotonic() - START))))
        lines = p.stdout.decode('utf-8', 'replace').splitlines()
        selected = [line[:1024] for line in lines if pattern.search(line)]
        return {'argv': argv, 'exit_code': p.returncode, 'matched_rows': selected[:128],
                'truncated': len(selected) > 128, 'stderr_sha256': hashlib.sha256(p.stderr).hexdigest()}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'argv': argv, 'error': type(exc).__name__}


home = Path.home()
config = home / '.openclaw/openclaw.json'
REPORT['client_config'] = metadata(config)
if REPORT['client_config'].get('kind') == 'file' and REPORT['client_config']['bytes'] < 4 * 1024 * 1024:
    try:
        fd = os.open(config, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            raw = stream.read(4 * 1024 * 1024 + 1)
        value = json.loads(raw)
        plugin = value.get('plugins', {}).get('entries', {}).get('openclaw-authbus', {})
        conf = plugin.get('config', {})
        address = conf.get('address')
        if isinstance(address, str):
            parsed = urllib.parse.urlsplit(address)
            address = {'scheme': parsed.scheme, 'hostname': parsed.hostname, 'port': parsed.port,
                       'userinfo_path_and_query_omitted': True}
        fields = ('hostId', 'caFile', 'roleIdFile', 'secretIdFile', 'leader', 'publishNew',
                  'manageOrder', 'enforceRefreshLeases', 'schedulerMode', 'orderExcludeAgentIds',
                  'releaseGeneration', 'pollIntervalMs')
        projected = {k: conf.get(k) for k in fields}
        for k in ('caFile', 'roleIdFile', 'secretIdFile'):
            v = projected[k]
            if v is not None and (not isinstance(v, str) or not v.startswith('/')):
                projected[k] = '<non-absolute-path-omitted>'
        REPORT['authbus'] = {'enabled': plugin.get('enabled'), 'address': address,
                            'configuration': projected}
        REPORT['client_config']['sha256'] = hashlib.sha256(raw).hexdigest()
        REPORT['configured_agent_ids'] = [a.get('id') for a in value.get('agents', {}).get('list', []) if isinstance(a, dict)]
        REPORT['client_config_after'] = metadata(config)
        REPORT['client_config_metadata_stable'] = all(REPORT['client_config'].get(k) == REPORT['client_config_after'].get(k)
                                                     for k in ('device', 'inode', 'bytes', 'mtime_ns'))
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        REPORT['errors'].append({'scope': 'client_config_projection', 'error': type(exc).__name__})

bins = set()
for name in ('bao', 'openbao', 'heptabao', 'heptabao-server'):
    found = shutil.which(name)
    if found:
        bins.add(found)
for base in ('/usr/bin', '/usr/local/bin', '/opt/homebrew/bin', str(home / '.local/bin')):
    for name in ('bao', 'openbao', 'heptabao', 'heptabao-server'):
        p = Path(base) / name
        if p.exists() or p.is_symlink():
            bins.add(str(p))
REPORT['installed_binary_candidates'] = [metadata(p, digest=True) for p in sorted(bins)]
service_dirs = [home / '.config/systemd/user', Path('/etc/systemd/system'), Path('/usr/lib/systemd/system')]
if sys.platform == 'darwin':
    service_dirs = [home / 'Library/LaunchAgents', Path('/Library/LaunchAgents'), Path('/Library/LaunchDaemons')]
REPORT['service_files'] = []
for directory in service_dirs:
    try:
        REPORT['service_files'] += [metadata(p, digest=True) for p in sorted(directory.iterdir()) if PATTERN.search(p.name)][:128]
    except OSError as exc:
        REPORT['errors'].append({'scope': str(directory), 'error': type(exc).__name__})
REPORT['manager_observations'] = []
if sys.platform == 'darwin':
    REPORT['manager_observations'].append(safe_rows(['/bin/launchctl', 'list']))
else:
    for mode in ([], ['--user']):
        REPORT['manager_observations'].append(safe_rows(['/usr/bin/systemctl', *mode, 'list-unit-files', '--no-pager', '--no-legend']))
        REPORT['manager_observations'].append(safe_rows(['/usr/bin/systemctl', *mode, 'list-units', '--all', '--no-pager', '--no-legend']))
REPORT['process_names_only'] = safe_rows(['/bin/ps', '-axo', 'pid=,ppid=,comm='])
REPORT['backup_path_candidates'] = []
for directory in (home / '.openclaw', home / '.config', home,
                  Path('/Volumes/T5/hepta-vnext-recovery-20261013')):
    if not directory.is_dir():
        continue
    try:
        entries = sorted(directory.iterdir())
        selected = [p for p in entries if PATTERN.search(p.name)
                    and any(word in p.name.lower() for word in ('backup', 'snapshot', 'recovery', '.bak', 'rollback'))]
        REPORT['backup_path_candidates'].append({'directory': str(directory), 'recursive': False,
            'total_directory_entries': len(entries), 'selected': [metadata(p) for p in selected[:128]],
            'truncated': len(selected) > 128})
    except OSError as exc:
        REPORT['errors'].append({'scope': str(directory), 'error': type(exc).__name__})
docker = shutil.which('docker')
if docker:
    REPORT['docker_listing'] = safe_rows([docker, 'ps', '-a', '--format', '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}'],
                                        re.compile(r'bao|vault', re.I))
REPORT['elapsed_seconds'] = time.monotonic() - START
REPORT['finished_unix_ns'] = time.time_ns()
print(json.dumps(REPORT, sort_keys=True))
