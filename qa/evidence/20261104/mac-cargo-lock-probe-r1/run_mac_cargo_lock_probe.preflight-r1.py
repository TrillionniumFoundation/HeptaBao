#!/usr/bin/env python3
"""Stage and execute one pinned, isolated Mac Cargo lock probe on the known T5."""
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import socket
import stat
import subprocess
import sys
import time

PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python')
PYTHON_SHA = '7ecc1ecbf9daa9303c4bf502ff62ffdd9010ed5c08729d470ae9380c10ce1211'
VOLUME_UUID = 'FB804D1B-24CB-4D6E-AEA7-A9E180807758'
BASE = Path('/Volumes/T5/hepta-vnext-recovery-20261013')
CONTROL = BASE / 'continuation-20261104-ha-cargo-lock-control-61ff-r1'
PROBE_ROOT = BASE / 'continuation-20261104-ha-cargo-lock-probe-61ff-r1'
SOURCE_SHA = 'aaec18ac2ac5a610629b3eaa6d0e8e0de7ef0d45716cd5e3ea24b11145136271'
SOURCE_BYTES = 9003


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def read_pinned(path, expected, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
        assert before.st_uid == 501 and before.st_size <= limit
        blocks = []
        count = 0
        while count <= limit:
            block = os.read(fd, min(65536, limit + 1 - count))
            if not block:
                break
            blocks.append(block)
            count += len(block)
        raw = b''.join(blocks)
        assert len(raw) == before.st_size
        assert identity(before) == identity(os.fstat(fd)) == identity(path.lstat())
        assert hashlib.sha256(raw).hexdigest() == expected
        return raw
    finally:
        os.close(fd)


def write_new(path, raw, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    os.umask(0o077)
    assert platform.system() == 'Darwin' and platform.machine() == 'arm64'
    assert os.getuid() == os.geteuid() == 501 and socket.gethostname() == 'MacBook-Pro.local'
    assert Path(sys.executable).resolve(strict=True) == PYTHON
    read_pinned(PYTHON, PYTHON_SHA, 1024 * 1024)
    raw = sys.stdin.buffer.read(SOURCE_BYTES + 1)
    assert len(raw) == SOURCE_BYTES and hashlib.sha256(raw).hexdigest() == SOURCE_SHA
    compiled = compile(raw, str(CONTROL / 'probe_actual_cargo_release_lock_r2.py'), 'exec')
    result = subprocess.run(['/usr/sbin/diskutil', 'info', '-plist', '/Volumes/T5'],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=10, check=False)
    assert result.returncode == 0
    volume = plistlib.loads(result.stdout)
    assert volume.get('MountPoint') == '/Volumes/T5' and volume.get('VolumeUUID') == VOLUME_UUID
    assert volume.get('FilesystemType') == 'apfs' and volume.get('Writable') is True
    assert volume.get('Internal') is False
    device = Path('/Volumes/T5').lstat().st_dev
    for path in (Path('/Volumes/T5'), BASE):
        info = path.lstat()
        assert stat.S_ISDIR(info.st_mode) and not path.is_symlink()
        assert info.st_dev == device and info.st_uid == 501
    assert BASE.resolve(strict=True) == BASE
    for path in (CONTROL, PROBE_ROOT):
        assert not path.exists() and not path.is_symlink()
    CONTROL.mkdir(mode=0o700)
    source = CONTROL / 'probe_actual_cargo_release_lock_r2.py'
    write_new(source, raw, 0o500)
    staged = read_pinned(source, SOURCE_SHA, SOURCE_BYTES)
    assert staged == raw and source.lstat().st_dev == device
    receipt = {
        'schema': 'heptabao.mac-cargo-lock-probe-stage.v1', 'ok': True,
        'staged_at_unix': time.time(), 'python_path': str(PYTHON), 'python_sha256': PYTHON_SHA,
        'volume_uuid': VOLUME_UUID, 'volume_device': device, 'probe_source': str(source),
        'probe_source_bytes': len(raw), 'probe_source_sha256': SOURCE_SHA,
        'probe_root': str(PROBE_ROOT), 'product_source_or_cache_touched': False,
        'production_service_or_client_changed': False,
        'probe_original_total_budget_seconds': 30,
    }
    receipt_raw = (json.dumps(receipt, sort_keys=True, indent=2) + '\n').encode()
    write_new(CONTROL / 'stage.public.json', receipt_raw, 0o600)
    fd = os.open(CONTROL, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    print(json.dumps({'stage_ok': True, 'stage_receipt_sha256': hashlib.sha256(receipt_raw).hexdigest(),
                      'source_sha256': SOURCE_SHA, 'probe_root': str(PROBE_ROOT)}, sort_keys=True), flush=True)
    exec(compiled, {'__name__': '__main__', '__file__': str(source), '__builtins__': __builtins__})


if __name__ == '__main__':
    main()
