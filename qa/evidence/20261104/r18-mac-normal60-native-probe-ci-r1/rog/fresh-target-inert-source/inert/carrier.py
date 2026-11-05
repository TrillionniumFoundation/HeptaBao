#!/usr/bin/env python3
"""Publish five fixed public fresh-cache controls only; execute no product code."""
from pathlib import Path
import base64
import hashlib
import json
import os
import stat
import sys
import time

STARTED = time.monotonic()
UNTIL = STARTED + 45.0
os.umask(0o077)
ROOT = Path('/home/qian-qi/heptabao-cold-h2-normal-20261105-r1')
CONTROL = ROOT / 'control-r3'
PINS = {
    "launch_normal_cold_h2.py": [
        39664,
        "98b7838cd4550467b76bc3c9fd3b4925b806075536b7e22dc1cba1c79063bde3"
    ],
    "prior-normal-early-failure.authority.original.json": [
        726,
        "9188213431c349616ecd8dd329f930d909fb3b973ff27848ae3afb7957e2bfae"
    ],
    "prior-normal-early-failure.stderr": [
        693,
        "bb032403580f205d6e15f90da809c666b4accec08a0acf00f0a83611ecbbe01e"
    ],
    "prior-normal-target-metadata.stdout.json": [
        13741,
        "e4e062eacfb4b6080f973d053d301504b90b27d0782172c227745488ec826a6a"
    ],
    "prior-normal-target-metadata.authority.original.json": [
        733,
        "70a9289777c626b8ea795ae017161f923638a74459b79c350f94b5650ef72752"
    ]
}
ORIGINAL = {
    "control/launch_normal_cold_h2.py": [
        31963,
        "7c3dbf522f51931aaa5c1947ec0742883bdcc1405913d45f8b43f217983acb98"
    ],
    "control/normal_cold_h2_build.py": [
        26659,
        "1a3fdc3a7cf6504447feb7d7dadf2f365b292512f6d0cf8cdfb4a2ea63d33d40"
    ],
    "control/normal-test-groups.public.json": [
        6249,
        "0566f7f98ea16a4c1df43ebaf992172646ad91623c18f68fcc59f7c08b53d1f1"
    ],
    "control/stage-result.public.json": [
        25754,
        "7364fb449d5c46afa65507469b88427c8acc088fe4ef166cd1c5a436e56be9be"
    ]
}
FD_LEDGER = []
RESULT = {'schema': 'heptabao.cold-h2-fresh-cache-inert.v1', 'status': 'failed',
          'files': [], 'descriptors': FD_LEDGER, 'original_before': {}, 'original_after': {},
          'source_executed': False, 'compiler_started': False, 'git_started': False,
          'service_started': False, 'target_created': False, 'production_changed': False,
          'created_control': False, 'inner_seconds': 45, 'outer_seconds': 60}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def remaining():
    value = UNTIL - time.monotonic()
    assert value > 0, 'inert original deadline expired'
    return value


def register(name, fd):
    entry = {'name': name, 'fd': fd, 'close_attempted': False, 'closed': False}
    FD_LEDGER.append(entry)
    return fd, entry


def close_once(fd, entry):
    assert not entry['close_attempted']
    entry['close_attempted'] = True
    try:
        os.close(fd)
        entry['closed'] = True
    except BaseException as error:
        entry['close_error_type'] = type(error).__name__
        raise


def exact_original(relative, length, digest):
    remaining()
    path = ROOT / relative
    assert path.resolve(strict=True) == path
    fd, entry = register(relative, os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK))
    try:
        first = os.fstat(fd)
        assert stat.S_ISREG(first.st_mode) and first.st_uid == 1000 and first.st_nlink == 1
        assert stat.S_IMODE(first.st_mode) == 0o600 and first.st_size == length
        data = bytearray()
        while True:
            remaining()
            block = os.read(fd, 65536)
            if not block:
                break
            data.extend(block)
            assert len(data) <= length
        assert len(data) == length and sha(data) == digest
        assert identity(first) == identity(os.fstat(fd)) == identity(path.lstat())
        return {'bytes': length, 'sha256': digest, 'identity': list(identity(first))}
    finally:
        close_once(fd, entry)


def exact_created(control_fd, name, raw):
    remaining()
    fd, entry = register(name + ':read', os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=control_fd))
    try:
        first = os.fstat(fd)
        assert stat.S_ISREG(first.st_mode) and first.st_uid == 1000 and first.st_nlink == 1
        assert stat.S_IMODE(first.st_mode) == 0o600 and first.st_size == len(raw)
        data = bytearray()
        while True:
            remaining()
            part = os.read(fd, 65536)
            if not part:
                break
            data.extend(part)
            assert len(data) <= len(raw)
        assert bytes(data) == raw
        assert identity(first) == identity(os.fstat(fd)) == identity(os.stat(name, dir_fd=control_fd, follow_symlinks=False))
        return {'path': str(CONTROL / name), 'bytes': len(raw), 'sha256': sha(raw), 'identity': list(identity(first))}
    finally:
        close_once(fd, entry)


def publish(control_fd, name, raw):
    remaining()
    temporary = '.' + name + '.fresh-inert-r3.tmp'
    fd, entry = register(name + ':write', os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=control_fd))
    try:
        written = 0
        while written < len(raw):
            remaining()
            count = os.write(fd, raw[written:])
            assert count > 0
            written += count
        os.fsync(fd)
        remaining()
        made = os.fstat(fd)
        assert stat.S_ISREG(made.st_mode) and made.st_uid == 1000 and made.st_nlink == 1
        assert stat.S_IMODE(made.st_mode) == 0o600 and made.st_size == len(raw)
        assert identity(made) == identity(os.stat(temporary, dir_fd=control_fd, follow_symlinks=False))
    finally:
        close_once(fd, entry)
    remaining()
    os.link(temporary, name, src_dir_fd=control_fd, dst_dir_fd=control_fd, follow_symlinks=False)
    current = os.stat(temporary, dir_fd=control_fd, follow_symlinks=False)
    assert identity(current)[:5] == identity(made)[:5] and current.st_nlink == 2
    os.unlink(temporary, dir_fd=control_fd)
    os.fsync(control_fd)
    remaining()
    return exact_created(control_fd, name, raw)


try:
    incoming = sys.stdin.buffer.read(262145)
    remaining()
    assert 0 < len(incoming) <= 262144
    payload = json.loads(incoming)
    assert set(payload) == {'schema', 'files'} and payload['schema'] == 'heptabao.cold-h2-fresh-cache-inert-inputs.v1'
    assert set(payload['files']) == set(PINS)
    decoded = {}
    for name, (length, digest) in PINS.items():
        raw = base64.b64decode(payload['files'][name], validate=True)
        assert len(raw) == length and sha(raw) == digest
        decoded[name] = raw
    compile(decoded['launch_normal_cold_h2.py'], str(CONTROL / 'launch_normal_cold_h2.py'), 'exec')
    RESULT.update(stdin_bytes=len(incoming), stdin_sha256=sha(incoming), all_payloads_verified_before_write=True)
    assert (os.uname().sysname, os.uname().machine) == ('Linux', 'x86_64') and os.getuid() == 1000
    assert ROOT.resolve(strict=True) == ROOT
    root_fd, root_entry = register('root', os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
    root_before = os.fstat(root_fd)
    assert identity(root_before) == identity(ROOT.lstat())
    assert stat.S_ISDIR(root_before.st_mode) and root_before.st_uid == 1000 and stat.S_IMODE(root_before.st_mode) == 0o700
    for relative, (length, digest) in ORIGINAL.items():
        RESULT['original_before'][relative] = exact_original(relative, length, digest)
    for path in (CONTROL, ROOT / 'target-normal-r3', ROOT / 'build-control-r3', ROOT / 'normal-release-tests-r3'):
        assert not os.path.lexists(path)
    remaining()
    os.mkdir(CONTROL.name, 0o700, dir_fd=root_fd)
    RESULT['created_control'] = True
    control_fd, control_entry = register('control', os.open(CONTROL.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd))
    control_before = os.fstat(control_fd)
    assert identity(control_before) == identity(os.stat(CONTROL.name, dir_fd=root_fd, follow_symlinks=False))
    assert stat.S_ISDIR(control_before.st_mode) and control_before.st_uid == 1000 and stat.S_IMODE(control_before.st_mode) == 0o700
    for name, raw in decoded.items():
        RESULT['files'].append(publish(control_fd, name, raw))
    for relative, (length, digest) in ORIGINAL.items():
        RESULT['original_after'][relative] = exact_original(relative, length, digest)
    assert RESULT['original_before'] == RESULT['original_after']
    for path in (ROOT / 'target-normal-r3', ROOT / 'build-control-r3', ROOT / 'normal-release-tests-r3'):
        assert not os.path.lexists(path)
    for fd in (control_fd, root_fd):
        remaining()
        os.fsync(fd)
        remaining()
    root_after, control_after = os.fstat(root_fd), os.fstat(control_fd)
    assert identity(root_after)[:5] == identity(root_before)[:5]
    assert identity(root_after) == identity(ROOT.lstat())
    assert identity(control_after)[:5] == identity(control_before)[:5]
    assert identity(control_after) == identity(os.stat(CONTROL.name, dir_fd=root_fd, follow_symlinks=False))
    RESULT.update(root_identity_after=list(identity(root_after)), control_identity_after=list(identity(control_after)))
    remaining()
    RESULT['status'] = 'prepared'
except BaseException as error:
    RESULT.update(status='failed', error_type=type(error).__name__)
finally:
    for entry in reversed(FD_LEDGER):
        if entry['close_attempted']:
            continue
        try:
            close_once(entry['fd'], entry)
        except BaseException:
            RESULT['status'] = 'failed'
    RESULT['all_opened_descriptors_closed'] = all(entry['closed'] for entry in FD_LEDGER)
    if not RESULT['all_opened_descriptors_closed']:
        RESULT['status'] = 'failed'
    RESULT['elapsed_seconds'] = time.monotonic() - STARTED
    RESULT['publication_within_original_deadline'] = time.monotonic() < UNTIL
    if not RESULT['publication_within_original_deadline']:
        RESULT['status'] = 'failed'
    sys.stdout.buffer.write((json.dumps(RESULT, sort_keys=True) + '\n').encode())
    sys.stdout.buffer.flush()
raise SystemExit(0 if RESULT['status'] == 'prepared' and time.monotonic() < UNTIL else 1)
