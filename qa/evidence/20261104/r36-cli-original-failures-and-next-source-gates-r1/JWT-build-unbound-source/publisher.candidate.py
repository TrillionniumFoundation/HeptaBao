#!/usr/bin/env python3
"""Create-only distribution and compile-check of the three separately reviewed JWT build controls."""
from pathlib import Path
import base64, hashlib, json, os, stat, sys, time

BINDING_READY = False
assert BINDING_READY, 'final formatted source and build control pins are not yet bound'
os.umask(0o077)
PARENT = Path('/home/qian-qi')
BASE = PARENT / 'heptabao-native-jwt-r2-controls-20261106-r1'
created_base = False
RECEIPT = BASE / 'inert-stage.result.public.json'
PINS = {
    "native_jwt_build.py": [
        30303,
        "41565b0c1fd33602f6fda340890c0a075b2a8f88075406282acd711e8e164e8b"
    ],
    "launch_native_jwt_build.py": [
        38330,
        "b8c56a8bcf36738d90c191aef011e5ee7d2f4112512e955bfe01b647eb6e15e5"
    ],
    "jwt-test-groups.public.json": [
        19325,
        "8651fc3043a14556734d2e1992ac941ffbd812671fa0f3486d8813084e5918ba"
    ]
}

def sha(raw):
    return hashlib.sha256(raw).hexdigest()
def ident(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)
def sync_dir():
    fd = os.open(BASE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
def exact(path, raw):
    assert path.resolve(strict=True) == path
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_uid == 1000
        assert before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
        assert before.st_size == len(raw)
        parts, count = [], 0
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            count += len(block)
            assert count <= len(raw)
            parts.append(block)
        assert b''.join(parts) == raw
        assert ident(before) == ident(os.fstat(fd)) == ident(path.lstat())
        return {'bytes': count, 'sha256': sha(raw), 'mode': '0600', 'identity': list(ident(before))}
    finally:
        os.close(fd)
def publish(name, raw):
    destination = BASE / name
    if os.path.lexists(destination):
        return {'path': str(destination), 'publication': 'existing_exact', **exact(destination, raw)}
    temporary = BASE / ('.' + name + '.hepta-r10-inert-r1.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fchmod(stream.fileno(), 0o600)
        os.fsync(stream.fileno())
        made = os.fstat(stream.fileno())
    assert stat.S_ISREG(made.st_mode) and made.st_uid == 1000 and made.st_nlink == 1
    assert ident(made) == ident(temporary.lstat())
    publication = 'created'
    try:
        os.link(temporary, destination, follow_symlinks=False)
    except FileExistsError:
        publication = 'existing_after_race'
    # Only unlink the temporary inode that this attempt exclusively created.
    current = temporary.lstat()
    assert (current.st_dev, current.st_ino) == (made.st_dev, made.st_ino)
    os.unlink(temporary)
    sync_dir()
    return {'path': str(destination), 'publication': publication, **exact(destination, raw)}

assert (os.uname().sysname, os.uname().machine) == ('Linux', 'x86_64')
assert os.getuid() == 1000 and PARENT.resolve(strict=True) == PARENT and PARENT.stat().st_uid == 1000
assert not os.path.lexists(BASE)
assert not os.path.lexists(RECEIPT)
result = {'schema': 'heptabao.native-jwt-build-controls-inert.v1', 'status': 'failed',
          'started_ns': time.time_ns(), 'files': [], 'source_executed': False,
          'git_started': False, 'compiler_started': False, 'service_started': False,
          'python_compile_only': True, 'artifact_transfer_started': False}
try:
    incoming = sys.stdin.buffer.read(262145)
    assert 0 < len(incoming) <= 262144
    payload = json.loads(incoming)
    assert set(payload) == {'schema', 'files'} and payload['schema'] == 'heptabao.native-jwt-build-control-inputs.v1'
    assert set(payload['files']) == set(PINS)
    decoded = {}
    for name, (length, digest) in PINS.items():
        raw = base64.b64decode(payload['files'][name], validate=True)
        assert len(raw) == length and sha(raw) == digest
        compile(raw, name, 'exec')
        decoded[name] = raw
    BASE.mkdir(mode=0o700)
    created_base = True
    parent_fd = os.open(PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    result['stdin_bytes'] = len(incoming)
    result['stdin_sha256'] = sha(incoming)
    for name, raw in decoded.items():
        result['files'].append(publish(name, raw))
    result['status'] = 'prepared'
except BaseException as error:
    result['error_type'] = type(error).__name__
finally:
    result['terminal_ns'] = time.time_ns()
    raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
    if created_base:
        publish(RECEIPT.name, raw)
    print(json.dumps(result, sort_keys=True), flush=True)
sys.exit(0 if result['status'] == 'prepared' else 1)
