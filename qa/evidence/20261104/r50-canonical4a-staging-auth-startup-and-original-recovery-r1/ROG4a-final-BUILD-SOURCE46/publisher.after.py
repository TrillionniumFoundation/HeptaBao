#!/usr/bin/env python3
"""Publish three exact fresh-target controls, then exec their admitted build in this PID."""
from pathlib import Path
import base64, hashlib, json, os, signal, stat, sys, time

JOINT_STARTED = time.monotonic()
PUBLICATION_UNTIL = JOINT_STARTED + 60
JOINT_UNTIL = JOINT_STARTED + 12000
def publication_timeout(_signum, _frame):
    # There are no subprocesses in this phase. Kernel closes this process's FDs.
    os._exit(124)
signal.signal(signal.SIGALRM, publication_timeout)
signal.setitimer(signal.ITIMER_REAL, max(0.001, PUBLICATION_UNTIL - time.monotonic()))

BINDING_READY = True
assert BINDING_READY, 'final formatted source and build control pins are not yet bound'
os.umask(0o077)
PARENT = Path('/home/qian-qi')
BASE = PARENT / 'hb-4a49405b-controls-20261106-r1'
created_base = False
RECEIPT = BASE / 'inert-stage.result.public.json'
PINS = {
    "native_jwt_build.py": [
        38598,
        "3adf3aa07ec747e978f8484f670b41b2874d5f1d2b5a1a7afb45ea5989635a09"
    ],
    "launch_native_jwt_build.py": [
        39650,
        "f39c03fd166ea30a466189446596506fd0f570c9949d4d9da7d497c85c0fd466"
    ],
    "jwt-test-groups.public.json": [
        35287,
        "617d5c104309ec8fcd006d97a60cb519c7b26ad203359ca6dc84146855f746df"
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
result = {'schema': 'heptabao.native-jwt-pki-build-controls-inert.v1', 'status': 'failed',
          'started_ns': time.time_ns(), 'files': [], 'source_executed': False,
          'git_started': False, 'compiler_started': False, 'service_started': False,
          'python_compile_only': True, 'artifact_transfer_started': False,
          'phase': 'controls_publication_before_same_pid_build',
          'publication_cap_seconds': 60, 'joint_cap_seconds': 12000,
          'joint_started_monotonic': JOINT_STARTED, 'same_pid': os.getpid()}
try:
    incoming = sys.stdin.buffer.read(262145)
    assert 0 < len(incoming) <= 262144
    payload = json.loads(incoming)
    assert set(payload) == {'schema', 'files'} and payload['schema'] == 'heptabao.native-jwt-pki-build-control-inputs.v1'
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
if result['status'] != 'prepared':
    raise SystemExit(1)
assert time.monotonic() < PUBLICATION_UNTIL
assert time.monotonic() < JOINT_UNTIL
argv = ['/usr/bin/python3', '-I', '-S', '-B', str(BASE / 'launch_native_jwt_build.py'),
        '--host', 'rog',
        '--commit', '4a49405b93c45ab1c25ecba11cde63a7ede20dce',
        '--tree', 'f02dd113d208d79f5275005dc65a5e8aecd0e9d3',
        '--stage-sha256', '5f7d5a19bd785dd3bd258a21de2452bf7029c5e5c91a2f69b8c0be19b2ae5be5',
        '--runner-sha256', PINS['native_jwt_build.py'][1],
        '--groups-sha256', PINS['jwt-test-groups.public.json'][1],
        '--controls-sha256', sha(raw),
        '--publisher-started-monotonic', repr(JOINT_STARTED),
        '--publisher-pid', str(os.getpid())]
# No new clock origin; the launcher also rejects entry after the publication cap.
signal.setitimer(signal.ITIMER_REAL, 0)
assert time.monotonic() < PUBLICATION_UNTIL
os.execv(argv[0], argv)
