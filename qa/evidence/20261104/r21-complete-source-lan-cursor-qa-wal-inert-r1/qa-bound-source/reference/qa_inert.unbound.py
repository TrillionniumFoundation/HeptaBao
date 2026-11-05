#!/usr/bin/env python3
"""Create-only publication of seven reviewed H2 QA sources and one actual-bound build binding."""
from pathlib import Path
import base64, hashlib, json, os, stat, sys, time

ACTUAL_INPUTS_READY = False
if not ACTUAL_INPUTS_READY:
    raise RuntimeError('actual_qa_build_binding_unresolved')
os.umask(0o077)
PARENT = Path('/home/qian-qi')
BASE = PARENT / 'heptabao-native-h2-qa-controls-df026-20261105-r1'
created_base = False
RECEIPT = BASE / 'inert-stage.result.public.json'
PINS = {
    "build_native_h2_client_r1.py": [
        35155,
        "2e2ea6edd029b3d7164fbe6a85826ef3523a0ec60586d330b539761d870c0a35"
    ],
    "inputs/native_h2_client.rs": [
        19382,
        "41347a71055e5c7086a256549f25f20d52ba8361e16926b4470f3448425f90dd"
    ],
    "inputs/native_h2_client_tests.rs": [
        8942,
        "7f23470287fe953f0271e974d6eda759b7daf9f15bc363d522a02d3633e012c2"
    ],
    "inputs/Cargo.toml": [
        957,
        "960de7b19776cda4bd8a00561a417f72b08ca320efb93ec05028a3be0e7315e5"
    ],
    "inputs/canonical.Cargo.lock": [
        101193,
        "d2d07ea13e42a8d4ba65fafc642ca98ae1a7de68f6cd46a69043332267f378d5"
    ],
    "inputs/owned_reference_phaseb_r3.py": [
        61210,
        "10816d06fd5ad59175872ccb7db1337d7677e92405a26a7ab1cae2796ee0a86c"
    ],
    "inputs/official_cli_reference_r4.py": [
        46586,
        "18318841d3538e60fddf951708055a206402f5bf1ecdacc2bfceabec4f998dd9"
    ],
    "build-binding.private.json": [
        None,
        None
    ]
}
def sha(raw):
    return hashlib.sha256(raw).hexdigest()
def ident(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)
def sync_dir(path=BASE):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
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
    assert name in PINS or name == RECEIPT.name
    assert destination.parent in (BASE, BASE / 'inputs')
    if os.path.lexists(destination):
        return {'path': str(destination), 'publication': 'existing_exact', **exact(destination, raw)}
    temporary = destination.with_name('.' + destination.name + '.hepta-h2-qa-inert-r1.tmp')
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
    sync_dir(destination.parent)
    return {'path': str(destination), 'publication': publication, **exact(destination, raw)}

assert (os.uname().sysname, os.uname().machine) == ('Linux', 'x86_64')
assert os.getuid() == 1000 and PARENT.resolve(strict=True) == PARENT and PARENT.stat().st_uid == 1000
assert not os.path.lexists(BASE)
assert not os.path.lexists(RECEIPT)
result = {'schema': 'heptabao.native-h2-qa-build-inert.v1', 'status': 'failed',
          'started_ns': time.time_ns(), 'files': [], 'source_executed': False,
          'git_started': False, 'compiler_started': False, 'service_started': False,
          'python_compile_only': True, 'artifact_transfer_started': False}
try:
    incoming = sys.stdin.buffer.read(524289)
    assert 0 < len(incoming) <= 524288
    payload = json.loads(incoming)
    assert set(payload) == {'schema', 'files'} and payload['schema'] == 'heptabao.native-h2-qa-build-inputs.v1'
    assert set(payload['files']) == set(PINS)
    decoded = {}
    for name, (length, digest) in PINS.items():
        raw = base64.b64decode(payload['files'][name], validate=True)
        assert len(raw) == length and sha(raw) == digest
        if name.endswith('.py'):
            compile(raw, name, 'exec')
        decoded[name] = raw
    BASE.mkdir(mode=0o700)
    created_base = True
    (BASE / 'inputs').mkdir(mode=0o700)
    sync_dir()
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
