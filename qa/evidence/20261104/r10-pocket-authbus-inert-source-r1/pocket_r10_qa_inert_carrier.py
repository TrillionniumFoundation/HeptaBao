#!/usr/bin/env python3
"""Create-only distribution of eleven approved Pocket QA files; compile only the three changed Python sources."""
from pathlib import Path
import base64, hashlib, json, os, stat, sys, time

os.umask(0o077)
PARENT = Path('/home/alex/heptabao-installed-authbus-consumer-36076-20261104-r1')
BASE = PARENT / 'shared-first-cycle-r10-qa-r1'
created_base = False
RECEIPT = BASE / 'inert-stage.result.public.json'
PINS = {
    "authbus_coordinator.py": [
        44118,
        "eaf83832144e7ecf1f369ec91007b0d8b4dc55f59342f3ce27ca64a4aea6f76d"
    ],
    "pocket_authbus_cache_cas_r1.mjs": [
        6846,
        "91644b97ae7deb4ede468832d3f91646bb00cd919149a510bfffe38d23544af8"
    ],
    "pocket_first_cycle_consumer_r1.mjs": [
        24016,
        "6455180970f37831bb1a4084aab8583822c900586f9fabcbd7536332bc45429e"
    ],
    "pocket_first_cycle_inputs_r1.py": [
        20076,
        "1ffcca778b9f78f0f63679b0cf0050afc8d520ca3c823ee65fc0aed9bd84f5ac"
    ],
    "pocket_first_cycle_launch_r10.py": [
        13062,
        "1cbec91c3b19c3c488ae8976c01fee2b6eb40c03c56b1c55064ccbd5268f93ee"
    ],
    "pocket_first_cycle_prepare_r10.py": [
        7091,
        "900be9fdafb575a47a29c74779b5aad298054f593884d81e15c60d20a0b2ae1d"
    ],
    "pocket_native_auth_rows_cas_r1.mjs": [
        2703,
        "4b4fc09d04b58896965856d436ef883ead90eb140b051efc15261ff72912ae83"
    ],
    "pocket_native_observer_r3.mjs": [
        11901,
        "663b93419e66d92d5518135ef01c6703a67e1ddfed2d0b313beabca0998c3027"
    ],
    "pocket_shared_first_cycle_live_r2.py": [
        45061,
        "97f982832d79916deb6dbfe0ddfae56c8b4070246d52e65c6ab498483d0f9992"
    ],
    "project_trusted_profile12.py": [
        9233,
        "a7b05f1729cb658fe036d75caaeb6376149ae08a717cbdd91b69042a9b7b8e43"
    ],
    "qa-pins.public.json": [
        1955,
        "62cefe180d5c946d8586924b93345c71c2b510cb878f52614f627026752e56f3"
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
    temporary = BASE / ('.' + name + '.hepta-r10-pocket-qa-inert-r1.tmp')
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
result = {'schema': 'heptabao.pocket-r10-qa-inert-carrier.v1', 'status': 'failed',
          'started_ns': time.time_ns(), 'files': [], 'source_executed': False,
          'git_started': False, 'compiler_started': False, 'service_started': False,
          'python_compile_only': True, 'artifact_transfer_started': False,
          'python_compiled_files': []}
try:
    incoming = sys.stdin.buffer.read(262145)
    assert 0 < len(incoming) <= 262144
    payload = json.loads(incoming)
    assert set(payload) == {'schema', 'files'} and payload['schema'] == 'heptabao.pocket-r10-qa-inert-inputs.v1'
    assert set(payload['files']) == set(PINS)
    decoded = {}
    for name, (length, digest) in PINS.items():
        raw = base64.b64decode(payload['files'][name], validate=True)
        assert len(raw) == length and sha(raw) == digest
        if name in ('pocket_first_cycle_launch_r10.py', 'pocket_first_cycle_prepare_r10.py',
                    'pocket_shared_first_cycle_live_r2.py'):
            compile(raw, name, 'exec')
            result['python_compiled_files'].append(name)
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
