#!/usr/bin/env python3
"""Create-only distribution and compile-check of the reviewed X230 product test controls."""
from pathlib import Path
import base64, hashlib, json, os, stat, sys, time

os.umask(0o077)
PARENT = Path('/home/qian')
BASE = PARENT / 'heptabao-blocker-closure-r10-49503322-20261104-r1'
verified_base = False
RECEIPT = BASE / 'test-controls-inert.result.public.json'
TRANSFER_RECEIPT = BASE / 'artifacts/transfer.result.public.json'
TRANSFER_PIN = (33818, '725f9a7e51a202a2139618b933c55b1f387ef53af61035a3aa59d21394b0669a')
PINS = {
    "full34_controller.py": [
        5313,
        "001079203a066e5d69b3aa756622593f108f93a56a0537188a672d06e273b0bc"
    ],
    "comparison69_controller.py": [
        6944,
        "c2f96586d735d21b9cf17040242e96371d27239b80fdf1756ba1b175b9e900eb"
    ],
    "native271_comparison_final_r1.py": [
        9261,
        "fd88ed0b8f1c1010e79f9393dfbf6464cabcac48ece8c6e448a64b7ccc45272e"
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
assert BASE.resolve(strict=True) == BASE and BASE.is_dir() and BASE.stat().st_uid == 1000
assert not os.path.lexists(RECEIPT)
result = {'schema': 'heptabao.r10-x230-test-controls-inert-carrier.v1', 'status': 'failed',
          'started_ns': time.time_ns(), 'files': [], 'source_executed': False,
          'git_started': False, 'compiler_started': False, 'service_started': False,
          'python_compile_only': True, 'source_transfer_started': False}
try:
    incoming = sys.stdin.buffer.read(262145)
    assert 0 < len(incoming) <= 262144
    payload = json.loads(incoming)
    assert set(payload) == {'schema', 'files', 'transfer_receipt_base64'} and payload['schema'] == 'heptabao.r10-x230-test-controls-inputs.v1'
    assert set(payload['files']) == set(PINS)
    decoded = {}
    for name, (length, digest) in PINS.items():
        raw = base64.b64decode(payload['files'][name], validate=True)
        assert len(raw) == length and sha(raw) == digest
        compile(raw, name, 'exec')
        decoded[name] = raw
    receipt_raw = base64.b64decode(payload['transfer_receipt_base64'], validate=True)
    assert len(receipt_raw) == TRANSFER_PIN[0] and sha(receipt_raw) == TRANSFER_PIN[1]
    result['accepted_transfer_before'] = exact(TRANSFER_RECEIPT, receipt_raw)
    verified_base = True
    result['stdin_bytes'] = len(incoming)
    result['stdin_sha256'] = sha(incoming)
    for name, raw in decoded.items():
        result['files'].append(publish(name, raw))
    result['accepted_transfer_after'] = exact(TRANSFER_RECEIPT, receipt_raw)
    assert result['accepted_transfer_before'] == result['accepted_transfer_after']
    result['status'] = 'prepared'
except BaseException as error:
    result['error_type'] = type(error).__name__
finally:
    result['terminal_ns'] = time.time_ns()
    raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
    if verified_base:
        publish(RECEIPT.name, raw)
    print(json.dumps(result, sort_keys=True), flush=True)
sys.exit(0 if result['status'] == 'prepared' else 1)
