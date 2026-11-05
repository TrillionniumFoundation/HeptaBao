#!/usr/bin/env python3
"""Create-only fresh post-recovery QA inputs; compile syntax, execute none."""
from pathlib import Path
import ast, base64, hashlib, json, os, stat, sys, time

os.umask(0o077)
PARENT = Path('/home/qian-qi/heptabao-ha-closure-20261103-r1')
BASE = PARENT / 'normal-r10-pocket3-mac1-postrecovery-cold-control-r1'
RECEIPT = BASE / 'inert-stage.result.public.json'
PINS = {
    "launch_normal_r10_pocket_postrecovery_cold_r1.py": [
        22623,
        "5c4cd9276a1ddc012547a1106f310f94af409d8d66599ba69369f9861a302b01"
    ],
    "native_v6_pocket_source_postrecovery_cold_r10_r1.py": [
        54668,
        "06acd60952d5804dd8bd7b67f399216f26df8e04a24d58e2bea7e82383c9ac47"
    ],
    "read_stopped_postrecovery_frontier_r1.py": [
        16274,
        "e951cca69fdc9e85dfd68b4af46b2a0cb01f7caae9ba24b9f0d16c985d476f43"
    ],
    "read_stopped_recovered_cipher_r1.py": [
        13207,
        "096792825beee8577a9cbd33fe039e08a284a2186ce485131ac6b74ee56cc956"
    ],
    "probe_normal_build_r10_r1.py": [
        6445,
        "4f556104c0a66fd7b7fa59811bfec1e5dcb701a42cd9231aa2812233a5a840ee"
    ],
    "deadline_qa/ha_multihost_live.py": [
        79776,
        "e37e39459f290c8b9121039196038c9021607e86ed4112def8060d20b1233460"
    ],
    "deadline_qa/native_v6_ha_multihost_live.py": [
        87254,
        "6fb8f2dbac97730bea706503fb07e9fd5de60e794475d52f32290e374f86d429"
    ],
    "deadline_qa/native_v6_ha_direct_lan_live.py": [
        14046,
        "bc99f154d89dfbe8a82babb8c50bcda3accaf8c486c51750db48bfc4003932ea"
    ],
    "deadline_qa/native_ha_foreground_watchdog.py": [
        41618,
        "04189572097f5f7ac1f4ea3eaf53afaa3bf9854043cec9e190b9fd96d628ef89"
    ]
}
def sha(raw):
    return hashlib.sha256(raw).hexdigest()
def ident(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)
def sync_dir(directory=BASE):
    assert directory in (BASE, BASE / 'deadline_qa')
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
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
    assert destination.parent in (BASE, BASE / 'deadline_qa')
    if os.path.lexists(destination):
        return {'path': str(destination), 'publication': 'existing_exact', **exact(destination, raw)}
    temporary = destination.parent / ('.' + destination.name + '.hepta-r10-inert-r1.tmp')
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
assert PARENT.stat().st_mode & 0o022 == 0
assert not os.path.lexists(BASE)
assert hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest() == 'd90fa41f7e59edf2f2a732ea082cac83085a2a3695a503cd82b6b4eef9cab9f3'
created = False
result = {'schema': 'heptabao.r10-validation-control-inert-carrier.v1', 'status': 'failed',
          'started_ns': time.time_ns(), 'files': [], 'source_executed': False,
          'git_started': False, 'compiler_started': False, 'service_started': False}
try:
    incoming = sys.stdin.buffer.read(1048577)
    assert 0 < len(incoming) <= 1048576
    payload = json.loads(incoming)
    assert set(payload) == {'schema', 'files'} and payload['schema'] == 'heptabao.r10-validation-control-inert-inputs.v1'
    assert set(payload['files']) == set(PINS)
    decoded = {}
    for name, (length, digest) in PINS.items():
        relative = Path(name)
        assert not relative.is_absolute() and '..' not in relative.parts
        assert relative.parent in (Path('.'), Path('deadline_qa')) and relative.suffix == '.py'
        raw = base64.b64decode(payload['files'][name], validate=True)
        assert len(raw) == length and sha(raw) == digest
        decoded[name] = raw
    syntax = []
    for name in tuple(PINS):
        ast.parse(decoded[name], filename=name)
        compile(decoded[name], name, 'exec', dont_inherit=True)
        syntax.append({'name': name, 'sha256': sha(decoded[name]), 'ast_parse': True, 'compile_only': True, 'source_executed': False})
    result['syntax'] = syntax
    BASE.mkdir(mode=0o700)
    created = True
    (BASE / 'deadline_qa').mkdir(mode=0o700)
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
    if created:
        publish(RECEIPT.name, raw)
    else:
        result['receipt_not_created'] = True
    print(json.dumps(result, sort_keys=True), flush=True)
sys.exit(0 if result['status'] == 'prepared' else 1)
