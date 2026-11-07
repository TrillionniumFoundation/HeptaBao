#!/usr/bin/env python3
"""Publish exact Mac normal61 plus native JWT/PKI28 controls only; never execute them."""
from pathlib import Path
import base64, hashlib, json, os, stat, sys, time

os.umask(0o077)
PARENT = Path("/Volumes/T5/hepta-vnext-recovery-20261013/hb-4a49405b-src-20261106-r1")
ROOT = PARENT / 'normal-build-r1'
BASE = ROOT / 'control'
BINDING_READY = False
STAGE_REPORT = PARENT / 'control/stage-result.public.json'
STAGE_EXPECTED = None
COMMIT = "4a49405b93c45ab1c25ecba11cde63a7ede20dce"
TREE = "f02dd113d208d79f5275005dc65a5e8aecd0e9d3"
created_root = False
created_base = False
RECEIPT = BASE / 'inert-stage.result.public.json'
PINS = {"mac_normal_same_root_publication_build.py":[42977,"9b05569375d5de0836ece83e9a93d04d6d60b50f455e535e980fefc7989f6a22"],"launch_normal_same_root_publication.py":[25832,"16b5b0fec596e59f8d4369f2597487e25282aae206f3030b0839038acb7d9b68"],"normal-test-groups.public.json":[13725,"3db98fdaf90b753b15e2c98fa256f3c5c7cd66667492db4422b2a0bfb902997d"]}
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
        assert stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
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
    temporary = BASE / ('.' + name + '.mac-full34-inert-r1.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fchmod(stream.fileno(), 0o600)
        os.fsync(stream.fileno())
        made = os.fstat(stream.fileno())
    assert stat.S_ISREG(made.st_mode) and made.st_uid == os.geteuid() and made.st_nlink == 1
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

assert BINDING_READY is True and STAGE_EXPECTED is not None
assert all(type(length) is int and length > 0 and isinstance(digest, str) and len(digest) == 64 and all(c in '0123456789abcdef' for c in digest) for length, digest in PINS.values())
assert (os.uname().sysname, os.uname().machine) == ('Darwin', 'arm64')
assert os.getuid() == os.geteuid() and PARENT.resolve(strict=True) == PARENT
assert stat.S_ISDIR(PARENT.lstat().st_mode) and PARENT.stat().st_uid == os.geteuid()
assert not os.path.lexists(ROOT)
assert not os.path.lexists(BASE)
assert not os.path.lexists(RECEIPT)
result = {'schema': 'heptabao.mac-normal61-native-jwt-pki28-controls-inert.v1', 'status': 'failed',
          'started_ns': time.time_ns(), 'files': [], 'source_executed': False,
          'source_commit': COMMIT, 'source_tree': TREE,
          'target_scope': 'fresh-create-only-owned-no-historical-runtime-inheritance',
          'git_started': False, 'compiler_started': False, 'service_started': False,
          'python_compile_only': True, 'artifact_transfer_started': False}
try:
    incoming = sys.stdin.buffer.read(262145)
    assert 0 < len(incoming) <= 262144
    payload = json.loads(incoming)
    assert set(payload) == {'schema', 'files', 'source_stage_base64'} and payload['schema'] == 'heptabao.mac-normal61-native-jwt-pki28-controls-inputs.v1'
    assert set(payload['files']) == set(PINS)
    decoded = {}
    for name, (length, digest) in PINS.items():
        raw = base64.b64decode(payload['files'][name], validate=True)
        assert len(raw) == length and sha(raw) == digest
        if name.endswith('.py'):
            compile(raw, name, 'exec')
        else:
            assert name == 'normal-test-groups.public.json'
            group_plan = json.loads(raw)
            assert set(group_plan) == {'schema', 'normal61_groups', 'native_jwt_pki_groups'}
            assert group_plan['schema'] == 'heptabao.mac.normal61-native-jwt-pki28-groups.v1'
            groups = group_plan['normal61_groups']
            native_groups = group_plan['native_jwt_pki_groups']
            assert [[g['label'], len(g['tests'])] for g in groups] == [['ssh25', 25], ['mount1', 1], ['redirect5', 5], ['actor2', 2], ['ordinary5', 5], ['no_forward6', 6]]
            assert all(g['runtime_seconds'] == 600 for g in groups)
            assert [[g['label'], g['libtest_profile'], len(g['tests'])] for g in native_groups] == [
                ['native-jwt-pki-file28', 'file', 28], ['native-jwt-pki-default28', 'default', 28]]
            assert all(g['runtime_seconds'] == 600 and len(set(g['tests'])) == 28 for g in native_groups)
            assert native_groups[0]['tests'] == native_groups[1]['tests']
        decoded[name] = raw
    stage_raw = base64.b64decode(payload['source_stage_base64'], validate=True)
    assert len(stage_raw) == STAGE_EXPECTED['bytes'] and sha(stage_raw) == STAGE_EXPECTED['sha256']
    stage_pin = exact(STAGE_REPORT, stage_raw)
    assert [str(x) for x in stage_pin['identity']] == STAGE_EXPECTED['full9']
    stage = json.loads(stage_raw)
    assert stage['schema'] == 'heptabao.final-mac-source-only-stage.v1' and stage['status'] == 'prepared'
    assert stage['source_commit'] == COMMIT and stage['source_tree'] == TREE
    assert stage['root'] == str(PARENT) and stage['source'] == str(PARENT / 'source')
    assert stage['source_clean'] and stage['independent_git_directory'] and stage['full_strict_fsck_passed']
    assert stage['controls_published'] is False and stage['compiler_started'] is False
    assert stage['within_new_stage_deadline'] and all(x['direct_child_reaped'] and not x['remaining'] and not x.get('cleanup_error_type') for x in stage['cleanup'])
    result['source_stage'] = {'path': str(STAGE_REPORT), **stage_pin}
    result['exact_groups'] = [[g['label'], len(g['tests'])] for g in groups]
    result['exact_test_count'] = sum(len(g['tests']) for g in groups)
    assert result['exact_test_count'] == 44
    result['normal_total_test_count'] = 61
    result['native_groups'] = [[g['label'], g['libtest_profile'], len(g['tests'])] for g in native_groups]
    result['native_unique_test_count'] = 28
    result['native_profile_execution_count'] = 56
    result['selected_unique_test_count'] = 89
    result['selected_profile_execution_count'] = 117
    ROOT.mkdir(mode=0o700)
    created_root = True
    parent_fd = os.open(PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    BASE.mkdir(mode=0o700)
    created_base = True
    root_fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(root_fd)
    finally:
        os.close(root_fd)
    result['stdin_bytes'] = len(incoming)
    result['stdin_sha256'] = sha(incoming)
    for name, raw in decoded.items():
        result['files'].append(publish(name, raw))
    result['status'] = 'prepared'
except BaseException as error:
    result['error_type'] = type(error).__name__
finally:
    result['root_created'] = created_root
    result['control_created'] = created_base
    result['terminal_ns'] = time.time_ns()
    raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
    if created_base:
        result['receipt'] = publish(RECEIPT.name, raw)
    print(json.dumps(result, sort_keys=True), flush=True)
sys.exit(0 if result['status'] == 'prepared' else 1)
