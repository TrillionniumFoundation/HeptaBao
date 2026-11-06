#!/usr/bin/env python3
"""Stage exact unformatted snapshot forwarding source independently; no Cargo or product."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import time

os.umask(0o077)
STARTED = time.monotonic()
STAGE_SECONDS = 300.0
parser = argparse.ArgumentParser()
parser.add_argument('--self-sha256', required=True)
parser.add_argument('--carrier-sha256', required=True)
args = parser.parse_args()
args.host = 'rog'
ROOT = Path('/home/qian-qi/heptabao-native-snapshot-forward-source-8c95fb0a-20261106-r1')
SOURCE = ROOT / 'source'
CONTROL = ROOT / 'control'
OLD = Path('/home/qian-qi/heptabao-native-ssh-owner-20261104-r1/r10-native-state-helper-r1/source')
OLD_COMMIT = '49503322c7f446e5eb41e7744f1fdbd7f1192ecc'
OLD_TREE = '1d4211f91e1b34a2ed087a3bbef2e2884bac88e9'
COMMIT = '8c95fb0a8b2f61933a09b04986df2bafc9e7095c'
TREE = 'f412f1524e08a56e23374897d329bfcf6295f4fe'
PARENT = '808e45d690f177ecb922e13d1ed19f7877156094'
ANCESTRY = (
    ('8c95fb0a8b2f61933a09b04986df2bafc9e7095c', '808e45d690f177ecb922e13d1ed19f7877156094'),
    ('808e45d690f177ecb922e13d1ed19f7877156094', 'e3afc157447d35c861f275a761b29da3e42aff8e'),
    ('e3afc157447d35c861f275a761b29da3e42aff8e', '4e808d0ecb1bcded22870a7ec960dfb2491cf6ec'),
    ('4e808d0ecb1bcded22870a7ec960dfb2491cf6ec', '1c66541993662f92cf717154e33717abedb2ea74'),
    ('1c66541993662f92cf717154e33717abedb2ea74', '6d02ceca629163e1c07480fa1f21520434407143'),
    ('6d02ceca629163e1c07480fa1f21520434407143', '19ba09ab5c494f25a3531749b0b99fc5c651d56c'),
    ('19ba09ab5c494f25a3531749b0b99fc5c651d56c', 'e69e52f28c653d28c5ae36dbbf6eb51b844536bc'),
    ('e69e52f28c653d28c5ae36dbbf6eb51b844536bc', 'c133d7e7b8a1df5f0be8f4337893f234c6ccede2'),
    ('c133d7e7b8a1df5f0be8f4337893f234c6ccede2', 'df026fe323dd7cf0f0ec57d7d2d9c5a79897053c'),
    ('df026fe323dd7cf0f0ec57d7d2d9c5a79897053c', '6304a898192bfdf7eabec3c4ea40f7166e59a137'),
    ('6304a898192bfdf7eabec3c4ea40f7166e59a137', 'e5de554f5dfe99f0de30012122fe3e248fb60532'),
    ('e5de554f5dfe99f0de30012122fe3e248fb60532', 'fab39e28c7d0b6d0d1482e98cde1c291b6fc88cd'),
    ('fab39e28c7d0b6d0d1482e98cde1c291b6fc88cd', '6d3040a2dbd06661a67f5c62df259ff446eb8515'),
    ('6d3040a2dbd06661a67f5c62df259ff446eb8515', '49503322c7f446e5eb41e7744f1fdbd7f1192ecc'),
)
ROOT_COMMIT = '67d79b3b5442ed033d38929eab2010403463e56d'
ORIGIN = 'https://github.com/TrillionniumFoundation/HeptaBao.git'
EXPECTED_CONTROLS = {
    "normal_same_root_publication_build.py": (35452, "93dd6190c7f081305defdbc1c49600974bfa581d943736c77798d51a1c8f54be"),
    "launch_normal_same_root_publication.py": (35592, "8c0ba96f4953ba934d2dd067ef8bc7de2534f93181d99816fe38b056f564ab96"),
    "normal-test-groups.public.json": (6249, "0566f7f98ea16a4c1df43ebaf992172646ad91623c18f68fcc59f7c08b53d1f1"),
    "prior-observer-build-authority.public.json": (726, "820a3243ba5be87f4d8fdf3d47d68361a2f2d6a95043d38c0086afab1cf559b6"),
}
FAILED_ROOT = Path('/home/qian-qi/heptabao-phaseb-fresh-ingress-observer-normal-20261104-r1')
FAILED_SOURCE = FAILED_ROOT / 'source'
FAILED_COMMIT = 'bf0aaec1dcafbf476c0ab3a75544bb0eafaeff24'
FAILED_TREE = 'ac4027db88fec69381ea0c6bba953d9a99c4e82a'
FAILED_AUTHORITY_NAME = 'prior-observer-build-authority.public.json'
FAILED_AUTHORITY_SHA = '820a3243ba5be87f4d8fdf3d47d68361a2f2d6a95043d38c0086afab1cf559b6'
FAILED_FILES = {
    'control/stage-result.public.json': (6838, 'bb2bd7b46974dc18bcb87325ea55c46383e17f2f8a521f2eaa77b1fc9fba8d2b'),
    'build-control-r1/launch-preflight.public.json': (12914, '91b8fe2e1d6e34d1e0b885a9bbb81c27e83e1d6f3f07cb4235cb2314b27e29d4'),
    'normal-release-tests-r1/intent.public.json': (7838, 'ad7adbf410217af34555e9b9135505cb8f70309facfa748f4fb1c3f0614eedb2'),
    'normal-release-tests-r1/result.public.json': (9233, '2947b177c2b7ca145a499175567aec632c76d12641c8afa4276ae900dda3a122'),
    'normal-release-tests-r1/normal-release-build.public.json': (710, '654c0e9dd676855d585746275be3dc92188c843e576d873d6b3607141fb9f412'),
    'normal-release-tests-r1/normal-release-build.stderr': (27914, 'd47156c8828983229eccec58c9a4cd5f1535b653c7d59fab9ddf4db72839ee3e'),
    'normal-release-tests-r1/normal-release-build.stdout': (384196, '324a6b59e740e1ed2dc0c447ce638557d5cbd53cdec2c5b3afaa0a701cee3c92'),
    'control/stage_source_phaseb_observer.py': (18774, '2cfc47c230d7a4780e758ee8736e4cd6f1412a2f65174c5581be48038581b32a'),
    'control/launch_normal_phaseb_observer.py': (22961, '56c7b06d4329e4fdb72079a089ad2f1509e856357328d849d58844236b86fd63'),
    'control/normal_phaseb_observer_build.py': (20791, 'c46efcee52b0b836f8c6539e86a02114c10828b0a295f4571178643dcc0f0273'),
    'control/normal-test-groups.public.json': (6249, '0566f7f98ea16a4c1df43ebaf992172646ad91623c18f68fcc59f7c08b53d1f1'),
    'source/crates/heptabao-server/src/ha_native_v6_runtime.rs': (61578, 'cf0e9e69bf295591d3a904458500bfcf7b01acaa0987ae1da8761f76b9ee136d'),
}

children = []
protected = 0
pending_signal = None
created_control = False

class Cancelled(BaseException):
    pass


def on_signal(signum, _frame):
    global pending_signal
    pending_signal = signum
    if not protected:
        raise Cancelled()


for signum in (signal.SIGINT, signal.SIGTERM):
    signal.signal(signum, on_signal)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def stable_read(path, limit, expected_size=None, expected_sha=None):
    assert path.resolve(strict=True) == path
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
        assert before.st_nlink == 1 and 0 <= before.st_size <= limit
        chunks, count = [], 0
        while True:
            part = os.read(fd, min(1024 * 1024, limit + 1 - count))
            if not part:
                break
            chunks.append(part)
            count += len(part)
            assert count <= limit
        raw = b''.join(chunks)
        assert count == before.st_size
        assert identity(before) == identity(os.fstat(fd)) == identity(path.lstat())
        if expected_size is not None:
            assert count == expected_size
        if expected_sha is not None:
            assert digest(raw) == expected_sha
        return raw
    finally:
        os.close(fd)


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw)
        out.flush()
        os.fchmod(out.fileno(), mode)
        os.fsync(out.fileno())


def public(path, value):
    create(path, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())
    fsync_dir(path.parent)


def group_members(pgid):
    raw = subprocess.check_output(
        ['/bin/ps', '-axo', 'pid=,ppid=,pgid=,stat='], text=True, timeout=10)
    result = []
    for line in raw.splitlines():
        values = line.split()
        if len(values) >= 4 and int(values[2]) == pgid:
            result.append({'pid': int(values[0]), 'ppid': int(values[1]),
                           'pgid': int(values[2]), 'state': values[3]})
    return result


def stop_owned(process):
    # Signal only while the original direct child has not been reaped.
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
    # A residual group after reap is a failure, never authority to signal it.
    return group_members(process.pid)


environment = dict(os.environ)
environment.update({'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
                    'LANG': 'C', 'LC_ALL': 'C', 'GIT_NO_LAZY_FETCH': '1',
                    'GIT_NO_REPLACE_OBJECTS': '1',
                    'GIT_ALLOW_PROTOCOL': 'file' if args.host == 'mac' else 'file:https'})
for key in list(environment):
    if key in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY',
               'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_CONFIG_COUNT') or key.startswith('GIT_CONFIG_KEY_') or key.startswith('GIT_CONFIG_VALUE_'):
        environment.pop(key)


def owned(label, argv, limit=90, cwd=None):
    global protected
    prefix = '%03d-%s' % (len(children), label)
    stdout_path = CONTROL / (prefix + '.stdout')
    stderr_path = CONTROL / (prefix + '.stderr')
    start = time.monotonic()
    timed_out = False
    with stdout_path.open('xb') as out, stderr_path.open('xb') as err:
        protected += 1
        try:
            process = subprocess.Popen(argv, cwd=cwd, env=environment,
                                       stdin=subprocess.DEVNULL, stdout=out,
                                       stderr=err, start_new_session=True)
            children.append((prefix, process))
        finally:
            protected -= 1
        if pending_signal is not None:
            raise Cancelled()
        try:
            code = process.wait(timeout=limit)
        except subprocess.TimeoutExpired:
            timed_out = True
            stop_owned(process)
            code = process.returncode
        finally:
            if process.poll() is None:
                stop_owned(process)
            out.flush()
            err.flush()
            os.fsync(out.fileno())
            os.fsync(err.fileno())
    remaining = group_members(process.pid)
    receipt = {'argv': argv, 'exit_code': code, 'timed_out': timed_out,
               'elapsed_seconds': time.monotonic() - start, 'limit_seconds': limit,
               'pid': process.pid, 'direct_child_reaped': process.returncode is not None,
               'remaining': remaining, 'stdout_sha256': digest(stdout_path.read_bytes()),
               'stderr_sha256': digest(stderr_path.read_bytes())}
    public(CONTROL / (prefix + '.public.json'), receipt)
    assert code == 0 and not timed_out and not remaining, 'owned command failed: ' + label
    return stdout_path.read_bytes()


def git(path, *command):
    return owned('git-' + command[0], ['/usr/bin/git', '-c', 'gc.auto=0',
        '-c', 'maintenance.auto=false', '-c', 'core.hooksPath=' + str(CONTROL / 'empty-hooks'),
        '-c', 'core.fsmonitor=false', '-c', 'log.showSignature=false',
        '-c', 'protocol.allow=never', '-c', 'protocol.file.allow=always',
        '-c', 'protocol.https.allow=' + ('never' if args.host == 'mac' else 'always'),
        '-C', str(path), *command])




def stage_remaining():
    value = STAGE_SECONDS - (time.monotonic() - STARTED)
    assert value > 0, 'source stage absolute deadline'
    return value


# All original owned-child lifecycle code above is retained byte for byte.
# Clamp each new source command to its existing leaf limit and this stage budget.
original_owned = owned
def owned(label, argv, limit=90, cwd=None):
    return original_owned(label, argv, min(limit, stage_remaining()), cwd)


def freeze(path):
    return {'commit': git(path, 'rev-parse', 'HEAD').decode().strip(),
            'tree': git(path, 'rev-parse', 'HEAD^{tree}').decode().strip(),
            'status': git(path, 'status', '--porcelain=v1', '--untracked-files=all').decode()}


def preserve_failed_observer():
    stage_remaining()
    before = freeze(FAILED_SOURCE)
    assert before == {'commit': FAILED_COMMIT, 'tree': FAILED_TREE, 'status': ''}
    rows, loaded = {}, {}
    for relative, (size, expected_sha) in FAILED_FILES.items():
        stage_remaining()
        path = FAILED_ROOT / relative
        info = path.lstat()
        raw = stable_read(path, size, size, expected_sha)
        assert identity(info) == identity(path.lstat())
        rows[relative] = {'path': str(path), 'bytes': size, 'sha256': expected_sha,
                          'identity': list(identity(info))}
        if relative in ('normal-release-tests-r1/result.public.json',
                        'normal-release-tests-r1/normal-release-build.public.json'):
            loaded[relative] = json.loads(raw)
    authority_path = CONTROL / FAILED_AUTHORITY_NAME
    authority_info = authority_path.lstat()
    authority_raw = stable_read(authority_path, 726, 726, FAILED_AUTHORITY_SHA)
    assert identity(authority_info) == identity(authority_path.lstat())
    authority = json.loads(authority_raw)
    assert authority['job_id'] == '1a1a87f578a-fc05-2ee0'
    assert authority['state'] == 'failed' and authority['exit_code'] == 1
    assert authority['output_complete'] and authority['output_durable']
    assert authority['terminal_publication_confirmed']
    assert not authority['timed_out'] and not authority['cancelled'] and not authority['automatic_retry']
    assert all(value is False for value in authority['log_truncated'].values())
    assert all(value is None for value in authority['log_errors'].values())
    failed = loaded['normal-release-tests-r1/result.public.json']
    child = loaded['normal-release-tests-r1/normal-release-build.public.json']
    assert failed['source_commit'] == FAILED_COMMIT and failed['source_tree'] == FAILED_TREE
    assert failed['status'] == 'failed' and failed['failure_type'] == 'AssertionError'
    assert failed['failure'] == 'normal production binary compilation failed'
    assert failed['runtime_tests_started'] is False and failed['group_results'] == []
    assert failed['test_count'] == 44 and failed['normal_release_build'] == child
    assert child['exit_code'] == 101 and not child['timed_out']
    assert child['outer_cap_seconds'] == 1800 and child['elapsed_seconds'] < 1800
    assert child['direct_child_reaped'] and child['remaining'] == []
    assert len(failed['cleanup']) == 1
    assert all(row['direct_child_reaped'] and row['remaining'] == []
               and row['exit_code'] == 101 and not row.get('cleanup_error_type')
               for row in failed['cleanup'])
    assert freeze(FAILED_SOURCE) == before
    stage_remaining()
    return {'source_before': before, 'source_after': before, 'files': rows,
            'authority': {'path': str(authority_path), 'bytes': 726,
                          'sha256': FAILED_AUTHORITY_SHA,
                          'identity': list(identity(authority_info)),
                          'source': 'exact cached authoritative terminal receipt'},
            'prior_failed_build_replayed': False}


def walk_error(error):
    raise error


def independent_git():
    assert git(SOURCE, 'rev-parse', '--absolute-git-dir').decode().strip() == str(SOURCE / '.git')
    common = Path(git(SOURCE, 'rev-parse', '--git-common-dir').decode().strip())
    common = common if common.is_absolute() else SOURCE / common
    assert common.resolve(strict=True) == SOURCE / '.git'
    assert not os.path.lexists(SOURCE / '.git/objects/info/alternates')
    count = 0
    for directory, dirs, names in os.walk(SOURCE / '.git/objects', followlinks=False, onerror=walk_error):
        stage_remaining()
        for name in dirs:
            p = Path(directory) / name
            info = p.lstat()
            assert stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == os.getuid()
        for name in names:
            p = Path(directory) / name
            info = p.lstat()
            assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
            assert not name.endswith('.promisor')
            count += 1
    assert count > 0
    return {'independent_git_directory': True, 'no_alternates': True,
            'no_shared_object_links': True, 'object_files_checked': count}


def verify_full_worktree():
    raw = git(SOURCE, 'ls-tree', '-r', '-z', '--full-tree', 'HEAD')
    entries = []
    for item in raw.split(b'\0'):
        if not item:
            continue
        head, relative_raw = item.split(b'\t', 1)
        mode, kind, object_id = head.decode().split()
        relative = relative_raw.decode('utf-8')
        p = PurePosixPath(relative)
        assert kind == 'blob' and mode in ('100644', '100755')
        assert not p.is_absolute() and '..' not in p.parts and str(p) == relative
        entries.append((relative, mode, object_id))
    assert len(entries) == 3928 and len({x[0] for x in entries}) == 3928
    indexed = []
    for item in git(SOURCE, 'ls-files', '--stage', '-z').split(b'\0'):
        if not item:
            continue
        head, path = item.split(b'\t', 1)
        mode, object_id, stage = head.decode().split()
        assert stage == '0'
        indexed.append((path.decode('utf-8'), mode, object_id))
    assert sorted(indexed) == sorted(entries)
    total, proof = 0, hashlib.sha256()
    for relative, mode, object_id in entries:
        stage_remaining()
        path = SOURCE / relative
        assert path.resolve(strict=True) == path
        content = stable_read(path, 2 * 1024 * 1024)
        info = path.lstat()
        assert bool(info.st_mode & 0o111) == (mode == '100755')
        assert not info.st_mode & 0o022
        assert blob(content) == object_id
        total += len(content)
        assert total <= 128 * 1024 * 1024
        proof.update((relative + '\0' + mode + '\0' + object_id + '\0' + str(len(content)) + '\n').encode())
    runtime = stable_read(SOURCE / 'crates/heptabao-server/src/ha_native_v6_runtime.rs',
                          65536, 61623,
                          '5291c584d8c91d6517cf4282fbbb66424dbdb184e070b9b23d11a4cbc564074a')
    assert blob(runtime) == '3289da21ebb25a1efd04ae0d0fd1013ac7ac8fb3'
    stage_remaining()
    return {'tracked_leaf_count': len(entries), 'tracked_bytes': total,
            'full_leaf_index_sha256': proof.hexdigest(), 'index_matches_tree': True,
            'all_tracked_worktree_blobs_and_modes_match': True}



def canonical_bundle_header(raw):
    end = raw.find(b'\n\n', 0, 65536)
    assert end > 0 and raw[end + 2:end + 6] == b'PACK'
    lines = raw[:end].split(b'\n')
    assert lines.pop(0) == b'# v2 git bundle'
    prerequisites, heads = [], []
    for line in lines:
        if line.startswith(b'-'):
            object_id, separator, _message = line[1:].partition(b' ')
            assert separator
            prerequisites.append(object_id.decode('ascii'))
        else:
            object_id, separator, name = line.partition(b' ')
            assert separator
            heads.append([object_id.decode('ascii'), name.decode('ascii')])
    assert prerequisites == [OLD_COMMIT]
    assert heads == [[COMMIT, 'HEAD']]
    return {'version': 2, 'prerequisites': prerequisites, 'heads': heads,
            'header_sha256': digest(raw[:end + 2])}

assert (os.uname().sysname, os.uname().machine, os.getuid()) == ('Linux', 'x86_64', 1000)
assert ROOT.parent.resolve(strict=True) == ROOT.parent and ROOT.parent.stat().st_uid == os.getuid()
assert OLD.resolve(strict=True) == OLD
source_index = sys.orig_argv.index('-c') + 1
self_source = sys.orig_argv[source_index]
assert digest(self_source.encode()) == args.self_sha256
carrier = sys.stdin.buffer.read(262145)
assert len(carrier) <= 262144 and digest(carrier) == args.carrier_sha256
data = json.loads(carrier)
assert set(data) == {'schema', 'controls'} and data['schema'] == 'heptabao.same-root-publication-inert-controls.v1'
assert set(data['controls']) == set(EXPECTED_CONTROLS)
for name, (size, expected_sha) in EXPECTED_CONTROLS.items():
    raw = data['controls'][name].encode()
    assert len(raw) == size and digest(raw) == expected_sha
    if name.endswith('.py'):
        compile(raw, name, 'exec')
groups = json.loads(data['controls']['normal-test-groups.public.json'])
assert [(g['label'], len(g['tests'])) for g in groups] == [
    ('ssh25', 25), ('mount1', 1), ('redirect5', 5), ('actor2', 2), ('ordinary5', 5), ('no_forward6', 6)]
assert sum(len(g['tests']) for g in groups) == 44 and all(g['runtime_seconds'] == 600 for g in groups)
assert not os.path.lexists(ROOT)
result = {'schema': 'heptabao.native-snapshot-forward-independent-source-stage.v1', 'status': 'failed',
          'source_commit': COMMIT, 'source_tree': TREE, 'sole_parent': PARENT,
          'root': str(ROOT), 'source': str(SOURCE), 'host': 'rog',
          'stager_sha256': args.self_sha256, 'carrier_sha256': args.carrier_sha256,
          'original_git_leaf_cap_seconds': 90, 'original_clone_cap_seconds': 180,
          'new_stage_total_seconds': 300, 'new_supervisor_seconds': 360,
          'server_started': False, 'compiler_started': False, 'production_changed': False,
          'source_ref': None, 'source_fetch_argument': COMMIT,
          'stage_purpose': 'unformatted_snapshot_forward_source_for_separate_formatter_admission',
          'historical_controls_executed': False, 'candidate_build_qualification': False,
          'formatter_executed': False, 'rust_tests_executed': False,
          'canonical_history_count': 3766, 'actual_build_qualification': False,
          'controls': {}, 'started_ns': time.time_ns()}
before = None
try:
    stage_remaining()
    ROOT.mkdir(mode=0o700)
    CONTROL.mkdir(mode=0o700)
    created_control = True
    (CONTROL / 'empty-hooks').mkdir(mode=0o700)
    (CONTROL / 'empty-template').mkdir(mode=0o700)
    create(CONTROL / 'stage_source_native_snapshot_forward.py', self_source.encode())
    for name in EXPECTED_CONTROLS:
        create(CONTROL / name, data['controls'][name].encode())
        result['controls'][name] = {'sha256': EXPECTED_CONTROLS[name][1],
                                    'bytes': EXPECTED_CONTROLS[name][0]}
    fsync_dir(CONTROL)
    fsync_dir(ROOT)
    fsync_dir(ROOT.parent)
    public(CONTROL / 'stage-intent.public.json', result)
    before = freeze(OLD)
    assert before == {'commit': OLD_COMMIT, 'tree': OLD_TREE, 'status': ''}
    result['old_source_before'] = before
    result['failed_observer_before'] = preserve_failed_observer()
    owned('independent-local-clone',
          ['/usr/bin/git', '-c', 'gc.auto=0', '-c', 'maintenance.auto=false',
           '-c', 'core.hooksPath=' + str(CONTROL / 'empty-hooks'),
           '-c', 'protocol.allow=never', '-c', 'protocol.file.allow=always',
           'clone', '--no-hardlinks', '--dissociate', '--no-checkout',
           '--template=' + str(CONTROL / 'empty-template'), str(OLD), str(SOURCE)], 180)
    git(SOURCE, 'remote', 'set-url', 'origin', ORIGIN)
    assert git(SOURCE, 'remote', 'get-url', 'origin').decode().strip() == ORIGIN
    git(SOURCE, '-c', 'fetch.fsckObjects=true', '-c', 'transfer.fsckObjects=true',
        'fetch', '--no-tags', '--no-recurse-submodules', '--no-write-fetch-head', 'origin', COMMIT)
    assert git(SOURCE, 'rev-parse', COMMIT + '^{tree}').decode().strip() == TREE
    for child_commit, parent_commit in ANCESTRY:
        assert git(SOURCE, 'show', '-s', '--format=%P', child_commit).decode().strip() == parent_commit
    added = git(SOURCE, 'rev-list', COMMIT, '^' + OLD_COMMIT).decode().splitlines()
    assert len(added) == 14 and set(added) == {row[0] for row in ANCESTRY}
    result['new_commits_since_actual_495'] = added
    assert git(SOURCE, 'rev-list', '--count', OLD_COMMIT).decode().strip() == '3752'
    assert git(SOURCE, 'rev-list', '--count', COMMIT).decode().strip() == '3766'
    assert git(SOURCE, 'rev-list', '--max-parents=0', COMMIT).decode().strip() == ROOT_COMMIT
    git(SOURCE, 'checkout', '--detach', COMMIT)
    assert freeze(SOURCE) == {'commit': COMMIT, 'tree': TREE, 'status': ''}
    git(SOURCE, 'fsck', '--full', '--strict', '--no-reflogs', '--no-dangling', COMMIT)
    result.update(independent_git())
    result['full_worktree'] = verify_full_worktree()
    assert result['full_worktree']['tracked_bytes'] == 62460068
    assert result['full_worktree']['full_leaf_index_sha256'] == '6baa9290fa3ee8f67bc22a77697d38a7ad1c4c776fc769f5f04ee645de204574'
    assert freeze(SOURCE) == {'commit': COMMIT, 'tree': TREE, 'status': ''}

    canonical_path = CONTROL / 'canonical-native-snapshot-forward-8c95fb0a-from495.bundle'
    assert not os.path.lexists(canonical_path)
    git(SOURCE, 'bundle', 'create', '--version=2', str(canonical_path), 'HEAD', '^' + OLD_COMMIT)
    canonical_raw = stable_read(canonical_path, 4 * 1024 * 1024)
    assert 0 < len(canonical_raw) <= 4 * 1024 * 1024
    canonical_identity = identity(canonical_path.lstat())
    assert stat.S_IMODE(canonical_path.lstat().st_mode) == 0o600
    canonical_header = canonical_bundle_header(canonical_raw)
    fd = os.open(canonical_path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        assert identity(os.fstat(fd)) == canonical_identity
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_dir(CONTROL)
    git(SOURCE, 'bundle', 'verify', str(canonical_path))
    assert git(SOURCE, 'bundle', 'list-heads', str(canonical_path)).decode().strip() == COMMIT + ' HEAD'
    assert identity(canonical_path.lstat()) == canonical_identity
    assert stable_read(canonical_path, 4 * 1024 * 1024) == canonical_raw
    result['canonical_bundle'] = {'path': str(canonical_path), 'bytes': len(canonical_raw),
                                  'sha256': digest(canonical_raw), 'header': canonical_header,
                                  'identity': list(canonical_identity),
                                  'public_network_import_required_on_mac': False}
    assert freeze(SOURCE) == {'commit': COMMIT, 'tree': TREE, 'status': ''}
    result['old_source_after'] = freeze(OLD)
    assert result['old_source_after'] == before
    result['failed_observer_after'] = preserve_failed_observer()
    assert result['failed_observer_after'] == result['failed_observer_before']
    stage_remaining()
    result.update(status='prepared', source_clean=True, old_source_unchanged=True,
                  exact_test_count=44,
                  exact_groups=[[g['label'], len(g['tests'])] for g in groups],
                  additional_existing_tests=7, additional_cold_h2_tests=9,
                  additional_same_root_publication_tests=1, original_60_test_count=60,
                  public_network_fetch_used=True, full_strict_fsck_passed=True)
except BaseException as error:
    result['error_type'] = type(error).__name__
    # All raw Git stderr remains in new private files; no exception text is published.
finally:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    cleanup = []
    for label, process in reversed(children):
        try:
            remaining_group = stop_owned(process)
            cleanup.append({'label': label, 'pid': process.pid, 'exit_code': process.returncode,
                            'direct_child_reaped': process.returncode is not None,
                            'remaining': remaining_group})
        except BaseException as error:
            cleanup.append({'label': label, 'pid': process.pid,
                            'direct_child_reaped': process.returncode is not None,
                            'remaining': None, 'cleanup_error_type': type(error).__name__})
    result['cleanup'] = cleanup
    if pending_signal is not None or any(x.get('cleanup_error_type') or x['remaining'] or not x['direct_child_reaped'] for x in cleanup):
        result['status'] = 'failed'
    result['elapsed_seconds_after_cleanup'] = time.monotonic() - STARTED
    result['within_new_stage_deadline'] = result['elapsed_seconds_after_cleanup'] < STAGE_SECONDS
    if not result['within_new_stage_deadline']:
        result['status'] = 'failed'
    result['terminal_ns'] = time.time_ns()
    if created_control:
        public(CONTROL / 'stage-result.public.json', result)
    print(json.dumps({'status': result['status'], 'source_commit': COMMIT, 'source_tree': TREE,
                      'result_path': str(CONTROL / 'stage-result.public.json') if created_control else None,
                      'all_owned_stopped': all(not x.get('cleanup_error_type') and not x['remaining'] and x['direct_child_reaped'] for x in cleanup),
                      'within_new_stage_deadline': time.monotonic() - STARTED < STAGE_SECONDS,
                      'server_started': False, 'compiler_started': False}, sort_keys=True), flush=True)
raise SystemExit(0 if result['status'] == 'prepared' and time.monotonic() - STARTED < STAGE_SECONDS else 1)
