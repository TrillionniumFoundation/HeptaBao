#!/usr/bin/env python3
"""Materialize one reviewed R9 tree in a new independent local checkout."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import plistlib
import signal
import stat
import subprocess
import time
import zlib

os.umask(0o077)
parser = argparse.ArgumentParser()
parser.add_argument('--host', choices=('mac', 'rog'), required=True)
for name in ('bundle', 'bundle-sha256', 'expanded-sha256', 'expected-tree'):
    parser.add_argument('--' + name, required=True)
for name in ('bundle-bytes', 'expanded-bytes'):
    parser.add_argument('--' + name, type=int, required=True)
args = parser.parse_args()
profiles = {
    'mac': {
        'system': ('Darwin', 'arm64'), 'uid': 501,
        'base': '/Volumes/T5/hepta-vnext-recovery-20261013',
        'old': 'continuation-20261104-native-ssh-http-r8/source',
        'root': 'continuation-20261104-native-http-r9',
        'bundle': 'continuation-20261104-native-http-r9.bundle.zlib',
        'commit': '2d9a2efd4cfc3a9ee60a450eee58866828a3f5ad',
    },
    'rog': {
        'system': ('Linux', 'x86_64'), 'uid': 1000,
        'base': '/home/qian-qi/heptabao-native-ssh-owner-20261104-r1',
        'old': 'source-r8-test-fixtures-r1',
        'root': 'r9-http-routing-r1',
        'bundle': 'normal-r9-source.bundle.zlib',
        'commit': '384c957612186d64c5a530044af0ae62c568cc3d',
    },
}
profile = profiles[args.host]
BASE = Path(profile['base'])
OLD = BASE / profile['old']
ROOT = BASE / profile['root']
SOURCE = ROOT / 'source'
CONTROL = ROOT / 'control'
BASE_TREE = 'd5a0f91a4d47f7c8d5f34170ea167d10dc036e04'
CANONICAL_COMMIT = '1d12abc45a83d4b32e7185d01a876eb93110b1e2'
CANONICAL_TREE = 'e1faeaa3ed49d26fb01a7617a8879cb693a12907'
children = []
protected = 0
pending_signal = None


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
                    'LANG': 'C', 'LC_ALL': 'C'})
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
        '-C', str(path), *command])


def freeze(path):
    return {'commit': git(path, 'rev-parse', 'HEAD').decode().strip(),
            'tree': git(path, 'rev-parse', 'HEAD^{tree}').decode().strip(),
            'status': git(path, 'status', '--porcelain=v1', '--untracked-files=all').decode()}


assert (os.uname().sysname, os.uname().machine) == profile['system']
assert os.getuid() == profile['uid'] == BASE.stat().st_uid
assert BASE.resolve(strict=True) == BASE and OLD.resolve(strict=True) == OLD
assert Path(args.bundle) == BASE / profile['bundle']
assert 0 < args.bundle_bytes <= 4 * 1024 * 1024 and 0 < args.expanded_bytes <= 16 * 1024 * 1024
compressed = stable_read(Path(args.bundle), 4 * 1024 * 1024, args.bundle_bytes, args.bundle_sha256)
assert stat.S_IMODE(Path(args.bundle).stat().st_mode) == 0o600
decoder = zlib.decompressobj()
expanded = decoder.decompress(compressed, args.expanded_bytes + 1)
assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
assert len(expanded) == args.expanded_bytes and digest(expanded) == args.expanded_sha256
bundle = json.loads(expanded)
assert set(bundle) == {'schema', 'base_tree', 'expected_tree', 'files', 'controls', 'expected_groups'}
assert bundle['schema'] == 'heptabao.r9-reviewed-independent-source-bundle.v1'
assert bundle['base_tree'] == BASE_TREE and bundle['expected_tree'] == args.expected_tree == CANONICAL_TREE
assert not ROOT.exists() and not ROOT.is_symlink()
ROOT.mkdir(mode=0o700)
CONTROL.mkdir(mode=0o700)
(CONTROL / 'empty-hooks').mkdir(mode=0o700)
(CONTROL / 'empty-template').mkdir(mode=0o700)
result = {'schema': 'heptabao.r9-independent-source-stage-result.v1', 'status': 'failed',
          'host': args.host, 'root': str(ROOT), 'source': str(SOURCE),
          'base_commit': profile['commit'], 'base_tree': BASE_TREE,
          'expected_tree': args.expected_tree, 'bundle_sha256': args.bundle_sha256,
          'expanded_sha256': args.expanded_sha256, 'stager_sha256': digest(Path(__file__).read_bytes()),
          'started_ns': time.time_ns(), 'server_started': False, 'compiler_started': False,
          'production_changed': False, 'source_qualification': False}
public(CONTROL / 'stage-intent.public.json', result)
try:
    if args.host == 'mac':
        info = plistlib.loads(owned('t5-volume-identity',
            ['/usr/sbin/diskutil', 'info', '-plist', '/Volumes/T5'], 30))
        assert info.get('VolumeUUID') == 'FB804D1B-24CB-4D6E-AEA7-A9E180807758'
        result['external_volume_uuid'] = info['VolumeUUID']
    before = freeze(OLD)
    assert before == {'commit': profile['commit'], 'tree': BASE_TREE, 'status': ''}
    result['old_source_before'] = before
    records = bundle['files']
    assert 1 <= len(records) <= 80 and len({x['path'] for x in records}) == len(records)
    for record in records:
        assert set(record) == {'path', 'before_mode', 'before_git_blob', 'after_mode',
                               'after_git_blob', 'after_sha256', 'after_bytes', 'content'}
        path = PurePosixPath(record['path'])
        assert not path.is_absolute() and '..' not in path.parts and str(path) == record['path']
        assert record['after_mode'] in ('100644', '100755')
        assert record['before_mode'] in (None, '100644', '100755')
        raw = record['content'].encode('utf-8')
        assert len(raw) == record['after_bytes'] and digest(raw) == record['after_sha256']
        assert blob(raw) == record['after_git_blob']
        old_path = OLD / record['path']
        if record['before_git_blob'] is None:
            assert record['before_mode'] is None and not old_path.exists() and not old_path.is_symlink()
        else:
            assert blob(stable_read(old_path, 2 * 1024 * 1024)) == record['before_git_blob']
    controls = bundle['controls']
    expected_controls = {'build_normal.py', 'mac_normal_exact_tests_r9.py',
                         'linux_normal_release_and_tests_r9.py',
                         'normal-test-groups.public.json', 'r8-normal-test-groups.public.json'}
    assert set(controls) == expected_controls
    for name, control in controls.items():
        assert set(control) == {'content', 'bytes', 'sha256'}
        raw = control['content'].encode('utf-8')
        assert len(raw) == control['bytes'] and digest(raw) == control['sha256']
        create(CONTROL / name, raw)
    original_groups = json.loads(controls['r8-normal-test-groups.public.json']['content'])
    assert controls['r8-normal-test-groups.public.json']['sha256'] == 'c725fd978f4d730b28cbf90335d8cc6e673003a5dc64b6fb965c7b1ae3485deb'
    groups = json.loads(controls['normal-test-groups.public.json']['content'])
    assert groups[:4] == original_groups and len(groups) <= 12
    assert [(x['label'], len(x['tests'])) for x in groups] == [tuple(x) for x in bundle['expected_groups']]
    names = [name for group in groups for name in group['tests']]
    assert len(names) == len(set(names)) and all(x['runtime_seconds'] == 600 for x in groups)
    owned('independent-local-clone', ['/usr/bin/git', '-c', 'gc.auto=0',
        '-c', 'maintenance.auto=false', 'clone', '--no-checkout', '--no-hardlinks', '--local',
        '--template=' + str(CONTROL / 'empty-template'), str(OLD), str(SOURCE)], 180)
    git(SOURCE, 'remote', 'set-url', 'origin', 'https://github.com/TrillionniumFoundation/HeptaBao.git')
    assert git(SOURCE, 'remote', 'get-url', 'origin').decode().strip() == 'https://github.com/TrillionniumFoundation/HeptaBao.git'
    git(SOURCE, 'checkout', '--detach', profile['commit'])
    assert freeze(SOURCE) == before
    assert Path(git(SOURCE, 'rev-parse', '--absolute-git-dir').decode().strip()) == SOURCE / '.git'
    common = Path(git(SOURCE, 'rev-parse', '--git-common-dir').decode().strip())
    common = common if common.is_absolute() else SOURCE / common
    assert common.resolve(strict=True) == SOURCE / '.git'
    assert not (SOURCE / '.git/objects/info/alternates').exists()
    assert all(not p.is_symlink() and p.stat().st_nlink == 1
               for p in (SOURCE / '.git/objects').rglob('*') if p.is_file())
    raw_entries = git(SOURCE, 'ls-files', '--stage', '-z').split(b'\0')
    index = {}
    for entry in raw_entries:
        if entry:
            metadata, name = entry.split(b'\t', 1)
            mode, object_id, stage = metadata.split()
            assert stage == b'0'
            index[name.decode()] = (mode.decode(), object_id.decode())
    for number, record in enumerate(records):
        path = SOURCE / record['path']
        assert path.parent.resolve(strict=True) == path.parent
        expected = None if record['before_git_blob'] is None else (record['before_mode'], record['before_git_blob'])
        assert index.get(record['path']) == expected
        if expected is not None:
            assert blob(stable_read(path, 2 * 1024 * 1024)) == expected[1]
        else:
            assert not path.exists() and not path.is_symlink()
        raw = record['content'].encode('utf-8')
        temporary = path.parent / ('.r9-reviewed-file-%02d' % number)
        create(temporary, raw, 0o755 if record['after_mode'] == '100755' else 0o644)
        os.replace(temporary, path)
        fsync_dir(path.parent)
        assert digest(stable_read(path, 2 * 1024 * 1024)) == record['after_sha256']
    git(SOURCE, 'add', '--', *(x['path'] for x in records))
    changed = git(SOURCE, 'diff', '--cached', '--name-only', '-z').decode().rstrip('\0').split('\0')
    assert set(changed) == {x['path'] for x in records}
    assert git(SOURCE, 'write-tree').decode().strip() == args.expected_tree
    git(SOURCE, '-c', 'user.name=Codex', '-c', 'user.email=codex@local.invalid',
        '-c', 'commit.gpgsign=false', 'commit', '-m',
        'Bind native HTTP redirect ownership and complete bounded response framing r9')
    materialized = freeze(SOURCE)
    assert materialized['tree'] == args.expected_tree and materialized['status'] == ''
    # Use the same actual commit on both ABIs. The original HA QA requires one
    # source commit, not merely equal trees. Fetch only the reviewed commit into
    # this new independent clone; the old source remains read-only.
    git(SOURCE, 'fetch', '--no-tags', '--no-recurse-submodules',
        '--no-write-fetch-head', 'origin', CANONICAL_COMMIT)
    assert git(SOURCE, 'cat-file', '-t', CANONICAL_COMMIT).decode().strip() == 'commit'
    assert git(SOURCE, 'rev-parse', CANONICAL_COMMIT + '^{tree}').decode().strip() == CANONICAL_TREE
    git(SOURCE, 'checkout', '--detach', CANONICAL_COMMIT)
    after = freeze(SOURCE)
    assert after == {'commit': CANONICAL_COMMIT, 'tree': CANONICAL_TREE, 'status': ''}
    result['local_materialization_commit'] = materialized['commit']
    result['canonical_source_commit'] = CANONICAL_COMMIT
    result['canonical_source_tree'] = CANONICAL_TREE
    result['canonical_fetch_in_new_clone_only'] = True
    assert freeze(OLD) == before
    result.update(status='prepared', source_commit=after['commit'], source_tree=after['tree'],
                  source_clean=True, old_source_after=before, old_source_unchanged=True,
                  independent_git_directory=True, shared_common_git_directory_dependency=False,
                  object_alternates_present=False, hardlinked_git_objects_present=False,
                  origin_url='https://github.com/TrillionniumFoundation/HeptaBao.git',
                  local_source_path_not_retained_as_origin=True,
                  changes=[{k: v for k, v in x.items() if k != 'content'} for x in records],
                  controls={k: {j: v for j, v in x.items() if j != 'content'} for k, x in controls.items()},
                  exact_groups=bundle['expected_groups'], exact_test_count=len(names))
except BaseException as error:
    result.update(error_type=type(error).__name__, error=str(error))
finally:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    cleanup = []
    for label, process in reversed(children):
        try:
            remaining = stop_owned(process)
            cleanup.append({'label': label, 'pid': process.pid, 'exit_code': process.returncode,
                            'direct_child_reaped': process.returncode is not None, 'remaining': remaining})
        except BaseException as error:
            cleanup.append({'label': label, 'pid': process.pid, 'cleanup_error': type(error).__name__})
    result['cleanup'] = cleanup
    if pending_signal is not None or any(x.get('cleanup_error') or x.get('remaining') or not x.get('direct_child_reaped') for x in cleanup):
        result['status'] = 'failed'
    result['terminal_ns'] = time.time_ns()
    public(CONTROL / 'stage-result.public.json', result)
    fsync_dir(ROOT)
    fsync_dir(BASE)
    print(json.dumps({'status': result['status'], 'receipt': str(CONTROL / 'stage-result.public.json'),
                      'receipt_sha256': digest((CONTROL / 'stage-result.public.json').read_bytes()),
                      'source_commit': result.get('source_commit'), 'source_tree': result.get('source_tree'),
                      'independent_git_directory': result.get('independent_git_directory', False),
                      'server_started': False, 'compiler_started': False}), flush=True)
raise SystemExit(0 if result['status'] == 'prepared' else 1)
