#!/usr/bin/env python3
"""Check frozen source, retained R8 evidence, and the idle target; exec R9 once."""
from pathlib import Path
import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import time

os.umask(0o077)
parser = argparse.ArgumentParser()
parser.add_argument('--host', choices=('mac', 'rog'), required=True)
for name in ('commit', 'tree', 'stage-sha256', 'runner-sha256', 'groups-sha256'):
    parser.add_argument('--' + name, required=True)
args = parser.parse_args()
for name in ('commit', 'tree'):
    assert re.fullmatch('[0-9a-f]{40}', getattr(args, name))
for name in ('stage_sha256', 'runner_sha256', 'groups_sha256'):
    assert re.fullmatch('[0-9a-f]{64}', getattr(args, name))

if args.host == 'mac':
    BASE = Path('/Volumes/T5/hepta-vnext-recovery-20261013')
    ROOT = BASE / 'continuation-20261104-native-http-r9'
    OLD = BASE / 'continuation-20261104-native-ssh-http-r8'
    OLD_SOURCE = OLD / 'source'
    OLD_COMMIT = '2d9a2efd4cfc3a9ee60a450eee58866828a3f5ad'
    OLD_BUILD = OLD / 'build-normal-r1/result.public.json'
    OLD_BUILD_SHA = '31e5bb7905b11a4bad1bf9df34360cc0443f70455a047ac06914208d2bfe3a54'
    OLD_NATIVE = OLD / 'build-normal-r1/native-build.public.json'
    OLD_NATIVE_SHA = 'c372ef673bd3dd70daaf2791f4d0ba18893fb7235137c2ad0ce452b6b3fad5bd'
    OLD_TEST = OLD / 'normal-exact33-r1/result.public.json'
    OLD_TEST_SHA = 'fc6677c0f65ba0e2050f0fe20d25356cba33a20ab2c287de5e0e0c7d4dd56557'
    OLD_LIBTEST = OLD / 'mac-tls-einval-diagnostic-r1/retained-r8-libtest'
    OLD_LIBTEST_SHA = '648236a59ebf23aee2ebd02039e6045fb491cebff80ac8d4e564b78b3e316aab'
    OLD_LIBTEST_BYTES = 154048544
    OLD_STATUS = 'failed'
    TARGET = BASE / 'continuation-20261029-joint2dbb-full6-r1/runtime.noindex/target-native-full-r2'
    TOOLCHAIN = '/Users/qianqi/.rustup/toolchains/1.98.0-aarch64-apple-darwin/bin'
    CARGO_HOME = str(BASE / 'r13-full-native-cargo-home-r1')
    PYTHON = '/opt/homebrew/bin/python3'
    RUNNER_NAME = 'mac_normal_exact_tests_r9.py'
    expected_system, expected_uid = ('Darwin', 'arm64'), 501
else:
    BASE = Path('/home/qian-qi/heptabao-native-ssh-owner-20261104-r1')
    ROOT = BASE / 'r9-http-routing-r1'
    OLD = BASE / 'normal-release-tests-r8-r1'
    OLD_SOURCE = BASE / 'source-r8-test-fixtures-r1'
    OLD_COMMIT = '384c957612186d64c5a530044af0ae62c568cc3d'
    OLD_BUILD = OLD / 'normal-release-result.public.json'
    OLD_BUILD_SHA = '2dad4d882854850cbe05825785e77532656da255a11ce7a551969bd7439456a5'
    OLD_NATIVE = OLD / 'native-build.public.json'
    OLD_NATIVE_SHA = 'f96740372ada668a566aa1b90b2cd8daf463c009de8eed5ba86cb20a2883b8f9'
    OLD_TEST = OLD / 'result.public.json'
    OLD_TEST_SHA = '8fa3a928de5c705e6da80d9dd6fc64c5252035226013650c37941105e4069715'
    OLD_LIBTEST = OLD / 'retained-heptabao-server-libtest'
    OLD_LIBTEST_SHA = '9f498c4c2c14f2198dcbe746be81be1cf0c7caabca28671bba83fb003a65b46a'
    OLD_LIBTEST_BYTES = 188077176
    OLD_STATUS = 'passed'
    TARGET = Path('/home/qian-qi/heptabao-native-20261029-c1bd-r1/runtime/target')
    TOOLCHAIN = '/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin'
    CARGO_HOME = '/home/qian-qi/heptabao-native-20261029-c1bd-r1/cargo-home'
    PYTHON = '/usr/bin/python3'
    RUNNER_NAME = 'linux_normal_release_and_tests_r9.py'
    expected_system, expected_uid = ('Linux', 'x86_64'), 1000

SOURCE = ROOT / 'source'
CONTROL = ROOT / 'control'
ADMISSION = ROOT / 'build-control-r1'
OUTPUT = ROOT / 'normal-release-tests-r1'
OLD_TREE = 'd5a0f91a4d47f7c8d5f34170ea167d10dc036e04'


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_bound(path, expected_sha, cap, retain=True):
    assert path.resolve(strict=True) == path
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
        assert 0 <= before.st_size <= cap
        digest, parts, count = hashlib.sha256(), [], 0
        while True:
            part = os.read(fd, 1024 * 1024)
            if not part:
                break
            count += len(part)
            assert count <= cap
            digest.update(part)
            if retain:
                parts.append(part)
        assert count == before.st_size and digest.hexdigest() == expected_sha
        assert identity(before) == identity(os.fstat(fd)) == identity(path.lstat())
        return b''.join(parts), {'path': str(path), 'bytes': count, 'sha256': expected_sha,
                               'identity': list(identity(before))}
    finally:
        os.close(fd)


def freeze(path):
    def git(*command):
        return subprocess.check_output(['/usr/bin/git', '-C', str(path), *command],
                                       text=True, timeout=30).strip()
    return {'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
            'status': git('status', '--porcelain=v1', '--untracked-files=all')}


def public(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(value, out, indent=2, sort_keys=True)
        out.write('\n')
        out.flush()
        os.fsync(out.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def holders():
    if args.host == 'mac':
        observed = subprocess.run(['/usr/sbin/lsof', '-t', str(TARGET / 'release/.cargo-lock')],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        assert observed.returncode in (0, 1)
        return [int(value) for value in observed.stdout.split()]
    matches = []
    for directory in Path('/proc').iterdir():
        if not directory.name.isdigit():
            continue
        try:
            if directory.stat().st_uid != os.getuid():
                continue
            comm = (directory / 'comm').read_text().strip()
            if comm not in ('cargo', 'rustc', 'rustdoc'):
                continue
            env = (directory / 'environ').read_bytes().split(b'\0')
            target_values = [x.split(b'=', 1)[1] for x in env if x.startswith(b'CARGO_TARGET_DIR=')]
            argv = (directory / 'cmdline').read_bytes().split(b'\0')
            cwd = str((directory / 'cwd').resolve(strict=True))
            if str(TARGET).encode() in target_values or any(str(TARGET).encode() in x for x in argv) or cwd in (str(SOURCE), str(OLD_SOURCE)):
                matches.append({'pid': int(directory.name), 'comm': comm, 'cwd': cwd})
        except (FileNotFoundError, ProcessLookupError):
            continue
    return matches


assert (os.uname().sysname, os.uname().machine) == expected_system
assert os.getuid() == expected_uid == ROOT.stat().st_uid
assert ROOT.resolve(strict=True) == ROOT and TARGET.resolve(strict=True) == TARGET
assert not ADMISSION.exists() and not ADMISSION.is_symlink()
assert not OUTPUT.exists() and not OUTPUT.is_symlink()
stage_raw, stage_pin = read_bound(CONTROL / 'stage-result.public.json', args.stage_sha256, 150000)
stage = json.loads(stage_raw)
assert stage['status'] == 'prepared' and stage['source_commit'] == args.commit and stage['source_tree'] == args.tree
assert stage['source_clean'] and stage['independent_git_directory'] and stage['old_source_unchanged']
assert all(x['direct_child_reaped'] and not x['remaining'] for x in stage['cleanup'])
runner = CONTROL / RUNNER_NAME
_, runner_pin = read_bound(runner, args.runner_sha256, 40000)
groups_raw, groups_pin = read_bound(CONTROL / 'normal-test-groups.public.json', args.groups_sha256, 20000)
groups = json.loads(groups_raw)
assert stage['controls'][RUNNER_NAME]['sha256'] == args.runner_sha256
assert stage['controls']['normal-test-groups.public.json']['sha256'] == args.groups_sha256
assert [[g['label'], len(g['tests'])] for g in groups] == stage['exact_groups']
assert sum(len(g['tests']) for g in groups) == stage['exact_test_count']
assert all(g['runtime_seconds'] == 600 for g in groups)
ADMISSION.mkdir(mode=0o700)
result = {'schema': 'heptabao.r9-normal-target-admission.v1', 'status': 'failed',
          'host': args.host, 'source_commit': args.commit, 'source_tree': args.tree,
          'stage': stage_pin, 'runner': runner_pin, 'groups': groups_pin,
          'target': str(TARGET), 'production_changed': False, 'normal_runner_started': False,
          'started_ns': time.time_ns()}
public(ADMISSION / 'launch-intent.public.json', result)
lock_fd = None
try:
    before, old_before = freeze(SOURCE), freeze(OLD_SOURCE)
    assert before == {'commit': args.commit, 'tree': args.tree, 'status': ''}
    assert old_before == {'commit': OLD_COMMIT, 'tree': OLD_TREE, 'status': ''}
    result.update(source_before=before, old_source_before=old_before)
    result['compiler_holders_before_lock'] = holders()
    assert not result['compiler_holders_before_lock']
    lock_fd = os.open(TARGET / 'release/.cargo-lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    info = os.fstat(lock_fd)
    assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    result['compiler_holders_under_lock'] = holders()
    if args.host == 'mac':
        # lsof also observes this controller's own temporary lock descriptor.
        assert all(pid == os.getpid() for pid in result['compiler_holders_under_lock'])
    else:
        assert not result['compiler_holders_under_lock']
    result['target_lock'] = {'identity': list(identity(info)), 'nonblocking_exclusive_probe': True}
    build_raw, result['old_build_receipt'] = read_bound(OLD_BUILD, OLD_BUILD_SHA, 30000)
    native_raw, result['old_native_receipt'] = read_bound(OLD_NATIVE, OLD_NATIVE_SHA, 5000)
    test_raw, result['old_exact_test_receipt'] = read_bound(OLD_TEST, OLD_TEST_SHA, 40000)
    build, native, old_test = map(json.loads, (build_raw, native_raw, test_raw))
    assert build['source_commit'] == native['source_commit'] == old_test['source_commit'] == OLD_COMMIT
    assert build['source_tree'] == native['source_tree'] == old_test['source_tree'] == OLD_TREE
    assert build['source_freeze_verified'] and build['build_exit_code'] == 0 and build['build_finished_success'] and not build['timed_out'] and not build['owned_group_survivors_after_wait']
    assert old_test['status'] == OLD_STATUS and old_test['test_count'] == 33
    assert old_test['binary']['sha256'] == OLD_LIBTEST_SHA and old_test['binary']['bytes'] == OLD_LIBTEST_BYTES
    assert sorted(build['artifacts']) == ['heptabao-seed', 'heptabao-server']
    retained = []
    for value in build['artifacts'].values():
        _, artifact_pin = read_bound(Path(value['path']), value['sha256'], value['bytes'], retain=False)
        assert artifact_pin['bytes'] == value['bytes']
        assert sorted(value['features']) == ['default', 'native-v6-ha', 'native-v6-storage']
        assert not Path(value['path']).is_relative_to(TARGET)
        retained.append(artifact_pin)
    _, libtest_pin = read_bound(OLD_LIBTEST, OLD_LIBTEST_SHA, OLD_LIBTEST_BYTES, retain=False)
    assert libtest_pin['bytes'] == OLD_LIBTEST_BYTES and not OLD_LIBTEST.is_relative_to(TARGET)
    retained.append(libtest_pin)
    assert freeze(SOURCE) == before and freeze(OLD_SOURCE) == old_before
    argv = [PYTHON, '-I', '-S', '-B', str(runner), '--source', str(SOURCE),
            '--output', str(OUTPUT), '--commit', args.commit, '--tree', args.tree,
            '--toolchain', TOOLCHAIN, '--cargo-home', CARGO_HOME, '--target', str(TARGET),
            '--groups', str(CONTROL / 'normal-test-groups.public.json'),
            '--groups-sha256', args.groups_sha256]
    result.update(status='admitted', retained_r8_artifacts=retained,
                  prior_r8_failure_replayed=False, source_and_retained_artifacts_unchanged=True,
                  normal_runner_argv=argv, original_release_build_cap_seconds=1800,
                  original_libtest_build_cap_seconds=1800 if args.host == 'mac' else 3600,
                  each_listing_cap_seconds=30, each_runtime_group_cap_seconds=600,
                  exact_test_count=stage['exact_test_count'])
except BaseException as error:
    result.update(error_type=type(error).__name__, error=str(error))
finally:
    result['terminal_ns'] = time.time_ns()
    public(ADMISSION / 'launch-preflight.public.json', result)
    if lock_fd is not None:
        os.close(lock_fd)
if result['status'] != 'admitted':
    print(json.dumps({'status': 'refused', 'receipt': str(ADMISSION / 'launch-preflight.public.json'),
                      'error_type': result.get('error_type')}), flush=True)
    raise SystemExit(1)
print(json.dumps({'status': 'preflight-admitted', 'source_commit': args.commit,
                  'source_tree': args.tree, 'exact_test_count': stage['exact_test_count'],
                  'retained_r8_artifacts_verified': True, 'original_budgets_preserved': True}), flush=True)
os.execv(argv[0], argv)
