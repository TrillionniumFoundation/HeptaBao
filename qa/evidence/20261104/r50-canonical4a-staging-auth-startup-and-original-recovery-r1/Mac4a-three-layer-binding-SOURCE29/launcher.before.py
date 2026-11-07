#!/usr/bin/env python3
"""Admit the exact staged source and published controls into one fresh Mac target."""
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

OUTER_STARTED = time.monotonic()
ORIGINAL_OUTER_SECONDS = 8280
OUTER_UNTIL = OUTER_STARTED + ORIGINAL_OUTER_SECONDS
os.umask(0o077)
parser = argparse.ArgumentParser()
parser.add_argument('--host', choices=('mac',), required=True)
for name in ('commit', 'tree', 'stage-sha256', 'runner-sha256', 'groups-sha256', 'launcher-sha256', 'controls-sha256', 'controls-full9-json'):
    parser.add_argument('--' + name, required=True)
args = parser.parse_args()
assert args.commit == '5767739cd25e458ac052dc8d384019bab8688ae0'
assert args.tree == '42477d622dcf96e1e2b0929fe9ecc6b7ba484740'
STAGE_EXPECTED_FULL9 = None
for name in ('commit', 'tree'):
    assert re.fullmatch('[0-9a-f]{40}', getattr(args, name))
for name in ('stage_sha256', 'runner_sha256', 'groups_sha256', 'launcher_sha256', 'controls_sha256'):
    assert re.fullmatch('[0-9a-f]{64}', getattr(args, name))

if args.host == 'mac':
    BASE = Path('/Volumes/T5/hepta-vnext-recovery-20261013')
    STAGE_ROOT = BASE / 'hb-5767739c-src-20261106-r1'
    ROOT = STAGE_ROOT / 'normal-build-r1'
    R9 = BASE / 'continuation-20261104-native-http-r9'
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
    TARGET = ROOT / 'target-normal-r1'
    TOOLCHAIN = '/Users/qianqi/.rustup/toolchains/1.98.0-aarch64-apple-darwin/bin'
    CARGO_HOME = str(BASE / 'r13-full-native-cargo-home-r1')
    PYTHON = '/opt/homebrew/bin/python3'
    RUNNER_NAME = 'mac_normal_same_root_publication_build.py'
    expected_system, expected_uid = ('Darwin', 'arm64'), 501
else:
    BASE = Path('/home/qian-qi/heptabao-native-ssh-owner-20261104-r1')
    ROOT = BASE / 'r10-native-state-helper-r1'
    R9 = BASE / 'r9-http-routing-r1'
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
    RUNNER_NAME = 'linux_normal_release_and_tests_r10.py'
    expected_system, expected_uid = ('Linux', 'x86_64'), 1000

SOURCE = STAGE_ROOT / 'source'
STAGE_REPORT = STAGE_ROOT / 'control/stage-result.public.json'
CONTROLS_RECEIPT = ROOT / 'control/inert-stage.result.public.json'
CONTROL = ROOT / 'control'
ADMISSION = ROOT / 'build-control-r1'
OUTPUT = ROOT / 'normal-release-tests-r1'
OLD_TREE = 'd5a0f91a4d47f7c8d5f34170ea167d10dc036e04'
R9_SOURCE = R9 / 'source'
R9_COMMIT = '1d12abc45a83d4b32e7185d01a876eb93110b1e2'
R9_TREE = 'e1faeaa3ed49d26fb01a7617a8879cb693a12907'
R9_MAC_STAGE_FENCES = {
    'stage-result.public.json': '1f60d0bbdab00feee4e0d5d1593fa3543b74ff05fae8ec60f9d17b3ddd381166',
    '021-git-fetch.public.json': '89e4865c8bb30bc500b05cd1fd0a79d0d39bb49fbe1830250d155f9797ff19a5',
    '021-git-fetch.stderr': 'dbcc4dce38066a3223043b215a80a7acdd2dd1e2f52063de42801d63d931e5ff',
    '021-git-fetch.stdout': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
}


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


def preserve_r9():
    r9_before = freeze(R9_SOURCE)
    assert r9_before == {'commit': R9_COMMIT, 'tree': R9_TREE, 'status': ''}
    evidence = {'source_before': r9_before, 'prior_failures_replayed': False}
    if args.host == 'rog':
        output = R9 / 'normal-release-tests-r1'
        build_raw, evidence['normal_release'] = read_bound(
            output / 'normal-release-result.public.json',
            '103bbb68367a13ec3df53a8b437f6e33bd44c75a4ad23a6a792692ef858deb3d', 30000)
        native_raw, evidence['native_build'] = read_bound(
            output / 'native-build.public.json',
            '771f53ae44858d9bb73809b997103edfd69bc564e152d9ee40f3a45ca7f854d5', 5000)
        tests_raw, evidence['failed_exact44'] = read_bound(
            output / 'result.public.json',
            'b4d3f25c0694dfa7cc24dd3d2a8bdf780ec9eb43716abb61a4581b26c8cc676f', 40000)
        build, native, tests = map(json.loads, (build_raw, native_raw, tests_raw))
        assert all(x['source_commit'] == R9_COMMIT and x['source_tree'] == R9_TREE
                   for x in (build, native, tests))
        assert build['build_exit_code'] == 0 and build['build_finished_success']
        assert build['source_freeze_verified'] and not build['timed_out'] and not build['owned_group_survivors_after_wait']
        assert tests['status'] == 'failed' and tests['test_count'] == 44
        assert [(x['label'], x['tests']['exit_code']) for x in tests['group_results']] == [
            ('ssh25', 0), ('mount1', 0), ('redirect5', 0), ('actor2', 0), ('ordinary5', 0), ('no_forward6', 101)]
        assert all(not x['tests']['timed_out'] for x in tests['group_results'])
        assert all(x['direct_child_reaped'] and x['remaining'] == [] and not x.get('cleanup_error_type')
                   for x in tests['cleanup'])
        assert sorted(build['artifacts']) == ['heptabao-seed', 'heptabao-server']
        evidence['retained_artifacts'] = []
        for value in build['artifacts'].values():
            path = Path(value['path'])
            assert path == output / 'artifacts' / path.name and not path.is_relative_to(TARGET)
            assert sorted(value['features']) == ['default', 'native-v6-ha', 'native-v6-storage']
            _, pin = read_bound(path, value['sha256'], value['bytes'], retain=False)
            assert pin['bytes'] == value['bytes']
            evidence['retained_artifacts'].append(pin)
        libtest = output / 'retained-heptabao-server-libtest'
        libtest_sha = '9b871dd8d12c063e6ea042d5bb4415d9a042da0e4d18d83fca3e184396879cf4'
        libtest_bytes = 188176568
        assert tests['binary']['path'] == str(libtest)
        assert tests['binary']['sha256'] == libtest_sha and tests['binary']['bytes'] == libtest_bytes
        _, pin = read_bound(libtest, libtest_sha, libtest_bytes, retain=False)
        assert pin['bytes'] == libtest_bytes and stat.S_IMODE(libtest.stat().st_mode) == 0o500
        assert not libtest.is_relative_to(TARGET)
        evidence['retained_artifacts'].append(pin)
    else:
        evidence['failed_stage_fences'] = {}
        for name, sha256 in R9_MAC_STAGE_FENCES.items():
            _, pin = read_bound(R9 / 'control' / name, sha256, 2 * 1024 * 1024)
            evidence['failed_stage_fences'][name] = pin
        resume_path = R9 / 'control/canonical-resume-r2/result.public.json'
        resume_raw, evidence['canonical_resume'] = read_bound(resume_path, args.r9_resume_sha256, 150000)
        terminal_raw, evidence['canonical_resume_terminal'] = read_bound(
            BASE / 'continuation-20261104-native-http-r10/control/r9-canonical-resume-r2.terminal.public.json', args.r9_resume_terminal_sha256, 150000)
        authority_raw, evidence['canonical_resume_authority'] = read_bound(
            BASE / 'continuation-20261104-native-http-r10/control/r9-canonical-resume-r2.authority.public.json', args.r9_resume_authority_sha256, 20000)
        resume, terminal, authority = map(json.loads, (resume_raw, terminal_raw, authority_raw))
        assert resume['schema'] == 'heptabao.r9.offline-canonical-controller.v2'
        assert resume['status'] == 'prepared' and resume['action'] == 'resume-mac'
        assert resume['canonical_commit'] == R9_COMMIT and resume['canonical_tree'] == R9_TREE
        assert resume['source_after']['head'] == R9_COMMIT and resume['source_after']['tree'] == R9_TREE and resume['source_after']['clean']
        assert resume['canonical_proof']['commit_count'] == 3751 and resume['canonical_proof']['full_fsck_passed']
        assert resume['all_owned_stopped'] and resume['deadline_before_receipt_passed']
        assert terminal['status'] == terminal['receipt_candidate_status'] == 'prepared'
        assert terminal['action'] == 'resume-mac' and terminal['receipt'] == str(resume_path)
        assert terminal['canonical_commit'] == R9_COMMIT and terminal['canonical_tree'] == R9_TREE
        assert terminal['publication_within_original_deadline'] and terminal['all_owned_stopped']
        assert authority['state'] == 'succeeded' and authority['exit_code'] == 0
        assert authority['output_complete'] and authority['output_durable'] and authority['terminal_publication_confirmed']
        assert not authority['timed_out'] and not authority['cancelled']
        assert all(value is False for value in authority['log_truncated'].values())
        assert all(value is None for value in authority['log_errors'].values())
        evidence['r9_build_artifacts_required'] = False
        evidence['no_r9_artifact_claim'] = True
    assert freeze(R9_SOURCE) == r9_before
    evidence['source_after'] = r9_before
    return evidence


def preserve_r10():
    root = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-native-http-r10')
    source = root / 'source'
    output = root / 'normal-release-tests-r1'
    before = freeze(source)
    assert before == {'commit': '49503322c7f446e5eb41e7744f1fdbd7f1192ecc',
                      'tree': '1d4211f91e1b34a2ed087a3bbef2e2884bac88e9', 'status': ''}
    evidence = {'source_before': before, 'prior_failures_replayed': False}
    build_raw, evidence['normal_release'] = read_bound(output / 'normal-release-result.public.json',
        'f5746eaf7fd79c8001ac927c9738922297d6e5e575cbd12bc092aafa2c13f544', 30000)
    native_raw, evidence['native_build'] = read_bound(output / 'native-build.public.json',
        '16fa488ed8d7a9a46541b5aea5007e27b538e5c37f9246c14de0e5fe24b05ad1', 5000)
    tests_raw, evidence['exact44'] = read_bound(output / 'result.public.json',
        '28f47931ad644e610d45af00545b343a8d5867546ea8d00a44cae0a3de13c961', 40000)
    build, native, tests = map(json.loads, (build_raw, native_raw, tests_raw))
    assert all(x['source_commit'] == before['commit'] and x['source_tree'] == before['tree']
               for x in (build, native, tests))
    assert build['source_freeze_verified'] and build['build_exit_code'] == 0 and build['build_finished_success']
    assert not build['timed_out'] and not build['owned_group_survivors_after_wait']
    assert tests['status'] == 'passed' and tests['test_count'] == 44
    assert tests['binary']['sha256'] == 'b36998def7d3642f78a00dffbd3390f10d2b8f9ed1fcdeb8739ea4a6a7230549'
    assert tests['binary']['bytes'] == 155908848
    assert len(tests['cleanup']) == 14
    assert all(x['direct_child_reaped'] and x['remaining'] == [] and not x.get('cleanup_error_type') for x in tests['cleanup'])
    retained = []
    for name in ('heptabao-server', 'heptabao-seed'):
        item = build['artifacts'][name]
        path = output / 'artifacts' / name
        assert item['path'] == str(path) and not path.is_relative_to(TARGET)
        _, fact = read_bound(path, item['sha256'], item['bytes'], retain=False)
        assert fact['bytes'] == item['bytes']
        assert sorted(item['features']) == ['default', 'native-v6-ha', 'native-v6-storage']
        retained.append(fact)
    _, fact = read_bound(output / 'retained-heptabao-server-libtest',
        tests['binary']['sha256'], tests['binary']['bytes'], retain=False)
    assert fact['bytes'] == tests['binary']['bytes']
    retained.append(fact)
    assert freeze(source) == before
    evidence.update(source_after=before, retained=retained, all_unchanged=True)
    return evidence



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
            if str(TARGET).encode() in target_values or any(str(TARGET).encode() in x for x in argv) or cwd in (str(SOURCE), str(OLD_SOURCE), str(R9_SOURCE)):
                matches.append({'pid': int(directory.name), 'comm': comm, 'cwd': cwd})
        except (FileNotFoundError, ProcessLookupError):
            continue
    return matches


assert (os.uname().sysname, os.uname().machine) == expected_system
assert os.getuid() == expected_uid == ROOT.stat().st_uid
assert ROOT.resolve(strict=True) == ROOT and STAGE_ROOT.resolve(strict=True) == STAGE_ROOT
assert not os.path.lexists(TARGET), 'fresh target must not already exist'
assert Path(__file__).resolve(strict=True) == CONTROL / 'launch_normal_same_root_publication.py'
assert not ADMISSION.exists() and not ADMISSION.is_symlink()
assert not OUTPUT.exists() and not OUTPUT.is_symlink()
stage_raw, stage_pin = read_bound(STAGE_REPORT, args.stage_sha256, 65536)
assert STAGE_EXPECTED_FULL9 is not None and [str(x) for x in stage_pin['identity']] == STAGE_EXPECTED_FULL9
stage = json.loads(stage_raw)
assert stage['schema'] == 'heptabao.final-mac-source-only-stage.v1'
assert stage['status'] == 'prepared' and stage['source_commit'] == args.commit and stage['source_tree'] == args.tree
assert stage['source_clean'] and stage['independent_git_directory'] and stage['old_source_unchanged']
assert stage['source'] == str(SOURCE) and stage['root'] == str(STAGE_ROOT)
assert stage['stage_purpose'] == 'SOURCE_ONLY_NO_BUILD_CONTROLS' and stage['controls_published'] is False
assert stage['full_strict_fsck_passed'] and stage['within_new_stage_deadline']
assert stage['full_worktree']['tracked_leaf_count'] == 3932
assert stage['full_worktree']['tracked_bytes'] == 62553540
assert stage['full_worktree']['full_leaf_index_sha256'] == '20ff64f463eb63a45a6dda92a17f23e814503b77ca5325d1b2c4a0ee4f4a5423'
assert all(x['direct_child_reaped'] and not x['remaining'] and not x.get('cleanup_error_type') for x in stage['cleanup'])
controls_raw, controls_pin = read_bound(CONTROLS_RECEIPT, args.controls_sha256, 20000)
assert [str(x) for x in controls_pin['identity']] == json.loads(args.controls_full9_json)
assert stat.S_IMODE(controls_pin['identity'][4]) == 0o600
controls = json.loads(controls_raw)
assert controls['schema'] == 'heptabao.mac-normal61-native-jwt-pki28-controls-inert.v1'
assert controls['status'] == 'prepared' and controls['root_created'] and controls['control_created']
assert controls['compiler_started'] is False and controls['service_started'] is False and controls['source_executed'] is False
assert controls['source_stage']['path'] == str(STAGE_REPORT)
assert controls['source_stage']['sha256'] == args.stage_sha256
assert controls['source_stage']['identity'] == stage_pin['identity']
assert controls['source_commit'] == args.commit and controls['source_tree'] == args.tree
file_rows = {row['path']: row for row in controls['files']}
assert len(file_rows) == len(controls['files']) == 3
assert set(file_rows) == {str(CONTROL / name) for name in (RUNNER_NAME, 'launch_normal_same_root_publication.py', 'normal-test-groups.public.json')}
_, launcher_pin = read_bound(Path(__file__), args.launcher_sha256, 40000)
runner = CONTROL / RUNNER_NAME
_, runner_pin = read_bound(runner, args.runner_sha256, 49152)
groups_raw, groups_pin = read_bound(CONTROL / 'normal-test-groups.public.json', args.groups_sha256, 20000)
group_plan = json.loads(groups_raw)
assert set(group_plan) == {'schema', 'normal61_groups', 'native_jwt_pki_groups'}
assert group_plan['schema'] == 'heptabao.mac.normal61-native-jwt-pki28-groups.v1'
groups = group_plan['normal61_groups']
native_groups = group_plan['native_jwt_pki_groups']
for name, pin in ((RUNNER_NAME, runner_pin), ('launch_normal_same_root_publication.py', launcher_pin), ('normal-test-groups.public.json', groups_pin)):
    row = file_rows[str(CONTROL / name)]
    assert row['publication'] == 'created' and row['mode'] == '0600'
    assert row['bytes'] == pin['bytes'] and row['sha256'] == pin['sha256'] and row['identity'] == pin['identity']
    assert stat.S_IMODE(pin['identity'][4]) == 0o600
assert [[g['label'], len(g['tests'])] for g in groups] == controls['exact_groups']
assert sum(len(g['tests']) for g in groups) == controls['exact_test_count'] == 44
assert controls['normal_total_test_count'] == 61
assert all(g['runtime_seconds'] == 600 for g in groups)
assert [[g['label'], g['libtest_profile'], len(g['tests'])] for g in native_groups] == controls['native_groups'] == [
    ['native-jwt-pki-file28', 'file', 28], ['native-jwt-pki-default28', 'default', 28]]
assert all(g['runtime_seconds'] == 600 for g in native_groups)
assert native_groups[0]['tests'] == native_groups[1]['tests']
assert controls['native_unique_test_count'] == 28 and controls['native_profile_execution_count'] == 56
assert controls['selected_unique_test_count'] == 89 and controls['selected_profile_execution_count'] == 117
ADMISSION.mkdir(mode=0o700)
result = {'schema': 'heptabao.same-root-publication-normal-target-admission.v1', 'status': 'failed',
          'host': args.host, 'source_commit': args.commit, 'source_tree': args.tree,
          'stage': stage_pin, 'controls_receipt': controls_pin, 'runner': runner_pin, 'groups': groups_pin,
          'launcher': launcher_pin, 'target_scope': 'fresh-create-only-owned',
          'target': str(TARGET), 'production_changed': False, 'normal_runner_started': False,
          'started_ns': time.time_ns()}
public(ADMISSION / 'launch-intent.public.json', result)
lock_fd = None
try:
    before = freeze(SOURCE)
    assert before == {'commit': args.commit, 'tree': args.tree, 'status': ''}
    result.update(source_before=before, historical_runtime_qualification_inherited=False)
    assert not os.path.lexists(TARGET)
    TARGET.mkdir(mode=0o700)
    (TARGET / 'release').mkdir(mode=0o700)
    assert TARGET.resolve(strict=True) == TARGET and stat.S_ISDIR(TARGET.lstat().st_mode)
    assert TARGET.stat().st_uid == os.getuid() and stat.S_IMODE(TARGET.stat().st_mode) == 0o700
    result['fresh_target_created'] = True
    result['compiler_holders_before_lock'] = holders()
    assert not result['compiler_holders_before_lock']
    lock_fd = os.open(TARGET / 'release/.cargo-lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
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
    assert freeze(SOURCE) == before
    assert read_bound(STAGE_REPORT, args.stage_sha256, 65536)[1] == stage_pin
    assert read_bound(CONTROLS_RECEIPT, args.controls_sha256, 20000)[1] == controls_pin
    argv = [PYTHON, '-I', '-S', '-B', str(runner), '--source', str(SOURCE),
            '--output', str(OUTPUT), '--commit', args.commit, '--tree', args.tree,
            '--toolchain', TOOLCHAIN, '--cargo-home', CARGO_HOME, '--target', str(TARGET),
            '--groups', str(CONTROL / 'normal-test-groups.public.json'),
            '--groups-sha256', args.groups_sha256,
            '--outer-started-monotonic', repr(OUTER_STARTED), '--launcher-pid', str(os.getpid())]
    assert time.monotonic() < OUTER_UNTIL, 'original outer deadline expired before exec admission'
    result.update(status='admitted', source_unchanged=True,
                  prior_build_replayed=False, controls_receipt_unchanged=True,
                  normal_runner_argv=argv, original_release_build_cap_seconds=1800,
                  original_libtest_build_cap_seconds=1800 if args.host == 'mac' else 3600,
                  each_listing_cap_seconds=30, each_runtime_group_cap_seconds=600,
                  exact_test_count=controls['exact_test_count'],
                  additional_existing_ingress_tests=7, additional_cold_h2_tests=9,
                  additional_same_root_publication_tests=1, original_60_test_count=60,
                  original_61_test_count=61, native_jwt_pki_unique_tests=28,
                  native_jwt_pki_profile_executions=56, selected_unique_test_total=89,
                  selected_profile_execution_total=117, additional_file_libtest_cap_seconds=1800,
                  default_profile_reuses_same_run_normal_libtest=True,
                  each_additional_group_total_cap_seconds=600,
                  original_supervisor_seconds=ORIGINAL_OUTER_SECONDS,
                  outer_started_monotonic=OUTER_STARTED, outer_until_monotonic=OUTER_UNTIL)
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
                  'source_tree': args.tree, 'exact_test_count': controls['exact_test_count'],
                  'fresh_target': str(TARGET), 'historical_runtime_qualification_inherited': False,
                  'original_budgets_preserved': True}), flush=True)
assert time.monotonic() < OUTER_UNTIL, 'original outer deadline expired before same-PID exec'
os.execv(argv[0], argv)
