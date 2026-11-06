#!/usr/bin/env python3
"""Build the separately admitted native JWT and PKI source and run 149 unique names in 166 profile instances."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import signal
import stat
import shutil
import subprocess
import time

BINDING_READY = True
assert BINDING_READY, 'formatter, final source and control publication require separate admission'
os.umask(0o077)
parser = argparse.ArgumentParser()
for name in ('source', 'output', 'commit', 'tree', 'toolchain', 'cargo-home', 'target', 'groups', 'groups-sha256'):
    parser.add_argument('--' + name, required=True)
parser.add_argument('--outer-started-monotonic', required=True, type=float)
parser.add_argument('--launcher-pid', required=True, type=int)
args = parser.parse_args()
ORIGINAL_OUTER_SECONDS = 12000
assert args.launcher_pid == os.getpid(), 'same-PID launcher exec required'
assert 0 < args.outer_started_monotonic <= time.monotonic()
OUTER_UNTIL = args.outer_started_monotonic + ORIGINAL_OUTER_SECONDS
assert time.monotonic() < OUTER_UNTIL, 'original outer deadline expired before runner'
source, output = Path(args.source), Path(args.output)
DIAGNOSTIC_COMMIT = '025b05a340de841b8161c1120344e86eae30eb97'
DIAGNOSTIC_TREE = '1d8160c9385f8053b9a683cc1834da0f912e2d37'
children = []
protected = 0
pending_signal = None

class Cancelled(BaseException):
    pass

def signal_received(signum, _frame):
    global pending_signal
    pending_signal = signum
    if not protected:
        raise Cancelled()

for sig in (signal.SIGTERM, signal.SIGINT):
    signal.signal(sig, signal_received)

def sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

PRIOR_DF026_FILES = {
    "/home/qian-qi/heptabao-cold-h2-normal-20261105-r1/normal-release-tests-r3/normal-release-result.public.json": [
        3137,
        "6691ddb0f927a068bd3b7b4da1f190399bf58558ab1efb754fa57b4233597f1d",
        384
    ],
    "/home/qian-qi/heptabao-cold-h2-normal-20261105-r1/normal-release-tests-r3/native-build.public.json": [
        772,
        "ebef4cd1143ea4d6cc197916072de4978520a0f67d1a175adc7bb2faae7fd69e",
        384
    ],
    "/home/qian-qi/heptabao-cold-h2-normal-20261105-r1/normal-release-tests-r3/result.public.json": [
        48188,
        "84d763e6ff948df27964f373e834f869d7b22eeb0d7efb929fbd5c299c528f1b",
        384
    ],
    "/home/qian-qi/heptabao-cold-h2-normal-20261105-r1/normal-release-tests-r3/artifacts/heptabao-seed": [
        102260520,
        "846a00f5f6fb6ee12f91c151d202ac3059aff1878a254b89bb093313911ec21f",
        320
    ],
    "/home/qian-qi/heptabao-cold-h2-normal-20261105-r1/normal-release-tests-r3/artifacts/heptabao-server": [
        110339520,
        "7540cfb7e691fe5bea2515df3c35d8f31cdc42f05d5c9f2199c8464182de40b2",
        320
    ],
    "/home/qian-qi/heptabao-cold-h2-normal-20261105-r1/normal-release-tests-r3/retained-heptabao-server-libtest": [
        189730456,
        "640fdb602cf264c29eb816a85c2a0e2763d66438b97e1c8e75564ad0a01d91e2",
        320
    ],
    "/home/qian-qi/heptabao-same-root-publication-normal-20261105-r2/normal-release-tests-r1/artifacts/heptabao-seed": [102145376,"0edc8d3c1fb3b78a4b018f684bfc07269d273c72925582a849b68df6c003b6a6",320],
    "/home/qian-qi/heptabao-same-root-publication-normal-20261105-r2/normal-release-tests-r1/artifacts/heptabao-server": [110219600,"cb840a0f275f5c56c5b60e774d613020160853495f821975df7a1451522e15f0",320],
    "/home/qian-qi/heptabao-same-root-publication-normal-20261105-r2/normal-release-tests-r1/retained-heptabao-server-libtest": [187839640,"7ea0be2f071a9bfe562c5a1d6a2cedf225cfdae23363a039be80fb7a42198725",320],
    "/home/qian-qi/heptabao-same-root-publication-normal-20261105-r2/normal-release-tests-r1/native-build.public.json": [786,"3bfc21f48ce6dd831c8bde094b2f24f53ed0266e57e5fd55839b0a5977f5db5a",384],
    "/home/qian-qi/heptabao-same-root-publication-normal-20261105-r2/normal-release-tests-r1/normal-release-result.public.json": [3192,"78d5eeb0235f62896ec57ca4d0243e31c56e861a4dde438ccd23eac3edafdd22",384],
    "/home/qian-qi/heptabao-same-root-publication-normal-20261105-r2/normal-release-tests-r1/result.public.json": [57532,"7830845172732432895c246d77c47266432a03c0788e15689ea74d15dff14475",384]
}


def preserve_prior_df026(evidence):
    global protected
    evidence.update(status='failed', files=[], all_opened_descriptors_closed=False,
                    purpose='Immutable retained qualification files outside the reusable Cargo target')
    try:
        for name, (size, expected_sha, expected_mode) in PRIOR_DF026_FILES.items():
            bounded_remaining(OUTER_UNTIL)
            path = Path(name)
            assert path.resolve(strict=True) == path and not path.is_relative_to(Path(args.target))
            row = {'path': name, 'opened': False, 'close_attempted': False, 'closed': False}
            evidence['files'].append(row)
            fd = None
            protected += 1
            try:
                try:
                    if pending_signal is not None:
                        raise Cancelled()
                    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    row['opened'] = True
                    if pending_signal is not None:
                        raise Cancelled()
                    before = os.fstat(fd)
                    fields = lambda info: (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                                           info.st_mode, info.st_nlink, info.st_size,
                                           info.st_mtime_ns, info.st_ctime_ns)
                    assert stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                    assert before.st_nlink == 1 and before.st_size == size
                    assert stat.S_IMODE(before.st_mode) == expected_mode
                    assert fields(before) == fields(path.lstat())
                    count, digest = 0, hashlib.sha256()
                    while True:
                        if pending_signal is not None:
                            raise Cancelled()
                        bounded_remaining(OUTER_UNTIL)
                        part = os.read(fd, min(1024 * 1024, size + 1 - count))
                        if not part:
                            break
                        count += len(part)
                        assert count <= size
                        digest.update(part)
                    assert count == size and digest.hexdigest() == expected_sha
                    assert fields(before) == fields(os.fstat(fd)) == fields(path.lstat())
                    assert path.resolve(strict=True) == path
                    row.update(bytes=count, sha256=expected_sha, identity=list(fields(before)))
                    bounded_remaining(OUTER_UNTIL)
                    if pending_signal is not None:
                        raise Cancelled()
                finally:
                    if fd is not None:
                        row['close_attempted'] = True
                        try:
                            os.close(fd)
                            row['closed'] = True
                        except BaseException as error:
                            row['close_error_type'] = type(error).__name__
                            raise
            finally:
                protected -= 1
        bounded_remaining(OUTER_UNTIL)
        if pending_signal is not None:
            raise Cancelled()
        evidence['status'] = 'unchanged'
    finally:
        evidence['all_opened_descriptors_closed'] = all(
            not row['opened'] or row['closed'] for row in evidence['files'])


def write(name, value):
    path = output / name
    with path.open('x') as f:
        json.dump(value, f, sort_keys=True, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(output, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def git(*command):
    return subprocess.check_output(['/usr/bin/git', '-C', str(source), *command],
                                   text=True, timeout=30).strip()

def freeze():
    return {'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
            'status': git('status', '--porcelain')}

def group_members(pgid):
    raw = subprocess.check_output(['/bin/ps', '-axo', 'pid=,ppid=,pgid=,stat='], text=True, timeout=10)
    result = []
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) >= 4 and int(fields[2]) == pgid:
            result.append({'pid': int(fields[0]), 'ppid': int(fields[1]), 'pgid': int(fields[2]), 'state': fields[3]})
    return result

def terminate_owned(process):
    # Each direct Popen is registered while Python signal delivery is deferred.
    # The still-held child cannot be PID-reused before its original wait.
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
    # Report a remaining group as a failed cleanup; do not signal a reaped,
    # potentially recycled group solely because a numeric PGID still exists.
    return group_members(process.pid)

profile = {
    'PATH': args.toolchain + ':/usr/bin:/bin',
    'CARGO_HOME': args.cargo_home, 'CARGO_TARGET_DIR': args.target,
    'CARGO_BUILD_JOBS': '1', 'CARGO_PROFILE_RELEASE_OPT_LEVEL': '3',
    'CARGO_PROFILE_RELEASE_CODEGEN_UNITS': '16', 'CARGO_PROFILE_RELEASE_LTO': 'false',
    'CARGO_PROFILE_RELEASE_DEBUG': '0', 'CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS': 'true',
    'CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS': 'true', 'CARGO_PROFILE_RELEASE_PANIC': 'unwind',
    'RUSTFLAGS': '', 'CARGO_TERM_COLOR': 'never',
}
environment = dict(os.environ)
environment.update(profile)
environment.pop('CARGO_ENCODED_RUSTFLAGS', None)

def bounded_remaining(until):
    value = until - time.monotonic()
    assert value > 0, 'bounded extra-group child deadline'
    return value


def owned(label, command, limit, *, deadline=None):
    global protected
    started = time.monotonic()
    absolute_until = None if deadline is None else min(started + limit, deadline, OUTER_UNTIL)
    if absolute_until is not None:
        bounded_remaining(absolute_until)
    timed_out = False
    with (output / (label + '.stdout')).open('xb') as out, (output / (label + '.stderr')).open('xb') as err:
        process = None
        protected += 1
        try:
            if absolute_until is not None:
                bounded_remaining(absolute_until)
            process = subprocess.Popen(command, cwd=source, env=environment,
                                       stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                       start_new_session=True)
            children.append((label, process))
        finally:
            protected -= 1
        if pending_signal is not None:
            raise Cancelled()
        try:
            code = process.wait(timeout=limit if absolute_until is None else bounded_remaining(absolute_until))
        except subprocess.TimeoutExpired:
            timed_out = True
            terminate_owned(process)
            code = process.returncode
        finally:
            if process.poll() is None:
                terminate_owned(process)
            out.flush()
            err.flush()
            os.fsync(out.fileno())
            os.fsync(err.fileno())
    remaining = group_members(process.pid)
    if absolute_until is not None and time.monotonic() >= absolute_until:
        timed_out = True
    record = {'label': label, 'argv': command, 'exit_code': code, 'timed_out': timed_out,
              'elapsed_seconds': time.monotonic() - started, 'outer_cap_seconds': limit,
              'owned_pgid': process.pid, 'direct_child_reaped': process.returncode is not None,
              'remaining': remaining, 'stdout_sha256': sha(output / (label + '.stdout')),
              'stderr_sha256': sha(output / (label + '.stderr'))}
    write(label + '.public.json', record)
    assert not remaining, 'owned child group did not finish'
    return record

assert os.uname().sysname == 'Linux' and os.uname().machine == 'x86_64'
# Physical commit is pinned by the reviewed launcher and the clean-tree freeze below.
assert isinstance(DIAGNOSTIC_COMMIT, str) and isinstance(DIAGNOSTIC_TREE, str), 'diagnostic source identity unresolved'
assert args.commit == DIAGNOSTIC_COMMIT and args.tree == DIAGNOSTIC_TREE
assert args.groups_sha256 == '35153ff5e90b582f83e4fbbb66ff5c9fb295e95153f08df152cefedecdb50869'
assert sha(args.groups) == args.groups_sha256
groups = json.loads(Path(args.groups).read_text())
EXPECTED_GROUP_SHAPES = [('native-jwt-pki-file17', 'file', 17), ('native-jwt-pki-default17', 'default', 17),
                         ('legacy-jwt-default63', 'default', 63), ('native-auth-identity-default69', 'default', 69)]
assert [(g['label'], g['libtest_profile'], len(g['tests'])) for g in groups] == EXPECTED_GROUP_SHAPES
all_names = []
for group in groups:
    assert set(group) == {'label', 'libtest_profile', 'tests', 'runtime_seconds'}
    assert group['runtime_seconds'] == 600 and group['libtest_profile'] in ('file', 'default')
    assert group['tests'] and len(group['tests']) == len(set(group['tests']))
    assert all(isinstance(n, str) and n for n in group['tests'])
    assert group['label'].replace('-', '').replace('_', '').isalnum()
    all_names.extend(group['tests'])
assert groups[0]['tests'] == groups[1]['tests'], 'same seventeen source names in both feature profiles'
assert len(all_names) == 166 and len(set(all_names)) == 149
assert len(set(groups[1]['tests'] + groups[2]['tests'] + groups[3]['tests'])) == 149
assert not output.exists() and not output.is_symlink()
before = freeze()
assert before == {'commit': args.commit, 'tree': args.tree, 'status': ''}
output.mkdir(mode=0o700)
intent = {'schema': 'heptabao.native-jwt-pki-build-regression.v1', 'source_commit': args.commit,
          'source_tree': args.tree, 'normal_default_features': True, 'fixture_features': [],
          'profile': profile, 'groups': groups, 'test_count': 149,
          'groups_sha256': args.groups_sha256, 'controller_sha256': sha(__file__),
          'production_changed': False, 'started_ns': time.time_ns(),
          'selected_unique_test_total': 149, 'selected_profile_instance_total': 166,
          'new_unique_test_total': 17, 'existing_unique_test_total': 132,
          'actual_fixture_backend_for_new_tests': 'FileV6',
          'distributed_native_jwt_ha_qualified': False,
          'old_normal61_full34_LAN98plus12_comparison69_rerun': False,
          'original_outer_seconds': ORIGINAL_OUTER_SECONDS,
          'launcher_started_monotonic': args.outer_started_monotonic,
          'same_pid_launcher': args.launcher_pid,
          'outer_phase_caps_seconds': {'normal_release_build': 1800,
                                       'all_compile_checks_shared': 3600,
                                       'each_listing': 30, 'each_runtime_family_shared': 600}}
write('intent.public.json', intent)
result = {**intent, 'status': 'failed', 'runtime_tests_started': False, 'group_results': []}
try:
    result['retained_df026_before'] = {}
    preserve_prior_df026(result['retained_df026_before'])
    assert result['retained_df026_before']['status'] == 'unchanged'
    assert result['retained_df026_before']['all_opened_descriptors_closed']
    rustc = subprocess.check_output([str(Path(args.toolchain) / 'rustc'), '-vV'], text=True, timeout=30)
    assert 'release: 1.98.0' in rustc and 'host: x86_64-unknown-linux-gnu' in rustc
    result['rustc_vv'] = rustc
    release = owned('normal-release-build', [str(Path(args.toolchain) / 'cargo'), 'build',
                    '--release', '--locked', '--offline', '-p', 'heptabao-server',
                    '--bin', 'heptabao-server', '--bin', 'heptabao-seed',
                    '--message-format=json-render-diagnostics'], 1800, deadline=OUTER_UNTIL)
    result['normal_release_build'] = release
    assert release['exit_code'] == 0 and not release['timed_out'], 'normal production binary compilation failed'
    release_events = []
    for line in (output / 'normal-release-build.stdout').read_text().splitlines():
        try:
            release_events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    assert any(e.get('reason') == 'build-finished' and e.get('success') is True for e in release_events)
    artifact_dir = output / 'artifacts'
    artifact_dir.mkdir(mode=0o700)
    release_artifacts = {}
    for name in ('heptabao-server', 'heptabao-seed'):
        matches = [e for e in release_events if e.get('reason') == 'compiler-artifact'
                   and e.get('target', {}).get('name') == name and e.get('executable')]
        assert len(matches) == 1
        event = matches[0]
        assert sorted(event['features']) == ['default', 'native-v6-ha', 'native-v6-storage']
        assert event['profile'] == {'opt_level': '3', 'debuginfo': 0, 'debug_assertions': True,
                                   'overflow_checks': True, 'test': False}
        original = Path(event['executable'])
        assert original.is_file() and not original.is_symlink()
        assert original.resolve().is_relative_to(Path(args.target).resolve())
        digest = sha(original)
        retained = artifact_dir / name
        with original.open('rb') as src, retained.open('xb') as dst:
            shutil.copyfileobj(src, dst, 1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())
        retained.chmod(0o500)
        assert sha(retained) == digest and sha(original) == digest
        release_artifacts[name] = {'path': str(retained), 'sha256': digest,
                'bytes': retained.stat().st_size, 'compiler_executable': str(original),
                'features': event['features'], 'profile': event['profile'], 'fresh': event.get('fresh')}
    fd = os.open(artifact_dir, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    assert freeze() == before
    release_result = {'schema': 'heptabao.native-default-build-result.v1',
            'normal_default_candidate': True, 'formal_qualification': False,
            'source_commit': args.commit, 'source_tree': args.tree, 'source_freeze_verified': True,
            'native_abi': 'x86_64-unknown-linux-gnu', 'build_exit_code': 0,
            'build_finished_success': True, 'timed_out': False,
            'owned_group_survivors_after_wait': bool(release['remaining']),
            'elapsed_seconds': release['elapsed_seconds'], 'command': release['argv'],
            'rustc_vv': rustc, 'build_driver_path': __file__, 'build_driver_sha256': sha(__file__),
            'cargo_events_sha256': release['stdout_sha256'], 'cargo_stderr_sha256': release['stderr_sha256'],
            'requested_release_profile': {k:v for k,v in profile.items() if k.startswith('CARGO_PROFILE_RELEASE_')},
            'artifacts': release_artifacts}
    write('normal-release-result.public.json', release_result)
    native_receipt = {'schema': 'heptabao.native-build.v1', 'source_commit': args.commit,
            'source_tree': args.tree, 'source_freeze_verified': True,
            'native_abi': 'x86_64-unknown-linux-gnu', 'build_exit_code': 0,
            'binary_sha256': release_artifacts['heptabao-server']['sha256'],
            'features': release_artifacts['heptabao-server']['features'],
            'provenance': {'result_path': str(output / 'normal-release-result.public.json'),
                'result_sha256': sha(output / 'normal-release-result.public.json'),
                'cargo_events_sha256': release['stdout_sha256']}}
    write('native-build.public.json', native_receipt)
    result['release_artifacts'] = release_artifacts
    result['native_build_receipt_sha256'] = sha(output / 'native-build.public.json')
    print(json.dumps({'phase': 'normal-production-release-built', 'source_commit': args.commit,
          'source_tree': args.tree, 'artifacts': release_artifacts,
          'native_build_receipt_sha256': result['native_build_receipt_sha256']}), flush=True)
    # One original 3600-second compilation budget includes all three checks.
    compile_started = time.monotonic()
    compile_until = min(compile_started + 3600.0, OUTER_UNTIL)
    result['compile_shared'] = {'started_monotonic': compile_started, 'until_monotonic': compile_until,
                                'cap_seconds': 3600, 'deadline_reset': False, 'commands': []}
    ordinary = owned('ordinary-no-default-check', [str(Path(args.toolchain) / 'cargo'), 'check',
                     '--release', '--locked', '--offline', '-p', 'heptabao-server',
                     '--lib', '--no-default-features', '--message-format=json-render-diagnostics'],
                     bounded_remaining(compile_until), deadline=compile_until)
    result['compile_shared']['commands'].append(ordinary)
    assert ordinary['exit_code'] == 0 and not ordinary['timed_out'], 'ordinary feature compilation failed'
    ordinary_events = []
    for line in (output / 'ordinary-no-default-check.stdout').read_text().splitlines():
        try:
            ordinary_events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    assert any(e.get('reason') == 'build-finished' and e.get('success') is True for e in ordinary_events)
    ordinary_artifacts = [e for e in ordinary_events if e.get('reason') == 'compiler-artifact'
                          and e.get('target', {}).get('name') == 'heptabao_server']
    assert len(ordinary_artifacts) == 1 and ordinary_artifacts[0]['features'] == []
    assert not ordinary_artifacts[0]['profile']['test']
    assert freeze() == before
    binaries = {}
    for profile_name, feature_arguments, expected_features in (
            ('file', ['--no-default-features', '--features', 'native-v6-storage'], ['native-v6-storage']),
            ('default', [], ['default', 'native-v6-ha', 'native-v6-storage'])):
        label = profile_name + '-libtest-build'
        build = owned(label, [str(Path(args.toolchain) / 'cargo'), 'test', '--release', '--locked',
                      '--offline', '-p', 'heptabao-server', '--lib', '--no-run',
                      *feature_arguments, '--message-format=json-render-diagnostics'],
                      bounded_remaining(compile_until), deadline=compile_until)
        result['compile_shared']['commands'].append(build)
        assert build['exit_code'] == 0 and not build['timed_out'], 'reviewed libtest profile compilation failed'
        events, artifacts = [], []
        for line in (output / (label + '.stdout')).read_text().splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            events.append(event)
            if (event.get('reason') == 'compiler-artifact' and event.get('profile', {}).get('test')
                    and event.get('target', {}).get('name') == 'heptabao_server' and event.get('executable')):
                artifacts.append(event)
        assert any(e.get('reason') == 'build-finished' and e.get('success') is True for e in events)
        assert len(artifacts) == 1
        artifact = artifacts[0]
        assert sorted(artifact['features']) == expected_features
        assert artifact['profile'] == {'opt_level': '3', 'debuginfo': 0, 'debug_assertions': True,
                                       'overflow_checks': True, 'test': True}
        built = Path(artifact['executable'])
        assert built.is_file() and not built.is_symlink()
        assert built.resolve().is_relative_to(Path(args.target).resolve())
        binary_sha = sha(built)
        binary = output / ('retained-heptabao-server-libtest-' + profile_name)
        with built.open('rb') as original, binary.open('xb') as retained:
            shutil.copyfileobj(original, retained, 1024 * 1024)
            retained.flush()
            os.fsync(retained.fileno())
        binary.chmod(0o500)
        assert sha(binary) == binary_sha and sha(built) == binary_sha
        binaries[profile_name] = {'path': str(binary), 'sha256': binary_sha, 'bytes': binary.stat().st_size,
                                 'features': artifact['features'], 'profile': artifact['profile'],
                                 'compiler_executable': str(built), 'build': build}
        bounded_remaining(compile_until)
        assert freeze() == before
    result['binaries'] = binaries
    result['compile_shared']['elapsed_seconds'] = time.monotonic() - compile_started
    bounded_remaining(compile_until)
    for group in groups:
        family_started = time.monotonic()
        family_until = min(family_started + group['runtime_seconds'], OUTER_UNTIL)
        selected_binary = binaries[group['libtest_profile']]
        binary, binary_sha = Path(selected_binary['path']), selected_binary['sha256']
        assert sha(binary) == binary_sha and freeze() == before
        family = {'label': group['label'], 'libtest_profile': group['libtest_profile'],
                  'status': 'failed', 'test_count': len(group['tests']), 'actual_test_names': [],
                  'cap_seconds': 600, 'clamped_to_original_outer_deadline': True, 'tests': []}
        result['group_results'].append(family)
        for index, name in enumerate(group['tests']):
            label = group['label'] + '-' + str(index + 1)
            listing = owned(label + '-list', [str(binary), name, '--exact', '--list'],
                            min(30.0, bounded_remaining(family_until)), deadline=family_until)
            assert listing['exit_code'] == 0 and not listing['timed_out']
            selected = [line[:-6] for line in (output / (label + '-list.stdout')).read_text().splitlines()
                        if line.endswith(': test')]
            assert selected == [name], 'exact reviewed testcase missing from selected feature profile'
            bounded_remaining(family_until)
            result['runtime_tests_started'] = True
            tests = owned(label, [str(binary), name, '--exact', '--nocapture', '--test-threads=1'],
                          bounded_remaining(family_until), deadline=family_until)
            family['actual_test_names'].append(name)
            family['tests'].append({'name': name, 'listing': listing, 'tests': tests})
            assert tests['exit_code'] == 0 and not tests['timed_out']
            summary = (output / (label + '.stdout')).read_text()
            assert 'test result: ok. 1 passed; 0 failed; 0 ignored;' in summary, 'actual testcase not executed'
            bounded_remaining(family_until)
        assert sha(binary) == binary_sha and freeze() == before
        family['elapsed_seconds'] = time.monotonic() - family_started
        bounded_remaining(family_until)
        family['status'] = 'passed'
    result['binaries_unchanged'] = all(sha(v['path']) == v['sha256'] for v in binaries.values())
    result['release_artifacts_unchanged'] = all(sha(v['path']) == v['sha256'] for v in release_artifacts.values())
    result['source_unchanged'] = freeze() == before
    actual_names = [name for family in result['group_results'] for name in family['actual_test_names']]
    assert len(actual_names) == 166 and len(set(actual_names)) == 149
    assert result['binaries_unchanged'] and result['release_artifacts_unchanged'] and result['source_unchanged']
    assert len(result['group_results']) == 4 and all(g['status'] == 'passed' for g in result['group_results'])
    result['actual_unique_test_total'] = 149
    result['actual_profile_instance_total'] = 166
    result['status'] = 'passed'
except BaseException as error:
    result['failure_type'] = type(error).__name__
    result['failure'] = str(error)
finally:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    cleanup = []
    for label, process in reversed(children):
        try:
            remaining = terminate_owned(process)
            cleanup.append({'label': label, 'pid': process.pid, 'exit_code': process.returncode,
                            'direct_child_reaped': process.returncode is not None, 'remaining': remaining})
        except BaseException as error:
            result['status'] = 'failed'
            cleanup.append({'label': label, 'pid': process.pid, 'exit_code': process.returncode,
                            'direct_child_reaped': process.returncode is not None,
                            'remaining': None, 'cleanup_error_type': type(error).__name__})
    result['cleanup'] = cleanup
    if pending_signal is not None or any(x.get('cleanup_error_type') or x['remaining'] or not x['direct_child_reaped'] for x in cleanup):
        result['status'] = 'failed'
    if result.get('retained_df026_before', {}).get('status') == 'unchanged':
        result['retained_df026_after'] = {}
        try:
            preserve_prior_df026(result['retained_df026_after'])
            assert result['retained_df026_after'] == result['retained_df026_before']
        except BaseException as error:
            result['status'] = 'failed'
            result['retained_df026_fence_error_type'] = type(error).__name__
    else:
        result['status'] = 'failed'
    result['terminal_ns'] = time.time_ns()
    result['within_original_outer_before_receipt'] = time.monotonic() < OUTER_UNTIL
    if not result['within_original_outer_before_receipt']:
        result['status'] = 'failed'
    write('result.public.json', result)
    print(json.dumps({'status': result['status'], 'source_commit': args.commit, 'source_tree': args.tree,
                      'result_path': str(output / 'result.public.json'),
                      'result_sha256': sha(output / 'result.public.json'),
                      'publication_within_original_outer': time.monotonic() < OUTER_UNTIL,
                      'all_owned_stopped': all(not x.get('cleanup_error_type') and not x['remaining'] and x['direct_child_reaped'] for x in cleanup)}), flush=True)
raise SystemExit(0 if result['status'] == 'passed' and time.monotonic() < OUTER_UNTIL else 1)
