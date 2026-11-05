#!/usr/bin/env python3
"""Build exact same-root publication source; retain 44/7/9 and add one real A-B-A regression."""
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
DIAGNOSTIC_COMMIT = '4e808d0ecb1bcded22870a7ec960dfb2491cf6ec'
DIAGNOSTIC_TREE = 'eba5e650bd080b8ad41ea52a2bc68867f541d255'
INGRESS_OBSERVER_TESTS = (
    "service::native_v6_ha_install::tests::ingress_selection_tests::fresh_ingress_permission_is_affine_and_resumed_binding_never_arms",
    "service::native_v6_ha_install::tests::ingress_selection_tests::fresh_ingress_permission_rejects_actual_new_request_nonce_or_selected_root",
    "service::native_v6_ha_install::tests::ingress_selection_tests::fresh_ingress_actual_failed_repair_closes_reselection_before_any_result",
    "ha::native_v6_runtime::request_timing_tests::native_request_timing_failure_has_only_bounded_static_metadata",
    "ha::native_v6_runtime::request_timing_tests::native_request_timing_sixty_four_buckets_preserve_existing_aggregates",
    "ha::native_v6_runtime::request_timing_tests::native_request_timing_observes_deadlines_but_preserves_once_only_results",
    "ha::native_v6_runtime::request_timing_tests::native_request_timing_phase_advance_is_distinct_from_operation_success",
)
COLD_H2_TESTS = (
    "service::native_v6_ha_install::read::cold_timing_tests::cold_native_ha_timing_preserves_once_and_owned_result_identity",
    "service::native_v6_ha_install::read::cold_timing_tests::cold_native_ha_timing_preserves_nested_source_and_inner_results",
    "service::native_v6_ha_install::tests::native_ha_install_batches_actual_readindex_cold_missing_and_corrupt_file",
    "http::h2_transport::sync_worker_tests::h2_sync_worker_is_unentered_and_retains_outer_context",
    "http::h2_transport::sync_worker_tests::h2_sync_worker_expired_deadline_never_calls_work",
    "http::h2_transport::sync_worker_tests::h2_sync_worker_preserves_inner_result",
    "http::h2_transport::sync_worker_tests::h2_sync_worker_joins_panicked_work_and_drops_capture",
    "http::h2_transport::sync_worker_tests::h2_sync_worker_does_not_authorize_nested_runtime_context",
    "http::h2_transport::sync_worker_tests::h2_sync_worker_cancelled_waiter_retains_blocking_capacity",
)
SAME_ROOT_PUBLICATION_TESTS = (
    "service::native_v6_ha_install::tests::same_root_republication_tests::native_ha_same_root_republication_advances_warm_and_cold_cursors",
)
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
    ]
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
assert args.groups_sha256 == '0566f7f98ea16a4c1df43ebaf992172646ad91623c18f68fcc59f7c08b53d1f1'
assert sha(args.groups) == args.groups_sha256
groups = json.loads(Path(args.groups).read_text())
EXPECTED_GROUP_SHAPES = [('ssh25', 25), ('mount1', 1), ('redirect5', 5), ('actor2', 2), ('ordinary5', 5), ('no_forward6', 6)]
assert isinstance(groups, list) and groups and len(groups) == len(EXPECTED_GROUP_SHAPES)
assert [(g['label'], len(g['tests'])) for g in groups] == EXPECTED_GROUP_SHAPES
all_names = []
for group in groups:
    assert set(group) == {'label', 'filter', 'exact', 'tests', 'runtime_seconds'}
    assert group['runtime_seconds'] == 600 and isinstance(group['exact'], bool)
    assert group['tests'] and len(group['tests']) == len(set(group['tests']))
    assert all(isinstance(n, str) and n for n in group['tests'])
    assert group['label'].replace('-', '').replace('_', '').isalnum()
    all_names.extend(group['tests'])
assert len(all_names) == len(set(all_names)) == sum(n for _, n in EXPECTED_GROUP_SHAPES), 'reviewed disjoint names required'
assert len(INGRESS_OBSERVER_TESTS) == len(set(INGRESS_OBSERVER_TESTS)) == 7
assert len(COLD_H2_TESTS) == len(set(COLD_H2_TESTS)) == 9
assert len(set(all_names) | set(INGRESS_OBSERVER_TESTS) | set(COLD_H2_TESTS)) == 60
assert len(SAME_ROOT_PUBLICATION_TESTS) == len(set(SAME_ROOT_PUBLICATION_TESTS)) == 1
assert len(set(all_names) | set(INGRESS_OBSERVER_TESTS) | set(COLD_H2_TESTS) | set(SAME_ROOT_PUBLICATION_TESTS)) == 61
assert not output.exists() and not output.is_symlink()
before = freeze()
assert before == {'commit': args.commit, 'tree': args.tree, 'status': ''}
output.mkdir(mode=0o700)
intent = {'schema': 'heptabao.linux-normal-same-root-publication-exact-tests.v1', 'source_commit': args.commit,
          'source_tree': args.tree, 'normal_default_features': True, 'fixture_features': [],
          'profile': profile, 'groups': groups, 'test_count': len(all_names),
          'groups_sha256': args.groups_sha256, 'controller_sha256': sha(__file__),
          'production_changed': False, 'started_ns': time.time_ns(),
          'selected_test_total': 61, 'original_60_test_total': 60,
          'additional_test_counts': {'ingress_observer': 7, 'cold_h2': 9, 'same_root_publication': 1},
          'original_outer_seconds': ORIGINAL_OUTER_SECONDS,
          'launcher_started_monotonic': args.outer_started_monotonic,
          'same_pid_launcher': args.launcher_pid,
          'additional_group_caps_seconds': {'ingress_observer': 600, 'cold_h2': 600, 'same_root_publication': 600},
          'outer_phase_caps_seconds': {'normal_release_build': 1800, 'normal_libtest_build': 3600,
                                       'each_listing': 30, 'each_runtime_group': 600}}
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
                    '--message-format=json-render-diagnostics'], 1800)
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
    build = owned('build', [str(Path(args.toolchain) / 'cargo'), 'test', '--release', '--locked',
                  '--offline', '-p', 'heptabao-server', '--lib', '--no-run',
                  '--message-format=json-render-diagnostics'], 3600)
    result['build'] = build
    assert build['exit_code'] == 0 and not build['timed_out'], 'normal libtest compilation failed'
    artifacts = []
    for line in (output / 'build.stdout').read_text().splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (event.get('reason') == 'compiler-artifact' and event.get('profile', {}).get('test')
                and event.get('target', {}).get('name') == 'heptabao_server' and event.get('executable')):
            artifacts.append(event)
    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert sorted(artifact['features']) == ['default', 'native-v6-ha', 'native-v6-storage']
    assert artifact['profile'] == {'opt_level': '3', 'debuginfo': 0, 'debug_assertions': True,
                                   'overflow_checks': True, 'test': True}
    built = Path(artifact['executable'])
    assert built.is_file() and not built.is_symlink()
    binary_sha = sha(built)
    binary = output / 'retained-heptabao-server-libtest'
    with built.open('rb') as original, binary.open('xb') as retained:
        shutil.copyfileobj(original, retained, 1024 * 1024)
        retained.flush()
        os.fsync(retained.fileno())
    binary.chmod(0o500)
    assert sha(binary) == binary_sha and sha(built) == binary_sha
    result['build_artifact_path'] = str(built)
    result['binary'] = {'path': str(binary), 'sha256': binary_sha, 'bytes': binary.stat().st_size,
                        'features': artifact['features'], 'profile': artifact['profile']}
    assert freeze() == before
    for group in groups:
        options = ['--exact'] if group['exact'] else []
        listing = owned(group['label'] + '-list', [str(binary), group['filter'], *options, '--list'], 30)
        assert listing['exit_code'] == 0 and not listing['timed_out']
        selected = [line[:-6] for line in (output / (group['label'] + '-list.stdout')).read_text().splitlines() if line.endswith(': test')]
        assert len(selected) == len(group['tests']) and set(selected) == set(group['tests'])
        assert sha(binary) == binary_sha and freeze() == before
        result['runtime_tests_started'] = True
        tests = owned(group['label'], [str(binary), group['filter'], *options,
                      '--nocapture', '--test-threads=1'], group['runtime_seconds'])
        result['group_results'].append({'label': group['label'], 'actual_test_names': selected, 'tests': tests})
    result['binary_unchanged'] = sha(binary) == binary_sha
    result['release_artifacts_unchanged'] = all(sha(v['path']) == v['sha256'] for v in release_artifacts.values())
    result['source_unchanged'] = freeze() == before
    result['status'] = 'passed' if (result['binary_unchanged'] and result['release_artifacts_unchanged'] and result['source_unchanged']
            and all(x['tests']['exit_code'] == 0 and not x['tests']['timed_out'] for x in result['group_results'])) else 'failed'
    if result['status'] == 'passed':
        # Preserve the original 44 denominator and its completed result. The new
        # bounded group executes only after those original checks succeeded.
        result['original_44_status'] = 'passed'
        result['status'] = 'failed'
        extra_started = time.monotonic()
        extra_until = min(extra_started + 600.0, OUTER_UNTIL)
        extra = {'schema': 'heptabao.normal-ingress-observer-regression.v1',
                 'status': 'failed', 'test_count': len(INGRESS_OBSERVER_TESTS),
                 'original_44_denominator_unchanged': True,
                 'new_total_group_cap_seconds': 600,
                 'clamped_to_original_outer_deadline': True,
                 'actual_test_names': [], 'tests': []}
        result['ingress_observer_regression'] = extra
        def extra_remaining():
            value = extra_until - time.monotonic()
            assert value > 0, 'ingress observer group deadline'
            return value
        for index, name in enumerate(INGRESS_OBSERVER_TESTS):
            label = 'ingress-observer-' + str(index + 1)
            listing = owned(label + '-list', [str(binary), name, '--exact', '--list'],
                            min(30.0, extra_remaining()), deadline=extra_until)
            assert listing['exit_code'] == 0 and not listing['timed_out']
            selected = [line[:-6] for line in (output / (label + '-list.stdout')).read_text().splitlines()
                        if line.endswith(': test')]
            assert selected == [name], 'exact original ingress/timing testcase missing'
            extra_remaining()
            tests = owned(label, [str(binary), name, '--exact', '--nocapture', '--test-threads=1'],
                          extra_remaining(), deadline=extra_until)
            extra['actual_test_names'].append(name)
            extra['tests'].append({'name': name, 'tests': tests})
            assert tests['exit_code'] == 0 and not tests['timed_out']
            summary = (output / (label + '.stdout')).read_text()
            assert 'test result: ok. 1 passed; 0 failed; 0 ignored;' in summary, 'actual testcase not executed'
            extra_remaining()
        result['binary_unchanged'] = sha(binary) == binary_sha
        result['release_artifacts_unchanged'] = all(sha(v['path']) == v['sha256'] for v in release_artifacts.values())
        result['source_unchanged'] = freeze() == before
        assert result['binary_unchanged'] and result['release_artifacts_unchanged'] and result['source_unchanged']
        extra_completed = time.monotonic()
        assert extra_completed < extra_until, 'ingress observer group deadline'
        extra['elapsed_seconds'] = extra_completed - extra_started
        extra['status'] = 'passed'
        result['status'] = 'passed'
    if result['status'] == 'passed':
        # This separate nine-test group never changes either prior denominator.
        result['original_44_and_ingress_7_status'] = 'passed'
        result['status'] = 'failed'
        increment_started = time.monotonic()
        increment_until = min(increment_started + 600.0, OUTER_UNTIL)
        increment = {'schema': 'heptabao.normal-cold-h2-regression.v1',
                     'status': 'failed', 'test_count': len(COLD_H2_TESTS),
                     'original_44_denominator_unchanged': True,
                     'existing_ingress_7_denominator_unchanged': True,
                     'new_total_group_cap_seconds': 600,
                     'clamped_to_original_outer_deadline': True,
                     'actual_test_names': [], 'tests': []}
        result['cold_h2_regression'] = increment
        def increment_remaining():
            value = increment_until - time.monotonic()
            assert value > 0, 'cold H2 group deadline'
            return value
        for index, name in enumerate(COLD_H2_TESTS):
            label = 'cold-h2-' + str(index + 1)
            listing = owned(label + '-list', [str(binary), name, '--exact', '--list'],
                            min(30.0, increment_remaining()), deadline=increment_until)
            assert listing['exit_code'] == 0 and not listing['timed_out']
            selected = [line[:-6] for line in (output / (label + '-list.stdout')).read_text().splitlines()
                        if line.endswith(': test')]
            assert selected == [name], 'exact reviewed cold/H2 testcase missing'
            increment_remaining()
            tests = owned(label, [str(binary), name, '--exact', '--nocapture', '--test-threads=1'],
                          increment_remaining(), deadline=increment_until)
            increment['actual_test_names'].append(name)
            increment['tests'].append({'name': name, 'tests': tests})
            assert tests['exit_code'] == 0 and not tests['timed_out']
            summary = (output / (label + '.stdout')).read_text()
            assert 'test result: ok. 1 passed; 0 failed; 0 ignored;' in summary, 'actual testcase not executed'
            increment_remaining()
        result['binary_unchanged'] = sha(binary) == binary_sha
        result['release_artifacts_unchanged'] = all(sha(v['path']) == v['sha256'] for v in release_artifacts.values())
        result['source_unchanged'] = freeze() == before
        assert result['binary_unchanged'] and result['release_artifacts_unchanged'] and result['source_unchanged']
        increment_completed = time.monotonic()
        assert increment_completed < increment_until, 'cold H2 group deadline'
        increment['elapsed_seconds'] = increment_completed - increment_started
        increment['status'] = 'passed'
        result['status'] = 'passed'
    if result['status'] == 'passed':
        # Keep all sixty prior results distinct; this regression is additional.
        result['original_60_status'] = 'passed'
        result['status'] = 'failed'
        publication_started = time.monotonic()
        publication_until = min(publication_started + 600.0, OUTER_UNTIL)
        publication = {'schema': 'heptabao.normal-same-root-publication-regression.v1',
                       'status': 'failed', 'test_count': 1,
                       'original_44_7_9_denominators_unchanged': True,
                       'new_total_group_cap_seconds': 600,
                       'clamped_to_original_outer_deadline': True,
                       'actual_test_names': [], 'tests': []}
        result['same_root_publication_regression'] = publication
        def publication_remaining():
            value = publication_until - time.monotonic()
            assert value > 0, 'same-root publication regression deadline'
            return value
        name = SAME_ROOT_PUBLICATION_TESTS[0]
        label = 'same-root-publication-1'
        listing = owned(label + '-list', [str(binary), name, '--exact', '--list'],
                        min(30.0, publication_remaining()), deadline=publication_until)
        assert listing['exit_code'] == 0 and not listing['timed_out']
        selected = [line[:-6] for line in (output / (label + '-list.stdout')).read_text().splitlines()
                    if line.endswith(': test')]
        assert selected == [name], 'exact same-root publication testcase missing'
        publication_remaining()
        tests = owned(label, [str(binary), name, '--exact', '--nocapture', '--test-threads=1'],
                      publication_remaining(), deadline=publication_until)
        publication['actual_test_names'].append(name)
        publication['tests'].append({'name': name, 'tests': tests})
        assert tests['exit_code'] == 0 and not tests['timed_out']
        summary = (output / (label + '.stdout')).read_text()
        assert 'test result: ok. 1 passed; 0 failed; 0 ignored;' in summary, 'actual testcase not executed'
        publication_remaining()
        result['binary_unchanged'] = sha(binary) == binary_sha
        result['release_artifacts_unchanged'] = all(sha(v['path']) == v['sha256'] for v in release_artifacts.values())
        result['source_unchanged'] = freeze() == before
        assert result['binary_unchanged'] and result['release_artifacts_unchanged'] and result['source_unchanged']
        publication_completed = time.monotonic()
        assert publication_completed < publication_until, 'same-root publication regression deadline'
        publication['elapsed_seconds'] = publication_completed - publication_started
        publication['status'] = 'passed'
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
