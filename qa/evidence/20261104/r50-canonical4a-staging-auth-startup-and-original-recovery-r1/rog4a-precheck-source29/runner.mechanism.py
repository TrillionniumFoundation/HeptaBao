#!/usr/bin/env python3
"""Build one admitted combined source and run 252 unique cases in 280 profile instances."""
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
parser.add_argument('--fresh-target-first5', required=True)
args = parser.parse_args()
ORIGINAL_OUTER_SECONDS = 12000
assert args.launcher_pid == os.getpid(), 'same-PID launcher exec required'
assert 0 < args.outer_started_monotonic <= time.monotonic()
OUTER_UNTIL = args.outer_started_monotonic + ORIGINAL_OUTER_SECONDS
assert time.monotonic() < OUTER_UNTIL, 'original outer deadline expired before runner'
source, output = Path(args.source), Path(args.output)
DIAGNOSTIC_COMMIT = '5767739cd25e458ac052dc8d384019bab8688ae0'
DIAGNOSTIC_TREE = '42477d622dcf96e1e2b0929fe9ecc6b7ba484740'
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

def fresh_identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


PUBLIC_TOOL_IDENTITIES = {
    "/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/cargo": ["66306","28970595","1000","1000","33261","1","40688400","1791677518879180933","1791677518982180473"],
    "/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustc": ["66306","28970693","1000","1000","33261","1","645016","1791677530537128895","1791677533756422548"]
}
CARGO_HOME_FIRST5 = ["66306","31604578","1000","1000","16832"]

def current_tool_whole(path):
    global protected
    expected = PUBLIC_TOOL_IDENTITIES[str(path)]
    assert path.resolve(strict=True) == path
    fd = None
    protected += 1
    try:
        try:
            if pending_signal is not None:
                raise Cancelled()
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            before = os.fstat(fd)
            assert [str(x) for x in fresh_identity(before)] == expected
            assert stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 1000
            assert before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o755
            count, digest = 0, hashlib.sha256()
            while True:
                if pending_signal is not None:
                    raise Cancelled()
                assert time.monotonic() < OUTER_UNTIL
                part = os.read(fd, min(1024 * 1024, before.st_size + 1 - count))
                if not part:
                    break
                count += len(part)
                assert count <= before.st_size
                digest.update(part)
            assert count == before.st_size
            assert fresh_identity(before) == fresh_identity(os.fstat(fd)) == fresh_identity(path.lstat())
            pin = {'path': str(path), 'bytes': count, 'sha256': digest.hexdigest(),
                   'identity': list(fresh_identity(before)),
                   'independent_prior_content_sha_observed': False}
        finally:
            if fd is not None:
                os.close(fd)
    finally:
        protected -= 1
    if pending_signal is not None:
        raise Cancelled()
    return pin


def fresh_target_pin():
    path = Path(args.target)
    assert path == Path('/home/qian-qi/hb-5767739c-controls-20261106-r1/cargo-target-r1')
    assert path.parent == Path(__file__).resolve(strict=True).parent
    assert path.resolve(strict=True) == path
    info = path.lstat()
    fields = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
              info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    expected = json.loads(args.fresh_target_first5)
    assert len(expected) == 5 and all(type(x) is int for x in expected)
    assert list(fields[:5]) == expected
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 1000
    assert stat.S_IMODE(info.st_mode) == 0o700
    return {'path': str(path), 'identity': list(fields),
            'new_independent_target': True, 'legacy_cache_reused': False}

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
assert args.groups_sha256 == '617d5c104309ec8fcd006d97a60cb519c7b26ad203359ca6dc84146855f746df'
assert sha(args.groups) == args.groups_sha256
groups = json.loads(Path(args.groups).read_text())
PROFILE_CRATES = {'file': 'heptabao-server', 'default': 'heptabao-server',
                  'ha-native-v6-peer-ingress': 'heptabao-ha-service'}
EXPECTED_GROUP_SHAPES = [
    ("native-jwt-pki-file28", "file", 28), ("native-jwt-pki-default28", "default", 28),
    ("legacy-jwt-default67", "default", 67), ("native-auth-identity-default69", "default", 69),
    ("snapshot-body10", "ha-native-v6-peer-ingress", 10), ("snapshot-peer7", "ha-native-v6-peer-ingress", 7),
    ("snapshot-actor2", "default", 2), ("snapshot-wire4", "default", 4),
    ("snapshot-service-audit4", "default", 4), ("ssh25", "default", 25),
    ("mount1", "default", 1), ("redirect5", "default", 5),
    ("actor2", "default", 2), ("ordinary5", "default", 5),
    ("no_forward6", "default", 6), ("ingress_observer", "default", 7),
    ("cold_h2", "default", 9), ("same_root_publication", "default", 1)]
assert [(g['label'], g['libtest_profile'], len(g['tests'])) for g in groups] == EXPECTED_GROUP_SHAPES
all_cases = []
for group in groups:
    assert set(group) == {'label', 'libtest_profile', 'tests', 'runtime_seconds'}
    assert group['runtime_seconds'] == 600 and group['libtest_profile'] in PROFILE_CRATES
    assert group['tests'] and len(group['tests']) == len(set(group['tests']))
    assert all(isinstance(n, str) and n for n in group['tests'])
    assert group['label'].replace('-', '').replace('_', '').isalnum()
    all_cases.extend((PROFILE_CRATES[group['libtest_profile']], n) for n in group['tests'])
assert groups[0]['tests'] == groups[1]['tests'], 'same twenty-eight source names in both feature profiles'
assert len(all_cases) == 280 and len(set(all_cases)) == 252
assert sum(len(g['tests']) for g in groups[:4]) == 192
assert len({n for g in groups[:4] for n in g['tests']}) == 164
assert sum(len(g['tests']) for g in groups[4:9]) == 27
assert sum(len(g['tests']) for g in groups[9:]) == 61
assert not output.exists() and not output.is_symlink()
before = freeze()
assert before == {'commit': args.commit, 'tree': args.tree, 'status': ''}
output.mkdir(mode=0o700)
intent = {'schema': 'heptabao.combined-snapshot-jwt-pki-build-regression.v1', 'source_commit': args.commit,
          'source_tree': args.tree, 'normal_default_features': True, 'fixture_features': [],
          'profile': profile, 'groups': groups, 'test_count': 252,
          'groups_sha256': args.groups_sha256, 'controller_sha256': sha(__file__),
          'production_changed': False, 'started_ns': time.time_ns(),
          'selected_unique_test_total': 252, 'selected_profile_instance_total': 280,
          'baseline_c_unique_test_total': 149, 'baseline_c_profile_instance_total': 166,
          'jwt_policy_delta_unique_test_total': 9, 'jwt_policy_delta_profile_instance_total': 14,
           'jwt_batch_delta_unique_test_total': 6, 'jwt_batch_delta_profile_instance_total': 12,
          'baseline_c_added_unique_test_total': 17, 'baseline_c_existing_unique_test_total': 132,
          'baseline_native_jwt_pki_fixture_backend': 'FileV6',
          'snapshot_low_level_component_total': 23, 'snapshot_service_regression_total': 4,
          'normal61_selected_test_total': 61, 'full34_LAN98plus12_comparison69_selected': False,
          'distributed_native_jwt_ha_qualified': False,
          'original_outer_seconds': ORIGINAL_OUTER_SECONDS,
          'launcher_started_monotonic': args.outer_started_monotonic,
          'same_pid_launcher': args.launcher_pid,
          'outer_phase_caps_seconds': {'normal_release_build': 1800,
                                       'all_compile_checks_shared': 3600,
                                       'each_listing': 30, 'each_runtime_family_shared': 600}}
write('intent.public.json', intent)
result = {**intent, 'status': 'failed', 'runtime_tests_started': False, 'group_results': []}
try:
    result['fresh_target_before'] = fresh_target_pin()
    result['current_tools'] = [current_tool_whole(Path(args.toolchain) / name)
                               for name in ('cargo', 'rustc')]
    cargo_home = Path(args.cargo_home)
    assert cargo_home == Path('/home/qian-qi/heptabao-native-20261029-c1bd-r1/cargo-home')
    assert cargo_home.resolve(strict=True) == cargo_home
    cargo_info = cargo_home.lstat()
    assert [str(x) for x in fresh_identity(cargo_info)[:5]] == CARGO_HOME_FIRST5
    result['cargo_home'] = {'path': str(cargo_home), 'identity': list(fresh_identity(cargo_info)),
                            'offline_contents_qualified': False}
    result['historical_cache_evidence'] = {
        'reverified_in_this_build': False, 'qualification_inherited': False,
        'old_target_or_artifacts_modified': False,
        'retained_prior_function_and_table_executed': False,
        'known_missing_original_root': '/home/qian-qi/heptabao-same-root-publication-normal-20261105-r2',
        'known_missing_original_table_leaves': 6,
        'metadata_sha256': '47ea247da0a38c51468821bbcd8c34800ebf9c27790b5968e09141b53f799972'}
    rustc = subprocess.check_output([str(Path(args.toolchain) / 'rustc'), '-vV'], text=True, timeout=30)
    assert 'release: 1.98.0' in rustc and 'host: x86_64-unknown-linux-gnu' in rustc
    result['rustc_vv'] = rustc
    release_started = time.monotonic()
    release_until = min(release_started + 1800.0, OUTER_UNTIL)
    result['release_shared'] = {'started_monotonic': release_started, 'until_monotonic': release_until,
                               'cap_seconds': 1800, 'precheck_max_seconds': 300, 'deadline_reset': False}
    precheck = owned('default-libtest-precheck', [str(Path(args.toolchain) / 'cargo'), 'check',
                     '--locked', '--offline', '-p', 'heptabao-server', '--lib', '--profile', 'test',
                     '--message-format=json-render-diagnostics'],
                     min(300.0, bounded_remaining(release_until)), deadline=release_until)
    result['default_libtest_precheck'] = precheck
    assert precheck['exit_code'] == 0 and not precheck['timed_out'], 'default libtest precheck failed'
    precheck_events = []
    for line in (output / 'default-libtest-precheck.stdout').read_text().splitlines():
        try:
            precheck_events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    precheck_finished = [e for e in precheck_events if e.get('reason') == 'build-finished']
    assert len(precheck_finished) == 1 and precheck_finished[0].get('success') is True
    precheck_artifacts = [e for e in precheck_events if e.get('reason') == 'compiler-artifact'
                         and e.get('target', {}).get('name') == 'heptabao_server'
                         and e.get('profile', {}).get('test') is True]
    assert len(precheck_artifacts) == 1
    precheck_artifact = precheck_artifacts[0]
    assert precheck_artifact['target']['kind'] == ['lib']
    assert precheck_artifact['target']['src_path'] == str(source / 'crates/heptabao-server/src/lib.rs')
    assert precheck_artifact['manifest_path'] == str(source / 'crates/heptabao-server/Cargo.toml')
    assert sorted(precheck_artifact['features']) == ['default', 'native-v6-ha', 'native-v6-storage']
    result['default_libtest_precheck_mode'] = {'actual_artifact': precheck_artifact,
        'actual_build_finished': precheck_finished[0], 'linked_test_executable_qualified': False,
        'runtime_tests_qualified': False, 'replaces_release_or_no_run': False}
    assert freeze() == before
    release = owned('normal-release-build', [str(Path(args.toolchain) / 'cargo'), 'build',
                    '--release', '--locked', '--offline', '-p', 'heptabao-server',
                    '--bin', 'heptabao-server', '--bin', 'heptabao-seed',
                    '--message-format=json-render-diagnostics'], bounded_remaining(release_until), deadline=release_until)
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
    # One original 3600-second compilation budget includes all four checks.
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
    for profile_name, package, target_name, feature_arguments, expected_features in (
            ('file', 'heptabao-server', 'heptabao_server', ['--no-default-features', '--features', 'native-v6-storage'], ['native-v6-storage']),
            ('default', 'heptabao-server', 'heptabao_server', [], ['default', 'native-v6-ha', 'native-v6-storage']),
            ('ha-native-v6-peer-ingress', 'heptabao-ha-service', 'heptabao_ha_service', ['--no-default-features', '--features', 'native-v6-peer-ingress'], ['native-v6-peer-ingress'])):
        label = profile_name + '-libtest-build'
        build = owned(label, [str(Path(args.toolchain) / 'cargo'), 'test', '--release', '--locked',
                      '--offline', '-p', package, '--lib', '--no-run',
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
                    and event.get('target', {}).get('name') == target_name and event.get('executable')):
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
        binary = output / ('retained-' + package + '-libtest-' + profile_name)
        with built.open('rb') as original, binary.open('xb') as retained:
            shutil.copyfileobj(original, retained, 1024 * 1024)
            retained.flush()
            os.fsync(retained.fileno())
        binary.chmod(0o500)
        assert sha(binary) == binary_sha and sha(built) == binary_sha
        binaries[profile_name] = {'path': str(binary), 'sha256': binary_sha, 'bytes': binary.stat().st_size,
                                 'features': artifact['features'], 'profile': artifact['profile'],
                                 'compiler_executable': str(built), 'build': build, 'crate': package,
                                 'target_name': target_name}
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
        assert selected_binary['crate'] == PROFILE_CRATES[group['libtest_profile']]
        family = {'label': group['label'], 'libtest_profile': group['libtest_profile'],
                  'crate': selected_binary['crate'],
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
    actual_cases = [(family['crate'], name) for family in result['group_results'] for name in family['actual_test_names']]
    assert len(actual_cases) == 280 and len(set(actual_cases)) == 252
    assert result['binaries_unchanged'] and result['release_artifacts_unchanged'] and result['source_unchanged']
    assert len(result['group_results']) == 18 and all(g['status'] == 'passed' for g in result['group_results'])
    result['actual_unique_test_total'] = 252
    result['actual_profile_instance_total'] = 280
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
    try:
        result['fresh_target_after'] = fresh_target_pin()
        assert result['fresh_target_after']['identity'][:5] == result['fresh_target_before']['identity'][:5]
        assert [str(x) for x in fresh_identity(Path(args.cargo_home).lstat())[:5]] == CARGO_HOME_FIRST5
        for tool in result['current_tools']:
            assert list(fresh_identity(Path(tool['path']).lstat())) == tool['identity']
    except BaseException as error:
        result['status'] = 'failed'
        result['fresh_target_fence_error_type'] = type(error).__name__
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
