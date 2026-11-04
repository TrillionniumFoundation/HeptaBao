#!/usr/bin/env python3
"""Build frozen Mac R9 normal server/seed and libtest with original budgets."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import signal
import shutil
import subprocess
import time

os.umask(0o077)
parser = argparse.ArgumentParser()
for name in ('source', 'output', 'commit', 'tree', 'toolchain', 'cargo-home', 'target', 'groups', 'groups-sha256'):
    parser.add_argument('--' + name, required=True)
args = parser.parse_args()
source, output = Path(args.source), Path(args.output)
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
    'PATH': args.toolchain + ':/opt/homebrew/bin:/usr/bin:/bin',
    'CARGO_HOME': args.cargo_home, 'CARGO_TARGET_DIR': args.target,
    'CARGO_BUILD_JOBS': '2', 'CARGO_PROFILE_RELEASE_OPT_LEVEL': '3',
    'CARGO_PROFILE_RELEASE_CODEGEN_UNITS': '16', 'CARGO_PROFILE_RELEASE_LTO': 'false',
    'CARGO_PROFILE_RELEASE_DEBUG': '0', 'CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS': 'true',
    'CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS': 'true', 'CARGO_PROFILE_RELEASE_PANIC': 'unwind',
    'RUSTFLAGS': '', 'CARGO_TERM_COLOR': 'never',
}
environment = dict(os.environ)
environment.update(profile)
environment.pop('CARGO_ENCODED_RUSTFLAGS', None)

def owned(label, command, limit):
    global protected
    started = time.monotonic()
    timed_out = False
    with (output / (label + '.stdout')).open('xb') as out, (output / (label + '.stderr')).open('xb') as err:
        process = None
        protected += 1
        try:
            process = subprocess.Popen(command, cwd=source, env=environment,
                                       stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                       start_new_session=True)
            children.append((label, process))
        finally:
            protected -= 1
        if pending_signal is not None:
            raise Cancelled()
        try:
            code = process.wait(timeout=limit)
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
    record = {'label': label, 'argv': command, 'exit_code': code, 'timed_out': timed_out,
              'elapsed_seconds': time.monotonic() - started, 'outer_cap_seconds': limit,
              'owned_pgid': process.pid, 'direct_child_reaped': process.returncode is not None,
              'remaining': remaining, 'stdout_sha256': sha(output / (label + '.stdout')),
              'stderr_sha256': sha(output / (label + '.stderr'))}
    write(label + '.public.json', record)
    assert not remaining, 'owned child group did not finish'
    return record

assert os.uname().sysname == 'Darwin' and os.uname().machine == 'arm64'
# Physical commit is pinned by the reviewed launcher and the clean-tree freeze below.
assert args.tree == 'e1faeaa3ed49d26fb01a7617a8879cb693a12907'
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
assert not output.exists() and not output.is_symlink()
before = freeze()
assert before == {'commit': args.commit, 'tree': args.tree, 'status': ''}
output.mkdir(mode=0o700)
intent = {'schema': 'heptabao.mac-normal-release-and-exact-libtest-r9.v1', 'source_commit': args.commit,
          'source_tree': args.tree, 'normal_default_features': True, 'fixture_features': [],
          'profile': profile, 'groups': groups, 'test_count': len(all_names),
          'groups_sha256': args.groups_sha256, 'controller_sha256': sha(__file__),
          'production_changed': False, 'started_ns': time.time_ns(),
          'outer_phase_caps_seconds': {'normal_release_build': 1800, 'normal_libtest_build': 1800,
                                       'each_listing': 30, 'each_runtime_group': 600}}
write('intent.public.json', intent)
result = {**intent, 'status': 'failed', 'runtime_tests_started': False, 'group_results': []}
try:
    rustc = subprocess.check_output([str(Path(args.toolchain) / 'rustc'), '-vV'], text=True, timeout=30)
    assert 'release: 1.98.0' in rustc and 'host: aarch64-apple-darwin' in rustc
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
            'native_abi': 'aarch64-apple-darwin', 'build_exit_code': 0,
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
            'native_abi': 'aarch64-apple-darwin', 'build_exit_code': 0,
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
                  '--message-format=json-render-diagnostics'], 1800)
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
    result['terminal_ns'] = time.time_ns()
    write('result.public.json', result)
    print(json.dumps({'status': result['status'], 'source_commit': args.commit, 'source_tree': args.tree,
                      'result_path': str(output / 'result.public.json'),
                      'result_sha256': sha(output / 'result.public.json'),
                      'all_owned_stopped': all(not x.get('cleanup_error_type') and not x['remaining'] and x['direct_child_reaped'] for x in cleanup)}), flush=True)
raise SystemExit(0 if result['status'] == 'passed' else 1)
