#!/usr/bin/env python3
"""Build one frozen normal libtest and execute exact reviewed groups on Mac."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import signal
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
assert sha(args.groups) == args.groups_sha256
groups = json.loads(Path(args.groups).read_text())
assert isinstance(groups, list) and groups and len(groups) <= 4
all_names = []
for group in groups:
    assert set(group) == {'label', 'filter', 'exact', 'tests', 'runtime_seconds'}
    assert group['runtime_seconds'] == 600 and isinstance(group['exact'], bool)
    assert group['tests'] and len(group['tests']) == len(set(group['tests']))
    assert all(isinstance(n, str) and n for n in group['tests'])
    assert group['label'].replace('-', '').replace('_', '').isalnum()
    all_names.extend(group['tests'])
assert len(all_names) == len(set(all_names)), 'groups overlap'
assert not output.exists() and not output.is_symlink()
before = freeze()
assert before == {'commit': args.commit, 'tree': args.tree, 'status': ''}
output.mkdir(mode=0o700)
intent = {'schema': 'heptabao.mac-normal-exact-libtest.v1', 'source_commit': args.commit,
          'source_tree': args.tree, 'normal_default_features': True, 'fixture_features': [],
          'profile': profile, 'groups': groups, 'test_count': len(all_names),
          'groups_sha256': args.groups_sha256, 'controller_sha256': sha(__file__),
          'production_changed': False, 'started_ns': time.time_ns()}
write('intent.public.json', intent)
result = {**intent, 'status': 'failed', 'runtime_tests_started': False, 'group_results': []}
try:
    rustc = subprocess.check_output([str(Path(args.toolchain) / 'rustc'), '-vV'], text=True, timeout=30)
    assert 'release: 1.98.0' in rustc and 'host: aarch64-apple-darwin' in rustc
    result['rustc_vv'] = rustc
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
    binary = Path(artifact['executable'])
    assert binary.is_file() and not binary.is_symlink()
    binary_sha = sha(binary)
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
    result['source_unchanged'] = freeze() == before
    result['status'] = 'passed' if (result['binary_unchanged'] and result['source_unchanged']
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
