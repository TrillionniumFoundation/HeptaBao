#!/usr/bin/env python3
"""Own one isolated, pinned source and cache; format/freeze before normal builds."""
import base64
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time

ROOT = Path('/home/qian-qi/heptabao-bao-acceptance-unified-61ff-20261104-r1')
SOURCE = ROOT / 'source'
RUN = ROOT / 'normal-build-r4'
TARGET = ROOT / 'cargo-target-normal'
PRIOR = Path('/home/qian-qi/heptabao-native-ssh-owner-20261104-r1/source')
CACHE = Path('/home/qian-qi/heptabao-native-20261029-c1bd-r1/runtime/target')
BASE = '33cafa4c6e29f0bde1553e041550d21b4c725d9c'
BASE_TREE = 'cdc2376e7b39c1d8bbbeb10a813d58bfe923f336'
PRIOR_HEAD = '71e1cfff25a124d77ee1771c840c4c69b58c573e'
BRANCH = 'codex/heptabao-unified-61ff-20261104-r1'
TOOLCHAIN = '/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin'
PROFILE = {
    'PATH': TOOLCHAIN + ':/usr/bin:/bin',
    'CARGO_HOME': '/home/qian-qi/heptabao-native-20261029-c1bd-r1/cargo-home',
    'CARGO_TARGET_DIR': str(TARGET),
    'CARGO_BUILD_JOBS': '1',
    'CARGO_PROFILE_RELEASE_OPT_LEVEL': '3',
    'CARGO_PROFILE_RELEASE_CODEGEN_UNITS': '16',
    'CARGO_PROFILE_RELEASE_LTO': 'false',
    'CARGO_PROFILE_RELEASE_DEBUG': '0',
    'CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS': 'true',
    'CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS': 'true',
    'CARGO_PROFILE_RELEASE_PANIC': 'unwind',
}
EXPIRES = json.loads((ROOT / 'overall-bound.public.json').read_text())['monotonic_expires']
BOOT = Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def git(where, *args, raw=False):
    data = subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(where), *args],
                                   stderr=subprocess.DEVNULL, timeout=60)
    return data if raw else data.decode().strip()


def write_new(path, data):
    with path.open('xb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def public(path, data):
    write_new(path, (json.dumps(data, indent=2) + '\n').encode())


def phase(label, **data):
    print(json.dumps({'phase': label, 'observed_ns': time.time_ns(), **data}, sort_keys=True), flush=True)


def active_builders():
    found = []
    for item in Path('/proc').iterdir():
        if not item.name.isdigit():
            continue
        try:
            if item.stat().st_uid != os.getuid():
                continue
            name = (item / 'comm').read_text().strip()
            executable = os.readlink(item / 'exe')
            if name in {'cargo', 'rustc', 'rustfmt', 'rustdoc', 'clippy-driver', 'cc', 'gcc', 'clang', 'ld', 'ld.lld', 'rust-lld'} or Path(executable).name.startswith('heptabao_server-') or Path(executable).name == 'retained-heptabao-server-libtest':
                found.append({'pid': int(item.name), 'name': name, 'cwd': os.readlink(item / 'cwd')})
        except (OSError, ValueError):
            pass
    return found


def owned(label, args, directory=SOURCE, ceiling=None):
    public(RUN / (label + '-compile-admission.public.json'), compile_admission())
    phase(label + '_start')
    cap = EXPIRES - time.monotonic()
    if ceiling is not None:
        cap = min(cap, ceiling)
    assert cap > 0, 'original overall build envelope elapsed'
    env = dict(os.environ)
    env.update(PROFILE)
    started = time.monotonic()
    timed_out = False
    with (RUN / (label + '.stdout')).open('xb') as out, (RUN / (label + '.stderr')).open('xb') as err:
        child = subprocess.Popen(args, cwd=directory, env=env, stdout=out, stderr=err, start_new_session=True)
        try:
            code = child.wait(timeout=cap)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(child.pid, signal.SIGKILL)
            code = child.wait(timeout=20)
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=20)
    remaining = []
    for item in Path('/proc').iterdir():
        if not item.name.isdigit():
            continue
        try:
            raw = (item / 'stat').read_text()
            parts = raw[raw.rfind(')') + 2:].split()
            if int(parts[2]) == child.pid:
                remaining.append(int(item.name))
        except (OSError, ValueError, IndexError):
            pass
    report = {'label': label, 'args': args, 'exit_code': code, 'timed_out': timed_out,
              'elapsed_seconds': time.monotonic() - started, 'owned_pgid': child.pid,
              'remaining': remaining, 'original_outer_remaining_seconds': cap,
              'stdout_sha256': sha(RUN / (label + '.stdout')),
              'stderr_sha256': sha(RUN / (label + '.stderr'))}
    public(RUN / (label + '.public.json'), report)
    phase(label + '_complete', exit_code=code, elapsed_seconds=report['elapsed_seconds'], remaining=remaining)
    assert code == 0 and not timed_out and not remaining, label + ' did not complete successfully'
    return report


def artifacts(label):
    rows = []
    finished = []
    for line in (RUN / (label + '.stdout')).read_text().splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get('reason') == 'compiler-artifact':
            rows.append(row)
        elif row.get('reason') == 'build-finished':
            finished.append(row)
    assert finished == [{'reason': 'build-finished', 'success': True}], label + ' missing actual Cargo success event'
    return rows


def retain(executable, name):
    path = Path(executable)
    assert path.is_file() and not path.is_symlink()
    before = sha(path)
    target = RUN / name
    with path.open('rb') as src, target.open('xb') as dst:
        shutil.copyfileobj(src, dst, 1024 * 1024)
        dst.flush()
        os.fsync(dst.fileno())
    target.chmod(0o500)
    assert sha(target) == before
    return {'original_path': str(path), 'path': str(target), 'sha256': before, 'bytes': target.stat().st_size}


"""One observed foreign build may coexist with compilation, never timed tests.

This is an invocation-time guard scoped to the configured operator UID. Every
compiler phase repeats it before its own process group starts. Other UIDs are
not assessed; this claims neither whole-host exclusivity nor a continuing host
reservation. It never signals or changes a foreign process or reads argv/env.
"""
import os
from pathlib import Path
import shutil
import time

FOREIGN_CARGO_PID = 3058880
FOREIGN_START_CLOCK_TICKS = 13955583
FOREIGN_ROOT = Path('/home/qian-qi/work/trill-g2-native-rog-20261104-v1')
FOREIGN_SOURCE = FOREIGN_ROOT / 'hepta-6b715'
FOREIGN_TARGET_LOCKS = {
    str(FOREIGN_ROOT / 'static-target/release/.cargo-lock'),
    str(FOREIGN_ROOT / 'static-target/x86_64-unknown-linux-gnu/release/.cargo-lock'),
}
OWNED_BOUNDARIES = [
    Path('/home/qian-qi/heptabao-bao-acceptance-unified-61ff-20261104-r1/source'),
    Path('/home/qian-qi/heptabao-bao-acceptance-unified-61ff-20261104-r1/cargo-target-normal'),
    Path('/home/qian-qi/heptabao-native-20261029-c1bd-r1/runtime/target'),
    Path('/home/qian-qi/heptabao-native-20261029-c1bd-r1/cargo-home'),
]
COMPILER_NAMES = {
    'cargo', 'rustc', 'rustfmt', 'rustdoc', 'clippy-driver', 'cc', 'gcc',
    'clang', 'ld', 'ld.lld', 'rust-lld', 'cc1', 'cc1plus', 'c++', 'g++',
    'as', 'collect2', 'lld',
}
# Exact public identities observed in jobs 2b69/2b70. These persistent session
# daemons protect exe metadata; no protected path is reopened or bypassed.
# This classification covers only each listed process, never any descendant.
PINNED_SESSION_DAEMONS = {
    2217: ('systemd', 1, 971, '0::/user.slice/user-1000.slice/user@1000.service/init.scope'),
    2282: ('(sd-pam)', 2217, 977, '0::/user.slice/user-1000.slice/user@1000.service/init.scope'),
    9026: ('ssh-agent', 2217, 2526, '0::/user.slice/user-1000.slice/user@1000.service/app.slice/ssh-agent.service'),
    17987: ('ssh-agent', 9023, 12193, '0::/user.slice/user-1000.slice/user@1000.service/app.slice/gcr-ssh-agent.service'),
}


def is_unit_test(row):
    suffix = row['executable_basename'].rsplit('-', 1)[-1]
    cargo_test_path = ('/deps/' in row['executable_path'] and len(suffix) == 16
                       and all(character in '0123456789abcdef' for character in suffix))
    return (cargo_test_path or row['executable_basename'].startswith('heptabao_server-')
            or row['executable_basename'].startswith('heptabao_ha_service-')
            or row['executable_basename'].startswith('retained-')
            and row['executable_basename'].endswith('-libtest'))


def process_snapshot():
    assert os.getuid() == 1000, 'configured operator differs from observed resource owner'
    rows = {}
    session_daemons = []
    for item in Path('/proc').iterdir():
        if not item.name.isdigit():
            continue
        try:
            uid = item.stat().st_uid
        except FileNotFoundError:
            continue
        except OSError as error:
            raise RuntimeError('cannot observe process ownership for admission') from error
        if uid != os.getuid():
            continue
        try:
            raw = (item / 'stat').read_text()
            fields = raw[raw.rfind(')') + 2:].split()
            if fields[0] in {'Z', 'X'}:
                continue
            pid = int(item.name)
            name = (item / 'comm').read_text().strip()
            if pid in PINNED_SESSION_DAEMONS:
                actual = (name, int(fields[1]), int(fields[19]), (item / 'cgroup').read_text().strip())
                assert actual == PINNED_SESSION_DAEMONS[pid], 'pinned session daemon identity drifted'
                repeated = (item / 'stat').read_text()
                repeated_fields = repeated[repeated.rfind(')') + 2:].split()
                assert item.stat().st_uid == uid == 1000, 'pinned session daemon owner changed'
                assert repeated_fields[0] not in {'Z', 'X'}, 'pinned session daemon exited during classification'
                assert (int(repeated_fields[1]), int(repeated_fields[19])) == actual[1:3], 'pinned session daemon PID changed'
                assert (item / 'comm').read_text().strip() == actual[0], 'pinned session daemon name changed'
                assert (item / 'cgroup').read_text().strip() == actual[3], 'pinned session daemon unit changed'
                session_daemons.append({'pid': pid, 'uid': uid, 'name': actual[0],
                    'parent_pid': actual[1], 'start_clock_ticks': actual[2], 'cgroup': actual[3],
                    'category': 'exact_observed_persistent_session_daemon',
                    'protected_exe_or_fd_read': False, 'descendants_excluded': False})
                continue
            executable = os.readlink(item / 'exe')
            rows[pid] = {
                'pid': pid, 'name': name,
                'cwd': os.readlink(item / 'cwd'), 'parent_pid': int(fields[1]),
                'start_clock_ticks': int(fields[19]),
                'executable_basename': Path(executable).name, 'executable_path': executable,
            }
        except (OSError, ValueError, IndexError) as error:
            try:
                item.stat()
            except FileNotFoundError:
                # Confirmed process exit only. An active descendant must
                # still prove its entire expected parent chain below.
                continue
            except OSError as ownership_error:
                raise RuntimeError('cannot distinguish exited process from unobservable operator process') from ownership_error
            raise RuntimeError('live operator process metadata unobservable; refusing admission') from error
    return rows, session_daemons


def under(path, root):
    actual = os.path.realpath(path.removesuffix(' (deleted)'))
    expected = os.path.realpath(root)
    return actual == expected or actual.startswith(expected + '/')


def is_foreign_descendant(pid, processes):
    seen = set()
    while pid != FOREIGN_CARGO_PID:
        if pid in seen or pid not in processes:
            return False
        seen.add(pid)
        pid = processes[pid]['parent_pid']
    return True


def inspect_fds(row):
    def confirm_identity():
        item = Path('/proc') / str(row['pid'])
        assert item.stat().st_uid == os.getuid(), 'process owner changed during descriptor inspection'
        raw = (item / 'stat').read_text()
        fields = raw[raw.rfind(')') + 2:].split()
        assert fields[0] not in {'Z', 'X'}, 'process exited during descriptor inspection'
        assert int(fields[19]) == row['start_clock_ticks'], 'PID identity changed during descriptor inspection'
        assert (item / 'comm').read_text().strip() == row['name'], 'process name changed during descriptor inspection'
        assert os.readlink(item / 'cwd') == row['cwd'], 'process cwd changed during descriptor inspection'

    confirm_identity()
    locks = []
    overlaps = []
    # An inability to inspect a still-live owner's fd directory is a refusal,
    # never an empty proof. This invocation can be re-admitted after it exits.
    for fd in (Path('/proc') / str(row['pid']) / 'fd').iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:
            continue
        if any(under(target, root) for root in OWNED_BOUNDARIES):
            overlaps.append({'fd': fd.name, 'path': target})
        if Path(target).name in {'.cargo-lock', '.package-cache', '.package-cache-mutate', '.global-cache'}:
            locks.append(target)
    confirm_identity()
    return locks, overlaps


def compile_admission():
    processes, session_daemons = process_snapshot()
    active = [row for row in processes.values()
              if row['name'] in COMPILER_NAMES or is_unit_test(row)]
    memory = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith(('MemAvailable:', 'MemTotal:')):
            memory[line.split(':')[0]] = int(line.split()[1]) * 1024
    resources = {
        'cpu_count': os.cpu_count(), 'load_average_1m': os.getloadavg()[0],
        'memory': memory, 'disk_free_bytes': shutil.disk_usage(OWNED_BOUNDARIES[0]).free,
    }
    assert memory['MemAvailable'] >= 32 * 1024 ** 3, 'compilation memory floor unavailable'
    assert resources['disk_free_bytes'] >= 32 * 1024 ** 3, 'compilation disk floor unavailable'
    assert resources['load_average_1m'] <= resources['cpu_count'] / 2, 'compilation CPU margin unavailable'
    report = {'observed_unix_ns': time.time_ns(), 'resources': resources,
              'observed_builders': active, 'argv_or_environment_read': False,
              'foreign_processes_changed': False, 'valid_only_for_compiler_phase_admission': True,
              'process_scope': 'configured_operator_uid_only', 'operator_uid': os.getuid(),
              'other_uids_assessed': False, 'whole_host_exclusivity_claimed': False,
              'exact_public_session_daemon_classifications': session_daemons}
    if not active:
        return {**report, 'admission': 'no_external_compiler_or_unit_test'}
    assert not any(is_unit_test(row) for row in active), 'an external unit test is active'
    actual = processes.get(FOREIGN_CARGO_PID)
    assert actual is not None, 'expected foreign cargo is absent; active owner unknown'
    assert (actual['name'] == 'cargo'
            and actual['start_clock_ticks'] == FOREIGN_START_CLOCK_TICKS
            and actual['cwd'] == str(FOREIGN_SOURCE)), 'foreign cargo identity changed'
    assert all(is_foreign_descendant(row['pid'], processes) for row in active), 'unknown new builder owner'
    descendants = [row for row in processes.values()
                   if is_foreign_descendant(row['pid'], processes)]
    assert all(under(row['cwd'], FOREIGN_ROOT) for row in descendants), 'foreign descendant cwd left observed workspace'
    checked = []
    for row in descendants:
        locks, overlaps = inspect_fds(row)
        assert not overlaps, 'foreign descriptor crosses an owned source/cache/target boundary'
        assert all(under(lock, FOREIGN_ROOT) for lock in locks), 'foreign lock outside observed workspace'
        if row['pid'] == FOREIGN_CARGO_PID:
            assert FOREIGN_TARGET_LOCKS.issubset(set(locks)), 'observed foreign target locks changed'
        checked.append({**row, 'lock_paths': sorted(locks), 'owned_boundary_overlaps': overlaps})
    return {**report, 'admission': 'exact_observed_foreign_build_with_independent_locks',
            'foreign_cargo': actual, 'checked_descendants': checked,
            'owned_boundaries': [str(path) for path in OWNED_BOUNDARIES]}


def exclusive_timed_test_admission():
    processes, session_daemons = process_snapshot()
    active = [row for row in processes.values()
              if row['name'] in COMPILER_NAMES or is_unit_test(row)]
    assert not active, 'external compiler or unit test still active; no timed test admission'
    return {'observed_unix_ns': time.time_ns(), 'observed_builders': active,
            'admission': 'operator_uid_no_external_compiler_or_unit_test',
            'argv_or_environment_read': False, 'foreign_processes_changed': False,
            'process_scope': 'configured_operator_uid_only', 'operator_uid': os.getuid(),
            'other_uids_assessed': False, 'whole_host_exclusivity_claimed': False,
            'exact_public_session_daemon_classifications': session_daemons}


def main():
    os.umask(0o077)
    payload = json.load(sys.stdin)
    old_frozen = json.loads((ROOT / 'frozen-source-r3.public.json').read_text())
    assert sha(ROOT / 'frozen-source-r3.public.json') == 'e8492bff7ae331205c5c83232b7fc94f6471b99d7be3ae4f1c4fe2005cd831a3'
    assert old_frozen['source'] == '3961275d27e4a4e64e2d28619ef3b1b8d76e9980'
    assert old_frozen['tree'] == 'd6dffaf4627ac16961e67c94b99f84122adc2e1d'
    assert sha(ROOT / 'normal-build-r3/strict_clippy.stderr') == '034471356ac69df6bbd7840e851b3681af085eb492883b4decc28b4ff63cf418'
    previous = json.loads((ROOT / 'normal-build-r3/strict_clippy.public.json').read_text())
    assert previous['exit_code'] == 101 and not previous['timed_out'] and not previous['remaining']
    bound = json.loads((ROOT / 'overall-bound.public.json').read_text())
    assert BOOT == bound['boot_id'] and time.monotonic() < EXPIRES
    assert git(SOURCE, 'rev-parse', 'HEAD') == old_frozen['source']
    assert git(SOURCE, 'rev-parse', 'HEAD^{tree}') == old_frozen['tree']
    assert git(SOURCE, 'branch', '--show-current') == BRANCH
    assert not git(SOURCE, 'status', '--porcelain=v1', '--untracked-files=all')
    assert not RUN.exists() and not (ROOT / 'frozen-source-r4.public.json').exists()
    initial_compile_admission = compile_admission()
    old_files = {row['path']: row for row in old_frozen['files']}
    changed = {row['path'] for row in payload['files']}
    paths = set(old_files) | changed
    assert len(changed) == 4 and len(paths) == 59
    for row in old_frozen['files']:
        assert sha(SOURCE / row['path']) == row['sha256']
    for row in payload['files']:
        assert sha(SOURCE / row['path']) == row['base_sha256']
        assert git(SOURCE, 'rev-parse', 'HEAD:' + row['path']) == row['base_git_blob']
        if row['path'] in old_files:
            assert row['base_sha256'] == old_files[row['path']]['sha256']
        assert sha_bytes(row['content'].encode()) == row['candidate_sha256']
    RUN.mkdir(mode=0o700)
    public(RUN / 'initial-compile-admission.public.json', initial_compile_admission)
    public(RUN / 'delta-input.public.json', {key: value for key, value in payload.items() if key != 'workspace_runner'})
    write_new(ROOT / 'run_full_workspace-r4.py', payload['workspace_runner'].encode())
    result = {'status': 'failed', 'qualified_full_replacement': False, 'workspace_tests_started': False,
              'profile': PROFILE, 'fixture_features': [], 'fixture_budgets_changed': False,
              'prior_terminal_job': '1a1a7730b93-fc05-2b7b', 'prior_source': old_frozen['source'],
              'prior_gate': 'server_libtest_E0277_E0063_and_one_prefetch_lint',
              'overall_deadline_unchanged': True, 'reuses_independent_owned_source_cache': True,
              'prior_admission_only_failure_job': '1a1a75eaff9-fc05-2b29',
              'prior_metadata_only_refusal_job': '1a1a76bcaaa-fc05-2b63',
              'compile_admission_guard_sha256': '108ea3a050eb5f1596b8c6cab3aeffbce8a220e91ae1b15ac70b3b6176c097cb'}
    try:
        for row in payload['files']:
            (SOURCE / row['path']).write_text(row['content'])
        owned('format', [TOOLCHAIN + '/cargo', 'fmt', '--all'], ceiling=300)
        owned('format_check', [TOOLCHAIN + '/cargo', 'fmt', '--all', '--', '--check'], ceiling=300)
        assert set(git(SOURCE, 'diff', '--name-only').splitlines()) == changed
        git(SOURCE, 'diff', '--check')
        git(SOURCE, 'add', '--', *sorted(changed))
        git(SOURCE, '-c', 'user.name=Codex', '-c', 'user.email=codex@localhost', 'commit', '-m',
            'Fix snapshot clock test construction without exposing response bodies or minting receipts')
        commit, tree = git(SOURCE, 'rev-parse', 'HEAD'), git(SOURCE, 'rev-parse', 'HEAD^{tree}')
        assert not git(SOURCE, 'status', '--porcelain=v1', '--untracked-files=all')
        critical_tests = old_frozen['critical_tests']
        assert len(critical_tests) == 56 and len({row['name'] for row in critical_tests}) == 56
        frozen = {**old_frozen, 'source': commit, 'tree': tree, 'parent_source': old_frozen['source'],
                  'parent_tree': old_frozen['tree'], 'formatted': True, 'compiled': False,
                  'files': [{'path': path, 'sha256': sha(SOURCE / path), 'bytes': (SOURCE / path).stat().st_size,
                             'git_blob': git(SOURCE, 'rev-parse', 'HEAD:' + path)} for path in sorted(paths)],
                  'critical_tests': critical_tests,
                  'known_remaining_product_gaps': old_frozen['known_remaining_product_gaps'] + payload['newly_proven_gaps'],
                  'repair_scope': 'four test compilation fixes; production semantics, budgets and authority unchanged'}
        public(ROOT / 'frozen-source-r4.public.json', frozen)
        write_new(ROOT / 'frozen-source-r4.patch', git(SOURCE, 'diff', '--binary', BASE, 'HEAD', raw=True))
        write_new(RUN / 'r3-to-r4.patch', git(SOURCE, 'diff', '--binary', old_frozen['source'], 'HEAD', raw=True))
        # Transfer only exact formatted files the local publisher does not yet own.
        transfer_files = [{'path': row['path'], 'sha256': row['sha256'], 'git_blob': row['git_blob'],
                           'content': (SOURCE / row['path']).read_text()}
                          for row in frozen['files'] if payload['local_known_sha256'].get(row['path']) != row['sha256']]
        transfer = json.dumps({'source': commit, 'tree': tree, 'files': transfer_files}, separators=(',', ':')).encode()
        compressed = gzip.compress(transfer, mtime=0)
        encoded = base64.b64encode(compressed)
        chunks = []
        for offset in range(0, len(encoded), 24000):
            file = RUN / ('frozen-source.b64.' + str(offset))
            write_new(file, encoded[offset:offset + 24000])
            chunks.append({'path': str(file), 'bytes': file.stat().st_size, 'sha256': sha(file)})
        public(RUN / 'source-transfer.public.json', {'source': commit, 'tree': tree, 'files': len(transfer_files),
               'original_bytes': len(transfer), 'original_sha256': sha_bytes(transfer),
               'compressed_bytes': len(compressed), 'compressed_sha256': sha_bytes(compressed),
               'chunks': chunks, 'frozen_manifest_sha256': sha(ROOT / 'frozen-source-r4.public.json')})
        assert git(PRIOR, 'rev-parse', 'HEAD') == PRIOR_HEAD and not git(PRIOR, 'status', '--porcelain=v1', '--untracked-files=all')
        phase('source_frozen', source=commit, tree=tree, files=len(paths), critical_tests=len(critical_tests))
        result.update(source=commit, tree=tree)
        result['strict_clippy'] = owned('strict_clippy', [TOOLCHAIN + '/cargo', 'clippy', '--release', '--locked', '--offline', '--workspace', '--all-targets', '--exclude', 'qrcode', '--', '-D', 'warnings'])

        public(RUN / 'clippy-qualified-source.public.json', {
            'source': commit, 'tree': tree, 'frozen_manifest_sha256': sha(ROOT / 'frozen-source-r4.public.json'),
            'strict_clippy': result['strict_clippy'], 'normal_profile': PROFILE,
            'production_linked': False, 'workspace_tests_passed': False, 'qualified_full_replacement': False})
        phase('strict_clippy_qualified_source_ready', source=commit, tree=tree)
        result['production_build'] = owned('production_build', [TOOLCHAIN + '/cargo', 'build', '--release', '--locked', '--offline', '-p', 'heptabao-server', '--bin', 'heptabao-server', '--bin', 'heptabao-seed', '--message-format=json-render-diagnostics'])
        production = artifacts('production_build')
        result['production_artifacts'] = []
        for name in ('heptabao-server', 'heptabao-seed'):
            actual = [row for row in production if row.get('target', {}).get('name') == name and row.get('executable')]
            assert len(actual) == 1
            row = actual[0]
            assert row['features'] == ['default', 'native-v6-ha', 'native-v6-storage']
            assert row['profile']['opt_level'] == '3' and row['profile']['debuginfo'] == 0
            assert row['profile']['debug_assertions'] and row['profile']['overflow_checks'] and not row['profile']['test']
            public(RUN / (name + '-cargo-artifact.public.json'), row)
            result['production_artifacts'].append(retain(row['executable'], 'retained-' + name))
        result['workspace_compile'] = owned('workspace_compile', [TOOLCHAIN + '/cargo', 'test', '--release', '--locked', '--offline', '--workspace', '--all-targets', '--no-fail-fast', '--no-run', '--message-format=json-render-diagnostics'])
        tests = artifacts('workspace_compile')
        result['test_artifacts'] = []
        for name in ('heptabao_server', 'heptabao_ha_service'):
            actual = [row for row in tests if row.get('target', {}).get('name') == name and row.get('profile', {}).get('test') and row.get('executable')]
            assert len(actual) == 1
            row = actual[0]
            assert row['profile'] == {'opt_level': '3', 'debuginfo': 0, 'debug_assertions': True, 'overflow_checks': True, 'test': True}
            if name == 'heptabao_server':
                assert row['features'] == ['default', 'native-v6-ha', 'native-v6-storage']
            else:
                assert 'native-v6-peer-ingress' in row['features']
            assert Path(row['target']['src_path']).is_relative_to(SOURCE)
            public(RUN / (name + '-cargo-artifact.public.json'), row)
            result['test_artifacts'].append(retain(row['executable'], 'retained-' + name + '-libtest'))
        assert git(SOURCE, 'rev-parse', 'HEAD') == commit and git(SOURCE, 'rev-parse', 'HEAD^{tree}') == tree
        assert not git(SOURCE, 'status', '--porcelain=v1', '--untracked-files=all')
        result['status'] = 'normal_builds_passed_awaiting_full_workspace_tests'
        result['source_unchanged'] = True
        phase('ready_for_full_workspace_tests', source=commit, tree=tree)
    except Exception as error:
        result['failure_class'] = type(error).__name__
        phase('build_stopped', failure_class=type(error).__name__)
        raise
    finally:
        public(RUN / 'result.public.json', result)


if __name__ == '__main__':
    main()
