#!/usr/bin/env python3
"""Run the complete unchanged normal workspace after build and scheduling handoff."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

ROOT = Path('/home/qian-qi/heptabao-bao-acceptance-unified-61ff-20261104-r1')
SOURCE = ROOT / 'source'
RUN = ROOT / 'normal-workspace'
BUILD = json.loads((ROOT / 'normal-build-r6/result.public.json').read_text())
FROZEN = json.loads((ROOT / 'frozen-source-r6.public.json').read_text())
INPUT = json.loads((ROOT / 'input-manifest.public.json').read_text())
BOUND = json.loads((ROOT / 'overall-bound.public.json').read_text())


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def git(*args):
    return subprocess.check_output(['git', '-C', str(SOURCE), *args], text=True, timeout=30).strip()


def write(name, value):
    with (RUN / name).open('x') as f:
        json.dump(value, f, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())


def unchanged():
    assert git('rev-parse', 'HEAD') == FROZEN['source']
    assert git('rev-parse', 'HEAD^{tree}') == FROZEN['tree']
    assert not git('status', '--porcelain=v1', '--untracked-files=all')
    for artifact in BUILD['production_artifacts'] + BUILD['test_artifacts']:
        assert sha(artifact['path']) == artifact['sha256']
        assert sha(artifact['original_path']) == artifact['sha256']


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
    assert BUILD['status'] == 'normal_builds_passed_awaiting_full_workspace_tests'
    assert FROZEN['source'] == BUILD['source'] and FROZEN['tree'] == BUILD['tree']
    assert Path('/proc/sys/kernel/random/boot_id').read_text().strip() == BOUND['boot_id']
    cap = BOUND['monotonic_expires'] - time.monotonic()
    assert cap > 0, 'original combined build/test envelope elapsed; no automatic budget renewal'
    assert not RUN.exists(), 'one fresh full-workspace test owner required'
    unchanged()
    timed_admission = exclusive_timed_test_admission()
    RUN.mkdir(mode=0o700)
    args = [BUILD['profile']['PATH'].split(':')[0] + '/cargo', 'test', '--release', '--locked', '--offline',
            '--workspace', '--all-targets', '--no-fail-fast', '--', '--test-threads=1']
    intent = {'source': FROZEN['source'], 'tree': FROZEN['tree'], 'profile': BUILD['profile'],
              'args': args, 'fixture_budgets_changed': False, 'fixture_features': [],
              'original_overall_remaining_seconds': cap, 'exclusive_timed_test_admission': timed_admission, 'critical_tests': FROZEN['critical_tests']}
    write('intent.public.json', intent)
    print(json.dumps({'phase': 'full_workspace_tests_start', 'source': FROZEN['source'], 'tree': FROZEN['tree']}), flush=True)
    environment = dict(os.environ)
    environment.update(BUILD['profile'])
    began = time.monotonic()
    timed_out = False
    result = {**intent, 'status': 'failed', 'qualified_full_replacement': False,
              'known_remaining_product_gaps': FROZEN['known_remaining_product_gaps']}
    try:
        with (RUN / 'workspace.stdout').open('xb') as out, (RUN / 'workspace.stderr').open('xb') as err:
            assert time.monotonic() < BOUND['monotonic_expires'], 'original envelope elapsed before test launch'
            child = subprocess.Popen(args, cwd=SOURCE, env=environment, stdout=out, stderr=err, start_new_session=True)
            try:
                code = child.wait(timeout=max(0.0, BOUND['monotonic_expires'] - time.monotonic()))
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
        stdout = (RUN / 'workspace.stdout').read_text()
        passed = re.findall(r'^test ([^ ]+) \.\.\. ok$', stdout, re.M)
        ignored = re.findall(r'^test ([^ ]+) \.\.\. ignored', stdout, re.M)
        failed = re.findall(r'^test ([^ ]+) \.\.\. FAILED$', stdout, re.M)
        groups = [dict(zip(('passed', 'failed', 'ignored', 'measured', 'filtered'), map(int, row)))
                  for row in re.findall(r'^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', stdout, re.M)]
        top = [row for row in groups if row['filtered'] == 0]
        critical = []
        for test in FROZEN['critical_tests']:
            count = passed.count(test['name'])
            critical.append({**test, 'actual_pass_count': count, 'ignored': test['name'] in ignored})
        result.update(exit_code=code, timed_out=timed_out, elapsed_seconds=time.monotonic()-began,
                      owned_pgid=child.pid, remaining=remaining, failed_tests=failed,
                      ignored_tests=ignored, critical_results=critical,
                      top_level_summary_groups=len(top),
                      top_level_summary_totals={key:sum(row[key] for row in top) for key in ('passed','failed','ignored','measured','filtered')},
                      nested_filtered_summaries=[row for row in groups if row['filtered']],
                      stdout_sha256=sha(RUN/'workspace.stdout'), stderr_sha256=sha(RUN/'workspace.stderr'))
        unchanged()
        result['source_and_retained_binaries_unchanged'] = True
        assert code == 0 and not timed_out and not remaining and not failed, 'full workspace returned a real failure'
        assert set(ignored) == set(INPUT['ignored_baseline_names']), 'explicit ignored baseline changed'
        assert all(row['actual_pass_count'] == 1 and not row['ignored'] for row in critical), 'a required critical test did not run exactly once'
        assert top and all(row['failed'] == 0 for row in top)
        result['status'] = 'full_normal_workspace_passed'
    except Exception as error:
        result['failure_class'] = type(error).__name__
        raise
    finally:
        write('result.public.json', result)
        print(json.dumps({'phase': 'full_workspace_tests_complete', 'status': result['status'],
                          'qualified_full_replacement': False}), flush=True)


if __name__ == '__main__':
    main()
