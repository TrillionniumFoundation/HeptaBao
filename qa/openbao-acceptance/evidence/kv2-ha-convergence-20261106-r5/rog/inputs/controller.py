#!/usr/bin/env python3
"""Isolated ROG product diagnosis. Legacy preservation and machine acceptance stay HOLD."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time

os.umask(0o077)
ROOT = Path('/home/qian-qi/heptabao-kv2-ha-convergence-20261106-r1')
SOURCE = ROOT / 'source-4bde9-diagnostic-r11'
OUT = ROOT / 'build-test-4bde9-diagnostic-r11'
COMMIT = '4bde9aee03fcd27c59e13607e529b1cee594b249'
TREE = 'f08493a23f8ea0637073651231865ea9607b790e'
PARENT = '09c14eae7a3b52dee8ce3af3175dad5900ac59ec'
OLD_HEAD = '4bde9aee03fcd27c59e13607e529b1cee594b249'
FORMAT_PATCH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
BUNDLE_SHA = '9808cfef28ce90733b636e81aed122aeeaf4fe81e0f34b1b84dde7e0ab0e11cd'
TOOLCHAIN = Path('/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin')
PINS = {
    'cargo': 'ff3022fcbd13b08434ea7afde9a0ef9d5b3f5c17b5fc7a40031be3ee000a6a24',
    'rustc': '3690cc576ede140504698405d5d8fa3826aaadbe71699c6c4ed0a565d6f493e2',
    'rustfmt': '5005cdcd39ded526dca8fa6ccd716d42fc7da54469034e055dbf54649bec7877',
}
TARGET = ROOT / 'target-4bde9-diagnostic-r11'
PREP_RECEIPT = ROOT / 'control/source-4bde9-diagnostic-r11-prep/result.public.json'
CARGO_HOME = Path('/home/qian-qi/heptabao-native-20261029-c1bd-r1/cargo-home')
EXACT_ABSENT = frozenset(('heptabao-seed', 'heptabao-server', 'server_libtest'))
EXPECTED_OLD_PINS_SHA256 = '1c21715a8157542e5205dfea92437f172a86619120de8d34769f0075a4ba5b73'
DIAGNOSTIC_SUCCESS = 'diagnostic_passed_legacy_hold'
START = time.monotonic()
DEADLINE = START + 12000
MANIFEST = json.loads((OUT / 'test-selection.public.json').read_text())
ENV = {key: os.environ[key] for key in ('HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'TMPDIR', 'TZ')
       if key in os.environ}
ENV.update(MANIFEST['diagnostic_build_environment'])
ENV.update(RUSTC=str(TOOLCHAIN / 'rustc'), RUSTFMT=str(TOOLCHAIN / 'rustfmt'),
           RUSTC_WRAPPER='', RUSTC_WORKSPACE_WRAPPER='',
           CARGO_BUILD_RUSTC_WRAPPER='', CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER='')
REPORT = {
    'schema': 'heptabao.convergence-normal-diagnostic-build-tests.v1',
    'status': 'running', 'source_commit': COMMIT, 'source_tree': TREE,
    'source_parent': PARENT, 'created_at_unix': time.time(),
    'outer_budget_seconds': 12000, 'deadline_renewed': False,
    'toolchain_pins': PINS, 'build_environment_overrides': MANIFEST['diagnostic_build_environment'],
    'expected_denominators': MANIFEST['denominators'],
    'steps': [], 'artifacts': {}, 'groups': [], 'enumeration': {},
    'production_changed': False, 'production_server_started': False,
    'formal_kv2_qualified': False, 'physical_ha_qualified': False,
    'authbus_migration_qualified': False, 'full_replacement_qualified': False,
    'automatic_retry': False, 'failure': None,
    'legacy_preservation': False, 'machine_acceptance': 'HOLD',
    'rollback_qualified': False, 'dr_qualified': False, 'cutover_qualified': False,
    'production_cutover_qualified': False, 'machine_qualified_cases': 0,
    'original_r10_preservation_failure_remains': True,
    'compilation_performance_comparison_qualified': False,
    'cold_target_changes_cache_state': True,
    'expected_legacy_artifacts': MANIFEST['old_retained_artifacts'],
    'expected_legacy_absent_names': sorted(EXACT_ABSENT),
    'ambient_build_overrides_inherited': False,
    'explicit_compiler': str(TOOLCHAIN / 'rustc'), 'compiler_wrappers_disabled': True,
}


class Failed(RuntimeError):
    pass


class Interrupted(BaseException):
    pass


def interrupted(signum, _frame):
    raise Interrupted(signum)


signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)


def process_group(pgid):
    rows = []
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
            if int(fields[2]) == pgid and int(fields[3]) == pgid:
                rows.append({'pid': int(path.name), 'state': fields[0],
                             'pgrp': int(fields[2]), 'session': int(fields[3]),
                             'start_ticks': int(fields[19])})
        except (OSError, ValueError, IndexError):
            continue
    return rows


def clean_owned_group(proc, leader_start, abnormal):
    before = process_group(proc.pid)
    for row in before:
        need(row['start_ticks'] >= leader_start, 'owned_group_identity_conflict')
        if row['pid'] == proc.pid:
            need(row['start_ticks'] == leader_start, 'owned_group_leader_reused')
    actions = []
    for sig, cap in ((signal.SIGTERM, 2), (signal.SIGKILL, 2)):
        rows = process_group(proc.pid)
        if not rows:
            break
        if any(row['state'] != 'Z' for row in rows):
            try:
                os.killpg(proc.pid, sig); actions.append(signal.Signals(sig).name)
            except ProcessLookupError:
                pass
        until = time.monotonic() + cap
        while time.monotonic() < until:
            proc.poll()
            if not process_group(proc.pid):
                break
            time.sleep(0.05)
    if proc.poll() is None:
        proc.wait(timeout=1)
    after = process_group(proc.pid)
    return {'pgid': proc.pid, 'leader_start_ticks': leader_start,
            'abnormal_exit': abnormal, 'remaining_before_cleanup': before,
            'signals': actions, 'remaining_after_cleanup': after,
            'all_owned_processes_gone': not after}


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def need(value, label):
    if not value:
        raise Failed(label)


def publish(path, value):
    temp = path.with_suffix(path.suffix + '.tmp')
    with temp.open('w') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    os.replace(temp, path)


def checkpoint():
    REPORT['elapsed_seconds'] = round(time.monotonic() - START, 3)
    publish(OUT / 'progress.public.json', REPORT)


def run_step(label, argv, seconds, *, end=None, allowed=(0,)):
    remaining = min(DEADLINE - 30, end if end is not None else DEADLINE) - time.monotonic()
    budget = min(seconds, remaining)
    need(budget > 0, label + '_original_deadline_expired')
    stdout = OUT / (label + '.stdout')
    stderr = OUT / (label + '.stderr')
    row = {'step': label, 'argv': argv, 'requested_cap_seconds': seconds,
           'effective_budget_seconds': round(budget, 6), 'attempts': 1,
           'timed_out': False, 'started_at_unix': time.time()}
    print(json.dumps({'event': 'step_started', 'step': label, 'budget_seconds': round(budget, 3)}), flush=True)
    began = time.monotonic()
    proc = None
    leader_start = None
    with stdout.open('xb') as so, stderr.open('xb') as se:
        try:
            proc = subprocess.Popen(argv, cwd=SOURCE, env=ENV, stdin=subprocess.DEVNULL,
                                    stdout=so, stderr=se, start_new_session=True)
            row['pid'] = proc.pid
            leader = [p for p in process_group(proc.pid) if p['pid'] == proc.pid]
            need(len(leader) == 1, 'owned_leader_identity_unavailable')
            leader_start = leader[0]['start_ticks']
            row['exit_code'] = proc.wait(timeout=budget)
        except subprocess.TimeoutExpired:
            row['timed_out'] = True
        except BaseException as error:
            row['exception_type'] = type(error).__name__
        finally:
            if proc is not None:
                try:
                    need(leader_start is not None, 'owned_leader_identity_missing')
                    cleanup = clean_owned_group(proc, leader_start,
                                                row['timed_out'] or 'exception_type' in row)
                    row['owned_group_cleanup'] = cleanup
                    row['unexpected_live_descendants_on_success'] = (
                        row.get('exit_code') == 0
                        and any(p['state'] != 'Z' for p in cleanup['remaining_before_cleanup']))
                except BaseException as error:
                    row['owned_group_cleanup'] = {'all_owned_processes_gone': False,
                                                  'cleanup_error_type': type(error).__name__}
                row['exit_code'] = proc.returncode
            else:
                row['exit_code'] = None
                row['owned_group_cleanup'] = {'all_owned_processes_gone': True, 'child_started': False}
            so.flush(); se.flush(); os.fsync(so.fileno()); os.fsync(se.fileno())
    row.update(seconds=round(time.monotonic() - began, 6),
               stdout_bytes=stdout.stat().st_size, stderr_bytes=stderr.stat().st_size,
               stdout_sha256=digest(stdout), stderr_sha256=digest(stderr))
    REPORT['steps'].append(row)
    publish(OUT / (label + '.public.json'), row)
    checkpoint()
    print(json.dumps({'event': 'step_finished', 'step': label, 'exit_code': row['exit_code'],
                      'timed_out': row['timed_out'], 'seconds': row['seconds']}), flush=True)
    need(not row['timed_out'] and 'exception_type' not in row and row['exit_code'] in allowed
         and row['owned_group_cleanup']['all_owned_processes_gone']
         and not row.get('unexpected_live_descendants_on_success'), label + '_failed')
    return stdout


def git(label, args, cap=30):
    return run_step(label, ['/usr/bin/git', *args], cap).read_text().strip()


def resources():
    mem = dict((line.split(':')[0], int(line.split()[1]))
               for line in Path('/proc/meminfo').read_text().splitlines()
               if line.startswith(('MemAvailable:', 'SwapFree:')))
    compilers = []
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            name = (path / 'comm').read_text().strip()
        except OSError:
            continue
        if name in {'cargo', 'rustc', 'rustfmt', 'rust-lld'}:
            compilers.append({'pid': int(path.name), 'comm': name})
    return {'disk_free_bytes': shutil.disk_usage(ROOT).free,
            'mem_available_kib': mem['MemAvailable'], 'swap_free_kib': mem['SwapFree'],
            'load_average': list(os.getloadavg()), 'compiler_processes': compilers}


def retain_artifact(json_path, label, target_name, test):
    found = []
    for line in json_path.read_text().splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (item.get('reason') == 'compiler-artifact'
            and item.get('target', {}).get('name') == target_name
            and item.get('profile', {}).get('test') is test and item.get('executable')):
            found.append(item)
    need(len(found) == 1, label + '_unambiguous_cargo_artifact')
    item = found[0]; source = Path(item['executable'])
    package = 'heptabao-ha-service' if target_name == 'heptabao_ha_service' else 'heptabao-server'
    expected_features = (['default', 'native-v6-peer-ingress'] if package == 'heptabao-ha-service'
                         else ['default', 'native-v6-ha', 'native-v6-storage'])
    need(sorted(item.get('features', [])) == sorted(expected_features), label + '_normal_features')
    expected_profile = {'opt_level': '3', 'debuginfo': 0, 'debug_assertions': True,
                        'overflow_checks': True, 'test': test}
    need(all(item.get('profile', {}).get(k) == v for k, v in expected_profile.items()),
         label + '_normal_profile')
    expected_entry = ('src/lib.rs' if test else
                      'src/bin/heptabao-seed.rs' if target_name == 'heptabao-seed' else 'src/main.rs')
    package_root = SOURCE / 'crates' / package
    need(Path(item.get('target', {}).get('src_path', '')).resolve() == package_root / expected_entry,
         label + '_source_entry')
    need(item.get('package_id', '').startswith('path+file://' + str(package_root) + '#'),
         label + '_source_package')
    target = OUT / 'artifacts' / label
    need(source.is_file() and not source.is_symlink(), label + '_regular_file')
    before = digest(source)
    with source.open('rb') as src, target.open('xb') as dst:
        shutil.copyfileobj(src, dst, 1024 * 1024)
        dst.flush(); os.fsync(dst.fileno())
    target.chmod(0o700)
    need(before == digest(target) == digest(source), label + '_copy_hash')
    REPORT['artifacts'][label] = {
        'path': str(target), 'sha256': before, 'bytes': target.stat().st_size,
        'source_commit': COMMIT, 'source_tree': TREE,
        'cargo_features': item.get('features'), 'cargo_profile': item.get('profile'),
        'cargo_fresh': item.get('fresh'), 'cargo_artifact_path': str(source),
        'cargo_source_entry': item['target']['src_path'], 'cargo_package_id': item['package_id'],
        'normal_features_profile_and_source_verified': True,
    }
    checkpoint()
    return target


def listed(label, binary):
    path = run_step(label + '-list', [str(binary), '--list'], 30)
    rows = [line[:-6] for line in path.read_text().splitlines() if line.endswith(': test')]
    need(rows and len(rows) == len(set(rows)), label + '_listing_unique_nonzero')
    return set(rows)


def test_summary(path, expected):
    matches = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', path.read_text())
    need(len(matches) == 1, 'single_libtest_result_required')
    state, passed, failed, ignored, measured, filtered = matches[0]
    result = {'passed': int(passed), 'failed': int(failed), 'ignored': int(ignored),
              'measured': int(measured), 'filtered_out': int(filtered)}
    result['exact_denominator_passed'] = (state == 'ok' and result['passed'] == expected
        and result['failed'] == 0 and result['ignored'] == 0 and result['measured'] == 0)
    result['reported_state'] = state
    return result


def execute_group(index, group, binary):
    started = time.monotonic()
    end = min(DEADLINE, started + group['runtime_seconds'])
    row = {'label': group['label'], 'crate': group['crate'], 'expected_count': group['expected_count'],
           'original_group_budget_seconds': group['runtime_seconds'], 'budget_renewed_per_case': False,
           'tests': group['tests'], 'passed': 0, 'results': [], 'status': 'running'}
    REPORT['groups'].append(row); checkpoint()
    suffixes = group.get('argv_suffixes', [group.get('argv_suffix')])
    for n, suffix in enumerate(suffixes):
        need(suffix is not None, 'test_argv_missing')
        expected = 1 if len(suffixes) > 1 or group.get('selection_mode') == 'per-test-exact' else group['expected_count']
        path = run_step(f'test-{index:02d}-{group["label"]}-{n:02d}', [str(binary), *suffix],
                        group['runtime_seconds'], end=end, allowed=(0, 101))
        result = test_summary(path, expected)
        row['results'].append(result); checkpoint()
        need(result['exact_denominator_passed'] and REPORT['steps'][-1]['exit_code'] == 0,
             group['label'] + '_exact_test_result_failed')
        row['passed'] += result['passed']; checkpoint()
    need(row['passed'] == row['expected_count'], group['label'] + '_count')
    row['status'] = 'passed'; row['seconds'] = round(time.monotonic() - started, 6); checkpoint()



def owned_directory(path, label):
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
         and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
         label + '_owned_private_directory_required')
    return {'path': str(path), 'device': info.st_dev, 'inode': info.st_ino,
            'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode)}


def diagnostic_directories():
    return {name: owned_directory(path, name) for name, path in (
        ('root', ROOT), ('source', SOURCE), ('cargo_home', CARGO_HOME), ('target', TARGET))}


def diagnostic_layout():
    need(MANIFEST.get('schema') == 'heptabao.normal-rust-diagnostic-selection.v1',
         'diagnostic_selection_schema_required')
    binding = MANIFEST.get('fresh_diagnostic_source', {})
    expected_sha = binding.get('preparation_result_sha256')
    need(isinstance(expected_sha, str) and re.fullmatch('[0-9a-f]{64}', expected_sha)
         and binding.get('source_preparation_executed') is True,
         'completed_diagnostic_preparation_binding_required')
    raw = PREP_RECEIPT.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == expected_sha
         and len(raw) == binding.get('preparation_result_bytes')
         and binding.get('preparation_result_path') == str(PREP_RECEIPT),
         'diagnostic_preparation_receipt_changed')
    prepared = json.loads(raw)
    need(prepared.get('schema') == 'heptabao.fresh-diagnostic-source-preparation.v1'
         and prepared.get('status') == 'prepared_diagnostic_legacy_hold'
         and prepared.get('source_commit') == COMMIT and prepared.get('source_tree') == TREE
         and prepared.get('new_source') == str(SOURCE)
         and prepared.get('new_source_clean') is True
         and prepared.get('old_source_preserved') is True
         and prepared.get('new_cold_target_created_empty') is True
         and prepared.get('legacy_preservation') is False
         and prepared.get('machine_acceptance') == 'HOLD',
         'diagnostic_preparation_scope_or_identity')
    expected_env = dict(MANIFEST['original_build']['env'])
    expected_env['CARGO_TARGET_DIR'] = str(TARGET)
    need(MANIFEST['diagnostic_build_environment'] == expected_env
         and ENV['CARGO_TARGET_DIR'] == str(TARGET) and ENV['CARGO_HOME'] == str(CARGO_HOME),
         'diagnostic_only_target_environment_change')
    current = diagnostic_directories()
    REPORT['diagnostic_directories_before'] = current
    need(current == prepared.get('directories_after'), 'diagnostic_directory_identity_changed')
    need(not any(TARGET.iterdir()), 'diagnostic_cold_target_no_longer_empty')
    REPORT['diagnostic_preparation'] = {
        'path': str(PREP_RECEIPT), 'bytes': len(raw), 'sha256': expected_sha,
        'new_cold_target_created_empty': True, 'source_commit': COMMIT, 'source_tree': TREE}
    return TARGET


def diagnostic_legacy_condition(observed):
    expected = MANIFEST['old_retained_artifacts']
    expected_sha = hashlib.sha256(json.dumps(expected, sort_keys=True,
                                            separators=(',', ':')).encode()).hexdigest()
    pin_set_matches = (len(expected) == 21 and EXACT_ABSENT.issubset(expected)
                       and expected_sha == EXPECTED_OLD_PINS_SHA256)
    matching, absent, unexpected = [], [], []
    for name, pin in expected.items():
        actual = observed.get(name, {})
        if name in EXACT_ABSENT:
            accepted = (actual.get('path') == pin['path']
                        and actual.get('matches_original') is False
                        and actual.get('error_type') == 'FileNotFoundError'
                        and 'sha256' not in actual and 'bytes' not in actual)
            (absent if accepted else unexpected).append(name)
        else:
            accepted = (actual.get('path') == pin['path']
                        and actual.get('matches_original') is True
                        and actual.get('sha256') == pin['sha256']
                        and actual.get('bytes') == pin['bytes'] and 'error_type' not in actual)
            (matching if accepted else unexpected).append(name)
    exact = (pin_set_matches and set(observed) == set(expected)
             and set(absent) == EXACT_ABSENT and len(matching) == 18 and not unexpected)
    return {'diagnostic_condition_met': exact, 'expected_pin_set_unchanged': pin_set_matches,
            'expected_legacy_count': 21, 'expected_absent_names': sorted(EXACT_ABSENT),
            'observed_absent_names': sorted(absent), 'retained_matching_names': sorted(matching),
            'retained_matching_count': len(matching), 'unexpected_names': sorted(unexpected),
            'legacy_preservation': False, 'machine_acceptance': 'HOLD',
            'original_all_21_preservation_gate_passed': (len(observed) == 21
                and all(value.get('matches_original') is True for value in observed.values()))}


def main():
    need(MANIFEST['execution_source_commit'] == COMMIT, 'selection_source_binding')
    groups = MANIFEST['legacy_groups'] + MANIFEST['legacy_additional_groups'] + MANIFEST['added_groups']
    names = [name for group in groups for name in group['tests']]
    need(len(names) == len(set(names)) == 107, '107_unique_selected_names')
    need(sum(len(g['tests']) for g in groups if g['crate'] == 'heptabao-server') == 90, 'server90')
    for name, sha in PINS.items():
        need(digest(TOOLCHAIN / name) == sha, 'toolchain_pin_' + name)
    REPORT['old_retained_artifacts_before'] = old_artifacts()
    REPORT['diagnostic_legacy_before'] = diagnostic_legacy_condition(REPORT['old_retained_artifacts_before'])
    need(REPORT['diagnostic_legacy_before']['diagnostic_condition_met'],
         'diagnostic_exact_3_absent_18_matching_preflight_required')
    REPORT['preflight'] = resources(); checkpoint()
    need(not REPORT['preflight']['compiler_processes'], 'other_compiler_present')
    need(REPORT['preflight']['disk_free_bytes'] >= 8 * 1024**3, 'build_disk_headroom')
    need(REPORT['preflight']['mem_available_kib'] >= 12 * 1024**2, 'build_ram_headroom')
    need(git('00-source-head', ['rev-parse', 'HEAD']) == OLD_HEAD, 'staged_original_head')
    patch = run_step('01-preserved-format-diff', ['/usr/bin/git', 'diff', '--binary', 'HEAD'], 30)
    need(digest(patch) == FORMAT_PATCH, 'exact_original_format_patch')
    need(not git('02-untracked', ['ls-files', '--others', '--exclude-standard']), 'untracked_source')
    need(digest(OUT / 'candidate.bundle') == BUNDLE_SHA, 'canonical_bundle_hash')
    git('03-bundle-verify', ['bundle', 'verify', str(OUT / 'candidate.bundle')])
    git('04-fetch', ['fetch', str(OUT / 'candidate.bundle'), 'HEAD'])
    need(git('05-canonical-tree', ['rev-parse', COMMIT + '^{tree}']) == TREE, 'canonical_tree')
    need(git('06-canonical-parent', ['rev-parse', COMMIT + '^']) == PARENT, 'canonical_parent')
    git('07-stage-exact-format', ['add', '--update'])
    need(git('08-format-working-tree', ['write-tree']) == TREE, 'format_working_tree_matches_canonical')
    git('09-checkout-canonical', ['checkout', '--detach', COMMIT])
    need(not git('10-clean-source', ['status', '--porcelain']), 'source_dirty_before_build')
    git('11-fsck', ['fsck', '--full', '--strict'], 60)
    run_step('12-format-check', [str(TOOLCHAIN / 'cargo'), 'fmt', '--all', '--', '--check'], 60)
    (OUT / 'artifacts').mkdir(mode=0o700)
    build = run_step('13-normal-release-build', MANIFEST['build_examples']['server_release'], 1800)
    retain_artifact(build, 'heptabao-server', 'heptabao-server', False)
    retain_artifact(build, 'heptabao-seed', 'heptabao-seed', False)
    test_build = run_step('14-server-libtest-build', MANIFEST['build_examples']['server_libtest'], 3600)
    server_tests = retain_artifact(test_build, 'heptabao-server-libtest', 'heptabao_server', True)
    peer_build = run_step('15-peer-libtest-build', MANIFEST['build_examples']['peer_libtest'], 3600)
    peer_tests = retain_artifact(peer_build, 'heptabao-ha-service-libtest', 'heptabao_ha_service', True)
    binaries = {'heptabao-server': server_tests, 'heptabao-ha-service': peer_tests}
    all_names = {crate: listed(crate, binary) for crate, binary in binaries.items()}
    for group in groups:
        expected = set(group['tests']); available = all_names[group['crate']]
        if group.get('selection_mode') == 'per-test-exact':
            selected = available.intersection(expected)
        elif group['exact']:
            selected = {name for name in available if name == group['filter']}
        else:
            selected = {name for name in available if group['filter'] in name}
        need(selected == expected and len(selected) == group['expected_count'], group['label'] + '_enumeration_mismatch')
        REPORT['enumeration'][group['label']] = {'matched_names': sorted(selected), 'matched_count': len(selected)}
    checkpoint()
    for index, group in enumerate(groups):
        execute_group(index, group, binaries[group['crate']])
    need(sum(g['passed'] for g in REPORT['groups']) == 107, 'final107')
    need(git('99-final-source-head', ['rev-parse', 'HEAD']) == COMMIT, 'source_head_changed')
    need(not git('99-final-source-clean', ['status', '--porcelain']), 'source_dirty_after_execution')
    for artifact in REPORT['artifacts'].values():
        need(digest(artifact['path']) == artifact['sha256'], 'retained_artifact_changed')
    REPORT['source_and_artifacts_unchanged'] = True
    REPORT['passed_cases'] = 107
    need(time.monotonic() < DEADLINE, 'original_outer_deadline_expired')
    REPORT['status'] = DIAGNOSTIC_SUCCESS


def old_artifacts():
    result = {}
    for name, artifact in MANIFEST['old_retained_artifacts'].items():
        path = Path(artifact['path'])
        try:
            sha = digest(path); size = path.stat().st_size
            result[name] = {'path': str(path), 'sha256': sha, 'bytes': size,
                            'matches_original': sha == artifact['sha256'] and size == artifact['bytes']}
        except OSError as error:
            result[name] = {'path': str(path), 'matches_original': False,
                            'error_type': type(error).__name__}
    return result


if __name__ == '__main__':
    lock = None
    try:
        target = diagnostic_layout()
        lock = (target / '.heptabao-convergence-exclusive.lock').open('x')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        REPORT['selection_sha256'] = digest(OUT / 'test-selection.public.json')
        REPORT['controller_sha256'] = digest(__file__)
        main()
    except BaseException as error:
        REPORT['status'] = 'failed'
        REPORT['failure'] = str(error) if isinstance(error, Failed) else type(error).__name__
        if REPORT['groups'] and REPORT['groups'][-1]['status'] == 'running':
            REPORT['groups'][-1]['status'] = 'failed'
    finally:
        REPORT['old_retained_artifacts_after'] = old_artifacts()
        REPORT['diagnostic_legacy_after'] = diagnostic_legacy_condition(REPORT['old_retained_artifacts_after'])
        if (not REPORT['diagnostic_legacy_after']['diagnostic_condition_met']
            or REPORT.get('old_retained_artifacts_before') != REPORT['old_retained_artifacts_after']):
            REPORT['status'] = 'failed'; REPORT['failure'] = REPORT['failure'] or 'diagnostic_legacy_condition_changed'
        try:
            REPORT['diagnostic_directories_after'] = diagnostic_directories()
            need(REPORT['diagnostic_directories_after'] == REPORT.get('diagnostic_directories_before'),
                 'diagnostic_directory_identity_changed_after')
        except BaseException as error:
            REPORT['status'] = 'failed'
            REPORT['failure'] = REPORT['failure'] or (str(error) if isinstance(error, Failed) else type(error).__name__)
        if time.monotonic() >= DEADLINE:
            REPORT['status'] = 'failed'; REPORT['failure'] = REPORT['failure'] or 'original_outer_deadline_expired'
        REPORT['elapsed_seconds'] = round(time.monotonic() - START, 6)
        REPORT['finished_at_unix'] = time.time()
        REPORT['postflight'] = resources()
        REPORT['executed_passed_cases'] = sum(g['passed'] for g in REPORT['groups'])
        REPORT['not_qualified_cases'] = 107 - REPORT['executed_passed_cases']
        publish(OUT / 'result.public.json', REPORT)
        checkpoint()
        print(json.dumps({'event': 'terminal', 'status': REPORT['status'], 'failure': REPORT['failure'],
                          'executed_passed_cases': REPORT['executed_passed_cases'],
                          'result': str(OUT / 'result.public.json')}), flush=True)
        if lock is not None:
            lock.close()
    sys.exit(0 if REPORT['status'] == DIAGNOSTIC_SUCCESS else 1)
