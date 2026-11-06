#!/usr/bin/env python3
"""One owned native Mac source/build/test attempt. No production service operations."""
import fcntl
import hashlib
import json
import os
import plistlib
import stat
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

os.umask(0o077)
ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
SOURCE = ROOT / 'source-2b38-r2'
OLD_SOURCE = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261105-same-root-publication-normal-r2/source')
OUT = ROOT / 'build-test-2b38-r2'
COMMIT = '2b38f091c2903eac74b4ed9dc32b1f1f00fd8a8a'
TREE = 'e2da9354cf482a8d3ebd67898812e2fcb026832a'
PARENT = '1d63ec98ce0fc5cbc7d74a37f6307be148dd5aeb'
OLD_HEAD = '4e808d0ecb1bcded22870a7ec960dfb2491cf6ec'
OLD_TREE = 'eba5e650bd080b8ad41ea52a2bc68867f541d255'
BUNDLE_SHA = '03ceec075c48d7210d22994e7cd6efbbcb9f58219dbabf4776efebe8b270752d'
BUNDLE = ROOT / 'control/candidate-2b38-from-4e808.bundle'
SELECTION_SHA = '666116a237a02165a06db787e8e5aedd9407064cfba99c3a5c8a0bdc520ee785'
PYTHON_SHA = 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'
TOOLCHAIN = Path('/Users/qianqi/.rustup/toolchains/1.98.0-aarch64-apple-darwin/bin')
PINS = {
    'cargo': '1de2e84c15443b70444eecfa959ff9099dd8c1a5606b6d9ef5bc0ea9c25bc7f9',
    'rustc': 'a11618eca0956a8aa4372c2bc898690b513cbdfa2cb9125b2a5301e360ed5b49',
    'rustfmt': 'ca9cbe15a4add6baf62d8ce177015c9c48f209ebcf4364416b1953142e8701f8',
}
START = time.monotonic()
DEADLINE = START + 8280
MANIFEST = json.loads((OUT / 'test-selection.public.json').read_text())
ENV = {key: os.environ[key] for key in ('HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'TMPDIR', 'TZ')
       if key in os.environ}
ENV.update(MANIFEST['original_build']['env'])
ENV.update(RUSTC=str(TOOLCHAIN / 'rustc'), RUSTFMT=str(TOOLCHAIN / 'rustfmt'),
           RUSTC_WRAPPER='', RUSTC_WORKSPACE_WRAPPER='',
           CARGO_BUILD_RUSTC_WRAPPER='', CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER='')
REPORT = {
    'schema': 'heptabao.convergence-normal-build-tests.v1',
    'status': 'running', 'source_commit': COMMIT, 'source_tree': TREE,
    'source_parent': PARENT, 'created_at_unix': time.time(),
    'outer_budget_seconds': 8280, 'deadline_renewed': False,
    'toolchain_pins': PINS, 'build_environment_overrides': MANIFEST['original_build']['env'],
    'expected_denominators': MANIFEST['denominators'],
    'steps': [], 'artifacts': {}, 'groups': [], 'enumeration': {},
    'production_changed': False, 'production_server_started': False,
    'formal_kv2_qualified': False, 'physical_ha_qualified': False,
    'authbus_migration_qualified': False, 'full_replacement_qualified': False,
    'automatic_retry': False, 'failure': None,
    'ambient_build_overrides_inherited': False,
    'host': 'mac', 'native_platform': 'aarch64-apple-darwin',
    'original_mac61_process_method': True, 'linux_proc_used': False,
    'source': str(SOURCE), 'original_source': str(OLD_SOURCE),
    'controller_uses_failed_custody_helper': False,
    'explicit_compiler': str(TOOLCHAIN / 'rustc'), 'compiler_wrappers_disabled': True,
}


class Failed(RuntimeError):
    pass


class Interrupted(BaseException):
    pass


CHILDREN = []
PROTECTED = 0
PENDING = None


def interrupted(signum, _frame):
    global PENDING
    PENDING = signum
    if not PROTECTED:
        raise Interrupted(signum)


signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)


def process_group(pgid):
    raw = subprocess.check_output(['/bin/ps', '-axo', 'pid=,ppid=,pgid=,stat='],
                                  timeout=5, text=True, env=ENV)
    rows = []
    for line in raw.splitlines():
        fields = line.split()
        need(len(fields) == 4 and all(v.isdecimal() for v in fields[:3]), 'darwin_ps_shape')
        if int(fields[2]) == pgid:
            rows.append(dict(pid=int(fields[0]), ppid=int(fields[1]),
                             pgid=int(fields[2]), state=fields[3]))
    return rows


def clean_owned_group(proc):
    # Preserve the established Mac61 ownership rule. Before the original wait
    # reaps a child its PID cannot be reused. Never signal a reaped numeric group.
    actions = []
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGTERM); actions.append('SIGTERM')
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL); actions.append('SIGKILL')
            except ProcessLookupError:
                pass
            proc.wait(timeout=5)
    rows = process_group(proc.pid)
    return dict(pgid=proc.pid, direct_child_reaped=proc.returncode is not None,
                signals=actions, remaining_after_cleanup=rows,
                all_owned_processes_gone=proc.returncode is not None and not rows,
                signals_after_reap=False)


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


def run_step(label, argv, seconds, *, end=None, allowed=(0,), cwd=None):
    global PROTECTED
    remaining = min(DEADLINE - 30, end if end is not None else DEADLINE) - time.monotonic()
    budget = min(seconds, remaining)
    need(budget > 0, label + '_original_deadline_expired')
    until = time.monotonic() + budget
    stdout, stderr = OUT / (label + '.stdout'), OUT / (label + '.stderr')
    row = dict(step=label, argv=argv, requested_cap_seconds=seconds,
               effective_budget_seconds=round(budget, 6), attempts=1, timed_out=False,
               started_at_unix=time.time())
    print(json.dumps(dict(event='step_started', step=label, budget_seconds=round(budget, 3))), flush=True)
    began, proc = time.monotonic(), None
    with stdout.open('xb') as so, stderr.open('xb') as se:
        try:
            PROTECTED += 1
            try:
                proc = subprocess.Popen(argv, cwd=cwd or SOURCE, env=ENV, stdin=subprocess.DEVNULL,
                                        stdout=so, stderr=se, start_new_session=True)
                CHILDREN.append((label, proc))
            finally:
                PROTECTED -= 1
            if PENDING is not None:
                raise Interrupted(PENDING)
            row['pid'] = proc.pid
            row['exit_code'] = proc.wait(timeout=max(0.001, until - time.monotonic()))
        except subprocess.TimeoutExpired:
            row['timed_out'] = True
        except BaseException as error:
            row['exception_type'] = type(error).__name__
        finally:
            if proc is not None:
                try:
                    row['owned_group_cleanup'] = clean_owned_group(proc)
                except BaseException as error:
                    row['owned_group_cleanup'] = dict(all_owned_processes_gone=False,
                                                      cleanup_error_type=type(error).__name__)
                row['exit_code'] = proc.returncode
            else:
                row['exit_code'] = None
                row['owned_group_cleanup'] = dict(all_owned_processes_gone=True, child_started=False)
            so.flush(); se.flush(); os.fsync(so.fileno()); os.fsync(se.fileno())
    if time.monotonic() >= until:
        row['timed_out'] = True
    row.update(seconds=round(time.monotonic() - began, 6), stdout_bytes=stdout.stat().st_size,
               stderr_bytes=stderr.stat().st_size, stdout_sha256=digest(stdout), stderr_sha256=digest(stderr))
    REPORT['steps'].append(row); publish(OUT / (label + '.public.json'), row); checkpoint()
    print(json.dumps(dict(event='step_finished', step=label, exit_code=row['exit_code'],
                          timed_out=row['timed_out'], seconds=row['seconds'])), flush=True)
    need(not row['timed_out'] and 'exception_type' not in row and row['exit_code'] in allowed
         and row['owned_group_cleanup']['all_owned_processes_gone'], label + '_failed')
    return stdout


def git(label, args, cap=30, cwd=None):
    command = ['/usr/bin/git', '--no-optional-locks', '-c', 'core.hooksPath=/dev/null', *args]
    return run_step(label, command, cap, cwd=cwd).read_text().strip()


def freeze(label, path):
    return dict(commit=git(label + '-head', ['rev-parse', 'HEAD'], cwd=path),
                tree=git(label + '-tree', ['rev-parse', 'HEAD^{tree}'], cwd=path),
                status=git(label + '-clean', ['status', '--porcelain=v1', '--untracked-files=all'], cwd=path))


def resources(label):
    raw = run_step(label + '-process-metadata', ['/bin/ps', '-axo', 'pid=,ppid=,pgid=,uid=,comm='], 10, cwd=ROOT).read_text()
    compilers = []
    for line in raw.splitlines():
        fields = line.split(None, 4)
        need(len(fields) == 5 and all(v.isdecimal() for v in fields[:3]), 'process_metadata_shape')
        command = Path(fields[4]).name
        if command in {'cargo', 'rustc', 'rustfmt', 'rust-lld', 'cc', 'clang', 'ld'} or command.startswith('build-script'):
            compilers.append(dict(pid=int(fields[0]), ppid=int(fields[1]), pgid=int(fields[2]), comm=command))
    total = int(run_step(label + '-ram-total', ['/usr/sbin/sysctl', '-n', 'hw.memsize'], 10, cwd=ROOT).read_text().strip())
    pages = run_step(label + '-vm-stat', ['/usr/bin/vm_stat'], 10, cwd=ROOT).read_text()
    matched = re.search(r'page size of (\d+) bytes', pages)
    need(matched is not None, 'vm_page_size')
    page_bytes = int(matched.group(1))
    fields = dict((m.group(1), int(m.group(2))) for m in re.finditer(r'^([^:]+):\s+(\d+)\.', pages, re.M))
    locks = run_step(label + '-cargo-lock', ['/usr/sbin/lsof', '-t', '--', str(Path(ENV['CARGO_TARGET_DIR']) / 'release/.cargo-lock')], 10, cwd=ROOT, allowed=(0, 1)).read_text().strip()
    need(not (OUT / (label + '-cargo-lock.stderr')).read_text().strip(), 'cargo_lock_probe_error')
    return dict(disk_free_bytes=shutil.disk_usage(ROOT).free, internal_disk_free_bytes=shutil.disk_usage('/Users/qianqi').free,
                ram_total_bytes=total, free_pages_bytes=fields.get('Pages free', 0) * page_bytes,
                inactive_pages_bytes=fields.get('Pages inactive', 0) * page_bytes,
                memory_values_are_not_memavailable=True, load_average=list(os.getloadavg()),
                compiler_processes=compilers, cargo_lock_pids=locks.splitlines() if locks else [],
                sample_is_atomic=False, target_st_dev=ROOT.stat().st_dev)


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


def main():
    need(os.uname().sysname == 'Darwin' and os.uname().machine == 'arm64' and os.geteuid() == 501, 'actual_mac_arm64')
    need(ROOT.resolve(strict=True) == ROOT and ROOT.stat().st_uid == 501
         and stat.S_IMODE(ROOT.stat().st_mode) == 0o700 and ROOT.stat().st_dev == 16777244, 'private_t5_root')
    need(Path('/Volumes/T5').stat().st_dev == ROOT.stat().st_dev, 'root_on_t5_device')
    volume_path = run_step('00-t5-volume', ['/usr/sbin/diskutil', 'info', '-plist', '/Volumes/T5'], 10, cwd=ROOT)
    volume = plistlib.loads(volume_path.read_bytes())
    need(volume.get('VolumeUUID') == 'FB804D1B-24CB-4D6E-AEA7-A9E180807758'
         and volume.get('MountPoint') == '/Volumes/T5', 't5_volume_identity')
    REPORT['volume_identity'] = {k:volume.get(k) for k in ('VolumeUUID','DeviceIdentifier','MountPoint','FilesystemType')}
    need(digest(sys.executable) == PYTHON_SHA, 'pinned_native_python')
    need(digest(OUT / 'test-selection.public.json') == SELECTION_SHA, 'selection_digest')
    need(MANIFEST['execution_source_commit'] == COMMIT and MANIFEST['execution_source_tree'] == TREE, 'selection_source_binding')
    groups = MANIFEST['legacy_groups'] + MANIFEST['legacy_additional_groups'] + MANIFEST['added_groups']
    names = [name for group in groups for name in group['tests']]
    need(len(names) == len(set(names)) == 107, '107_unique_selected_names')
    need(sum(len(g['tests']) for g in groups if g['crate'] == 'heptabao-server') == 90, 'server90')
    need(sum(len(g['tests']) for g in groups if g['crate'] == 'heptabao-ha-service') == 17, 'ha_service17')
    need(all(g['runtime_seconds'] == 600 for g in groups), 'original_group_budgets')
    for name, sha in PINS.items():
        need(digest(TOOLCHAIN / name) == sha, 'toolchain_pin_' + name)
    REPORT['old_retained_artifacts_before'] = old_artifacts()
    need(all(x['matches_original'] for x in REPORT['old_retained_artifacts_before'].values()), 'old_retained_artifact_preflight_changed')
    REPORT['old_source_before'] = freeze('00-old-source', OLD_SOURCE)
    need(REPORT['old_source_before'] == dict(commit=OLD_HEAD, tree=OLD_TREE, status=''), 'original_source_identity')
    REPORT['preflight'] = resources('01-preflight'); checkpoint()
    need(not REPORT['preflight']['compiler_processes'] and not REPORT['preflight']['cargo_lock_pids'], 'other_compiler_or_cache_user_present')
    need(REPORT['preflight']['disk_free_bytes'] >= 8 * 1024**3, 'build_disk_headroom')
    need(REPORT['preflight']['ram_total_bytes'] >= 32 * 1024**3, 'original_mac_ram')
    need(digest(BUNDLE) == BUNDLE_SHA and BUNDLE.stat().st_size == 123258, 'canonical_bundle_hash')
    need(not SOURCE.exists(), 'new_candidate_source_required')
    git('02-independent-source-clone', ['clone', '--no-hardlinks', '--no-checkout', '--', str(OLD_SOURCE), str(SOURCE)], 120, cwd=ROOT)
    need((SOURCE / '.git').is_dir() and not (SOURCE / '.git').is_symlink()
         and not (SOURCE / '.git/objects/info/alternates').exists(), 'independent_git_object_store')
    git('03-bundle-verify', ['bundle', 'verify', str(BUNDLE)])
    git('04-fetch-local-bundle', ['fetch', '--no-tags', str(BUNDLE), 'HEAD'], 60)
    need(git('05-canonical-tree', ['rev-parse', COMMIT + '^{tree}']) == TREE, 'canonical_tree')
    need(git('06-canonical-parent', ['rev-parse', COMMIT + '^']) == PARENT, 'canonical_parent')
    git('07-original-ancestor', ['merge-base', '--is-ancestor', OLD_HEAD, COMMIT])
    git('08-checkout-canonical', ['checkout', '--detach', COMMIT], 60)
    need(not git('09-clean-source', ['status', '--porcelain=v1', '--untracked-files=all']), 'source_dirty_before_build')
    need(git('10-full-repository', ['rev-parse', '--is-shallow-repository']) == 'false', 'full_source_repository')
    git('11-fsck', ['fsck', '--full', '--strict'], 60)
    run_step('12-format-check', [str(TOOLCHAIN / 'cargo'), 'fmt', '--all', '--', '--check'], 60)
    (OUT / 'artifacts').mkdir(mode=0o700)
    build = run_step('13-normal-release-build', MANIFEST['build_examples']['server_release'], 1800)
    retain_artifact(build, 'heptabao-server', 'heptabao-server', False)
    retain_artifact(build, 'heptabao-seed', 'heptabao-seed', False)
    test_build = run_step('14-server-libtest-build', MANIFEST['build_examples']['server_libtest'], 1800)
    server_tests = retain_artifact(test_build, 'heptabao-server-libtest', 'heptabao_server', True)
    peer_build = run_step('15-peer-libtest-build', MANIFEST['build_examples']['peer_libtest'], 1800)
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
    need(not git('99-final-source-clean', ['status', '--porcelain=v1', '--untracked-files=all']), 'source_dirty_after_execution')
    need(git('99-final-source-tree', ['rev-parse', 'HEAD^{tree}']) == TREE, 'source_tree_changed')
    for artifact in REPORT['artifacts'].values():
        need(digest(artifact['path']) == artifact['sha256'], 'retained_artifact_changed')
    REPORT['source_and_artifacts_unchanged'] = True
    REPORT['passed_cases'] = 107
    need(time.monotonic() < DEADLINE, 'original_outer_deadline_expired')
    REPORT['status'] = 'passed'


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
        target = Path(ENV['CARGO_TARGET_DIR'])
        need(target.is_dir() and not target.is_symlink(), 'existing_build_cache_required')
        lock = (target / '.heptabao-mac-convergence-exclusive.lock').open('a')
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
        # Mask subsequent cancellation during bounded, registered cleanup and preservation.
        PROTECTED += 1
        PENDING = None
        try:
            REPORT['old_retained_artifacts_after'] = old_artifacts()
            if not all(x['matches_original'] for x in REPORT['old_retained_artifacts_after'].values()):
                raise Failed('old_retained_artifact_changed')
            REPORT['old_source_after'] = freeze('98-old-final', OLD_SOURCE)
            need(REPORT['old_source_after'] == dict(commit=OLD_HEAD, tree=OLD_TREE, status=''), 'original_source_changed')
            REPORT['postflight'] = resources('98-postflight')
        except BaseException as error:
            REPORT['status'] = 'failed'
            REPORT['preservation_error'] = str(error) if isinstance(error, Failed) else type(error).__name__
            REPORT['failure'] = REPORT['failure'] or 'preservation_gate_failed'
        REPORT['final_cleanup'] = []
        for label, proc in reversed(CHILDREN):
            try:
                row = dict(label=label, **clean_owned_group(proc))
            except BaseException as error:
                row = dict(label=label, pgid=proc.pid, all_owned_processes_gone=False, error_type=type(error).__name__)
            REPORT['final_cleanup'].append(row)
        REPORT['all_owned_processes_gone'] = all(row['all_owned_processes_gone'] for row in REPORT['final_cleanup'])
        if not REPORT['all_owned_processes_gone']:
            REPORT['status'] = 'failed'; REPORT['failure'] = REPORT['failure'] or 'owned_cleanup_failed'
        if PENDING is not None:
            REPORT['status'] = 'failed'
            REPORT['failure'] = REPORT['failure'] or 'interrupted_during_final_cleanup'
            REPORT['interrupted_during_final_cleanup_signum'] = PENDING
        if time.monotonic() >= DEADLINE:
            REPORT['status'] = 'failed'; REPORT['failure'] = REPORT['failure'] or 'original_outer_deadline_expired'
        REPORT['elapsed_seconds'] = round(time.monotonic() - START, 6)
        REPORT['finished_at_unix'] = time.time()
        REPORT['executed_passed_cases'] = sum(g['passed'] for g in REPORT['groups'])
        REPORT['not_qualified_cases'] = 107 - REPORT['executed_passed_cases']
        publish(OUT / 'result.public.json', REPORT); checkpoint()
        print(json.dumps(dict(event='terminal', status=REPORT['status'], failure=REPORT['failure'],
                              executed_passed_cases=REPORT['executed_passed_cases'],
                              result=str(OUT / 'result.public.json'))), flush=True)
        if lock is not None:
            lock.close()
    sys.exit(0 if REPORT['status'] == 'passed' else 1)
