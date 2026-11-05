#!/usr/bin/env python3
"""One bounded read-only observation; never starts Cargo, a fixture, or a service."""
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time


ROOT = Path('/home/qian-qi/heptabao-bao-acceptance-unified-61ff-20261104-r1')
SOURCE = ROOT / 'source'
TARGET = ROOT / 'cargo-target-normal'
CACHE = Path('/home/qian-qi/heptabao-native-20261029-c1bd-r1/runtime/target')
CARGO_HOME = Path('/home/qian-qi/heptabao-native-20261029-c1bd-r1/cargo-home')
TOOLCHAIN = Path('/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin')
BASE_COMMIT = '70714605c39014bea93545f7f6aa4217d2a23544'
BASE_TREE = 'ef0ae63704a06b7dda1038e02abcc3233a2a438f'
BASE_BRANCH = 'refs/heads/codex/heptabao-unified-61ff-20261104-r1'
FROZEN_SHA256 = 'ad59fb02e3affc08720c13f7349d93a99df646ca7616f9a10e41e1cc6ddbeff1'
GUARD_FRAGMENT_SHA256 = 'b00ff78b2a341a752d489c3a677f7a912f0f79b39c42601cfb030a29bea45b59'
PRIOR_DECLARED_GUARD_SHA256 = '108ea3a050eb5f1596b8c6cab3aeffbce8a220e91ae1b15ac70b3b6176c097cb'
MAX_RESULT_BYTES = 512 * 1024
MAX_CHILD_BYTES = 128 * 1024
MAX_PROCESSES = 2048
MAX_FDS = 65536
BOUNDARIES = [SOURCE, TARGET, CACHE, CARGO_HOME]


class Refused(RuntimeError):
    pass


def need(condition, code):
    if not condition:
        raise Refused(code)


def remaining():
    left = PREFLIGHT_UNTIL - time.monotonic()
    need(left > 0, 'readonly_preflight_absolute_deadline')
    return left


def identity(info):
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def public_stat(path, info):
    return {'path': str(path), 'device': info.st_dev, 'inode': info.st_ino,
            'uid': info.st_uid, 'gid': info.st_gid, 'mode': oct(stat.S_IMODE(info.st_mode)),
            'bytes': info.st_size, 'nlink': info.st_nlink,
            'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}


def directory_info(path):
    remaining()
    need(path.resolve(strict=True) == path, 'directory_symlink_or_changed_path')
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 1000, 'owned_directory_required')
    return public_stat(path, info)


def read_regular(path, max_bytes, owners=(1000,), keep=False):
    remaining()
    need(path.resolve(strict=True) == path, 'regular_file_symlink_or_changed_path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid in owners,
             'regular_file_owner_or_type')
        need(0 <= before.st_size <= max_bytes, 'regular_file_size_bound')
        sha = hashlib.sha256()
        git = hashlib.sha1(('blob ' + str(before.st_size) + '\0').encode())
        data = bytearray()
        count = 0
        while True:
            remaining()
            chunk = os.read(fd, min(1024 * 1024, max_bytes + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            need(count <= max_bytes, 'regular_file_grew_over_bound')
            sha.update(chunk)
            git.update(chunk)
            if keep:
                data.extend(chunk)
        need(count == before.st_size and identity(before) == identity(os.fstat(fd))
             == identity(path.lstat()), 'regular_file_identity_changed')
        report = public_stat(path, before)
        report.update(sha256=sha.hexdigest(), git_blob=git.hexdigest())
        return report, bytes(data) if keep else None
    finally:
        os.close(fd)


def lock_probe(path):
    remaining()
    need(path.resolve(strict=True) == path, 'lock_path_symlink')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    locked = False
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 1000
             and before.st_size == 0, 'existing_empty_owned_lock_required')
        result = public_stat(path, before)
        result.update(opened_read_only=True, nonblocking_flock=True,
                      persistent_reservation=False, file_contents_changed=False)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError as error:
            if error.errno not in (errno.EACCES, errno.EAGAIN):
                raise
            result.update(acquired=False, released=False, error_code='advisory_lock_busy')
            return result
        need(identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
             'lock_identity_changed')
        result.update(acquired=True, released=True)
        return result
    finally:
        if locked:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


class ReadonlyChildren:
    """Git children remain inside the Runtime job group. This code sends no signal."""
    def __init__(self):
        self.child = None
        self.records = []

    def git(self, label, *args):
        remaining()
        need(self.child is None, 'one_readonly_child_at_a_time')
        argv = ['/usr/bin/git', '--no-optional-locks', '-c', 'core.hooksPath=/dev/null',
                '-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false',
                '-c', 'submodule.recurse=false', '-C', str(SOURCE), *args]
        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C',
               'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
               'GIT_OPTIONAL_LOCKS': '0', 'GIT_TERMINAL_PROMPT': '0',
               'GIT_PAGER': 'cat', 'PAGER': 'cat'}
        started = time.monotonic()
        record = {'label': label, 'args': argv, 'started_unix_ns': time.time_ns(),
                  'exit_code': None, 'original_child_waited': False,
                  'same_runtime_process_group': True, 'signals_sent_by_script': 0}
        self.records.append(record)
        child = subprocess.Popen(argv, cwd=SOURCE, env=env, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=False, close_fds=True)
        self.child = child
        record['pid'] = child.pid
        buffers = [bytearray(), bytearray()]
        selector = selectors.DefaultSelector()
        try:
            for index, pipe in enumerate((child.stdout, child.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, index)
            while selector.get_map():
                left = remaining()
                for key, unused in selector.select(min(0.1, left)):
                    chunk = os.read(key.fd, 32768)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        buffers[key.data].extend(chunk)
                        need(sum(map(len, buffers)) <= MAX_CHILD_BYTES,
                             'readonly_child_output_bound')
            code = child.wait(timeout=remaining())
            record.update(exit_code=code, original_child_waited=True,
                          elapsed_seconds=time.monotonic() - started,
                          stdout_bytes=len(buffers[0]), stderr_bytes=len(buffers[1]),
                          stdout_sha256=hashlib.sha256(buffers[0]).hexdigest(),
                          stderr_sha256=hashlib.sha256(buffers[1]).hexdigest())
            self.child = None
            need(code == 0, 'readonly_git_nonzero_' + label)
            return bytes(buffers[0]).decode('utf-8', 'strict').strip()
        finally:
            selector.close()
            for pipe in (child.stdout, child.stderr):
                pipe.close()

    def finish(self):
        if self.child is None:
            return {'all_original_children_waited': True, 'signals_sent_by_script': 0}
        child = self.child
        record = self.records[-1]
        try:
            # After a failed observation only wait/reap this exact Popen child.
            # No more observation, work, retry, or signal is permitted here.
            code = child.wait(timeout=max(0.001, PREFLIGHT_BEGAN + 75 - time.monotonic()))
        except subprocess.TimeoutExpired:
            print(json.dumps({'schema': 'heptabao.readonly-preflight-incomplete-child.v1',
                              'pid': child.pid, 'original_child_waited': False,
                              'observation_deadline_elapsed': True,
                              'execution_admitted': False,
                              'supervisor_bound_seconds': 90,
                              'signals_sent_by_script': 0}, sort_keys=True), flush=True)
            # Keep the original child in the original Runtime-owned job group.
            # The already-declared 90s supervisor is the sole terminal bound.
            # Exiting here could falsely detach a still-running Git child.
            code = child.wait()
        record.update(exit_code=code, original_child_waited=True,
                      observed_during_cleanup=True)
        self.child = None
        return {'all_original_children_waited': True, 'signals_sent_by_script': 0,
                'cleanup_only_after_failure': True, 'last_returncode': code}


def source_state(children, label):
    return {'commit': children.git(label + '-head', 'rev-parse', '--verify', 'HEAD'),
            'tree': children.git(label + '-tree', 'rev-parse', '--verify', 'HEAD^{tree}'),
            'branch': children.git(label + '-branch', 'symbolic-ref', 'HEAD'),
            'clean': children.git(label + '-status', 'status', '--porcelain=v1',
                                  '--untracked-files=all', '--ignore-submodules=none') == ''}


def pin_source_files(manifest):
    need(manifest['source'] == BASE_COMMIT and manifest['tree'] == BASE_TREE
         and len(manifest['files']) == 62, 'fixed_7071_manifest_identity')
    result = []
    seen = set()
    for entry in manifest['files']:
        remaining()
        relative = Path(entry['path'])
        need(not relative.is_absolute() and '..' not in relative.parts
             and str(relative) not in seen, 'closed_manifest_source_path')
        seen.add(str(relative))
        observed, unused = read_regular(SOURCE / relative, 8 * 1024 * 1024)
        need(observed['bytes'] == entry['bytes'] and observed['sha256'] == entry['sha256']
             and observed['git_blob'] == entry['git_blob'], '7071_source_file_pin_mismatch')
        result.append({'path': str(relative), 'bytes': observed['bytes'],
                       'sha256': observed['sha256'], 'git_blob': observed['git_blob']})
    return result


def same_process(row):
    path = Path('/proc') / str(row['pid'])
    raw = (path / 'stat').read_text()
    fields = raw[raw.rfind(')') + 2:].split()
    need(path.stat().st_uid == 1000 and fields[0] not in ('Z', 'X')
         and int(fields[19]) == row['start_clock_ticks']
         and int(fields[1]) == row['parent_pid']
         and (path / 'comm').read_text().strip() == row['name']
         and os.readlink(path / 'exe') == row['executable_path']
         and os.readlink(path / 'cwd') == row['cwd'], 'process_identity_changed_during_fd_scan')


def process_and_related_fds(guard):
    rows, daemons = guard['process_snapshot']()
    need(len(rows) <= MAX_PROCESSES, 'operator_process_count_bound')
    related = []
    scanned = 0
    exited = []
    for pid, row in sorted(rows.items()):
        remaining()
        try:
            same_process(row)
            fds = Path('/proc') / str(pid) / 'fd'
            for descriptor in fds.iterdir():
                remaining()
                scanned += 1
                need(scanned <= MAX_FDS, 'operator_fd_count_bound')
                try:
                    target = os.readlink(descriptor)
                except FileNotFoundError:
                    continue
                if any(guard['under'](target, boundary) for boundary in BOUNDARIES):
                    related.append({'pid': pid, 'start_clock_ticks': row['start_clock_ticks'],
                                    'fd': descriptor.name, 'target_path': target,
                                    'preflight_self': pid == os.getpid()})
            same_process(row)
        except FileNotFoundError:
            need(not (Path('/proc') / str(pid)).exists(),
                 'live_process_metadata_missing_during_fd_scan')
            exited.append({'pid': pid, 'start_clock_ticks': row['start_clock_ticks']})
    products = [row for row in rows.values()
                if row['executable_basename'] in ('heptabao-server', 'heptabao-seed',
                    'retained-heptabao-server', 'retained-heptabao-seed', 'bao', 'openbao')]
    return {'processes': list(rows.values()), 'pinned_session_daemons': daemons,
            'target_related_file_descriptors': related, 'fd_count_observed': scanned,
            'confirmed_exits_during_scan': exited, 'product_named_processes': products,
            'process_scope': 'configured_operator_uid_only', 'operator_uid': 1000,
            'argv_or_environment_read': False, 'foreign_processes_changed': False,
            'atomic_snapshot': False, 'host_exclusivity_established': False,
            'product_process_presence_is_not_classified_by_original_compiler_guard': True}


def main():
    need(__debug__ and sys.flags.optimize == 0, 'guard_assertions_must_be_enabled')
    need(platform.system() == 'Linux' and platform.machine() == 'x86_64'
         and os.getuid() == os.geteuid() == 1000, 'configured_linux_operator_required')
    need(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
         'original_child_wait_semantics_required')
    guard_source = PREFLIGHT_INPUT['guard_source']
    frozen_raw = PREFLIGHT_INPUT['base_frozen_source'].encode('utf-8')
    need(hashlib.sha256(guard_source.encode('utf-8')).hexdigest() == GUARD_FRAGMENT_SHA256,
         'embedded_original_guard_bytes_mismatch')
    need(hashlib.sha256(frozen_raw).hexdigest() == FROZEN_SHA256,
         'base_frozen_manifest_bytes_mismatch')
    guard = {'__name__': 'heptabao_original_r6_readonly_guard'}
    exec(compile(guard_source, '<pinned-original-r6-guard>', 'exec'), guard)
    manifest = json.loads(frozen_raw)
    report = {'schema': 'heptabao.rog-readonly-preflight.v1',
              'scope': 'read-only current source, toolchain, locks, resources, and operator processes',
              'configured_host': 'rog', 'hostname_observed': socket.gethostname(),
              'platform': platform.system(), 'machine': platform.machine(),
              'uid': os.getuid(), 'euid': os.geteuid(), 'pid': os.getpid(),
              'pgid': os.getpgrp(), 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
              'started_unix_ns': PREFLIGHT_STARTED_UNIX_NS,
              'observation_budget_seconds': 60, 'supervisor_bound_seconds': 90,
              'source_write_attempted': False, 'target_created': False,
              'cargo_or_product_started': False, 'signals_sent_by_script': 0,
              'original_r6_guard_fragment_sha256': GUARD_FRAGMENT_SHA256,
              'prior_r6_declared_guard_identity_sha256': PRIOR_DECLARED_GUARD_SHA256,
              'fragment_hash_is_distinct_from_prior_declared_file_identity': True,
              'checks': [], 'execution_admitted': False, 'timed_test_execution_admitted': False,
              'mac_window_released': False, 'whole_lan_blocked': False,
              'candidate_compiled': False, 'full_replacement_qualified': False}
    children = ReadonlyChildren()
    observed_source = []

    def observe(label, action):
        remaining()
        check = {'label': label, 'observed_unix_ns': time.time_ns(), 'passed': False}
        report['checks'].append(check)
        try:
            check['data'] = action()
            check['passed'] = True
        except (Refused, AssertionError) as error:
            check.update(error_class=type(error).__name__, error_code=str(error))
        except Exception as error:
            check.update(error_class=type(error).__name__,
                         error_code='readonly_observation_error', errno=getattr(error, 'errno', None))
        remaining()
        need(children.child is None, 'readonly_child_not_yet_waited')
        return check

    def source(label):
        value = source_state(children, label)
        observed_source.append(value)
        need(value == {'commit': BASE_COMMIT, 'tree': BASE_TREE,
                       'branch': BASE_BRANCH, 'clean': True}, '7071_source_not_clean_or_changed')
        return value

    try:
        report['directories'] = [directory_info(path) for path in (ROOT, SOURCE, TARGET, CACHE, CARGO_HOME)]
        tools = [Path('/proc/self/exe').resolve(strict=True), Path('/usr/bin/git').resolve(strict=True),
                 TOOLCHAIN / 'cargo', TOOLCHAIN / 'rustc', TOOLCHAIN / 'clippy-driver',
                 TOOLCHAIN / 'rustfmt', Path('/usr/bin/openssl').resolve(strict=True)]
        report['toolchain_files'] = [read_regular(path, 256 * 1024 * 1024, (0, 1000))[0]
                                     for path in tools]
        report['toolchain_hashes_are_current_observations_not_previous_pins'] = True
        observe('source-before', lambda: source('before'))
        observe('all-62-original-source-pins', lambda: pin_source_files(manifest))
        observe('operator-processes-and-target-related-fds', lambda: process_and_related_fds(guard))
        for label, path in [('target-release-lock', TARGET / 'release/.cargo-lock'),
                            ('prior-cache-release-lock', CACHE / 'release/.cargo-lock')]:
            check = observe(label, lambda p=path: lock_probe(p))
            if check.get('data', {}).get('acquired') is not True:
                check['passed'] = False
        observe('original-compile-admission', guard['compile_admission'])
        observe('original-timed-test-admission', guard['exclusive_timed_test_admission'])
        observe('source-after', lambda: source('after'))
        need(len(observed_source) == 2 and observed_source[0] == observed_source[1],
             'non_atomic_source_observations_changed')
        report['completed_readonly_observation'] = True
    except BaseException as error:
        report.update(completed_readonly_observation=False, error_class=type(error).__name__,
                      error_code=str(error) if isinstance(error, Refused) else 'readonly_preflight_failed')
    finally:
        report['owned_readonly_child_cleanup'] = children.finish()
        report['readonly_child_commands'] = children.records
        report['elapsed_seconds'] = time.monotonic() - PREFLIGHT_BEGAN
        report['absolute_deadline_met'] = time.monotonic() <= PREFLIGHT_UNTIL
        report['source_observations'] = observed_source
        report['all_required_checks_passed'] = (report.get('completed_readonly_observation') is True
            and report['absolute_deadline_met'] and all(check['passed'] for check in report['checks']))
        report['status'] = ('completed_readonly_observation' if report.get('completed_readonly_observation')
                            else 'incomplete_readonly_observation')
        raw = (json.dumps(report, sort_keys=True, separators=(',', ':')) + '\n').encode()
        need(len(raw) <= MAX_RESULT_BYTES, 'readonly_public_result_size_bound')
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
    return 0 if report['all_required_checks_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
