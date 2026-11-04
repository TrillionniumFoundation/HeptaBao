#!/usr/bin/env python3
"""Stage one strict-qualified source tree on the known external T5; no build."""
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import signal
import socket
import stat
import subprocess
import sys
import time

BASE = Path('/Volumes/T5/hepta-vnext-recovery-20261013')
ROOT = BASE / 'continuation-20261104-ha-unified-normal-61ff-r1'
SOURCE = ROOT / 'source'
CONTROL = ROOT / 'control'
REMOTE_SOURCE = '/home/qian-qi/heptabao-bao-acceptance-unified-61ff-20261104-r1/source'
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python')
PYTHON_SHA = '7ecc1ecbf9daa9303c4bf502ff62ffdd9010ed5c08729d470ae9380c10ce1211'
VOLUME_UUID = 'FB804D1B-24CB-4D6E-AEA7-A9E180807758'
BUILDER_SHA = 'f902727e82a3c7a8942006b056ecfca9258a856d456f4b1aa2131b2aa3a35d82'
PROBE_RESULT = BASE / 'continuation-20261104-ha-cargo-lock-probe-61ff-r1/result.public.json'
PROBE_SHA = 'd9be1b814a0f7834f22eef219c765a3dae8ede2b6be60ca02f1b88600cc69403'
STAGE_SECONDS = 240.0
child = None
child_reaped = True
creating = False
pending_signal = None
stage_creation_started = False


def need(ok, code):
    if not ok:
        raise RuntimeError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def read_owned(path, limit=4 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 501
             and before.st_nlink == 1 and before.st_size <= limit, 'file_custody')
        chunks, count = [], 0
        while count <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
        need(count == before.st_size, 'file_size_changed')
        need(identity(before) == identity(os.fstat(fd)) == identity(path.lstat()), 'file_changed')
        return b''.join(chunks)
    finally:
        os.close(fd)


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def interrupted(signum, frame):
    global pending_signal
    if creating:
        pending_signal = signum
    else:
        raise RuntimeError('owned_stage_interrupted')


def group_members(pgid):
    result = subprocess.run(['/bin/ps', '-axo', 'pid=,pgid='],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, timeout=5)
    need(result.returncode == 0, 'group_observation_failed')
    return [int(parts[0]) for row in result.stdout.splitlines()
            if len(parts := row.split()) == 2 and int(parts[1]) == pgid]


def child_exit_without_reaping():
    need(child is not None and not child_reaped, 'unreaped_owned_child_required')
    observed = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    need(observed is None or observed.si_pid == child.pid, 'unexpected_waitid_child')
    return observed is not None


def signal_owned_group(signum):
    # A successful start_new_session=True owns this unreaped child's group.
    # waitid fails if custody was lost; a numeric PGID alone never authorizes
    # signalling. On Darwin an exited, unreaped child can return ESRCH from
    # getpgid. A live-to-exited race must be confirmed by a second waitid.
    exited = child_exit_without_reaping()
    if not exited:
        try:
            need(os.getpgid(child.pid) == child.pid, 'owned_child_group_changed')
        except ProcessLookupError:
            need(child_exit_without_reaping(), 'live_owned_child_group_missing')
    try:
        os.killpg(child.pid, signum)
    except ProcessLookupError:
        pass


def stop_owned():
    global child_reaped
    if child is None:
        return None
    if child_reaped:
        return {'pid': child.pid, 'returncode': child.returncode, 'forced': False,
                'remaining': group_members(child.pid), 'already_reaped': True}
    # Keep the original direct child unreaped through group cleanup. Darwin
    # can stop resolving getpgid for an exited child even before it is reaped.
    exited = child_exit_without_reaping()
    descendants = [pid for pid in group_members(child.pid) if pid != child.pid]
    forced = False
    if not exited or descendants:
        signal_owned_group(signal.SIGTERM)
        stop_until = time.monotonic() + 5
        while time.monotonic() < stop_until:
            exited = child_exit_without_reaping()
            descendants = [pid for pid in group_members(child.pid) if pid != child.pid]
            if exited and not descendants:
                break
            time.sleep(0.025)
        if not exited or descendants:
            signal_owned_group(signal.SIGKILL)
            forced = True
    code = child.wait(timeout=5)
    child_reaped = True
    after_until = time.monotonic() + 2
    members = group_members(child.pid)
    while members and time.monotonic() < after_until:
        time.sleep(0.025)
        members = group_members(child.pid)
    return {'pid': child.pid, 'returncode': code, 'forced': forced,
            'remaining': members, 'group_cleanup_before_reap': True}

def main():
    global child, creating, stage_creation_started
    os.umask(0o077)
    need(len(sys.argv) == 2 and re.fullmatch('[0-9a-f]{64}', sys.argv[1]), 'packet_pin_required')
    packet_raw = sys.stdin.buffer.read(1024 * 1024 + 1)
    need(len(packet_raw) <= 1024 * 1024 and sha(packet_raw) == sys.argv[1], 'packet_pin')
    packet = json.loads(packet_raw)
    need(packet['schema'] == 'heptabao.mac-unified-source-stage-input.v1', 'packet_schema')
    names = {'build_normal.py', 'launch_mac_normal_build_r3.py',
             'frozen-source.public.json', 'clippy-qualified-source.public.json'}
    need(set(packet['files']) == names and set(packet['file_pins']) == names, 'closed_control_files')
    for name in names:
        need(isinstance(packet['files'][name], str)
             and sha(packet['files'][name].encode()) == packet['file_pins'][name], 'control_file_pin')
    need(packet['file_pins']['build_normal.py'] == BUILDER_SHA, 'unchanged_builder_required')
    frozen = json.loads(packet['files']['frozen-source.public.json'])
    qualified = json.loads(packet['files']['clippy-qualified-source.public.json'])
    commit, tree = packet['source_commit'], packet['source_tree']
    need(re.fullmatch('[0-9a-f]{40}', commit) and re.fullmatch('[0-9a-f]{40}', tree), 'git_identifiers')
    need(frozen['source'] == qualified['source'] == commit
         and frozen['tree'] == qualified['tree'] == tree, 'same_qualified_source')
    need(frozen['source_path'] == REMOTE_SOURCE, 'fixed_source_location')
    need(qualified['frozen_manifest_sha256'] == packet['file_pins']['frozen-source.public.json'],
         'frozen_receipt_binding')
    strict = qualified['strict_clippy']
    need(strict['exit_code'] == 0 and strict['timed_out'] is False
         and strict['remaining'] == [], 'strict_clippy_not_qualified')
    args = strict['args']
    need(isinstance(args, list) and all(isinstance(x, str) for x in args), 'strict_args')
    expected_strict_args = [
        '/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/cargo',
        'clippy', '--release', '--locked', '--offline', '--workspace', '--all-targets',
        '--exclude', 'qrcode', '--', '-D', 'warnings',
    ]
    need(args == expected_strict_args, 'exact_inherited_strict_gate_required')
    need(qualified['normal_profile'] == packet['expected_normal_profile'], 'normal_profile_binding')
    need(isinstance(frozen['files'], list) and frozen['files'], 'source_file_manifest')
    need(platform.system() == 'Darwin' and platform.machine() == 'arm64', 'mac_arm_required')
    need(all(hasattr(os, name) for name in ('waitid', 'P_PID', 'WEXITED', 'WNOHANG', 'WNOWAIT'))
         and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, 'non_reaping_wait_required')
    need(os.getuid() == os.geteuid() == 501 and socket.gethostname() == 'MacBook-Pro.local', 'operator_identity')
    need(Path(sys.executable).resolve(strict=True) == PYTHON and sha(read_owned(PYTHON)) == PYTHON_SHA, 'python_pin')
    volume_result = subprocess.run(['/usr/sbin/diskutil', 'info', '-plist', '/Volumes/T5'],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=10)
    need(volume_result.returncode == 0, 'volume_observation_failed')
    volume = plistlib.loads(volume_result.stdout)
    need(volume.get('MountPoint') == '/Volumes/T5' and volume.get('VolumeUUID') == VOLUME_UUID
         and volume.get('FilesystemType') == 'apfs' and volume.get('Writable') is True
         and volume.get('Internal') is False, 't5_identity')
    device = Path('/Volumes/T5').lstat().st_dev
    for path in (Path('/Volumes/T5'), BASE):
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and not path.is_symlink()
             and info.st_dev == device, 't5_directory_boundary')
        need(info.st_uid in (0, 501) if path == Path('/Volumes/T5') else info.st_uid == 501, 'directory_owner')
    need(BASE.resolve(strict=True) == BASE, 'base_symlink')
    probe_raw = read_owned(PROBE_RESULT)
    need(sha(probe_raw) == PROBE_SHA and json.loads(probe_raw)['status'] == 'passed', 'actual_cargo_lock_probe')
    need(not ROOT.exists() and not ROOT.is_symlink(), 'fresh_stage_required')
    began = time.monotonic()
    until = began + STAGE_SECONDS
    stage_creation_started = True
    ROOT.mkdir(mode=0o700)
    CONTROL.mkdir(mode=0o700)
    SOURCE.mkdir(mode=0o700)
    result = {'schema': 'heptabao.mac-unified-source-stage.v1', 'status': 'failed',
              'root': str(ROOT), 'source': commit, 'tree': tree, 'packet_sha256': sha(packet_raw),
              'frozen_manifest_sha256': packet['file_pins']['frozen-source.public.json'],
              'qualified_receipt_sha256': packet['file_pins']['clippy-qualified-source.public.json'],
              'python_sha256': PYTHON_SHA, 'volume_uuid': VOLUME_UUID, 'volume_device': device,
              'actual_lock_probe_sha256': PROBE_SHA, 'stage_budget_seconds': STAGE_SECONDS,
              'strict_clippy_inherited_excluded_package': 'qrcode',
              'commands': [], 'cache_cloned': False, 'cargo_started': False,
              'product_service_started': False, 'production_changed': False}
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    environment.update({'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_NOSYSTEM': '1',
                        'GIT_CONFIG_GLOBAL': '/dev/null',
                        'GIT_SSH_COMMAND': '/usr/bin/ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 -o ConnectionAttempts=1'})
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)

    def remaining():
        left = until - time.monotonic()
        need(left > 0, 'original_stage_deadline')
        return left

    def command(label, argv):
        global child, creating, child_reaped
        need(child is None or child_reaped, 'one_owned_child')
        stdout_path, stderr_path = CONTROL / (label + '.stdout'), CONTROL / (label + '.stderr')
        started = time.monotonic()
        with stdout_path.open('xb') as so, stderr_path.open('xb') as se:
            creating = True
            try:
                child = subprocess.Popen(argv, cwd=SOURCE, env=environment, stdin=subprocess.DEVNULL,
                                         stdout=so, stderr=se, start_new_session=True)
                child_reaped = False
            finally:
                creating = False
            if pending_signal is not None:
                raise RuntimeError('interrupted_during_spawn')
            while not child_exit_without_reaping():
                time.sleep(min(0.025, remaining()))
            cleanup = stop_owned()
            code = cleanup['returncode']
            so.flush()
            se.flush()
            os.fsync(so.fileno())
            os.fsync(se.fileno())
        members = cleanup['remaining']
        out, err = read_owned(stdout_path), read_owned(stderr_path)
        result['commands'].append({'label': label, 'argv': argv, 'pid': child.pid,
                                   'exit_code': code, 'remaining': members, 'cleanup': cleanup,
                                   'elapsed_seconds': time.monotonic() - started,
                                   'stdout_sha256': sha(out), 'stderr_sha256': sha(err)})
        need(code == 0 and not members, 'source_command_failed_or_children_remain')
        return out.decode('utf-8', 'strict').strip()

    def git(label, *args):
        return command(label, ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-C', str(SOURCE), *args])

    try:
        write_new(CONTROL / 'stage-input.public.json', packet_raw)
        for name in sorted(names):
            write_new(CONTROL / name, packet['files'][name].encode(), 0o500 if name.endswith('.py') else 0o600)
        sync_dir(CONTROL)
        git('git-init', 'init', '--quiet')
        git('git-fetch', 'fetch', '--no-tags', '--depth=1', '--no-recurse-submodules',
            'rog:' + REMOTE_SOURCE, commit)
        git('git-checkout', 'checkout', '--detach', commit)
        need(git('git-head', 'rev-parse', 'HEAD') == commit, 'actual_commit')
        need(git('git-tree', 'rev-parse', 'HEAD^{tree}') == tree, 'actual_tree')
        need(git('git-clean', 'status', '--porcelain=v1', '--untracked-files=all') == '', 'source_dirty')
        checked = []
        seen = set()
        for pin in frozen['files']:
            rel = Path(pin['path'])
            need(not rel.is_absolute() and '..' not in rel.parts and str(rel) not in seen, 'manifest_path')
            seen.add(str(rel))
            path = SOURCE / rel
            for parent in path.parents:
                if parent == SOURCE:
                    break
                info = parent.lstat()
                need(stat.S_ISDIR(info.st_mode) and not parent.is_symlink()
                     and info.st_dev == device and info.st_uid == 501, 'source_parent_custody')
            raw = read_owned(path)
            need(path.lstat().st_dev == device and len(raw) == pin['bytes']
                 and sha(raw) == pin['sha256'], 'source_file_pin')
            blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            need(blob == pin['git_blob'], 'source_git_blob_pin')
            checked.append({'path': str(rel), 'bytes': len(raw), 'sha256': sha(raw), 'git_blob': blob})
        need(git('git-final-clean', 'status', '--porcelain=v1', '--untracked-files=all') == '', 'final_source_dirty')
        remaining()
        result.update(status='staged', verified_files=checked, source_file_count=len(checked),
                      source_fetched_readonly_from='rog:' + REMOTE_SOURCE,
                      physical_source_commit_preserved=True)
    except Exception as error:
        result['failure_class'] = type(error).__name__
        result['failure_code'] = str(error) if isinstance(error, RuntimeError) else None
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            result['last_owned_child_cleanup'] = stop_owned()
            if result['last_owned_child_cleanup'] and result['last_owned_child_cleanup']['remaining']:
                result['status'] = 'failed'
        except Exception as error:
            result['status'] = 'failed'
            result['cleanup_error_class'] = type(error).__name__
        result['elapsed_seconds'] = time.monotonic() - began
        if result['elapsed_seconds'] > STAGE_SECONDS:
            result['status'] = 'failed'
            result['failure_code'] = 'original_stage_deadline'
        raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
        write_new(CONTROL / 'source-stage-result.public.json', raw)
        sync_dir(CONTROL)
        sync_dir(ROOT)
        print(json.dumps({'status': result['status'], 'result_sha256': sha(raw),
                          'result': str(CONTROL / 'source-stage-result.public.json'),
                          'source': commit, 'tree': tree, 'source_file_count': result.get('source_file_count'),
                          'cargo_started': False, 'production_changed': False}, sort_keys=True), flush=True)
    return 0 if result['status'] == 'staged' else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status': 'failed_after_stage_started' if stage_creation_started else 'refused_before_stage',
                          'error_class': type(error).__name__,
                          'error_code': str(error) if isinstance(error, RuntimeError) else None}, sort_keys=True), flush=True)
        raise SystemExit(2) from None
