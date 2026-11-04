#!/usr/bin/env python3
"""Run the recovered normal builder on one strict-qualified Mac source tree."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
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
TARGET = ROOT / 'runtime.noindex' / 'target'
OUTPUT = ROOT / 'normal-default-r1'
CACHE = BASE / 'continuation-20261029-joint2dbb-full6-r1/runtime.noindex/target-native-full-r2'
CARGO_HOME = BASE / 'r13-full-native-cargo-home-r1'
TOOLCHAIN = Path('/Users/qianqi/.rustup/toolchains/1.98.0-aarch64-apple-darwin/bin')
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python')
PYTHON_SHA = '7ecc1ecbf9daa9303c4bf502ff62ffdd9010ed5c08729d470ae9380c10ce1211'
CARGO_SHA = '1de2e84c15443b70444eecfa959ff9099dd8c1a5606b6d9ef5bc0ea9c25bc7f9'
RUSTC_SHA = 'a11618eca0956a8aa4372c2bc898690b513cbdfa2cb9125b2a5301e360ed5b49'
COMMIT = '70714605c39014bea93545f7f6aa4217d2a23544'
TREE = 'ef0ae63704a06b7dda1038e02abcc3233a2a438f'
FROZEN_SHA = 'ad59fb02e3affc08720c13f7349d93a99df646ca7616f9a10e41e1cc6ddbeff1'
QUALIFIED_SHA = '510de9e176b77e771a3233d56620c32975c161970213d7f83d1b7eceb37624db'
BUILDER_SHA = 'f902727e82a3c7a8942006b056ecfca9258a856d456f4b1aa2131b2aa3a35d82'
PROBE = BASE / 'continuation-20261104-ha-cargo-lock-probe-61ff-r1/result.public.json'
PROBE_SHA = 'd9be1b814a0f7834f22eef219c765a3dae8ede2b6be60ca02f1b88600cc69403'
VOLUME_UUID = 'FB804D1B-24CB-4D6E-AEA7-A9E180807758'
PREPARATION_SECONDS = 300.0
RESULT = CONTROL / 'normal-launch-r3.public.json'
original_popen = subprocess.Popen
owned_children = []
creating = False
pending_signal = None
preparation_deadline = None
launch_work_started = False


def need(ok, code):
    if not ok:
        raise RuntimeError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def remaining():
    left = preparation_deadline - time.monotonic()
    need(left > 0, 'original_preparation_deadline')
    return left


def read_owned(path, limit=4 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 501
             and before.st_nlink == 1 and before.st_size <= limit, 'input_file_custody')
        chunks, count = [], 0
        while count <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
        need(count == before.st_size
             and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
             'input_file_changed')
        return b''.join(chunks)
    finally:
        os.close(fd)


def hash_binary(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 501
             and before.st_size <= 256 * 1024 * 1024, 'binary_custody')
        h = hashlib.sha256()
        count = 0
        while True:
            remaining()
            data = os.read(fd, 1024 * 1024)
            if not data:
                break
            h.update(data)
            count += len(data)
        need(count == before.st_size
             and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
             'binary_changed')
        return h.hexdigest()
    finally:
        os.close(fd)


def directory(path, device, mount=False):
    need(path.resolve(strict=True) == path, 'directory_symlink')
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_dev == device, 'directory_device')
    need(info.st_uid in (0, 501) if mount else info.st_uid == 501, 'directory_owner')
    return info


def owned_ancestors(path, device):
    need(path == BASE or BASE in path.parents, 'outside_owned_base')
    for item in reversed((path, *path.parents)):
        if item == BASE or BASE in item.parents:
            directory(item, device)


def write_new(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return sha(raw)


def interrupted(signum, frame):
    global pending_signal
    if creating:
        pending_signal = signum
    else:
        raise RuntimeError('owned_launcher_interrupted')


class TrackedPopen(original_popen):
    """Retain creation custody without changing argv, env, sessions or waits."""
    def __init__(self, *args, **kwargs):
        global creating
        need(not creating, 'nested_process_creation')
        creating = True
        try:
            super().__init__(*args, **kwargs)
            owned_children.append((self, kwargs.get('start_new_session') is True))
        finally:
            creating = False
        if pending_signal is not None:
            raise RuntimeError('interrupted_during_owned_spawn')


def group_members(pgid):
    proc = original_popen(['/bin/ps', '-axo', 'pid=,pgid='],
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
    try:
        out, err = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate(timeout=5)
        raise RuntimeError('group_observation_deadline') from None
    need(proc.returncode == 0, 'group_observation_failed')
    return [int(fields[0]) for line in out.splitlines()
            if len(fields := line.split()) == 2 and int(fields[1]) == pgid]


def child_exited_unreaped(proc):
    result = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    return result is not None and result.si_pid == proc.pid


def cleanup_children():
    records = []
    for proc, own_group in reversed(owned_children):
        if proc.returncode is not None:
            # The original builder may already have reaped its leader. Never
            # send a group signal after that ownership anchor has disappeared.
            members = group_members(proc.pid) if own_group else []
            records.append({'pid': proc.pid, 'returncode': proc.returncode,
                            'already_reaped': True, 'remaining_observed': members,
                            'group_signalled_after_reap': False})
            continue
        # Only a still-unreaped direct child can anchor these signals.
        child_exited_unreaped(proc)
        forced = False
        if own_group:
            need(os.getpgid(proc.pid) == proc.pid, 'owned_group_anchor_changed')
            os.killpg(proc.pid, signal.SIGTERM)
            stop = time.monotonic() + 5
            while time.monotonic() < stop:
                others = [pid for pid in group_members(proc.pid) if pid != proc.pid]
                if child_exited_unreaped(proc) and not others:
                    break
                time.sleep(min(0.05, max(0, stop - time.monotonic())))
            else:
                need(os.getpgid(proc.pid) == proc.pid, 'owned_group_anchor_changed')
                os.killpg(proc.pid, signal.SIGKILL)
                forced = True
            stop = time.monotonic() + 5
            while time.monotonic() < stop:
                others = [pid for pid in group_members(proc.pid) if pid != proc.pid]
                if child_exited_unreaped(proc) and not others:
                    break
                time.sleep(min(0.05, max(0, stop - time.monotonic())))
            remaining_before_reap = group_members(proc.pid)
        else:
            if not child_exited_unreaped(proc):
                proc.terminate()
            remaining_before_reap = []
        try:
            code = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if own_group:
                need(os.getpgid(proc.pid) == proc.pid, 'owned_group_anchor_changed')
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
            forced = True
            code = proc.wait(timeout=5)
        records.append({'pid': proc.pid, 'returncode': code, 'already_reaped': False,
                        'forced': forced, 'remaining_before_reap': remaining_before_reap,
                        'remaining_observed': group_members(proc.pid) if own_group else [],
                        'group_signalled_after_reap': False})
    return records


def checked_output(argv):
    return subprocess.check_output(argv, stdin=subprocess.DEVNULL,
                                   stderr=subprocess.PIPE,
                                   timeout=min(30, remaining()))


def git(*args):
    return checked_output(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null',
                           '-C', str(SOURCE), *args]).decode().strip()


def verify_source(frozen):
    need(git('rev-parse', 'HEAD') == COMMIT and git('rev-parse', 'HEAD^{tree}') == TREE,
         'staged_source_identity')
    need(git('status', '--porcelain=v1', '--untracked-files=all') == '', 'staged_source_dirty')
    seen = set()
    for pin in frozen['files']:
        remaining()
        rel = Path(pin['path'])
        need(not rel.is_absolute() and '..' not in rel.parts
             and str(rel) not in seen, 'source_manifest_path')
        seen.add(str(rel))
        path = SOURCE / rel
        need(path.resolve(strict=True) == path, 'source_file_symlink')
        raw = read_owned(path)
        need(len(raw) == pin['bytes'] and sha(raw) == pin['sha256'], 'source_file_pin')
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        need(blob == pin['git_blob'], 'source_file_git_blob')
    need(len(seen) == 62, 'source_manifest_count')
    return len(seen)


def verify_clone(device):
    counts = {'directories': 0, 'regular_files': 0}
    pairs = [(CACHE, TARGET)]
    while pairs:
        remaining()
        src, dst = pairs.pop()
        a, b = src.lstat(), dst.lstat()
        need(a.st_dev == b.st_dev == device and a.st_uid == b.st_uid == 501,
             'clone_custody')
        need((a.st_dev, a.st_ino) != (b.st_dev, b.st_ino), 'clone_shared_inode')
        need(stat.S_IFMT(a.st_mode) == stat.S_IFMT(b.st_mode), 'clone_type')
        if stat.S_ISDIR(a.st_mode):
            counts['directories'] += 1
            with os.scandir(src) as entries:
                left = {entry.name for entry in entries}
            with os.scandir(dst) as entries:
                right = {entry.name for entry in entries}
            need(left == right, 'clone_entry_set')
            pairs.extend((src / name, dst / name) for name in left)
        elif stat.S_ISREG(a.st_mode):
            need(a.st_size == b.st_size, 'clone_file_size')
            counts['regular_files'] += 1
        else:
            # A copied symlink can refer back to a shared cache; never build
            # through such an unproved alias. There is no copy fallback.
            raise RuntimeError('clone_nonregular_entry')
    return counts


def main():
    global preparation_deadline, launch_work_started
    os.umask(0o077)
    began = time.monotonic()
    preparation_deadline = began + PREPARATION_SECONDS
    need(len(sys.argv) == 1, 'fixed_launcher_takes_no_arguments')
    need(platform.system() == 'Darwin' and platform.machine() == 'arm64'
         and os.getuid() == os.geteuid() == 501
         and socket.gethostname() == 'MacBook-Pro.local', 'actual_mac_operator')
    need(all(hasattr(os, name) for name in ('waitid', 'P_PID', 'WEXITED', 'WNOHANG', 'WNOWAIT')),
         'unreaped_child_observation_unavailable')
    need(Path(sys.executable).resolve(strict=True) == PYTHON
         and hash_binary(PYTHON) == PYTHON_SHA, 'fixed_python_pin')
    need(hash_binary(TOOLCHAIN / 'cargo') == CARGO_SHA
         and hash_binary(TOOLCHAIN / 'rustc') == RUSTC_SHA, 'actual_toolchain_pins')
    for name in list(os.environ):
        if name.startswith(('CARGO_', 'GIT_', 'RUSTUP_', 'RUSTC_', 'DYLD_')) or name in (
                'RUSTFLAGS', 'RUSTC', 'RUSTDOC', 'CC', 'CXX', 'AR', 'RANLIB',
                'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS'):
            os.environ.pop(name, None)
    os.environ.update({'PATH': str(TOOLCHAIN) + ':/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin',
                       'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                       'GIT_TERMINAL_PROMPT': '0'})
    volume = plistlib.loads(checked_output(['/usr/sbin/diskutil', 'info', '-plist', '/Volumes/T5']))
    need(volume.get('MountPoint') == '/Volumes/T5' and volume.get('VolumeUUID') == VOLUME_UUID
         and volume.get('FilesystemType') == 'apfs' and volume.get('Writable') is True
         and volume.get('Internal') is False, 'actual_t5_volume')
    device = Path('/Volumes/T5').lstat().st_dev
    directory(Path('/Volumes/T5'), device, mount=True)
    for path in (BASE, ROOT, SOURCE, CONTROL, CACHE, CARGO_HOME):
        owned_ancestors(path, device)
    need(not RESULT.exists() and not RESULT.is_symlink(), 'fresh_launch_receipt_required')
    need(not OUTPUT.exists() and not OUTPUT.is_symlink()
         and not TARGET.parent.exists() and not TARGET.parent.is_symlink(), 'fresh_build_paths_required')
    raw_frozen = read_owned(CONTROL / 'frozen-source.public.json')
    raw_qualified = read_owned(CONTROL / 'clippy-qualified-source.public.json')
    builder_path = CONTROL / 'build_normal.py'
    builder_raw = read_owned(builder_path)
    need(sha(raw_frozen) == FROZEN_SHA and sha(raw_qualified) == QUALIFIED_SHA
         and len(builder_raw) == 5531 and sha(builder_raw) == BUILDER_SHA, 'exact_control_pins')
    frozen, qualified = json.loads(raw_frozen), json.loads(raw_qualified)
    need(frozen['source'] == qualified['source'] == COMMIT
         and frozen['tree'] == qualified['tree'] == TREE
         and qualified['frozen_manifest_sha256'] == FROZEN_SHA, 'qualified_source_binding')
    gate = qualified['strict_clippy']
    need(gate['exit_code'] == 0 and gate['timed_out'] is False and gate['remaining'] == [],
         'strict_gate_not_complete')
    need(gate['args'] == [
        '/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/cargo',
        'clippy', '--release', '--locked', '--offline', '--workspace', '--all-targets',
        '--exclude', 'qrcode', '--', '-D', 'warnings'], 'strict_gate_exact_args')
    profile = qualified['normal_profile']
    for name, value in {'OPT_LEVEL': '3', 'DEBUG_ASSERTIONS': 'true',
                        'OVERFLOW_CHECKS': 'true', 'DEBUG': '0', 'LTO': 'false',
                        'CODEGEN_UNITS': '16', 'PANIC': 'unwind'}.items():
        need(profile['CARGO_PROFILE_RELEASE_' + name] == value, 'normal_release_profile')
    probe_raw = read_owned(PROBE)
    need(sha(probe_raw) == PROBE_SHA, 'actual_lock_probe_pin')
    probe = json.loads(probe_raw)
    need(probe['status'] == 'passed' and probe['cargo']['sha256'] == CARGO_SHA
         and probe['rustc']['sha256'] == RUSTC_SHA
         and probe['owned_child_cleanup']['remaining'] == [], 'actual_lock_probe_result')
    result = {'schema': 'heptabao.mac-normal-launch.v3', 'status': 'failed',
              'source': COMMIT, 'tree': TREE, 'root': str(ROOT),
              'builder_sha256': BUILDER_SHA, 'frozen_sha256': FROZEN_SHA,
              'qualified_sha256': QUALIFIED_SHA, 'probe_sha256': PROBE_SHA,
              'python_sha256': PYTHON_SHA, 'cargo_sha256': CARGO_SHA, 'rustc_sha256': RUSTC_SHA,
              'preparation_budget_seconds': PREPARATION_SECONDS,
              'original_builder_cargo_budget_seconds': 1800,
              'source_cache_scope': 'release build-directory lock; not whole cache or host reservation',
              'cache_copy_mode': 'APFS cp -cR, no fallback',
              'strict_clippy_inherited_excluded_package': 'qrcode',
              'builder_started': False, 'product_service_started': False,
              'full_replacement_qualified': False}
    lock_fd = None
    launch_work_started = True
    subprocess.Popen = TrackedPopen
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        result['verified_source_files'] = verify_source(frozen)
        compile(builder_raw, str(builder_path), 'exec')
        lock_path = CACHE / 'release' / '.cargo-lock'
        owned_ancestors(lock_path.parent, device)
        lock_fd = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW)
        lock_stat = os.fstat(lock_fd)
        need(stat.S_ISREG(lock_stat.st_mode) and lock_stat.st_uid == 501
             and lock_stat.st_dev == device and lock_stat.st_nlink == 1,
             'source_release_lock_custody')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        held_at = time.monotonic_ns()
        need(identity(lock_stat) == identity(os.fstat(lock_fd)) == identity(lock_path.lstat()),
             'source_release_lock_changed')
        TARGET.parent.mkdir(mode=0o700)
        cp = subprocess.Popen(['/bin/cp', '-cR', str(CACHE), str(TARGET)],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, start_new_session=True)
        unused, cp_error = cp.communicate(timeout=remaining())
        need(cp.returncode == 0, 'apfs_clone_failed')
        need(not group_members(cp.pid), 'clone_group_remaining')
        result['clone_inode_verification'] = verify_clone(device)
        need(identity(lock_stat) == identity(os.fstat(lock_fd)) == identity(lock_path.lstat()),
             'source_release_lock_changed')
        result['source_release_lock'] = {
            'path': str(lock_path), 'device': lock_stat.st_dev, 'inode': lock_stat.st_ino,
            'descriptor_mode': 'O_RDONLY|O_NOFOLLOW', 'primitive': 'flock LOCK_EX|LOCK_NB',
            'held_since_monotonic_ns': held_at,
            'verified_through_monotonic_ns': time.monotonic_ns()}
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
        lock_fd = None
        result['preparation_elapsed_seconds'] = time.monotonic() - began
        remaining()
        sys.argv = [str(builder_path), '--source', str(SOURCE), '--output', str(OUTPUT),
                    '--commit', COMMIT, '--tree', TREE, '--toolchain', str(TOOLCHAIN),
                    '--cargo-home', str(CARGO_HOME), '--target', str(TARGET),
                    '--abi', 'aarch64-apple-darwin']
        write_new(CONTROL / 'normal-launch-r3-intent.public.json', result)
        remaining()
        result['builder_started'] = True
        namespace = {'__name__': '__main__', '__file__': str(builder_path)}
        exec(compile(builder_raw, str(builder_path), 'exec'), namespace, namespace)
        need(sha(read_owned(builder_path)) == BUILDER_SHA, 'builder_file_changed')
        native_raw = read_owned(OUTPUT / 'native-build.public.json')
        native = json.loads(native_raw)
        need(native['source_commit'] == COMMIT and native['source_tree'] == TREE
             and native['source_freeze_verified'] is True and native['build_exit_code'] == 0,
             'actual_native_build_receipt')
        result.update(status='built_normal_candidate', native_build_sha256=sha(native_raw),
                      server_sha256=native['binary_sha256'],
                      qualification_scope='normal production build only; no runtime or replacement pass')
    except (Exception, SystemExit) as error:
        result['failure_class'] = type(error).__name__
        result['failure_code'] = str(error) if isinstance(error, (RuntimeError, SystemExit)) else None
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        subprocess.Popen = original_popen
        try:
            result['owned_children'] = cleanup_children()
            if any(item['remaining_observed'] for item in result['owned_children']):
                result['status'] = 'failed'
                result['failure_code'] = 'owned_group_remaining_no_unanchored_signal'
        except Exception as error:
            result['status'] = 'failed'
            result['cleanup_error_class'] = type(error).__name__
        finally:
            # A failed or interrupted clone is stopped while its source
            # release lock is still held. Successful clones released above.
            if lock_fd is not None:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
        result['elapsed_seconds'] = time.monotonic() - began
        digest = write_new(RESULT, result)
        print(json.dumps({'status': result['status'], 'result': str(RESULT),
                          'result_sha256': digest, 'source': COMMIT, 'tree': TREE,
                          'builder_started': result['builder_started'],
                          'full_replacement_qualified': False}, sort_keys=True), flush=True)
    return 0 if result['status'] == 'built_normal_candidate' else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status': 'failed_after_launch_started' if launch_work_started else 'refused_before_launch',
                          'error_class': type(error).__name__,
                          'error_code': str(error) if isinstance(error, RuntimeError) else None},
                         sort_keys=True), flush=True)
        raise SystemExit(2) from None
