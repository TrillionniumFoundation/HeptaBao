#!/usr/bin/env python3
"""Fresh isolated synthetic-data snapshot attempt with one declared 2400-second budget."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time

BASE = Path('/Volumes/T5/hepta-vnext-recovery-20261013')
ROOT = BASE / 'continuation-20261104-ha-snapshot-acl-denial-61ff-r1'
SOURCE = ROOT / 'source'
ORIGINAL_CONTROL = ROOT / 'control'
PREVIOUS_CONTROL = ORIGINAL_CONTROL / 'normal-attempt-r3'
CONTROL = ORIGINAL_CONTROL / 'normal-attempt-r5'
BASE_ROOT = BASE / 'continuation-20261104-ha-unified-normal-61ff-r1'
BASE_SOURCE = BASE_ROOT / 'source'
BASE_COMMIT = '70714605c39014bea93545f7f6aa4217d2a23544'
BASE_TREE = 'ef0ae63704a06b7dda1038e02abcc3233a2a438f'
REVIEW_COMMIT = '21a521e3e59af291dd2abc6721e8559e06338657'
INPUT_TREE = '625b0a5d4e2bce62fe0b014edff9c18f96840a3c'
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python')
PYTHON_SHA = '7ecc1ecbf9daa9303c4bf502ff62ffdd9010ed5c08729d470ae9380c10ce1211'
TOOLCHAIN = Path('/Users/qianqi/.rustup/toolchains/1.98.0-aarch64-apple-darwin/bin')
CARGO_SHA = '1de2e84c15443b70444eecfa959ff9099dd8c1a5606b6d9ef5bc0ea9c25bc7f9'
RUSTC_SHA = 'a11618eca0956a8aa4372c2bc898690b513cbdfa2cb9125b2a5301e360ed5b49'
VOLUME_UUID = 'FB804D1B-24CB-4D6E-AEA7-A9E180807758'
PROBE = BASE / 'continuation-20261104-ha-cargo-lock-probe-61ff-r1/result.public.json'
PROBE_SHA = 'd9be1b814a0f7834f22eef219c765a3dae8ede2b6be60ca02f1b88600cc69403'
creating = False
pending_signal = None


def need(ok, code):
    if not ok:
        raise RuntimeError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def remaining(until):
    left = until - time.monotonic()
    need(left > 0, 'original_absolute_deadline')
    return left


def read_owned(path, limit=4 * 1024 * 1024):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 501
             and before.st_nlink == 1 and before.st_size <= limit, 'file_custody')
        chunks, count = [], 0
        while count <= limit:
            data = os.read(fd, min(65536, limit + 1 - count))
            if not data:
                break
            chunks.append(data)
            count += len(data)
        need(count == before.st_size
             and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
             'file_changed')
        return b''.join(chunks)
    finally:
        os.close(fd)


def hash_owned(path, until=None, limit=1024 * 1024 * 1024, single_link=True):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 501
             and (not single_link or before.st_nlink == 1)
             and before.st_size <= limit, 'hash_file_custody')
        digest, count = hashlib.sha256(), 0
        while True:
            if until is not None:
                remaining(until)
            data = os.read(fd, 1024 * 1024)
            if not data:
                break
            digest.update(data)
            count += len(data)
        need(count == before.st_size
             and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
             'hashed_file_changed')
        return digest.hexdigest()
    finally:
        os.close(fd)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_raw(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    sync_dir(path.parent)
    return sha(raw)


def write_json(path, value):
    return write_raw(path, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())


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


def interrupted(signum, frame):
    global pending_signal
    if creating:
        pending_signal = signum
    else:
        raise RuntimeError('owned_job_interrupted')


def group_members(pgid):
    proc = subprocess.Popen(['/bin/ps', '-axo', 'pid=,pgid='],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    try:
        output, unused = proc.communicate(timeout=5)
    except BaseException:
        proc.kill()
        proc.communicate(timeout=5)
        raise
    need(proc.returncode == 0, 'group_observation_failed')
    return [int(fields[0]) for row in output.splitlines()
            if len(fields := row.split()) == 2 and int(fields[1]) == pgid]


class OwnedRunner:
    """Only a still-unreaped direct child authorizes group cleanup."""
    def __init__(self, output, environment):
        self.output = output
        self.environment = environment
        self.child = None
        self.reaped = True
        self.records = []

    def exited(self):
        need(self.child is not None and not self.reaped, 'owned_unreaped_child_required')
        event = os.waitid(os.P_PID, self.child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        need(event is None or event.si_pid == self.child.pid, 'unexpected_waitid_identity')
        return event is not None

    def signal(self, signum):
        exited = self.exited()
        if not exited:
            try:
                need(os.getpgid(self.child.pid) == self.child.pid, 'owned_group_changed')
            except ProcessLookupError:
                need(self.exited(), 'live_owned_group_missing')
        try:
            os.killpg(self.child.pid, signum)
        except ProcessLookupError:
            pass

    def cleanup(self):
        if self.child is None:
            return None
        if self.reaped:
            return {'pid': self.child.pid, 'returncode': self.child.returncode,
                    'already_reaped': True, 'forced': False,
                    'remaining': group_members(self.child.pid),
                    'group_signalled_after_reap': False}
        exited = self.exited()
        others = [pid for pid in group_members(self.child.pid) if pid != self.child.pid]
        forced = False
        if not exited or others:
            self.signal(signal.SIGTERM)
            stop = time.monotonic() + 5
            while time.monotonic() < stop:
                exited = self.exited()
                others = [pid for pid in group_members(self.child.pid) if pid != self.child.pid]
                if exited and not others:
                    break
                time.sleep(0.025)
            if not exited or others:
                self.signal(signal.SIGKILL)
                forced = True
                stop = time.monotonic() + 5
                while time.monotonic() < stop:
                    exited = self.exited()
                    others = [pid for pid in group_members(self.child.pid) if pid != self.child.pid]
                    if exited and not others:
                        break
                    time.sleep(0.025)
        # No later group signal is allowed once this original anchor is reaped.
        code = self.child.wait(timeout=5)
        self.reaped = True
        return {'pid': self.child.pid, 'returncode': code, 'already_reaped': False,
                'forced': forced, 'remaining': group_members(self.child.pid),
                'group_cleanup_before_reap': True, 'group_signalled_after_reap': False}

    def run(self, label, argv, until, cwd=SOURCE, expect_zero=True):
        global creating
        remaining(until)
        need(self.child is None or self.reaped, 'one_owned_child')
        need(re.fullmatch('[a-z0-9_-]+', label), 'closed_command_label')
        stdout_path = self.output / (label + '.stdout')
        stderr_path = self.output / (label + '.stderr')
        began = time.monotonic()
        record = {'label': label, 'argv': argv, 'cwd': str(cwd),
                  'timed_out': False, 'exit_code': None,
                  'remaining_at_start_seconds': remaining(until)}
        self.records.append(record)
        error = None
        with stdout_path.open('xb') as so, stderr_path.open('xb') as se:
            try:
                creating = True
                try:
                    self.child = subprocess.Popen(
                        argv, cwd=cwd, env=self.environment,
                        stdin=subprocess.DEVNULL, stdout=so, stderr=se,
                        start_new_session=True)
                    self.reaped = False
                    record['owned_pgid'] = self.child.pid
                finally:
                    creating = False
                if pending_signal is not None:
                    raise RuntimeError('interrupted_during_spawn')
                while not self.exited():
                    if time.monotonic() >= until:
                        record['timed_out'] = True
                        raise RuntimeError('original_absolute_deadline')
                    time.sleep(min(0.025, max(0, until - time.monotonic())))
            except BaseException as exc:
                error = exc
                record['error_class'] = type(exc).__name__
                record['error_code'] = str(exc) if isinstance(exc, RuntimeError) else None
            finally:
                cleanup = self.cleanup()
                record['cleanup'] = cleanup
                if cleanup is not None:
                    record['exit_code'] = cleanup['returncode']
                    record['remaining'] = cleanup['remaining']
                so.flush()
                se.flush()
                os.fsync(so.fileno())
                os.fsync(se.fileno())
        record.update(elapsed_seconds=time.monotonic() - began,
                      remaining_at_end_seconds=max(0, until - time.monotonic()),
                      stdout_sha256=hash_owned(stdout_path),
                      stderr_sha256=hash_owned(stderr_path),
                      stdout_bytes=stdout_path.stat().st_size,
                      stderr_bytes=stderr_path.stat().st_size)
        write_json(self.output / (label + '.public.json'), record)
        if error is not None:
            raise error
        need(not record['timed_out'] and not record.get('remaining')
             and not record['cleanup']['forced'], 'command_cleanup_or_deadline_failed')
        if expect_zero:
            need(record['exit_code'] == 0, 'command_nonzero_' + label)
        remaining(until)
        return read_owned(stdout_path, 64 * 1024 * 1024)

    def git(self, label, until, *args, directory_path=SOURCE):
        return self.run(label, ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null',
                                '-c', 'commit.gpgsign=false', '-C', str(directory_path),
                                *args], until).decode('utf-8', 'strict').strip()


def clean_environment():
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('CARGO_', 'GIT_', 'RUSTUP_', 'RUSTC_', 'DYLD_'))
           and key not in ('RUSTFLAGS', 'RUSTC', 'RUSTDOC', 'CC', 'CXX', 'AR', 'RANLIB',
                           'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS')}
    env.update({'PATH': str(TOOLCHAIN) + ':/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin',
                'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
                'GIT_AUTHOR_NAME': 'HeptaBao isolated verification',
                'GIT_AUTHOR_EMAIL': 'heptabao-verification@localhost',
                'GIT_COMMITTER_NAME': 'HeptaBao isolated verification',
                'GIT_COMMITTER_EMAIL': 'heptabao-verification@localhost'})
    return env


def preflight_host(until):
    remaining(until)
    need(platform.system() == 'Darwin' and platform.machine() == 'arm64'
         and os.getuid() == os.geteuid() == 501
         and socket.gethostname() == 'MacBook-Pro.local', 'actual_mac_operator')
    need(all(hasattr(os, name) for name in ('waitid', 'P_PID', 'WEXITED', 'WNOHANG', 'WNOWAIT'))
         and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, 'non_reaping_wait_required')
    need(Path(sys.executable).resolve(strict=True) == PYTHON
         and hash_owned(PYTHON, until) == PYTHON_SHA, 'fixed_python_pin')
    raw = subprocess.check_output(['/usr/sbin/diskutil', 'info', '-plist', '/Volumes/T5'],
                                  stdin=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                  timeout=min(10, remaining(until)))
    volume = plistlib.loads(raw)
    need(volume.get('MountPoint') == '/Volumes/T5' and volume.get('VolumeUUID') == VOLUME_UUID
         and volume.get('FilesystemType') == 'apfs' and volume.get('Writable') is True
         and volume.get('Internal') is False, 'actual_t5_volume')
    device = Path('/Volumes/T5').lstat().st_dev
    directory(Path('/Volumes/T5'), device, mount=True)
    owned_ancestors(BASE, device)
    probe_raw = read_owned(PROBE)
    probe = json.loads(probe_raw)
    need(sha(probe_raw) == PROBE_SHA and probe['status'] == 'passed'
         and probe['cargo']['sha256'] == CARGO_SHA and probe['rustc']['sha256'] == RUSTC_SHA
         and probe['owned_child_cleanup']['remaining'] == [], 'actual_cargo_lock_probe')
    return device


def source_file_pins(manifest, device, expected_count):
    checked = []
    seen = set()
    for item in manifest['files']:
        rel = Path(item['path'])
        need(not rel.is_absolute() and '..' not in rel.parts
             and str(rel) not in seen, 'source_pin_path')
        seen.add(str(rel))
        path = SOURCE / rel
        owned_ancestors(path.parent, device)
        raw = read_owned(path)
        need(path.lstat().st_dev == device and len(raw) == item['bytes']
             and sha(raw) == item['sha256'] and blob(raw) == item['git_blob'], 'source_pin')
        checked.append({'path': str(rel), 'bytes': len(raw),
                        'sha256': sha(raw), 'git_blob': blob(raw)})
    need(len(checked) == expected_count, 'source_pin_count')
    return checked

CACHE = BASE_ROOT / 'runtime.noindex' / 'target'
TARGET = ROOT / 'runtime.noindex' / 'target'
CARGO_HOME = BASE / 'r13-full-native-cargo-home-r1'
OUTPUT = ROOT / 'normal-default-r5'
CARGO_SECONDS = 2400.0
PREVIOUS_STARTED_MONOTONIC = 2709075.262300833
PREVIOUS_DEADLINE_MONOTONIC = 2711475.262300833
PREVIOUS_DEADLINE_UNIX = 1793825628
NORMAL_PROFILE = {
    'CARGO_PROFILE_RELEASE_OPT_LEVEL': '3',
    'CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS': 'true',
    'CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS': 'true',
    'CARGO_PROFILE_RELEASE_DEBUG': '0',
    'CARGO_PROFILE_RELEASE_LTO': 'false',
    'CARGO_PROFILE_RELEASE_CODEGEN_UNITS': '16',
    'CARGO_PROFILE_RELEASE_PANIC': 'unwind',
}
FEATURES = ['default', 'native-v6-ha', 'native-v6-storage']
CRITICAL_TESTS = [
    "service::native_v6_ha_pipeline_tests::historical_restore_tests::cold_dr_tests::standby_http_tests::acl_denial_tests::formal_native_nonroot_snapshot_acl_and_historical_restore_use_original_update_actor",
    "service::native_v6_ha_pipeline_tests::historical_restore_tests::cold_dr_tests::standby_http_tests::acl_denial_tests::formal_native_standby_acl_denial_commits_floor_without_transfer_lease_and_survives_cold",
    "service::native_v6_ha_pipeline_tests::historical_restore_tests::cold_dr_tests::standby_http_tests::acl_denial_tests::formal_native_standby_original_snapshot_actor_expiry_before_floor_returns_proved_403",
    "service::native_v6_ha_pipeline_tests::historical_restore_tests::cold_dr_tests::standby_http_tests::acl_denial_tests::formal_native_snapshot_clock_actual_mtls_nochange_keeps_full_local_checkpoints",
    "service::native_v6_ha_pipeline_tests::historical_restore_tests::cold_dr_tests::standby_http_tests::acl_denial_tests::formal_native_http_consistency_forward_restricts_local_snapshot_and_no_forward_kv",
    "service::native_v6_ha_pipeline_tests::historical_restore_tests::cold_dr_tests::standby_http_tests::formal_native_standby_snapshot_read_restore_validation_and_no_forward_use_real_owners",
    "service::native_v6_ha_pipeline_tests::historical_restore_tests::cold_dr_tests::standby_http_tests::formal_native_standby_snapshot_finite_tokens_redirect_without_consumption",
    "service::native_v6_ha_pipeline_tests::historical_restore_tests::cold_dr_tests::standby_http_tests::formal_native_standby_snapshot_late_root_change_and_lost_quorum_refuse_delivery",
    "service::native_v6_ha_pipeline_tests::historical_restore_tests::cold_dr_tests::standby_http_tests::formal_native_standby_ttl_snapshot_commits_real_leader_floor_and_survives_cold_restart",
    "ha::snapshot_clock::tests::snapshot_clock_denied_requires_original_binding_exact_successor_and_only_status_403",
    "service::native_v6_ha_pipeline_tests::historical_restore_tests::cold_dr_tests::standby_http_tests::formal_native_standby_snapshot_missing_api_origin_remains_503",
    "service::native_storage::tests::configured_native_activation_rejects_unsupported_live_engine_without_retiring_v5",
    "service::native_v6_ha_pipeline_tests::historical_restore_tests::cold_dr_tests::cold_dr_unsupported_engine_archive_refused_without_destination_or_source_loss",
    "http::snapshot_accept_tests::native_snapshot_https_json_accept_keeps_actor_namespace_seal_and_archive_refusals"
]
work_started = False


def verify_clone(device, until):
    counts = {'directories': 0, 'regular_files': 0}
    pairs = [(CACHE, TARGET)]
    while pairs:
        remaining(until)
        src, dst = pairs.pop()
        before, after = src.lstat(), dst.lstat()
        need(before.st_dev == after.st_dev == device
             and before.st_uid == after.st_uid == 501, 'clone_custody')
        need((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino), 'clone_shared_inode')
        need(stat.S_IFMT(before.st_mode) == stat.S_IFMT(after.st_mode), 'clone_type')
        if stat.S_ISDIR(before.st_mode):
            counts['directories'] += 1
            with os.scandir(src) as entries:
                left = {entry.name for entry in entries}
            with os.scandir(dst) as entries:
                right = {entry.name for entry in entries}
            need(left == right, 'clone_entry_set')
            pairs.extend((src / name, dst / name) for name in left)
        elif stat.S_ISREG(before.st_mode):
            need(before.st_size == after.st_size, 'clone_file_size')
            counts['regular_files'] += 1
        else:
            raise RuntimeError('clone_nonregular_entry')
    return counts


def source_state(runner, label, until):
    return {
        'commit': runner.git(label + '-head', until, 'rev-parse', 'HEAD'),
        'tree': runner.git(label + '-tree', until, 'rev-parse', 'HEAD^{tree}'),
        'status': runner.git(label + '-clean', until, 'status', '--porcelain=v1', '--untracked-files=all'),
    }


def artifact_events(raw):
    events = []
    for line in raw.splitlines():
        try:
            value = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        if isinstance(value, dict):
            events.append(value)
    need(any(event.get('reason') == 'build-finished' and event.get('success') is True
             for event in events), 'cargo_build_finished_missing')
    return events


def retain_artifact(event, name, device, until, test):
    need(sorted(event.get('features', [])) == FEATURES, 'actual_artifact_features')
    profile = event.get('profile', {})
    need(str(profile.get('opt_level')) == '3'
         and profile.get('debug_assertions') is True
         and profile.get('overflow_checks') is True
         and profile.get('test') is test, 'actual_artifact_profile')
    original = Path(event['executable'])
    need(original.is_absolute() and original.resolve(strict=True) == original
         and TARGET / 'release' in original.parents, 'artifact_target_boundary')
    owned_ancestors(original.parent, device)
    target = OUTPUT / 'artifacts' / name
    fd = os.open(original, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 501
             and before.st_dev == device and before.st_size <= 1024 * 1024 * 1024,
             'artifact_file_custody')
        out_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
        digest, count = hashlib.sha256(), 0
        with os.fdopen(out_fd, 'wb') as output:
            while True:
                remaining(until)
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                output.write(chunk)
                digest.update(chunk)
                count += len(chunk)
            output.flush()
            os.fsync(output.fileno())
        need(count == before.st_size and identity(before) == identity(os.fstat(fd))
             == identity(original.lstat()), 'artifact_changed_during_copy')
    finally:
        os.close(fd)
    expected = digest.hexdigest()
    need(hash_owned(target, until) == expected
         and hash_owned(original, until, single_link=False) == expected, 'retained_artifact_pin')
    sync_dir(target.parent)
    return {'path': str(target), 'sha256': expected, 'bytes': count,
            'compiler_executable': str(original), 'features': event['features'],
            'profile': profile, 'fresh': event.get('fresh')}




PREVIOUS_DRIVER_SHA = '7a12c1279c7ee5404c69c3bb0dc86a719e1ca53c7a3cc21d5d28cfbc6b828704'
PREVIOUS_RESULT_SHA = 'a90a6abf56405d3f006171554ebac16ffe89b8bf20240526a38dc7fc1f0ef508'
PREVIOUS_FROZEN_SHA = 'ca909caf1a9ca02e6d2122c916dd4d3d96adb0099bfaf0a87f2c51c7bce70d21'
PREVIOUS_STRICT_SHA = 'f270834ffaead917919495e4a315cf7131f2174917b5c1c9b9aed462b654d850'
PREVIOUS_COMPILE_SHA = '8e9346646a10e2d4fdde62c1c130820535afbc44f6051b05378f12461bb47213'
PREVIOUS_SOURCE = 'f06478d8f5451d3a4e5ab86f73bccd37612d378f'
PREVIOUS_TREE = '5389e69cc0c9b36dcb48d7480ac109a811745bec'
PATCH_SHA = '6e809de9c1ff4c011a552795a503d44fa8552ae0e8adccffc1e26cde973b14a5'
CHANGED_FILES = [{"path":"crates/heptabao-server/src/http_formal_api_fixture.rs","bytes":11432,"sha256":"0380d128a33a915a433866abbf9ee541b979ab7da919bfc2734e1befee57fdc4","git_blob":"cc8105bb10dbac9827b5135db1182b7a94fb1bec"},{"path":"crates/heptabao-server/src/service_snapshot_transfer.rs","bytes":64504,"sha256":"ac2b39c922f62c0d5b616e12c574934617e8dd0ab55bfa7524007c7c2c08f8fe","git_blob":"74e822d9ae06eef1d5c308c4865b8e5fa8dca7cc"},{"path":"crates/heptabao-server/src/http_snapshot_accept_tests.rs","bytes":27709,"sha256":"46857f23f2e3ddf57916b92fd71a48e10d7ac4214fd06be68ccb013b3f1e02d5","git_blob":"703a7183185a4fee775a95109e7b084c1aa315f6"}]
ALL_FILES = [{"path":"crates/heptabao-server/src/service.rs","bytes":520380,"sha256":"ecc34e93aeec0832943910aeab443009bfcad4f4cbc6d721b7a2fb213c599313","git_blob":"965df43d4bd0b43f15160d8d7387aa49c2432250"},{"path":"crates/heptabao-server/src/service_snapshot_transfer.rs","bytes":64504,"sha256":"ac2b39c922f62c0d5b616e12c574934617e8dd0ab55bfa7524007c7c2c08f8fe","git_blob":"74e822d9ae06eef1d5c308c4865b8e5fa8dca7cc"},{"path":"crates/heptabao-server/src/service_snapshot_v6_ha.rs","bytes":22940,"sha256":"439777e663ca6812c39eba52c8bdc420ad5c570bd39befe4dfd3b3ed1bf2a92a","git_blob":"5c4b8a99208ddfed8585067ebdbbd9b374c22804"},{"path":"crates/heptabao-server/src/service_snapshot_v6.rs","bytes":27950,"sha256":"4bc682d4565942e10d93a72ea48de4e1e9c44f7d7891750899cebaa0cb0b65f0","git_blob":"a33a8cb8466d9b5b6769583f393f05d55360c36f"},{"path":"crates/heptabao-server/src/service_snapshot_clock.rs","bytes":14207,"sha256":"3d540aaf346b91ee45ef1f9d63c09ca2c3f05d5904953864a370027d57b18ed0","git_blob":"ed85659b2480759ba88301dede9fe9028cd61751"},{"path":"crates/heptabao-server/src/service_snapshot_denial.rs","bytes":14526,"sha256":"9524a08f9636b9e068ffaa156acbc8081314454698bb71fa2c07b01209d3f522","git_blob":"d19daa78b09a443fa1fcb55447e256b8372ba41f"},{"path":"crates/heptabao-server/src/snapshot_file.rs","bytes":16786,"sha256":"98d3215819659dce42213be41215827cb19110311221ea460a09cacb63576414","git_blob":"af44a032d401e0269809aedd07cb9429ea151af9"},{"path":"crates/heptabao-server/src/ha_snapshot_clock.rs","bytes":38808,"sha256":"1319fa425aaa656f266e3b4e3bb064b7b3326272c8d3794744e2d1dc656f1d47","git_blob":"07e5587d47632a9a693bbbfad1d16d5bcdfbd2af"},{"path":"crates/heptabao-server/src/service_snapshot_v6_ha_restore.rs","bytes":44113,"sha256":"7b420b0e859c7cd7376687a9404b3ae37678c3dd98eb55e55e0f51187a7f812d","git_blob":"ebb045e333f78144e5a9a035d74ce789f5c36a76"},{"path":"crates/heptabao-server/src/service_native_v6_ha_standby_http_tests.rs","bytes":18430,"sha256":"5e9ba6230ba492bd7f25bee095d8c5bd1f6361375cef95041eeea772f5b417d4","git_blob":"3f3d70ced4c9e137b7ff61a1b4668822e737ac59"},{"path":"crates/heptabao-server/src/service_native_v6_ha_snapshot_acl_tests.rs","bytes":18963,"sha256":"be1c636aa2115305bfd20c2e7b8ea687aa0c36bb2113bd308fd7e3fa44c6651c","git_blob":"fbf227834e90f0bfa6b0e289e2ee971fa5500c8a"},{"path":"crates/heptabao-server/src/http.rs","bytes":231872,"sha256":"98ecbfc23750153e99a48b017c2235d6bcfbfd57160a7e0fc9c8dcdd29dfcb58","git_blob":"3801150b71e68d75afb46136e31dce05841fe081"},{"path":"crates/heptabao-server/src/http_consistency.rs","bytes":16843,"sha256":"d8d20d8c69e6cf02a29801a3f05645d8ba58138d0d97c72cdd20994c2caa56cf","git_blob":"ed64b70e48cb8d549597e0102cf9003e0c1e606f"},{"path":"crates/heptabao-server/src/http_formal_api_fixture.rs","bytes":11432,"sha256":"0380d128a33a915a433866abbf9ee541b979ab7da919bfc2734e1befee57fdc4","git_blob":"cc8105bb10dbac9827b5135db1182b7a94fb1bec"},{"path":"crates/heptabao-server/src/service_native_v6_ha_formal_api_pipeline_tests.rs","bytes":7773,"sha256":"d2128db04e062b186ec3e04bdabd39fcf759ef576447a65d92c8f866931e0240","git_blob":"e5b89de07763968c517665152b1f3744c06e85cf"},{"path":"crates/heptabao-server/src/service_native_v6_ha_pipeline_tests.rs","bytes":72052,"sha256":"a269af3e4f35efaed11a9b7726c6d04ab581bb9c53d4fa97993325efbdb9f500","git_blob":"ea282af1c03e61961c91b9b127a73accd1936f77"},{"path":"crates/heptabao-server/src/service_native_v6_ha_cold_restore_tests.rs","bytes":34048,"sha256":"16bbb285164867c1afb3fd97428455ce6e3d68b503981c4df2d1eec275034233","git_blob":"6a2c2940afe460843738fe938ced2a26a409182f"},{"path":"crates/heptabao-server/src/service_native_storage_tests.rs","bytes":26293,"sha256":"2763e39946aaa67b340bddec60bd703a5f17531166cbc6acd704790381bb86b8","git_blob":"4953a421615ea06980284819f53be0ef603c8d88"},{"path":"qa/openbao-acceptance/kv2_271_lossless_native_live.py","bytes":49483,"sha256":"33377bc52b520c53aa2195ee68556581ea78036fbb887ffc2e5bb6fd4d985e47","git_blob":"def438a011a389920e824b3ab29f853a4db862ed"},{"path":"tools/migration/openbao271_kv2_native_large_migrate.py","bytes":16591,"sha256":"8043bce5e2443ca10f09d88dc854fc1a850ae4ac8b904763fbfc1ae3fa2de52a","git_blob":"6f1e114e545c1f292c696f4cd881a982db95114b"},{"path":"crates/heptabao-server/src/http_snapshot_accept_tests.rs","bytes":27709,"sha256":"46857f23f2e3ddf57916b92fd71a48e10d7ac4214fd06be68ccb013b3f1e02d5","git_blob":"703a7183185a4fee775a95109e7b084c1aa315f6"}]
KNOWN_GAPS = ["A first new expiry observed only after the one leader clock writer returns 503 without replay; it is not mislabeled as a proved entry-time Denied 403.","Other pre-plan errors such as a quota refusal are not covered by the new snapshot denial capsule.","Ordinary KV X-Vault-No-Request-Forwarding plus global precision still needs an independent closed authority and metadata-only leader clock path.","Listener consistency Forward restriction is implemented; its r3 component failed during TLS setup and its normal-wire validation remains unqualified.","Other non-clock maintenance states remain ineligible for this local standby snapshot path.","Original 7071 full workspace has eight retained actual failures. The actual r3 fourteen-component run passed five and failed nine; this new fourteen-component attempt is not a full workspace rerun.","Fixed OpenBao 2.7.1 accepted a truncated gzip footer and concatenated archive with actual restore; current archive rejection is an unresolved compatibility difference.","Six ordinary KV and consistency cases still returned 307 instead of official 200 on the normal 7071 wire observer; the new immutable KV clock closure is not included here.","Normal-binary HTTPS 34-case observer, physical three-host HA, full34 migration/recovery and production cutover remain unqualified for this source.","Moving the complete native transport eligibility check after synchronization also lets a native-disabled V5 standby run its existing V5 sync before redirect. A sync failure may return 503 instead of the former immediate 307; the fourteen cases do not qualify that branch."]


def main():
    global work_started
    os.umask(0o077)
    began = time.monotonic()
    began_utc = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    cargo_until = began + CARGO_SECONDS
    need(time.time() > PREVIOUS_DEADLINE_UNIX, 'previous_attempt_window_not_expired')
    need(len(sys.argv) == 3 and sha(__source_raw__) == sys.argv[1]
         and sha(__packet_raw__) == sys.argv[2], 'exact_new_attempt_sources')
    device = preflight_host(cargo_until)
    need(hash_owned(TOOLCHAIN / 'cargo', cargo_until, single_link=False) == CARGO_SHA
         and hash_owned(TOOLCHAIN / 'rustc', cargo_until, single_link=False) == RUSTC_SHA,
         'actual_toolchain_pins')
    for path in (ROOT, SOURCE, ORIGINAL_CONTROL, PREVIOUS_CONTROL, TARGET, CARGO_HOME):
        owned_ancestors(path, device)
    need(hash_owned(PREVIOUS_CONTROL / 'run_normal_attempt_r3.py', cargo_until)
         == PREVIOUS_DRIVER_SHA, 'previous_driver_unchanged')
    previous_raw = read_owned(PREVIOUS_CONTROL / 'candidate-normal-result.public.json')
    frozen_raw = read_owned(PREVIOUS_CONTROL / 'frozen-source.public.json')
    strict_raw = read_owned(ROOT / 'normal-default-r3/strict-clippy.public.json')
    compile_raw = read_owned(ROOT / 'normal-default-r3/server-tests-compile.public.json')
    need(sha(previous_raw) == PREVIOUS_RESULT_SHA and sha(frozen_raw) == PREVIOUS_FROZEN_SHA
         and sha(strict_raw) == PREVIOUS_STRICT_SHA and sha(compile_raw) == PREVIOUS_COMPILE_SHA,
         'actual_previous_receipt_pins')
    previous, old_frozen, old_strict, old_compile = map(
        json.loads, (previous_raw, frozen_raw, strict_raw, compile_raw))
    need(previous['status'] == 'failed'
         and previous['failure_code'] == 'critical_test_failures'
         and len(previous['completed_tests']) == 5
         and len(previous['observed_tests']) == 14 and len(previous['failed_tests']) == 9
         and [item['name'] for item in previous['observed_tests']] == CRITICAL_TESTS
         and sum(item['passed'] is True for item in previous['observed_tests']) == 5
         and previous['frozen_source'] == {
             'commit': PREVIOUS_SOURCE, 'tree': PREVIOUS_TREE, 'status': ''}
         and previous['cargo_started_monotonic'] == PREVIOUS_STARTED_MONOTONIC
         and previous['cargo_deadline_monotonic'] == PREVIOUS_DEADLINE_MONOTONIC
         and previous['shared_cargo_budget_seconds'] == CARGO_SECONDS
         and previous['last_owned_child_cleanup']['remaining'] == []
         and previous['last_owned_child_cleanup']['group_signalled_after_reap'] is False
         and previous['last_owned_child_cleanup']['forced'] is False,
         'previous_actual_red_and_original_budget')
    need(len(previous['commands']) == 38
         and all(isinstance(record['exit_code'], int)
                 and record['timed_out'] is False
                 and record['remaining'] == []
                 and record['cleanup']['remaining'] == []
                 and record['cleanup']['forced'] is False
                 and record['cleanup']['group_signalled_after_reap'] is False
                 for record in previous['commands']), 'previous_all_commands_completed_cleanup')
    need(old_strict['exit_code'] == 0 and old_strict['timed_out'] is False
         and old_strict['remaining'] == [] and old_strict['cleanup']['forced'] is False
         and old_compile['timed_out'] is False and old_compile['exit_code'] == 0
         and old_compile['remaining'] == [] and old_compile['cleanup']['forced'] is False
         and old_compile['cleanup']['group_cleanup_before_reap'] is True
         and old_compile['cleanup']['group_signalled_after_reap'] is False,
         'previous_actual_strict_and_compile_cleanup')
    need(old_frozen['source'] == PREVIOUS_SOURCE and old_frozen['tree'] == PREVIOUS_TREE
         and old_frozen['source_path'] == str(SOURCE) and old_frozen['formatted']
         and not old_frozen['compiled'] and len(old_frozen['files']) == 21,
         'previous_frozen_identity')
    need(set(__payload__) == {'driver', 'files', 'changed_files', 'patch'}
         and __payload__['files'] == ALL_FILES
         and __payload__['changed_files'] == CHANGED_FILES
         and sha(__payload__['patch'].encode()) == PATCH_SHA, 'closed_new_source_payload')
    manifest = {'files': ALL_FILES, 'known_remaining_product_gaps': KNOWN_GAPS}
    need(not CONTROL.exists() and not CONTROL.is_symlink()
         and not OUTPUT.exists() and not OUTPUT.is_symlink(), 'fresh_new_attempt_output')
    need(shutil.disk_usage(ROOT).free >= 1024 * 1024 * 1024, 'build_disk_space')
    source_file_pins(old_frozen, device, 21)
    remaining(cargo_until)
    work_started = True
    CONTROL.mkdir(mode=0o700)
    OUTPUT.mkdir(mode=0o700)
    (OUTPUT / 'artifacts').mkdir(mode=0o700)
    write_raw(CONTROL / 'run_normal_attempt_r5.py', __source_raw__)
    write_raw(CONTROL / 'input.public.json', __packet_raw__)
    patch_path = CONTROL / 'source.patch'
    write_raw(patch_path, __payload__['patch'].encode())
    env = clean_environment()
    env.update(NORMAL_PROFILE)
    env.update({'CARGO_HOME': str(CARGO_HOME), 'CARGO_TARGET_DIR': str(TARGET),
                'CARGO_BUILD_JOBS': '2', 'CARGO_TERM_COLOR': 'never', 'RUSTFLAGS': ''})
    runner = OwnedRunner(OUTPUT, env)
    result = {
        'schema': 'heptabao.mac-snapshot-api-normal-attempt.v2', 'status': 'failed',
        'root': str(ROOT), 'source_path': str(SOURCE), 'target_path': str(TARGET),
        'review_commit': REVIEW_COMMIT, 'input_tree': INPUT_TREE,
        'driver_sha256': sys.argv[1], 'packet_sha256': sys.argv[2],
        'previous_driver_sha256': PREVIOUS_DRIVER_SHA,
        'previous_failed_result_sha256': PREVIOUS_RESULT_SHA,
        'previous_frozen_sha256': PREVIOUS_FROZEN_SHA, 'patch_sha256': PATCH_SHA,
        'python_sha256': PYTHON_SHA, 'cargo_sha256': CARGO_SHA, 'rustc_sha256': RUSTC_SHA,
        'shared_cargo_budget_seconds': CARGO_SECONDS,
        'cargo_started_monotonic': began, 'cargo_deadline_monotonic': cargo_until,
        'cargo_started_utc': began_utc,
        'attempt_relation': 'new declared 2400-second attempt after expired r3 window and known cleanup',
        'attempt_label': 'normal-attempt-r5',
        'prior_observation': {'tests': 14, 'passed': 5, 'failed': 9},
        'real_credentials_used': False,
        'previous_budget_extended': False, 'cache_cloned_again': False,
        'normal_profile': NORMAL_PROFILE, 'cargo_build_jobs': 2,
        'strict_clippy_inherited_excluded_package': 'qrcode',
        'product_service_started': False, 'production_changed': False,
        'multi_physical_host_ha_executed': False, 'full_replacement_qualified': False,
        'critical_tests': CRITICAL_TESTS, 'completed_tests': [], 'observed_tests': [],
        'known_remaining_product_gaps': KNOWN_GAPS,
    }
    lock_fd = None
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        before = source_state(runner, 'input', cargo_until)
        need(before == {'commit': PREVIOUS_SOURCE, 'tree': PREVIOUS_TREE, 'status': ''},
             'previous_source_changed')
        result['input_source'] = before
        result['previous_product_files'] = source_file_pins(old_frozen, device, 21)
        processes = runner.run('preparation-process-snapshot',
                               ['/bin/ps', '-axo', 'pid=,ppid=,pgid=,comm='],
                               cargo_until).decode('utf-8', 'strict')
        blockers = []
        for row in processes.splitlines():
            fields = row.split(maxsplit=3)
            if len(fields) != 4:
                continue
            name = Path(fields[3]).name
            if name in ('cargo', 'rustc', 'heptabao-server', 'heptabao-seed') or name.startswith('heptabao_server-'):
                blockers.append({'pid': int(fields[0]), 'ppid': int(fields[1]),
                                 'pgid': int(fields[2]), 'executable': fields[3]})
        result['preparation_process_blockers'] = blockers
        need(not blockers, 'external_compiler_or_product_process_present')
        lock_path = TARGET / 'release/.cargo-lock'
        owned_ancestors(lock_path.parent, device)
        lock_fd = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW)
        lock_info = os.fstat(lock_fd)
        need(stat.S_ISREG(lock_info.st_mode) and lock_info.st_uid == 501
             and lock_info.st_dev == device and lock_info.st_nlink == 1, 'owned_target_lock_custody')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        need(identity(lock_info) == identity(os.fstat(lock_fd)) == identity(lock_path.lstat()),
             'owned_target_lock_changed')
        runner.git('source-apply', cargo_until, 'apply', '--index', '--whitespace=error',
                   str(patch_path))
        changed = runner.git('source-paths', cargo_until, 'diff', '--cached', '--name-only').splitlines()
        need(set(changed) == {item['path'] for item in CHANGED_FILES}
             and runner.git('source-tree', cargo_until, 'write-tree') == INPUT_TREE,
             'exact_new_source_tree')
        result['input_product_files'] = source_file_pins(manifest, device, 21)
        runner.git('source-freeze', cargo_until, 'commit', '--quiet', '-m',
                   'Repair actual Darwin TLS accepted mode and cold snapshot eligibility')
        repaired = source_state(runner, 'repaired', cargo_until)
        need(repaired['tree'] == INPUT_TREE and repaired['status'] == '', 'new_source_changed')
        result['repaired_source'] = repaired
        need(identity(lock_info) == identity(os.fstat(lock_fd)) == identity(lock_path.lstat()),
             'owned_target_lock_changed')
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
        lock_fd = None
        rustc_vv = runner.run('rustc-version', [str(TOOLCHAIN / 'rustc'), '-vV'],
                              cargo_until).decode('utf-8', 'strict')
        need('host: aarch64-apple-darwin' in rustc_vv, 'native_toolchain_abi')
        result['rustc_vv'] = rustc_vv
        result['attempt_preparation_elapsed_seconds'] = time.monotonic() - began
        write_json(CONTROL / 'candidate-normal-intent.public.json', result)
        cargo = str(TOOLCHAIN / 'cargo')
        runner.run('cargo-fmt', [cargo, 'fmt', '--all'], cargo_until)
        runner.run('cargo-fmt-check', [cargo, 'fmt', '--all', '--', '--check'], cargo_until)
        modified = runner.git('formatted-paths', cargo_until, 'diff', '--name-only').splitlines()
        allowed_product_paths = {item['path'] for item in manifest['files']}
        need(set(modified) <= allowed_product_paths, 'format_changed_unreviewed_source')
        format_patch = runner.run('format-diff', ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null',
                                  '-C', str(SOURCE), 'diff', '--no-ext-diff'], cargo_until)
        result['format_diff_sha256'] = sha(format_patch)
        if modified:
            runner.git('format-add', cargo_until, 'add', '--', *sorted(modified))
            runner.git('format-freeze', cargo_until, 'commit', '--quiet', '-m',
                       'Format isolated snapshot ACL and denial integration candidate')
        frozen = source_state(runner, 'frozen', cargo_until)
        need(frozen['status'] == '', 'formatted_source_dirty')
        result['frozen_source'] = frozen
        formatted_files = []
        for item in manifest['files']:
            remaining(cargo_until)
            raw = read_owned(SOURCE / item['path'])
            formatted_files.append({'path': item['path'], 'bytes': len(raw),
                                    'sha256': sha(raw), 'git_blob': blob(raw)})
        frozen_manifest = {
            'schema': 'heptabao.mac-snapshot-candidate-frozen-source.v1',
            'source': frozen['commit'], 'tree': frozen['tree'], 'source_path': str(SOURCE),
            'review_input_commit': REVIEW_COMMIT, 'review_input_tree': INPUT_TREE,
            'actual_input_source': before, 'files': formatted_files,
            'formatted': True, 'compiled': False, 'critical_tests': CRITICAL_TESTS,
            'format_changed_paths': sorted(modified), 'format_diff_sha256': sha(format_patch),
            'normal_profile': NORMAL_PROFILE,
            'known_remaining_product_gaps': manifest['known_remaining_product_gaps'],
            'full_replacement_qualified': False,
        }
        frozen_sha = write_json(CONTROL / 'frozen-source.public.json', frozen_manifest)
        result['frozen_manifest_sha256'] = frozen_sha
        strict_args = [cargo, 'clippy', '--release', '--locked', '--offline',
                       '--workspace', '--all-targets', '--exclude', 'qrcode', '--', '-D', 'warnings']
        runner.run('strict-clippy', strict_args, cargo_until)
        qualified = {
            'schema': 'heptabao.mac-snapshot-candidate-clippy-qualified.v1',
            'source': frozen['commit'], 'tree': frozen['tree'],
            'frozen_manifest_sha256': frozen_sha, 'normal_profile': NORMAL_PROFILE,
            'strict_clippy': runner.records[-1], 'production_linked': False,
            'workspace_tests_passed': False, 'qualified_full_replacement': False,
        }
        result['strict_qualified_sha256'] = write_json(CONTROL / 'clippy-qualified-source.public.json', qualified)
        test_compile_args = [cargo, 'test', '--release', '--locked', '--offline',
                             '-p', 'heptabao-server', '--lib', '--no-run', '--message-format=json']
        test_raw = runner.run('server-tests-compile', test_compile_args, cargo_until)
        test_events = artifact_events(test_raw)
        test_matches = [event for event in test_events
                        if event.get('reason') == 'compiler-artifact' and event.get('executable')
                        and event.get('target', {}).get('src_path') == str(SOURCE / 'crates/heptabao-server/src/lib.rs')
                        and event.get('profile', {}).get('test') is True]
        need(len(test_matches) == 1, 'exact_current_test_artifact')
        test_artifact = retain_artifact(test_matches[0], 'heptabao-server-tests', device, cargo_until, True)
        result['test_artifact'] = test_artifact
        binary = test_artifact['path']
        test_list = runner.run('server-tests-list', [binary, '--list'], cargo_until).decode('utf-8', 'strict')
        available = [line[:-6] for line in test_list.splitlines() if line.endswith(': test')]
        need(len(CRITICAL_TESTS) == len(set(CRITICAL_TESTS)) == 14
             and all(available.count(name) == 1 for name in CRITICAL_TESTS),
             'critical_test_exact_inventory')
        for index, name in enumerate(CRITICAL_TESTS, 1):
            label = 'critical-test-' + str(index).zfill(2)
            output = runner.run(label, [binary, '--exact', name, '--nocapture', '--test-threads=1'],
                                cargo_until, expect_zero=False).decode('utf-8', 'strict')
            observed = {
                'name': name, 'record': str(OUTPUT / (label + '.public.json')),
                'stdout_sha256': runner.records[-1]['stdout_sha256'],
                'stderr_sha256': runner.records[-1]['stderr_sha256'],
                'artifact_sha256': test_artifact['sha256'],
                'passed': (runner.records[-1]['exit_code'] == 0
                           and 'running 1 test' in output
                           and 'test result: ok. 1 passed; 0 failed;' in output),
            }
            result['observed_tests'].append(observed)
            if observed['passed']:
                result['completed_tests'].append(observed)
        # A known isolated test failure is retained while the remaining named
        # cases run. A timeout, unknown outcome or owned cleanup failure still
        # stops immediately in OwnedRunner.run; no test is replayed.
        result['failed_tests'] = [item['name'] for item in result['observed_tests']
                                  if not item['passed']]
        need(len(result['observed_tests']) == 14 and not result['failed_tests'],
             'critical_test_failures')
        need(hash_owned(Path(binary), cargo_until) == test_artifact['sha256'], 'test_artifact_changed')
        result['critical_tests_passed'] = len(result['completed_tests']) == 14
        production_args = [cargo, 'build', '--release', '--locked', '--offline',
                           '-p', 'heptabao-server', '--bin', 'heptabao-server',
                           '--bin', 'heptabao-seed', '--message-format=json']
        production_raw = runner.run('production-build', production_args, cargo_until)
        production_record = runner.records[-1]
        events = artifact_events(production_raw)
        artifacts = {}
        for name in ('heptabao-server', 'heptabao-seed'):
            matches = [event for event in events if event.get('reason') == 'compiler-artifact'
                       and event.get('target', {}).get('name') == name and event.get('executable')]
            need(len(matches) == 1, 'exact_production_artifact_' + name)
            artifacts[name] = retain_artifact(matches[0], name, device, cargo_until, False)
        final_source = source_state(runner, 'final', cargo_until)
        need(final_source == frozen, 'source_changed_during_validation')
        result['source_freeze_verified'] = True
        result['artifacts'] = artifacts
        build_result = {
            'schema': 'heptabao.native-default-build-result.v1',
            'normal_default_candidate': True, 'formal_qualification': False,
            'source_commit': frozen['commit'], 'source_tree': frozen['tree'],
            'source_freeze_verified': True, 'native_abi': 'aarch64-apple-darwin',
            'build_exit_code': 0, 'build_finished_success': True, 'timed_out': False,
            'owned_group_survivors_after_wait': False,
            'elapsed_seconds': production_record['elapsed_seconds'], 'command': production_args,
            'rustc_vv': rustc_vv, 'build_driver_path': str(Path(__file__)),
            'build_driver_sha256': sys.argv[1],
            'cargo_events_sha256': sha(production_raw),
            'cargo_stderr_sha256': production_record['stderr_sha256'],
            'requested_release_profile': NORMAL_PROFILE, 'artifacts': artifacts,
            'frozen_manifest_sha256': frozen_sha,
            'shared_cargo_budget_seconds': CARGO_SECONDS,
            'prior_critical_tests_passed': len(result['completed_tests']),
            'public_https_observer_executed': False, 'full_replacement_qualified': False,
        }
        build_sha = write_json(OUTPUT / 'result.public.json', build_result)
        receipt = {
            'schema': 'heptabao.native-build.v1',
            'source_commit': frozen['commit'], 'source_tree': frozen['tree'],
            'source_freeze_verified': True, 'native_abi': 'aarch64-apple-darwin',
            'build_exit_code': 0, 'binary_sha256': artifacts['heptabao-server']['sha256'],
            'features': artifacts['heptabao-server']['features'],
            'provenance': {'result_path': str(OUTPUT / 'result.public.json'),
                           'result_sha256': build_sha, 'cargo_events_sha256': sha(production_raw)},
        }
        receipt_sha = write_json(OUTPUT / 'native-build.public.json', receipt)
        remaining(cargo_until)
        result.update(status='normal_candidate_built_after_targeted_tests',
                      production_build_result_sha256=build_sha,
                      native_build_sha256=receipt_sha,
                      server_sha256=artifacts['heptabao-server']['sha256'],
                      qualification_scope='strict normal Clippy, fourteen named components including owned loopback API TLS, and normal production build; no production HTTPS observer, full workspace or physical-host HA qualification')
    except BaseException as error:
        result['failure_class'] = type(error).__name__
        result['failure_code'] = str(error) if isinstance(error, RuntimeError) else None
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        result['commands'] = runner.records
        try:
            result['last_owned_child_cleanup'] = runner.cleanup()
            if result['last_owned_child_cleanup'] and result['last_owned_child_cleanup']['remaining']:
                result.update(status='failed', failure_code='owned_group_remaining')
        except Exception as error:
            result.update(status='failed', cleanup_error_class=type(error).__name__)
        finally:
            # An owned subprocess is stopped before its target lock is released.
            if lock_fd is not None:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
        result['elapsed_seconds'] = time.monotonic() - began
        if cargo_until is not None:
            result['cargo_remaining_seconds'] = max(0, cargo_until - time.monotonic())
            if time.monotonic() > cargo_until:
                result.update(status='failed', failure_code='declared_new_attempt_deadline')
        digest = write_json(CONTROL / 'candidate-normal-result.public.json', result)
        print(json.dumps({'status': result['status'],
                          'result': str(CONTROL / 'candidate-normal-result.public.json'),
                          'result_sha256': digest, 'source': result.get('frozen_source'),
                          'completed_named_tests': len(result['completed_tests']),
                          'server_sha256': result.get('server_sha256'),
                          'full_replacement_qualified': False}, sort_keys=True), flush=True)
    return 0 if result['status'] == 'normal_candidate_built_after_targeted_tests' else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status': 'failed_after_build_started' if work_started else 'refused_before_build',
                          'error_class': type(error).__name__,
                          'error_code': str(error) if isinstance(error, RuntimeError) else None},
                         sort_keys=True), flush=True)
        raise SystemExit(2) from None
