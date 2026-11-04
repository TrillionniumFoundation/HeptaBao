#!/usr/bin/env python3
"""Validate one isolated snapshot candidate under a single normal Cargo budget."""
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
CONTROL = ROOT / 'control'
BASE_ROOT = BASE / 'continuation-20261104-ha-unified-normal-61ff-r1'
BASE_SOURCE = BASE_ROOT / 'source'
BASE_COMMIT = '70714605c39014bea93545f7f6aa4217d2a23544'
BASE_TREE = 'ef0ae63704a06b7dda1038e02abcc3233a2a438f'
REVIEW_COMMIT = '4609acf94695508ea49097039b8355897a1b20f2'
INPUT_TREE = '6708710421a4407e0d098fcc9ecc9aea479441db'
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python')
PYTHON_SHA = '7ecc1ecbf9daa9303c4bf502ff62ffdd9010ed5c08729d470ae9380c10ce1211'
TOOLCHAIN = Path('/Users/qianqi/.rustup/toolchains/1.98.0-aarch64-apple-darwin/bin')
CARGO_SHA = '1de2e84c15443b70444eecfa959ff9099dd8c1a5606b6d9ef5bc0ea9c25bc7f9'
RUSTC_SHA = 'a11618eca0956a8aa4372c2bc898690b513cbdfa2cb9125b2a5301e360ed5b49'
VOLUME_UUID = 'FB804D1B-24CB-4D6E-AEA7-A9E180807758'
PROBE = BASE / 'continuation-20261104-ha-cargo-lock-probe-61ff-r1/result.public.json'
PROBE_SHA = 'd9be1b814a0f7834f22eef219c765a3dae8ede2b6be60ca02f1b88600cc69403'
EVIDENCE_PREFIX = 'qa/evidence/20261104/ha-snapshot-acl-denial-61ff-r1'
CANDIDATE_MANIFEST_SHA = 'a777bbd32459928e7bb9363be591e2765abb9e7648c6325d5f5cce85b8983bc7'
PRODUCT_PATCH_SHA = '4de10395d9c41a868619a4c6af0d8f8ccb59c404f7c927e367221cc7fecf3e37'
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


def source_file_pins(manifest, device):
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
    need(len(checked) == 13, 'source_pin_count')
    return checked

CACHE = BASE_ROOT / 'runtime.noindex' / 'target'
TARGET = ROOT / 'runtime.noindex' / 'target'
CARGO_HOME = BASE / 'r13-full-native-cargo-home-r1'
OUTPUT = ROOT / 'normal-default-r1'
PREPARATION_SECONDS = 300.0
CARGO_SECONDS = 1800.0
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
    "ha::snapshot_clock::tests::snapshot_clock_denied_requires_original_binding_exact_successor_and_only_status_403"
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


def main():
    global work_started
    os.umask(0o077)
    began = time.monotonic()
    prep_until = began + PREPARATION_SECONDS
    need(len(sys.argv) == 3 and all(re.fullmatch('[0-9a-f]{64}', value)
                                   for value in sys.argv[1:]), 'build_and_stage_pins_required')
    need(hash_owned(Path(__file__), prep_until) == sys.argv[1], 'actual_build_driver_pin')
    device = preflight_host(prep_until)
    need(hash_owned(TOOLCHAIN / 'cargo', prep_until, single_link=False) == CARGO_SHA
         and hash_owned(TOOLCHAIN / 'rustc', prep_until, single_link=False) == RUSTC_SHA, 'actual_toolchain_pins')
    for path in (ROOT, SOURCE, CONTROL, CACHE, CARGO_HOME):
        owned_ancestors(path, device)
    stage_raw = read_owned(CONTROL / 'source-stage-result.public.json')
    need(sha(stage_raw) == sys.argv[2], 'actual_stage_receipt_pin')
    stage = json.loads(stage_raw)
    need(stage['status'] == 'staged_uncompiled_candidate'
         and stage['input_tree'] == INPUT_TREE and stage['review_commit'] == REVIEW_COMMIT
         and stage['root'] == str(ROOT) and stage['source_path'] == str(SOURCE)
         and stage['build_source_sha256'] == sys.argv[1]
         and stage['source_file_count'] == 13 and stage['evidence_file_count'] == 5,
         'actual_staged_candidate')
    need(stage['last_owned_child_cleanup']['remaining'] == []
         and all(record['exit_code'] == 0 and record['remaining'] == []
                 and not record['timed_out'] for record in stage['commands']), 'stage_cleanup_or_command')
    packet_raw = read_owned(CONTROL / 'stage-input.public.json')
    need(sha(packet_raw) == stage['packet_sha256'], 'staged_packet_pin')
    packet = json.loads(packet_raw)
    need(sha(packet['build_source'].encode()) == sys.argv[1]
         and sha(packet['stage_source'].encode()) == stage['stage_source_sha256']
         and hash_owned(CONTROL / 'stage_source_r1.py', prep_until) == stage['stage_source_sha256'],
         'staged_controls_binding')
    manifest_raw = read_owned(CONTROL / 'candidate-manifest.public.json')
    need(sha(manifest_raw) == CANDIDATE_MANIFEST_SHA, 'candidate_manifest_pin')
    manifest = json.loads(manifest_raw)
    need(not OUTPUT.exists() and not OUTPUT.is_symlink()
         and not TARGET.parent.exists() and not TARGET.parent.is_symlink()
         and not (CONTROL / 'candidate-normal-result.public.json').exists(),
         'fresh_build_run_required')
    need(shutil.disk_usage(ROOT).free >= 1024 * 1024 * 1024, 'build_disk_space')
    remaining(prep_until)
    work_started = True
    OUTPUT.mkdir(mode=0o700)
    (OUTPUT / 'artifacts').mkdir(mode=0o700)
    env = clean_environment()
    env.update(NORMAL_PROFILE)
    env.update({'CARGO_HOME': str(CARGO_HOME), 'CARGO_TARGET_DIR': str(TARGET),
                'CARGO_BUILD_JOBS': '2', 'CARGO_TERM_COLOR': 'never',
                'RUSTFLAGS': ''})
    runner = OwnedRunner(OUTPUT, env)
    result = {
        'schema': 'heptabao.mac-snapshot-candidate-normal.v1', 'status': 'failed',
        'root': str(ROOT), 'source_path': str(SOURCE), 'target_path': str(TARGET),
        'review_commit': REVIEW_COMMIT, 'input_tree': INPUT_TREE,
        'driver_sha256': sys.argv[1], 'stage_receipt_sha256': sys.argv[2],
        'python_sha256': PYTHON_SHA, 'cargo_sha256': CARGO_SHA, 'rustc_sha256': RUSTC_SHA,
        'preparation_budget_seconds': PREPARATION_SECONDS,
        'shared_cargo_budget_seconds': CARGO_SECONDS,
        'normal_profile': NORMAL_PROFILE, 'cargo_build_jobs': 2,
        'strict_clippy_inherited_excluded_package': 'qrcode',
        'source_cache_scope': 'release build-directory lock; not whole cache or host reservation',
        'source_cache_path': str(CACHE), 'copy_mode': 'APFS cp -cR, no fallback',
        'product_service_started': False, 'production_changed': False,
        'multi_physical_host_ha_executed': False, 'full_replacement_qualified': False,
        'critical_tests': CRITICAL_TESTS, 'completed_tests': [],
        'known_remaining_product_gaps': manifest['known_remaining_product_gaps'],
    }
    lock_fd = None
    cargo_until = None
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        before = source_state(runner, 'input', prep_until)
        need(before == {'commit': stage['physical_source_commit'], 'tree': INPUT_TREE, 'status': ''},
             'input_source_changed')
        result['input_source'] = before
        result['input_product_files'] = source_file_pins(manifest, device)
        processes = runner.run('preparation-process-snapshot',
                               ['/bin/ps', '-axo', 'pid=,ppid=,pgid=,comm='],
                               prep_until).decode('utf-8', 'strict')
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
        lock_path = CACHE / 'release' / '.cargo-lock'
        owned_ancestors(lock_path.parent, device)
        lock_fd = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW)
        lock_info = os.fstat(lock_fd)
        need(stat.S_ISREG(lock_info.st_mode) and lock_info.st_uid == 501
             and lock_info.st_dev == device and lock_info.st_nlink == 1, 'source_release_lock_custody')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        held_at = time.monotonic_ns()
        need(identity(lock_info) == identity(os.fstat(lock_fd)) == identity(lock_path.lstat()),
             'source_release_lock_changed')
        TARGET.parent.mkdir(mode=0o700)
        runner.run('apfs-cache-clone', ['/bin/cp', '-cR', str(CACHE), str(TARGET)], prep_until)
        result['clone_inode_verification'] = verify_clone(device, prep_until)
        need(identity(lock_info) == identity(os.fstat(lock_fd)) == identity(lock_path.lstat()),
             'source_release_lock_changed')
        result['source_release_lock'] = {
            'path': str(lock_path), 'device': lock_info.st_dev, 'inode': lock_info.st_ino,
            'descriptor_mode': 'O_RDONLY|O_NOFOLLOW', 'primitive': 'flock LOCK_EX|LOCK_NB',
            'held_since_monotonic_ns': held_at,
            'verified_through_monotonic_ns': time.monotonic_ns()}
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
        lock_fd = None
        rustc_vv = runner.run('rustc-version', [str(TOOLCHAIN / 'rustc'), '-vV'],
                              prep_until).decode('utf-8', 'strict')
        need('host: aarch64-apple-darwin' in rustc_vv, 'native_toolchain_abi')
        result['rustc_vv'] = rustc_vv
        result['preparation_elapsed_seconds'] = time.monotonic() - began
        remaining(prep_until)
        cargo_started = time.monotonic()
        cargo_until = cargo_started + CARGO_SECONDS
        result.update(cargo_started_monotonic=cargo_started,
                      cargo_deadline_monotonic=cargo_until,
                      cargo_started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
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
        need(len(CRITICAL_TESTS) == len(set(CRITICAL_TESTS)) == 10
             and all(available.count(name) == 1 for name in CRITICAL_TESTS),
             'critical_test_exact_inventory')
        for index, name in enumerate(CRITICAL_TESTS, 1):
            label = 'critical-test-' + str(index).zfill(2)
            output = runner.run(label, [binary, '--exact', name, '--nocapture', '--test-threads=1'],
                                cargo_until).decode('utf-8', 'strict')
            need('running 1 test' in output and 'test result: ok. 1 passed; 0 failed;' in output,
                 'critical_test_actual_count')
            result['completed_tests'].append({
                'name': name, 'record': str(OUTPUT / (label + '.public.json')),
                'stdout_sha256': runner.records[-1]['stdout_sha256'],
                'stderr_sha256': runner.records[-1]['stderr_sha256'],
                'artifact_sha256': test_artifact['sha256'],
            })
        need(hash_owned(Path(binary), cargo_until) == test_artifact['sha256'], 'test_artifact_changed')
        result['critical_tests_passed'] = len(result['completed_tests']) == 10
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
                      qualification_scope='strict normal Clippy, ten named component tests and normal production build; no HTTPS or physical-host HA qualification')
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
            # A failed clone is stopped before its source lock is released.
            if lock_fd is not None:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
        result['elapsed_seconds'] = time.monotonic() - began
        if cargo_until is not None:
            result['cargo_remaining_seconds'] = max(0, cargo_until - time.monotonic())
            if time.monotonic() > cargo_until:
                result.update(status='failed', failure_code='original_shared_cargo_deadline')
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
