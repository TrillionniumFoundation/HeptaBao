#!/usr/bin/env python3
"""Stage one uncompiled snapshot candidate from the unchanged local Mac base."""
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

STAGE_SECONDS = 240.0
stage_started = False


def main():
    global stage_started
    os.umask(0o077)
    began = time.monotonic()
    until = began + STAGE_SECONDS
    need(len(sys.argv) == 3 and re.fullmatch('[0-9a-f]{64}', sys.argv[1])
         and re.fullmatch('[0-9a-f]{64}', sys.argv[2]), 'stage_input_pins')
    packet_raw = ADMITTED_PACKET_RAW
    need(len(packet_raw) <= 1024 * 1024 and sha(packet_raw) == sys.argv[1], 'stage_packet_pin')
    packet = json.loads(packet_raw)
    need(packet['schema'] == 'heptabao.mac-snapshot-candidate-stage-input.v1'
         and packet['input_review_commit'] == REVIEW_COMMIT
         and packet['input_tree'] == INPUT_TREE, 'closed_candidate_input')
    need(sha(packet['stage_source'].encode()) == sys.argv[2]
         and sha(packet['build_source'].encode()) == packet['build_source_sha256'],
         'control_source_pins')
    compile(packet['build_source'], str(CONTROL / 'run_candidate_normal_r1.py'), 'exec')
    allowed = {EVIDENCE_PREFIX + '/' + name for name in (
        'candidate-manifest.public.json', 'product.patch', 'README.md',
        'revision2-review-and-tests.public.json', 'revision3-routing.patch')}
    need(set(packet['artifacts']) == allowed and set(packet['artifact_pins']) == allowed,
         'closed_artifact_paths')
    for name in allowed:
        need(isinstance(packet['artifacts'][name], str)
             and sha(packet['artifacts'][name].encode()) == packet['artifact_pins'][name],
             'artifact_content_pin')
    manifest_raw = packet['artifacts'][EVIDENCE_PREFIX + '/candidate-manifest.public.json'].encode()
    patch_raw = packet['artifacts'][EVIDENCE_PREFIX + '/product.patch'].encode()
    need(sha(manifest_raw) == CANDIDATE_MANIFEST_SHA
         and sha(patch_raw) == PRODUCT_PATCH_SHA and len(patch_raw) == 84576,
         'fixed_candidate_manifest_and_patch')
    manifest = json.loads(manifest_raw)
    need(manifest['base']['physical_commit'] == BASE_COMMIT
         and manifest['base']['tree'] == BASE_TREE and len(manifest['files']) == 13,
         'fixed_candidate_base')
    device = preflight_host(until)
    owned_ancestors(BASE_SOURCE, device)
    need(not ROOT.exists() and not ROOT.is_symlink(), 'fresh_candidate_root_required')
    remaining(until)
    stage_started = True
    ROOT.mkdir(mode=0o700)
    CONTROL.mkdir(mode=0o700)
    SOURCE.mkdir(mode=0o700)
    result = {
        'schema': 'heptabao.mac-snapshot-candidate-source-stage.v1', 'status': 'failed',
        'root': str(ROOT), 'source_path': str(SOURCE), 'base_source_path': str(BASE_SOURCE),
        'base_commit': BASE_COMMIT, 'base_tree': BASE_TREE,
        'review_commit': REVIEW_COMMIT, 'input_tree': INPUT_TREE,
        'packet_sha256': sha(packet_raw), 'stage_source_sha256': sys.argv[2],
        'build_source_sha256': packet['build_source_sha256'],
        'candidate_manifest_sha256': CANDIDATE_MANIFEST_SHA,
        'product_patch_sha256': PRODUCT_PATCH_SHA,
        'python_sha256': PYTHON_SHA, 'volume_uuid': VOLUME_UUID, 'volume_device': device,
        'actual_lock_probe_sha256': PROBE_SHA, 'stage_budget_seconds': STAGE_SECONDS,
        'cache_cloned': False, 'cargo_started': False, 'product_service_started': False,
        'production_changed': False, 'full_replacement_qualified': False,
    }
    runner = OwnedRunner(CONTROL, clean_environment())
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        write_raw(CONTROL / 'stage-input.public.json', packet_raw)
        write_raw(CONTROL / 'stage_source_r1.py', packet['stage_source'].encode(), 0o500)
        write_raw(CONTROL / 'run_candidate_normal_r1.py', packet['build_source'].encode(), 0o500)
        write_raw(CONTROL / 'candidate-manifest.public.json', manifest_raw)
        write_raw(CONTROL / 'product.patch', patch_raw)
        need(runner.git('base-head-before', until, 'rev-parse', 'HEAD',
                        directory_path=BASE_SOURCE) == BASE_COMMIT, 'base_commit_changed')
        need(runner.git('base-tree-before', until, 'rev-parse', 'HEAD^{tree}',
                        directory_path=BASE_SOURCE) == BASE_TREE, 'base_tree_changed')
        need(runner.git('base-clean-before', until, 'status', '--porcelain=v1',
                        '--untracked-files=all', directory_path=BASE_SOURCE) == '', 'base_dirty')
        runner.git('git-init', until, 'init', '--quiet')
        runner.git('git-fetch-local', until, '-c', 'protocol.file.allow=always', 'fetch',
                   '--no-tags', '--depth=1', '--no-recurse-submodules',
                   'file://' + str(BASE_SOURCE), BASE_COMMIT)
        runner.git('git-checkout', until, 'checkout', '--detach', BASE_COMMIT)
        for item in manifest['files']:
            path = SOURCE / item['path']
            owned_ancestors(path.parent, device)
            if item['base_sha256'] is None:
                need(not path.exists() and not path.is_symlink(), 'new_source_path_exists')
            else:
                raw = read_owned(path)
                need(sha(raw) == item['base_sha256'] and blob(raw) == item['base_git_blob'],
                     'actual_base_file_pin')
        runner.git('git-apply', until, 'apply', '--index', str(CONTROL / 'product.patch'))
        result['verified_product_files'] = source_file_pins(manifest, device)
        for name in sorted(allowed):
            path = SOURCE / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            owned_ancestors(path.parent, device)
            write_raw(path, packet['artifacts'][name].encode())
        runner.git('git-add-evidence', until, 'add', '--', *sorted(allowed))
        changed = runner.git('git-index-paths', until, 'diff', '--cached', '--name-only').splitlines()
        need(set(changed) == allowed | {item['path'] for item in manifest['files']}
             and len(changed) == 18, 'closed_source_delta')
        need(runner.git('git-input-tree', until, 'write-tree') == INPUT_TREE, 'input_tree_mismatch')
        runner.git('git-freeze-input', until, 'commit', '--quiet', '-m',
                   'Freeze isolated Mac snapshot ACL and denial input 4609')
        result['physical_source_commit'] = runner.git('git-frozen-head', until, 'rev-parse', 'HEAD')
        need(runner.git('git-frozen-tree', until, 'rev-parse', 'HEAD^{tree}') == INPUT_TREE,
             'frozen_input_tree_changed')
        need(runner.git('git-clean-input', until, 'status', '--porcelain=v1',
                        '--untracked-files=all') == '', 'input_source_dirty')
        need(runner.git('base-head-after', until, 'rev-parse', 'HEAD',
                        directory_path=BASE_SOURCE) == BASE_COMMIT, 'base_commit_changed')
        need(runner.git('base-tree-after', until, 'rev-parse', 'HEAD^{tree}',
                        directory_path=BASE_SOURCE) == BASE_TREE, 'base_tree_changed')
        need(runner.git('base-clean-after', until, 'status', '--porcelain=v1',
                        '--untracked-files=all', directory_path=BASE_SOURCE) == '', 'base_dirty')
        remaining(until)
        result.update(status='staged_uncompiled_candidate',
                      source_fetched_readonly_from=str(BASE_SOURCE),
                      review_alias_same_tree=True, source_file_count=13,
                      evidence_file_count=5, base_source_unchanged=True)
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
                result['status'] = 'failed'
        except Exception as error:
            result['status'] = 'failed'
            result['cleanup_error_class'] = type(error).__name__
        result['elapsed_seconds'] = time.monotonic() - began
        if result['elapsed_seconds'] > STAGE_SECONDS:
            result.update(status='failed', failure_code='original_stage_deadline')
        digest = write_json(CONTROL / 'source-stage-result.public.json', result)
        sync_dir(ROOT)
        print(json.dumps({'status': result['status'],
                          'result_path': str(CONTROL / 'source-stage-result.public.json'),
                          'result_sha256': digest,
                          'source': result.get('physical_source_commit'),
                          'tree': INPUT_TREE, 'cargo_started': False,
                          'full_replacement_qualified': False}, sort_keys=True), flush=True)
    return 0 if result['status'] == 'staged_uncompiled_candidate' else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status': 'failed_after_stage_started' if stage_started else 'refused_before_stage',
                          'error_class': type(error).__name__,
                          'error_code': str(error) if isinstance(error, RuntimeError) else None},
                         sort_keys=True), flush=True)
        raise SystemExit(2) from None
