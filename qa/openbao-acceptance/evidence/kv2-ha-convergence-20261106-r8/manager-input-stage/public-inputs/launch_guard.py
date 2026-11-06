#!/usr/bin/env python3
"""Bounded pre-exec admission for one normal launchd-owned private KV2 server.

This does not initialize/unseal, invoke a provider or create a child process.
It checks a private, explicitly published binding, leaves a private pre-exec
receipt, then replaces itself with the exact normal server. A pre-exec receipt
is not proof that exec, TLS bind or manager handoff subsequently succeeded.
"""
from __future__ import annotations

import time
ENTRY = time.monotonic()
import contextlib
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys

SERVICE = Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-production-20261104-r1/formal-kv2-current-20261106-r1')
KEY_ROOT = Path('/Users/qianqi/heptabao-formal-kv2-current-20261106-r1/service-authority-current-20261106-r1')
BINDING = SERVICE / 'manager/launch-binding.private.json'
UID = 501
FILE_KEYS = {'dev', 'inode', 'uid', 'gid', 'mode', 'nlink', 'bytes', 'mtime_ns', 'ctime_ns', 'file_type'}
DIR_KEYS = {'path', 'dev', 'inode', 'uid', 'gid', 'mode'}


class Refused(Exception):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        need(name not in result, 'duplicate_binding_field')
        result[name] = value
    return result


def file_identity(value):
    return {'dev': value.st_dev, 'inode': value.st_ino, 'uid': value.st_uid,
            'gid': value.st_gid, 'mode': stat.S_IMODE(value.st_mode),
            'nlink': value.st_nlink, 'bytes': value.st_size,
            'mtime_ns': value.st_mtime_ns, 'ctime_ns': value.st_ctime_ns,
            'file_type': stat.S_IFMT(value.st_mode)}


def directory_identity(path, value):
    return {'path': str(path), 'dev': value.st_dev, 'inode': value.st_ino,
            'uid': value.st_uid, 'gid': value.st_gid, 'mode': stat.S_IMODE(value.st_mode)}


def canonical_path(value):
    need(type(value) is str and 1 < len(value) <= 4096 and value.startswith('/'), 'absolute_path')
    need(not any(ord(c) < 32 or ord(c) == 127 for c in value)
         and not any(c in ('', '.', '..') for c in value[1:].split('/')), 'canonical_path')
    path = Path(value)
    need(path.resolve(strict=True) == path, 'no_symlink_path')
    return path


class LaunchClock:
    """Defer a termination signal only while registering/retiring an owned FD."""
    def __init__(self, end):
        self.end = end
        self.depth = 0
        self.pending = None
        self.previous = {}
        self.timer_owned = False

    def interrupted(self, signum, _frame):
        if self.pending is None:
            self.pending = signum
        if not self.depth:
            raise Refused('launch_signal_or_deadline')

    @contextlib.contextmanager
    def critical(self):
        self.depth += 1
        try:
            yield
        finally:
            self.depth -= 1

    def start(self):
        need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'no_inherited_launch_timer')
        with self.critical():
            for signum in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
                self.previous[signum] = signal.getsignal(signum)
                signal.signal(signum, self.interrupted)
            signal.setitimer(signal.ITIMER_REAL, max(0.001, self.end - time.monotonic()))
            self.timer_owned = True
        self.check()

    def check(self):
        need(self.pending is None and time.monotonic() < self.end, 'original_launch_deadline')

    def finish(self):
        if self.timer_owned:
            signal.setitimer(signal.ITIMER_REAL, 0)
            self.timer_owned = False
        for signum, handler in self.previous.items():
            signal.signal(signum, handler)
        self.previous.clear()


class Admission:
    def __init__(self, end, clock=None):
        self.end = end
        self.clock = clock if clock is not None else LaunchClock(end)
        self.directories = []
        self.files = []
        self.handles = {}
        self.cleanup_errors = []

    def check(self):
        self.clock.check()
        need(not self.cleanup_errors, 'original_handles_close_failed')

    def open_fd(self, path, flags, mode=0o600, *, dir_fd=None):
        self.check()
        with self.clock.critical():
            fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=dir_fd)
            # Registration is adjacent to birth and cannot be interrupted by
            # our handlers. Even a later fstat/validation failure retains this
            # original descriptor for one explicit cleanup attempt.
            self.handles[fd] = str(path)
        self.check()
        return fd

    def release_fd(self, fd):
        # Never retry close after an error: its numeric FD may have been reused.
        # Cleanup errors remain separate from a primary admission exception.
        with self.clock.critical():
            if fd not in self.handles:
                self.cleanup_errors.append('unknown_original_handle')
                return
            del self.handles[fd]
            try:
                os.close(fd)
            except OSError:
                self.cleanup_errors.append('original_handle_close_failed')

    def hold_directory(self, pin, *, private=True):
        self.check()
        need(type(pin) is dict and set(pin) == DIR_KEYS, 'directory_pin_shape')
        need(all(type(pin[k]) is int for k in DIR_KEYS - {'path'}), 'directory_pin_integers')
        path = canonical_path(pin['path'])
        before = path.lstat()
        need(stat.S_ISDIR(before.st_mode) and directory_identity(path, before) == pin, 'directory_pin_exact')
        if private:
            need(pin['uid'] == UID and pin['mode'] == 0o700, 'private_directory_owner')
        else:
            need(path in (Path('/Volumes/T5'), Path('/System/Volumes/Data')), 'only_two_fixed_volume_roots')
        fd = self.open_fd(path, os.O_RDONLY | os.O_DIRECTORY)
        need(directory_identity(path, os.fstat(fd)) == pin == directory_identity(path, path.lstat()), 'original_directory_fd')
        row = {'path': path, 'pin': pin, 'fd': fd}
        self.directories.append(row)
        return row

    def read_file(self, item, *, maximum, private=True, materialize=True, verify_bytes=True):
        self.check()
        need(type(item) is dict and set(item) == {'path', 'bytes', 'sha256', 'identity'}, 'file_binding_shape')
        pin = item['identity']
        need(type(pin) is dict and set(pin) == FILE_KEYS and all(type(x) is int for x in pin.values()), 'full_file_identity_shape')
        need(type(item['bytes']) is int and 0 <= item['bytes'] <= maximum and item['bytes'] == pin['bytes'], 'bounded_file')
        need(type(item['sha256']) is str and len(item['sha256']) == 64
             and all(x in '0123456789abcdef' for x in item['sha256']), 'file_digest_shape')
        path = canonical_path(item['path'])
        before = file_identity(path.lstat())
        need(before == pin and pin['file_type'] == stat.S_IFREG and pin['nlink'] == 1, 'original_regular_file')
        need(pin['mode'] & 0o022 == 0, 'not_group_or_world_writable')
        if private:
            need(pin['uid'] == UID and pin['mode'] in (0o600, 0o700), 'owned_private_file')
        fd = self.open_fd(path, os.O_RDONLY)
        need(file_identity(os.fstat(fd)) == pin, 'original_file_fd')
        digest = hashlib.sha256()
        data = []
        count = 0
        if verify_bytes:
            while True:
                self.check()
                part = os.read(fd, min(1024 * 1024, maximum + 1 - count))
                if not part:
                    break
                count += len(part)
                need(count <= maximum, 'file_read_cap')
                digest.update(part)
                if materialize:
                    data.append(part)
            need(count == item['bytes'] and digest.hexdigest() == item['sha256'], 'original_file_content')
        need(file_identity(os.fstat(fd)) == pin == file_identity(path.lstat()), 'file_identity_unchanged')
        self.files.append({'path': path, 'pin': pin, 'fd': fd, 'byte_hash_checked': verify_bytes})
        return b''.join(data) if materialize and verify_bytes else None

    def recheck(self):
        self.check()
        for row in self.directories:
            need(directory_identity(row['path'], row['path'].lstat()) == row['pin']
                 == directory_identity(row['path'], os.fstat(row['fd'])), 'original_directories_unchanged')
        for row in self.files:
            need(file_identity(row['path'].lstat()) == row['pin']
                 == file_identity(os.fstat(row['fd'])), 'original_files_unchanged')

    def close(self):
        for fd in reversed(list(self.handles)):
            self.release_fd(fd)
        self.files.clear()
        self.directories.clear()
        return list(self.cleanup_errors)


def read_initial_binding(path, guard):
    path = canonical_path(str(path))
    need(path == BINDING, 'fixed_launch_binding_path')
    before = file_identity(path.lstat())
    need(before['file_type'] == stat.S_IFREG and before['uid'] == UID
         and before['mode'] == 0o600 and before['nlink'] == 1 and 0 < before['bytes'] <= 131072, 'private_launch_binding_file')
    fd = guard.open_fd(path, os.O_RDONLY)
    try:
        need(file_identity(os.fstat(fd)) == before, 'binding_original_fd')
        data = bytearray()
        while len(data) <= 131072:
            guard.check()
            part = os.read(fd, 16384)
            if not part:
                break
            data.extend(part)
        need(len(data) == before['bytes'] and file_identity(os.fstat(fd)) == before == file_identity(path.lstat()), 'binding_stable_read')
        obj = json.loads(data, object_pairs_hook=unique_object)
        return obj, {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'identity': before}
    finally:
        guard.release_fd(fd)


def admit(binding, original_binding, guard):
    need(type(binding) is dict and set(binding) == {
        'schema', 'state', 'manager', 'roots', 'files', 'data_pin', 'seal_file', 'normal_config',
    }, 'exact_launch_binding_fields')
    need(binding['schema'] == 'heptabao.normal-kv2-launch-binding.private.v1', 'launch_binding_schema')
    need(binding['state'] in ('initial_empty', 'initialized'), 'known_launch_binding_state')
    need(binding['manager'] == {'domain': 'gui/501', 'label': 'org.heptabao.kv2', 'uid': 501, 'gid': 20}, 'fixed_observed_manager_target')
    need(os.geteuid() == UID and os.getegid() == 20, 'actual_manager_uid_gid')
    roots = binding['roots']
    need(type(roots) is dict and set(roots) == {'service', 'key', 'admissions', 't5', 'internal'}, 'exact_launch_roots')
    need(roots['service']['path'] == str(SERVICE), 'fixed_service_root')
    need(roots['key']['path'] == str(KEY_ROOT), 'fixed_internal_key_root')
    need(roots['t5']['path'] == '/Volumes/T5' and roots['internal']['path'] == '/System/Volumes/Data', 'fixed_volume_paths')
    need(roots['admissions']['path'] == roots['key']['path'] + '/manager-admissions', 'private_admissions_child')
    for role in ('t5', 'internal', 'service', 'key', 'admissions'):
        guard.hold_directory(roots[role], private=role not in ('t5', 'internal'))
    need(roots['service']['dev'] == roots['t5']['dev'] and roots['key']['dev'] == roots['internal']['dev']
         and roots['key']['dev'] != roots['service']['dev'], 'actual_separate_internal_key_filesystem')
    guard.read_file(original_binding, maximum=131072)
    files = binding['files']
    need(type(files) is dict and set(files) == {'python', 'guard', 'server', 'config', 'ca_certificate', 'server_certificate', 'server_private_key'}, 'exact_launch_files')
    expected = {'guard': str(SERVICE / 'manager/launch_guard.py'),
                'server': str(SERVICE / 'runtime/heptabao-server'),
                'config': str(SERVICE / 'config/server.json'),
                'ca_certificate': str(SERVICE / 'tls/ca.crt'),
                'server_certificate': str(SERVICE / 'tls/server.crt'),
                'server_private_key': roots['key']['path'] + '/tls/server.key'}
    need(all(files[role]['path'] == path for role, path in expected.items()), 'fixed_role_file_locations')
    need(Path(sys.executable).resolve(strict=True) == Path(files['python']['path'])
         and Path(__file__).resolve(strict=True) == Path(files['guard']['path']), 'actual_python_and_guard_entry')
    guard.read_file(files['python'], maximum=128 * 1024 * 1024, private=False, materialize=False)
    guard.read_file(files['guard'], maximum=65536, materialize=False)
    guard.read_file(files['server'], maximum=128 * 1024 * 1024, materialize=False)
    need(files['server']['identity']['mode'] == 0o700, 'private_executable_mode')
    config_bytes = guard.read_file(files['config'], maximum=65536)
    config = json.loads(config_bytes, object_pairs_hook=unique_object)
    need(config == binding['normal_config'] and set(config) == {
        'ui', 'disable_unauthed_rekey_endpoints', 'listen', 'data_dir', 'storage', 'audit_file',
        'tls_cert_file', 'tls_key_file', 'tls_min_version', 'tls_max_version', 'max_connections',
        'timeout_seconds', 'outbound_endpoints',
    }, 'exact_normal_config')
    need(config == {
        'ui': False, 'disable_unauthed_rekey_endpoints': True, 'listen': '127.0.0.1:18240',
        'data_dir': str(SERVICE / 'data'), 'storage': {'native_v6_file': {'path': str(SERVICE / 'data')}},
        'audit_file': str(SERVICE / 'audit/audit.jsonl'), 'tls_cert_file': expected['server_certificate'],
        'tls_key_file': expected['server_private_key'], 'tls_min_version': 'tls12', 'tls_max_version': 'tls13',
        'max_connections': 16, 'timeout_seconds': 15, 'outbound_endpoints': [],
    }, 'normal_file_only_without_providers')
    for role in ('ca_certificate', 'server_certificate'):
        guard.read_file(files[role], maximum=65536, materialize=False)
    # The guard proves the original key file descriptor/metadata without reading
    # or hashing its secret bytes. Actual key/certificate use belongs to TLS.
    guard.read_file(files['server_private_key'], maximum=16384, materialize=False, verify_bytes=False)
    need(binding['data_pin']['path'] == str(SERVICE / 'data'), 'fixed_data_child')
    data = guard.hold_directory(binding['data_pin'])
    if binding['state'] == 'initial_empty':
        need(binding['seal_file'] is None and os.listdir(data['fd']) == [], 'original_empty_before_init')
    else:
        need(binding['seal_file']['path'] == str(SERVICE / 'data/seal.json'), 'fixed_initialized_seal_file')
        guard.read_file(binding['seal_file'], maximum=16384, materialize=False)
    guard.recheck()
    return roots, files


def publish_pre_exec(guard, roots, binding_pin, state):
    directory = next(row for row in guard.directories if row['path'] == Path(roots['admissions']['path']))
    name = 'launch-' + str(os.getpid()) + '-' + os.urandom(8).hex() + '.private.json'
    body = {'schema': 'heptabao.normal-kv2-pre-exec.private.v1', 'pid': os.getpid(), 'ppid': os.getppid(),
            'uid': os.geteuid(), 'gid': os.getegid(), 'pgid': os.getpgid(0), 'session': os.getsid(0),
            'binding': binding_pin, 'state': state, 'roots': roots,
            'file_checks': [{'path': str(row['path']), 'identity': row['pin'], 'byte_hash_checked': row['byte_hash_checked']} for row in guard.files],
            'normal_server_exec_intended': True, 'normal_server_exec_observed': False,
            'service_tls_bind_observed': False, 'root_nonce_or_share_read': False,
            'automatic_unseal': False, 'provider_called': False,
            'volume_uuid_requeried': False, 'fixed_volume_identity_verified': True,
            'elapsed_before_exec': time.monotonic() - ENTRY}
    raw = (json.dumps(body, sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = guard.open_fd(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, dir_fd=directory['fd'])
    try:
        offset = 0
        while offset < len(raw):
            guard.check()
            count = os.write(fd, memoryview(raw)[offset:])
            need(count > 0, 'private_receipt_short_write')
            offset += count
        os.fsync(fd)
        info = file_identity(os.fstat(fd))
        need(info['uid'] == UID and info['mode'] == 0o600 and info['nlink'] == 1 and info['bytes'] == len(raw), 'private_pre_exec_receipt')
        os.fsync(directory['fd'])
    finally:
        guard.release_fd(fd)
    guard.recheck()


def main():
    need(sys.platform == 'darwin' and sys.argv[1:] == ['--binding', str(BINDING)], 'fixed_darwin_launch_argv')
    need(sys.flags.isolated == 1 and sys.dont_write_bytecode, 'isolated_no_bytecode_launch')
    clock = LaunchClock(ENTRY + 15)
    guard = Admission(clock.end, clock)
    primary = None
    try:
        clock.start()
        binding, pin = read_initial_binding(BINDING, guard)
        roots, files = admit(binding, pin, guard)
        publish_pre_exec(guard, roots, pin, binding['state'])
        os.chdir(SERVICE)
        guard.recheck()
        # CLOEXEC closes all original validation handles in the new process.
        # Disarm only after final admission and immediately before exec. The
        # HTTP server has its own normal 15-second request deadline thereafter.
        with clock.critical():
            clock.finish()
            clock.check()
        os.execve(files['server']['path'], [files['server']['path'], '--config', files['config']['path']],
                  {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'})
    except BaseException as error:
        primary = error
    finally:
        with clock.critical():
            cleanup_errors = guard.close()
            try:
                clock.finish()
            except BaseException:
                cleanup_errors.append('signal_handler_retirement_failed')
        if cleanup_errors:
            print('heptabao launch cleanup: ' + ','.join(cleanup_errors), file=sys.stderr)
    if primary is not None:
        raise primary
    need(not cleanup_errors, 'original_handles_close_failed')
    raise Refused('exec_unexpectedly_returned')


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        code = str(error) if isinstance(error, Refused) else 'launch_operation_failed'
        if not code.replace('_', '').isalnum():
            code = 'launch_operation_failed'
        print('heptabao launch refused: ' + code, file=sys.stderr)
        raise SystemExit(78)
