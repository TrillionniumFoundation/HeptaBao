#!/usr/bin/env python3
"""One new, uninitialized normal Rust listener; only unauthenticated health GET.

The parent owns the SSH stream. This worker owns the original Rust child via
the unchanged, source-pinned process-custody module. No old fixture is started,
initialized, repaired, removed or otherwise changed.
"""
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import select
import signal
import socket
import ssl
import stat
import subprocess
import sys
import time
import types
import urllib.error

BASE = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
ROOT = BASE / 'ha128-mac-rust-tls-worker-20261106-r1'
OLD = BASE / 'native-ha-4bde9-authbus-node-r2'
QUALIFIED = OLD  # Previously installed, whole-pinned normal Mac artifact only.
QA = BASE / 'ha-qa-af91-preparation-20261106-r1/source/qa/openbao-acceptance'
BIN = OLD / 'heptabao-server'
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
PYTHON_PIN = (34640, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13')
IP, PORT = '192.168.0.8', 31040
CA_PIN = (1192, '25be2e78e9cdb325f74a8cef2e4a8795b18f66ff722293c947099332a237c932')
LEAF_PIN = (1277, '037e7a71b68c9ce98963ff6187473a1f235ba50e4950cb4215fccdc93031dfb7')
BIN_PIN = (92359328, '5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c')
COMMON_PINS = {
    'fixture_mounts': (1560, '55075ee436c22816a176dfb06cec387df37fdadd581c16acc07dabc837ba85b5'),
    'owned_process': (28442, '0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0'),
    'kv2_dr_process_custody': (26131, '669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008'),
}
WORKER_BASE_PIN = (77824, '2c87ffbcee09fc7706e7ac59c73ac851ac8313ce18a962255a26ad54e90d089e')


class Refused(RuntimeError):
    pass


def need(value, label):
    if not value:
        raise Refused(label)


def ident(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid',
                 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def deadline(until):
    need(time.monotonic() < until, 'diagnostic_total_deadline')


def file_pin(path, pin, until, *, contents=False):
    deadline(until)
    info = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(info.st_mode)
         and info.st_nlink == 1 and info.st_uid in (0, os.getuid())
         and not info.st_mode & 0o022 and info.st_size == pin[0], 'fixed_owned_public_input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        need(ident(os.fstat(fd)) == ident(info), 'same_open_public_input')
        digest, count, raw = hashlib.sha256(), 0, bytearray()
        while True:
            deadline(until)
            part = os.read(fd, min(1048576, pin[0] + 1 - count))
            if not part:
                break
            count += len(part)
            need(count <= pin[0], 'public_input_read_bound')
            digest.update(part)
            if contents:
                raw.extend(part)
        need(count == pin[0] and digest.hexdigest() == pin[1]
             and ident(os.fstat(fd)) == ident(path.lstat()) == ident(info), 'public_input_pin_or_identity_changed')
        return ident(info), bytes(raw)
    finally:
        os.close(fd)


def owned_directory(path, *, private=False):
    s = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISDIR(s.st_mode)
         and s.st_uid == os.getuid() and not s.st_mode & 0o022, 'owned_canonical_directory')
    need(not private or stat.S_IMODE(s.st_mode) == 0o700, 'private_directory_0700')
    return ident(s)


def key_metadata(path):
    s = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(s.st_mode)
         and s.st_nlink == 1 and s.st_uid == os.getuid()
         and stat.S_IMODE(s.st_mode) == 0o600 and 0 < s.st_size <= 16384,
         'existing_synthetic_key_private_0600')
    return ident(s)


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
    finally:
        os.close(fd)


def load_originals(qa, base_pin, until):
    pins = {**COMMON_PINS, 'ha_multihost_live': base_pin}
    records, modules = {}, {}
    for name, pin in pins.items():
        path = qa / (name + '.py')
        identity, raw = file_pin(path, pin, until, contents=True)
        need(name not in sys.modules, 'original_module_not_preimported')
        module = types.ModuleType(name)
        module.__file__ = str(path)
        sys.modules[name] = module
        exec(compile(raw, str(path), 'exec'), module.__dict__)
        records[path] = (pin, identity)
        modules[name] = module
    return modules['ha_multihost_live'], modules['kv2_dr_process_custody'], records


def safe_error(error):
    out = {'type': type(error).__name__}
    if isinstance(error, Refused):
        out['code'] = str(error)
    for value, prefix in ((error, ''), (getattr(error, 'reason', None), 'reason')):
        if value is None:
            continue
        if prefix:
            out['reasonType'] = type(value).__name__
        if isinstance(value, OSError) and type(value.errno) is int:
            out[prefix + 'Errno' if prefix else 'errno'] = value.errno
        if isinstance(value, ssl.SSLError):
            reason = getattr(value, 'reason', None)
            if isinstance(reason, str) and re.fullmatch(r'[A-Z0-9_]{1,96}', reason):
                out[prefix + 'SslReason' if prefix else 'sslReason'] = reason
            code = getattr(value, 'verify_code', None)
            if type(code) is int:
                out[prefix + 'VerifyCode' if prefix else 'verifyCode'] = code
    return out


def health_case(base, context, node):
    start = time.monotonic()
    row = {'stage': 'original_urllib_health', 'passed': False, 'method': 'GET',
           'route': '/v1/sys/health', 'authenticationSent': False, 'budgetSeconds': 1.5}
    try:
        status, body = base.api(context, node, 'GET', 'sys/health', timeout=1.5)
        row.update(httpStatus=status, initialized=body.get('initialized') if type(body.get('initialized')) is bool else None,
                   sealed=body.get('sealed') if type(body.get('sealed')) is bool else None)
        row['passed'] = status == 501 and time.monotonic() - start <= 1.5
    except BaseException as error:
        row['error'] = safe_error(error)
    row['elapsedSeconds'] = time.monotonic() - start
    return row


def verify_records(records, until):
    for path, (pin, identity) in records.items():
        now, _ = file_pin(path, pin, until)
        need(now == identity, 'public_input_final_identity_changed')


def emit(phase, data):
    print(json.dumps({'phase': phase, 'data': data}, sort_keys=True, separators=(',', ':')), flush=True)


def run_worker():
    start = time.monotonic()
    until = start + 85
    report = {'schema': 'heptabao.ha-rust-tls-diagnostic-worker.r1', 'ok': False,
              'oldFixtureRestarted': False, 'initializationSubmitted': False,
              'diagnosticStorageMode': 'standalone_new_empty_directory',
              'launchLane': 'existing_hepta_mac_local_ssh',
              'mutationRequests': 0, 'credentialsUsed': False, 'keyDigestPublished': False,
              'productionChanged': False, 'haQualified': False, 'remoteClosureUnknown': True}
    created = False
    child = owner = log = None
    records = {}
    key_before = None
    try:
        need(sys.platform == 'darwin' and os.getuid() == 501 and platform.machine() == 'arm64'
             and platform.node() == 'MacBook-Pro.local' and Path(sys.executable).resolve(strict=True) == PYTHON,
             'actual_mac_worker_account_and_interpreter')
        owned_directory(ROOT.parent)
        owned_directory(OLD, private=True)
        owned_directory(QUALIFIED, private=True)
        need(not ROOT.exists() and not ROOT.is_symlink(), 'new_diagnostic_root_absent')
        base, custody, records = load_originals(QA, WORKER_BASE_PIN, until)
        for path, pin in ((BIN, BIN_PIN), (PYTHON, PYTHON_PIN), (OLD / 'ca.crt', CA_PIN), (OLD / 'tls.crt', LEAF_PIN)):
            identity, _ = file_pin(path, pin, until)
            records[path] = (pin, identity)
        need(stat.S_IMODE(BIN.stat().st_mode) == 0o500, 'qualified_normal_binary_mode')
        key_before = key_metadata(OLD / 'tls.key')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as preflight:
            preflight.bind((IP, PORT))
        ROOT.mkdir(mode=0o700, exist_ok=False)
        created = True
        config = {'listen': f'{IP}:{PORT}', 'data_dir': str(ROOT / 'state'),
                  'audit_file': str(ROOT / 'audit.jsonl'),
                  'tls_cert_file': str(OLD / 'tls.crt'), 'tls_key_file': str(OLD / 'tls.key'),
                  'max_connections': 64, 'timeout_seconds': 15, 'rate_limit_per_second': 2000,
                  'rate_limit_burst': 4000, 'rate_limit_entries': 512, 'lifecycle_interval_seconds': 1}
        write_new(ROOT / 'server.json', (json.dumps(config, sort_keys=True) + '\n').encode())
        log_fd = os.open(ROOT / 'process.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        log = os.fdopen(log_fd, 'wb')
        node = base.Node(3, 'hepta-mac-local', IP, str(ROOT), PORT, 31041)
        context = ssl.create_default_context(cafile=str(OLD / 'ca.crt'))
        try:
            with custody.activated() as current_owner:
                owner = current_owner
                try:
                    child = subprocess.Popen([str(BIN), '--config', str(ROOT / 'server.json')],
                                             stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                             close_fds=True, start_new_session=True)
                    ready_until = time.monotonic() + 45
                    ready = b'HeptaBao single-node TLS listener ready at 192.168.0.8:31040\n'
                    while True:
                        deadline(min(until, ready_until))
                        need(child.poll() is None, 'owned_rust_listener_exited_before_ready')
                        with (ROOT / 'process.log').open('rb') as observation:
                            raw = observation.read(65537)
                        need(len(raw) <= 65536, 'bounded_owned_rust_log')
                        if ready in raw:
                            break
                        time.sleep(0.025)
                    libproc = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
                    proc_pidpath = libproc.proc_pidpath
                    proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
                    proc_pidpath.restype = ctypes.c_int
                    image_path = ctypes.create_string_buffer(4096)
                    path_length = proc_pidpath(child.pid, image_path, len(image_path))
                    need(0 < path_length < len(image_path) and image_path.value.decode('utf-8') == str(BIN),
                         'actual_owned_rust_executable')
                    report['listenerPid'] = child.pid
                    report['selfHealth'] = health_case(base, context, node)
                    need(child.poll() is None, 'owned_rust_alive_after_self_probe')
                    report['aliveBeforeParentProbe'] = True
                    emit('ready', {'pid': child.pid, 'selfHealth': report['selfHealth'],
                                   'controlBudgetSeconds': 15, 'newUninitializedFixture': True})
                    readable, _, _ = select.select([sys.stdin], [], [], min(15, until - time.monotonic()))
                    need(bool(readable), 'parent_control_deadline')
                    command = os.read(sys.stdin.fileno(), 16)
                    need(command == b'finish\n', 'exact_parent_finish_command')
                    need(child.poll() is None, 'owned_rust_alive_after_parent_probe')
                    report['aliveAfterParentProbe'] = True
                finally:
                    if child is not None and child.poll() is None:
                        child.terminate()
                        try:
                            child.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            child.kill()
                            child.wait(timeout=5)
        finally:
            if log is not None:
                log.close()
                report['logStreamClosed'] = log.closed
        report['processCustody'] = owner.assert_retired()
        need(report['processCustody']['original_count'] == 1
             and report['processCustody']['passed_process_custody'], 'exact_original_rust_custody')
        need(key_metadata(OLD / 'tls.key') == key_before, 'original_synthetic_key_identity_changed')
        verify_records(records, until)
        report.update(remoteClosureUnknown=False, allInputsUnchanged=True,
                      originalSyntheticKeyIdentityUnchanged=True, originalRustChildRetired=True,
                      diagnosticComplete=True, ok=True)
    except BaseException as error:
        report['error'] = safe_error(error)
    finally:
        if log is not None and not log.closed:
            log.close()
        if owner is not None:
            report['processCustody'] = owner.receipt()
            report['remoteClosureUnknown'] = not (
                owner.finished and all(row.get('original_wait_completed') is True
                and row.get('no_live_members_before_reap') is True for row in owner.rows))
        else:
            report['remoteClosureUnknown'] = False
            report['rustChildStarted'] = False
        report['elapsedSeconds'] = time.monotonic() - start
        report['logStreamClosed'] = log is None or log.closed
        if key_before is not None:
            try:
                report['originalSyntheticKeyIdentityUnchanged'] = key_metadata(OLD / 'tls.key') == key_before
            except BaseException:
                report['originalSyntheticKeyIdentityUnchanged'] = False
        report['ok'] = (report['ok'] and not report['remoteClosureUnknown'] and report['logStreamClosed']
                        and report.get('originalSyntheticKeyIdentityUnchanged') is True)
        if created:
            write_new(ROOT / 'result.public.json', (json.dumps(report, sort_keys=True) + '\n').encode())
        emit('final', report)
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(run_worker())
