#!/usr/bin/env python3
"""Back up the initialized complete runtime and prove independent cold recovery.

The original initialized store is never initialized or reset. Its actual data
writer fence remains held across copying and restored lifecycle checks. The
restored binary and TLS materials come from the complete backup; the existing
separate HOME custody supplies the original unseal/root material privately.
No current client credential, provider, service registration or legacy action.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
import time
import types

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-authbus-production')
CALLER_HOME = Path('/Users/qianqi')
CUSTODY = CALLER_HOME / 'heptabao-authbus-production-custody'
OPERATIONS = CUSTODY / 'complete-backup-r1'
BACKUPS = CALLER_HOME / 'heptabao-authbus-production-backups'
BACKUP_ROUND = BACKUPS / 'complete-20261107-r1'
RECOVERY = CALLER_HOME / 'heptabao-authbus-production-recovery-20261107-r1'
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
PRODUCT = '4bde9aee03fcd27c59e13607e529b1cee594b249'
BINARY = ROOT / 'releases' / PRODUCT / 'heptabao-server'
BINARY_BYTES = 92359328
BINARY_SHA = '5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c'
CA_SHA = '456ea07b02ead7ac3397507a4e41befeaad822dcdd74695f6a38239029aac01f'
LEAF_SHA = 'abaf8527105e19cbbe0da57a64c7a87d8e7f6e6ae15edc3636f5eee65eefd3bd'
PORT = 31080
CONFIG = ROOT / 'etc/server-bootstrap-r2.json'
ROLE = 'bootstrap-lifecycle-r1'
SECRET_PATH = '/v1/openclaw-auth/data/qualification/bootstrap-lifecycle-r1'
TOOL_PINS = {
    str(PYTHON): (34640, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'),
    '/usr/sbin/diskutil': (1937776, '624a8601b97ddfaa4b18dd2854c299e084cd45eb18fc152011c97615c3b9da1f'),
    '/usr/bin/sandbox-exec': (None, 'abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a'),
    '/bin/ps': (170432, '3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c'),
}
# PAYLOAD_PLACEHOLDER
START = time.monotonic()
UNTIL = START + 300
FDS = []
CONTROL_SIGNALS = None
REPORT = {'schema': 'heptabao.permanent-complete-runtime-backup.r1', 'ok': False,
    'productCommit': PRODUCT, 'automaticRetry': False, 'initializationRequests': 0,
    'currentCredentialReads': 0, 'providerCalls': 0, 'legacyChanges': 0,
    'productionClientChanges': 0, 'launchAgentInstalled': False, 'j3160Requests': 0,
    'rootKeyValuesOrDigestsPublished': False, 'backupManifestPublic': False,
    'productionCutoverQualified': False, 'productionBackupQualified': False,
    'parentSeconds': 300, 'supervisorSeconds': 330, 'eachApiPhaseSeconds': 120,
    'originalPermanentBootstrapJob': '1a1b396b21c-fc05-83b9',
    'serverProcesses': [], 'apiPhases': [], 'copyPhases': []}


class Refused(RuntimeError):
    pass

def need(value, code):
    if not value:
        raise Refused(code)

def remaining():
    need(CONTROL_SIGNALS is None or CONTROL_SIGNALS.pending is None, 'bootstrap_cancelled')
    value = UNTIL - time.monotonic()
    need(value > 0, 'bootstrap_original_parent_deadline')
    return value

def full9(value):
    return tuple(str(getattr(value, name)) for name in ('st_dev', 'st_ino', 'st_uid',
        'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def own(fd, label):
    row = {'fd': fd, 'label': label, 'attempts': 0, 'closed': False}
    FDS.append(row)
    return row

def close(row):
    if row['attempts']:
        return
    row['attempts'] = 1
    os.close(row['fd'])
    row['closed'] = True

def open_fd(path, flags, label, *, dir_fd=None):
    remaining()
    return own(os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
        0o600, **({} if dir_fd is None else {'dir_fd': dir_fd})), label)

class PrivateOperations:
    def __init__(self):
        self.counter = 0
        self.dirs = []
        previous = None
        for path in (Path('/'), Path('/Users'), CALLER_HOME, CUSTODY):
            row = open_fd(path if previous is None else path.name, os.O_RDONLY | os.O_DIRECTORY,
                          'private-parent', dir_fd=None if previous is None else previous['fd'])
            info = os.fstat(row['fd'])
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == (0 if path in (Path('/'), Path('/Users')) else 501)
                 and not info.st_mode & 0o022 and full9(info) == full9(path.lstat()), 'bootstrap_private_parent')
            if path == CUSTODY:
                need(stat.S_IMODE(info.st_mode) == 0o700, 'bootstrap_custody_private')
            self.dirs.append((path, row, full9(info)[:5]))
            previous = row
        self.check()
        os.mkdir(OPERATIONS.name, 0o700, dir_fd=previous['fd'])
        os.fsync(previous['fd'])
        self.root = open_fd(OPERATIONS.name, os.O_RDONLY | os.O_DIRECTORY, 'operation-directory', dir_fd=previous['fd'])
        info = os.fstat(self.root['fd'])
        need(info.st_uid == 501 and info.st_gid == 20 and stat.S_IMODE(info.st_mode) == 0o700,
             'bootstrap_new_operation_directory')
        self.dirs.append((OPERATIONS, self.root, full9(info)[:5]))
        self.check()

    def check(self):
        remaining()
        for path, row, identity in self.dirs:
            need(full9(os.fstat(row['fd']))[:5] == full9(path.lstat())[:5] == identity,
                 'bootstrap_same_private_parent')

    def create(self, name):
        self.check()
        need(re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,120}', name), 'bootstrap_fixed_private_name')
        row = open_fd(name, os.O_RDWR | os.O_CREAT | os.O_EXCL, name, dir_fd=self.root['fd'])
        before = os.fstat(row['fd'])
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_gid == 20
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600,
             'bootstrap_private_new_regular_file')
        os.fsync(row['fd']); os.fsync(self.root['fd'])
        return row

    def write(self, name, raw):
        need(isinstance(raw, bytes) and len(raw) <= 1048576, 'bootstrap_private_body_bound')
        row = self.create(name)
        try:
            start = full9(os.fstat(row['fd']))[:6]
            offset = 0
            while offset < len(raw):
                remaining()
                count = os.write(row['fd'], raw[offset:offset + 65536])
                need(count > 0, 'bootstrap_private_write_progress')
                offset += count
            os.fsync(row['fd']); os.fsync(self.root['fd'])
            after = os.fstat(row['fd'])
            need(full9(after)[:6] == start and after.st_size == len(raw)
                 and full9(after) == full9(os.stat(name, dir_fd=self.root['fd'], follow_symlinks=False)),
                 'bootstrap_private_write_generation')
        finally:
            close(row)
        self.check()

    def append(self, category, value):
        need(self.counter < 512 and category in ('api-request-intent', 'api-request-result',
             'server-start-intent', 'server-stop-result', 'bootstrap-recovery'), 'bootstrap_finite_journal')
        self.write('event-%04d.private.json' % self.counter, encoded({'category': category, 'value': value}))
        self.counter += 1

    def response_bytes(self, phase, ordinal, raw):
        need(phase in ('locked-positive', 'recovered', 'recovered-cold') and 1 <= ordinal <= 192, 'bootstrap_exact_response_slot')
        self.write('%s-%03d.response.private.bin' % (phase, ordinal), raw)

def binary_pin():
    row = open_fd(BINARY, os.O_RDONLY, 'fixed-normal-binary')
    try:
        before = os.fstat(row['fd'])
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_gid == 20
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o500
             and before.st_size == BINARY_BYTES, 'bootstrap_exact_binary_metadata')
        digest, count = hashlib.sha256(), 0
        while True:
            remaining()
            raw = os.read(row['fd'], min(1048576, BINARY_BYTES + 1 - count))
            if not raw:
                break
            count += len(raw); digest.update(raw)
            need(count <= BINARY_BYTES, 'bootstrap_exact_binary_bound')
        need(count == BINARY_BYTES and digest.hexdigest() == BINARY_SHA
             and full9(before) == full9(os.fstat(row['fd'])) == full9(BINARY.lstat()),
             'bootstrap_exact_original_normal_binary')
        return full9(before)
    finally:
        close(row)

def main():
    global CONTROL_SIGNALS
    import errno
    import fcntl
    os.umask(0o077)
    sys.dont_write_bytecode = True
    guard = operations = commands = signals = data_lock = None
    current = None
    process_rows, apis, copies, sensitive = [], [], [], []
    lock_held = False
    restored_protected = {}
    restored_directories = {}
    home_dirs = []
    try:
        need(sys.platform == 'darwin' and os.getuid() == 501 and os.getgid() == 20
             and Path(sys.executable).resolve(strict=True) == PYTHON, 'backup_exact_mac_owner_runtime')
        for name, source in PAYLOAD['sources'].items():
            raw = source.encode()
            need(len(raw) == PAYLOAD['pins'][name]['bytes'] and hashlib.sha256(raw).hexdigest()
                 == PAYLOAD['pins'][name]['sha256'], 'backup_exact_complete_source')
            ast.parse(source)
            module = types.ModuleType(Path(name).stem)
            module.__file__ = str(OPERATIONS / name)
            sys.modules[module.__name__] = module
            exec(compile(source, module.__file__, 'exec'), module.__dict__)
        from mac_owned_commands_r1 import Commands, Signals
        from mac_owned_unreaped_r1 import require_waitid, capture_child, stop_once_unreaped
        from mac_production_t5_guard_r1 import HeldT5
        from mac_public_code_pin_excerpt_r1 import public_code_pin
        from permanent_recovery_api_r1 import Api
        from complete_cold_tree_backup_r2 import CompleteColdCopy
        signals = Signals(); signals.install(); commands = Commands(signals)
        CONTROL_SIGNALS = signals
        pins = {}
        for path, expected in TOOL_PINS.items():
            pin = public_code_pin(path, remaining=remaining, critical=signals.critical)
            need(pin['sha256'] == expected[1] and (expected[0] is None or pin['bytes'] == expected[0]),
                 'backup_exact_native_tool')
            pins[path] = pin
        anchor = {'schema': 'heptabao.mac-current-t5-public-anchor.r1',
            'source_inventory_sha256': hashlib.sha256(encoded(PAYLOAD['pins'])).hexdigest(),
            'volumeUUID': 'FB804D1B-24CB-4D6E-AEA7-A9E180807758',
            'expectedVolumeDevice': str(Path('/Volumes/T5').lstat().st_dev),
            'anchors': [{'path': path, 'identity': list(full9(Path(path).lstat()))}
                        for path in ('/', '/Volumes', '/Volumes/T5')]}
        raw = encoded(anchor)
        guard = HeldT5(raw, hashlib.sha256(raw).hexdigest(), remaining, signals.critical)
        record, out, err = commands.run('backup-t5-volume', ['/usr/sbin/diskutil', 'info', '-plist', '/Volumes/T5'],
            until=min(UNTIL, time.monotonic() + 15), maximum=262144)
        need(record['exitCode'] == 0 and not record['outcomeUnknown'] and not err, 'backup_known_original_t5')
        guard.accept_diskutil(out)
        operations = PrivateOperations()
        for name, source in PAYLOAD['sources'].items():
            operations.write(name, source.encode())
        operations.write('source-pins.public.json', encoded(PAYLOAD['pins']))
        expected_config = {'listen': '127.0.0.1:31080', 'data_dir': str(ROOT / 'data'),
            'audit_file': str(ROOT / 'log/audit.jsonl'), 'tls_cert_file': str(ROOT / 'tls/server-r2.crt'),
            'tls_key_file': str(ROOT / 'tls/server.key'), 'max_connections': 64, 'timeout_seconds': 15,
            'rate_limit_per_second': 2000, 'rate_limit_burst': 4000, 'rate_limit_entries': 512,
            'storage': {'native_v6_file': {'path': str(ROOT / 'data')}}}
        need(json.loads(guard.read(CONFIG, 16384)) == expected_config, 'backup_exact_original_configuration')
        before_binary = binary_pin()
        protected = {path: full9(path.lstat()) for path in
            (BINARY, CONFIG, ROOT / 'tls/ca.crt', ROOT / 'tls/server-r2.crt', ROOT / 'tls/server.key')}
        for name, expected in (('ca.crt', CA_SHA), ('server-r2.crt', LEAF_SHA)):
            raw = guard.read(ROOT / 'tls' / name, 16384)
            need(hashlib.sha256(ssl.PEM_cert_to_DER_cert(raw.decode('ascii'))).hexdigest() == expected,
                 'backup_exact_original_independent_certificate')

        class BoundGuard:
            def check(self):
                remaining(); guard.check(); operations.check()
                for path, stamp in protected.items():
                    need(full9(path.lstat()) == stamp, 'backup_original_code_configuration_generation')
                for path, stamp in restored_protected.items():
                    need(full9(path.lstat()) == stamp, 'backup_restored_code_configuration_generation')
                for path, stamp in restored_directories.items():
                    need(full9(path.lstat())[:5] == stamp, 'backup_restored_parent_namespace_generation')
                for path, row, stamp in home_dirs:
                    need(full9(os.fstat(row['fd']))[:5] == full9(path.lstat())[:5] == stamp,
                         'backup_original_home_directory_namespace')
                if data_lock is not None and not data_lock['closed']:
                    need(full9(os.fstat(data_lock['fd']))[:5] == full9((ROOT / 'data').lstat())[:5]
                         == data_identity, 'backup_original_data_directory_lock_anchor')
        fence = BoundGuard()

        def open_home_directory(path, *, create=False):
            need(path in (BACKUPS, BACKUP_ROUND, RECOVERY), 'backup_finite_home_roots')
            parent = open_fd(path.parent, os.O_RDONLY | os.O_DIRECTORY, 'home-root-parent')
            before = os.fstat(parent['fd'])
            need(full9(before) == full9(path.parent.lstat()) and stat.S_ISDIR(before.st_mode)
                 and before.st_uid == 501 and not stat.S_IMODE(before.st_mode) & 0o022,
                 'backup_private_home_parent')
            home_dirs.append((path.parent, parent, full9(before)[:5]))
            if create:
                os.mkdir(path.name, 0o700, dir_fd=parent['fd']); os.fsync(parent['fd'])
            row = open_fd(path.name, os.O_RDONLY | os.O_DIRECTORY, 'home-root', dir_fd=parent['fd'])
            info = os.fstat(row['fd'])
            need(CompleteColdCopy.private_directory(info) and full9(info) == full9(path.lstat())
                 and info.st_dev != int(anchor['expectedVolumeDevice']), 'backup_independent_private_home_filesystem')
            home_dirs.append((path, row, full9(info)[:5]))
            return row

        def write_home(parent, name, raw):
            fence.check()
            need(re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,120}', name) and isinstance(raw, bytes)
                 and len(raw) <= 2 * 1048576, 'backup_bounded_new_private_home_file')
            row = open_fd(name, os.O_RDWR | os.O_CREAT | os.O_EXCL, 'new-home-private-file', dir_fd=parent['fd'])
            try:
                first = os.fstat(row['fd'])
                need(CompleteColdCopy.private_file(first) and first.st_size == 0, 'backup_private_home_file')
                offset = 0
                while offset < len(raw):
                    remaining(); count = os.write(row['fd'], raw[offset:offset + 65536])
                    need(count > 0, 'backup_private_home_write_progress'); offset += count
                os.fsync(row['fd']); os.fsync(parent['fd'])
                final = os.fstat(row['fd'])
                need(full9(first)[:6] == full9(final)[:6] and final.st_size == len(raw)
                     and full9(final) == full9(os.stat(name, dir_fd=parent['fd'], follow_symlinks=False)),
                     'backup_private_home_publication_generation')
                os.lseek(row['fd'], 0, os.SEEK_SET)
                readback = bytearray()
                while len(readback) <= len(raw):
                    remaining(); part = os.read(row['fd'], min(65536, len(raw) + 1 - len(readback)))
                    if not part: break
                    readback.extend(part)
                need(bytes(readback) == raw and full9(final) == full9(os.fstat(row['fd']))
                     == full9(os.stat(name, dir_fd=parent['fd'], follow_symlinks=False)),
                     'backup_private_home_publication_readback')
                return full9(final)
            finally:
                close(row)

        def read_old_private(name):
            need(name in ('initial-002.response.private.bin', 'temporary-role.private.json',
                 'cold-new-process-004.response.private.bin'), 'backup_exact_independent_custody_inputs')
            parent = open_fd('bootstrap-r2', os.O_RDONLY | os.O_DIRECTORY,
                'original-bootstrap-custody-directory', dir_fd=operations.dirs[-2][1]['fd'])
            try:
                info = os.fstat(parent['fd'])
                need(CompleteColdCopy.private_directory(info) and full9(info) == full9((CUSTODY / 'bootstrap-r2').lstat()),
                     'backup_existing_custody_directory')
                row = open_fd(name, os.O_RDONLY, 'original-bootstrap-private-file', dir_fd=parent['fd'])
                try:
                    first = os.fstat(row['fd'])
                    need(CompleteColdCopy.private_file(first) and 0 < first.st_size <= 1048576,
                         'backup_existing_bounded_private_custody_file')
                    value = bytearray()
                    while len(value) <= first.st_size:
                        remaining(); part = os.read(row['fd'], min(65536, first.st_size + 1 - len(value)))
                        if not part: break
                        value.extend(part)
                    need(len(value) == first.st_size and full9(first) == full9(os.fstat(row['fd']))
                         == full9(os.stat(name, dir_fd=parent['fd'], follow_symlinks=False))
                         and full9(info) == full9(os.fstat(parent['fd'])) == full9((CUSTODY / 'bootstrap-r2').lstat()),
                         'backup_complete_original_private_custody_generation')
                    return json.loads(value)
                finally:
                    close(row)
            finally:
                close(parent)

        def start_server(phase, *, binary, config, directory, port, ca, sandbox=False):
            nonlocal current
            need(current is None and len(process_rows) < 3 and phase in ('locked-positive', 'recovered', 'recovered-cold'),
                 'backup_finite_original_server_starts')
            require_waitid(); fence.check()
            outputs = [operations.create(phase + '.' + label + '.private.log') for label in ('stdout', 'stderr')]
            argv = [str(binary), '--config', str(config)]
            if sandbox:
                argv = ['/usr/bin/sandbox-exec', '-f', str(RECOVERY / 'recovery.sb'), *argv]
            operations.append('server-start-intent', {'phase': phase, 'argv': argv, 'state': 'dispatched_or_unknown'})
            current = {'phase': phase, 'process': None, 'custody': None, 'stopAttempted': False, 'outputs': outputs}
            process_rows.append(current)
            with signals.critical():
                process = subprocess.Popen(argv, cwd=str(directory), stdin=subprocess.DEVNULL,
                    stdout=outputs[0]['fd'], stderr=outputs[1]['fd'], start_new_session=True, close_fds=True,
                    env={'HOME': str(CALLER_HOME), 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'})
                current['process'] = process
            current['custody'] = capture_child(process, until=min(UNTIL, time.monotonic() + 15))
            api = Api({'port': port, 'certificateLeafSha256': LEAF_SHA, 'caFile': str(ca)}, phase,
                      min(UNTIL, time.monotonic() + 120), operations, fence)
            apis.append(api)
            return api

        def stop_server():
            nonlocal current
            if current is None: return
            need(not current['stopAttempted'], 'backup_original_server_stop_once')
            current['stopAttempted'] = True
            with signals.critical():
                current['cleanup'] = (stop_once_unreaped(current['process'], current['custody'])
                    if current['process'] is not None else {'ok': False, 'outcomeUnknown': True})
            report = {'phase': current['phase'], 'cleanup': current['cleanup'], 'logs': []}
            for descriptor in current['outputs']:
                os.fsync(descriptor['fd']); first = os.fstat(descriptor['fd'])
                need(first.st_size <= 2097152, 'backup_bounded_original_server_log')
                os.lseek(descriptor['fd'], 0, os.SEEK_SET); content = bytearray()
                while len(content) <= first.st_size:
                    block = os.read(descriptor['fd'], min(65536, first.st_size + 1 - len(content)))
                    if not block: break
                    content.extend(block)
                need(len(content) == first.st_size and full9(first) == full9(os.fstat(descriptor['fd'])),
                     'backup_stopped_original_server_log_complete')
                report['logs'].append({'bytes': len(content),
                    'containsCredentialPlaintext': any(value.encode() in content for value in sensitive if value)})
                close(descriptor)
            need(current['cleanup'].get('ok') is True and not any(row['containsCredentialPlaintext'] for row in report['logs']),
                 'backup_original_server_and_private_logs_closed')
            operations.append('server-stop-result', report)
            REPORT['serverProcesses'].append(report); current = None

        original_init = read_old_private('initial-002.response.private.bin')
        original_role = read_old_private('temporary-role.private.json')
        old_probe = read_old_private('cold-new-process-004.response.private.bin')['data']
        root_token, unseal = original_init.get('root_token'), original_init.get('keys_base64', [None])[0]
        role_id, old_sid, old_token = (original_role.get(key) for key in ('roleId', 'secretId', 'token'))
        need(all(isinstance(value, str) and 8 <= len(value) <= 16384 for value in
                 (root_token, unseal, role_id, old_sid, old_token))
             and old_probe.get('metadata', {}).get('version') == 2 and isinstance(old_probe.get('data'), dict),
             'backup_actual_original_independent_custody_material')
        sensitive.extend((root_token, unseal, role_id, old_sid, old_token))
        value = old_probe['data']
        for port in (31080, 31082):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(('127.0.0.1', port))
        with guard.parent(ROOT / 'data') as (parent, name):
            data_lock = open_fd(name, os.O_RDONLY | os.O_DIRECTORY, 'original-data-writer-fence', dir_fd=parent)
        data_identity = full9(os.fstat(data_lock['fd']))[:5]
        need(CompleteColdCopy.private_directory(os.fstat(data_lock['fd'])), 'backup_actual_private_data_directory')
        with signals.critical():
            fcntl.flock(data_lock['fd'], fcntl.LOCK_EX | fcntl.LOCK_NB); lock_held = True
        # Ordinary startup is sealed and deliberately has no data writer.
        # The actual Rust FileBackend takes its writer fence during unseal.
        # Keep this same owned process/key/config and change only our lock.
        positive = start_server('locked-positive', binary=BINARY, config=CONFIG, directory=ROOT,
            port=31080, ca=ROOT / 'tls/ca.crt')
        positive.root_token = root_token
        health = positive.call('writer_lock.initial_health', 'GET', '/v1/sys/health', token='',
            expected=503, category='health', readiness=True)
        positive.check('writer_lock.original_store_initialized_sealed', health.get('initialized') is True and health.get('sealed') is True)
        rejected = positive.call('writer_lock.unseal_while_python_locked', 'POST', '/v1/sys/unseal',
            {'key': unseal}, token='', expected=400, category='unseal')
        positive.check('writer_lock.known_backend_rejection', rejected.get('errors') == ['unseal or recovery failed'])
        health = positive.call('writer_lock.rejected_remains_sealed', 'GET', '/v1/sys/health', token='',
            expected=503, category='health')
        positive.check('writer_lock.rejected_state_sealed', health.get('initialized') is True and health.get('sealed') is True)
        with signals.critical():
            fcntl.flock(data_lock['fd'], fcntl.LOCK_UN); lock_held = False
        positive.check('writer_lock.same_process_unseals_after_release', positive.call(
            'writer_lock.unseal_after_release', 'POST', '/v1/sys/unseal', {'key': unseal},
            token='', category='unseal').get('sealed') is False)
        positive.check('writer_lock.actual_native_format_two', positive.call('writer_lock.capacity', 'GET',
            '/v1/sys/internal/capacity', category='capacity').get('data', {}).get('native_kv2_reader_format') == 2)
        probe = positive.call('writer_lock.original_probe', 'GET', SECRET_PATH, category='kv-read')['data']
        positive.check('writer_lock.original_probe_v2_private_equal', probe['metadata']['version'] == 2 and probe['data'] == value)
        busy = False
        with signals.critical():
            try:
                fcntl.flock(data_lock['fd'], fcntl.LOCK_EX | fcntl.LOCK_NB); lock_held = True
            except BlockingIOError as error:
                need(error.errno in (errno.EAGAIN, errno.EWOULDBLOCK), 'backup_reverse_lock_errno')
                busy = True
        need(busy and not lock_held, 'backup_actual_rust_writer_excludes_python_copy')
        stop_server()
        with signals.critical():
            fcntl.flock(data_lock['fd'], fcntl.LOCK_EX | fcntl.LOCK_NB); lock_held = True
        REPORT['actualNormalServerDirectoryWriterLockQualified'] = True
        REPORT['writerFenceProof'] = {'sameOriginalServerAcrossNegativeAndPositive': True,
            'sealedStartupIsNotWriterAcquisition': True, 'pythonLockDeniesKnownCompleteUnseal': True,
            'releasedPythonLockAdmitsSameKeyAndServer': True, 'activeRustWriterDeniesPythonLock': True,
            'originalServerStoppedBeforeColdCopy': True, 'unknownRequestReplayed': False}
        open_home_directory(BACKUPS)
        backup_dir = open_home_directory(BACKUP_ROUND, create=True)
        recovery_dir = open_home_directory(RECOVERY, create=True)
        for path in (BACKUP_ROUND, RECOVERY):
            free = os.statvfs(path)
            need(free.f_bavail * free.f_frsize >= 2 * 1024 * 1024 * 1024, 'backup_fresh_independent_filesystem_budget')
        relative_binary = 'releases/' + PRODUCT + '/heptabao-server'
        public_pin = {relative_binary: (BINARY_BYTES, BINARY_SHA)}
        backup = CompleteColdCopy(ROOT, BACKUP_ROUND / 'runtime', check=fence.check,
            critical=signals.critical, public_executables=public_pin)
        copies.append(('complete-runtime-backup', backup))
        manifest = backup.run()
        need(any(row['path'] == 'data/seal.json' for row in manifest['files'])
             and any(row['path'] == 'tls/server.key' for row in manifest['files'])
             and any(row['path'] == 'log/audit.jsonl' for row in manifest['files']),
             'backup_complete_runtime_data_tls_audit_present')
        write_home(backup_dir, 'manifest.private.json', encoded(manifest))
        write_home(backup_dir, 'recovery-requirements.private.json', encoded({
            'schema': 'heptabao.permanent-complete-backup-requirements.r1',
            'unsealAndRootCustody': str(CUSTODY / 'bootstrap-r2'),
            'independentCaCustody': str(CUSTODY / 'pki'),
            'separateCustodyRequired': True, 'unsealMaterialIncludedInRuntimeBackup': False,
            'storeAlreadyInitialized': True, 'reinitializeForbidden': True,
            'publicNormalBinarySha256': BINARY_SHA, 'productCommit': PRODUCT,
            'originalDataWriterLockHeldThroughBackupAndRecovery': True}))
        restore = CompleteColdCopy(BACKUP_ROUND / 'runtime', RECOVERY / 'runtime', check=fence.check,
            critical=signals.critical, public_executables=public_pin, expected_manifest=manifest)
        copies.append(('complete-runtime-restore', restore))
        restored_manifest = restore.run()
        write_home(recovery_dir, 'restore-manifest.private.json', encoded(restored_manifest))
        restored = RECOVERY / 'runtime'
        for relative, (_, stamp, _, _) in restore.dest_dirs.items():
            restored_directories[restored / relative] = stamp
        for relative in (relative_binary, 'tls/ca.crt', 'tls/server-r2.crt', 'tls/server.key'):
            restored_protected[restored / relative] = restore.entries[relative]['destinationIdentity']
        fence.check()
        recovery_config = dict(expected_config, listen='127.0.0.1:31082',
            data_dir=str(restored / 'data'), audit_file=str(restored / 'log/audit.jsonl'),
            tls_cert_file=str(restored / 'tls/server-r2.crt'), tls_key_file=str(restored / 'tls/server.key'),
            storage={'native_v6_file': {'path': str(restored / 'data')}})
        restored_protected[RECOVERY / 'server.config.private.json'] = write_home(
            recovery_dir, 'server.config.private.json', encoded(recovery_config))
        policy = ('(version 1)\n(allow default)\n'
            '(deny file-read* (subpath ' + json.dumps(str(ROOT)) + '))\n'
            '(deny file-write* (subpath ' + json.dumps(str(ROOT)) + '))\n'
            '(deny file-read* (subpath "/Users/qianqi/.openclaw"))\n'
            '(deny file-write* (subpath "/Users/qianqi/.openclaw"))\n')
        restored_protected[RECOVERY / 'recovery.sb'] = write_home(recovery_dir, 'recovery.sb', policy.encode())
        denial_source = ('import errno,json,os\npaths=' + repr([str(ROOT / 'data/seal.json'), str(BINARY)])
            + '\ncount=0\nfor p in paths:\n'
            ' try:\n  fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)\n'
            ' except PermissionError as e:\n  assert e.errno in (errno.EACCES,errno.EPERM);count+=1\n'
            ' else:\n  os.close(fd);raise AssertionError("source_not_denied")\n'
            'print(json.dumps({"denied":count,"required":2,"fileContentsRead":0}))\n')
        record, out, err = commands.run('recovery-kernel-original-source-denial',
            ['/usr/bin/sandbox-exec', '-f', str(RECOVERY / 'recovery.sb'), str(PYTHON), '-I', '-S', '-c', denial_source],
            until=min(UNTIL, time.monotonic() + 15), maximum=65536)
        need(record['exitCode'] == 0 and not record['outcomeUnknown'] and not err
             and json.loads(out) == {'denied': 2, 'required': 2, 'fileContentsRead': 0},
             'backup_actual_kernel_original_t5_source_denied')
        REPORT['restoredServerKernelDeniedOriginalRuntime'] = True
        recovered = start_server('recovered', binary=restored / relative_binary,
            config=RECOVERY / 'server.config.private.json', directory=restored,
            port=31082, ca=restored / 'tls/ca.crt', sandbox=True)
        recovered.root_token = root_token
        health = recovered.call('restore.health', 'GET', '/v1/sys/health', token='', expected=503,
            category='health', readiness=True)
        recovered.check('restore.existing_initialized_sealed', health.get('initialized') is True and health.get('sealed') is True)
        recovered.check('restore.original_separate_key_unseals', recovered.call('restore.unseal', 'POST',
            '/v1/sys/unseal', {'key': unseal}, token='', category='unseal').get('sealed') is False)
        recovered.check('restore.native_format_two', recovered.call('restore.capacity', 'GET',
            '/v1/sys/internal/capacity', category='capacity').get('data', {}).get('native_kv2_reader_format') == 2)
        probe = recovered.call('restore.original_probe', 'GET', SECRET_PATH, category='kv-read')['data']
        recovered.check('restore.original_version_two_and_private_value_equal',
            probe['metadata']['version'] == 2 and probe['data'] == value)
        recovered.call('restore.original_revoked_token_denied', 'GET', SECRET_PATH,
            token=old_token, expected=403, category='kv-read')
        recovered.call('restore.original_destroyed_sid_denied', 'POST', '/v1/auth/approle/login',
            {'role_id': role_id, 'secret_id': old_sid}, token='', expected=400, category='login')
        base = '/v1/auth/approle/role/' + ROLE
        restored_role = recovered.call('restore.role_id', 'GET', base + '/role-id', category='role-id')['data']['role_id']
        recovered.check('restore.original_role_identity_persisted', restored_role == role_id)
        sid = recovered.call('restore.fresh_sid', 'POST', base + '/secret-id', {}, category='secret-id')['data']['secret_id']
        sensitive.append(sid)
        login = {'role_id': role_id, 'secret_id': sid}
        auth = recovered.call('restore.fresh_login', 'POST', '/v1/auth/approle/login', login, token='', category='login')['auth']
        token = auth['client_token']; sensitive.append(token)
        recovered.check('restore.scoped_renewable_role', auth.get('renewable') is True and ROLE in auth.get('policies', []))
        recovered.check('restore.scoped_read', recovered.call('restore.scoped_read', 'GET', SECRET_PATH,
            token=token, category='kv-read')['data']['data'] == value)
        recovered.call('restore.other_key_denied', 'GET', '/v1/openclaw-auth/data/qualification/other',
            token=token, expected=403, category='kv-read')
        recovered.call('restore.admin_denied', 'GET', '/v1/sys/mounts', token=token, expected=403, category='admin-denied')
        renewed = recovered.call('restore.renew', 'POST', '/v1/auth/token/renew-self',
            {'increment': '1200s'}, token=token, category='renew')['auth']
        recovered.check('restore.same_positive_bearer_renewed', renewed.get('client_token') == token
            and renewed.get('renewable') is True and renewed.get('lease_duration', 0) > 0)
        new_value = dict(value, recoveryMarker=os.urandom(16).hex())
        recovered.check('restore.cas_two_to_three', recovered.call('restore.write', 'POST', SECRET_PATH,
            {'data': new_value, 'options': {'cas': 2}}, token=token, category='kv-write')['data']['version'] == 3)
        recovered.call('restore.revoke', 'POST', '/v1/auth/token/revoke-self', {}, token=token, expected=204, category='revoke')
        recovered.call('restore.revoked_read_denied', 'GET', SECRET_PATH, token=token, expected=403, category='kv-read')
        recovered.call('restore.destroy_sid', 'POST', base + '/secret-id/destroy', {'secret_id': sid},
            expected=204, category='secret-destroy')
        recovered.call('restore.destroyed_sid_denied', 'POST', '/v1/auth/approle/login', login,
            token='', expected=400, category='login')
        stop_server()
        cold = start_server('recovered-cold', binary=restored / relative_binary,
            config=RECOVERY / 'server.config.private.json', directory=restored,
            port=31082, ca=restored / 'tls/ca.crt', sandbox=True)
        cold.root_token = root_token
        health = cold.call('restore_cold.health', 'GET', '/v1/sys/health', token='', expected=503,
            category='health', readiness=True)
        cold.check('restore_cold.sealed', health.get('initialized') is True and health.get('sealed') is True)
        cold.check('restore_cold.unsealed', cold.call('restore_cold.unseal', 'POST', '/v1/sys/unseal',
            {'key': unseal}, token='', category='unseal').get('sealed') is False)
        probe = cold.call('restore_cold.read', 'GET', SECRET_PATH, category='kv-read')['data']
        cold.check('restore_cold.version_three_private_value_persisted',
            probe['metadata']['version'] == 3 and probe['data'] == new_value)
        cold.call('restore_cold.revocation_persisted', 'GET', SECRET_PATH, token=token, expected=403, category='kv-read')
        cold.call('restore_cold.sid_destruction_persisted', 'POST', '/v1/auth/approle/login', login,
            token='', expected=400, category='login')
        stop_server()
        # The original data fence stayed held through both recovery processes.
        # Verify all names/full generations again, including original audit,
        # configuration, TLS files, native objects and the public executable.
        verifier = CompleteColdCopy(ROOT, BACKUP_ROUND / 'never-created-verifier', check=fence.check,
            critical=signals.critical, public_executables=public_pin)
        try:
            source = verifier.open_chain(ROOT); verifier.scan('', source); verifier.source_unchanged()
            need(verifier.children == backup.children and set(verifier.entries) == set(backup.entries)
                 and {name: stamp for name, (_, stamp) in verifier.source_dirs.items()}
                     == {name: stamp for name, (_, stamp) in backup.source_dirs.items()}
                 and all(verifier.entries[name]['sourceIdentity'] == backup.entries[name]['sourceIdentity']
                         for name in backup.entries), 'backup_entire_original_runtime_unchanged_through_restore')
        finally:
            verifier_errors = []
            for descriptor in reversed(verifier.fds):
                try: verifier.close(descriptor)
                except BaseException: verifier_errors.append('source_verifier_descriptor_close_failed')
            REPORT['finalSourceMetadataDescriptors'] = len(verifier.fds)
            REPORT['finalSourceMetadataDescriptorsClosedOnce'] = all(row['attempts'] == 1 and row['closed'] for row in verifier.fds)
            REPORT['finalSourceMetadataCloseErrors'] = verifier_errors
            need(not verifier_errors and REPORT['finalSourceMetadataDescriptorsClosedOnce'],
                 'backup_final_source_metadata_closure')
        need(binary_pin() == before_binary, 'backup_original_binary_still_exact')
        for path, expected in pins.items():
            need(public_code_pin(path, remaining=remaining, critical=signals.critical) == expected,
                 'backup_native_tools_still_exact')
        fence.check()
        REPORT.update(ok=True, completeRuntimeBackupAndRestoredColdLifecycleQualified=True,
            originalRuntimeAndDataUnchangedThroughRecovery=True, independentFilesystemBackup=True,
            copiedRuntimeFiles=manifest['completeFileCount'], copiedRuntimeBytes=manifest['completeBytes'],
            sourceFilesExcluded=0, sealAndRootCustodySeparateAndRequired=True,
            backupContainsActualCurrentProductionCredentials=False,
            restoredBinarySource='complete-independent-backup', finalServersRunning=False)
        operations.write('business-phase-complete.private.json', encoded({
            'businessChecksComplete': True, 'finalOriginalResourceClosureNotYetObserved': True,
            'notFurtherActionAuthorityWithoutOriginalTerminal': True}))
    except BaseException as error:
        REPORT['errorType'] = type(error).__name__
        safe = re.fullmatch(r'[a-z0-9._-]{1,120}', str(error)) is not None
        REPORT['errorCode'] = str(error) if safe and type(error).__name__ in ('Refused', 'BackupRefused') else 'backup_original_attempt_failed_no_replay'
        REPORT['ok'] = False
    finally:
        if current is not None:
            try: stop_server()
            except BaseException as error:
                REPORT['serverClosureError'] = type(error).__name__; REPORT['ok'] = False
        REPORT['apiPhases'] = [api.public() for api in apis]
        REPORT['copyPhases'] = [{'phase': phase, **copier.result} for phase, copier in copies]
        REPORT['originalServerCleanupRecords'] = [{'phase': row['phase'], 'stopAttempted': row['stopAttempted'],
            'pid': row['process'].pid if row['process'] is not None else None, 'cleanup': row.get('cleanup')} for row in process_rows]
        REPORT['allOriginalServersClosed'] = all(row['stopAttempted'] and row.get('cleanup', {}).get('ok') is True for row in process_rows)
        errors = []
        if data_lock is not None:
            try: close(data_lock)
            except BaseException: errors.append('original_data_fence_close_failed')
        REPORT['originalDataWriterFenceReleased'] = data_lock is None or data_lock['closed']
        if guard is not None:
            try: guard.close()
            except BaseException: errors.append('t5_guard_close_failed')
            REPORT['volumeClosure'] = guard.public_state()
        for descriptor in reversed(FDS):
            try: close(descriptor)
            except BaseException: errors.append('outer_descriptor_close_failed')
        REPORT['allExplicitDescriptorsClosedOnce'] = all(row['attempts'] == 1 and row['closed'] for row in FDS)
        REPORT['explicitDescriptors'] = len(FDS); REPORT['descriptorCloseErrors'] = errors
        REPORT['commands'] = commands.public() if commands is not None else {'allOwnedCommandsStopped': True, 'unknownCommandCount': 0, 'commands': []}
        REPORT['deadlineAfterClosure'] = time.monotonic() < UNTIL
        REPORT['cancellationObserved'] = CONTROL_SIGNALS is not None and CONTROL_SIGNALS.pending is not None
        REPORT['ok'] = bool(REPORT['ok'] and not errors and REPORT['allOriginalServersClosed']
            and REPORT['originalDataWriterFenceReleased'] and REPORT['allExplicitDescriptorsClosedOnce']
            and all(copier.result['ok'] and copier.result['allDescriptorsClosedOnce'] for _, copier in copies)
            and REPORT.get('finalSourceMetadataDescriptorsClosedOnce') is True
            and REPORT['commands']['allOwnedCommandsStopped'] and REPORT['commands']['unknownCommandCount'] == 0
            and REPORT['deadlineAfterClosure'] and not REPORT['cancellationObserved']
            and REPORT.get('volumeClosure', {}).get('lastAnchorCheckPassed')
            and REPORT['volumeClosure']['allDescriptorsClosed'])
        REPORT['elapsedSeconds'] = time.monotonic() - START
        print(json.dumps(REPORT, sort_keys=True), flush=True)
    return 0 if REPORT['ok'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
