#!/usr/bin/env python3
"""Initialize the new independent service once, prove its cold lifecycle, stop.

No installed service, current credential, provider, legacy service or client is
opened. Every actual API response is retained privately before parsing. A failed
or unknown request prevents the next phase; this program never retries it.
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
OPERATIONS = CUSTODY / 'bootstrap-r1'
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
PRODUCT = '4bde9aee03fcd27c59e13607e529b1cee594b249'
BINARY = ROOT / 'releases' / PRODUCT / 'heptabao-server'
BINARY_BYTES = 92359328
BINARY_SHA = '5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c'
CA_SHA = '456ea07b02ead7ac3397507a4e41befeaad822dcdd74695f6a38239029aac01f'
LEAF_SHA = '44b6927479f25f2eb9b2a1d0fb9b522066f03200ad03e0400dee76132c7e589c'
PORT = 31080
CONFIG = ROOT / 'etc/server-bootstrap.json'
ROLE = 'bootstrap-lifecycle-r1'
SECRET_PATH = '/v1/openclaw-auth/data/qualification/bootstrap-lifecycle-r1'
TOOL_PINS = {
    str(PYTHON): (34640, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'),
    '/usr/sbin/diskutil': (1937776, '624a8601b97ddfaa4b18dd2854c299e084cd45eb18fc152011c97615c3b9da1f'),
    '/bin/ps': (170432, '3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c'),
}
# PAYLOAD_PLACEHOLDER
START = time.monotonic()
UNTIL = START + 300
FDS = []
CONTROL_SIGNALS = None
REPORT = {'schema': 'heptabao.permanent-bootstrap-lifecycle.r1', 'ok': False,
    'productCommit': PRODUCT, 'automaticRetry': False, 'currentCredentialReads': 0,
    'providerCalls': 0, 'productionClientChanges': 0, 'launchAgentInstalled': False,
    'legacyChanges': 0, 'j3160Requests': 0, 'rootKeyValuesOrDigestsPublished': False,
    'productionCutoverQualified': False, 'productionBackupQualified': False,
    'parentSeconds': 300, 'eachApiPhaseSeconds': 120, 'supervisorSeconds': 330,
    'permanentStoreInitialized': False, 'serverProcesses': [], 'apiPhases': []}

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
        need(phase in ('initial', 'cold-new-process') and 1 <= ordinal <= 192, 'bootstrap_exact_response_slot')
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
    os.umask(0o077)
    sys.dont_write_bytecode = True
    guard = operations = commands = signals = None
    current = None
    process_rows = []
    apis = []
    sensitive = []
    try:
        need(sys.platform == 'darwin' and os.getuid() == 501 and os.getgid() == 20
             and Path(sys.executable).resolve(strict=True) == PYTHON, 'bootstrap_exact_mac_owner_runtime')
        for name, source in PAYLOAD['sources'].items():
            raw = source.encode()
            need(len(raw) == PAYLOAD['pins'][name]['bytes'] and hashlib.sha256(raw).hexdigest()
                 == PAYLOAD['pins'][name]['sha256'], 'bootstrap_complete_public_source_pin')
            ast.parse(source)
            module = types.ModuleType(Path(name).stem)
            module.__file__ = str(OPERATIONS / name)
            sys.modules[module.__name__] = module
            exec(compile(source, module.__file__, 'exec'), module.__dict__)
        from mac_owned_commands_r1 import Commands, Signals
        from mac_owned_unreaped_r1 import require_waitid, capture_child, stop_once_unreaped
        from mac_production_t5_guard_r1 import HeldT5
        from mac_public_code_pin_excerpt_r1 import public_code_pin
        from permanent_bootstrap_api_r1 import Api
        signals = Signals(); signals.install(); commands = Commands(signals)
        CONTROL_SIGNALS = signals
        pins = {}
        for name, expected in TOOL_PINS.items():
            value = public_code_pin(name, remaining=remaining, critical=signals.critical)
            need((value['bytes'], value['sha256']) == expected, 'bootstrap_exact_native_tool')
            pins[name] = value
        need(not OPERATIONS.exists() and not OPERATIONS.is_symlink(), 'bootstrap_original_slot_absent')
        anchor = {'schema': 'heptabao.mac-current-t5-public-anchor.r1', 'source_inventory_sha256': hashlib.sha256(encoded(PAYLOAD['pins'])).hexdigest(),
                  'volumeUUID': 'FB804D1B-24CB-4D6E-AEA7-A9E180807758',
                  'expectedVolumeDevice': str(Path('/Volumes/T5').lstat().st_dev),
                  'anchors': [{'path': path, 'identity': list(full9(Path(path).lstat()))} for path in ('/', '/Volumes', '/Volumes/T5')]}
        raw = encoded(anchor)
        guard = HeldT5(raw, hashlib.sha256(raw).hexdigest(), remaining, signals.critical)
        row, out, err = commands.run('bootstrap-t5-volume', ['/usr/sbin/diskutil', 'info', '-plist', '/Volumes/T5'],
                                     until=min(UNTIL, time.monotonic() + 15), maximum=262144)
        need(row['exitCode'] == 0 and not row['outcomeUnknown'] and not err, 'bootstrap_known_t5_volume')
        guard.accept_diskutil(out)
        expected_config = {'listen': '127.0.0.1:31080', 'data_dir': str(ROOT / 'data'),
            'audit_file': str(ROOT / 'log/audit.jsonl'), 'tls_cert_file': str(ROOT / 'tls/server.crt'),
            'tls_key_file': str(ROOT / 'tls/server.key'), 'max_connections': 64, 'timeout_seconds': 15,
            'rate_limit_per_second': 2000, 'rate_limit_burst': 4000, 'rate_limit_entries': 512,
            'storage': {'native_v6_file': {'path': str(ROOT / 'data')}}}
        need(json.loads(guard.read(CONFIG, 16384)) == expected_config, 'bootstrap_exact_loopback_configuration')
        for name, expected in (('ca.crt', CA_SHA), ('server.crt', LEAF_SHA)):
            raw = guard.read(ROOT / 'tls' / name, 16384)
            need(hashlib.sha256(ssl.PEM_cert_to_DER_cert(raw.decode('ascii'))).hexdigest() == expected,
                 'bootstrap_original_independent_certificate')
        key = (ROOT / 'tls/server.key').lstat()
        need(stat.S_ISREG(key.st_mode) and key.st_uid == 501 and key.st_gid == 20 and key.st_nlink == 1
             and stat.S_IMODE(key.st_mode) == 0o600, 'bootstrap_key_metadata_only')
        with guard.parent(ROOT / 'data') as (parent, name):
            directory = open_fd(name, os.O_RDONLY | os.O_DIRECTORY, 'initial-data-directory', dir_fd=parent)
            need(os.listdir(directory['fd']) == [], 'bootstrap_fresh_empty_permanent_data_directory')
            close(directory)
        before_bin = binary_pin()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(('127.0.0.1', PORT))
        operations = PrivateOperations()
        for name, source in PAYLOAD['sources'].items():
            operations.write(name, source.encode())
        operations.write('source-pins.public.json', encoded(PAYLOAD['pins']))
        operations.write('initial-config.private.json', encoded(expected_config))
        protected = {path: full9(path.lstat()) for path in
            (BINARY, CONFIG, ROOT / 'tls/ca.crt', ROOT / 'tls/server.crt', ROOT / 'tls/server.key')}
        class BoundGuard:
            def check(self):
                guard.check(); operations.check()
                for path, expected in protected.items():
                    need(full9(path.lstat()) == expected, 'bootstrap_fixed_configuration_and_binary_generation')
        fence = BoundGuard()
        fence.check()
        need(json.loads(guard.read(CONFIG, 16384)) == expected_config, 'bootstrap_config_readback_before_start')
        need(binary_pin() == before_bin, 'bootstrap_same_original_binary_before_start')
        for name, expected in (('ca.crt', CA_SHA), ('server.crt', LEAF_SHA)):
            raw = guard.read(ROOT / 'tls' / name, 16384)
            need(hashlib.sha256(ssl.PEM_cert_to_DER_cert(raw.decode('ascii'))).hexdigest() == expected,
                 'bootstrap_certificate_readback_before_start')
        fence.check()

        def start_server(phase):
            nonlocal current
            need(current is None and len(process_rows) < 2 and phase in ('initial', 'cold-new-process'), 'bootstrap_finite_server_start')
            require_waitid(); fence.check()
            outputs = [operations.create(phase + '.' + label + '.private.log') for label in ('stdout', 'stderr')]
            intent = {'phase': phase, 'argv': [str(BINARY), '--config', str(CONFIG)], 'state': 'dispatched_or_unknown'}
            operations.append('server-start-intent', intent)
            current = {'phase': phase, 'process': None, 'custody': None, 'stopAttempted': False, 'outputs': outputs}
            process_rows.append(current)
            with signals.critical():
                p = subprocess.Popen(intent['argv'], cwd=str(ROOT), stdin=subprocess.DEVNULL,
                    stdout=outputs[0]['fd'], stderr=outputs[1]['fd'], start_new_session=True, close_fds=True,
                    env={'HOME': str(CALLER_HOME), 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'})
                current['process'] = p
            current['custody'] = capture_child(p, until=min(UNTIL, time.monotonic() + 15))
            api = Api({'port': PORT, 'certificateLeafSha256': LEAF_SHA}, phase,
                      min(UNTIL, time.monotonic() + 120), operations, fence)
            apis.append(api)
            return api

        def stop_server():
            nonlocal current
            if current is None:
                return
            need(not current['stopAttempted'], 'bootstrap_original_stop_once')
            current['stopAttempted'] = True
            with signals.critical():
                if current['process'] is not None:
                    current['cleanup'] = stop_once_unreaped(current['process'], current['custody'])
                else:
                    current['cleanup'] = {'ok': False, 'outcomeUnknown': True}
            row = {'phase': current['phase'], 'cleanup': current['cleanup'], 'logs': []}
            for descriptor in current['outputs']:
                os.fsync(descriptor['fd'])
                before = os.fstat(descriptor['fd'])
                need(before.st_size <= 2097152, 'bootstrap_bounded_original_server_log')
                os.lseek(descriptor['fd'], 0, os.SEEK_SET)
                content = bytearray()
                while True:
                    block = os.read(descriptor['fd'], min(65536, 2097153 - len(content)))
                    if not block:
                        break
                    content.extend(block)
                    need(len(content) <= 2097152, 'bootstrap_server_log_limit')
                need(len(content) == before.st_size and full9(before) == full9(os.fstat(descriptor['fd'])), 'bootstrap_stopped_original_log_stable')
                row['logs'].append({'bytes': len(content), 'containsCredentialPlaintext': any(value.encode() in content for value in sensitive if value)})
                close(descriptor)
            need(current['cleanup'].get('ok') is True and not any(item['containsCredentialPlaintext'] for item in row['logs']), 'bootstrap_original_server_closed_private_logs')
            operations.append('server-stop-result', row)
            REPORT['serverProcesses'].append(row)
            current = None

        api = start_server('initial')
        health = api.call('initial.health', 'GET', '/v1/sys/health', token='', expected=501, category='health', readiness=True)
        api.check('initial.uninitialized', health.get('initialized') is False and health.get('sealed') is True)
        initialized = api.call('initial.init_once', 'POST', '/v1/sys/init', {'secret_shares': 1, 'secret_threshold': 1}, token='', category='init')
        root_token, unseal = initialized.get('root_token'), initialized.get('keys_base64', [None])[0]
        need(isinstance(root_token, str) and len(root_token) >= 8 and isinstance(unseal, str) and len(unseal) >= 8, 'bootstrap_original_init_material')
        sensitive.extend((root_token, unseal))
        operations.append('bootstrap-recovery', {'rootToken': root_token, 'unsealKey': unseal})
        REPORT['permanentStoreInitialized'] = True
        api.root_token = root_token
        api.check('initial.unsealed', api.call('initial.unseal', 'POST', '/v1/sys/unseal', {'key': unseal}, token='', category='unseal').get('sealed') is False)
        api.call('initial.kv_mount', 'POST', '/v1/sys/mounts/openclaw-auth', {'type': 'kv', 'options': {'version': '2'}}, expected=204, category='mount')
        api.call('initial.approle_mount', 'POST', '/v1/sys/auth/approle', {'type': 'approle'}, expected=204, category='mount')
        api.call('initial.native_activate', 'POST', '/v1/sys/storage/native-v6/activate', {}, expected=204, category='activate')
        api.check('initial.native_format_two', api.call('initial.capacity', 'GET', '/v1/sys/internal/capacity', category='capacity').get('data', {}).get('native_kv2_reader_format') == 2)
        value = {'schema': 'heptabao.permanent-bootstrap-probe.r1', 'marker': os.urandom(16).hex()}
        api.check('initial.version_one', api.call('initial.seed', 'POST', SECRET_PATH, {'data': value, 'options': {'cas': 0}}, category='kv-write').get('data', {}).get('version') == 1)
        policy = 'path "openclaw-auth/data/qualification/bootstrap-lifecycle-r1" { capabilities=["read","update"] }\npath "auth/token/lookup-self" { capabilities=["read"] }\npath "auth/token/renew-self" { capabilities=["update"] }\npath "auth/token/revoke-self" { capabilities=["update"] }\n'
        api.call('initial.policy', 'PUT', '/v1/sys/policies/acl/' + ROLE, {'policy': policy}, expected=204, category='policy')
        base = '/v1/auth/approle/role/' + ROLE
        api.call('initial.role', 'POST', base, {'token_policies': [ROLE], 'token_ttl': '1200s', 'token_max_ttl': '3600s', 'secret_id_num_uses': 0, 'secret_id_ttl': '3600s'}, expected=204, category='role')
        role_id = api.call('initial.role_id', 'GET', base + '/role-id', category='role-id')['data']['role_id']
        secret_id = api.call('initial.secret_id', 'POST', base + '/secret-id', {}, category='secret-id')['data']['secret_id']
        sensitive.extend((role_id, secret_id))
        login = {'role_id': role_id, 'secret_id': secret_id}
        auth = api.call('initial.login', 'POST', '/v1/auth/approle/login', login, token='', category='login')['auth']
        token = auth['client_token']; sensitive.append(token)
        api.check('initial.renewable', auth.get('renewable') is True and ROLE in auth.get('policies', []))
        api.check('initial.scoped_read', api.call('initial.scoped_read', 'GET', SECRET_PATH, token=token, category='kv-read')['data']['data'] == value)
        api.check('initial.scoped_write', api.call('initial.scoped_write', 'POST', SECRET_PATH, {'data': value, 'options': {'cas': 1}}, token=token, category='kv-write')['data']['version'] == 2)
        api.call('initial.other_key_denied', 'GET', '/v1/openclaw-auth/data/qualification/other', token=token, expected=403, category='kv-read')
        api.call('initial.admin_denied', 'GET', '/v1/sys/mounts', token=token, expected=403, category='admin-denied')
        renewed = api.call('initial.renew', 'POST', '/v1/auth/token/renew-self', {'increment': '1200s'}, token=token, category='renew')['auth']
        api.check('initial.same_token_renewal', renewed.get('client_token') == token and renewed.get('renewable') is True and renewed.get('lease_duration', 0) > 0)
        operations.write('temporary-role.private.json', encoded({'roleId': role_id, 'secretId': secret_id, 'token': token}))
        stop_server()

        cold = start_server('cold-new-process'); cold.root_token = root_token
        health = cold.call('cold.health', 'GET', '/v1/sys/health', token='', expected=503, category='health', readiness=True)
        cold.check('cold.sealed_existing', health.get('initialized') is True and health.get('sealed') is True)
        cold.check('cold.unsealed', cold.call('cold.unseal', 'POST', '/v1/sys/unseal', {'key': unseal}, token='', category='unseal').get('sealed') is False)
        cold.check('cold.native_format_two', cold.call('cold.capacity', 'GET', '/v1/sys/internal/capacity', category='capacity').get('data', {}).get('native_kv2_reader_format') == 2)
        stored = cold.call('cold.old_token_read', 'GET', SECRET_PATH, token=token, category='kv-read')['data']
        cold.check('cold.version_and_value_persisted', stored['metadata']['version'] == 2 and stored['data'] == value)
        fresh = cold.call('cold.new_login', 'POST', '/v1/auth/approle/login', login, token='', category='login')['auth']['client_token']
        sensitive.append(fresh); cold.check('cold.distinct_new_token', fresh != token)
        cold.check('cold.new_token_read', cold.call('cold.new_token_read', 'GET', SECRET_PATH, token=fresh, category='kv-read')['data']['data'] == value)
        for ordinal, bearer in enumerate((token, fresh), 1):
            cold.call('cold.revoke_' + str(ordinal), 'POST', '/v1/auth/token/revoke-self', {}, token=bearer, expected=204, category='revoke')
            cold.call('cold.revoked_read_' + str(ordinal), 'GET', SECRET_PATH, token=bearer, expected=403, category='kv-read')
        cold.call('cold.destroy_sid', 'POST', base + '/secret-id/destroy', {'secret_id': secret_id}, expected=204, category='secret-destroy')
        cold.call('cold.destroyed_sid_denied', 'POST', '/v1/auth/approle/login', login, token='', expected=400, category='login')
        stop_server()
        need(binary_pin() == before_bin, 'bootstrap_original_binary_unchanged')
        for name in pins:
            need(public_code_pin(name, remaining=remaining, critical=signals.critical) == pins[name], 'bootstrap_native_tools_unchanged')
        need(full9(key) == full9((ROOT / 'tls/server.key').lstat()), 'bootstrap_original_private_key_metadata_unchanged')
        guard.check(); operations.check()
        REPORT.update(ok=True, independentPermanentTlsAppRoleKvPolicyRenewRevokeQualified=True,
                      actualColdRestartQualified=True, actualCurrentCredentialReadWriteQualified=False,
                      permanentServiceInstalled=False, finalServerRunning=False)
        operations.write('business-phase-complete.private.json', encoded({
            'schema': 'heptabao.permanent-bootstrap-business-phase.r1',
            'businessChecksComplete': True, 'finalResourceClosureNotYetObserved': True,
            'notSufficientForFurtherActionWithoutOriginalTerminalAndFreshState': True}))
    except BaseException as error:
        REPORT['errorType'] = type(error).__name__
        REPORT['errorCode'] = str(error) if isinstance(error, Refused) and re.fullmatch(r'[a-z0-9._-]{1,120}', str(error)) else 'bootstrap_failed_no_replay'
    finally:
        if current is not None:
            try:
                stop_server()
            except BaseException as error:
                REPORT['finalServerClosureError'] = type(error).__name__
                REPORT['ok'] = False
        REPORT['apiPhases'] = [api.public() for api in apis]
        REPORT['originalServerCleanupRecords'] = [{'phase': row['phase'], 'stopAttempted': row['stopAttempted'],
            'pid': row['process'].pid if row['process'] is not None else None,
            'cleanup': row.get('cleanup')} for row in process_rows]
        REPORT['allOriginalServersClosed'] = all(row['stopAttempted'] and row.get('cleanup', {}).get('ok') is True for row in process_rows)
        if guard is not None:
            try:
                guard.close()
            except BaseException:
                REPORT['ok'] = False
            REPORT['volumeClosure'] = guard.public_state()
        errors = []
        for row in reversed(FDS):
            try:
                close(row)
            except BaseException as error:
                errors.append(type(error).__name__)
        REPORT['allExplicitDescriptorsClosedOnce'] = all(row['attempts'] == 1 and row['closed'] for row in FDS)
        REPORT['explicitDescriptors'] = len(FDS)
        REPORT['descriptorCloseErrors'] = errors
        REPORT['commands'] = commands.public() if commands is not None else {'allOwnedCommandsStopped': True, 'unknownCommandCount': 0, 'commands': []}
        REPORT['deadlineAfterClosure'] = time.monotonic() < UNTIL
        REPORT['cancellationObserved'] = CONTROL_SIGNALS is not None and CONTROL_SIGNALS.pending is not None
        REPORT['ok'] = bool(REPORT['ok'] and REPORT['allOriginalServersClosed'] and REPORT['allExplicitDescriptorsClosedOnce']
            and not errors and REPORT['commands']['allOwnedCommandsStopped'] and REPORT['commands']['unknownCommandCount'] == 0
            and REPORT['deadlineAfterClosure'] and not REPORT['cancellationObserved']
            and REPORT.get('volumeClosure', {}).get('lastAnchorCheckPassed') and REPORT['volumeClosure']['allDescriptorsClosed'])
        REPORT['elapsedSeconds'] = time.monotonic() - START
        print(json.dumps(REPORT, sort_keys=True), flush=True)
    return 0 if REPORT['ok'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
