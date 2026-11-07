#!/usr/bin/env python3
"""Validate two launchd cold generations of the initialized permanent store.

The four once-only launchd actions retain original absent disabled override.
Each exact bound birth uses strict original CA/leaf and the LAN IP SAN. Existing
separate HOME custody supplies explicit unseal; initialization and storage
activation are forbidden. The plist stays outside autoload and the final
registration is absent. No provider refresh or registered client action.
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
OPERATIONS = CUSTODY / 'service-lifecycle-r1'
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
PRODUCT = '4bde9aee03fcd27c59e13607e529b1cee594b249'
BINARY = ROOT / 'releases' / PRODUCT / 'heptabao-server'
BINARY_BYTES = 92359328
BINARY_SHA = '5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c'
CA_SHA = '456ea07b02ead7ac3397507a4e41befeaad822dcdd74695f6a38239029aac01f'
LEAF_SHA = 'abaf8527105e19cbbe0da57a64c7a87d8e7f6e6ae15edc3636f5eee65eefd3bd'
PORT = 31080
CONFIG = ROOT / 'etc/server-r2.json'
ROLE = 'service-lifecycle-r1'
OLD_SECRET_PATH = '/v1/openclaw-auth/data/qualification/bootstrap-lifecycle-r1'
SECRET_PATH = '/v1/openclaw-auth/data/qualification/service-lifecycle-r1'
TOOL_PINS = {
    str(PYTHON): (34640, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'),
    '/usr/sbin/diskutil': (1937776, '624a8601b97ddfaa4b18dd2854c299e084cd45eb18fc152011c97615c3b9da1f'),
    '/bin/launchctl': (363488, 'b4dbf509754d8e1117f7851baa93ede75bc75218c48d6ddf19fbb1505d261be7'),
    '/bin/ps': (170432, '3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c'),
}
# PAYLOAD_PLACEHOLDER
START = time.monotonic()
UNTIL = START + 45
FDS = []
CONTROL_SIGNALS = None
REPORT = {'schema': 'heptabao.permanent-launchd-service-lifecycle.r1', 'ok': False,
    'productCommit': PRODUCT, 'automaticRetry': False, 'initializationRequests': 0,
    'currentCredentialReads': 0, 'providerCalls': 0, 'legacyChanges': 0,
    'productionClientChanges': 0, 'autoloadPlistInstalled': False, 'j3160Requests': 0,
    'rootKeyValuesOrDigestsPublished': False, 'productionCutoverQualified': False,
    'parentSeconds': 45, 'supervisorSeconds': 70, 'phaseDeadlineIsOriginalParent': True,
    'originalPermanentBootstrapJob': '1a1b396b21c-fc05-83b9',
    'originalPreserveAbsentJob': '1a1b3d6ebd5-fc05-8503',
    'independentLanClientQualified': False, 'apiPhases': []}


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
        need(phase in ('first', 'recovery') and 1 <= ordinal <= 192, 'bootstrap_exact_response_slot')
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
    guard = operations = commands = signals = qualification = None
    apis, sensitive = [], []
    protected, pins, bootstrap_inputs = {}, {}, {}
    failure_close_attempted = False
    try:
        need(sys.platform == 'darwin' and os.getuid() == 501 and os.getgid() == 20
             and Path(sys.executable).resolve(strict=True) == PYTHON,
             'service_exact_original_mac_runtime')
        for name, source in PAYLOAD['sources'].items():
            raw = source.encode()
            need(len(raw) == PAYLOAD['pins'][name]['bytes'] and hashlib.sha256(raw).hexdigest()
                 == PAYLOAD['pins'][name]['sha256'], 'service_exact_complete_source')
            ast.parse(source)
            if name == 'mac_owned_launchd_r3.py':
                continue
            module = types.ModuleType(Path(name).stem)
            module.__file__ = str(OPERATIONS / name)
            need(module.__name__ not in sys.modules, 'service_no_preloaded_owned_module')
            sys.modules[module.__name__] = module
            exec(compile(source, module.__file__, 'exec'), module.__dict__)
        from mac_owned_commands_r1 import Commands, Signals
        from mac_native_process_observer_r1 import ProcessReader, BsdInfo
        from mac_owned_unreaped_r1 import require_waitid
        from mac_production_t5_guard_r1 import HeldT5
        from mac_public_code_pin_excerpt_r1 import public_code_pin
        from permanent_service_api_r1 import Api
        from mac_permanent_service_primitives_r1 import Qualification, safe_command_public
        require_waitid()
        signals = Signals(); signals.install(); commands = Commands(signals)
        CONTROL_SIGNALS = signals
        for path, expected in TOOL_PINS.items():
            pin = public_code_pin(path, remaining=remaining, critical=signals.critical)
            need(pin['sha256'] == expected[1] and pin['bytes'] == expected[0],
                 'service_exact_original_native_tool')
            pins[path] = pin
        anchor = {'schema': 'heptabao.mac-current-t5-public-anchor.r1',
            'source_inventory_sha256': hashlib.sha256(encoded(PAYLOAD['pins'])).hexdigest(),
            'volumeUUID': 'FB804D1B-24CB-4D6E-AEA7-A9E180807758',
            'expectedVolumeDevice': str(Path('/Volumes/T5').lstat().st_dev),
            'anchors': [{'path': path, 'identity': list(full9(Path(path).lstat()))}
                        for path in ('/', '/Volumes', '/Volumes/T5')]}
        raw = encoded(anchor)
        guard = HeldT5(raw, hashlib.sha256(raw).hexdigest(), remaining, signals.critical)
        record, out, err = commands.run('service-t5-volume',
            ['/usr/sbin/diskutil', 'info', '-plist', '/Volumes/T5'],
            until=min(UNTIL, time.monotonic() + 15), maximum=262144)
        need(record['exitCode'] == 0 and not record['outcomeUnknown'] and not err,
             'service_known_original_t5')
        guard.accept_diskutil(out)
        operations = PrivateOperations()
        for name, source in PAYLOAD['sources'].items():
            operations.write(name, source.encode())
        operations.write('source-pins.public.json', encoded(PAYLOAD['pins']))
        expected_config = {'listen': '192.168.0.8:31080', 'data_dir': str(ROOT / 'data'),
            'audit_file': str(ROOT / 'log/audit.jsonl'), 'tls_cert_file': str(ROOT / 'tls/server-r2.crt'),
            'tls_key_file': str(ROOT / 'tls/server.key'), 'max_connections': 64, 'timeout_seconds': 15,
            'rate_limit_per_second': 2000, 'rate_limit_burst': 4000, 'rate_limit_entries': 512,
            'storage': {'native_v6_file': {'path': str(ROOT / 'data')}}}
        need(json.loads(guard.read(CONFIG, 16384)) == expected_config,
             'service_exact_corrected_lan_configuration')
        before_binary = binary_pin()
        protected = {path: full9(path.lstat()) for path in
            (BINARY, CONFIG, ROOT / 'tls/ca.crt', ROOT / 'tls/server-r2.crt', ROOT / 'tls/server.key')}
        for name, expected in (('ca.crt', CA_SHA), ('server-r2.crt', LEAF_SHA)):
            raw = guard.read(ROOT / 'tls' / name, 16384)
            need(hashlib.sha256(ssl.PEM_cert_to_DER_cert(raw.decode('ascii'))).hexdigest() == expected,
                 'service_original_independent_tls_certificate')
        data_identity = full9((ROOT / 'data').lstat())[:5]
        need(stat.S_ISDIR((ROOT / 'data').lstat().st_mode), 'service_existing_data_directory')

        def runtime_fence():
            remaining(); guard.check(); operations.check()
            for path, stamp in protected.items():
                need(full9(path.lstat()) == stamp, 'service_same_original_runtime_generation')
            need(full9((ROOT / 'data').lstat())[:5] == data_identity,
                 'service_same_existing_data_directory')
            for path, stamp in bootstrap_inputs.items():
                need(full9(path.lstat()) == stamp, 'service_same_original_separate_key_custody')
            for path, original in pins.items():
                need(public_code_pin(path, remaining=remaining, critical=signals.critical) == original,
                     'service_same_original_native_tool')

        class BoundGuard:
            def check(self):
                runtime_fence()

        def read_original(name):
            need(name in ('initial-002.response.private.bin',
                          'cold-new-process-004.response.private.bin'),
                 'service_exact_original_custody_input')
            parent = open_fd('bootstrap-r2', os.O_RDONLY | os.O_DIRECTORY,
                'original-bootstrap-custody', dir_fd=operations.dirs[-2][1]['fd'])
            try:
                directory = os.fstat(parent['fd'])
                need(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 501
                     and directory.st_gid == 20 and stat.S_IMODE(directory.st_mode) == 0o700
                     and full9(directory) == full9((CUSTODY / 'bootstrap-r2').lstat()),
                     'service_original_private_custody_directory')
                row = open_fd(name, os.O_RDONLY, 'original-private-custody', dir_fd=parent['fd'])
                try:
                    first = os.fstat(row['fd'])
                    need(stat.S_ISREG(first.st_mode) and first.st_uid == 501 and first.st_gid == 20
                         and first.st_nlink == 1 and stat.S_IMODE(first.st_mode) == 0o600
                         and 0 < first.st_size <= 1048576, 'service_bounded_original_custody_file')
                    raw = bytearray()
                    while len(raw) <= first.st_size:
                        remaining(); block = os.read(row['fd'], min(65536, first.st_size + 1 - len(raw)))
                        if not block: break
                        raw.extend(block)
                    path = CUSTODY / 'bootstrap-r2' / name
                    need(len(raw) == first.st_size and full9(first) == full9(os.fstat(row['fd']))
                         == full9(os.stat(name, dir_fd=parent['fd'], follow_symlinks=False))
                         and full9(directory) == full9(os.fstat(parent['fd']))
                         == full9(path.parent.lstat()), 'service_complete_original_custody_generation')
                    bootstrap_inputs[path] = full9(first)
                    bootstrap_inputs[path.parent] = full9(directory)
                    return json.loads(raw)
                finally:
                    close(row)
            finally:
                close(parent)

        initialized = read_original('initial-002.response.private.bin')
        old_probe = read_original('cold-new-process-004.response.private.bin')['data']
        root_token, unseal = initialized.get('root_token'), initialized.get('keys_base64', [None])[0]
        need(all(type(value) is str and 8 <= len(value) <= 16384 for value in (root_token, unseal))
             and old_probe.get('metadata', {}).get('version') == 2
             and type(old_probe.get('data')) is dict, 'service_existing_original_material')
        sensitive.extend((root_token, unseal))
        value = {'schema': 'heptabao.permanent-launchd-probe.r1', 'marker': os.urandom(16).hex()}
        role_state = {}
        base = '/v1/auth/approle/role/' + ROLE
        policy = ('path "openclaw-auth/data/qualification/service-lifecycle-r1" '
            '{ capabilities=["read","update"] }\n'
            'path "auth/token/lookup-self" { capabilities=["read"] }\n'
            'path "auth/token/renew-self" { capabilities=["update"] }\n'
            'path "auth/token/revoke-self" { capabilities=["update"] }\n')

        def phase_action(phase, process, original_until):
            need(phase in ('first', 'recovery') and original_until == UNTIL
                 and qualification.reader.read(process['pid']) == process,
                 'service_original_bound_phase_birth_and_deadline')
            api = Api({'port': PORT, 'certificateLeafSha256': LEAF_SHA}, phase,
                      original_until, operations, BoundGuard())
            apis.append(api); api.root_token = root_token
            def case(name): return phase + '.' + name
            health = api.call(case('sealed_health'), 'GET', '/v1/sys/health', token='',
                expected=503, category='health', readiness=True)
            api.check(case('already_initialized_and_sealed'),
                health.get('initialized') is True and health.get('sealed') is True)
            api.check(case('original_key_explicit_unseal'), api.call(case('unseal'), 'POST',
                '/v1/sys/unseal', {'key': unseal}, token='', category='unseal').get('sealed') is False)
            api.check(case('native_format_two'), api.call(case('capacity'), 'GET',
                '/v1/sys/internal/capacity', category='capacity').get('data', {}).get('native_kv2_reader_format') == 2)
            prior = api.call(case('original_probe'), 'GET', OLD_SECRET_PATH, category='kv-read')['data']
            api.check(case('original_probe_private_value_and_version'),
                prior['metadata']['version'] == 2 and prior['data'] == old_probe['data'])
            if phase == 'first':
                api.call(case('new_policy_absent'), 'GET', '/v1/sys/policies/acl/' + ROLE,
                    expected=404, category='policy')
                api.call(case('new_role_absent'), 'GET', base, expected=404, category='role')
                api.call(case('new_key_absent'), 'GET', SECRET_PATH, expected=404, category='kv-read')
                api.call(case('policy'), 'PUT', '/v1/sys/policies/acl/' + ROLE,
                    {'policy': policy}, expected=204, category='policy')
                api.call(case('role'), 'POST', base, {'token_policies': [ROLE],
                    'token_ttl': '1200s', 'token_max_ttl': '3600s', 'secret_id_num_uses': 0,
                    'secret_id_ttl': '3600s'}, expected=204, category='role')
                role_state['roleId'] = api.call(case('role_id'), 'GET', base + '/role-id',
                    category='role-id')['data']['role_id']
                api.check(case('version_one'), api.call(case('seed'), 'POST', SECRET_PATH,
                    {'data': value, 'options': {'cas': 0}}, category='kv-write')['data']['version'] == 1)
            else:
                api.call(case('old_revocation_persisted'), 'GET', SECRET_PATH,
                    token=role_state['oldToken'], expected=403, category='kv-read')
                api.call(case('old_sid_destruction_persisted'), 'POST', '/v1/auth/approle/login',
                    {'role_id': role_state['roleId'], 'secret_id': role_state['oldSid']},
                    token='', expected=400, category='login')
            sid = api.call(case('secret_id'), 'POST', base + '/secret-id', {},
                category='secret-id')['data']['secret_id']
            login = {'role_id': role_state['roleId'], 'secret_id': sid}
            auth = api.call(case('login'), 'POST', '/v1/auth/approle/login', login,
                token='', category='login')['auth']
            token = auth['client_token']; sensitive.extend((role_state['roleId'], sid, token))
            api.check(case('renewable_scoped_role'), auth.get('renewable') is True
                and ROLE in auth.get('policies', []))
            stored = api.call(case('scoped_read'), 'GET', SECRET_PATH,
                token=token, category='kv-read')['data']
            api.check(case('exact_stored_value_and_version'), stored['data'] == value
                and stored['metadata']['version'] == (1 if phase == 'first' else 2))
            if phase == 'first':
                api.check(case('scoped_cas_version_two'), api.call(case('scoped_write'), 'POST',
                    SECRET_PATH, {'data': value, 'options': {'cas': 1}}, token=token,
                    category='kv-write')['data']['version'] == 2)
            api.call(case('other_key_denied'), 'GET', OLD_SECRET_PATH,
                token=token, expected=403, category='kv-read')
            api.call(case('admin_denied'), 'GET', '/v1/sys/mounts',
                token=token, expected=403, category='admin-denied')
            renewed = api.call(case('renew'), 'POST', '/v1/auth/token/renew-self',
                {'increment': '1200s'}, token=token, category='renew')['auth']
            api.check(case('same_token_renewed'), renewed.get('client_token') == token
                and renewed.get('renewable') is True and renewed.get('lease_duration', 0) > 0)
            api.call(case('revoke'), 'POST', '/v1/auth/token/revoke-self', {},
                token=token, expected=204, category='revoke')
            api.call(case('revoked_denied'), 'GET', SECRET_PATH, token=token,
                expected=403, category='kv-read')
            api.call(case('destroy_sid'), 'POST', base + '/secret-id/destroy',
                {'secret_id': sid}, expected=204, category='secret-destroy')
            api.call(case('destroyed_sid_denied'), 'POST', '/v1/auth/approle/login', login,
                token='', expected=400, category='login')
            if phase == 'first':
                role_state.update(oldToken=token, oldSid=sid)
                operations.write('first-role.private.json', encoded(role_state))
            need(qualification.reader.read(process['pid']) == process,
                 'service_same_original_birth_after_phase')

        names = ['ManagerRefused', 'need', 'parse_print', 'missing_service']
        parsed = ast.parse(PAYLOAD['sources']['mac_owned_launchd_r3.py'])
        selected = [node for node in parsed.body
            if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name in names]
        need([node.name for node in selected] == names, 'service_exact_four_qualified_pure_parsers')
        namespace = {'__builtins__': __builtins__, 're': re}
        exec(compile(ast.Module(body=selected, type_ignores=[]),
            'qualified-launchd-four-pure-parsers', 'exec'), namespace)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(('192.168.0.8', PORT))
        runtime_fence()
        qualification = Qualification(commands=commands, reader=ProcessReader(), bsd_info=BsdInfo,
            parse_print=namespace['parse_print'], missing_service=namespace['missing_service'],
            until=UNTIL, runtime_fence=runtime_fence, phase_action=phase_action)
        qualification.run()
        need(binary_pin() == before_binary, 'service_original_normal_binary_unchanged')
        runtime_fence()
        REPORT.update(ok=True, permanentLaunchdTwoColdGenerationsQualified=True,
            strictLanAddressTlsAppRoleKvPolicyRenewRevokeQualified=True,
            originalKeyExplicitUnsealQualified=True, existingStoreReinitialized=False,
            finalServiceRegistrationAbsent=True, autoloadPlistInstalled=False)
    except BaseException as error:
        REPORT['errorType'] = type(error).__name__
        REPORT['errorCode'] = (str(error) if type(error).__name__ in
            ('Refused', 'CommandRefused', 'ObservationRefused', 'ManagerRefused', 'VolumeRefused')
            and re.fullmatch(r'[a-z0-9._-]{1,120}', str(error)) else 'permanent_service_refused_no_replay')
        # Closing this already bound generation does not replay an API request.
        # A launchctl UNKNOWN, missing birth or exhausted original clock never
        # authorizes a later action, recovery generation, or fresh operation.
        if qualification is not None and not qualification.unknown:
            generation = qualification.active_generation
            operation = 'bootout-' + generation if generation in ('first', 'recovery') else None
            if operation is not None and operation not in qualification.mutations:
                failure_close_attempted = True
                try:
                    qualification.dispatch(operation, generation)
                    qualification.absence(generation)
                except BaseException as close_error:
                    REPORT['originalKnownGenerationClosureError'] = type(close_error).__name__
        REPORT['ok'] = False
    finally:
        REPORT['apiPhases'] = [api.public() for api in apis]
        REPORT['knownOriginalGenerationFailureCloseAttempted'] = failure_close_attempted
        if qualification is not None:
            REPORT['qualification'] = qualification.public()
            if qualification.unknown or REPORT['qualification']['registeredServiceMayRemain']:
                REPORT['ok'] = False
        if commands is not None:
            state = commands.public()
            from mac_permanent_service_primitives_r1 import safe_command_public
            REPORT['originalCommandHelpers'] = {**state,
                'commands': [safe_command_public(row) if row is not None else None
                             for row in state['commands']]}
            if not state['allOwnedCommandsStopped'] or state['unknownCommandCount']:
                REPORT['ok'] = False
        if guard is not None:
            try: guard.close()
            except BaseException: REPORT['ok'] = False
            REPORT['volumeClosure'] = guard.public_state()
        errors = []
        for row in reversed(FDS):
            try: close(row)
            except BaseException as error: errors.append(type(error).__name__)
        REPORT['allExplicitDescriptorsClosedOnce'] = all(
            row['attempts'] == 1 and row['closed'] for row in FDS)
        REPORT['explicitDescriptors'] = len(FDS)
        REPORT['descriptorCloseErrors'] = errors
        REPORT['elapsedSeconds'] = time.monotonic() - START
        REPORT['businessWithinOriginal45Seconds'] = REPORT['elapsedSeconds'] < 45
        REPORT['cancellationObserved'] = CONTROL_SIGNALS is not None and CONTROL_SIGNALS.pending is not None
        if errors or not REPORT['allExplicitDescriptorsClosedOnce'] or not REPORT['businessWithinOriginal45Seconds'] \
                or REPORT['cancellationObserved'] or not REPORT.get('volumeClosure', {}).get('lastAnchorCheckPassed') \
                or not REPORT.get('volumeClosure', {}).get('allDescriptorsClosed'):
            REPORT['ok'] = False
        print(json.dumps(REPORT, sort_keys=True, separators=(',', ':')), flush=True)
    return 0 if REPORT['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
