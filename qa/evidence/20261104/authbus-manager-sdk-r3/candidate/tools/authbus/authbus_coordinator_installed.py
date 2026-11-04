#!/usr/bin/env python3
"""Explicitly bound, single-owner installation entry for the existing coordinator.

The service has only serve/recover. Administrative manifest transitions are
one-shot operator calls with exact input/head pins and a durable dispatch
record. An unknown administrative CAS is reconciled from KV history, never
sent again. This entry does not approve identities, refresh OAuth, or schedule
clients. The original candidate CLI remains explicitly uninstalled.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import sys
import time
import types
import uuid

SCHEMA = 'heptabao-authbus-coordinator-v1'
ENTRY = Path(__file__).absolute()
CORE = ENTRY.with_name('authbus_coordinator.py')
MAX_FILE = 2 * 1024 * 1024
STATE_FILES = ('owner.private.json', 'operation.lock', 'service.lock')


class InstallationError(Exception):
    """Only fixed non-secret error codes are exposed."""


def need(ok, code):
    if not ok:
        raise InstallationError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def absolute(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'installation_absolute_path_required')
    # Refuse symlink ancestors, including a replaced state parent. No path
    # expansion, environment substitution or shell execution is performed.
    for parent in (path, *path.parents):
        if parent.exists():
            need(not parent.is_symlink(), 'installation_symlink_path')
    return path


def file_bytes(path, *, private=False, maximum=MAX_FILE):
    path = absolute(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        mode = stat.S_IMODE(before.st_mode)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_uid in (0, os.geteuid()) and not mode & 0o022
             and before.st_size <= maximum, 'installation_file_custody')
        if private:
            need(before.st_uid == os.geteuid() and mode == 0o600, 'installation_private_file_custody')
        result = bytearray()
        while len(result) <= maximum:
            block = os.read(fd, min(65536, maximum + 1 - len(result)))
            if not block:
                break
            result.extend(block)
        after = os.fstat(fd)
        signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns,
                               s.st_uid, s.st_mode, s.st_nlink)
        need(signature(before) == signature(after) and len(result) == before.st_size,
             'installation_file_changed')
        return bytes(result)
    finally:
        os.close(fd)


def record(path, private=False):
    path = absolute(path)
    return {'path': str(path), 'sha256': sha(file_bytes(path, private=private)), 'private': private}


def identity_record(path, directory=False):
    path = absolute(path)
    info = path.lstat()
    need((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
         and info.st_uid == os.geteuid()
         and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)
         and (directory or info.st_nlink == 1), 'installation_state_custody')
    return {'path': str(path), 'device': info.st_dev, 'inode': info.st_ino,
            'uid': info.st_uid, 'mode': stat.S_IMODE(info.st_mode)}


def load_core(expected=None):
    raw = file_bytes(CORE)
    need(expected is None or sha(raw) == expected, 'installation_core_pin')
    module = types.ModuleType('authbus_coordinator_installed_core')
    module.__file__ = str(CORE)
    # Execute the already verified bytes, not a second unpinned file open.
    exec(compile(raw, str(CORE), 'exec'), module.__dict__)
    return module


def prepare_state(path, owner, sources):
    central = load_core()
    central.require(central.valid_uuid(owner) and 1 <= len(sources) <= 16
                    and len(set(sources)) == len(sources)
                    and all(central.HOST.fullmatch(s) for s in sources), 'coordinator_owner_configuration')
    path = absolute(path)
    central.owned_directory(path.parent)
    central.owned_directory(path, create=True)
    anchor = {'schema': SCHEMA + '.owner-state', 'ownerId': owner, 'sourceHosts': list(sources)}
    central.private_json(path / 'owner.private.json', anchor)
    for name in ('operation.lock', 'service.lock'):
        fd = os.open(path / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    central.sync_directory(path)
    return {'statePrepared': True, 'ownerId': owner, 'sourceHosts': list(sources),
            'stateDirectory': identity_record(path, True),
            'ownerAnchor': record(path / 'owner.private.json', True),
            'operationLock': identity_record(path / 'operation.lock'),
            'serviceLock': identity_record(path / 'service.lock'),
            'networkCalled': False, 'productionServicesChanged': False}


def current_service_identity():
    uid, gid = os.geteuid(), os.getegid()
    return {'uid': uid, 'gid': gid, 'user': pwd.getpwuid(uid).pw_name,
            'group': grp.getgrgid(gid).gr_name}


def service_scope(config):
    scope = config.get('service_scope')
    need(isinstance(scope, dict) and set(scope) == {'manager', 'uid', 'gid', 'user', 'group'}
         and scope['manager'] in ('user', 'system'), 'installation_service_scope_required')
    need(scope == {'manager': scope['manager'], **current_service_identity()},
         'installation_service_identity_changed')
    need(all(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', scope[k]) for k in ('user', 'group')),
         'installation_service_identity_syntax')
    need(scope['manager'] != 'system' or scope['uid'] > 0 and scope['gid'] > 0,
         'installation_system_service_must_be_nonroot')
    return dict(scope)


def service_unit_record(path, scope):
    path = absolute(path)
    before = path.lstat()
    system = scope['manager'] == 'system'
    if system:
        need(path.parent in (Path('/run/systemd/system'), Path('/etc/systemd/system')),
             'installation_system_unit_directory')
    uid, gid, mode = (0, 0, 0o644) if system else (scope['uid'], scope['gid'], 0o600)
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
         and (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) == (uid, gid, mode),
         'installation_service_unit_custody')
    value = record(path)
    after = path.lstat()
    signature = lambda st: (st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode,
                            st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    need(signature(before) == signature(after), 'installation_service_unit_changed')
    value['custody'] = {'device': after.st_dev, 'inode': after.st_ino,
                        'uid': uid, 'gid': gid, 'mode': mode}
    return value


def service_file_bytes(config, binding_path, pin_path):
    scope = service_scope(config)
    paths = [ENTRY, ENTRY.parent, Path(config['state_dir']), Path(binding_path), Path(pin_path),
             Path(config['ca_file']), Path(config['role_id_file']), Path(config['secret_id_file'])]
    need(all(str(absolute(p)) == str(p) and re.fullmatch(r'[A-Za-z0-9_./-]+', str(p)) for p in paths),
         'installation_service_path_syntax')
    config_dir = Path(binding_path).parent
    need(Path(pin_path).parent == config_dir, 'installation_activation_pin_directory')
    command = (f'ExecStart=/usr/bin/python3 -I -S -B {ENTRY} service serve --binding {binding_path}'
               ' --binding-sha256 ' + '$' + '{HEPTABAO_BINDING_SHA256}')
    lines = ['[Unit]', 'Description=HeptaBao AuthBus single-owner inbox coordinator',
             'After=network-online.target', 'Wants=network-online.target',
             f'ConditionPathExists={binding_path}', f'ConditionPathExists={pin_path}', '', '[Service]',
             *([f'User={scope["user"]}', f'Group={scope["group"]}'] if scope['manager'] == 'system' else []),
             'Type=simple', f'WorkingDirectory={ENTRY.parent}', 'UMask=0077',
             f'EnvironmentFile={pin_path}', command, 'Restart=on-failure', 'RestartSec=5s',
             'RestartPreventExitStatus=2 3', 'TimeoutStopSec=15s', 'KillMode=control-group',
             'NoNewPrivileges=yes', 'PrivateUsers=yes', 'PrivateTmp=yes',
             'ProtectSystem=strict', 'ProtectHome=read-only',
             f'ReadOnlyPaths={ENTRY.parent} {config_dir}', f'ReadWritePaths={config["state_dir"]}',
             'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6', '', '[Install]',
             'WantedBy=' + ('multi-user.target' if scope['manager'] == 'system' else 'default.target'), '']
    return '\n'.join(lines).encode()


def create_private_bytes(path, raw, central):
    path = absolute(path)
    central.owned_directory(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        central.sync_directory(path.parent)
    except BaseException:
        # Retain a partial preparation for explicit inspection; never replace.
        raise


def activation_bytes(expected):
    return ('HEPTABAO_BINDING_SHA256=' + expected + '\n').encode()


def make_binding(config_path, config_sha, unit_path, unit_sha, output, pin_path=None):
    central = load_core()
    config_path = absolute(config_path)
    raw = file_bytes(config_path, private=True)
    need(sha(raw) == config_sha, 'installation_config_pin')
    cfg = json.loads(raw)
    need(cfg.get('schema') == SCHEMA + '.config' and cfg.get('production_cutover') is True,
         'installed_entry_requires_explicit_production_configuration')
    state = absolute(cfg['state_dir'])
    output = absolute(output)
    pin_path = absolute(pin_path or output.with_suffix('.pin.env'))
    need(not output.exists() and not pin_path.exists(), 'installation_preparation_must_be_new')
    anchor = json.loads(file_bytes(state / 'owner.private.json', private=True))
    need(anchor == {'schema': SCHEMA + '.owner-state', 'ownerId': cfg['owner_id'],
                    'sourceHosts': cfg['source_hosts']}, 'installation_owner_anchor')
    scope = service_scope(cfg)
    unit = service_unit_record(unit_path, scope)
    need(unit['sha256'] == unit_sha, 'installation_service_file_pin')
    need(file_bytes(unit_path) == service_file_bytes(cfg, output, pin_path),
         'installation_service_command_contract')
    document = {
        'schema': SCHEMA + '.installation', 'production_cutover': True,
        'host': socket.gethostname(), 'uid': os.geteuid(),
        'service_scope': scope,
        'owner_id': cfg['owner_id'], 'source_hosts': cfg['source_hosts'],
        'address': cfg['address'], 'server_certificate_sha256': cfg['server_certificate_sha256'],
        'config': record(config_path, True),
        'activation_pin_file': str(pin_path),
        'entry': record(ENTRY), 'core': record(CORE), 'service_file': unit,
        'state_directory': identity_record(state, True),
        'owner_anchor': record(state / 'owner.private.json', True),
        'operation_lock': identity_record(state / 'operation.lock'),
        'service_lock': identity_record(state / 'service.lock'),
        'credentials': {key: record(cfg[key], True)
                        for key in ('ca_file', 'role_id_file', 'secret_id_file')},
        'single_owner_only': True,
    }
    # Producing a binding is create-only preparation. Its returned SHA must be
    # explicitly fixed in the reviewed service/operator invocation.
    central.private_json(output, document)
    binding_sha = sha(file_bytes(output, private=True))
    # Only the path participates in the binding hash. The exact digest value
    # is then written once into the externally fixed activation reference.
    create_private_bytes(pin_path, activation_bytes(binding_sha), central)
    return {'bindingPrepared': True, 'bindingSha256': binding_sha,
            'networkCalled': False, 'productionServicesChanged': False}


class Binding:
    def __init__(self, path, expected):
        self.path = absolute(path)
        self.expected = expected
        need(isinstance(expected, str) and len(expected) == 64
             and all(c in '0123456789abcdef' for c in expected), 'installation_binding_sha_shape')
        raw = file_bytes(self.path, private=True)
        need(sha(raw) == expected, 'installation_binding_pin')
        self.value = json.loads(raw)
        b = self.value
        need(b.get('schema') == SCHEMA + '.installation' and b.get('production_cutover') is True
             and b.get('single_owner_only') is True, 'installation_schema')
        need(b.get('host') == socket.gethostname() and b.get('uid') == os.geteuid(),
             'installation_host_or_uid_changed')
        need(b['entry']['path'] == str(ENTRY) and b['core']['path'] == str(CORE),
             'installation_code_path')
        self.verify()
        self.central = load_core(b['core']['sha256'])
        self.config = json.loads(file_bytes(b['config']['path'], private=True))
        cfg = self.config
        need(cfg.get('schema') == SCHEMA + '.config' and cfg.get('production_cutover') is True,
             'installed_entry_requires_explicit_production_configuration')
        need(all(cfg[k] == b[k] for k in
                 ('owner_id', 'source_hosts', 'address', 'server_certificate_sha256')),
             'installation_configuration_binding')
        need(cfg['state_dir'] == b['state_directory']['path'], 'installation_state_path')
        need(service_scope(cfg) == b['service_scope'], 'installation_service_scope_binding')
        need(file_bytes(b['service_file']['path']) == service_file_bytes(cfg, self.path, b['activation_pin_file']),
             'installation_service_command_contract')
        need(all(cfg[k] == b['credentials'][k]['path'] for k in b['credentials']),
             'installation_credential_path')
        anchor = json.loads(file_bytes(b['owner_anchor']['path'], private=True))
        need(anchor == {'schema': SCHEMA + '.owner-state', 'ownerId': cfg['owner_id'],
                        'sourceHosts': cfg['source_hosts']}, 'installation_owner_anchor')
        state = Path(cfg['state_dir'])
        need(b['owner_anchor']['path'] == str(state / 'owner.private.json')
             and b['operation_lock']['path'] == str(state / 'operation.lock')
             and b['service_lock']['path'] == str(state / 'service.lock'),
             'installation_state_member_paths')
        self.state = state

    def verify(self):
        b = self.value
        need(sha(file_bytes(self.path, private=True)) == self.expected, 'installation_binding_changed')
        need(file_bytes(b['activation_pin_file'], private=True, maximum=256) == activation_bytes(self.expected),
             'installation_activation_reference_changed')
        need(b.get('host') == socket.gethostname() and b.get('uid') == os.geteuid(),
             'installation_host_or_uid_changed')
        scope = service_scope({'service_scope': b.get('service_scope')})
        for item in (b['entry'], b['core'], b['config'], b['service_file'],
                     b['owner_anchor'], *b['credentials'].values()):
            need(sha(file_bytes(item['path'], private=item['private'])) == item['sha256'],
                 'installation_input_changed')
        need(service_unit_record(b['service_file']['path'], scope) == b['service_file'],
             'installation_service_unit_replaced')
        need(identity_record(b['state_directory']['path'], True) == b['state_directory'],
             'installation_state_directory_replaced')
        for key in ('operation_lock', 'service_lock'):
            need(identity_record(b[key]['path']) == b[key], 'installation_original_lock_replaced')

    @contextmanager
    def lock(self, kind='operation_lock'):
        self.verify()
        expected = self.value[kind]
        # No O_CREAT: missing/replaced original locks require reviewed recovery.
        fd = os.open(expected['path'], os.O_RDWR | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            need((info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode), info.st_nlink)
                 == (expected['device'], expected['inode'], expected['uid'], expected['mode'], 1),
                 'installation_open_lock_identity')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise InstallationError('installation_owner_busy') from None
            self.verify()
            yield
        finally:
            os.close(fd)

    def operation_lock(self, directory):
        need(Path(directory) == self.state, 'installation_operation_state')
        return self.lock()

    def worker(self, client):
        return self.central.Coordinator(client, self.state, self.config['owner_id'],
                                        self.config['source_hosts'], lock_factory=self.operation_lock)


class GuardedBao:
    """Use the original transport; stop on any pinned installation drift."""
    def __init__(self, binding, delegate=None):
        self.binding = binding
        self.delegate = delegate or binding.central.Bao(binding.config)
        self.cycle_secrets = []

    @property
    def secrets(self):
        return self.delegate.secrets + self.cycle_secrets

    def read(self, key, version=None):
        self.binding.verify()
        result = self.delegate.read(key, version)
        self.binding.verify()
        return result

    def list(self, prefix, *, after=None, limit=32):
        self.binding.verify()
        result = self.delegate.list(prefix, after=after, limit=limit)
        self.binding.verify()
        return result

    def write(self, key, value, cas):
        self.binding.verify()
        result = self.delegate.write(key, value, cas)
        try:
            self.binding.verify()
        except (InstallationError, OSError):
            raise self.binding.central.UnknownOutcome('installation_changed_after_mutation') from None
        return result


def pending_path(binding):
    return binding.state / 'operator-pending.private.json'


def validate_admin_record(binding, record):
    c = binding.central
    need(record.get('schema') == SCHEMA + '.operator-intent'
         and record.get('ownerId') == binding.config['owner_id']
         and record.get('sourceHosts') == binding.config['source_hosts']
         and isinstance(record.get('installationSha256'), str)
         and c.SHA.fullmatch(record['installationSha256'])
         and record.get('ownerAnchorSha256') == binding.value['owner_anchor']['sha256']
         and c.valid_uuid(record.get('operationId'))
         and record.get('command') in ('initialize', 'authorize', 'revoke-authorization')
         and record.get('key') == 'manifest'
         and isinstance(record.get('expectedVersion'), int) and record['expectedVersion'] >= 0
         and record.get('desiredManifestSha256') == c.digest(record.get('desiredManifest'))
         and record.get('phase') in ('prepared', 'dispatched'), 'operator_intent_binding')
    c.validate_manifest(record['desiredManifest'], binding.config['owner_id'], binding.config['source_hosts'])


def archive_admin(binding, record, outcome):
    c = binding.central
    value = dict(record, resolution=outcome)
    path = binding.state / ('operator-completed-' + record['operationId'] + '.private.json')
    if path.exists():
        need(json.loads(c.read_private(path)) == value, 'operator_completed_collision')
    else:
        c.private_json(path, value)
    pending_path(binding).unlink()
    c.sync_directory(binding.state)


class OperatorBao:
    """Journal the original administrative method's single manifest CAS."""
    def __init__(self, binding, client, command, version, head_sha, grant=None, grant_sha=None):
        self.binding, self.client, self.command = binding, client, command
        self.version, self.head_sha = version, head_sha
        self.grant, self.grant_sha, self.manifest_reads = grant, grant_sha, 0
        self.attempted = False

    @property
    def secrets(self):
        return self.client.secrets

    def read(self, key, version=None):
        result = self.client.read(key, version)
        if key == 'manifest':
            need(version is None, 'operator_head_only_before_dispatch')
            self.manifest_reads += 1
            need((result is None and self.version == 0 and self.head_sha == 'absent')
                 or (result is not None and result['version'] == self.version
                     and self.binding.central.digest(result['data']) == self.head_sha),
                 'operator_expected_manifest_changed')
            if self.command == 'revoke-authorization' and result is not None:
                matches = [g for g in result['data']['coordinator']['authorizations']
                           if g['authorizationId'] == self.grant['authorizationId']]
                need(not matches or matches == [self.grant], 'operator_revoke_exact_grant_changed')
        return result

    def write(self, key, value, cas):
        c = self.binding.central
        # Prior receipt completion is a service recover operation. An operator
        # call cannot silently perform a different write before its pinned CAS.
        need(key == 'manifest' and cas == self.version and self.manifest_reads == 1
             and not self.attempted, 'operator_only_one_exact_manifest_cas')
        need(not pending_path(self.binding).exists(), 'operator_pending_requires_reconciliation')
        self.attempted = True
        record = {'schema': SCHEMA + '.operator-intent', 'ownerId': self.binding.config['owner_id'],
                  'sourceHosts': self.binding.config['source_hosts'], 'installationSha256': self.binding.expected,
                  'ownerAnchorSha256': self.binding.value['owner_anchor']['sha256'],
                  'operationId': str(uuid.uuid4()), 'command': self.command, 'key': key,
                  'expectedVersion': cas, 'expectedManifestSha256': self.head_sha,
                  'authorizationSha256': self.grant_sha, 'desiredManifest': value,
                  'desiredManifestSha256': c.digest(value), 'phase': 'prepared'}
        c.private_json(pending_path(self.binding), record)
        record['phase'] = 'dispatched'
        c.private_json(pending_path(self.binding), record, replace=True)
        try:
            result = self.client.write(key, value, cas)
        except c.Conflict:
            archive_admin(self.binding, record, 'cas_rejected')
            raise
        except c.Error as exc:
            if not isinstance(exc, c.UnknownOutcome) and str(exc) in (
                    'bao_authentication_or_acl_denied', 'server_certificate_pin_changed'):
                archive_admin(self.binding, record, 'request_rejected')
            raise
        # Unknown/other failures after the durable dispatch record leave it
        # intact. A new invocation will be blocked before any repeated write.
        archive_admin(self.binding, record, 'response_confirmed')
        return result


def read_grant(binding, path, expected):
    need(path is not None and expected is not None, 'operator_exact_authorization_file_required')
    raw = file_bytes(path, private=True)
    need(sha(raw) == expected, 'operator_authorization_file_pin')
    grant = json.loads(raw)
    binding.central.validate_grant(grant, binding.config['source_hosts'])
    return grant


def operator(binding, client, command, *, version=None, head_sha=None, grant_path=None, grant_sha=None):
    c = binding.central
    binding.verify()
    if command == 'inspect':
        with binding.lock():
            snapshot = client.read('manifest')
            if snapshot is not None:
                c.validate_manifest(snapshot['data'], binding.config['owner_id'], binding.config['source_hosts'])
            return {'manifestVersion': 0 if snapshot is None else snapshot['version'],
                    'manifestSha256': 'absent' if snapshot is None else c.digest(snapshot['data']),
                    'operatorPending': pending_path(binding).exists(), 'remoteWrites': 0}
    if command == 'reconcile':
        return reconcile_operator(binding, client)
    need(not pending_path(binding).exists(), 'operator_pending_requires_reconciliation')
    need(isinstance(version, int) and not isinstance(version, bool) and version >= 0
         and ((version == 0 and head_sha == 'absent') or
              (version > 0 and isinstance(head_sha, str) and c.SHA.fullmatch(head_sha))),
         'operator_expected_manifest_pin_required')
    grant = read_grant(binding, grant_path, grant_sha) if command != 'initialize' else None
    if command == 'initialize':
        need(version == 0 and head_sha == 'absent' and grant_path is None and grant_sha is None,
             'operator_initialize_requires_absent_head')
    else:
        need(version > 0, 'operator_existing_manifest_required')
    limited = OperatorBao(binding, client, command, version, head_sha, grant, grant_sha)
    worker = binding.worker(limited)
    # The original methods hold the original operation lock, validate the
    # existing event journal, then perform their original CAS body.
    if command == 'initialize':
        return worker.initialize()
    if command == 'authorize':
        return worker.authorize(grant)
    need(command == 'revoke-authorization', 'operator_command')
    return worker.revoke_authorization(grant['authorizationId'])


def reconcile_operator(binding, client):
    c = binding.central
    with binding.lock():
        path = pending_path(binding)
        if not path.exists():
            return {'operatorPending': False, 'remoteWrites': 0}
        record = json.loads(c.read_private(path))
        validate_admin_record(binding, record)
        archive = binding.state / ('operator-completed-' + record['operationId'] + '.private.json')
        completed = json.loads(c.read_private(archive)) if archive.exists() else None
        if completed is not None:
            need({k: v for k, v in completed.items() if k != 'resolution'} == record,
                 'operator_completed_binding_mismatch')
            resolution = completed.get('resolution')
            need(resolution in ('not_dispatched', 'cas_rejected', 'request_rejected', 'response_confirmed',
                                'desired_manifest_confirmed', 'cas_slot_contains_different_manifest')
                 and (resolution != 'not_dispatched' or record['phase'] == 'prepared'),
                 'operator_completed_resolution')
            if resolution in ('not_dispatched', 'cas_rejected', 'request_rejected'):
                archive_admin(binding, record, resolution)
                return {'operatorPending': False, 'resolution': resolution, 'remoteWrites': 0}
        if record['phase'] == 'prepared':
            outcome = 'not_dispatched'
        else:
            expected_version = record['expectedVersion'] + 1
            current = client.read('manifest')
            if current is None or current['version'] < expected_version:
                raise c.UnknownOutcome('operator_manifest_cas_not_yet_classifiable')
            observed = current if current['version'] == expected_version else client.read('manifest', expected_version)
            if observed is None or observed['version'] != expected_version:
                raise c.UnknownOutcome('operator_manifest_history_unavailable')
            c.validate_manifest(observed['data'], binding.config['owner_id'], binding.config['source_hosts'])
            outcome = ('desired_manifest_confirmed' if c.digest(observed['data']) == record['desiredManifestSha256']
                       else 'cas_slot_contains_different_manifest')
        if completed is not None:
            # A completed record never licenses a conflicting remote restore.
            need((completed['resolution'] in ('response_confirmed', 'desired_manifest_confirmed')
                  and outcome == 'desired_manifest_confirmed')
                 or completed['resolution'] == outcome, 'operator_completed_remote_history_mismatch')
            outcome = completed['resolution']
        archive_admin(binding, record, outcome)
        return {'operatorPending': False, 'resolution': outcome, 'remoteWrites': 0}


def service_cycle(binding, client, recover=False):
    need(not pending_path(binding).exists(), 'operator_pending_requires_reconciliation')
    worker = binding.worker(client)
    # Keep only this worker cycle's redaction guard through result/error output.
    client.cycle_secrets = worker.secrets
    if recover:
        with binding.lock():
            need(not pending_path(binding).exists(), 'operator_pending_requires_reconciliation')
            recovered = worker.recover_locked()
            worker.finish_previous_receipt(worker.manifest())
            return {'recovered_pending': recovered}
    # Recheck under the same operation lock used by the actual worker. This
    # prevents an administrative unknown being missed between outer check/lock.
    original = worker.operation_lock
    @contextmanager
    def fenced(directory):
        with original(directory):
            need(not pending_path(binding).exists(), 'operator_pending_requires_reconciliation')
            yield
    worker.operation_lock = fenced
    return worker.once()


def render(binding, client, result):
    value = dict(result, schema=SCHEMA + '.installed-result', ok=True,
                 production_configuration=True, installation_sha256=binding.expected,
                 provider_called=False, oauth_refreshed=False)
    text = json.dumps(value, sort_keys=True)
    need(all(secret not in text for secret in client.secrets), 'public_result_contains_secret')
    print(text, flush=True)


def error_result(binding, client, exc):
    central = binding.central if binding is not None else None
    known = isinstance(exc, InstallationError) or (central is not None and isinstance(exc, central.Error))
    operator_pending = service_pending = dispatched = False
    profile_may_have_dispatched = manifest_may_have_dispatched = False
    if binding is not None:
        for path, phases, kind in (
                (pending_path(binding), ('dispatched',), 'operator'),
                (binding.state / 'pending.private.json',
                 ('prepared', 'manifest_dispatched', 'manifest_confirmed', 'receipt_confirmed'), 'service')):
            if not path.exists():
                continue
            operator_pending = operator_pending or kind == 'operator'
            service_pending = service_pending or kind == 'service'
            try:
                value = json.loads(central.read_private(path))
                dispatched = dispatched or value.get('phase') in phases
                if kind == 'service':
                    profile_may_have_dispatched = value.get('phase') == 'prepared'
                    manifest_may_have_dispatched = value.get('phase') in (
                        'manifest_dispatched', 'manifest_confirmed', 'receipt_confirmed')
            except Exception:
                # An unreadable existing dispatch journal cannot establish that
                # a remote write did not occur. Do not relabel it a safe retry.
                dispatched = True
                if kind == 'service':
                    profile_may_have_dispatched = manifest_may_have_dispatched = True
    unknown = bool(dispatched or (central is not None and isinstance(exc, central.UnknownOutcome)))
    result = {'schema': SCHEMA + '.installed-result', 'ok': False,
              'error': str(exc) if known else 'installed_coordinator_' + type(exc).__name__,
              'unknown_outcome': unknown, 'operator_reconciliation_required': operator_pending,
              'service_recovery_required': service_pending,
              'immutable_profile_write_may_have_dispatched': profile_may_have_dispatched,
              'event_manifest_write_may_have_dispatched': manifest_may_have_dispatched,
              'production_configuration': binding is not None,
              'provider_called': False, 'oauth_refreshed': False}
    text = json.dumps(result, sort_keys=True)
    if client is not None and any(secret in text for secret in client.secrets):
        result['error'] = 'public_result_contains_secret'
        text = json.dumps(result, sort_keys=True)
    return text, 3 if unknown else 2


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    groups = p.add_subparsers(dest='group', required=True)
    prep = groups.add_parser('prepare-state')
    prep.add_argument('--state-dir', required=True, type=Path)
    prep.add_argument('--owner-id', required=True)
    prep.add_argument('--source-host', action='append', required=True)
    bind = groups.add_parser('prepare-binding')
    bind.add_argument('--config', required=True, type=Path)
    bind.add_argument('--config-sha256', required=True)
    bind.add_argument('--service-file', required=True, type=Path)
    bind.add_argument('--service-file-sha256', required=True)
    bind.add_argument('--output', required=True, type=Path)
    bind.add_argument('--activation-pin-file', required=True, type=Path)
    unit = groups.add_parser('prepare-service-file')
    unit.add_argument('--config', required=True, type=Path)
    unit.add_argument('--config-sha256', required=True)
    unit.add_argument('--binding', required=True, type=Path)
    unit.add_argument('--activation-pin-file', required=True, type=Path)
    unit.add_argument('--output', required=True, type=Path)
    for group, commands in (
            ('service', ('serve', 'recover')),
            ('operator', ('initialize', 'authorize', 'revoke-authorization', 'inspect', 'reconcile'))):
        sub = groups.add_parser(group)
        sub.add_argument('command', choices=commands)
        sub.add_argument('--binding', required=True, type=Path)
        sub.add_argument('--binding-sha256', required=True)
        if group == 'operator':
            sub.add_argument('--expected-manifest-version', type=int)
            sub.add_argument('--expected-manifest-sha256')
            sub.add_argument('--authorization', type=Path)
            sub.add_argument('--authorization-sha256')
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    os.umask(0o077)
    binding = client = None
    try:
        if args.group == 'prepare-state':
            result = prepare_state(args.state_dir, args.owner_id, args.source_host)
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.group == 'prepare-binding':
            result = make_binding(args.config, args.config_sha256, args.service_file,
                                  args.service_file_sha256, args.output, args.activation_pin_file)
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.group == 'prepare-service-file':
            raw = file_bytes(args.config, private=True)
            need(sha(raw) == args.config_sha256, 'installation_config_pin')
            cfg = json.loads(raw)
            need(cfg.get('schema') == SCHEMA + '.config' and cfg.get('production_cutover') is True,
                 'installed_entry_requires_explicit_production_configuration')
            unit = service_file_bytes(cfg, args.binding, args.activation_pin_file)
            create_private_bytes(args.output, unit, load_core())
            print(json.dumps({'serviceFilePrepared': True, 'serviceFileSha256': sha(unit),
                              'networkCalled': False, 'productionServicesChanged': False}, sort_keys=True))
            return 0
        binding = Binding(args.binding, args.binding_sha256)
        client = GuardedBao(binding)
        if args.group == 'operator':
            result = operator(binding, client, args.command, version=args.expected_manifest_version,
                              head_sha=args.expected_manifest_sha256, grant_path=args.authorization,
                              grant_sha=args.authorization_sha256)
            render(binding, client, result)
            return 0
        # One local service process for this exact owner installation. Operator
        # calls use only the short operation lock; they do not spawn a worker.
        with binding.lock('service_lock'):
            if args.command == 'recover':
                render(binding, client, service_cycle(binding, client, recover=True))
                return 0
            interval = binding.config.get('poll_interval_seconds', 15)
            need(isinstance(interval, int) and not isinstance(interval, bool) and 1 <= interval <= 60,
                 'poll_interval_bound')
            while True:
                render(binding, client, service_cycle(binding, client))
                time.sleep(interval)
    except Exception as exc:
        text, status = error_result(binding, client, exc)
        print(text, flush=True)
        return status


if __name__ == '__main__':
    raise SystemExit(main())
