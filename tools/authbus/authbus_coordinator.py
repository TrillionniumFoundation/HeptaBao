#!/usr/bin/env python3
"""Independent AuthBus inbox publisher, with CAS and recoverable outcomes.

This service speaks the existing OpenClaw AuthBus event/manifest contract. It
does not refresh provider credentials or implement enforced scheduling. An
operator authorizes each exact current->next credential digest transition.
Credentials stay in OpenBao/HeptaBao and private owner files; stdout contains
fixed result codes and digests only.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import time
from urllib.parse import quote, urlsplit
import uuid


PROTOCOL = 'heptabao-authbus-coordinator-v1'
MOUNT = 'openclaw-auth'
MAX_BODY = 2 * 1024 * 1024
MAX_DOCUMENT = 128 * 1024
MAX_PROFILES = 64
MAX_GRANTS = 32
HOST = re.compile(r'[a-z0-9][a-z0-9-]{0,62}\Z')
SHA = re.compile(r'[a-f0-9]{64}\Z')
CAS_ERROR = 'check-and-set parameter did not match the current version'


class Error(Exception):
    """Only fixed non-secret codes are exposed by the CLI."""


class Conflict(Error):
    pass


class UnknownOutcome(Error):
    pass


def require(condition, code):
    if not condition:
        raise Error(code)


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def normalized(value, depth=0):
    require(depth <= 12, 'json_depth_exceeded')
    if isinstance(value, dict):
        require(len(value) <= 256 and all(isinstance(k, str) for k in value), 'json_object_bound')
        # JavaScript .sort() compares UTF-16 code units. Credential digests must
        # exactly match stableStringify in the original plugin.
        return {key: normalized(value[key], depth + 1)
                for key in sorted(value, key=lambda k: k.encode('utf-16-be', 'surrogatepass'))}
    if isinstance(value, list):
        require(len(value) <= 1024, 'json_array_bound')
        return [normalized(item, depth + 1) for item in value]
    if isinstance(value, str):
        require(len(value.encode('utf8')) <= MAX_DOCUMENT, 'json_string_bound')
        return value
    if value is None or isinstance(value, bool):
        return value
    require(isinstance(value, int) and abs(value) <= 9007199254740991,
            'credential_json_number_must_be_safe_integer')
    return value


def canonical(value):
    return json.dumps(normalized(value), ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf8')


def digest(value):
    return sha(canonical(value))


def read_private(path, maximum=MAX_BODY):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size <= maximum, 'private_file_custody')
        chunks, size = [], 0
        while True:
            block = os.read(fd, min(65536, maximum + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
            require(size <= maximum, 'private_file_bound')
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'private_file_changed')
        return b''.join(chunks)
    finally:
        os.close(fd)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def owned_directory(path, create=False):
    if create:
        path.mkdir(mode=0o700, parents=False, exist_ok=False)
        sync_directory(path.parent)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700 and not path.is_symlink(), 'private_directory_custody')


def private_json(path, value, replace=False):
    payload = canonical(value) + b'\n'
    require(len(payload) <= MAX_BODY, 'private_document_bound')
    temporary = path.with_name(path.name + '.' + secrets.token_hex(8) + '.tmp') if replace else path
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            try:
                path.lstat()
                read_private(path)
            except FileNotFoundError:
                pass
            os.replace(temporary, path)
        sync_directory(path.parent)
    except BaseException:
        # Never remove or overwrite an existing source on a failed operation.
        if temporary != path and temporary.exists():
            temporary.unlink()
        raise


@contextmanager
def operation_lock(directory):
    owned_directory(directory)
    path = directory / 'operation.lock'
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600, 'operation_lock_custody')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Error('coordinator_operation_busy') from None
        yield
    finally:
        os.close(fd)


def valid_uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def valid_profile_id(value):
    return isinstance(value, str) and 1 <= len(value) <= 240 and all(ord(c) >= 32 for c in value)


def identity(credential):
    return digest({key: credential.get(key) for key in ('provider', 'type', 'email', 'accountId', 'projectId')})


def credential_valid(credential):
    require(isinstance(credential, dict), 'credential_shape')
    require(isinstance(credential.get('provider'), str) and 1 <= len(credential['provider']) <= 100,
            'credential_provider_shape')
    kind = credential.get('type')
    require(kind in ('oauth', 'token', 'api_key'), 'credential_type_shape')
    keys = ('access', 'refresh') if kind == 'oauth' else ('key',) if kind == 'api_key' else ('token',)
    require(all(isinstance(credential.get(key), str) and len(credential[key]) >= 8 for key in keys), 'credential_secret_shape')
    require(all(key not in credential for key in ('keyRef', 'tokenRef', 'accessRef', 'refreshRef')), 'unresolved_secret_reference')
    if kind == 'oauth':
        require(isinstance(credential.get('expires'), int) and not isinstance(credential['expires'], bool)
                and credential['expires'] > 0, 'oauth_expiry_shape')
    require(len(canonical(credential)) <= MAX_DOCUMENT, 'credential_document_bound')


def parse_event(source_host, event_id, value):
    require(HOST.fullmatch(source_host) and valid_uuid(event_id), 'inbox_path_shape')
    require(isinstance(value, dict) and value.get('sourceHost') == source_host
            and value.get('eventId') == event_id, 'inbox_body_path_identity_mismatch')
    event_sha = digest(value)
    require(len(canonical(value)) <= MAX_DOCUMENT, 'inbox_event_bound')
    if value.get('schemaVersion') == 2 and value.get('kind') == 'agent-report':
        require('credential' not in value and isinstance(value.get('profiles'), list)
                and len(value['profiles']) <= MAX_PROFILES, 'agent_report_shape')
        return {'kind': 'agent-report', 'sha256': event_sha}
    require(value.get('schemaVersion') == 1 and value.get('reason') in ('new-profile', 'manual-login', 'leader-refresh'),
            'unsupported_inbox_event')
    require(valid_profile_id(value.get('profileId')), 'event_profile_id_shape')
    credential_valid(value.get('credential'))
    require(hmac.compare_digest(digest(value['credential']), str(value.get('digest', '')))
            and hmac.compare_digest(identity(value['credential']), str(value.get('identity', ''))), 'event_credential_digest_mismatch')
    return {'kind': 'credential', 'sha256': event_sha}


def receipt_key(host, event_id):
    return 'coordinator-receipts/' + sha((host + '\0' + event_id).encode())


def validate_grant(value, sources):
    fields = {'authorizationId', 'profileId', 'sourceHost', 'provider', 'identityDigest', 'expectedCurrentDigest', 'nextDigest'}
    require(isinstance(value, dict) and set(value) == fields and valid_uuid(value['authorizationId']), 'operator_authorization_shape')
    require(valid_profile_id(value['profileId']) and value['sourceHost'] in sources
            and isinstance(value['provider'], str) and 1 <= len(value['provider']) <= 100,
            'operator_authorization_source_scope')
    require(SHA.fullmatch(value['identityDigest']) and SHA.fullmatch(value['nextDigest'])
            and (value['expectedCurrentDigest'] is None or SHA.fullmatch(value['expectedCurrentDigest'])), 'operator_authorization_digest_shape')
    require(value['nextDigest'] != value['expectedCurrentDigest'], 'operator_authorization_no_transition')


def validate_manifest(value, owner_id, sources):
    require(isinstance(value, dict) and value.get('schemaVersion') == 1 and isinstance(value.get('generation'), int)
            and 0 <= value['generation'] < 9007199254740000 and isinstance(value.get('profiles'), list)
            and len(value['profiles']) <= MAX_PROFILES, 'manifest_shape')
    control = value.get('coordinator')
    require(isinstance(control, dict) and control.get('protocol') == PROTOCOL and control.get('ownerId') == owner_id
            and isinstance(control.get('authorizations'), list) and len(control['authorizations']) <= MAX_GRANTS,
            'manifest_coordinator_binding')
    ids = []
    for entry in value['profiles']:
        require(isinstance(entry, dict) and valid_profile_id(entry.get('profileId'))
                and isinstance(entry.get('key'), str) and re.fullmatch(r'sha256-[a-f0-9]{64}', entry['key'])
                and SHA.fullmatch(entry.get('digest', '')) and 'credential' not in entry, 'manifest_profile_shape')
        ids.append(entry['profileId'])
    require(len(ids) == len(set(ids)), 'manifest_duplicate_profile')
    grant_ids, grant_profiles = [], []
    for grant in control['authorizations']:
        validate_grant(grant, sources)
        grant_ids.append(grant['authorizationId']); grant_profiles.append(grant['profileId'])
    require(len(grant_ids) == len(set(grant_ids)) and len(grant_profiles) == len(set(grant_profiles)), 'manifest_duplicate_authorization')
    require(len(canonical(value)) <= MAX_DOCUMENT, 'manifest_document_bound')
    return value


class Bao:
    """Strict HTTPS/AppRole client. A mutation transport failure is unknown."""
    def __init__(self, config):
        target = urlsplit(config['address'])
        require(target.scheme == 'https' and target.hostname and not target.username and not target.password
                and not target.query and not target.fragment and target.path in ('', '/'), 'https_endpoint_required')
        self.host, self.port = target.hostname, target.port or 443
        self.timeout = config.get('request_timeout_seconds', 10)
        require(isinstance(self.timeout, int) and 1 <= self.timeout <= 30, 'request_timeout_bound')
        self.context = ssl.create_default_context(cafile=str(config['ca_file']))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.pin = config['server_certificate_sha256']
        require(SHA.fullmatch(self.pin), 'server_certificate_pin_shape')
        self.config, self.token, self.deadline, self.renewable = config, None, 0, False
        self.secrets = []

    def request(self, method, route, body=None):
        self.ensure_token()
        return self._dispatch(method, route, body, bearer=self.token, bearer_deadline=self.deadline)

    def _dispatch(self, method, route, body=None, *, bearer=None, started_at=None, bearer_deadline=None):
        """Send once with an explicit bearer; this method never logs in or renews.

        Both the original request budget and the accepted local bearer lease
        remain fixed while connecting, sending and consuming the response.
        A transport failure after a mutation was dispatched stays unknown.
        """
        started_at = time.monotonic() if started_at is None else started_at
        deadline = started_at + self.timeout
        if bearer_deadline is not None:
            deadline = min(deadline, bearer_deadline)

        def remaining():
            left = deadline - time.monotonic()
            require(left > 0, 'request_absolute_deadline')
            return left

        payload = None if body is None else canonical(body)
        require(payload is None or len(payload) <= MAX_BODY, 'request_body_bound')
        connection = http.client.HTTPSConnection(self.host, self.port, context=self.context, timeout=remaining())
        dispatched = False
        try:
            connection.connect()
            require(hmac.compare_digest(sha(connection.sock.getpeercert(binary_form=True)), self.pin), 'server_certificate_pin_changed')
            wire_socket = connection.sock
            wire_socket.settimeout(remaining())
            headers = {'Accept': 'application/json', 'Connection': 'close'}
            if payload is not None:
                headers['Content-Type'] = 'application/json'
            if bearer is not None:
                headers['X-Vault-Token'] = bearer
            wire_socket.settimeout(remaining())
            dispatched = True
            connection.request(method, '/v1/' + route, body=payload, headers=headers)
            wire_socket.settimeout(remaining())
            response = connection.getresponse()
            remaining()
            chunks, size = [], 0
            while response.fp is not None:
                # HTTPResponse retains the socket after Connection: close;
                # set its underlying read timeout before each bounded read.
                wire_socket.settimeout(remaining())
                block = response.read1(min(65536, MAX_BODY + 1 - size))
                if not block:
                    break
                chunks.append(block); size += len(block)
                require(size <= MAX_BODY, 'response_body_bound')
            raw = b''.join(chunks)
            value = json.loads(raw) if raw else None
            remaining()
            status = response.status
            if status == 400 and isinstance(value, dict) and value.get('errors') == [CAS_ERROR]:
                raise Conflict('kv_cas_conflict')
            if status == 404:
                return None
            if status in (401, 403):
                raise Error('bao_authentication_or_acl_denied')
            require(200 <= status < 300, 'bao_unexpected_http_status')
            return value
        except Conflict:
            raise
        except (OSError, TimeoutError, http.client.HTTPException, ValueError, Error) as exc:
            if isinstance(exc, Error) and str(exc) in ('bao_authentication_or_acl_denied', 'server_certificate_pin_changed'):
                raise
            if dispatched and method in ('POST', 'PUT', 'DELETE'):
                raise UnknownOutcome('mutation_outcome_unknown') from None
            if isinstance(exc, Error):
                raise
            raise Error('bao_read_transport_failed') from None
        finally:
            connection.close()

    def ensure_token(self):
        previous_token = self.token
        if self.token is None:
            role = read_private(Path(self.config['role_id_file']), 16384).decode().strip()
            secret = read_private(Path(self.config['secret_id_file']), 16384).decode().strip()
            require(8 <= len(role) <= 4096 and 8 <= len(secret) <= 4096, 'approle_material_shape')
            self.secrets.extend((role, secret))
            auth_started = time.monotonic()
            result = self._dispatch('POST', 'auth/approle/login', {'role_id': role, 'secret_id': secret},
                                    started_at=auth_started)
        elif time.monotonic() < self.deadline - 30:
            return
        else:
            require(self.renewable and time.monotonic() < self.deadline, 'coordinator_token_expired')
            auth_started = time.monotonic()
            result = self._dispatch('POST', 'auth/token/renew-self', {'increment': '300s'},
                                    bearer=previous_token, bearer_deadline=self.deadline, started_at=auth_started)
        auth = result.get('auth', {}) if isinstance(result, dict) else {}
        require(isinstance(auth.get('client_token'), str) and len(auth['client_token']) >= 8
                and isinstance(auth.get('lease_duration'), int) and auth['lease_duration'] > 30, 'approle_reply_shape')
        require(previous_token is None or auth['client_token'] == previous_token, 'coordinator_renewal_token_changed')
        accepted_deadline = auth_started + auth['lease_duration']
        require(time.monotonic() < accepted_deadline, 'coordinator_reply_lease_elapsed')
        self.token = auth['client_token']; self.secrets.append(self.token)
        self.deadline = accepted_deadline
        self.renewable = auth.get('renewable') is True

    def read(self, key, version=None):
        route = MOUNT + '/data/' + key
        if version is not None:
            route += '?version=' + str(version)
        value = self.request('GET', route)
        if value is None:
            return None
        data = value.get('data', {})
        require(isinstance(data.get('data'), dict) and isinstance(data.get('metadata', {}).get('version'), int), 'kv_reply_shape')
        return {'data': data['data'], 'version': data['metadata']['version']}

    def write(self, key, value, cas):
        result = self.request('POST', MOUNT + '/data/' + key, {'data': value, 'options': {'cas': cas}})
        require(isinstance(result, dict) and isinstance(result.get('data', {}).get('version'), int), 'kv_write_reply_shape')
        require(result['data']['version'] == cas + 1 if cas > 0 else result['data']['version'] == 1, 'kv_write_version_mismatch')
        return result['data']['version']

    def list(self, prefix):
        value = self.request('LIST', MOUNT + '/metadata/' + prefix)
        if value is None:
            return []
        keys = value.get('data', {}).get('keys')
        require(isinstance(keys, list) and len(keys) <= 1024 and all(isinstance(key, str) for key in keys), 'inbox_list_bound')
        return sorted(keys)


class Coordinator:
    def __init__(self, client, state_dir, owner_id, source_hosts, phase_hook=None):
        require(valid_uuid(owner_id) and 1 <= len(source_hosts) <= 16
                and all(HOST.fullmatch(host) for host in source_hosts)
                and len(source_hosts) == len(set(source_hosts)), 'coordinator_owner_configuration')
        self.client, self.state, self.owner = client, Path(state_dir), owner_id
        self.sources = list(source_hosts)
        self.hook = phase_hook or (lambda phase: None)
        owned_directory(self.state)
        self.pending = self.state / 'pending.private.json'
        self.secrets = []

    def manifest(self):
        result = self.client.read('manifest')
        require(result is not None, 'coordinator_not_initialized')
        validate_manifest(result['data'], self.owner, self.sources)
        return result

    def initialize(self):
        with operation_lock(self.state):
            require(not self.pending.exists(), 'pending_operation_requires_recovery')
            require(self.client.read('manifest') is None, 'existing_manifest_requires_reviewed_migration')
            value = {'schemaVersion': 1, 'generation': 0, 'profiles': [], 'coordinator': {
                'protocol': PROTOCOL, 'ownerId': self.owner, 'authorizations': [], 'lastReceipt': None}}
            self.client.write('manifest', value, 0)
            return {'initialized': True, 'manifest_version': 1, 'credential_profiles': 0}

    def ensure_immutable(self, key, value):
        current = self.client.read(key)
        if current is None:
            try:
                self.client.write(key, value, 0)
            except (Conflict, UnknownOutcome):
                # Re-reading a content-addressed CAS0 object is safe. Never
                # overwrite a different value or turn an ACL denial into OK.
                pass
            current = self.client.read(key)
        require(current is not None and current['version'] == 1 and canonical(current['data']) == canonical(value), 'immutable_object_not_confirmed')

    def finish_previous_receipt(self, manifest):
        last = manifest['data']['coordinator'].get('lastReceipt')
        if last is None:
            return
        require(isinstance(last, dict) and last.get('ownerId') == self.owner and last.get('status') == 'committed'
                and last.get('sourceHost') in self.sources and valid_uuid(last.get('eventId'))
                and SHA.fullmatch(last.get('eventDigest', '')), 'manifest_receipt_shape')
        key = receipt_key(last['sourceHost'], last['eventId'])
        existing = self.client.read(key)
        if existing is not None:
            require(existing['version'] == 1 and canonical(existing['data']) == canonical(last), 'committed_receipt_collision')
            return
        # A new process/state copy may finish the latest receipt from committed
        # canonical provenance, but cannot infer old overwritten outcomes.
        matching = [entry for entry in manifest['data']['profiles']
                    if sha(entry['profileId'].encode()) == last['profileIdSha256']]
        require(len(matching) == 1 and matching[0].get('sourceEvent') == {
                'sourceHost': last['sourceHost'], 'eventId': last['eventId'],
                'eventDigest': last['eventDigest'], 'authorizationId': last['authorizationId']}
                and matching[0]['digest'] == last['credentialDigest'] and matching[0]['key'] == last['profileKey'],
                'receipt_recovery_provenance_missing')
        self.ensure_immutable(key, last)

    def authorize(self, grant):
        validate_grant(grant, self.sources)
        with operation_lock(self.state):
            require(not self.pending.exists(), 'pending_operation_requires_recovery')
            snapshot = self.manifest(); self.finish_previous_receipt(snapshot)
            value = snapshot['data']
            current = next((entry for entry in value['profiles'] if entry['profileId'] == grant['profileId']), None)
            require((current or {}).get('digest') == grant['expectedCurrentDigest'], 'operator_expected_current_digest_mismatch')
            grants = value['coordinator']['authorizations']
            if grant in grants:
                return {'authorized': True, 'already_present': True, 'authorization_id': grant['authorizationId']}
            require(len(grants) < MAX_GRANTS and all(item['profileId'] != grant['profileId']
                    and item['authorizationId'] != grant['authorizationId'] for item in grants), 'operator_authorization_already_pending')
            grants.append(grant)
            validate_manifest(value, self.owner, self.sources)
            self.client.write('manifest', value, snapshot['version'])
            return {'authorized': True, 'authorization_id': grant['authorizationId'], 'manifest_version': snapshot['version'] + 1}

    def revoke_authorization(self, authorization_id):
        require(valid_uuid(authorization_id), 'operator_authorization_id_shape')
        with operation_lock(self.state):
            require(not self.pending.exists(), 'pending_operation_requires_recovery')
            snapshot = self.manifest(); self.finish_previous_receipt(snapshot)
            value = snapshot['data']
            grants = value['coordinator']['authorizations']
            remaining = [grant for grant in grants if grant['authorizationId'] != authorization_id]
            if len(remaining) == len(grants):
                return {'authorization_pending': False, 'authorization_id': authorization_id}
            value['coordinator']['authorizations'] = remaining
            self.client.write('manifest', value, snapshot['version'])
            return {'authorization_revoked': True, 'authorization_id': authorization_id,
                    'manifest_version': snapshot['version'] + 1}

    def save_pending(self, value):
        private_json(self.pending, value, replace=True)

    def complete_pending(self, value):
        require(valid_uuid(value.get('operationId')), 'journal_operation_id_shape')
        archive = self.state / ('completed-' + value['operationId'] + '.json')
        if archive.exists():
            require(json.loads(read_private(archive)) == value, 'completed_journal_collision')
        else:
            private_json(archive, value)
        self.pending.unlink(); sync_directory(self.state)

    def recover_locked(self):
        if not self.pending.exists():
            return False
        record = json.loads(read_private(self.pending))
        require(record.get('schema') == PROTOCOL + '.pending' and record.get('ownerId') == self.owner
                and record.get('sourceHost') in self.sources and valid_uuid(record.get('eventId'))
                and valid_uuid(record.get('operationId'))
                and digest(record['desiredManifest']) == record['desiredManifestDigest'], 'pending_journal_binding')
        validate_manifest(record['desiredManifest'], self.owner, self.sources)
        archive = self.state / ('completed-' + record['operationId'] + '.json')
        try:
            completed = json.loads(read_private(archive))
        except FileNotFoundError:
            completed = None
        if completed is not None:
            # The completed record is fsynced before pending is unlinked.
            # A crash between those operations must retain the exact known
            # outcome, including a CAS rejection that never published data.
            # Match every immutable field, not merely the operation UUID or
            # next credential digest. An unrelated restored archive is not
            # evidence about this pending operation.
            require(isinstance(completed, dict), 'completed_journal_binding_mismatch')
            binding = lambda value: {key: item for key, item in value.items() if key not in ('phase', 'result')}
            require(canonical(binding(completed)) == canonical(binding(record)), 'completed_journal_binding_mismatch')
            result, phase = completed.get('result'), completed.get('phase')
            valid_terminal = (
                result == 'not_dispatched' and phase == record['phase'] and phase in ('prepared', 'profile_confirmed')
                or result == 'known_cas_conflict' and phase == record['phase'] == 'manifest_dispatched'
                or result == 'committed' and phase == 'receipt_confirmed'
                and record['phase'] in ('manifest_dispatched', 'manifest_confirmed', 'receipt_confirmed')
            )
            require(valid_terminal and record.get('result', result) == result, 'completed_journal_terminal_mismatch')
            if result == 'committed':
                receipt = self.client.read(completed['receiptKey'])
                require(receipt is not None and receipt['version'] == 1
                        and canonical(receipt['data']) == canonical(completed['receipt']),
                        'completed_journal_receipt_not_confirmed')
            self.complete_pending(completed)
            return True
        if record['phase'] in ('prepared', 'profile_confirmed'):
            # No manifest request was dispatched. Retain immutable leftovers;
            # re-plan only after a fresh manifest and fresh operator grant read.
            record['result'] = 'not_dispatched'
            self.complete_pending(record)
            return True
        require(record['phase'] in ('manifest_dispatched', 'manifest_confirmed', 'receipt_confirmed'), 'pending_journal_phase')
        current = self.client.read('manifest')
        matching = current and current['version'] == record['expectedVersion'] + 1 and digest(current['data']) == record['desiredManifestDigest']
        if not matching:
            history = self.client.read('manifest', version=record['expectedVersion'] + 1)
            matching = history and history['version'] == record['expectedVersion'] + 1 and digest(history['data']) == record['desiredManifestDigest']
        if not matching:
            raise UnknownOutcome('manifest_history_does_not_prove_pending_commit')
        self.ensure_immutable(record['receiptKey'], record['receipt'])
        record['phase'] = 'receipt_confirmed'; record['result'] = 'committed'
        self.complete_pending(record)
        return True

    def commit_event(self, source_host, event_id, event, parsed):
        snapshot = self.manifest(); self.finish_previous_receipt(snapshot)
        manifest = snapshot['data']
        grant = next((item for item in manifest['coordinator']['authorizations']
                      if item['profileId'] == event['profileId']), None)
        require(grant is not None and grant['sourceHost'] == source_host and grant['provider'] == event['credential']['provider']
                and grant['identityDigest'] == event['identity'] and grant['nextDigest'] == event['digest'], 'credential_transition_not_authorized')
        current = next((entry for entry in manifest['profiles'] if entry['profileId'] == event['profileId']), None)
        require((current or {}).get('digest') == grant['expectedCurrentDigest'], 'authorized_transition_source_changed')
        profile = {'schemaVersion': 1, 'profileId': event['profileId'], 'credential': event['credential'],
                   'digest': event['digest'], 'identity': event['identity']}
        profile_key = 'sha256-' + digest(profile)
        receipt = {'schema': PROTOCOL + '.receipt', 'ownerId': self.owner, 'status': 'committed',
                   'sourceHost': source_host, 'eventId': event_id, 'eventDigest': parsed['sha256'],
                   'profileIdSha256': sha(event['profileId'].encode()), 'credentialDigest': event['digest'],
                   'profileKey': profile_key, 'authorizationId': grant['authorizationId'],
                   'manifestVersion': snapshot['version'] + 1}
        entry = {'profileId': event['profileId'], 'key': profile_key, 'digest': event['digest'], 'identity': event['identity'],
                 'provider': event['credential']['provider'], 'type': event['credential']['type'],
                 'sourceEvent': {key: receipt[key] for key in ('sourceHost', 'eventId', 'eventDigest', 'authorizationId')}}
        if 'expires' in event['credential']:
            entry['expires'] = event['credential']['expires']
        manifest['profiles'] = [item for item in manifest['profiles'] if item['profileId'] != event['profileId']] + [entry]
        manifest['profiles'].sort(key=lambda item: item['profileId'])
        manifest['generation'] += 1
        manifest['coordinator']['authorizations'] = [item for item in manifest['coordinator']['authorizations'] if item != grant]
        manifest['coordinator']['lastReceipt'] = receipt
        validate_manifest(manifest, self.owner, self.sources)
        journal = {'schema': PROTOCOL + '.pending', 'ownerId': self.owner, 'sourceHost': source_host,
                   'operationId': str(uuid.uuid4()),
                   'eventId': event_id, 'eventDigest': parsed['sha256'], 'expectedVersion': snapshot['version'],
                   'desiredManifest': manifest, 'desiredManifestDigest': digest(manifest),
                   'receiptKey': receipt_key(source_host, event_id), 'receipt': receipt, 'phase': 'prepared'}
        self.save_pending(journal); self.hook('journal_prepared')
        self.ensure_immutable('profiles/' + profile_key, profile)
        journal['phase'] = 'profile_confirmed'; self.save_pending(journal); self.hook('profile_confirmed')
        journal['phase'] = 'manifest_dispatched'; self.save_pending(journal)
        try:
            self.client.write('manifest', manifest, snapshot['version'])
        except Conflict:
            journal['result'] = 'known_cas_conflict'
            self.complete_pending(journal)
            raise
        self.hook('manifest_committed_before_journal_reply')
        journal['phase'] = 'manifest_confirmed'; self.save_pending(journal)
        self.ensure_immutable(journal['receiptKey'], receipt)
        self.hook('receipt_committed_before_journal_reply')
        journal['phase'] = 'receipt_confirmed'; journal['result'] = 'committed'
        self.complete_pending(journal)

    def once(self):
        report = {'schema': PROTOCOL + '.cycle', 'owner_id': self.owner, 'ok': False,
                  'committed': 0, 'observed_reports': 0, 'already_recorded': 0, 'deferred': 0,
                  'oauth_refreshed': False, 'scheduler_implemented': False, 'provider_liveness_verified': False}
        with operation_lock(self.state):
            report['recovered_pending'] = self.recover_locked()
            self.finish_previous_receipt(self.manifest())
            handled = 0
            for host in self.sources:
                for event_id in self.client.list('inbox/' + quote(host, safe='')):
                    require(valid_uuid(event_id), 'inbox_list_child_not_event_uuid')
                    key = 'inbox/' + host + '/' + event_id
                    value = self.client.read(key)
                    require(value is not None and value['version'] == 1, 'inbox_event_not_immutable')
                    event = value['data']
                    if isinstance(event.get('credential'), dict):
                        self.secrets.extend(item for name, item in event['credential'].items()
                            if name in ('key', 'access', 'refresh', 'token') and isinstance(item, str))
                    try:
                        parsed = parse_event(host, event_id, event)
                    except Error as exc:
                        if str(exc) == 'unsupported_inbox_event':
                            report['deferred'] += 1
                            report['unsupported_events_retained'] = report.get('unsupported_events_retained', 0) + 1
                            continue
                        raise
                    prior = self.client.read(receipt_key(host, event_id))
                    if prior is not None:
                        require(prior['version'] == 1 and prior['data'].get('ownerId') == self.owner
                                and prior['data'].get('sourceHost') == host and prior['data'].get('eventId') == event_id
                                and prior['data'].get('eventDigest') == parsed['sha256'], 'inbox_event_receipt_collision')
                        report['already_recorded'] += 1
                        continue
                    if handled >= 32:
                        report['batch_bound_hit'] = True
                        break
                    handled += 1
                    if parsed['kind'] == 'agent-report':
                        receipt = {'schema': PROTOCOL + '.receipt', 'ownerId': self.owner,
                                   'status': 'observed_no_scheduler_action', 'sourceHost': host,
                                   'eventId': event_id, 'eventDigest': parsed['sha256']}
                        self.ensure_immutable(receipt_key(host, event_id), receipt)
                        report['observed_reports'] += 1
                        continue
                    try:
                        self.commit_event(host, event_id, event, parsed)
                        report['committed'] += 1
                    except Conflict:
                        report['deferred'] += 1
                    except Error as exc:
                        if str(exc) in ('credential_transition_not_authorized', 'authorized_transition_source_changed'):
                            # An operator may authorize this exact event later.
                            # Do not mark it consumed, delete it, or overwrite a
                            # current credential based on an event timestamp.
                            report['deferred'] += 1
                            continue
                        raise
            report['ok'] = True
            return report


def load_config(path):
    config = json.loads(read_private(path))
    require(config.get('schema') == PROTOCOL + '.config', 'configuration_schema')
    state = Path(config['state_dir'])
    require(state.is_absolute(), 'state_directory_absolute_required')
    owned_directory(state)
    for key in ('ca_file', 'role_id_file', 'secret_id_file'):
        require(Path(config[key]).is_absolute(), 'credential_path_absolute_required')
        read_private(Path(config[key]), MAX_BODY)
    require(config.get('production_cutover') is False, 'candidate_requires_explicit_uninstalled_scope')
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('initialize', 'authorize', 'revoke-authorization', 'once', 'serve', 'recover'))
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--authorization', type=Path)
    parser.add_argument('--authorization-id')
    args = parser.parse_args()
    os.umask(0o077)
    client = worker = None
    try:
        config = load_config(args.config)
        client = Bao(config)
        worker = Coordinator(client, config['state_dir'], config['owner_id'], config['source_hosts'])
        if args.command == 'initialize':
            result = worker.initialize()
        elif args.command == 'authorize':
            require(args.authorization is not None, 'operator_authorization_file_required')
            result = worker.authorize(json.loads(read_private(args.authorization)))
        elif args.command == 'revoke-authorization':
            result = worker.revoke_authorization(args.authorization_id)
        elif args.command == 'recover':
            with operation_lock(worker.state):
                result = {'recovered_pending': worker.recover_locked()}
                worker.finish_previous_receipt(worker.manifest())
        else:
            interval = config.get('poll_interval_seconds', 15)
            require(isinstance(interval, int) and 1 <= interval <= 60, 'poll_interval_bound')
            while True:
                result = worker.once()
                if args.command == 'once':
                    break
                rendered = json.dumps(result, sort_keys=True)
                require(all(secret not in rendered for secret in client.secrets + worker.secrets), 'public_result_contains_secret')
                print(rendered, flush=True)
                time.sleep(interval)
        result.update(ok=True, production_cutover=False, provider_called=False, oauth_refreshed=False)
        rendered = json.dumps(result, sort_keys=True)
        require(all(secret not in rendered for secret in client.secrets + worker.secrets), 'public_result_contains_secret')
        print(rendered)
        return 0
    except (Error, OSError, ValueError, KeyError, TypeError) as exc:
        code = str(exc) if isinstance(exc, Error) else 'coordinator_' + type(exc).__name__
        print(json.dumps({'schema': PROTOCOL + '.result', 'ok': False, 'error': code,
                          'unknown_outcome': isinstance(exc, UnknownOutcome), 'production_cutover': False,
                          'provider_called': False, 'oauth_refreshed': False}))
        return 3 if isinstance(exc, UnknownOutcome) else 2


if __name__ == '__main__':
    raise SystemExit(main())
