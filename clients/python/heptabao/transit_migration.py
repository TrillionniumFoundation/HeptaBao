"""Explicit online Transit re-encryption. No key export, plaintext file or cutover.

A checkpoint is trusted local state protected from other OS users, not from root
or the same UID. Python/library copies of plaintext cannot be reliably erased;
run only in an approved isolated migration environment with core dumps disabled.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
from pathlib import Path

from .private_state import StateDirectory, read_trusted_ca
from .transport import BaoError, Client, canonical, digest, endpoint, key_path, private_json, private_read

MAX_RECORDS = 256
MAX_PLAINTEXT_BYTES = 16 * 1024
MAX_CIPHERTEXT_BYTES = 24 * 1024
SCHEMA = 'heptabao.transit-reencryption.v1'
PHASES = {'source_pending', 'encrypt_pending', 'encrypted', 'verified'}


def _b64(value, limit):
    if not isinstance(value, str) or len(value) > (limit + 2) // 3 * 4:
        raise BaoError('invalid_bounded_base64')
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise BaoError('invalid_bounded_base64') from None
    if len(decoded) > limit or base64.b64encode(decoded).decode('ascii') != value:
        raise BaoError('invalid_bounded_base64')
    return value


def ciphertext(value):
    if not isinstance(value, str) or len(value) > MAX_CIPHERTEXT_BYTES:
        raise BaoError('invalid_transit_ciphertext')
    match = re.fullmatch(r'vault:v([1-9][0-9]{0,9}):([A-Za-z0-9+/]*={0,2})', value)
    if match is None or len(base64.b64decode(_b64(match[2], MAX_CIPHERTEXT_BYTES), validate=True)) < 28:
        raise BaoError('invalid_transit_ciphertext')
    return value


def records_from(value):
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_RECORDS:
        raise BaoError('bounded_nonempty_record_list_required')
    result, ids = [], set()
    for record in value:
        if (not isinstance(record, dict) or not {'id', 'ciphertext'} <= set(record)
                or set(record) - {'id', 'ciphertext', 'context', 'associated_data'}):
            raise BaoError('invalid_transit_record_fields')
        ident = record['id']
        if not isinstance(ident, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', ident) or ident in ids:
            raise BaoError('duplicate_or_invalid_record_id')
        ids.add(ident)
        ciphertext(record['ciphertext'])
        for field in ('context', 'associated_data'):
            if field in record:
                _b64(record[field], 4096)
        result.append(dict(record))
    return result


def _configuration(value):
    if not isinstance(value, dict) or set(value) != {'source', 'target', 'target_key_version'}:
        raise BaoError('invalid_migration_configuration')
    if type(value['target_key_version']) is not int or not 1 <= value['target_key_version'] <= 1_000_000:
        raise BaoError('explicit_target_key_version_required')
    result = {'target_key_version': value['target_key_version']}
    for side in ('source', 'target'):
        config = value[side]
        fields = {'address', 'ca_file', 'token_file', 'namespace', 'mount', 'key'}
        if not isinstance(config, dict) or set(config) != fields or any(not isinstance(v, str) for v in config.values()):
            raise BaoError('invalid_endpoint_configuration')
        for field in ('ca_file', 'token_file'):
            if not Path(config[field]).is_absolute() or '..' in Path(config[field]).parts:
                raise BaoError('absolute_credential_and_ca_paths_required')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', config['key']):
            raise BaoError('invalid_transit_key_name')
        key_path(config['mount'])
        if config['namespace']:
            key_path(config['namespace'])
        result[side] = {**config, 'address': endpoint(config['address'])}
    if result['source']['address'] == result['target']['address']:
        raise BaoError('distinct_migration_endpoints_required')
    return result


def load_configuration(path):
    return _configuration(private_json(path))


def client_for(config):
    ca = read_trusted_ca(config['ca_file'])
    try:
        token = private_read(config['token_file'], 8192).decode('ascii').strip()
    except UnicodeError:
        raise BaoError('invalid_token_input') from None
    client = Client(config['address'], config['ca_file'], token, config['namespace'], trusted_ca_pem=ca)
    return client, hashlib.sha256(ca).hexdigest()


class TransitMigrator:
    """One descriptor-locked run. The caller owns and must close the directory."""
    def __init__(self, directory: StateDirectory, configuration, records, *, clients=None):
        self.directory = directory
        self.config = _configuration(configuration)
        self.records = records_from(records)
        if directory.lock_fd is None:
            raise BaoError('migration_writer_required')
        directory.check()
        if clients is None:
            self.source, source_ca = client_for(self.config['source'])
            self.target, target_ca = client_for(self.config['target'])
        else:
            # Dependency injection for deterministic tests; CLI never accepts it.
            self.source, self.target, source_ca, target_ca = clients
        source_health, target_health = self.source.health(), self.target.health()
        if source_health['cluster_id'] == target_health['cluster_id']:
            raise BaoError('distinct_migration_clusters_required')
        binding = {'schema': SCHEMA, 'target_key_version': self.config['target_key_version']}
        for name, health, ca in [('source', source_health, source_ca), ('target', target_health, target_ca)]:
            if not isinstance(ca, str) or not re.fullmatch('[a-f0-9]{64}', ca):
                raise BaoError('invalid_ca_binding')
            config = self.config[name]
            binding[name] = {k: config[k] for k in ('address', 'namespace', 'mount', 'key')}
            binding[name].update(cluster_id=health['cluster_id'], version=health['version'], ca_sha256=ca)
        self.binding = digest(binding)
        run = {'schema': SCHEMA, 'binding': self.binding, 'input_digest': digest(self.records), 'record_count': len(self.records)}
        existing = directory.json('transit-run.json', optional=True)
        if existing is not None and existing != run:
            raise BaoError('migration_binding_or_input_changed')
        # GET must find an existing target key: encryption must never upsert a key.
        config_path = '/v1/' + key_path(self.config['target']['mount'] + '/config/keys')
        key_config = self._request(self.target, 'GET', config_path, None)
        if key_config.get('disable_upsert') is not True:
            raise BaoError('target_must_disable_key_upsert')
        metadata = self._request(self.target, 'GET', self._path('target', 'keys'), None)
        version = metadata.get('latest_version')
        minimum = metadata.get('min_encryption_version', 0)
        decrypt_minimum = metadata.get('min_decryption_version', 1)
        if (metadata.get('type') not in ('aes128-gcm96', 'aes256-gcm96', 'chacha20-poly1305')
                or metadata.get('derived') is not False or metadata.get('convergent_encryption', False) is not False
                or type(version) is not int or type(minimum) is not int or type(decrypt_minimum) is not int
                or not max(1, minimum, decrypt_minimum) <= self.config['target_key_version'] <= version):
            raise BaoError('target_key_profile_or_version_not_admitted')
        if existing is None:
            directory.publish('transit-run.json', run)

    def _path(self, side, operation):
        config = self.config[side]
        return '/v1/' + key_path(config['mount'] + '/' + operation + '/' + config['key'])

    @staticmethod
    def _request(client, method, path, body):
        response = client.request(method, path, body)
        if response.status != 200:
            # Never echo remote response text, a key name, ciphertext or plaintext.
            raise BaoError('migration_endpoint_rejected')
        return response.data()

    def _source_plaintext(self, record):
        body = {k: v for k, v in record.items() if k != 'id'}
        response = self._request(self.source, 'POST', self._path('source', 'decrypt'), body)
        return _b64(response.get('plaintext'), MAX_PLAINTEXT_BYTES)

    def _checkpoint(self, record, phase, target_ciphertext=None):
        checkpoint = {'schema': SCHEMA, 'binding': self.binding, 'input_digest': digest(record), 'phase': phase}
        if target_ciphertext is not None:
            checkpoint['target_ciphertext'] = ciphertext(target_ciphertext)
            checkpoint['target_ciphertext_digest'] = digest(target_ciphertext)
        return checkpoint

    def migrate(self):
        completed = reused = 0
        for record in self.records:
            filename = 'transit-' + hashlib.sha256(record['id'].encode()).hexdigest() + '.json'
            checkpoint = self.directory.json(filename, optional=True)
            was_verified = False
            if checkpoint is not None:
                if not isinstance(checkpoint, dict) or checkpoint.get('phase') not in PHASES:
                    raise BaoError('invalid_migration_checkpoint')
                phase = checkpoint['phase']
                target_ciphertext = checkpoint.get('target_ciphertext')
                if checkpoint != self._checkpoint(record, phase, target_ciphertext):
                    raise BaoError('migration_checkpoint_binding_changed')
                if phase in ('source_pending', 'encrypt_pending'):
                    raise BaoError('migration_outcome_unknown_no_automatic_retry')
                if target_ciphertext is None:
                    raise BaoError('missing_target_ciphertext')
                was_verified = phase == 'verified'
            else:
                self.directory.publish(filename, self._checkpoint(record, 'source_pending'))
                plaintext = self._source_plaintext(record)
                try:
                    self.directory.publish(filename, self._checkpoint(record, 'encrypt_pending'))
                    payload = {'plaintext': plaintext, 'key_version': self.config['target_key_version']}
                    if 'associated_data' in record:
                        payload['associated_data'] = record['associated_data']
                    response = self._request(self.target, 'POST', self._path('target', 'encrypt'), payload)
                    target_ciphertext = ciphertext(response.get('ciphertext'))
                    if not target_ciphertext.startswith('vault:v' + str(self.config['target_key_version']) + ':'):
                        raise BaoError('target_encryption_version_changed')
                    # Persist the one actual ciphertext before any verification.
                    self.directory.publish(filename, self._checkpoint(record, 'encrypted', target_ciphertext))
                finally:
                    if 'payload' in locals():
                        payload.clear()
                    plaintext = None
            # Deliberate verification resumption only; never repeats target encrypt.
            plaintext = self._source_plaintext(record)
            payload = {'ciphertext': target_ciphertext}
            if 'associated_data' in record:
                payload['associated_data'] = record['associated_data']
            try:
                observed = self._request(self.target, 'POST', self._path('target', 'decrypt'), payload)
                target_plaintext = _b64(observed.get('plaintext'), MAX_PLAINTEXT_BYTES)
                if not hmac.compare_digest(plaintext, target_plaintext):
                    raise BaoError('reencryption_readback_mismatch')
                self.directory.publish(filename, self._checkpoint(record, 'verified', target_ciphertext))
                if was_verified:
                    reused += 1
                else:
                    completed += 1
            finally:
                payload.clear()
                if 'observed' in locals():
                    observed.clear()
                plaintext = target_plaintext = None
        return {'schema': SCHEMA, 'status': 'verified_ciphertext_outputs', 'converted': completed, 'reused': reused,
                'record_count': len(self.records), 'plaintext_persisted': False, 'key_exported': False,
                'source_cutover': False, 'application_data_updated': False, 'full_format_migration': False}
