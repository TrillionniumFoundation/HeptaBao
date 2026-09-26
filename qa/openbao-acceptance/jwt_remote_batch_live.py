#!/usr/bin/env python3
"""One real TLS candidate and HTTPS JWKS provider; ordinary JWT batch only.

No browser OIDC, official differential, HA or exact subsecond scheduling claim.
Every mutation is sent once. The deterministic same-second boundary is also a
Rust unit test; this runner records whether its immediate chain stayed in one
wall-clock second instead of retrying until a favorable clock boundary occurs.
"""
from __future__ import annotations
import base64
import importlib
import json
from pathlib import Path
import re
import secrets
import shutil
import signal
import tempfile
import time

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, file_hash
from jwt_api_tls_live import bounded_issuer
from native_snapshot_cli_live import contains_any, private_parent
from online_evidence import admit_output, complete_checks, source_identity
from remote_jwks_live import Instance, signing_key, token, serialization

PHASES = ('immediate', 'remote_unavailable', 'key_removed', 'rotated', 'role_deleted', 'mount_deleted', 'restarted')
REQUIRED = frozenset({'initialized', 'unsealed', 'empty_enrollment', 'kv_mount', 'policy', 'value',
    'jwt_mount', 'jwks_configuration', 'role', 'login', 'batch_shape', 'local_batch_issued',
    'local_batch_usable', 'reused_login', 'fresh_bearer', 'unavailable_denied', 'removed_key_denied',
    'rotated_login', 'rotated_batch_shape', 'role_deleted', 'mount_deleted', 'restart_unsealed',
    'processes_stopped', 'plaintext_absent', 'complete'}
    | {phase+'_'+kind for phase in PHASES for kind in ('kv', 'lookup')}
    | {phase+'_jwks_fetched' for phase in ('first', 'reused', 'unavailable', 'removed', 'rotation')})

class Failure(RuntimeError):
    pass


def complete(rows):
    return complete_checks(rows, required_cases=REQUIRED) and rows[-1]['case'] == 'complete'


def batch_shape(body):
    auth = body.get('auth') if isinstance(body, dict) else None
    return (isinstance(auth, dict) and isinstance(auth.get('client_token'), str)
            and bool(auth['client_token']) and auth.get('token_type') == 'batch'
            and auth.get('accessor') in ('', None) and auth.get('renewable') is False
            and type(auth.get('lease_duration')) is int and auth['lease_duration'] > 0
            and isinstance(auth.get('entity_id'), str) and bool(auth['entity_id'])
            and auth.get('metadata') == {'role': 'test'})


def denied(status, body, expected=400):
    return (status == expected and isinstance(body, dict) and isinstance(body.get('errors'), list)
            and bool(body['errors']) and not any(body.get(key) for key in ('auth', 'data', 'wrap_info')))


def verify_bearer(instance, bearer, expected, phase, check):
    status, body = instance.call('GET', 'batch-values/value', token=bearer)
    check(phase+'_kv', status == 200 and body.get('data') == expected)
    status, body = instance.call('GET', 'auth/token/lookup-self', token=bearer)
    data = body.get('data') or {}
    check(phase+'_lookup', status == 200 and data.get('id') == bearer and data.get('type') == 'batch'
          and data.get('accessor') in ('', None) and data.get('renewable') is False
          and type(data.get('ttl')) is int and data['ttl'] > 0)


def helpers():
    names = ('bao_http', 'heptabao.transport', 'core_isolation', 'jwt_api_tls_live',
             'native_snapshot_cli_live', 'online_evidence', 'remote_jwks_live',
             'external_tls_fixtures', 'smoke')
    return {name: file_hash(Path(importlib.import_module(name).__file__)) for name in names}


def run(binary, work, rows, observations):
    instance = issuer = None
    samples = []
    def check(name, passed):
        if not re.fullmatch('[a-z0-9_]{1,120}', name) or type(passed) is not bool:
            raise Failure('unsafe_observation')
        rows.append({'case': name, 'passed': passed})
        if not passed:
            raise Failure(name)
    def remember(value):
        samples.append(value.encode() if isinstance(value, str) else value)
        return value
    try:
        instance = Instance(binary, work/'candidate')
        config_path = instance.root/'server.json'
        config = json.loads(config_path.read_text())
        config['outbound_endpoints'] = []
        private_write(config_path, config, replace=True)
        check('empty_enrollment', json.loads(config_path.read_text())['outbound_endpoints'] == [])
        issuer = bounded_issuer(instance.root/'tls.crt', instance.root/'tls.key')
        private, jwk = signing_key('ES256', 'key-a')
        other_private, other_jwk = signing_key('ES256', 'key-b')
        for key in (private, other_private):
            remember(key.private_numbers().private_value.to_bytes(32, 'big'))
            for encoding in (serialization.Encoding.PEM, serialization.Encoding.DER):
                remember(key.private_bytes(encoding, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        issuer.documents['/keys'] = {'keys': [jwk]}
        instance.start()
        status, initial = instance.call('POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1})
        check('initialized', status == 200)
        share = remember(initial['keys_base64'][0]); instance.token = remember(initial['root_token'])
        for value in initial.get('keys', []):
            remember(value); remember(bytes.fromhex(value))
        remember(base64.b64decode(share, validate=True))
        check('unsealed', instance.call('POST', 'sys/unseal', {'key': share})[0] == 200)
        def call(name, path, payload=None, method='POST', expected=204):
            status, body = instance.call(method, path, payload)
            check(name, status == expected)
            return body
        call('kv_mount', 'sys/mounts/batch-values', {'type': 'kv', 'options': {'version': '1'}})
        call('policy', 'sys/policies/acl/remote-batch', {'policy': 'path "batch-values/*" { capabilities = ["read"] }'})
        value = {'value': remember('synthetic-kv-'+secrets.token_hex(24))}
        call('value', 'batch-values/value', value)
        call('jwt_mount', 'sys/auth/federated', {'type': 'jwt'})
        call('jwks_configuration', 'auth/federated/config', {'bound_issuer': issuer.origin,
             'jwks_url': issuer.origin+'/keys', 'jwks_ca_pem': (instance.root/'ca.crt').read_text(),
             'jwt_supported_algs': ['ES256']})
        call('role', 'auth/federated/role/test', {'role_type': 'jwt', 'user_claim': 'sub',
             'bound_audiences': ['heptabao-test'], 'token_policies': ['remote-batch'],
             'token_type': 'batch', 'token_ttl': 600, 'token_max_ttl': 600})
        assertion = remember(token(private, jwk, issuer.origin))
        def login(phase, assertion):
            preceding = len(issuer.calls)
            response = instance.call('POST', 'auth/federated/login', {'role': 'test', 'jwt': assertion}, token='')
            check(phase+'_jwks_fetched', issuer.calls[preceding:] == ['/keys'])
            return response
        start_second = int(time.time())
        status, logged = login('first', assertion)
        check('login', status == 200); check('batch_shape', batch_shape(logged))
        bearer = remember(logged['auth']['client_token'])
        verify_bearer(instance, bearer, value, 'immediate', check)
        local = call('local_batch_issued', 'auth/token/create-orphan',
                     {'type': 'batch', 'policies': ['remote-batch'], 'ttl': 600}, expected=200)
        local_bearer = remember(local['auth']['client_token'])
        local_status, local_body = instance.call('GET', 'batch-values/value', token=local_bearer)
        check('local_batch_usable', local_status == 200 and local['auth'].get('token_type') == 'batch'
              and local_body.get('data') == value)
        observations['immediate_chain_same_integer_second'] = start_second == int(time.time())
        status, repeated = login('reused', assertion)
        check('reused_login', status == 200 and batch_shape(repeated))
        repeated_bearer = remember(repeated['auth']['client_token'])
        check('fresh_bearer', repeated_bearer != bearer)
        issuer.mode = 'unavailable'
        status, body = login('unavailable', assertion); check('unavailable_denied', denied(status, body, 503))
        verify_bearer(instance, bearer, value, 'remote_unavailable', check)
        issuer.mode = 'normal'; issuer.documents['/keys'] = {'keys': [other_jwk]}
        status, body = login('removed', assertion); check('removed_key_denied', denied(status, body))
        verify_bearer(instance, bearer, value, 'key_removed', check)
        rotated_assertion = remember(token(other_private, other_jwk, issuer.origin))
        status, rotated = login('rotation', rotated_assertion)
        check('rotated_login', status == 200); check('rotated_batch_shape', batch_shape(rotated))
        remember(rotated['auth']['client_token'])
        verify_bearer(instance, bearer, value, 'rotated', check)
        call('role_deleted', 'auth/federated/role/test', method='DELETE')
        verify_bearer(instance, bearer, value, 'role_deleted', check)
        call('mount_deleted', 'sys/auth/federated', method='DELETE')
        verify_bearer(instance, bearer, value, 'mount_deleted', check)
        instance.stop(); instance.start()
        check('restart_unsealed', instance.call('POST', 'sys/unseal', {'key': share})[0] == 200)
        verify_bearer(instance, bearer, value, 'restarted', check)
        observations['jwks_http_calls'] = len(issuer.calls)
    finally:
        try:
            if instance is not None: instance.stop()
        finally:
            if issuer is not None: issuer.close()
    check('processes_stopped', instance.process is None and not issuer.thread.is_alive())
    paths = list((instance.root/'data').rglob('*')) + [instance.root/'audit.jsonl', instance.root/'server.log']
    check('plaintext_absent', bool(samples) and all(not contains_any(path, samples) for path in paths if path.is_file()))
    check('complete', True)


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--expected-binary-sha256', required=True)
    parser.add_argument('--build-source-commit', required=True)
    parser.add_argument('--work-parent', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{64}', args.expected_binary_sha256) or not re.fullmatch('[0-9a-f]{40}', args.build_source_commit):
        parser.error('invalid_input_identity')
    binary = args.binary.resolve(strict=True)
    if file_hash(binary) != args.expected_binary_sha256: parser.error('candidate_binary_mismatch')
    output = args.output.absolute(); admitted = admit_output(output)
    parent = private_parent(args.work_parent)
    before = source_identity(ROOT, binary)
    runner_hash, helper_hashes = file_hash(Path(__file__)), helpers()
    if before['source_dirty']: parser.error('source_dirty')
    work = Path(tempfile.mkdtemp(prefix='jwt-remote-batch-', dir=parent)); work.chmod(0o700)
    rows, observations, failure = [], {}, None
    def interrupted(signum, frame): raise Failure('fixture_interrupted')
    handlers = {kind: signal.signal(kind, interrupted) for kind in (signal.SIGTERM, signal.SIGINT)}
    try: run(binary, work, rows, observations)
    except Exception as error:
        failure = next((r['case'] for r in reversed(rows) if r['passed'] is not True), 'fixture_'+type(error).__name__)
    finally:
        for kind, handler in handlers.items(): signal.signal(kind, handler)
    after = source_identity(ROOT, binary)
    source_ok = before == after and not after['source_dirty']
    runner_ok, helpers_ok = file_hash(Path(__file__)) == runner_hash, helpers() == helper_hashes
    if not source_ok or not runner_ok or not helpers_ok: failure = 'inputs_changed'
    if not complete(rows): failure = failure or 'incomplete_observations'
    report = {'schema': 'heptabao.jwt-remote-batch-live.v1', 'status': 'failed' if failure else 'passed',
        'failure': failure, 'checks': rows, 'observations': observations, 'source_identity': before,
        'source_identity_after': after, 'source_and_binary_unchanged': source_ok,
        'build_source_commit': args.build_source_commit, 'build_source_identity': 'caller_supplied',
        'runner_sha256': runner_hash, 'runner_unchanged': runner_ok,
        'helper_sha256': helper_hashes, 'helpers_unchanged': helpers_ok,
        'retained_failure_work_dir': str(work) if failure else None, 'synthetic_only': True,
        'mutation_retries': 0, 'single_candidate': True, 'official_differential': False,
        'browser_oidc': False, 'ha_covered': False, 'independent_qualification': False,
        'full_openbao_compatibility': False}
    if admit_output(output) != admitted: raise ValueError('report_parent_changed')
    private_write(output, report, replace=False)
    if failure is None: shutil.rmtree(work)
    print(json.dumps({'status': report['status'], 'checks': len(rows), 'failure': failure}))
    return int(failure is not None)

if __name__ == '__main__': raise SystemExit(main())
