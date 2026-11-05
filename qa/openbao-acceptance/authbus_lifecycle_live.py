#!/usr/bin/env python3
"""Actual formal-V6 HeptaBao process with isolated TLS/AppRole client recovery.

Only new fixture credentials are used. Real lease expiry, two cold server
restarts, client process exits, self-revocation and a lost real renewal reply
are observed. Provider validity, live-client cutover and full replacement remain
outside this test. Private fixture state is retained for inspection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import uuid

import owned_process
from cert_auth_live import cert_sha256
from native_v6_authbus_client_live import CanaryFailure, private, sha, smoke

REPO = Path(__file__).resolve().parents[2]
TRANSPORT = REPO / 'tools/authbus/production-transport'
CHILD = TRANSPORT / 'tests/lifecycle-live-child.mjs'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def run(args, report):
    root = args.work_dir
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name in ('credentials', 'client-state', 'unknown-client-state'):
        (root / name).mkdir(mode=0o700)
    started = time.monotonic()
    instance = None
    sensitive, logs = [], []
    source_files = [TRANSPORT / ('plugin/' + name + '.js') for name in
                    ('strict-bao-client', 'production-client', 'bounded-outbox', 'private-outbox-store')]
    source_files += [CHILD, Path(__file__)]
    report.update(binary_sha256=sha(args.binary), checks=[], phases=[], server_restarts=[],
                  source_files={str(path.relative_to(REPO)): sha(path) for path in source_files},
                  node_version=subprocess.check_output([args.node, '--version'], text=True).strip())

    def check(name, condition, **detail):
        report['checks'].append({'case': name, 'passed': bool(condition), **detail})
        if not condition:
            raise CanaryFailure(name)

    def call(name, method, route, body=None, *, token=None, expected=200):
        status, value = instance.call(method, route, body, token=token)
        check(name, status == expected, status=status, expected=expected)
        return value

    def child(phase):
        result = owned_process.run([args.node, str(CHILD), str(root / 'client.private.json'), phase],
                                   capture_output=True, timeout=90, label='lifecycle.' + phase)
        logs.extend((result.stdout, result.stderr))
        private(root / (phase + '.stdout'), result.stdout)
        private(root / (phase + '.stderr'), result.stderr)
        try:
            value = json.loads(result.stdout)
        except ValueError:
            value = {'ok': False, 'error': 'child_public_result_invalid'}
        report['phases'].append(value)
        check(phase + '.exit', result.returncode == 0, exit_code=result.returncode)
        check(phase + '.ok', value.get('ok') is True)
        return value

    def stop(name):
        original = instance.process
        instance.stop()
        check(name + '.original_wait', original.returncode == -9)
        report['server_restarts'].append({'case': name, 'original_pid': original.pid, 'exit_code': original.returncode})

    def start(name):
        instance.start()
        call(name + '.sealed', 'GET', 'sys/health', expected=503)
        call(name + '.unseal', 'POST', 'sys/unseal', {'key': unseal}, token='')
        capacity = call(name + '.capacity', 'GET', 'sys/internal/capacity')['data']
        check(name + '.formal_profile_persisted', capacity.get('native_kv2_reader_format') == 2)

    try:
        instance = smoke.Instance(args.binary.resolve(strict=True), root / 'server')
        config_path = instance.root / 'server.json'
        config = json.loads(config_path.read_text())
        config['storage'] = {'native_v6_file': {'path': config['data_dir']}}
        private(config_path, json.dumps(config), replace=True)
        instance.start()
        init = call('initialize', 'POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1}, token='')
        instance.token, unseal = init['root_token'], init['keys_base64'][0]
        sensitive.extend((instance.token, unseal))
        private(root / 'recovery.private.json', json.dumps({'root_token': instance.token, 'unseal_key': unseal}))
        call('unseal', 'POST', 'sys/unseal', {'key': unseal}, token='')
        call('mount', 'POST', 'sys/mounts/openclaw-auth', {'type': 'kv', 'options': {'version': '2'}}, expected=204)
        call('approle_mount', 'POST', 'sys/auth/approle', {'type': 'approle'}, expected=204)
        call('formal_activation', 'POST', 'sys/storage/native-v6/activate', {}, expected=204)
        capacity = call('capacity', 'GET', 'sys/internal/capacity')['data']
        check('formal_native_v6', capacity.get('native_kv2_reader_format') == 2)
        owner, epoch = str(uuid.uuid4()), str(uuid.uuid4())
        control = {'schema': 'heptabao-authbus-fixed-slots-v1.control', 'ownerId': owner,
                   'retainedSlotVersions': 2, 'bootstrapProfileCount': 1,
                   'topology': [{'host_id': 'fixture-host', 'epoch': epoch, 'slots': 1, 'agents': ['main']}]}
        credential = {'provider': 'synthetic', 'type': 'api_key', 'key': secrets.token_urlsafe(32)}
        sensitive.append(credential['key'])
        profile = {'schemaVersion': 1, 'profileId': 'synthetic:lifecycle', 'credential': credential,
                   'digest': digest(credential), 'identity': digest({key: credential.get(key) for key in
                                                                  ('provider', 'type', 'email', 'accountId', 'projectId')})}
        profile_key = 'sha256-' + digest(profile)
        manifest = {'schemaVersion': 1, 'generation': 0,
                    'profiles': [{'profileId': profile['profileId'], 'key': profile_key, 'digest': profile['digest']}],
                    'coordinator': {'protocol': 'heptabao-authbus-coordinator-v1', 'ownerId': owner,
                                    'authorizations': [], 'lastReceipt': None}}
        for key, value in [('transport-v1/control', control), ('manifest', manifest), ('profiles/' + profile_key, profile)]:
            call('seed.' + key.split('/')[0], 'POST', 'openclaw-auth/data/' + key,
                 {'data': value, 'options': {'cas': 0}})
        policy = '''path "openclaw-auth/data/lifecycle/*" { capabilities=["create","read","update"] }
path "openclaw-auth/data/transport-v1/control" { capabilities=["read"] }
path "openclaw-auth/data/manifest" { capabilities=["read"] }
path "auth/token/renew-self" { capabilities=["update"] }
path "auth/token/revoke-self" { capabilities=["update"] }
path "auth/token/lookup-self" { capabilities=["read"] }'''
        call('policy', 'PUT', 'sys/policies/acl/lifecycle', {'policy': policy}, expected=204)
        call('role', 'POST', 'auth/approle/role/lifecycle', {'token_policies': ['lifecycle'],
             'token_ttl': '10s', 'token_max_ttl': '60s', 'secret_id_num_uses': 0, 'secret_id_ttl': '600s'}, expected=204)
        role_id = call('role_id', 'GET', 'auth/approle/role/lifecycle/role-id')['data']['role_id']
        sid = call('secret_id', 'POST', 'auth/approle/role/lifecycle/secret-id', {})['data']['secret_id']
        sensitive.extend((role_id, sid))
        credentials = root / 'credentials'
        private(credentials / 'role_id', role_id)
        private(credentials / 'secret_id', sid)
        private(credentials / 'ca.crt', (instance.root / 'ca.crt').read_bytes())
        synthetic_value = 'synthetic-lifecycle-' + secrets.token_hex(24)
        sensitive.append(synthetic_value)
        pin = cert_sha256(instance.root / 'tls.crt')
        client = {'address': instance.address, 'caFile': str(credentials / 'ca.crt'),
                  'roleIdFile': str(credentials / 'role_id'), 'secretIdFile': str(credentials / 'secret_id'),
                  'serverCertificateSha256': pin, 'hostId': 'fixture-host', 'tokenTtlSeconds': 10,
                  'stateRoot': str(root / 'client-state'), 'unknownStateRoot': str(root / 'unknown-client-state'),
                  'serverLog': str(instance.root / 'server.log'), 'syntheticValue': synthetic_value,
                  'revokedWitnessFile': str(root / 'revoked-bearer.private.json'),
                  'productionTransport': {'schema': 'heptabao-authbus-fixed-slots-v1', 'production': True,
                                          'epoch': epoch, 'slots': 1, 'agents': ['main'],
                                          'controlDigest': digest(control), 'serverCertificateSha256': pin}}
        private(root / 'client.private.json', json.dumps(client))
        initial = child('initial')
        stop('lease_expiry')
        wait_seconds = max(0, initial['expiresAtUnixMs'] / 1000 - time.time()) + 0.25
        check('actual_lease_wait_is_bounded', wait_seconds <= 11, wait_seconds=round(wait_seconds, 3))
        time.sleep(wait_seconds)
        report['real_lease_expiry_waited'] = True
        report['renewal_due_clock_forced'] = False
        start('expired_cold_restart')
        child('resume')
        stop('revocation')
        start('revoked_cold_restart')
        child('after-revoke')
        child('unknown-renewal')
        check('source_unchanged', all(sha(path) == report['source_files'][str(path.relative_to(REPO))] for path in source_files))
        check('binary_unchanged', sha(args.binary) == report['binary_sha256'])
        public = json.dumps(report).encode() + b''.join(logs) + (instance.root / 'server.log').read_bytes()
        check('diagnostics_no_fixture_credential_values', all(secret.encode() not in public for secret in sensitive))
        report.update(ok=True, actual_https_approle_kv2_policy_renewal_self_revocation=True,
                      actual_cold_service_restarts=2, actual_new_client_process_each_phase=True,
                      actual_renewal_response_dropped=True, fixture_server_flags=False,
                      storage_profile='native_v6_file', elapsed_seconds=round(time.monotonic() - started, 3))
    finally:
        if instance is not None and instance.process is not None:
            original = instance.process
            instance.stop()
            report['final_server_exit_code'] = original.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--node', default='node')
    args = parser.parse_args()
    os.umask(0o077)
    report = {'schema': 'heptabao.authbus-lifecycle-live.v1', 'ok': False,
              'real_heptabao_server': True, 'provider_called': False, 'real_provider_credentials': False,
              'j3160_contacted': False, 'production_cutover': False, 'production_changed': False,
              'full_replacement_qualified': False}
    try:
        run(args, report)
    except Exception as exc:
        report['error'] = str(exc) if isinstance(exc, CanaryFailure) else type(exc).__name__
    if args.work_dir.is_dir():
        private(args.work_dir / 'result.public.json', json.dumps(report, indent=2, sort_keys=True))
    print(json.dumps({'ok': report['ok'], 'checks': len(report.get('checks', [])),
                      'error': report.get('error'), 'result': str(args.work_dir / 'result.public.json')}))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
