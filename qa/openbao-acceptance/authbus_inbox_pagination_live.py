#!/usr/bin/env python3
"""Bounded legacy-inbox scanning against a fresh formal V6 HTTPS service.

All credentials and events belong to this new private fixture. This exercises
the actual AppRole/TLS/KV2/ACL APIs and cold child processes, without contacting
a provider, production gateway, another host, or J3160.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import owned_process
from cert_auth_live import cert_sha256
from native_v6_authbus_client_live import CanaryFailure, private, sha, smoke

HERE = Path(__file__).resolve().parent
CENTRAL = HERE.parents[1] / 'tools/authbus/authbus_coordinator.py'
SPEC = importlib.util.spec_from_file_location('inbox_central', CENTRAL)
central = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(central)
MOUNT = 'openclaw-auth'


def run(args, report):
    root = args.work_dir
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name in ('writer', 'state'):
        (root / name).mkdir(mode=0o700)
    started = time.monotonic()
    instance = None
    sensitive, logs = [], []
    report.update(binary_sha256=sha(args.binary), central_source_sha256=sha(CENTRAL),
                  driver_sha256=sha(__file__), checks=[], cycles=[], server_restarts=[])

    def check(name, condition, **detail):
        report['checks'].append({'case': name, 'passed': bool(condition), **detail})
        if not condition:
            raise CanaryFailure(name)

    def call(name, method, path, body=None, *, token=None, expected=200):
        status, value = instance.call(method, path, body, token=token)
        check(name, status == expected, status=status, expected=expected)
        return value

    def command(name, action='once'):
        result = owned_process.run([sys.executable, str(CENTRAL), action, '--config', str(root / 'config.private.json')],
                                   capture_output=True, timeout=60, label='inbox.' + name)
        logs.extend((result.stdout, result.stderr))
        check(name + '.exit', result.returncode == 0, exit_code=result.returncode)
        value = json.loads(result.stdout)
        check(name + '.ok', value.get('ok') is True)
        if action == 'once':
            check(name + '.bounded', value['scanned'] <= central.MAX_SCAN_EVENTS and value['list_requests'] <= 2)
            report['cycles'].append(value)
        return value

    def role(name, policy):
        route = 'auth/approle/role/' + name
        call(name + '.policy', 'PUT', 'sys/policies/acl/' + name, {'policy': policy}, expected=204)
        call(name + '.role', 'POST', route, {'token_policies': [name], 'token_ttl': '1200s',
             'token_max_ttl': '1800s', 'secret_id_num_uses': 0, 'secret_id_ttl': '3600s'}, expected=204)
        role_id = call(name + '.role_id', 'GET', route + '/role-id')['data']['role_id']
        sid = call(name + '.secret_id', 'POST', route + '/secret-id', {})['data']
        sensitive.extend((role_id, sid['secret_id'], sid['secret_id_accessor']))
        return role_id, sid

    def restart(name):
        original = instance.process
        instance.stop()
        check(name + '.original_wait', original.returncode == -9)
        report['server_restarts'].append({'case': name, 'original_pid': original.pid, 'exit_code': original.returncode})
        instance.start()
        call(name + '.sealed', 'GET', 'sys/health', expected=503)
        call(name + '.unseal', 'POST', 'sys/unseal', {'key': unseal}, token='')

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
        call('mount', 'POST', 'sys/mounts/' + MOUNT, {'type': 'kv', 'options': {'version': '2'}}, expected=204)
        call('approle_mount', 'POST', 'sys/auth/approle', {'type': 'approle'}, expected=204)
        call('formal_activation', 'POST', 'sys/storage/native-v6/activate', {}, expected=204)
        capacity = call('capacity', 'GET', 'sys/internal/capacity')['data']
        check('formal_native_v6', capacity.get('native_kv2_reader_format') == 2)
        report['storage_profile'] = 'native_v6_file'
        report['fixture_server_flags'] = False
        writer_policy = f'''path "{MOUNT}/data/manifest" {{ capabilities=["create","read","update"] }}
path "{MOUNT}/data/profiles/*" {{ capabilities=["create","read"] }}
path "{MOUNT}/data/coordinator-receipts/*" {{ capabilities=["create","read"] }}
path "auth/token/renew-self" {{ capabilities=["update"] }}
path "auth/token/revoke-self" {{ capabilities=["update"] }}'''
        for host in ('producer', 'follower'):
            writer_policy += f'\npath "{MOUNT}/metadata/inbox/{host}" {{ capabilities=["list"] }}\npath "{MOUNT}/data/inbox/{host}/*" {{ capabilities=["read"] }}'
        writer_role, writer_sid = role('writer', writer_policy)
        writer_dir = root / 'writer'
        private(writer_dir / 'role_id', writer_role)
        private(writer_dir / 'secret_id', writer_sid['secret_id'])
        private(writer_dir / 'ca.crt', (instance.root / 'ca.crt').read_bytes())
        config = {'schema': central.PROTOCOL + '.config', 'address': instance.address,
                  'ca_file': str(writer_dir / 'ca.crt'), 'role_id_file': str(writer_dir / 'role_id'),
                  'secret_id_file': str(writer_dir / 'secret_id'),
                  'server_certificate_sha256': cert_sha256(instance.root / 'tls.crt'),
                  'state_dir': str(root / 'state'), 'owner_id': str(uuid.uuid4()),
                  'source_hosts': ['producer', 'follower'], 'production_cutover': False}
        private(root / 'config.private.json', json.dumps(config))
        tokens = {}
        for host in ('producer', 'follower'):
            policy = f'path "{MOUNT}/data/inbox/{host}/*" {{ capabilities=["create"] }}'
            role_id, sid = role(host, policy)
            auth = call(host + '.login', 'POST', 'auth/approle/login',
                        {'role_id': role_id, 'secret_id': sid['secret_id']}, token='')['auth']
            tokens[host] = auth['client_token']; sensitive.append(tokens[host])
        command('coordinator_initialize', 'initialize')
        for number in range(100, 100 + args.events):
            event = {'schemaVersion': 2, 'kind': 'agent-report', 'sourceHost': 'producer',
                     'eventId': str(uuid.UUID(int=number)), 'profiles': []}
            call('seed.' + str(number), 'POST', MOUNT + '/data/inbox/producer/' + event['eventId'],
                 {'data': event, 'options': {'cas': 0}}, token=tokens['producer'])
            if (number - 99) % 256 == 0:
                print(json.dumps({'stage': 'seeded', 'events': number - 99}), flush=True)
        credential = {'provider': 'synthetic', 'type': 'api_key', 'key': 'synthetic-inbox-credential-' + uuid.uuid4().hex}
        sensitive.append(credential['key'])
        event = {'schemaVersion': 1, 'eventId': str(uuid.UUID(int=2)), 'sourceHost': 'follower',
                 'reason': 'new-profile', 'profileId': 'synthetic:inbox', 'credential': credential,
                 'digest': central.digest(credential), 'identity': central.identity(credential)}
        call('follower.event', 'POST', MOUNT + '/data/inbox/follower/' + event['eventId'],
             {'data': event, 'options': {'cas': 0}}, token=tokens['follower'])
        client = central.Bao(config)
        worker = central.Coordinator(client, config['state_dir'], config['owner_id'], config['source_hosts'])
        grant = {'authorizationId': str(uuid.uuid4()), 'profileId': event['profileId'], 'sourceHost': 'follower',
                 'provider': credential['provider'], 'identityDigest': event['identity'],
                 'expectedCurrentDigest': None, 'nextDigest': event['digest']}
        worker.authorize(grant)
        worker.revoke_authorization(grant['authorizationId'])
        first = command('first_page')
        check('first_page.exact_bound', first['observed_reports'] == 32)
        saved_cursor = (root / 'state/inbox-scan.private.json').read_bytes()
        restart('after_first_page')
        check('cursor_survived_server_restart', (root / 'state/inbox-scan.private.json').read_bytes() == saved_cursor)
        # A newly inserted key sorts before the durable anchor. A later sweep
        # must still find it without clearing or rewriting the existing cursor.
        lower = {'schemaVersion': 2, 'kind': 'agent-report', 'sourceHost': 'producer',
                 'eventId': str(uuid.UUID(int=1)), 'profiles': []}
        call('lower_uuid_insert', 'POST', MOUNT + '/data/inbox/producer/' + lower['eventId'],
             {'data': lower, 'options': {'cas': 0}}, token=tokens['producer'])
        observed = first['observed_reports']
        for index in range(1, args.events // 16 + 10):
            value = command('page_' + str(index))
            observed += value['observed_reports']
            check('revoked_grant_not_published.' + str(index), value['committed'] == 0)
            if observed == args.events + 1:
                break
        check('all_reports_observed', observed == args.events + 1, observed=observed, expected=args.events + 1)
        check('follower_not_starved', any(row['deferred'] > 0 for row in report['cycles'][1:3]))
        # Resume the same service state and authorize the exact previously
        # deferred transition; page state must not consume that event.
        client = central.Bao(config)
        worker = central.Coordinator(client, config['state_dir'], config['owner_id'], config['source_hosts'])
        worker.authorize({**grant, 'authorizationId': str(uuid.uuid4())})
        committed = 0
        for index in range(3):
            committed += command('authorized_' + str(index))['committed']
            if committed:
                break
        check('later_authorized_exact_event_committed_once', committed == 1)
        manifest = client.read('manifest')
        check('canonical_credential_digest_exact', manifest['data']['profiles'][0]['digest'] == event['digest'])
        receipt = client.read(central.receipt_key('follower', event['eventId']))
        check('immutable_original_receipt', receipt['version'] == 1 and receipt['data']['eventDigest'] == central.digest(event))
        previous = client.token
        client.deadline = time.monotonic() + 20
        client.ensure_token()
        check('real_renew_self_same_bearer', client.token == previous)
        report['renewal_due_clock_forced'] = True
        report['real_lease_expiry_waited'] = False
        sensitive.extend(client.secrets)
        call('writer_valid_before_acl_check', 'GET', MOUNT + '/data/manifest', token=client.token)
        call('writer_cannot_delete_inbox', 'DELETE', MOUNT + '/metadata/inbox/producer/' + lower['eventId'],
             token=client.token, expected=403)
        call('producer_cannot_write_canonical', 'POST', MOUNT + '/data/manifest',
             {'data': {}, 'options': {'cas': manifest['version']}}, token=tokens['producer'], expected=403)
        call('inbox_retained_after_denial', 'GET', MOUNT + '/data/inbox/producer/' + lower['eventId'])
        # Revocation is observed through the same authenticated transport; an
        # authentication denial is never recast as an empty page.
        call('token_revoke', 'POST', 'auth/token/revoke', {'token': client.token}, expected=204)
        try:
            client.list('inbox/producer')
        except central.Error as exc:
            check('revoked_bearer_page_denied', str(exc) == 'bao_authentication_or_acl_denied')
        else:
            check('revoked_bearer_page_denied', False)
        call('sid_revoke', 'POST', 'auth/approle/role/writer/secret-id-accessor/destroy',
             {'secret_id_accessor': writer_sid['secret_id_accessor']}, expected=204)
        restart('revocations')
        call('revoked_bearer_persisted', 'GET', MOUNT + '/data/manifest', token=client.token, expected=403)
        call('revoked_sid_persisted', 'POST', 'auth/approle/login',
             {'role_id': writer_role, 'secret_id': writer_sid['secret_id']}, token='', expected=400)
        check('source_unchanged', sha(CENTRAL) == report['central_source_sha256'])
        check('binary_unchanged', sha(args.binary) == report['binary_sha256'])
        public = json.dumps(report).encode() + b''.join(logs) + (instance.root / 'server.log').read_bytes()
        check('diagnostics_no_credential_values', all(secret.encode() not in public for secret in sensitive))
        report.update(ok=True, reports_observed=observed, max_events_per_cycle=max(row['scanned'] for row in report['cycles']),
                      actual_https_approle_kv2_policy_renewal_revocation=True,
                      actual_cold_service_restart=True, actual_new_coordinator_process_each_cycle=True,
                      elapsed_seconds=round(time.monotonic() - started, 3))
    finally:
        if instance is not None and instance.process is not None:
            original = instance.process
            instance.stop()
            report['final_server_exit_code'] = original.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--events', type=int, default=1057)
    args = parser.parse_args()
    if not 1025 <= args.events <= 4096:
        parser.error('--events must be between 1025 and 4096')
    os.umask(0o077)
    report = {'schema': 'heptabao.authbus-inbox-paginated-live.v1', 'ok': False,
              'provider_called': False, 'real_provider_credentials': False, 'j3160_contacted': False,
              'production_cutover': False, 'production_changed': False, 'actual_sdk_qualified': False,
              'full_replacement_qualified': False, 'inbox_deletions': 0}
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
