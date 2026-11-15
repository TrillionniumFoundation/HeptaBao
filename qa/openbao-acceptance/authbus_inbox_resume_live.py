#!/usr/bin/env python3
"""Continue a stopped, private long-inbox fixture without rebuilding its data.

This deliberately reports a continuation, not an uninterrupted run within the
original budget. It authenticates the existing fixture with its retained private
recovery material and relies on immutable receipt identities, never the scan
cursor, to establish previously completed report work.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import urlsplit
import urllib.request
import uuid

from authbus_inbox_pagination_live import CENTRAL, MOUNT, central
from native_v6_authbus_client_live import CanaryFailure, private, sha, smoke
from cert_auth_live import cert_sha256
import owned_process


def run(args, report):
    root = args.work_dir.resolve(strict=True)
    central.owned_directory(root)
    central.owned_directory(root / 'server')
    config = central.load_config(root / 'config.private.json')
    recovery = json.loads(central.read_private(root / 'recovery.private.json'))
    server_config = json.loads(central.read_private(root / 'server/server.json'))
    endpoint = urlsplit(config['address'])
    central.require(endpoint.scheme == 'https' and endpoint.hostname == '127.0.0.1' and endpoint.port
                    and server_config['listen'] == '127.0.0.1:' + str(endpoint.port)
                    and server_config['storage'] == {'native_v6_file': {'path': str(root / 'server/data')}}
                    and server_config['data_dir'] == str(root / 'server/data')
                    and config['state_dir'] == str(root / 'state')
                    and config['source_hosts'] == ['producer', 'follower'], 'resume_fixture_binding')
    with socket.socket() as probe:
        probe.settimeout(1)
        central.require(probe.connect_ex(('127.0.0.1', endpoint.port)) != 0,
                        'original_fixture_listener_still_running')
    output = root / args.run_name
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    report.update(binary_sha256=sha(args.binary), central_source_sha256=sha(CENTRAL),
                  driver_sha256=sha(__file__), original_fixture=str(root), checks=[], cycles=[], server_restarts=[])
    central.require(report['binary_sha256'] == args.binary_sha256
                    and report['central_source_sha256'] == args.central_sha256, 'resume_exact_source_binding')
    instance = object.__new__(smoke.Instance)
    instance.root, instance.binary = root / 'server', args.binary.resolve(strict=True)
    instance.port, instance.address = endpoint.port, config['address']
    instance.context = ssl.create_default_context(cafile=str(instance.root / 'ca.crt'))
    instance.context.minimum_version = ssl.TLSVersion.TLSv1_2
    instance.client = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                        urllib.request.HTTPSHandler(context=instance.context))
    instance.token, instance.process = recovery['root_token'], None
    sensitive = [recovery['root_token'], recovery['unseal_key']]
    logs = []
    started = time.monotonic()

    def check(name, condition, **metadata):
        report['checks'].append({'case': name, 'passed': bool(condition), **metadata})
        if not condition:
            raise CanaryFailure(name)

    def call(name, method, path, body=None, *, token=None, expected=200):
        status, value = instance.call(method, path, body, token=token)
        check(name, status == expected, status=status, expected=expected)
        return value

    expected_reports = {central.receipt_key('producer', str(uuid.UUID(int=number))).split('/')[-1]
                        for number in [1, *range(100, 100 + args.events)]}
    credential_receipt = central.receipt_key('follower', str(uuid.UUID(int=2))).split('/')[-1]

    def report_receipts(name):
        # A fixture verifier reads only bounded synthetic receipt names. The
        # subject coordinator still uses its positive-limit pages exclusively.
        value = call(name, 'LIST', MOUNT + '/metadata/coordinator-receipts')['data']['keys']
        check(name + '.declared_identities', isinstance(value, list) and len(value) == len(set(value))
              and set(value) <= expected_reports | {credential_receipt})
        return set(value) & expected_reports

    def cycle(name):
        result = owned_process.run([sys.executable, str(CENTRAL), 'once', '--config', str(root / 'config.private.json')],
                                   capture_output=True, timeout=300, label='inbox-resume.' + name)
        logs.extend((result.stdout, result.stderr))
        check(name + '.exit', result.returncode == 0, exit_code=result.returncode)
        value = json.loads(result.stdout)
        check(name + '.bounded', value.get('ok') is True and value['scanned'] <= 32 and value['list_requests'] <= 2)
        report['cycles'].append(value)
        private(output / 'progress.public.json', json.dumps(report, sort_keys=True), replace=True)
        return value

    def restart(name):
        original = instance.process
        instance.stop()
        check(name + '.original_wait', original.returncode == -9)
        report['server_restarts'].append({'case': name, 'original_pid': original.pid, 'exit_code': original.returncode})
        instance.start()
        call(name + '.sealed', 'GET', 'sys/health', expected=503)
        call(name + '.unseal', 'POST', 'sys/unseal', {'key': recovery['unseal_key']}, token='')

    try:
        check('same_server_certificate', cert_sha256(instance.root / 'tls.crt') == config['server_certificate_sha256'])
        instance.start()
        call('initial_sealed', 'GET', 'sys/health', expected=503)
        call('initial_unseal', 'POST', 'sys/unseal', {'key': recovery['unseal_key']}, token='')
        capacity = call('formal_capacity', 'GET', 'sys/internal/capacity')['data']
        check('formal_native_v6', capacity.get('native_kv2_reader_format') == 2)
        keys = call('original_inbox_retained', 'LIST', MOUNT + '/metadata/inbox/producer')['data']['keys']
        expected_ids = {str(uuid.UUID(int=number)) for number in [1, *range(100, 100 + args.events)]}
        check('original_inbox_identity_set', set(keys) == expected_ids and len(keys) == len(expected_ids))
        completed = report_receipts('existing_receipt_identity_set')
        report['initial_receipt_identities'] = len(completed)
        report['initial_cursor_used_as_commit_evidence'] = False
        observed = len(completed)
        for index in range(args.events // 8 + 20):
            if observed == len(expected_reports):
                break
            result = cycle('page_' + str(index))
            check('revoked_grant_not_published.' + str(index), result['committed'] == 0)
            observed += result['observed_reports']
        check('all_report_identities_confirmed', report_receipts('final_receipt_identity_set') == expected_reports)
        client = central.Bao(config)
        worker = central.Coordinator(client, config['state_dir'], config['owner_id'], config['source_hosts'])
        event_row = client.read('inbox/follower/' + str(uuid.UUID(int=2)))
        check('original_follower_event_immutable', event_row is not None and event_row['version'] == 1)
        event = event_row['data']; central.parse_event('follower', event['eventId'], event)
        sensitive.append(event['credential']['key'])
        before = client.read('manifest')
        check('revoked_transition_still_not_published', before['data']['profiles'] == []
              and before['data']['coordinator']['authorizations'] == [])
        grant = {'authorizationId': str(uuid.uuid4()), 'profileId': event['profileId'], 'sourceHost': 'follower',
                 'provider': event['credential']['provider'], 'identityDigest': event['identity'],
                 'expectedCurrentDigest': None, 'nextDigest': event['digest']}
        worker.authorize(grant)
        committed = 0
        for index in range(3):
            committed += cycle('authorized_' + str(index))['committed']
            if committed:
                break
        check('deferred_transition_committed_once', committed == 1)
        manifest = client.read('manifest')
        check('exact_canonical_digest', manifest['data']['generation'] == 1
              and manifest['data']['profiles'][0]['digest'] == event['digest'])
        receipt = client.read(central.receipt_key('follower', event['eventId']))
        check('original_receipt_binding', receipt['version'] == 1 and receipt['data']['eventDigest'] == central.digest(event))
        bearer = client.token
        client.deadline = time.monotonic() + 20
        client.ensure_token()
        check('real_renewal_same_bearer', client.token == bearer)
        sensitive.extend(client.secrets)
        call('writer_valid_before_acl_denial', 'GET', MOUNT + '/data/manifest', token=bearer)
        call('writer_cannot_delete_inbox', 'DELETE', MOUNT + '/metadata/inbox/producer/' + str(uuid.UUID(int=1)),
             token=bearer, expected=403)
        call('revoke_bearer', 'POST', 'auth/token/revoke', {'token': bearer}, expected=204)
        try:
            client.list('inbox/producer')
        except central.Error as exc:
            check('revoked_bearer_is_denial_not_empty_page', str(exc) == 'bao_authentication_or_acl_denied')
        else:
            check('revoked_bearer_is_denial_not_empty_page', False)
        sid = central.read_private(Path(config['secret_id_file'])).decode().strip()
        role_id = central.read_private(Path(config['role_id_file'])).decode().strip()
        sensitive.extend((sid, role_id))
        sid_data = call('retained_sid_lookup', 'POST', 'auth/approle/role/writer/secret-id/lookup', {'secret_id': sid})['data']
        call('revoke_retained_sid', 'POST', 'auth/approle/role/writer/secret-id-accessor/destroy',
             {'secret_id_accessor': sid_data['secret_id_accessor']}, expected=204)
        restart('revocation_cold_restart')
        call('bearer_revocation_persisted', 'GET', MOUNT + '/data/manifest', token=bearer, expected=403)
        call('sid_revocation_persisted', 'POST', 'auth/approle/login', {'role_id': role_id, 'secret_id': sid},
             token='', expected=400)
        check('reports_still_retained', report_receipts('post_restart_receipt_identity_set') == expected_reports)
        check('source_unchanged', sha(CENTRAL) == args.central_sha256)
        check('binary_unchanged', sha(args.binary) == args.binary_sha256)
        payload = json.dumps(report).encode() + b''.join(logs) + (instance.root / 'server.log').read_bytes()
        check('diagnostics_no_credentials', all(secret.encode() not in payload for secret in sensitive))
        report.update(ok=True, total_report_receipts=len(expected_reports),
                      additional_report_receipts=len(expected_reports) - report['initial_receipt_identities'],
                      max_events_per_cycle=max(row['scanned'] for row in report['cycles']),
                      actual_https_approle_kv2_policy_renewal_revocation=True,
                      actual_cold_service_restart=True, actual_new_coordinator_process_each_cycle=True,
                      elapsed_seconds=round(time.monotonic() - started, 3))
    finally:
        if instance.process is not None:
            original = instance.process
            instance.stop()
            report['final_server_exit_code'] = original.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--binary-sha256', required=True)
    parser.add_argument('--central-sha256', required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--run-name', required=True)
    parser.add_argument('--events', type=int, default=1057)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,40}', args.run_name) or not 1025 <= args.events <= 4096:
        parser.error('invalid fixed fixture bounds')
    os.umask(0o077)
    report = {'schema': 'heptabao.authbus-inbox-private-fixture-continuation.v1', 'ok': False,
              'original_uninterrupted_budget_passed': False, 'cycle_observation_timeout_seconds': 300,
              'production_changed': False,
              'production_cutover': False, 'full_replacement_qualified': False, 'provider_called': False,
              'j3160_contacted': False, 'real_provider_credentials': False, 'inbox_deletions': 0,
              'actual_sdk_qualified': False, 'renewal_due_clock_forced': True, 'real_lease_expiry_waited': False}
    try:
        run(args, report)
    except Exception as exc:
        report['error'] = str(exc) if isinstance(exc, (CanaryFailure, central.Error)) else type(exc).__name__
    output = args.work_dir / args.run_name
    if output.is_dir():
        private(output / 'result.public.json', json.dumps(report, indent=2, sort_keys=True))
    print(json.dumps({'ok': report['ok'], 'error': report.get('error'), 'checks': len(report.get('checks', []))}))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
