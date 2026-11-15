#!/usr/bin/env python3
"""Real HTTPS qualification of the independent central AuthBus candidate.

Uses an owned new V6 server, unchanged production OpenClaw plugin copies and
actual SDK SQLite stores. Source provider credentials are synthetic; no provider
API, production gateway, old Bao or J3160 is contacted. The independent service
performs all successful profile/manifest credential publication.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import time
import uuid

import owned_process
from cert_auth_live import cert_sha256
from native_v6_authbus_client_live import CanaryFailure, NativeInstance, private, sha, value_sha
from native_v6_openclaw_authbus_live import FILES, mkdir, owned_private_json


HERE = Path(__file__).resolve().parent
MOUNT = 'openclaw-auth'
PRODUCER, FOLLOWER, WRITER = 'authbus-central-producer', 'authbus-central-follower', 'authbus-central-writer'
PROFILE = 'openai:authbus-central-a'
ORIGINAL_PLUGIN_SHA = 'b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b'


def import_central(path, expected):
    if path.is_symlink() or sha(path) != expected:
        raise CanaryFailure('central_source_fingerprint')
    spec = importlib.util.spec_from_file_location('actual_authbus_coordinator_candidate', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_worker(config_path):
    """Private QA adapter around the unchanged independent service module."""
    cfg = owned_private_json(config_path)
    root, output = Path(cfg['workRoot']), Path(cfg['runDir'])
    if not output.is_relative_to(root) or output.is_symlink() or stat.S_IMODE(output.stat().st_mode) != 0o700:
        raise CanaryFailure('worker_scope')
    central = import_central(Path(cfg['centralSource']), cfg['centralSourceSha256'])
    config = central.load_config(Path(cfg['centralConfig']))
    client = central.Bao(config)
    secondary = []
    report = {'schema': 'authbus-central-actual-worker-v1', 'ok': False,
              'action': cfg['action'], 'sourceSha256': cfg['centralSourceSha256'],
              'syntheticCredentialFixture': True, 'productionMutation': False}

    def capture():
        tokens = [item.token for item in [client, *secondary] if item.token is not None]
        private(output / 'tokens.private.json', json.dumps({'tokens': tokens}))

    def hook(phase):
        if cfg.get('fault') == 'cas_metadata_race' and phase == 'profile_confirmed':
            competitor = central.Bao(config); secondary.append(competitor)
            current = competitor.read('manifest')
            current['data']['coordinator']['fixtureOperatorRevision'] = current['version']
            competitor.write('manifest', current['data'], current['version'])
            report['actualCompetingManifestCas'] = True
        if cfg.get('fault') == 'crash_after_manifest_commit' and phase == 'manifest_committed_before_journal_reply':
            capture()
            private(output / 'receipt.json', json.dumps({**report, 'injectedProcessExit': 73,
                     'lastObservedPhase': phase, 'publicSuccessClaimed': False}))
            os._exit(73)

    worker = central.Coordinator(client, config['state_dir'], config['owner_id'], config['source_hosts'], hook)
    code = 2
    try:
        if cfg['action'] == 'initialize':
            result = worker.initialize()
        elif cfg['action'] == 'authorize':
            result = worker.authorize(cfg['authorization'])
        elif cfg['action'] == 'revoke-authorization':
            result = worker.revoke_authorization(cfg['authorizationId'])
        elif cfg['action'] == 'recover':
            with central.operation_lock(worker.state):
                result = {'recovered_pending': worker.recover_locked()}
                worker.finish_previous_receipt(worker.manifest())
        elif cfg['action'] == 'renew-due':
            client.ensure_token(); before = client.token
            client.deadline = time.monotonic() + 20
            client.ensure_token()
            result = {'actualRenewSelfSameBearer': client.token == before, 'forcedLocalDueClock': True,
                      'realLeaseExpiryWaited': False}
        elif cfg['action'] == 'once':
            result = worker.once()
        else:
            raise CanaryFailure('worker_action')
        report.update(ok=True, result=result); code = 0
    except central.Error as exc:
        report.update(error=str(exc), unknownOutcome=isinstance(exc, central.UnknownOutcome))
        code = 3 if isinstance(exc, central.UnknownOutcome) else 2
    finally:
        capture()
        payload = json.dumps(report)
        sensitive = client.secrets + worker.secrets + [v for item in secondary for v in item.secrets]
        if any(secret and secret in payload for secret in sensitive):
            raise CanaryFailure('worker_public_secret')
        private(output / 'receipt.json', payload)
    print(json.dumps(report, sort_keys=True))
    return code


def run(args, report):
    root = args.work_dir
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    if root.is_symlink() or stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise CanaryFailure('new_root_custody')
    report.update(checks=[], clients=[], central_actions=[], server_cycles=[],
                  binary_sha256=sha(args.binary), driver_sha256=sha(__file__),
                  consumer_sha256=sha(HERE / 'native_v6_authbus_coordinator_consumer.mjs'),
                  central_source_sha256=sha(args.central_source))
    confidential, issued, logs = [], [], []
    roles, states, bindings = {}, {}, {}
    instance = None
    credential_a = {'provider': 'openai', 'type': 'oauth',
                    'access': 'synthetic-authbus-central-' + secrets.token_hex(20),
                    'refresh': 'synthetic-authbus-central-' + secrets.token_hex(20),
                    'expires': int(time.time() * 1000) + 86400000,
                    'email': 'synthetic-authbus-central@example.invalid', 'accountId': 'synthetic-authbus-central-account'}
    credential_b = {**credential_a, 'access': 'synthetic-authbus-central-' + secrets.token_hex(20),
                    'refresh': 'synthetic-authbus-central-' + secrets.token_hex(20), 'expires': credential_a['expires'] + 3600000}
    for credential in (credential_a, credential_b):
        confidential.extend(credential[field] for field in ('access', 'refresh'))
    digest_a, digest_b = value_sha(credential_a), value_sha(credential_b)

    def check(name, condition, **metadata):
        report['checks'].append({'case': name, 'passed': bool(condition), **metadata})
        if not condition:
            raise CanaryFailure(name)

    def call(name, method, path, body=None, *, token=None, expected=200):
        status, value = instance.call(method, path, body, token=token)
        check(name, status == expected, status=status, expected=expected)
        return value

    def read_manifest(name):
        return call(name, 'GET', MOUNT + '/data/manifest')

    def entry_of(manifest):
        items = [item for item in manifest['data']['data']['profiles'] if item['profileId'] == PROFILE]
        check('manifest.exact_single_profile.' + str(len(report['checks'])), len(items) == 1)
        return items[0]

    def role(host, policy):
        route = 'auth/approle/role/' + host
        call(host + '.policy', 'PUT', 'sys/policies/acl/' + host, {'policy': policy}, expected=204)
        call(host + '.role', 'POST', route, {'token_policies': [host], 'token_ttl': '1200s', 'token_max_ttl': '1800s',
             'secret_id_num_uses': 0, 'secret_id_ttl': '3600s'}, expected=204)
        role_id = call(host + '.role_id', 'GET', route + '/role-id')['data']['role_id']
        sid = call(host + '.sid', 'POST', route + '/secret-id', {})['data']
        confidential.extend((role_id, sid['secret_id'], sid['secret_id_accessor']))
        directory = root / 'credentials' / host; mkdir(directory)
        private(directory / 'role_id', role_id); private(directory / 'secret_id', sid['secret_id'])
        private(directory / 'ca.crt', (instance.root / 'ca.crt').read_bytes())
        roles[host] = {'role': route, **sid}
        return directory

    def prepare_state(host, credential_dir, leader=False):
        state = root / host; agent = state / 'agents/main/agent'
        for directory in (state, state / 'agents', state / 'agents/main', agent, state / 'home', state / 'credentials'):
            mkdir(directory)
        private(state / 'openclaw.json', json.dumps({'agents': {'list': [{'id': 'main', 'default': True, 'agentDir': str(agent)}]}}))
        binding = {'address': instance.address, 'caFile': str(credential_dir / 'ca.crt'),
                   'roleIdFile': str(credential_dir / 'role_id'), 'secretIdFile': str(credential_dir / 'secret_id'),
                   'hostId': PRODUCER if leader else FOLLOWER, 'leader': leader, 'publishNew': True, 'manageOrder': True,
                   'releaseGeneration': 201, 'pollIntervalMs': 15000, 'refreshMarginMs': 900000, 'maxRefreshesPerCycle': 1}
        binding_path = root / (host + '-binding.private.json'); private(binding_path, json.dumps(binding))
        states[host], bindings[host] = (state, agent), binding_path

    def collect_process(name, argv, run_dir, expected):
        result = owned_process.run(argv, cwd=root, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   timeout=75, label='authbus-coordinator.' + name)
        for filename, data in (('stdout.log', result.stdout), ('stderr.log', result.stderr)):
            private(run_dir / filename, data); logs.append(run_dir / filename)
        capture_path = run_dir / 'tokens.private.json'
        if capture_path.exists():
            for item in owned_private_json(capture_path).get('tokens', []):
                token = item.get('token') if isinstance(item, dict) else item
                check(name + '.captured_actual_token', isinstance(token, str) and len(token) >= 8)
                confidential.append(token); issued.append(token)
        check(name + '.private_diagnostics', all(secret.encode() not in result.stdout + result.stderr for secret in confidential))
        receipt = owned_private_json(run_dir / 'receipt.json')
        check(name + '.private_public_receipt', all(secret not in json.dumps(receipt) for secret in confidential))
        check(name + '.exit', result.returncode == expected, actual=result.returncode, expected=expected)
        return receipt

    def central_action(name, action='once', expected=0, **extra):
        run_dir = root / 'runs' / name; mkdir(run_dir)
        cfg = {'workRoot': str(root), 'runDir': str(run_dir), 'centralSource': str(root / 'authbus_coordinator.py'),
               'centralSourceSha256': report['central_source_sha256'], 'centralConfig': str(root / 'central-config.private.json'),
               'action': action, **extra}
        path = run_dir / 'worker.private.json'; private(path, json.dumps(cfg))
        result = collect_process(name, [sys.executable, str(Path(__file__).resolve()), '--worker', str(path)], run_dir, expected)
        report['central_actions'].append({'case': name, **result})
        if expected == 0:
            check(name + '.service_ok', result.get('ok') is True)
        return result

    def client(name, host, steps=None, expected=0):
        state, agent = states[host]
        run_dir = root / 'runs' / name; mkdir(run_dir)
        cfg = {'schema': 'authbus-central-client-driver-v1', 'workRoot': str(root), 'stateDir': str(state), 'agentDir': str(agent),
               'runDir': str(run_dir), 'homeDir': str(state / 'home'), 'oauthDir': str(state / 'credentials'),
               'configPath': str(state / 'openclaw.json'), 'openclawRoot': str(args.openclaw_root),
               'pluginEntry': str(root / 'plugin/index.js'), 'pluginConfig': owned_private_json(bindings[host]),
               'capturePath': str(run_dir / 'tokens.private.json'), 'receiptPath': str(run_dir / 'receipt.json'),
               'serverCertificateSha256': report['server_cert_der_sha256'], 'steps': steps or [{}]}
        path = run_dir / 'client.private.json'; private(path, json.dumps(cfg))
        result = collect_process(name, [str(args.node), str(HERE / 'native_v6_authbus_coordinator_consumer.mjs'), str(path)], run_dir, expected)
        report['clients'].append({'case': name, **result})
        check(name + '.actual_default_scope', result.get('defaultAgentScoped') is True)
        if expected == 0:
            check(name + '.actual_original_plugin_ok', result.get('ok') is True)
            check(name + '.actual_approle_login', result.get('authentications') == 1)
            observations = result['observations']
            check(name + '.real_full_tls', bool(observations) and all(item.get('tlsAuthorized') is True
                  and item.get('peerCertificateSha256') == report['server_cert_der_sha256']
                  and item.get('isSessionReused') is False for item in observations))
            check(name + '.actual_default_shadow', all(cycle['plugin'].get('schedulerMode') == 'shadow'
                  and cycle['plugin'].get('strictLeaseAssignments') == 0 for cycle in result['cycles']))
        return result

    def grant(credential, previous):
        return {'authorizationId': str(uuid.uuid4()), 'profileId': PROFILE, 'sourceHost': PRODUCER,
                'provider': credential['provider'], 'identityDigest': value_sha({key: credential.get(key)
                    for key in ('provider', 'type', 'email', 'accountId', 'projectId')}),
                'expectedCurrentDigest': previous, 'nextDigest': value_sha(credential)}

    def restart(name):
        old = instance.process; instance.stop()
        report['server_cycles'].append({'case': name, 'original_pid': old.pid, 'exit_code': old.returncode, 'method': 'SIGKILL'})
        check(name + '.binary_unchanged', sha(args.binary) == report['binary_sha256'])
        instance.start()
        call(name + '.sealed', 'GET', 'sys/health', expected=503)
        call(name + '.unseal', 'POST', 'sys/unseal', {'key': unseal}, token='')
        capacity = call(name + '.capacity', 'GET', 'sys/internal/capacity')['data']
        check(name + '.native_v6', capacity.get('native_kv2_reader_format') == 2)

    environment = dict(os.environ)
    for name in ('GOOGLE_API_KEY', 'GEMINI_API_KEY', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'OPENCLAW_GATEWAY_TOKEN', 'NODE_OPTIONS', 'NODE_PATH', 'PYTHONPATH'):
        environment.pop(name, None)
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    try:
        for directory in (root / 'plugin', root / 'node_modules', root / 'credentials', root / 'runs', root / 'central-state'):
            mkdir(directory)
        private(root / 'authbus_coordinator.py', args.central_source.read_bytes())
        report['plugin_source_sha256'] = {}
        for name in FILES:
            source = args.plugin_root / name
            check('original_plugin.' + name, source.is_file() and not source.is_symlink() and source.stat().st_size <= 262144)
            report['plugin_source_sha256'][name] = sha(source); private(root / 'plugin' / name, source.read_bytes())
        check('original_plugin.expected_main_version', report['plugin_source_sha256']['index.js'] == ORIGINAL_PLUGIN_SHA)
        private(root / 'plugin/package.json', json.dumps({'type': 'module', 'private': True}))
        (root / 'node_modules/openclaw').symlink_to(args.openclaw_root, target_is_directory=True)
        instance = NativeInstance(args.binary, root / 'server')
        report['server_cert_der_sha256'] = cert_sha256(instance.root / 'tls.crt'); instance.start()
        init = call('server.init', 'POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1}, token='')
        instance.token, unseal = init['root_token'], init['keys_base64'][0]
        confidential.extend((instance.token, unseal))
        private(root / 'recovery.private.json', json.dumps({'root_token': instance.token, 'unseal_key': unseal}))
        call('server.unseal', 'POST', 'sys/unseal', {'key': unseal}, token='')
        call('server.mount', 'POST', 'sys/mounts/' + MOUNT, {'type': 'kv', 'options': {'version': '2'}}, expected=204)
        call('server.activate_native', 'POST', 'sys/internal/native-v6/activate', {}, expected=204)
        capacity = call('server.capacity', 'GET', 'sys/internal/capacity')['data']
        check('server.native_format2', capacity.get('native_kv2_reader_format') == 2)
        call('server.approle_mount', 'POST', 'sys/auth/approle', {'type': 'approle'}, expected=204)
        for key, data in [('order-policy', {'schemaVersion': 1, 'generation': 0, 'providers': {}}),
                          ('scheduler-assignments', {'schemaVersion': 1, 'generation': 0, 'scopes': [], 'assignments': [], 'refreshLeases': []})]:
            call('bootstrap.empty.' + key, 'POST', MOUNT + '/data/' + key, {'data': data, 'options': {'cas': 0}})
        for host in (PRODUCER, FOLLOWER):
            policy = f'''path "{MOUNT}/data/manifest" {{ capabilities=["read"] }}
path "{MOUNT}/data/profiles/*" {{ capabilities=["read"] }}
path "{MOUNT}/data/order-policy" {{ capabilities=["read"] }}
path "{MOUNT}/data/scheduler-assignments" {{ capabilities=["read"] }}
path "{MOUNT}/data/inbox/{host}/*" {{ capabilities=["create"] }}
path "auth/token/renew-self" {{ capabilities=["update"] }}
path "auth/token/revoke-self" {{ capabilities=["update"] }}'''
            credential_dir = role(host, policy); prepare_state(host, credential_dir, leader=host == PRODUCER)
        writer_policy = f'''path "{MOUNT}/data/manifest" {{ capabilities=["create","read","update"] }}
path "{MOUNT}/data/profiles/*" {{ capabilities=["create","read"] }}
path "{MOUNT}/data/coordinator-receipts/*" {{ capabilities=["create","read"] }}
path "auth/token/renew-self" {{ capabilities=["update"] }}
path "auth/token/revoke-self" {{ capabilities=["update"] }}'''
        for host in (PRODUCER, FOLLOWER):
            writer_policy += f'\npath "{MOUNT}/metadata/inbox/{host}" {{ capabilities=["list"] }}\npath "{MOUNT}/data/inbox/{host}/*" {{ capabilities=["read"] }}'
        credential_dir = role(WRITER, writer_policy)
        config = {'schema': 'heptabao-authbus-coordinator-v1.config', 'address': instance.address,
                  'ca_file': str(credential_dir / 'ca.crt'), 'role_id_file': str(credential_dir / 'role_id'),
                  'secret_id_file': str(credential_dir / 'secret_id'), 'server_certificate_sha256': report['server_cert_der_sha256'],
                  'state_dir': str(root / 'central-state'), 'owner_id': str(uuid.uuid4()),
                  'source_hosts': [PRODUCER, FOLLOWER], 'production_cutover': False}
        private(root / 'central-config.private.json', json.dumps(config))
        central_action('central_initialize', 'initialize')
        published = client('original_producer_new_event', PRODUCER, [{}, {'upserts': [{'profileId': PROFILE, 'credential': credential_a}]}])
        check('original_producer.leader_flag_is_true', all(cycle['plugin'].get('leader') is True for cycle in published['cycles']))
        check('original_producer.baseline_then_new_event', [cycle['plugin'].get('publishedEvents') for cycle in published['cycles']] == [0, 1])
        deferred = central_action('central_requires_operator')
        check('central.no_implicit_source_authority', deferred['result']['committed'] == 0 and deferred['result']['deferred'] == 1)
        check('central.no_implicit_publication', read_manifest('manifest_before_authorization')['data']['data']['profiles'] == [])
        central_action('operator_authorize_a', 'authorize', authorization=grant(credential_a, None))
        committed = central_action('central_publish_a')
        check('central.actual_service_published_a', committed['result']['committed'] == 1)
        manifest_a = read_manifest('canonical_a'); entry_a = entry_of(manifest_a)
        payload_a = call('immutable_a_read', 'GET', MOUNT + '/data/profiles/' + entry_a['key'])['data']
        check('central.original_credential_payload_exact', payload_a['data']['credential'] == credential_a
              and entry_a['digest'] == digest_a and payload_a['metadata']['version'] == 1)
        check('central.full_document_content_address', entry_a['key'] == 'sha256-' + value_sha(payload_a['data']))
        accepted = client('original_producer_accept_a', PRODUCER)
        follower_a = client('original_follower_consume_a', FOLLOWER)
        check('original_follower.leader_flag_is_false', follower_a['cycles'][0]['plugin'].get('leader') is False)
        check('original_follower.actual_sdk_exact_a', follower_a['cycles'][0]['after']['profiles'].get(PROFILE) == digest_a)
        backup = root / 'follower-backup'; mkdir(backup)
        backup_files = []
        for suffix in ('', '-wal'):
            source = states[FOLLOWER][1] / ('openclaw-agent.sqlite' + suffix)
            if source.exists():
                check('backup.bound' + (suffix or '.db'), source.stat().st_size <= 32 * 1024 * 1024)
                private(backup / source.name, source.read_bytes()); backup_files.append(source.name)
        check('backup.closed_sdk_database', 'openclaw-agent.sqlite' in backup_files)
        central_action('operator_authorize_b', 'authorize', authorization=grant(credential_b, digest_a))
        manual = client('original_producer_manual_event', PRODUCER, [{'upserts': [{'profileId': PROFILE, 'credential': credential_b}]}])
        check('original_producer.manual_login_published', manual['cycles'][0]['plugin']['publishedEvents'] == 1)
        race = central_action('actual_manifest_cas_race', fault='cas_metadata_race')
        check('central.real_cas_rejection', race.get('actualCompetingManifestCas') is True and race['result']['deferred'] == 1)
        check('central.conflict_kept_a', entry_of(read_manifest('canonical_after_cas_conflict'))['digest'] == digest_a)
        central_action('actual_central_process_crash', expected=73, fault='crash_after_manifest_commit')
        pending = owned_private_json(root / 'central-state/pending.private.json')
        check('central.write_ahead_journal_survived', pending.get('phase') == 'manifest_dispatched')
        manifest_b = read_manifest('canonical_b_before_recovery')
        check('central.commit_exists_without_success_receipt', entry_of(manifest_b)['digest'] == digest_b)
        restart('server_cold_restart_with_pending')
        recovered = central_action('central_cold_recover', 'recover')
        check('central.current_or_historical_manifest_recovery', recovered['result']['recovered_pending'] is True)
        after_recovery = read_manifest('canonical_b_after_recovery')
        check('central.recovery_did_not_replay_manifest', after_recovery['data']['metadata']['version'] == manifest_b['data']['metadata']['version'])
        check('central.pending_cleared_after_receipt', not (root / 'central-state/pending.private.json').exists())
        follower_b = client('original_follower_consume_b', FOLLOWER)
        check('original_follower.actual_sdk_exact_b', follower_b['cycles'][0]['before']['profiles'].get(PROFILE) == digest_a
              and follower_b['cycles'][0]['after']['profiles'].get(PROFILE) == digest_b)
        restore_host = 'authbus-central-restored'
        prepare_state(restore_host, root / 'credentials' / FOLLOWER)
        for name in backup_files:
            private(states[restore_host][1] / name, (backup / name).read_bytes())
        restored = client('actual_sdk_backup_restore', restore_host)
        check('backup.actual_sdk_old_snapshot_and_current_manifest', restored['cycles'][0]['before']['profiles'].get(PROFILE) == digest_a
              and restored['cycles'][0]['after']['profiles'].get(PROFILE) == digest_b)
        binding_path = bindings[FOLLOWER]; original_binding = binding_path.read_bytes()
        owned_process.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=AuthBus Central Wrong CA',
                           '-keyout', str(root / 'wrong-ca.key'), '-out', str(root / 'wrong-ca.crt')], check=True,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, label='authbus-central.wrong-ca')
        (root / 'wrong-ca.key').chmod(0o600)
        wrong = owned_private_json(binding_path); wrong['caFile'] = str(root / 'wrong-ca.crt')
        private(binding_path, json.dumps(wrong), replace=True)
        rejected = client('follower_bad_binding', FOLLOWER, expected=3)
        check('rollback.no_auth_and_local_value_retained', rejected.get('authentications') == 0
              and rejected['cycles'][0]['after']['profiles'].get(PROFILE) == digest_b)
        private(binding_path, original_binding, replace=True)
        client('follower_binding_rollback', FOLLOWER)
        check('rollback.binding_bytes_restored', binding_path.read_bytes() == original_binding)
        renewed = central_action('central_actual_renewal_api', 'renew-due')
        check('central.renew_self_same_bearer', renewed['result']['actualRenewSelfSameBearer'] is True)
        writer_token = issued[-1]
        client('original_producer_acl_read_control', PRODUCER)
        producer_token = issued[-1]
        # ACL denials must use bearers just proven live, so an expired token
        # cannot make an overbroad policy appear correctly constrained.
        call('acl.producer_live_read_control', 'GET', MOUNT + '/data/manifest', token=producer_token)
        call('acl.writer_live_read_control', 'GET', MOUNT + '/data/manifest', token=writer_token)
        entry_b = entry_of(after_recovery)
        call('acl.producer_canonical_write_denied', 'POST', MOUNT + '/data/manifest', {'data': {}, 'options': {'cas': after_recovery['data']['metadata']['version']}}, token=producer_token, expected=403)
        call('acl.producer_other_inbox_denied', 'POST', MOUNT + '/data/inbox/' + FOLLOWER + '/' + str(uuid.uuid4()), {'data': {}, 'options': {'cas': 0}}, token=producer_token, expected=403)
        call('acl.writer_immutable_update_denied', 'POST', MOUNT + '/data/profiles/' + entry_b['key'], {'data': {}, 'options': {'cas': 1}}, token=writer_token, expected=403)
        latest_receipt = after_recovery['data']['data']['coordinator']['lastReceipt']
        receipt_path = 'coordinator-receipts/' + __import__('hashlib').sha256((latest_receipt['sourceHost'] + '\0' + latest_receipt['eventId']).encode()).hexdigest()
        call('acl.writer_receipt_update_denied', 'POST', MOUNT + '/data/' + receipt_path, {'data': {}, 'options': {'cas': 1}}, token=writer_token, expected=403)
        call('acl.writer_inbox_injection_denied', 'POST', MOUNT + '/data/inbox/' + PRODUCER + '/' + str(uuid.uuid4()), {'data': {}, 'options': {'cas': 0}}, token=writer_token, expected=403)
        unused = grant(credential_a, digest_b)
        central_action('operator_future_rotation', 'authorize', authorization=unused)
        revoked = central_action('operator_revoke_future_rotation', 'revoke-authorization', authorizationId=unused['authorizationId'])
        check('central.operator_grant_revoked', revoked['result']['authorization_revoked'] is True)
        dedup = central_action('central_cold_dedup')
        check('central.no_duplicate_credential_publication', dedup['result']['committed'] == 0
              and read_manifest('canonical_final_generation')['data']['data']['generation'] == 2)
        for index, token in enumerate(dict.fromkeys(issued)):
            call('revoke.token_live_before.' + str(index), 'GET', MOUNT + '/data/manifest', token=token)
            call('revoke.token.' + str(index), 'POST', 'auth/token/revoke-self', {}, token=token, expected=204)
            call('revoke.token_denied.' + str(index), 'GET', MOUNT + '/data/manifest', token=token, expected=403)
        for host in (PRODUCER, FOLLOWER, WRITER):
            call('revoke.sid.' + host, 'POST', roles[host]['role'] + '/secret-id-accessor/destroy', {'secret_id_accessor': roles[host]['secret_id_accessor']}, expected=204)
        revoked_login = client('original_follower_sid_revoked', FOLLOWER, expected=3)
        check('revoke.original_plugin_exact_sid_denial', revoked_login['authentications'] == 0
              and any(item.get('route') == 'login' and item.get('status') == 400 for item in revoked_login['observations']))
        restart('revocations_cold_restart')
        for index, token in enumerate(dict.fromkeys(issued)):
            call('revoke.persisted_token.' + str(index), 'GET', MOUNT + '/data/manifest', token=token, expected=403)
        check('source.original_plugin_unchanged', all(sha(args.plugin_root / name) == expected for name, expected in report['plugin_source_sha256'].items()))
        check('source.independent_service_unchanged', sha(args.central_source) == report['central_source_sha256'] == sha(root / 'authbus_coordinator.py'))
        all_diagnostics = b''.join(path.read_bytes() for path in logs) + (instance.root / 'server.log').read_bytes()
        check('evidence.no_credential_values', all(secret.encode() not in all_diagnostics + json.dumps(report).encode() for secret in confidential))
        report.update(ok=True, actual_independent_service_credential_publication=True,
                      actual_original_producer_and_consumer=True, plugin_leader_is_central_publisher=False,
                      actual_sdk_qualified=True, actual_service_https_qualified=True,
                      central_process_crash_and_server_restart_qualified=True, production_coordinator_replacement=False,
                      enforced_scheduler_qualified=False, oauth_refresh_ownership_qualified=False)
    finally:
        if instance is not None:
            instance.stop()


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--worker':
        return run_worker(Path(sys.argv[2]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--central-source', type=Path, required=True)
    parser.add_argument('--plugin-root', type=Path, required=True)
    parser.add_argument('--openclaw-root', type=Path, required=True)
    parser.add_argument('--node', type=Path, default=Path('/usr/bin/node'))
    parser.add_argument('--work-dir', type=Path, required=True)
    args = parser.parse_args()
    report = {'schema': 'native-v6-authbus-independent-coordinator-live-v1', 'ok': False,
              'production_cutover': False, 'production_coordinator_replacement': False,
              'j3160_contacted': False, 'real_provider_credentials': False, 'provider_called': False,
              'oauth_refreshed': False, 'enforced_scheduler_qualified': False,
              'actual_sdk_qualified': False, 'actual_service_https_qualified': False}
    try:
        run(args, report)
    except Exception as exc:
        report['error'] = str(exc) if isinstance(exc, CanaryFailure) else type(exc).__name__
    if args.work_dir.is_dir():
        private(args.work_dir / 'public-receipt.json', json.dumps(report, sort_keys=True))
    print(json.dumps({'ok': report['ok'], 'checks': len(report.get('checks', [])),
                      'public_receipt_path': str(args.work_dir / 'public-receipt.json'),
                      'error': report.get('error'), 'production_cutover': False}, sort_keys=True))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
