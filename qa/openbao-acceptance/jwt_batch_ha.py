#!/usr/bin/env python3
"""Three TLS voters: ordinary static JWT batches, Identity and HA lifecycle."""
from __future__ import annotations
import hashlib
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
from core_isolation import ROOT, ScenarioFailure, file_hash
from native_snapshot_ha_live import SaveCluster
from online_evidence import admit_output, complete_checks, source_identity
from remote_jwks_live import signing_key, token as sign_token, serialization
from userpass_batch_ha import standby_response, rejected
from userpass_params_ha import secret_free
from userpass_password_live import private_parent

MOUNT, ROLE, POLICY, KV = 'jwt-batch-ha', 'workload', 'jwt-batch-ha', 'jwt-batch-data/item'
ISSUER, SUBJECT = 'https://jwt-batch-ha.invalid', 'synthetic-ha-subject'
CUSTOM = {'qa': 'independent-custom-metadata'}
PHASES = ('initial', 'disabled', 'enabled', 'reused', 'role_deleted', 'mount_disabled', 'successor', 'restarted')


def names_for(phase):
    if phase not in PHASES: raise ValueError('unknown_phase')
    return ('original',) if phase in ('initial', 'disabled', 'enabled') else ('original', 'reused')


REQUIRED = frozenset({'three_processes', 'five_second_listeners', 'initial_standby', 'initial_issued',
    'custom_metadata_preserves_backend', 'disabled_login_rejected', 'reuse_standby', 'reused_issued',
    'reused_same_identity_distinct_token', 'role_deleted_status', 'mount_disabled_status',
    'step_down_status', 'successor_changed', 'former_leader_standby', 'full_restart',
    'processes_stopped', 'plaintext_absent', 'complete'}
    | {phase+'_all_voters' for phase in PHASES}
    | {f'{phase}_n{node}_{kind}_{case}' for phase in PHASES for node in (1, 2, 3)
       for kind in names_for(phase) for case in ('kv', 'lookup')}
    | {f'{phase}_n{node}_alias' for phase in PHASES for node in (1, 2, 3)})


def complete(rows):
    return complete_checks(rows, required_cases=REQUIRED) and rows[-1]['case'] == 'complete'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def samples_bytes(samples):
    if any(not isinstance(value, (str, bytes)) for value in samples): raise ValueError('invalid_scan_sample')
    return [value.encode() if isinstance(value, str) else value for value in samples if len(value) >= 16]


def report_secret_free(value, samples):
    encoded = canonical(value)
    return not any(sample in encoded for sample in samples_bytes(samples))


def batch_lookup(status, body, auth, entity):
    if not isinstance(body, dict) or not isinstance(body.get('data'), dict): return False
    data = body['data']
    return (status == 200 and data.get('id') == auth['client_token'] and data.get('type') == 'batch'
        and data.get('accessor') in (None, '') and data.get('renewable') is False
        and data.get('orphan') is True and data.get('entity_id') == entity
        and data.get('meta') == {'role': ROLE} and data.get('display_name') == MOUNT+'-'+SUBJECT
        and type(data.get('ttl')) is int and data['ttl'] > 0)


def immutable_view(data):
    return {key: data.get(key) for key in ('id', 'accessor', 'type', 'entity_id', 'meta', 'display_name',
        'renewable', 'orphan', 'creation_time', 'expire_time', 'expire_time_unix', 'num_uses')}


def verify_voters(cluster, tokens, entity, alias_id, expected_digest, phase, check):
    if {node.node_id for node in cluster.nodes} != {1, 2, 3} or len(cluster.nodes) != 3:
        raise ScenarioFailure('three_distinct_voters_required')
    if set(tokens) != set(names_for(phase)) or not entity or not alias_id:
        raise ScenarioFailure('complete_token_identity_matrix_required')
    denied, views = phase == 'disabled', []
    for node in cluster.nodes:
        view = []
        for label in names_for(phase):
            auth = tokens[label]; prefix = f'{phase}_n{node.node_id}_{label}'
            status, body = node.call('GET', KV, token=auth['client_token'])
            check(prefix+'_kv', rejected(status, body) if denied else status == 200
                  and hashlib.sha256(canonical(body.get('data'))).hexdigest() == expected_digest)
            status, body = node.call('GET', 'auth/token/lookup-self', token=auth['client_token'])
            check(prefix+'_lookup', rejected(status, body) if denied else batch_lookup(status, body, auth, entity))
            if not denied: view.append(immutable_view(body['data']))
        status, body = node.call('GET', 'identity/entity-alias/id/'+alias_id, token=cluster.root_token)
        alias = body.get('data') or {}
        check(f'{phase}_n{node.node_id}_alias', status == 200 and alias.get('canonical_id') == entity
            and alias.get('name') == SUBJECT and alias.get('metadata') == {'role': ROLE}
            and alias.get('custom_metadata') == CUSTOM)
        view.append(alias)
        views.append(view)
    check(phase+'_all_voters', all(view == views[0] for view in views))


def helpers():
    names = ('bao_http', 'heptabao.transport', 'core_isolation', 'online_evidence', 'ha_destructive',
        'ha_network_partition', 'native_snapshot_ha_live', 'native_snapshot_cli_live',
        'userpass_batch_ha', 'userpass_params_ha', 'userpass_password_live',
        'remote_jwks_live', 'external_tls_fixtures', 'smoke')
    return {name: file_hash(Path(importlib.import_module(name).__file__)) for name in names}


def run(binary, work, rows, bootstrap, observations, samples):
    cluster = None
    def check(name, condition):
        if not re.fullmatch('[a-z0-9_]{1,120}', name) or type(condition) is not bool:
            raise ScenarioFailure('unsafe_observation')
        if any(row['case'] == name for row in rows): raise ScenarioFailure('duplicate_case')
        rows.append({'case': name, 'passed': condition})
        if not condition: raise ScenarioFailure(name)
    try:
        cluster = SaveCluster(binary, work/'cluster'); cluster.bootstrap()
        bootstrap.extend(cluster.scenarios)
        samples.extend((cluster.root_token, cluster.unseal_key, cluster.replication_key))
        check('three_processes', len(cluster.running()) == 3)
        check('five_second_listeners', all(json.loads((n.root/'server.json').read_text())['timeout_seconds'] == 5
              for n in cluster.nodes))
        def call(node, name, method, path, body=None, *, token=None, expected=200):
            status, value = node.call(method, path, body, token=cluster.root_token if token is None else token)
            check(name+'_status', status == expected)
            if expected >= 400: check(name+'_rejected', rejected(status, value))
            return value
        def follower(name):
            leader = cluster.leader()
            node = next(n for n in cluster.nodes if n.node_id != leader.node_id)
            status, body = node.call('GET', 'sys/leader')
            check(name+'_standby', standby_response(status, body, f'https://127.0.0.1:{leader.http_port}'))
            return node
        def issue(node, name, assertion):
            value = call(node, name, 'POST', 'auth/'+MOUNT+'/login', {'role': ROLE, 'jwt': assertion}, token='')
            auth = value.get('auth') or {}; raw = auth.get('client_token')
            check(name+'_issued', isinstance(raw, str) and raw.startswith('hvb.')
                and auth.get('token_type') == 'batch' and auth.get('accessor') in (None, '')
                and auth.get('renewable') is False and auth.get('orphan') is True
                and type(auth.get('lease_duration')) is int and auth['lease_duration'] > 0
                and auth.get('metadata') == {'role': ROLE}
                and isinstance(auth.get('entity_id'), str) and bool(auth['entity_id']))
            samples.extend(value for value in (raw, auth.get('accessor')) if isinstance(value, str) and value)
            return auth
        leader = cluster.leader()
        call(leader, 'kv_mount', 'POST', 'sys/mounts/jwt-batch-data', {'type': 'kv', 'options': {'version': '1'}}, expected=204)
        value = {'value': secrets.token_hex(2048), 'revision': 'stable'}
        expected_digest = hashlib.sha256(canonical(value)).hexdigest()
        samples.append(value['value'][:80])
        call(leader, 'kv_seed', 'PUT', KV, value, expected=204)
        call(leader, 'policy', 'PUT', 'sys/policies/acl/'+POLICY,
            {'policy': 'path "jwt-batch-data/*" { capabilities=["read"] }'}, expected=204)
        call(leader, 'jwt_mount', 'POST', 'sys/auth/'+MOUNT, {'type': 'jwt'}, expected=204)
        private, jwk = signing_key('ES256', 'jwt-ha-key')
        samples.append(private.private_bytes(serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        call(leader, 'jwt_config', 'POST', 'auth/'+MOUNT+'/config',
            {'issuer': ISSUER, 'audiences': ['heptabao-test'], 'jwks': {'keys': [jwk]}}, expected=204)
        call(leader, 'jwt_role', 'POST', 'auth/'+MOUNT+'/role/'+ROLE,
            {'role_type': 'jwt', 'user_claim': 'sub', 'bound_audiences': ['heptabao-test'],
             'token_type': 'batch', 'token_ttl': 1800, 'token_max_ttl': 1800, 'token_policies': [POLICY]}, expected=204)
        assertion = sign_token(private, jwk, ISSUER, sub=SUBJECT, exp=int(time.time())+1800)
        samples.append(assertion)
        original = issue(follower('initial'), 'initial', assertion)
        entity = original['entity_id']; tokens = {'original': original}
        info = call(cluster.leader(), 'entity_read', 'GET', 'identity/entity/id/'+entity)['data']
        aliases = [a for a in info.get('aliases', []) if a.get('name') == SUBJECT]
        check('alias_unique', len(aliases) == 1)
        alias = aliases[0]; alias_id = alias['id']
        call(follower('custom'), 'custom_metadata', 'POST', 'identity/entity-alias/id/'+alias_id,
            {'canonical_id': entity, 'name': SUBJECT, 'mount_accessor': alias['mount_accessor'], 'custom_metadata': CUSTOM})
        updated = call(cluster.leader(), 'custom_read', 'GET', 'identity/entity-alias/id/'+alias_id)['data']
        check('custom_metadata_preserves_backend', updated.get('metadata') == {'role': ROLE}
            and updated.get('custom_metadata') == CUSTOM)
        verify_voters(cluster, tokens, entity, alias_id, expected_digest, 'initial', check)
        call(follower('disable'), 'identity_disable', 'POST', 'identity/entity/id/'+entity, {'disabled': True}, expected=204)
        call(follower('disabled_login'), 'disabled_login', 'POST', 'auth/'+MOUNT+'/login',
            {'role': ROLE, 'jwt': assertion}, token='', expected=403)
        verify_voters(cluster, tokens, entity, alias_id, expected_digest, 'disabled', check)
        call(follower('enable'), 'identity_enable', 'POST', 'identity/entity/id/'+entity, {'disabled': False}, expected=204)
        verify_voters(cluster, tokens, entity, alias_id, expected_digest, 'enabled', check)
        repeated = issue(follower('reuse'), 'reused', assertion)
        check('reused_same_identity_distinct_token', repeated['entity_id'] == entity
            and repeated['client_token'] != original['client_token'])
        tokens['reused'] = repeated
        verify_voters(cluster, tokens, entity, alias_id, expected_digest, 'reused', check)
        call(follower('delete'), 'role_deleted', 'DELETE', 'auth/'+MOUNT+'/role/'+ROLE, expected=204)
        verify_voters(cluster, tokens, entity, alias_id, expected_digest, 'role_deleted', check)
        call(follower('unmount'), 'mount_disabled', 'DELETE', 'sys/auth/'+MOUNT, expected=204)
        verify_voters(cluster, tokens, entity, alias_id, expected_digest, 'mount_disabled', check)
        leader = cluster.leader()
        call(leader, 'step_down', 'POST', 'sys/step-down', {}, expected=204)
        successor = cluster.leader(); check('successor_changed', successor.node_id != leader.node_id)
        status, body = leader.call('GET', 'sys/leader')
        check('former_leader_standby', standby_response(status, body, f'https://127.0.0.1:{successor.http_port}'))
        verify_voters(cluster, tokens, entity, alias_id, expected_digest, 'successor', check)
        for node in cluster.nodes: node.stop()
        for node in cluster.nodes: node.start(wait=False)
        for node in cluster.nodes: node.wait_ready()
        cluster.wait_quorum()
        for node in cluster.nodes:
            if node.call('POST', 'sys/unseal', {'key': cluster.unseal_key})[0] != 200:
                raise ScenarioFailure('restart_unseal_failed')
        cluster.leader(); check('full_restart', len(cluster.running()) == 3)
        verify_voters(cluster, tokens, entity, alias_id, expected_digest, 'restarted', check)
        observations['kv_sha256'] = expected_digest
        cluster.close(); check('processes_stopped', all(n.process is None for n in cluster.nodes))
        paths = []
        for node in cluster.nodes:
            paths.extend(p for base in (node.data_dir, node.root/'raft') for p in base.rglob('*'))
            paths.extend((node.root/'process.log', node.root/'audit.jsonl'))
        check('plaintext_absent', bool(paths) and secret_free(paths, samples_bytes(samples))
            and report_secret_free({'checks': rows, 'bootstrap': bootstrap, 'observations': observations}, samples))
        check('complete', True)
    finally:
        if cluster is not None: cluster.close()


def main():
    p = SafeArgumentParser(description=__doc__)
    for name in ('binary', 'work-parent', 'output'): p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--expected-binary-sha256', required=True); p.add_argument('--build-source-commit', required=True)
    args = p.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.build_source_commit) or not re.fullmatch('[0-9a-f]{64}', args.expected_binary_sha256):
        p.error('candidate_pins_required')
    binary = args.binary.resolve(strict=True)
    if file_hash(binary) != args.expected_binary_sha256: p.error('candidate_binary_mismatch')
    output = args.output.absolute(); admitted = admit_output(output)
    before, runner, helper = source_identity(ROOT, binary), file_hash(Path(__file__)), helpers()
    work = Path(tempfile.mkdtemp(prefix='jwt-batch-ha-', dir=private_parent(args.work_parent)))
    rows, bootstrap, observations, samples, failure = [], [], {}, [], None
    def interrupted(signum, frame): raise ScenarioFailure('interrupted')
    handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try: run(binary, work, rows, bootstrap, observations, samples)
    except Exception as error:
        failure = next((r['case'] for r in reversed(rows) if r['passed'] is not True), 'fixture_'+type(error).__name__)
    finally:
        for sig, handler in handlers.items(): signal.signal(sig, handler)
    after = source_identity(ROOT, binary)
    source_ok = before == after and after['binary_sha256'] == args.expected_binary_sha256
    runner_ok, helper_ok = file_hash(Path(__file__)) == runner, helpers() == helper
    if not source_ok or not runner_ok or not helper_ok: failure = 'source_binary_or_helpers_changed'
    if before['source_dirty'] or after['source_dirty']: failure = 'source_dirty'
    if not complete(rows): failure = failure or 'incomplete_observations'
    report = {'schema': 'heptabao.jwt-batch-ha.v1', 'status': 'failed' if failure else 'passed',
        'failure': failure, 'checks': rows, 'bootstrap': bootstrap, 'observations': observations,
        'source_identity': before, 'source_identity_after': after, 'source_and_binary_unchanged': source_ok,
        'build_source_commit': args.build_source_commit, 'runner_sha256': runner, 'runner_unchanged': runner_ok,
        'helper_sha256': helper, 'helpers_unchanged': helper_ok, 'node_count': 3, 'listener_timeout_seconds': 5,
        'mutation_retries': 0, 'ordinary_static_JWT_only': True, 'same_signed_assertion_reused': True,
        'every_voter_HTTP_checked': all({'case': phase+'_all_voters', 'passed': True} in rows for phase in PHASES),
        'direct_local_follower_reads_claimed': False, 'scan_scope': ['durable', 'raft', 'process_log', 'audit', 'receipt'],
        'snapshot_covered': False, 'key_rotation_covered': False, 'physical_failure_covered': False,
        'remote_JWKS_covered': False, 'OIDC_covered': False, 'full_openbao_compatibility': False,
        'retained_failure_work_dir': str(work) if failure else None, 'synthetic_only': True,
        'independent_qualification': False, 'production_authority': False}
    if not report_secret_free(report, samples): raise ValueError('sensitive_report_rejected')
    if admit_output(output) != admitted: raise ValueError('output_parent_changed')
    private_write(output, report, replace=False)
    if failure is None: shutil.rmtree(work)
    print(json.dumps({'status': report['status'], 'checks': len(rows), 'failure': failure}))
    return int(failure is not None)


if __name__ == '__main__': raise SystemExit(main())
