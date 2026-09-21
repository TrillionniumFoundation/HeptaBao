#!/usr/bin/env python3
"""Three TLS voters: batch claims across native same-cluster/seal restore.

The pinned OpenBao CLI saves a HeptaBao native-v2 archive. One independent raw
HTTP restore obtains its real publication receipt. No OpenBao state.bin import,
key rotation, mixed versions or physical crash durability is claimed.
"""
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

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, file_hash
from ha_destructive import FixtureError
from native_snapshot_cli_live import cli, contains_any, private_parent
from native_snapshot_ha_live import SaveCluster, capacity_data, client_view, strict_archive
from native_snapshot_ha_restore_live import publication, restart, restore_http
from official_openbao_launcher import pinned_artifact, verify_inputs
from online_evidence import admit_output, complete_checks, source_identity

MOUNT = 'batch-ha'
POLICY = 'batch-ha'
PATH = MOUNT+'/value'
BATCH_NAMES = ('userpass', 'pre_child_a', 'pre_orphan', 'post_orphan', 'post_child_a', 'child_b')
PHASES = ('pre_restore', 'restored', 'successor', 'restarted', 'parent_revoked', 'revoked_restart')
REQUIRED = frozenset({'three_processes', 'five_second_listeners', 'userpass_forwarded', 'parent_a_forwarded',
    'pre_child_a_forwarded', 'pre_orphan_forwarded', 'archive_saved', 'archive_complete', 'archive_no_publication',
    'post_orphan_issued', 'post_child_a_issued', 'parent_b_issued', 'child_b_issued', 'changed', 'later_written',
    'restore_publication', 'restore_generation', 'step_down', 'successor_changed', 'full_restart',
    'parent_a_revoked', 'revoked_full_restart', 'processes_stopped', 'plaintext_absent', 'complete'}
    | {phase+'_all_voters' for phase in PHASES}
    | {f'{phase}_n{node}_{name}_{kind}' for phase in PHASES for node in (1, 2, 3)
       for name in BATCH_NAMES for kind in ('kv', 'lookup')}
    | {f'{phase}_n{node}_userpass_identity' for phase in PHASES for node in (1, 2, 3)}
    | {f'{phase}_n{node}_later_absent' for phase in PHASES if phase != 'pre_restore' for node in (1, 2, 3)}
    | {f'restored_n{node}_parent_b_absent' for node in (1, 2, 3)})


def complete(rows):
    return complete_checks(rows, required_cases=REQUIRED) and rows[-1]['case'] == 'complete'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def helpers():
    names = ('bao_http', 'heptabao.transport', 'core_isolation', 'ha_destructive', 'ha_network_partition',
        'native_snapshot_cli_live', 'native_snapshot_ha_live', 'native_snapshot_ha_restore_live',
        'official_openbao_launcher', 'online_evidence')
    return {name: file_hash(Path(importlib.import_module(name).__file__)) for name in names}


def rejected(status, body):
    return (status == 403 and isinstance(body, dict) and isinstance(body.get('errors'), list)
            and bool(body['errors']) and not any(body.get(k) for k in ('auth', 'data', 'wrap_info')))


def lookup_matches(status, body, token, *, alive):
    if not alive:
        return rejected(status, body)
    if not isinstance(body, dict) or not isinstance(body.get('data'), dict):
        return False
    data = body.get('data') or {}
    return (status == 200 and data.get('id') == token and data.get('type') == 'batch'
            and data.get('accessor') in (None, '') and data.get('renewable') is False
            and type(data.get('ttl')) is int and data['ttl'] > 0)


def verify_voters(cluster, tokens, expected_digest, phase, check, *, userpass_entity, denied=frozenset(), parent_b=None):
    if (set(tokens) != set(BATCH_NAMES) or len(cluster.nodes) != 3
            or {node.node_id for node in cluster.nodes} != {1, 2, 3}
            or phase not in PHASES or not denied.issubset(BATCH_NAMES)
            or not isinstance(userpass_entity, str) or not userpass_entity):
        raise FixtureError('complete_token_and_voter_matrix_required')
    for node in cluster.nodes:
        prefix = f'{phase}_n{node.node_id}_'
        for name in BATCH_NAMES:
            token = tokens[name]
            status, body = node.call('GET', PATH, token=token)
            alive = name not in denied
            good = (status == 200 and hashlib.sha256(canonical(body.get('data'))).hexdigest() == expected_digest) if alive else rejected(status, body)
            check(prefix+name+'_kv', good)
            status, body = node.call('GET', 'auth/token/lookup-self', token=token)
            check(prefix+name+'_lookup', lookup_matches(status, body, token, alive=alive))
            if name == 'userpass':
                check(prefix+'userpass_identity', status == 200 and (body.get('data') or {}).get('entity_id') == userpass_entity)
        if phase != 'pre_restore':
            status, body = node.call('GET', MOUNT+'/later', token=cluster.root_token)
            check(prefix+'later_absent', status == 404 and not body.get('data'))
        if parent_b is not None:
            status, body = node.call('GET', 'auth/token/lookup-self', token=parent_b)
            check(prefix+'parent_b_absent', rejected(status, body))
    check(phase+'_all_voters', True)


def run(binary, bao, work, rows, observations):
    cluster = None
    samples = []
    def check(name, passed):
        if not isinstance(name, str) or re.fullmatch('[a-z0-9_]{1,120}', name) is None or type(passed) is not bool:
            raise FixtureError('unsafe_observation')
        rows.append({'case': name, 'passed': passed})
        if not passed:
            raise FixtureError(name)
    try:
        cluster = SaveCluster(binary, work/'cluster')
        cluster.bootstrap()
        check('three_processes', len({node.process.pid for node in cluster.nodes}) == 3)
        check('five_second_listeners', all(json.loads((n.root/'server.json').read_text())['timeout_seconds'] == 5 for n in cluster.nodes))
        leader, root = cluster.leader(), cluster.root_token
        samples.extend((root.encode(), cluster.unseal_key.encode()))
        password = secrets.token_urlsafe(24)
        samples.append(password.encode())
        def call(node, name, method, path, body=None, *, token=None, expected=200):
            status, value = node.call(method, path, body, token=root if token is None else token)
            check(name, status == expected)
            return value
        def follower(name):
            active = cluster.leader()
            node = next(n for n in cluster.nodes if n.node_id != active.node_id)
            status, body = node.call('GET', 'sys/leader')
            check(name+'_standby', status == 200 and body.get('is_self') is False
                  and body.get('leader_address') == f'https://127.0.0.1:{active.http_port}')
            return node
        def grant(node, name, body, *, parent=None, orphan=False, batch=True):
            route = 'auth/token/create-orphan' if orphan else 'auth/token/create'
            value = call(node, name+'_status', 'POST', route, body, token=parent)
            auth = value.get('auth') or {}
            raw = auth.get('client_token')
            kind = 'batch' if batch else 'service'
            good = isinstance(raw, str) and raw.startswith('hvb.' if batch else 'hvs.') and auth.get('token_type') == kind
            good = good and type(auth.get('lease_duration')) is int and auth['lease_duration'] > 0
            if batch:
                good = good and auth.get('renewable') is False and auth.get('accessor') in ('', None)
            else:
                good = good and isinstance(auth.get('accessor'), str) and bool(auth['accessor'])
            check(name+'_shape', good)
            samples.append(raw.encode())
            return raw
        call(leader, 'kv_mounted', 'POST', 'sys/mounts/'+MOUNT, {'type': 'kv', 'options': {'version': '1'}}, expected=204)
        original = {'value': secrets.token_hex(2048), 'revision': 'archived'}
        original_digest = hashlib.sha256(canonical(original)).hexdigest()
        samples.append(original['value'][:80].encode())
        call(leader, 'seeded', 'PUT', PATH, original, expected=204)
        policy = (f'path "{MOUNT}/*" {{ capabilities = ["read"] }} '
                  'path "auth/token/create" { capabilities = ["update"] }')
        call(leader, 'policy_written', 'POST', 'sys/policies/acl/'+POLICY, {'policy': policy}, expected=204)
        call(leader, 'userpass_mounted', 'POST', 'sys/auth/'+MOUNT, {'type': 'userpass'}, expected=204)
        call(leader, 'userpass_configured', 'POST', f'auth/{MOUNT}/users/alice',
             {'password': password, 'token_type': 'batch', 'token_ttl': 1800, 'token_policies': [POLICY]}, expected=204)
        standby = follower('userpass')
        value = call(standby, 'userpass_forwarded', 'POST', f'auth/{MOUNT}/login/alice', {'password': password}, token='')
        auth = value.get('auth') or {}
        raw = auth.get('client_token')
        check('userpass_batch_shape', isinstance(raw, str) and raw.startswith('hvb.') and auth.get('token_type') == 'batch'
              and auth.get('accessor') in ('', None) and auth.get('renewable') is False
              and isinstance(auth.get('entity_id'), str) and bool(auth['entity_id']))
        samples.append(raw.encode())
        tokens = {'userpass': raw}
        userpass_entity = auth['entity_id']
        parent_a = grant(follower('parent_a'), 'parent_a', {'policies': [POLICY], 'ttl': 1800}, batch=False)
        check('parent_a_forwarded', True)
        params = {'type': 'batch', 'policies': [POLICY], 'ttl': 1800}
        tokens['pre_child_a'] = grant(follower('pre_child_a'), 'pre_child_a', params, parent=parent_a)
        check('pre_child_a_forwarded', True)
        tokens['pre_orphan'] = grant(follower('pre_orphan'), 'pre_orphan', params, orphan=True)
        check('pre_orphan_forwarded', True)
        leader = cluster.leader()
        archive = work/'pre-batch-history.snap'
        generation = capacity_data(leader, root)['generation']
        check('archive_saved', cli(bao, client_view(cluster, leader), work, 'save', archive) == 0)
        metadata = strict_archive(archive)
        observations['archive'] = metadata
        check('archive_complete', True)
        check('archive_no_publication', capacity_data(leader, root)['generation'] == generation)
        tokens['post_orphan'] = grant(follower('post_orphan'), 'post_orphan', params, orphan=True)
        check('post_orphan_issued', True)
        tokens['post_child_a'] = grant(follower('post_child_a'), 'post_child_a', params, parent=parent_a)
        check('post_child_a_issued', True)
        parent_b = grant(follower('parent_b'), 'parent_b', {'policies': [POLICY], 'ttl': 1800}, batch=False)
        check('parent_b_issued', True)
        tokens['child_b'] = grant(follower('child_b'), 'child_b', params, parent=parent_b)
        check('child_b_issued', True)
        leader = cluster.leader()
        changed = {'value': 'changed-after-archive', 'revision': 'live'}
        call(leader, 'changed', 'PUT', PATH, changed, expected=204)
        call(leader, 'later_written', 'PUT', MOUNT+'/later', {'value': 'must-disappear'}, expected=204)
        verify_voters(cluster, tokens, hashlib.sha256(canonical(changed)).hexdigest(), 'pre_restore', check,
                      userpass_entity=userpass_entity)
        before = capacity_data(leader, root)['generation']
        restored = publication(restore_http(leader, root, archive), before, metadata['generation'])
        check('restore_publication', restored is not None)
        observations['single_restore_publication'] = restored
        check('restore_generation', capacity_data(leader, root)['generation'] == restored['published_local_generation'])
        denied = frozenset({'child_b'})
        verify_voters(cluster, tokens, original_digest, 'restored', check, userpass_entity=userpass_entity,
                      denied=denied, parent_b=parent_b)
        previous = leader.node_id
        call(leader, 'step_down', 'POST', 'sys/step-down', {}, expected=204)
        leader = cluster.leader()
        check('successor_changed', leader.node_id != previous)
        verify_voters(cluster, tokens, original_digest, 'successor', check, userpass_entity=userpass_entity, denied=denied)
        restart(cluster)
        check('full_restart', True)
        verify_voters(cluster, tokens, original_digest, 'restarted', check, userpass_entity=userpass_entity, denied=denied)
        leader = cluster.leader()
        call(leader, 'parent_a_revoked', 'POST', 'auth/token/revoke', {'token': parent_a}, expected=204)
        denied |= {'pre_child_a', 'post_child_a'}
        verify_voters(cluster, tokens, original_digest, 'parent_revoked', check, userpass_entity=userpass_entity, denied=denied)
        restart(cluster)
        check('revoked_full_restart', True)
        verify_voters(cluster, tokens, original_digest, 'revoked_restart', check, userpass_entity=userpass_entity, denied=denied)
        observations['value_sha256'] = original_digest
        cluster.close()
        check('processes_stopped', all(node.process is None for node in cluster.nodes))
        files = [p for n in cluster.nodes for base in (n.data_dir, n.root/'raft') for p in base.rglob('*') if p.is_file()]
        files += [p for n in cluster.nodes for p in (n.root/'audit.jsonl', n.root/'process.log') if p.exists()]
        files += list(work.glob('*.snap'))
        check('plaintext_absent', bool(files) and all(not contains_any(path, samples) for path in files))
        check('complete', True)
    finally:
        if cluster is not None:
            cluster.close()


def main():
    parser = SafeArgumentParser(description=__doc__)
    for name in ('binary', 'work-parent', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--expected-binary-sha256', required=True)
    parser.add_argument('--build-source-commit', required=True)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.build_source_commit) or not re.fullmatch('[0-9a-f]{64}', args.expected_binary_sha256):
        parser.error('candidate_pins_required')
    binary = args.binary.resolve(strict=True)
    if file_hash(binary) != args.expected_binary_sha256:
        parser.error('candidate_binary_mismatch')
    output = args.output.absolute()
    admitted, parent = admit_output(output), private_parent(args.work_parent)
    bao = verify_inputs()
    cli_hash, runner_hash, helper_hashes = file_hash(bao), file_hash(Path(__file__)), helpers()
    before = source_identity(ROOT, binary)
    work = Path(tempfile.mkdtemp(prefix='userpass-batch-ha-', dir=parent))
    work.chmod(0o700)
    rows, observations, failure = [], {}, None
    def interrupted(signum, frame):
        raise FixtureError('fixture_interrupted')
    handlers = {kind: signal.signal(kind, interrupted) for kind in (signal.SIGTERM, signal.SIGINT)}
    try:
        run(binary, bao, work, rows, observations)
    except Exception as error:
        failure = next((row['case'] for row in reversed(rows) if row['passed'] is not True), 'fixture_'+type(error).__name__)
    finally:
        for kind, handler in handlers.items():
            signal.signal(kind, handler)
    after = source_identity(ROOT, binary)
    source_ok = before == after and after['binary_sha256'] == args.expected_binary_sha256
    runner_ok, cli_ok, helpers_ok = file_hash(Path(__file__)) == runner_hash, file_hash(bao) == cli_hash, helpers() == helper_hashes
    if not source_ok or not runner_ok or not cli_ok or not helpers_ok:
        failure = 'source_binary_cli_or_helpers_changed'
    if before['source_dirty'] or after['source_dirty']:
        failure = 'source_dirty'
    if not complete(rows):
        failure = failure or 'incomplete_observations'
    report = {'schema': 'heptabao.userpass-batch-ha.v1', 'status': 'failed' if failure else 'passed',
        'failure': failure, 'checks': rows, 'observations': observations,
        'source_identity': before, 'source_identity_after': after, 'source_and_binary_unchanged': source_ok,
        'build_source_commit': args.build_source_commit, 'runner_sha256': runner_hash, 'runner_unchanged': runner_ok,
        'helper_sha256': helper_hashes, 'helpers_unchanged': helpers_ok,
        'official_cli_version': '2.6.2', 'official_cli_sha256': cli_hash, 'official_cli_unchanged': cli_ok,
        'official_cli_artifact_sha256': pinned_artifact()['artifact_sha256'], 'official_cli_operation': 'save_once',
        'native_restore_operation': 'one_raw_HTTP_upload_with_numeric_publication_receipt',
        'native_archive_version': 2, 'node_count': 3, 'listener_timeout_seconds': 5, 'mutation_retries': 0,
        'same_cluster_and_seal': True, 'every_voter_HTTP_checked': all(
            any(row == {'case': phase+'_all_voters', 'passed': True} for row in rows) for phase in PHASES),
        'direct_local_follower_reads_claimed': False,
        'retained_failure_work_dir': str(work) if failure else None, 'synthetic_only': True,
        'key_rotation_covered': False, 'physical_failure_covered': False, 'CIDR_denial_covered': False,
        'dynamic_leases_covered': False, 'OpenBao_state_bin_interoperability': False,
        'full_openbao_compatibility': False, 'multi_host_covered': False,
        'independent_qualification': False, 'production_authority': False}
    if admit_output(output) != admitted:
        raise ValueError('report_parent_changed')
    private_write(output, report, replace=False)
    if failure is None:
        shutil.rmtree(work)
    print(json.dumps({'status': report['status'], 'checks': len(rows), 'failure': failure}))
    return int(failure is not None)


if __name__ == '__main__':
    raise SystemExit(main())
