#!/usr/bin/env python3
"""Three TLS voters: AppRole SID metadata, failed affine use and real snapshot catch-up."""
from __future__ import annotations
import importlib
import json
from pathlib import Path
import re
import shutil
import signal
import tempfile
import time

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from online_evidence import admit_output, complete_checks, source_identity
from native_snapshot_ha_live import SaveCluster
from radius_cidrs_live import SourceClient
from approle_secret_cidrs_ha import restart_cluster
from userpass_batch_ha import standby_response
from userpass_password_live import private_parent
from userpass_params_ha import secret_free, projection
from jwt_batch_ha import report_secret_free
from raft_record_snapshot_observation import inspect_record_bundle, SnapshotPending
from kv1_record_ha_live import snapshot_frontier

MOUNT, KV, POLICY = 'approle-metadata-ha', 'approle-metadata-kv/item', 'approle-metadata-ha'
KINDS = ('service', 'batch')
CUSTOM = {'owner': 'independent-admin'}
CALIBRATION = 'approle-secretid-metadata-official-b56954e.json'
CALIBRATION_SHA = '7292a2c8f5ada19543b2536c1cbfc0648f515a2684aa3c12fe8d9145c6942023'
PHASES = ('snapshot', 'successor', 'restarted')
REQUIRED = frozenset({'three_processes', 'five_second_listeners', 'lagger_stopped',
    'compact_status', 'purged_past_lagger', 'leader_snapshot', 'lagger_snapshot', 'lagger_unseal_status',
    'stepdown_status', 'successor_changed', 'former_leader_standby', 'full_restart',
    'processes_stopped', 'secrets_absent', 'complete'}
    | {f'{k}_{case}' for k in KINDS for case in ('one_standby', 'one_issued', 'wide_metadata',
        'source_standby', 'source_status', 'source_rejected', 'source_uses', 'source_alias_unchanged',
        'disabled_standby', 'disabled_status', 'disabled_rejected', 'disabled_uses', 'disabled_alias_backend', 'disabled_alias_custom', 'disabled_alias_binding',
        'two_standby', 'two_issued', 'same_entity', 'two_consumed', 'alias_backend', 'alias_custom', 'one_deleted_status')}
    | {f'{phase}_all_voters' for phase in PHASES}
    | {f'{phase}_n{node}_{kind}_{label}_snapshot' for phase in PHASES for node in (1, 2, 3)
       for kind in KINDS for label in ('one', 'two')}
    | {f'{phase}_n{node}_{kind}_alias' for phase in PHASES for node in (1, 2, 3) for kind in KINDS}
    | {f'{phase}_service_{via}_snapshot' for phase in ('after_delete', 'after_restart') for via in ('self', 'token', 'accessor')}
    | {f'{phase}_batch_{via}_rejected' for phase in ('after_delete', 'after_restart') for via in ('self', 'token')}
    | {f'{phase}_batch_no_accessor_route' for phase in ('after_delete', 'after_restart')})


def complete(rows):
    return complete_checks(rows, required_cases=REQUIRED) and rows[-1]['case'] == 'complete'


def metadata(env, role='spoofed'):
    # New aliases are sanitized upstream. Only update an already-created alias
    # with the 65-field representative; the first login is an ordinary map.
    return {'env': env, 'role_name': role, **({f'field{i:02d}': 'synthetic' for i in range(63)} if env == 'two' else {})}


def role(kind): return f'auth/{MOUNT}/role/{kind}'


class Trace:
    def __init__(self, client, rows, sensitive): self.client, self.rows, self.sensitive = client, rows, sensitive
    def check(self, name, ok):
        if (not isinstance(name, str) or not re.fullmatch('[a-z0-9_]{1,120}', name) or type(ok) is not bool
            or any(r['case'] == name for r in self.rows)): raise ScenarioFailure('unsafe_observation')
        self.rows.append({'case': name, 'passed': ok})
        if not ok: raise ScenarioFailure(name)
    def call(self, name, method, path, body=None, *, status=200, token=None, source='127.0.0.1', wrap_ttl=None, spoof=False):
        response = self.client.request(method, path, body, token=token, source=source, wrap_ttl=wrap_ttl, spoof=spoof)
        self.check(name+'_status', response.status == status)
        self.check(name+'_ipv4', self.client.last_family == 4)
        value = response.body; auth, data = value.get('auth') or {}, value.get('data') or {}
        self.sensitive.extend(v for v in (auth.get('client_token'), auth.get('accessor'), data.get('secret_id'),
            data.get('secret_id_accessor'), data.get('role_id')) if isinstance(v, str) and v)
        if status >= 400:
            self.check(name+'_rejected', bool(value.get('errors')) and not any(value.get(k) for k in ('auth', 'data', 'wrap_info')))
        return value
    def login(self, name, kind, creds, env):
        auth = self.call(name, 'POST', f'auth/{MOUNT}/login', creds, token='').get('auth') or {}
        self.check(name+'_issued', isinstance(auth.get('client_token'), str)
            and auth['client_token'].startswith('hvb.' if kind == 'batch' else 'hvs.')
            and auth.get('token_type') == kind and auth.get('metadata') == metadata(env, kind)
            and bool(auth.get('accessor')) == (kind == 'service') and auth.get('renewable') is (kind == 'service')
            and type(auth.get('lease_duration')) is int and auth['lease_duration'] > 0
            and isinstance(auth.get('entity_id'), str) and bool(auth['entity_id']))
        return auth
    def sid(self, name, kind, creds, uses, env):
        data = self.call(name+'_lookup', 'POST', role(kind)+'/secret-id/lookup', {'secret_id': creds['secret_id']})['data']
        self.check(name+'_uses', type(data.get('secret_id_num_uses')) is int and data['secret_id_num_uses'] == uses)
        self.check(name+'_raw_metadata', data.get('metadata') == metadata(env))
        return data
    def alias(self, name, ident):
        return self.call(name, 'GET', 'identity/entity-alias/id/'+ident)['data']

    def disabled_alias_refresh(self, name, original, kind):
        refreshed = self.alias(name+'_read', original['id'])
        self.check(name+'_backend', refreshed.get('metadata') == metadata('two', kind))
        self.check(name+'_custom', refreshed.get('custom_metadata') == original.get('custom_metadata') == CUSTOM)
        self.check(name+'_binding', all(refreshed.get(key) == original[key]
            for key in ('id', 'name', 'canonical_id', 'mount_accessor')))
        # No timestamp increment is required: successful final login supplies
        # the same backend map and both operations may occur in one second.
        return refreshed


def lookup_matches(data, auth, kind, env):
    return (isinstance(data, dict) and data.get('id') == auth['client_token'] and data.get('type') == kind
        and data.get('entity_id') == auth['entity_id'] and data.get('meta') == metadata(env, kind)
        and type(data.get('ttl')) is int and data['ttl'] > 0 and data.get('renewable') is (kind == 'service')
        and (data.get('accessor') == auth['accessor'] if kind == 'service' else data.get('accessor') in (None, '')))


def verify_voters(cluster, trace, held, phase):
    if phase not in PHASES or len(cluster.nodes) != 3 or {n.node_id for n in cluster.nodes} != {1, 2, 3}:
        raise ScenarioFailure('complete_voter_phase_required')
    if set(held) != set(KINDS) or any(set(held[k]) != {'one', 'two', 'alias'} for k in KINDS):
        raise ScenarioFailure('complete_token_matrix_required')
    views = []
    for node in cluster.nodes:
        t, view = trace(node), []
        for kind in KINDS:
            for label in ('one', 'two'):
                auth = held[kind][label]; name = f'{phase}_n{node.node_id}_{kind}_{label}'
                body = t.call(name+'_kv', 'GET', KV, token=auth['client_token'])
                t.check(name+'_value', body.get('data') == {'value': 'synthetic'})
                data = t.call(name+'_lookup', 'GET', 'auth/token/lookup-self', token=auth['client_token'])['data']
                t.check(name+'_snapshot', lookup_matches(data, auth, kind, label))
                view.append(projection(data))
            alias = t.alias(f'{phase}_n{node.node_id}_{kind}_alias_read', held[kind]['alias']['id'])
            t.check(f'{phase}_n{node.node_id}_{kind}_alias', alias.get('metadata') == metadata('two', kind)
                and alias.get('custom_metadata') == CUSTOM and alias.get('canonical_id') == held[kind]['one']['entity_id'])
            view.append(alias)
        views.append(view)
    trace(cluster.nodes[0]).check(phase+'_all_voters', all(v == views[0] for v in views))


def renew_one(t, phase, kind, auth):
    routes = [('self', 'auth/token/renew-self', {'increment': 900}, auth['client_token']),
        ('token', 'auth/token/renew', {'token': auth['client_token'], 'increment': 900}, None)]
    if kind == 'service': routes.append(('accessor', 'auth/token/renew-accessor', {'accessor': auth['accessor'], 'increment': 900}, None))
    else: t.check(phase+'_batch_no_accessor_route', auth.get('accessor') in (None, ''))
    for via, path, body, actor in routes:
        name = phase+'_'+kind+'_'+via
        result = t.call(name, 'POST', path, body, token=actor, status=200 if kind == 'service' else 400)
        if kind == 'service':
            issued = result.get('auth') or {}
            t.check(name+'_snapshot', issued.get('metadata') == metadata('one', kind)
                and (issued.get('client_token') in (None, '') if via == 'accessor' else issued.get('client_token') == auth['client_token']))


def wait_snapshot(node, target):
    deadline = time.monotonic()+15
    while True:
        try: return inspect_record_bundle(node.root/'raft/state-machine/state-bundle.bin', minimum_index=target)
        except (FileNotFoundError, SnapshotPending):
            if time.monotonic() >= deadline: raise ScenarioFailure('snapshot_install_not_observed') from None
            time.sleep(.1)


def run(binary, work, rows, bootstrap, observations, sensitive):
    cluster = None
    try:
        cluster = SaveCluster(binary, work/'cluster'); cluster.bootstrap(); bootstrap.extend(cluster.scenarios)
        sensitive.extend((cluster.root_token, cluster.unseal_key, cluster.replication_key))
        def trace(node):
            return Trace(SourceClient(f'https://127.0.0.1:{node.http_port}', cluster.root/'ca.crt',
                cluster.root_token, spoof_source='127.0.0.1'), rows, sensitive)
        def follower(name):
            leader = cluster.leader(); node = next(n for n in cluster.running() if n.node_id != leader.node_id)
            status, body = node.call('GET', 'sys/leader', timeout=5)
            trace(node).check(name+'_standby', standby_response(status, body, f'https://127.0.0.1:{leader.http_port}'))
            return trace(node)
        leader = cluster.leader(); t = trace(leader)
        t.check('three_processes', len(cluster.running()) == 3)
        t.check('five_second_listeners', all(json.loads((n.root/'server.json').read_text())['timeout_seconds'] == 5 for n in cluster.nodes))
        t.call('mount', 'POST', 'sys/auth/'+MOUNT, {'type': 'approle'}, status=204)
        t.call('kv_mount', 'POST', 'sys/mounts/approle-metadata-kv', {'type': 'kv', 'options': {'version': '1'}}, status=204)
        t.call('kv_seed', 'POST', KV, {'value': 'synthetic'}, status=204)
        t.call('policy', 'PUT', 'sys/policies/acl/'+POLICY, {'policy': 'path "approle-metadata-kv/*" { capabilities=["read"] }'}, status=204)
        before = t.call('before_snapshot', 'GET', 'sys/storage/raft/snapshot-status')['data']
        t.check('initial_frontier', snapshot_frontier(before))
        lagger = next(n for n in reversed(cluster.nodes) if n.node_id != leader.node_id); lagger.stop()
        t.check('lagger_stopped', lagger.process is None)
        held = {}
        for kind in KINDS:
            t = follower(kind+'_setup')
            t.call(kind+'_role', 'POST', role(kind), {'token_type': kind, 'token_policies': [POLICY],
                'token_ttl': 1800, 'token_max_ttl': 3600, 'secret_id_ttl': 1800,
                'secret_id_num_uses': 0, 'secret_id_bound_cidrs': ['127.0.0.1/32']}, status=204)
            rid = t.call(kind+'_role_id', 'GET', role(kind)+'/role-id')['data']['role_id']
            creds = {}
            for env, uses in (('one', 0), ('two', 3)):
                data = t.call(kind+'_'+env+'_sid', 'POST', role(kind)+'/secret-id',
                    {'metadata': json.dumps(metadata(env)), 'num_uses': uses})['data']
                creds[env] = {'role_id': rid, 'secret_id': data['secret_id']}
                t.sid(kind+'_'+env+'_raw', kind, creds[env], uses, env)
            first = follower(kind+'_one').login(kind+'_one', kind, creds['one'], 'one')
            entity = t.call(kind+'_entity', 'GET', 'identity/entity/id/'+first['entity_id'])['data']
            aliases = [a for a in entity.get('aliases', []) if a.get('name') == rid]
            t.check(kind+'_unique_alias', len(aliases) == 1); alias = aliases[0]
            t.call(kind+'_custom', 'POST', 'identity/entity-alias/id/'+alias['id'],
                {'name': rid, 'canonical_id': first['entity_id'], 'mount_accessor': alias['mount_accessor'],
                 'custom_metadata': CUSTOM})
            original_alias = t.alias(kind+'_original_alias', alias['id'])
            # Both denials consume the finite SID once. Source rejection precedes
            # alias update; native disabled-Identity rejection persists backend metadata.
            follower(kind+'_source').call(kind+'_source', 'POST', f'auth/{MOUNT}/login', creds['two'],
                token='', source='127.0.0.2', spoof=True, wrap_ttl='30s', status=400)
            t.sid(kind+'_source', kind, creds['two'], 2, 'two')
            t.check(kind+'_source_alias_unchanged', t.alias(kind+'_source_alias', alias['id']) == original_alias)
            t.call(kind+'_disable_identity', 'POST', 'identity/entity/id/'+first['entity_id'], {'disabled': True}, status=204)
            follower(kind+'_disabled').call(kind+'_disabled', 'POST', f'auth/{MOUNT}/login', creds['two'],
                token='', wrap_ttl='30s', status=403)
            t.sid(kind+'_disabled', kind, creds['two'], 1, 'two')
            t.disabled_alias_refresh(kind+'_disabled_alias', original_alias, kind)
            t.call(kind+'_enable_identity', 'POST', 'identity/entity/id/'+first['entity_id'], {'disabled': False}, status=204)
            second = follower(kind+'_two').login(kind+'_two', kind, creds['two'], 'two')
            t.check(kind+'_wide_metadata', len(second['metadata']) == 65
                and len(json.dumps(second['metadata']).encode()) < 4096)
            t.check(kind+'_same_entity', first['entity_id'] == second['entity_id'] and first['client_token'] != second['client_token'])
            deleted = t.call(kind+'_two_raw', 'POST', role(kind)+'/secret-id/lookup', {'secret_id': creds['two']['secret_id']}, status=204)
            t.check(kind+'_two_consumed', not any(deleted.get(k) for k in ('data', 'auth', 'wrap_info')))
            current_alias = t.alias(kind+'_updated_alias', alias['id'])
            t.check(kind+'_alias_backend', current_alias.get('metadata') == metadata('two', kind))
            t.check(kind+'_alias_custom', current_alias.get('custom_metadata') == CUSTOM)
            t.call(kind+'_one_deleted', 'POST', role(kind)+'/secret-id/destroy', {'secret_id': creds['one']['secret_id']}, status=204)
            t.call(kind+'_ttl_changed', 'POST', role(kind), {'token_ttl': 900}, status=204)
            renew_one(t, 'after_delete', kind, first)
            held[kind] = {'one': first, 'two': second, 'alias': alias}
        # Force one actual snapshot while the third voter has no metadata writes.
        leader = cluster.leader(); t = trace(leader)
        prior = t.call('before_compact', 'GET', 'sys/storage/raft/snapshot-status')['data']
        t.check('current_frontier', snapshot_frontier(prior))
        target = prior['applied_index']
        t.call('compact', 'POST', 'sys/storage/raft/compact', {})
        deadline = time.monotonic()+15; frontier = {}
        while True:
            response = t.client.request('GET', 'sys/storage/raft/snapshot-status')
            frontier = response.body.get('data') or {}
            if response.status != 200 or not snapshot_frontier(frontier):
                raise ScenarioFailure('snapshot_frontier_read_invalid')
            if frontier['purged_index'] >= target and frontier['purged_index'] > before['applied_index']: break
            if time.monotonic() >= deadline: raise ScenarioFailure('snapshot_purge_not_observed')
            time.sleep(.1)
        t.check('purged_past_lagger', True)
        observations['frontier'] = {k: frontier[k] for k in ('applied_index','snapshot_index','purged_index')}
        observations['leader_snapshot'] = wait_snapshot(leader, target); t.check('leader_snapshot', True)
        lagger.start(); observations['lagger_snapshot'] = wait_snapshot(lagger, target); t.check('lagger_snapshot', True)
        trace(lagger).call('lagger_unseal', 'POST', 'sys/unseal', {'key': cluster.unseal_key})
        verify_voters(cluster, trace, held, 'snapshot')
        leader = cluster.leader(); trace(leader).call('stepdown', 'POST', 'sys/step-down', {}, status=204)
        successor = cluster.leader(); t.check('successor_changed', successor.node_id != leader.node_id)
        status, body = leader.call('GET', 'sys/leader', timeout=5)
        t.check('former_leader_standby', standby_response(status, body, f'https://127.0.0.1:{successor.http_port}'))
        verify_voters(cluster, trace, held, 'successor')
        restart_cluster(cluster, t.check, 'full_restart')
        verify_voters(cluster, trace, held, 'restarted')
        for kind in KINDS: renew_one(follower('restart_'+kind), 'after_restart', kind, held[kind]['one'])
        cluster.close(); t.check('processes_stopped', all(n.process is None for n in cluster.nodes))
        paths = []
        for node in cluster.nodes:
            paths.extend(p for base in (node.data_dir, node.root/'raft') for p in base.rglob('*'))
            paths.extend((node.root/'process.log', node.root/'audit.jsonl'))
        t.check('secrets_absent', bool(paths) and secret_free(paths, sensitive)
            and report_secret_free({'checks': rows, 'bootstrap': bootstrap, 'observations': observations}, sensitive))
        t.check('complete', True)
    finally:
        if cluster is not None: cluster.close()


def helpers():
    names = ('bao_http','heptabao.transport','core_isolation','online_evidence','native_snapshot_ha_live',
        'ha_destructive','ha_network_partition','radius_cidrs_live','approle_secret_cidrs_ha','userpass_batch_ha',
        'userpass_password_live','userpass_params_ha','jwt_batch_ha','kv1_record_ha_live',
        'raft_record_snapshot_observation','raft_snapshot_observation')
    result = {name:file_hash(Path(importlib.import_module(name).__file__)) for name in names}
    digest = file_hash(ROOT/'qa/openbao-acceptance/evidence'/CALIBRATION)
    if digest != CALIBRATION_SHA: raise ScenarioFailure('official_metadata_calibration_changed')
    result['official_metadata_calibration'] = digest
    return result


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
    if before['source_dirty']: p.error('clean_harness_required')
    work = Path(tempfile.mkdtemp(prefix='approle-secretid-metadata-ha-', dir=private_parent(args.work_parent)))
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
    report = {'schema': 'heptabao.approle-secretid-metadata-ha.v1', 'status': 'failed' if failure else 'passed',
        'failure': failure, 'checks': rows, 'bootstrap_checks': bootstrap, 'observations': observations,
        'source_identity': before, 'source_identity_after': after, 'source_and_binary_unchanged': source_ok,
        'build_source_commit': args.build_source_commit, 'runner_sha256': runner, 'runner_unchanged': runner_ok,
        'helper_sha256': helper, 'helpers_unchanged': helper_ok, 'node_count': 3, 'listener_timeout_seconds': 5,
        'snapshot_read_only_wait_seconds': 15, 'mutation_retries': 0,
        'scope': 'two SIDs per service/batch role, affine source/Identity denials, native disabled-Identity alias refresh, metadata snapshots, actual Raft snapshot catch-up, stepdown/restart',
        'no_wrapper_evidence': 'denied wrapped requests return no wrapper; no private wrapper inventory is exposed',
        'wide_metadata_profile': 'second SID updates existing alias with 65 string fields; complete batch claims remain bounded',
        'direct_local_follower_reads_claimed': False, 'unknown_commit_faults_covered': False,
        'native_application_snapshot_restore_covered': False, 'physical_failure_covered': False,
        'ipv6_covered': False, 'actual_openbao_comparison': False, 'full_openbao_compatibility': False,
        'synthetic_only': True, 'retained_failure_work_dir': str(work) if failure else None}
    if not report_secret_free(report, samples): raise ValueError('sensitive_report_rejected')
    if admit_output(output) != admitted: raise ValueError('output_parent_changed')
    private_write(output, report, replace=False)
    if failure is None: shutil.rmtree(work)
    print(json.dumps({'status': report['status'], 'checks': len(rows), 'failure': failure}))
    return int(failure is not None)


if __name__ == '__main__': raise SystemExit(main())
