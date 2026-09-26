#!/usr/bin/env python3
"""Three real TLS voters: role SecretID CIDRs, affine consumption and peer forwarding."""
from __future__ import annotations
import importlib
import json
from pathlib import Path
import re
import shutil
import signal
import tempfile

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from online_evidence import admit_output, complete_checks, source_identity
from approle_cidrs_ha import Trace as BaseTrace, rows_secret_free
from native_snapshot_ha_live import SaveCluster
from radius_cidrs_live import SourceClient
from userpass_batch_ha import standby_response
from userpass_password_live import private_parent
from userpass_params_ha import projection, secret_free

MOUNT, KV, POLICY = 'approle-secret-cidrs-ha', 'approle-secret-cidrs-kv', 'approle-secret-cidrs-ha'
KINDS, LABELS = ('service', 'batch'), ('two', 'one', 'unlimited')
PHASES = ('denied', 'successor', 'restarted', 'consumed', 'cleared_restart')
EARLY = frozenset(('denied', 'successor', 'restarted'))
FIELD = 'secret_id_bound_cidrs'
BOUND = ['127.0.0.1/32']


def token_names(phase):
    if phase not in PHASES: raise ScenarioFailure('unknown_phase')
    return ('unbound', 'split') + (() if phase in EARLY else ('finite',)) + (('cleared',) if phase == 'cleared_restart' else ())


REQUIRED = frozenset({'three_processes', 'five_second_listeners', 'setup_standby',
    'stepdown_status', 'successor_changed', 'former_leader_standby', 'first_restart',
    'final_restart', 'processes_stopped', 'secrets_absent', 'complete'}
    | {f'{kind}_{label}_denied_rejected' for kind in KINDS for label in LABELS}
    | {f'{kind}_{label}_denial_standby' for kind in KINDS for label in LABELS}
    | {f'{kind}_{label}_baseline_uses' for kind in KINDS for label in LABELS}
    | {f'{kind}_{label}_forwarded_issued' for kind in KINDS for label in ('unbound', 'split', 'finite', 'cleared')}
    | {f'{kind}_finite_standby' for kind in KINDS}
    | {f'{kind}_unlimited_unchanged' for kind in KINDS}
    | {f'{kind}_one_allowed_rejected' for kind in KINDS}
    | {f'{kind}_finite_repeat_rejected' for kind in KINDS}
    | {f'{kind}_{label}_cleared_shape' for kind in KINDS for label in (*LABELS, 'split')}
    | {f'{phase}_all_voters' for phase in PHASES}
    | {f'{phase}_n{node}_{kind}_{label}_snapshot' for phase in PHASES for node in (1, 2, 3)
       for kind in KINDS for label in LABELS}
    | {f'{phase}_n{node}_{kind}_{name}_{case}' for phase in PHASES for node in (1, 2, 3)
       for kind in KINDS for name in token_names(phase) for case in ('foreign_value', 'foreign_shape')}
    | {f'{phase}_n{node}_{kind}_split_original_rejected' for phase in PHASES for node in (1, 2, 3) for kind in KINDS})


def complete(rows):
    return complete_checks(rows, required_cases=REQUIRED) and rows[-1]['case'] == 'complete'


def role_path(kind, label): return f'auth/{MOUNT}/role/{kind}-{label}'


class Trace(BaseTrace):
    def check(self, name, passed):
        if any(row['case'] == name for row in self.rows): raise ScenarioFailure('duplicate_case')
        super().check(name, passed)

    def login(self, name, kind, label, credentials, *, source='127.0.0.1', status=200, spoof=False):
        result = self.call(name, 'POST', f'auth/{MOUNT}/login',
            {'role_id': credentials['role_id'], 'secret_id': credentials['secret_id']},
            token='', source=source, status=status, spoof=spoof)
        if status != 200: return None
        auth = result.get('auth') or {}
        self.check(name+'_issued', isinstance(auth.get('client_token'), str)
            and bool(auth['client_token']) and auth.get('token_type') == kind
            and bool(auth.get('accessor')) == (kind == 'service')
            and auth.get('renewable') is (kind == 'service')
            and auth.get('metadata') == {'role_name': kind+'-'+label}
            and type(auth.get('lease_duration')) is int and auth['lease_duration'] > 0)
        self.remember(auth, 'client_token', 'accessor')
        return auth

    def read(self, name, auth, *, source='127.0.0.2', status=200, spoof=False):
        body = self.call(name, 'GET', KV+'/item', token=auth['client_token'], source=source, status=status, spoof=spoof)
        if status == 200: self.check(name+'_value', body.get('data') == {'value': 'synthetic'})

    def sid(self, name, kind, label, credentials, *, uses):
        path = role_path(kind, label)
        body = self.call(name+'_raw', 'POST', path+'/secret-id/lookup',
            {'secret_id': credentials['secret_id']}, status=204 if uses is None else 200)
        if uses is None:
            self.check(name+'_raw_empty', not any(body.get(key) for key in ('auth', 'data', 'wrap_info')))
            self.call(name+'_accessor', 'POST', path+'/secret-id-accessor/lookup',
                {'secret_id_accessor': credentials['secret_id_accessor']}, status=404)
            return None
        data = body.get('data') or {}
        self.check(name+'_uses', type(data.get('secret_id_num_uses')) is int
            and data['secret_id_num_uses'] == uses
            and data.get('secret_id_accessor') == credentials['secret_id_accessor'])
        return data


def lookup_shape(data, auth, kind, label, bounds):
    return (isinstance(data, dict) and data.get('id') == auth['client_token']
        and data.get('type') == kind and data.get('bound_cidrs', []) == bounds
        and type(data.get('ttl')) is int and data['ttl'] > 0
        and data.get('meta') == {'role_name': kind+'-'+label}
        and bool(data.get('accessor')) == (kind == 'service')
        and data.get('renewable') is (kind == 'service'))


def verify_voters(cluster, trace, credentials, snapshots, tokens, phase):
    if len(cluster.nodes) != 3 or {n.node_id for n in cluster.nodes} != {1, 2, 3}:
        raise ScenarioFailure('three_distinct_voters_required')
    if (phase not in PHASES or set(credentials) != set(KINDS) or set(snapshots) != set(KINDS)
        or set(tokens) != set(KINDS) or any(set(credentials[k]) != set(LABELS) | {'split'}
        or set(snapshots[k]) != set(LABELS) or set(tokens[k]) != set(token_names(phase)) for k in KINDS)):
        raise ScenarioFailure('complete_secret_token_matrix_required')
    views = []
    for node in cluster.nodes:
        t, view = trace(node), []
        for kind in KINDS:
            for label in LABELS:
                name = f'{phase}_n{node.node_id}_{kind}_{label}'
                uses = 0 if label == 'unlimited' else 1 if label == 'two' and phase in EARLY else None
                data = t.sid(name, kind, label, credentials[kind][label], uses=uses)
                # Complete SID query data includes absolute expiry and last-use
                # metadata. Restart/step-down cannot silently consume it again.
                expected = snapshots[kind][label] if uses is not None else None
                t.check(name+'_snapshot', data == expected)
                view.append(data)
            for name in token_names(phase):
                auth = tokens[kind][name]; prefix = f'{phase}_n{node.node_id}_{kind}_{name}'
                t.read(prefix+'_foreign', auth)
                data = t.call(prefix+'_lookup', 'GET', 'auth/token/lookup-self',
                    token=auth['client_token'], source='127.0.0.2').get('data') or {}
                label = 'two' if name == 'finite' else 'split' if name == 'split' else 'unlimited'
                t.check(prefix+'_foreign_shape', lookup_shape(data, auth, kind, label,
                    ['127.0.0.2'] if name == 'split' else []))
                view.append(projection(data))
                if name == 'split': t.read(prefix+'_original', auth, source='127.0.0.1', status=403)
        views.append(view)
    trace(cluster.nodes[0]).check(phase+'_all_voters', all(view == views[0] for view in views))


def restart_cluster(cluster, check, name):
    for node in cluster.nodes: node.stop()
    for node in cluster.nodes: node.start(wait=False)
    for node in cluster.nodes: node.wait_ready()
    cluster.wait_quorum()
    for node in cluster.nodes:
        if node.call('POST', 'sys/unseal', {'key': cluster.unseal_key})[0] != 200:
            raise ScenarioFailure('restart_unseal_failed')
    cluster.leader(); check(name, len(cluster.running()) == 3)


def run(binary, work, rows, bootstrap, diagnostics, sensitive):
    cluster = None
    try:
        cluster = SaveCluster(binary, work/'cluster'); cluster.bootstrap(); bootstrap.extend(cluster.scenarios)
        sensitive.extend((cluster.root_token, cluster.unseal_key, cluster.replication_key))
        def trace(node):
            return Trace(SourceClient(f'https://127.0.0.1:{node.http_port}', cluster.root/'ca.crt',
                cluster.root_token, spoof_source='127.0.0.1'), rows, sensitive)
        def standby(name):
            leader = cluster.leader(); node = next(n for n in cluster.nodes if n.node_id != leader.node_id)
            status, body = node.call('GET', 'sys/leader')
            trace(node).check(name+'_standby', standby_response(status, body, f'https://127.0.0.1:{leader.http_port}'))
            return trace(node)
        t = standby('setup'); t.check('three_processes', len(cluster.running()) == 3)
        t.check('five_second_listeners', all(json.loads((n.root/'server.json').read_text())['timeout_seconds'] == 5 for n in cluster.nodes))
        t.call('mount', 'POST', 'sys/auth/'+MOUNT, {'type': 'approle'}, status=204)
        t.call('kv_mount', 'POST', 'sys/mounts/'+KV, {'type': 'kv', 'options': {'version': '1'}}, status=204)
        t.call('kv_seed', 'POST', KV+'/item', {'value': 'synthetic'}, status=204)
        t.call('policy', 'PUT', 'sys/policies/acl/'+POLICY,
            {'policy': 'path "'+KV+'/*" { capabilities=["read"] }'}, status=204)
        credentials, snapshots, tokens = {}, {}, {}
        for kind in KINDS:
            credentials[kind], snapshots[kind], tokens[kind] = {}, {}, {}
            for label, uses in (('two', 2), ('one', 1), ('unlimited', 0), ('split', 0)):
                path = role_path(kind, label); prefix = kind+'_'+label
                fields = {'token_type': kind, 'token_policies': [POLICY], 'token_ttl': 1800,
                    'token_max_ttl': 3600, 'secret_id_num_uses': uses, FIELD: BOUND}
                if label == 'split': fields['token_bound_cidrs'] = ['127.0.0.2/32']
                t.call(prefix+'_role', 'POST', path, fields, status=204)
                rid = t.call(prefix+'_roleid', 'GET', path+'/role-id')['data']['role_id']
                sid = t.call(prefix+'_sid_issue', 'POST', path+'/secret-id', {})['data']
                sensitive.append(rid); t.remember(sid, 'secret_id', 'secret_id_accessor')
                credentials[kind][label] = dict(sid, role_id=rid)
                if label in LABELS:
                    snapshots[kind][label] = t.sid(prefix+'_baseline', kind, label, credentials[kind][label], uses=uses)
            for name, label in (('unbound', 'unlimited'), ('split', 'split')):
                tokens[kind][name] = standby(kind+'_'+name+'_issue').login(kind+'_'+name+'_forwarded',
                    kind, label, credentials[kind][label])
            for label in LABELS:
                standby(kind+'_'+label+'_denial').login(kind+'_'+label+'_denied', kind, label,
                    credentials[kind][label], source='127.0.0.2', status=400, spoof=True)
                after = t.sid(kind+'_'+label+'_after_denial', kind, label, credentials[kind][label],
                    uses=1 if label == 'two' else 0 if label == 'unlimited' else None)
                if label == 'unlimited': t.check(kind+'_unlimited_unchanged', after == snapshots[kind][label])
                snapshots[kind][label] = after
        verify_voters(cluster, trace, credentials, snapshots, tokens, 'denied')
        leader = cluster.leader(); trace(leader).call('stepdown', 'POST', 'sys/step-down', {}, status=204)
        successor = cluster.leader(); t.check('successor_changed', successor.node_id != leader.node_id)
        status, body = leader.call('GET', 'sys/leader')
        t.check('former_leader_standby', standby_response(status, body, f'https://127.0.0.1:{successor.http_port}'))
        verify_voters(cluster, trace, credentials, snapshots, tokens, 'successor')
        restart_cluster(cluster, t.check, 'first_restart')
        verify_voters(cluster, trace, credentials, snapshots, tokens, 'restarted')
        for kind in KINDS:
            current = standby(kind+'_finite')
            tokens[kind]['finite'] = current.login(kind+'_finite_forwarded', kind, 'two', credentials[kind]['two'])
            current.login(kind+'_one_allowed', kind, 'one', credentials[kind]['one'], status=400)
            current.login(kind+'_finite_repeat', kind, 'two', credentials[kind]['two'], status=400)
        verify_voters(cluster, trace, credentials, snapshots, tokens, 'consumed')
        for kind in KINDS:
            current = standby(kind+'_clear')
            for label in (*LABELS, 'split'):
                path = role_path(kind, label)
                current.call(kind+'_'+label+'_clear', 'POST', path, {FIELD: []}, status=204)
                data = current.call(kind+'_'+label+'_clear_read', 'GET', path)['data']
                current.check(kind+'_'+label+'_cleared_shape', data.get(FIELD) == [])
            tokens[kind]['cleared'] = current.login(kind+'_cleared_forwarded', kind, 'unlimited',
                credentials[kind]['unlimited'], source='127.0.0.2')
        restart_cluster(cluster, t.check, 'final_restart')
        verify_voters(cluster, trace, credentials, snapshots, tokens, 'cleared_restart')
        cluster.close(); t.check('processes_stopped', all(n.process is None for n in cluster.nodes))
        paths = []
        for node in cluster.nodes:
            paths.extend(p for folder in (node.data_dir, node.root/'raft') for p in folder.rglob('*'))
            paths.extend((node.root/'process.log', node.root/'audit.jsonl'))
        t.check('secrets_absent', bool(paths) and secret_free(paths, sensitive)
            and rows_secret_free({'checks': rows, 'bootstrap': bootstrap, 'diagnostics': diagnostics}, sensitive))
        t.check('complete', True)
    except Exception:
        if cluster is not None:
            for node in cluster.running():
                try:
                    status, body = node.call('GET', 'sys/health', timeout=2)
                    diagnostics.append({'node_id': node.node_id, 'status': status,
                        **{k: body[k] for k in ('sealed', 'standby', 'ha_active', 'ha_application_ready') if type(body.get(k)) is bool}})
                except Exception: diagnostics.append({'node_id': node.node_id, 'unavailable': True})
        raise
    finally:
        if cluster is not None: cluster.close()


def helpers():
    names = ('bao_http', 'heptabao.transport', 'core_isolation', 'online_evidence', 'ha_destructive',
        'ha_network_partition', 'native_snapshot_ha_live', 'userpass_batch_ha', 'radius_cidrs_live',
        'approle_cidrs_ha', 'userpass_params_ha', 'userpass_password_live')
    result = {name: file_hash(Path(importlib.import_module(name).__file__)) for name in names}
    result['official_source_cidr_calibration'] = file_hash(ROOT/'qa/openbao-acceptance/evidence/approle-secret-cidrs-official-2df0658.json')
    return result


def main():
    p = SafeArgumentParser(description=__doc__)
    for name in ('binary', 'work-parent', 'output'): p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--build-source-commit', required=True); p.add_argument('--expected-binary-sha256', required=True)
    args = p.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.build_source_commit) or not re.fullmatch('[0-9a-f]{64}', args.expected_binary_sha256):
        p.error('candidate_pins_required')
    binary = args.binary.resolve(strict=True)
    if file_hash(binary) != args.expected_binary_sha256: p.error('candidate_binary_mismatch')
    output = args.output.absolute(); admitted = admit_output(output)
    before, runner, helper = source_identity(ROOT, binary), file_hash(Path(__file__)), helpers()
    work = Path(tempfile.mkdtemp(prefix='approle-secret-cidrs-ha-', dir=private_parent(args.work_parent)))
    rows, bootstrap, diagnostics, sensitive, failure = [], [], [], [], None
    def interrupted(signum, frame): raise ScenarioFailure('fixture_interrupted')
    handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try: run(binary, work, rows, bootstrap, diagnostics, sensitive)
    except Exception as error:
        failure = next((r['case'] for r in reversed(rows) if r['passed'] is not True), 'fixture_'+type(error).__name__)
    finally:
        for sig, handler in handlers.items(): signal.signal(sig, handler)
    after = source_identity(ROOT, binary)
    unchanged = before == after and after['binary_sha256'] == args.expected_binary_sha256
    runner_ok, helper_ok = file_hash(Path(__file__)) == runner, helpers() == helper
    if not unchanged or not runner_ok or not helper_ok: failure = 'source_binary_or_helpers_changed'
    if before['source_dirty'] or after['source_dirty']: failure = 'source_dirty'
    if not complete(rows) or not bootstrap: failure = failure or 'incomplete_observations'
    report = {'schema': 'heptabao.approle-secret-cidrs-ha.v1', 'status': 'failed' if failure else 'passed',
        'failure': failure, 'checks': rows, 'bootstrap_checks': bootstrap, 'diagnostics': diagnostics,
        'source_identity': before, 'source_identity_after': after, 'source_and_binary_unchanged': unchanged,
        'build_source_commit': args.build_source_commit, 'runner_sha256': runner, 'runner_unchanged': runner_ok,
        'helper_sha256': helper, 'helpers_unchanged': helper_ok, 'node_count': 3, 'listener_timeout_seconds': 5,
        'real_source_addresses': ['127.0.0.1', '127.0.0.2'], 'mutation_retries': 0,
        'credential_snapshot_basis': 'authenticated HTTPS raw/accessor lookup through all three voter listeners',
        'direct_local_follower_reads_claimed': False, 'physical_fault_qualification': False,
        'snapshot_restore_covered': False, 'per_secret_id_CIDR_overrides_covered': False,
        'full_openbao_compatibility': False, 'synthetic_only': True,
        'retained_failure_work_dir': str(work) if failure else None}
    if not rows_secret_free(report, sensitive): raise ValueError('sensitive_report_rejected')
    if admit_output(output) != admitted: raise ValueError('report_parent_changed')
    private_write(output, report, replace=False)
    if failure is None: shutil.rmtree(work)
    print(json.dumps({'status': report['status'], 'checks': len(rows), 'failure': failure}))
    return int(failure is not None)


if __name__ == '__main__': raise SystemExit(main())
