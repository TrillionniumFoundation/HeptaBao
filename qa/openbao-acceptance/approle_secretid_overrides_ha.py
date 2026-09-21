#!/usr/bin/env python3
"""Three TLS voters: SecretID issuance overrides and affine failed-login consumption."""
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
from approle_secret_cidrs_ha import Trace as SecretTrace, MOUNT, KV, POLICY, KINDS, role_path, lookup_shape, restart_cluster
from approle_cidrs_ha import rows_secret_free
from native_snapshot_ha_live import SaveCluster
from radius_cidrs_live import SourceClient
from userpass_batch_ha import standby_response
from userpass_password_live import private_parent
from userpass_params_ha import projection, secret_free

CALIBRATION = 'approle-secretid-overrides-official-c54e9b0.json'
CALIBRATION_SHA = 'f3be3085aec18b4bc81b749e35b510de72b5645a6217170058d307d03b491a2e'
SOURCE_FIELD, TOKEN_FIELD = 'secret_id_bound_cidrs', 'token_bound_cidrs'
BROAD, FIRST, SECOND = ['127.0.0.0/8'], ['127.0.0.1/32'], ['127.0.0.2/32']
SID_LABELS = ('finite', 'subset', 'one', 'unlimited')
TOKEN_LABELS = ('finite', 'override_changed', 'override_cleared', 'empty_current', 'none_current', 'empty_cleared', 'none_cleared')
# Values are (the actual issuing role label, issued token CIDR snapshot).
TOKEN_CONTRACT = {'finite': ('finite', ['127.0.0.2']),
    'override_changed': ('unlimited', ['127.0.0.2']), 'override_cleared': ('unlimited', ['127.0.0.2']),
    'empty_current': ('empty', ['127.0.0.2']), 'none_current': ('none', ['127.0.0.2']),
    'empty_cleared': ('empty', []), 'none_cleared': ('none', [])}
REQUIRED = frozenset({'three_processes', 'five_second_listeners', 'setup_standby',
    'stepdown_status', 'successor_changed', 'former_leader_standby', 'first_restart',
    'final_restart', 'processes_stopped', 'secrets_absent', 'complete'}
    | {f'{k}_{label}_denial_standby' for k in KINDS for label in SID_LABELS}
    | {f'{k}_{label}_denied_rejected' for k in KINDS for label in SID_LABELS}
    | {f'{k}_unlimited_unchanged' for k in KINDS}
    | {f'{k}_subset_denied_subset_error' for k in KINDS}
    | {f'{k}_{label}_repeat_rejected' for k in KINDS for label in ('finite', 'subset', 'one')}
    | {f'{k}_{label}_issued' for k in KINDS for label in ('finite', 'subset', *TOKEN_LABELS[1:])}
    | {f'{k}_{label}_current_source_rejected' for k in KINDS for label in ('empty', 'none')}
    | {f'{phase}_all_voters' for phase in ('successor', 'restarted', 'final_sids', 'final_tokens')}
    | {f'{phase}_n{n}_{k}_{label}_snapshot' for phase in ('successor', 'restarted', 'final_sids')
       for n in (1, 2, 3) for k in KINDS for label in SID_LABELS}
    | {f'final_tokens_n{n}_{k}_{label}_shape' for n in (1, 2, 3) for k in KINDS for label in TOKEN_LABELS}
    | {f'final_tokens_n{n}_{k}_{label}_original_rejected' for n in (1, 2, 3)
       for k in KINDS for label in TOKEN_LABELS if TOKEN_CONTRACT[label][1]})


class Trace(SecretTrace):
    def call(self, name, method, path, body=None, **kwargs):
        result = super().call(name, method, path, body, **kwargs)
        if kwargs.get('status') == 500:
            errors = result.get('errors')
            self.check(name+'_subset_error', isinstance(errors, list)
                and all(isinstance(e, str) for e in errors)
                and any('subset' in e.lower() for e in errors))
        return result


def complete(rows):
    return complete_checks(rows, required_cases=REQUIRED) and rows[-1]['case'] == 'complete'


def distinct_voters(cluster):
    if len(cluster.nodes) != 3 or {n.node_id for n in cluster.nodes} != {1, 2, 3}:
        raise ScenarioFailure('three_distinct_voters_required')


def verify_credentials(cluster, trace, credentials, snapshots, phase, *, consumed=False):
    distinct_voters(cluster)
    if (phase not in ('successor', 'restarted', 'final_sids') or set(credentials) != set(KINDS)
        or set(snapshots) != set(KINDS) or any(not set(SID_LABELS).issubset(credentials[k])
        or set(snapshots[k]) != set(SID_LABELS) for k in KINDS)):
        raise ScenarioFailure('complete_secret_matrix_required')
    if consumed != (phase == 'final_sids'): raise ScenarioFailure('phase_consumption_mismatch')
    views = []
    for node in cluster.nodes:
        t, view = trace(node), []
        for kind in KINDS:
            for label in SID_LABELS:
                name = f'{phase}_n{node.node_id}_{kind}_{label}'
                uses = 0 if label == 'unlimited' else None if consumed or label == 'one' else 1
                data = t.sid(name, kind, label, credentials[kind][label], uses=uses)
                t.check(name+'_snapshot', data == (snapshots[kind][label] if uses is not None else None))
                view.append(data)
        views.append(view)
    trace(cluster.nodes[0]).check(phase+'_all_voters', all(v == views[0] for v in views))


def verify_tokens(cluster, trace, tokens):
    distinct_voters(cluster)
    if set(tokens) != set(KINDS) or any(set(tokens[k]) != set(TOKEN_LABELS) for k in KINDS):
        raise ScenarioFailure('complete_token_matrix_required')
    views = []
    for node in cluster.nodes:
        t, view = trace(node), []
        for kind in KINDS:
            for label in TOKEN_LABELS:
                auth = tokens[kind][label]; role, bounds = TOKEN_CONTRACT[label]
                name = f'final_tokens_n{node.node_id}_{kind}_{label}'
                t.read(name+'_foreign', auth)  # Real bearer request from .2, not root lookup.
                data = t.call(name+'_lookup', 'GET', 'auth/token/lookup-self',
                    token=auth['client_token'], source='127.0.0.2').get('data') or {}
                t.check(name+'_shape', lookup_shape(data, auth, kind, role, bounds))
                # Even after current-role clearing, issued .2 tokens must reject .1.
                t.read(name+'_original', auth, source='127.0.0.1', status=403 if bounds else 200)
                view.append(projection(data))
        views.append(view)
    trace(cluster.nodes[0]).check('final_tokens_all_voters', all(v == views[0] for v in views))


def issue(t, kind, label, uses, fields):
    path, name = role_path(kind, label), kind+'_'+label
    t.call(name+'_role', 'POST', path, {'token_type': kind, 'token_policies': [POLICY],
        'token_ttl': 1800, 'token_max_ttl': 3600, 'secret_id_num_uses': uses,
        SOURCE_FIELD: BROAD, TOKEN_FIELD: BROAD}, status=204)
    rid = t.call(name+'_roleid', 'GET', path+'/role-id')['data']['role_id']
    sid = t.call(name+'_sid_issue', 'POST', path+'/secret-id', fields)['data']
    t.sensitive.append(rid); t.remember(sid, 'secret_id', 'secret_id_accessor')
    return dict(sid, role_id=rid)


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
            for label, uses in (('finite', 2), ('subset', 2), ('one', 1), ('unlimited', 0)):
                credentials[kind][label] = issue(t, kind, label, uses, {'cidr_list': FIRST, TOKEN_FIELD: SECOND})
                snapshots[kind][label] = t.sid(kind+'_'+label+'_baseline', kind, label, credentials[kind][label], uses=uses)
            for label in ('empty', 'none'):
                fields = {'cidr_list': [], TOKEN_FIELD: []} if label == 'empty' else {}
                credentials[kind][label] = issue(t, kind, label, 0, fields)
            # Current-role source subset failure is 500, after affine use consumption.
            t.call(kind+'_subset_narrow', 'POST', role_path(kind, 'subset'), {SOURCE_FIELD: SECOND}, status=204)
            for label in SID_LABELS:
                is_subset = label == 'subset'
                standby(kind+'_'+label+'_denial').login(kind+'_'+label+'_denied', kind, label,
                    credentials[kind][label], source='127.0.0.1' if is_subset else '127.0.0.2',
                    status=500 if is_subset else 400, spoof=not is_subset)
                after = t.sid(kind+'_'+label+'_after_denial', kind, label, credentials[kind][label],
                    uses=0 if label == 'unlimited' else None if label == 'one' else 1)
                if label == 'unlimited': t.check(kind+'_unlimited_unchanged', after == snapshots[kind][label])
                snapshots[kind][label] = after
        leader = cluster.leader(); trace(leader).call('stepdown', 'POST', 'sys/step-down', {}, status=204)
        successor = cluster.leader(); t.check('successor_changed', successor.node_id != leader.node_id)
        status, body = leader.call('GET', 'sys/leader')
        t.check('former_leader_standby', standby_response(status, body, f'https://127.0.0.1:{successor.http_port}'))
        verify_credentials(cluster, trace, credentials, snapshots, 'successor')
        restart_cluster(cluster, t.check, 'first_restart')
        verify_credentials(cluster, trace, credentials, snapshots, 'restarted')
        for kind in KINDS:
            current = standby(kind+'_completion')
            current.call(kind+'_subset_repair', 'POST', role_path(kind, 'subset'), {SOURCE_FIELD: BROAD}, status=204)
            for label in ('finite', 'subset'):
                auth = current.login(kind+'_'+label, kind, label, credentials[kind][label])
                current.read(kind+'_'+label+'_issued_foreign', auth)
                current.read(kind+'_'+label+'_issued_original', auth, source='127.0.0.1', status=403)
                if label == 'finite': tokens[kind][label] = auth
                current.login(kind+'_'+label+'_repeat', kind, label, credentials[kind][label], status=400)
            current.login(kind+'_one_repeat', kind, 'one', credentials[kind]['one'], status=400)
            # Nonempty per-SID bearer CIDRs survive both incompatible role change and clearing.
            for label, bounds in (('override_changed', FIRST), ('override_cleared', [])):
                current.call(kind+'_'+label+'_role', 'POST', role_path(kind, 'unlimited'), {TOKEN_FIELD: bounds}, status=204)
                tokens[kind][label] = current.login(kind+'_'+label, kind, 'unlimited', credentials[kind]['unlimited'])
            # Both absent and explicitly empty SID overrides defer to the current role.
            for label in ('empty', 'none'):
                path = role_path(kind, label)
                current.call(kind+'_'+label+'_narrow', 'POST', path, {SOURCE_FIELD: SECOND, TOKEN_FIELD: SECOND}, status=204)
                current.login(kind+'_'+label+'_current_source', kind, label, credentials[kind][label], status=400)
                tokens[kind][label+'_current'] = current.login(kind+'_'+label+'_current', kind, label,
                    credentials[kind][label], source='127.0.0.2')
                current.call(kind+'_'+label+'_clear', 'POST', path, {SOURCE_FIELD: [], TOKEN_FIELD: []}, status=204)
                tokens[kind][label+'_cleared'] = current.login(kind+'_'+label+'_cleared', kind, label, credentials[kind][label])
        restart_cluster(cluster, t.check, 'final_restart')
        verify_credentials(cluster, trace, credentials, snapshots, 'final_sids', consumed=True)
        verify_tokens(cluster, trace, tokens)
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
        'approle_secret_cidrs_ha', 'approle_cidrs_ha', 'userpass_params_ha', 'userpass_password_live')
    result = {name: file_hash(Path(importlib.import_module(name).__file__)) for name in names}
    digest = file_hash(ROOT/'qa/openbao-acceptance/evidence'/CALIBRATION)
    if digest != CALIBRATION_SHA: raise ScenarioFailure('official_contract_receipt_changed')
    result['official_secretid_overrides_calibration'] = digest
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
    if before['source_dirty']: p.error('clean_harness_required')
    work = Path(tempfile.mkdtemp(prefix='approle-secretid-overrides-ha-', dir=private_parent(args.work_parent)))
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
    report = {'schema': 'heptabao.approle-secretid-overrides-ha.v1', 'status': 'failed' if failure else 'passed',
        'failure': failure, 'checks': rows, 'bootstrap_checks': bootstrap, 'diagnostics': diagnostics,
        'source_identity': before, 'source_identity_after': after, 'source_and_binary_unchanged': unchanged,
        'build_source_commit': args.build_source_commit,
        'build_source_binding_basis': 'caller-supplied commit and observed binary hash, not independent build attestation',
        'runner_sha256': runner, 'runner_unchanged': runner_ok, 'helper_sha256': helper, 'helpers_unchanged': helper_ok,
        'node_count': 3, 'listener_timeout_seconds': 5, 'real_source_addresses': ['127.0.0.1', '127.0.0.2'],
        'mutation_retries': 0, 'direct_local_follower_reads_claimed': False,
        'credential_snapshot_basis': 'authenticated raw/accessor HTTPS lookup through all three voter listeners',
        'scope': 'service/batch SecretID source and token overrides, affine denial consumption, stepdown and full restart',
        'actual_openbao_comparison': False, 'ipv6_covered': False, 'unknown_commit_faults_covered': False,
        'physical_fault_qualification': False, 'snapshot_restore_covered': False,
        'full_openbao_compatibility': False, 'synthetic_only': True,
        'retained_failure_work_dir': str(work) if failure else None}
    if not rows_secret_free(report, sensitive): raise ValueError('sensitive_report_rejected')
    if admit_output(output) != admitted: raise ValueError('report_parent_changed')
    private_write(output, report, replace=False)
    if failure is None: shutil.rmtree(work)
    print(json.dumps({'status': report['status'], 'checks': len(rows), 'failure': failure}))
    return int(failure is not None)


if __name__ == '__main__': raise SystemExit(main())
