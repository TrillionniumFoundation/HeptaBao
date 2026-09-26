#!/usr/bin/env python3
"""One three-voter TLS cluster: AppRole token CIDR snapshots and real origin."""
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
from userpass_password_live import private_parent
from userpass_params_ha import projection, secret_free

MOUNT = 'approle-cidrs-ha'
KV = 'approle-cidrs-kv'
POLICY = 'approle-cidrs-ha'
KINDS = ('service', 'batch')
PHASES = ('initial', 'cleared', 'successor', 'restarted')
REQUIRED = frozenset({'three_processes', 'five_second_listeners', 'forwarder_confirmed',
    'stepdown', 'successor_changed', 'former_leader_standby', 'full_restart',
    'processes_stopped', 'secrets_absent', 'complete'}
    | {kind + suffix for kind in KINDS for suffix in
       ('_forwarded_issued', '_sid_consumed_once', '_clear_role', '_clear_login_issued')}
    | {phase + '_all_voters' for phase in PHASES}
    | {f'{phase}_n{node}_{kind}_{case}' for phase in PHASES for node in (1, 2, 3)
       for kind in KINDS for case in ('allowed_kv_value', 'allowed_lookup_shape',
           'denied_kv_rejected', 'spoofed_kv_rejected', 'denied_lookup_rejected',
           'root_target_shape')}
    | {f'{phase}_n{node}_{kind}_new_allowed_value' for phase in PHASES if phase != 'initial'
       for node in (1, 2, 3) for kind in KINDS})


def complete(rows):
    return complete_checks(rows, required_cases=REQUIRED) and rows[-1]['case'] == 'complete'


def rows_secret_free(rows, sensitive):
    encoded = json.dumps(rows).encode()
    return not any((value.encode() if isinstance(value, str) else value) in encoded for value in sensitive)


def helpers():
    names = ('bao_http', 'heptabao.transport', 'core_isolation', 'online_evidence',
        'ha_destructive', 'ha_network_partition', 'native_snapshot_ha_live',
        'userpass_batch_ha', 'radius_cidrs_live', 'userpass_password_live', 'userpass_params_ha')
    return {name: file_hash(Path(importlib.import_module(name).__file__)) for name in names}


def lookup_shape(data, auth, kind, bounds):
    return (isinstance(data, dict) and data.get('id') == auth['client_token']
        and data.get('type') == kind and data.get('bound_cidrs', []) == bounds
        and type(data.get('ttl')) is int and data['ttl'] > 0
        and data.get('meta') == {'role_name': kind}
        and bool(data.get('accessor')) == (kind == 'service')
        and data.get('renewable') is (kind == 'service'))


class Trace:
    def __init__(self, client, rows, sensitive):
        self.client, self.rows, self.sensitive = client, rows, sensitive

    def remember(self, data, *keys):
        self.sensitive.extend(data[key] for key in keys
                              if isinstance(data.get(key), str) and data[key])

    def check(self, name, passed):
        if not re.fullmatch(r'[a-z0-9_]{1,120}', name) or type(passed) is not bool:
            raise ScenarioFailure('unsafe_observation')
        self.rows.append({'case': name, 'passed': passed})
        if not passed:
            raise ScenarioFailure(name)

    def call(self, name, method, path, body=None, *, status=200, token=None,
             source='127.0.0.1', spoof=False):
        result = self.client.request(method, path, body, token=token, source=source, spoof=spoof)
        self.check(name + '_status', result.status == status)
        self.check(name + '_ipv4', self.client.last_family == 4)
        if status >= 400:
            self.check(name + '_rejected', bool(result.body.get('errors'))
                and not any(result.body.get(key) for key in ('auth', 'data', 'wrap_info')))
        return result.body

    def login(self, name, kind, credentials):
        result = self.call(name, 'POST', f'auth/{MOUNT}/login', credentials,
                           token='', source='127.0.0.2')
        auth = result.get('auth') or {}
        self.check(name + '_issued', isinstance(auth.get('client_token'), str)
            and bool(auth['client_token']) and auth.get('token_type') == kind
            and bool(auth.get('accessor')) == (kind == 'service')
            and auth.get('renewable') is (kind == 'service')
            and auth.get('metadata') == {'role_name': kind})
        self.remember(auth, 'client_token', 'accessor')
        return auth

    def read(self, name, auth, *, source='127.0.0.1', status=200, spoof=False):
        result = self.call(name, 'GET', KV + '/item', token=auth['client_token'],
                           source=source, status=status, spoof=spoof)
        if status == 200:
            self.check(name + '_value', result.get('data') == {'value': 'synthetic'})


def verify_voters(cluster, trace, old, new, phase):
    if phase not in PHASES or set(old) != set(KINDS) or (phase != 'initial' and set(new) != set(KINDS)):
        raise ScenarioFailure('incomplete_token_matrix')
    if {node.node_id for node in cluster.nodes} != {1, 2, 3}:
        raise ScenarioFailure('incomplete_voter_matrix')
    views = []
    for node in cluster.nodes:
        t = trace(node); view = []
        for kind in KINDS:
            prefix = f'{phase}_n{node.node_id}_{kind}_'; auth = old[kind]
            t.read(prefix + 'allowed_kv', auth)
            data = t.call(prefix + 'allowed_lookup', 'GET', 'auth/token/lookup-self',
                          token=auth['client_token']).get('data') or {}
            t.check(prefix + 'allowed_lookup_shape', lookup_shape(data, auth, kind, ['127.0.0.1']))
            t.read(prefix + 'denied_kv', auth, source='127.0.0.2', status=403)
            t.read(prefix + 'spoofed_kv', auth, source='127.0.0.2', status=403, spoof=True)
            t.call(prefix + 'denied_lookup', 'GET', 'auth/token/lookup-self',
                   token=auth['client_token'], source='127.0.0.2', status=403, spoof=True)
            managed = t.call(prefix + 'root_target', 'POST', 'auth/token/lookup',
                            {'token': auth['client_token']}, source='127.0.0.2').get('data') or {}
            t.check(prefix + 'root_target_shape', lookup_shape(managed, auth, kind, ['127.0.0.1']))
            view.append(projection(managed))
            if phase != 'initial':
                t.read(prefix + 'new_allowed', new[kind], source='127.0.0.2')
                unbound = t.call(prefix + 'new_lookup', 'GET', 'auth/token/lookup-self',
                                token=new[kind]['client_token'], source='127.0.0.2').get('data') or {}
                t.check(prefix + 'new_lookup_shape', lookup_shape(unbound, new[kind], kind, []))
                view.append(projection(unbound))
        views.append(view)
    trace(cluster.nodes[0]).check(phase + '_all_voters', all(view == views[0] for view in views))


def run(binary, work, rows, bootstrap, diagnostics):
    from native_snapshot_ha_live import SaveCluster
    from userpass_batch_ha import standby_response
    from radius_cidrs_live import SourceClient
    cluster = None; sensitive = []
    try:
        cluster = SaveCluster(binary, work / 'cluster'); cluster.bootstrap()
        bootstrap.extend(cluster.scenarios)
        sensitive.extend([cluster.root_token, cluster.unseal_key, cluster.replication_key])
        def trace(node):
            return Trace(SourceClient(f'https://127.0.0.1:{node.http_port}', cluster.root / 'ca.crt',
                cluster.root_token, spoof_source='127.0.0.1'), rows, sensitive)
        leader = cluster.leader(); follower = next(n for n in cluster.nodes if n is not leader); t = trace(follower)
        t.check('three_processes', len(cluster.running()) == 3)
        t.check('five_second_listeners', all(json.loads((n.root / 'server.json').read_text())['timeout_seconds'] == 5 for n in cluster.nodes))
        status, body = follower.call('GET', 'sys/leader')
        t.check('forwarder_confirmed', standby_response(status, body, f'https://127.0.0.1:{leader.http_port}'))
        t.call('mount', 'POST', 'sys/auth/' + MOUNT, {'type': 'approle'}, status=204)
        t.call('kv_mount', 'POST', 'sys/mounts/' + KV, {'type': 'kv', 'options': {'version': '1'}}, status=204)
        t.call('seed', 'POST', KV + '/item', {'value': 'synthetic'}, status=204)
        t.call('policy', 'PUT', 'sys/policies/acl/' + POLICY,
               {'policy': 'path "' + KV + '/*" { capabilities=["read"] }'}, status=204)
        old = {}; new = {}; credentials = {}
        for kind in KINDS:
            path = f'auth/{MOUNT}/role/{kind}'
            t.call(kind + '_role', 'POST', path, {'token_type': kind, 'token_policies': [POLICY],
                'token_ttl': 600, 'token_max_ttl': 1800, 'secret_id_num_uses': 3,
                'token_bound_cidrs': ['127.0.0.1/32']}, status=204)
            rid = t.call(kind + '_role_id', 'GET', path + '/role-id')['data']['role_id']
            sid_data = t.call(kind + '_sid', 'POST', path + '/secret-id', {})['data']
            sid = sid_data['secret_id']
            t.remember(sid_data, 'secret_id', 'secret_id_accessor')
            sensitive.append(rid); credentials[kind] = {'role_id': rid, 'secret_id': sid}
            old[kind] = t.login(kind + '_forwarded', kind, credentials[kind])
            data = t.call(kind + '_sid_lookup', 'POST', path + '/secret-id/lookup', {'secret_id': sid})['data']
            t.check(kind + '_sid_consumed_once', data.get('secret_id_num_uses') == 2)
        verify_voters(cluster, trace, old, new, 'initial')
        for kind in KINDS:
            path = f'auth/{MOUNT}/role/{kind}/token-bound-cidrs'
            t.call(kind + '_clear_write', 'DELETE', path, status=204)
            data = t.call(kind + '_clear_read', 'GET', path).get('data') or {}
            t.check(kind + '_clear_role', 'token_bound_cidrs' in data and data['token_bound_cidrs'] is None)
            new[kind] = t.login(kind + '_clear_login', kind, credentials[kind])
        verify_voters(cluster, trace, old, new, 'cleared')
        trace(leader).call('stepdown_request', 'POST', 'sys/step-down', {}, status=204)
        t.check('stepdown', True)
        successor = cluster.leader(); t.check('successor_changed', successor is not leader)
        status, body = leader.call('GET', 'sys/leader')
        t.check('former_leader_standby', standby_response(status, body, f'https://127.0.0.1:{successor.http_port}'))
        verify_voters(cluster, trace, old, new, 'successor')
        for node in cluster.nodes: node.stop()
        for node in cluster.nodes: node.start(wait=False)
        for node in cluster.nodes: node.wait_ready()
        cluster.wait_quorum()
        for node in cluster.nodes:
            if node.call('POST', 'sys/unseal', {'key': cluster.unseal_key})[0] != 200:
                raise ScenarioFailure('restart_unseal_failed')
        cluster.leader(); t.check('full_restart', len(cluster.running()) == 3)
        verify_voters(cluster, trace, old, new, 'restarted')
        for node in cluster.nodes: node.stop()
        t.check('processes_stopped', not cluster.running())
        paths = []
        for node in cluster.nodes:
            paths.extend(p for folder in (node.data_dir, node.root / 'raft') for p in folder.rglob('*'))
            paths.extend([node.root / 'process.log', node.root / 'audit.jsonl'])
        t.check('secrets_absent', secret_free(paths, sensitive) and rows_secret_free(rows, sensitive))
        t.check('complete', True)
    except Exception:
        if cluster is not None:
            for node in cluster.running():
                try:
                    status, body = node.call('GET', 'sys/health', timeout=2)
                    diagnostics.append({'node_id': node.node_id, 'status': status,
                        **{k: body[k] for k in ('sealed', 'standby', 'ha_active', 'ha_application_ready') if type(body.get(k)) is bool}})
                except Exception:
                    diagnostics.append({'node_id': node.node_id, 'unavailable': True})
        raise
    finally:
        if cluster is not None: cluster.close()


def main():
    parser = SafeArgumentParser(description=__doc__)
    for name in ('binary', 'output', 'work-parent'): parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--build-source-commit', required=True)
    parser.add_argument('--expected-binary-sha256', required=True); args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}', args.build_source_commit) or not re.fullmatch(r'[0-9a-f]{64}', args.expected_binary_sha256):
        parser.error('candidate_pins_required')
    binary = args.binary.resolve(strict=True)
    if file_hash(binary) != args.expected_binary_sha256: parser.error('candidate_binary_mismatch')
    output = args.output.absolute(); admitted = admit_output(output)
    before = source_identity(ROOT, binary); helper_before = helpers(); runner = file_hash(Path(__file__))
    work = Path(tempfile.mkdtemp(prefix='approle-cidrs-ha-', dir=private_parent(args.work_parent))); work.chmod(0o700)
    rows, bootstrap, diagnostics = [], [], []; failure = None
    def interrupted(signum, frame): raise ScenarioFailure('fixture_interrupted')
    handlers = {kind: signal.signal(kind, interrupted) for kind in (signal.SIGTERM, signal.SIGINT)}
    try: run(binary, work, rows, bootstrap, diagnostics)
    except Exception as error: failure = next((r['case'] for r in reversed(rows) if r['passed'] is not True), 'fixture_' + type(error).__name__)
    finally:
        for kind, handler in handlers.items(): signal.signal(kind, handler)
    after = source_identity(ROOT, binary); helper_after = helpers()
    unchanged = before == after and after['binary_sha256'] == args.expected_binary_sha256
    runner_unchanged = runner == file_hash(Path(__file__))
    if not unchanged or not runner_unchanged or helper_before != helper_after: failure = 'source_binary_or_helpers_changed'
    if before['source_dirty'] or after['source_dirty']: failure = 'source_dirty'
    if not complete(rows) or not bootstrap: failure = failure or 'incomplete_observations'
    report = {'schema': 'heptabao.approle-cidrs-ha.v1', 'status': 'passed' if failure is None else 'failed',
        'failure': failure, 'checks': rows, 'bootstrap_checks': bootstrap, 'diagnostics': diagnostics,
        'source_identity': before, 'source_identity_after': after, 'source_and_binary_unchanged': unchanged,
        'runner_sha256': runner, 'runner_unchanged': runner_unchanged, 'helpers_before': helper_before, 'helpers_after': helper_after,
        'build_source_commit': args.build_source_commit, 'cluster_count': 1, 'voters': 3,
        'socket_peer_families': [4], 'source_client_timeout_seconds': 5, 'mutation_retries': 0,
        'snapshot_agreement_basis': 'HTTPS token lookup through every voter; no archive or storage dump comparison',
        'physical_fault_qualification': False, 'full_openbao_compatibility': False,
        'synthetic_only': True, 'retained_failure_work_dir': str(work) if failure else None}
    if admit_output(output) != admitted: raise ValueError('report_parent_changed')
    private_write(output, report, replace=False)
    if failure is None: shutil.rmtree(work)
    print(json.dumps({'status': report['status'], 'checks': len(rows), 'failure': failure}))
    return int(failure is not None)


if __name__ == '__main__': raise SystemExit(main())
