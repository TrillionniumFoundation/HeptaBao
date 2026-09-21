#!/usr/bin/env python3
"""Compare batch-owned leases against an actual disposable Kubernetes API.

Existing ServiceAccounts only: retiring a Bao lease does not revoke its JWT.
Candidate CA/manager-token enrollment is adapted explicitly. No mutation retry.
"""
from __future__ import annotations
import base64
import datetime as dt
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import sys
import tempfile
import time
import urllib.parse

from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from official_openbao_launcher import verify_inputs, start_oracle, stop_oracle, restart_oracle
from online_evidence import admit_output, source_identity
from userpass_password_live import free_port, private_parent, safe_files
from remote_jwks_live import Instance
import kubernetes_cluster_live as kube

MOUNT = 'batch-kubernetes'
POLICY = 'batch-kubernetes-policy'
REQUIRED = frozenset({'complete', 'revoke.child.jwt_survives', 'revoke.orphan.jwt_survives',
    'revoke.orphan.after_restart', 'revoke.orphan.explicit_revoke.jwt_survives',
    'parent_expiry.child.jwt_survives', 'batch_expiry.orphan.jwt_survives',
    'existing_serviceaccount_preserved'}) | frozenset(
    f'{phase}.{kind}.two_expiries' for phase, kinds in (
        ('revoke', ('child', 'orphan')), ('parent_expiry', ('child',)),
        ('batch_expiry', ('orphan',))) for kind in kinds)


class FixtureInterrupted(Exception):
    pass


def interrupted(signum, frame):
    raise FixtureInterrupted('fixture_interrupted')


def install_signal_handlers():
    return {kind: signal.signal(kind, interrupted) for kind in (signal.SIGTERM, signal.SIGINT)}


def restore_signal_handlers(handlers):
    for kind, handler in handlers.items():
        signal.signal(kind, handler)


def complete(rows):
    if not isinstance(rows, list) or not rows:
        return False
    names = []
    for row in rows:
        if (not isinstance(row, dict) or not {'case', 'passed'} <= row.keys()
                or row['passed'] is not True or not isinstance(row['case'], str)
                or re.fullmatch(r'[a-z0-9_.]{1,140}', row['case']) is None
                or set(row) - {'case', 'passed', 'status'}
                or 'status' in row and (type(row['status']) is not int or not 100 <= row['status'] <= 599)):
            return False
        names.append(row['case'])
    return len(names) == len(set(names)) and names[-1] == 'complete' and REQUIRED <= set(names)


def timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.timestamp() if parsed.tzinfo else None
    except (ValueError, OverflowError):
        return None


def separate_expiries(response, lookup, token_lookup, now, batch_ttl):
    """Do not accept a short Bao lease as evidence that the upstream JWT expired."""
    try:
        raw = response['data']['service_account_token']
        payload = raw.split('.')[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
        jwt_expiry = claims['exp']
        lease_expiry = timestamp(lookup['data'].get('expire_time'))
        batch_expiry = timestamp(token_lookup['data'].get('expire_time'))
        ttl = response['lease_duration']
        return (type(jwt_expiry) is int and jwt_expiry > now + 500
                and lease_expiry is not None and batch_expiry is not None
                and now < lease_expiry <= batch_expiry + .001
                and type(ttl) is int and max(1, batch_ttl - 3) <= ttl <= batch_ttl
                and jwt_expiry > lease_expiry + 450 and response.get('renewable') is False)
    except (KeyError, TypeError, ValueError, IndexError):
        return False


class Trace:
    def __init__(self, client, cluster, rows, sensitive):
        self.client, self.cluster, self.rows, self.sensitive = client, cluster, rows, sensitive

    def check(self, name, condition, **facts):
        if not re.fullmatch(r'[a-z0-9_.]{1,140}', name) or any(row['case'] == name for row in self.rows):
            raise ValueError('unsafe_or_duplicate_observation')
        if set(facts) - {'status'} or any(type(value) is not int for value in facts.values()):
            raise ValueError('unsafe_observation')
        self.rows.append({'case': name, 'passed': condition is True, **facts})
        if condition is not True:
            raise ScenarioFailure(name)

    def call(self, name, method, path, body=None, *, status=200, token=None):
        result = self.client.request(method, path, body, token=token)
        for owner, field in (('auth', 'client_token'), ('auth', 'accessor'),
                             ('data', 'service_account_token'), ('wrap_info', 'token')):
            value = (result.body.get(owner) or {}).get(field)
            if isinstance(value, str) and value:
                self.sensitive.append(value)
        self.check(name, result.status == status, status=result.status)
        if status >= 400:
            self.check(name + '.no_credentials', not result.body.get('auth')
                       and not result.body.get('wrap_info') and not result.body.get('data'))
        return result.body

    def absent(self, name, path, body):
        expected = 403 if path == 'auth/token/lookup' else 400
        if path not in ('auth/token/lookup', 'sys/leases/lookup'):
            raise ValueError('only_lookup_may_poll')
        until = time.monotonic() + 15
        while True:
            response = self.client.request('POST' if expected == 403 else 'PUT', path, body)
            if response.status == expected:
                self.check(name, not any(response.body.get(key) for key in ('auth', 'data', 'wrap_info')),
                           status=response.status)
                return
            if response.status != 200 or time.monotonic() >= until:
                self.check(name, False, status=response.status)
            time.sleep(.15)

    def jwt_alive(self, name, token):
        self.cluster.await_token_review(token, True)
        self.check(name, True)


def scenarios(t, side, manager, restart, worker_uid):
    t.call('mount', 'POST', 'sys/mounts/' + MOUNT, {'type': 'kubernetes'}, status=204)
    config = {'kubernetes_host': t.cluster.origin}
    if side == 'oracle':
        config.update(service_account_jwt=manager, kubernetes_ca_cert=t.cluster.ca.decode(),
                      disable_local_ca_jwt=True)
    else:
        config['service_account_token'] = manager
    t.call('config', 'POST', MOUNT + '/config', config, status=204)
    t.call('role', 'POST', MOUNT + '/roles/worker', {
        'allowed_kubernetes_namespaces': ['hb-work'], 'service_account_name': 'worker',
        'token_default_ttl': 600, 'token_max_ttl': 600,
        'token_default_audiences': [kube.AUDIENCE]}, status=204)
    t.call('policy', 'PUT', 'sys/policies/acl/' + POLICY, {'policy':
        f'path "{MOUNT}/creds/worker" {{ capabilities = ["update"] }}\n'
        'path "auth/token/create*" { capabilities = ["update", "sudo"] }\n'}, status=204)
    for phase, kinds in (('revoke', ('child', 'orphan')), ('parent_expiry', ('child',)),
                         ('batch_expiry', ('orphan',))):
        batch_ttl = 6 if phase == 'batch_expiry' else 30
        parent = t.call(phase + '.parent', 'POST', 'auth/token/create', {
            'policies': [POLICY], 'ttl': 6 if phase == 'parent_expiry' else 120})['auth']['client_token']
        held = {}
        for kind in kinds:
            name = phase + '.' + kind
            token = t.call(name + '.issue', 'POST', 'auth/token/' + (
                'create-orphan' if kind == 'orphan' else 'create'), {
                    'type': 'batch', 'policies': [POLICY], 'ttl': batch_ttl}, token=parent)['auth']['client_token']
            token_lookup = t.call(name + '.token_lookup', 'POST', 'auth/token/lookup', {'token': token})
            response = t.call(name + '.credential', 'POST', MOUNT + '/creds/worker', {
                'kubernetes_namespace': 'hb-work', 'ttl': 600, 'audiences': [kube.AUDIENCE]}, token=token)
            lease, jwt = response['lease_id'], response['data']['service_account_token']
            lookup = t.call(name + '.lease_lookup', 'PUT', 'sys/leases/lookup', {'lease_id': lease})
            t.check(name + '.two_expiries', separate_expiries(response, lookup, token_lookup, time.time(), batch_ttl))
            t.jwt_alive(name + '.actual_jwt', jwt)
            t.call(name + '.renew_denied', 'PUT', 'sys/leases/renew', {'lease_id': lease, 'increment': 600}, status=400)
            after = t.call(name + '.lease_after_renew', 'PUT', 'sys/leases/lookup', {'lease_id': lease})
            t.check(name + '.renew_preserved', after['data']['expire_time'] == lookup['data']['expire_time'])
            held[kind] = (token, lease, jwt)
        if phase == 'revoke':
            t.call(phase + '.parent_revoke', 'POST', 'auth/token/revoke', {'token': parent}, status=204)
        elif phase == 'parent_expiry':
            t.absent(phase + '.parent_expired', 'auth/token/lookup', {'token': parent})
        for kind, (token, lease, jwt) in held.items():
            name = phase + '.' + kind
            if phase == 'revoke' and kind == 'orphan':
                t.call(name + '.still_active', 'PUT', 'sys/leases/lookup', {'lease_id': lease})
                t.jwt_alive(name + '.jwt_survives', jwt)
                restart()
                t.call(name + '.after_restart', 'PUT', 'sys/leases/lookup', {'lease_id': lease})
                t.call(name + '.explicit_revoke', 'PUT', 'sys/leases/revoke', {'lease_id': lease}, status=204)
                t.absent(name + '.retired', 'sys/leases/lookup', {'lease_id': lease})
                t.jwt_alive(name + '.explicit_revoke.jwt_survives', jwt)
            else:
                t.absent(name + '.token_expired', 'auth/token/lookup', {'token': token})
                t.absent(name + '.retired', 'sys/leases/lookup', {'lease_id': lease})
                t.jwt_alive(name + '.jwt_survives', jwt)
    status, account = t.cluster.call('GET', '/api/v1/namespaces/hb-work/serviceaccounts/worker')
    t.check('existing_serviceaccount_preserved', status == 200 and account.get('metadata', {}).get('uid') == worker_uid)
    t.check('complete', True)


def helper_hashes():
    names = ('bao_http', 'core_isolation', 'official_openbao_launcher', 'online_evidence',
             'userpass_password_live', 'remote_jwks_live', 'smoke', 'kubernetes_cluster_live',
             'heptabao', 'heptabao.transport')
    return {name: file_hash(Path(sys.modules[name].__file__)) for name in names}


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('--kind', type=Path, required=True)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--build-source-commit')
    parser.add_argument('--expected-binary-sha256')
    parser.add_argument('--oracle-only', action='store_true')
    parser.add_argument('--allow-disposable-cluster', action='store_true')
    parser.add_argument('--work-parent', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if not args.allow_disposable_cluster:
        parser.error('disposable_cluster_scope_required')
    if not args.oracle_only and (args.binary is None
            or not re.fullmatch('[0-9a-f]{40}', args.build_source_commit or '')
            or not re.fullmatch('[0-9a-f]{64}', args.expected_binary_sha256 or '')):
        parser.error('candidate_binary_build_and_sha256_required')
    parent = private_parent(args.work_parent)
    output = args.output.absolute()
    admitted = admit_output(output)
    kind = kube.validate_binary(args.kind, kube.kind_digest(platform.system(), platform.machine()))
    bao = verify_inputs()
    binary = args.binary.resolve(strict=True) if args.binary else None
    if binary and file_hash(binary) != args.expected_binary_sha256:
        parser.error('candidate_binary_sha256_mismatch')
    before = source_identity(ROOT, binary or bao)
    inputs = {'runner': file_hash(Path(__file__)), 'kind': file_hash(kind), 'bao': file_hash(bao), **helper_hashes()}
    work = Path(tempfile.mkdtemp(prefix='batch-kubernetes-', dir=parent))
    cluster = kube.Cluster(kind, work / 'cluster')
    previous = os.environ.get('HB_ORACLE_WORK_ROOT')
    os.environ['HB_ORACLE_WORK_ROOT'] = str(work)
    oracle = candidate = None
    cases, failures, scans = {}, {}, {}
    sensitive = []
    handlers = install_signal_handlers()
    try:
        cluster.start()
        status, version = cluster.call('GET', '/version')
        if status != 200 or version.get('gitVersion') != 'v1.35.0':
            raise ScenarioFailure('kubernetes_version')
        for namespace in ('hb-review', 'hb-work'):
            cluster.post('/api/v1/namespaces', {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': namespace}})
        cluster.service_account('hb-review', 'reviewer')
        worker = cluster.service_account('hb-work', 'worker')
        cluster.post('/apis/rbac.authorization.k8s.io/v1/clusterroles', {
            'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRole', 'metadata': {'name': 'hb-review-only'},
            'rules': [{'apiGroups': ['authentication.k8s.io'], 'resources': ['tokenreviews'], 'verbs': ['create']},
                      {'apiGroups': [''], 'resources': ['serviceaccounts/token'], 'verbs': ['create']}]})
        cluster.post('/apis/rbac.authorization.k8s.io/v1/clusterrolebindings', {
            'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRoleBinding', 'metadata': {'name': 'hb-review-only'},
            'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': 'hb-review-only'},
            'subjects': [{'kind': 'ServiceAccount', 'namespace': 'hb-review', 'name': 'reviewer'}]})
        cluster.await_review_permission(True)
        status, discovery = cluster.call('GET', '/.well-known/openid-configuration')
        if status != 200 or not isinstance(discovery.get('issuer'), str):
            raise ScenarioFailure('kubernetes_issuer')
        for side in (('oracle',) if args.oracle_only else ('oracle', 'candidate')):
            if side == 'oracle':
                oracle = start_oracle(free_port())
                data_root = Path(oracle['root'])
                token = private_read(oracle['token_file']).decode().strip()
                sensitive.extend([token, private_read(data_root / 'unseal.key').decode().strip()])
                client = Client(oracle['address'], oracle['ca_file'], token)
                def restart():
                    stop_oracle(oracle)
                    restart_oracle(oracle)
            else:
                candidate = Instance(binary, work / 'candidate')
                path = candidate.root / 'server.json'
                config = json.loads(path.read_text())
                config['outbound_endpoints'] = [{'origin': cluster.origin,
                    'address': urllib.parse.urlsplit(cluster.origin).netloc, 'server_name': '127.0.0.1',
                    'ca_pem': cluster.ca.decode(), 'path_prefix': '/'}]
                config['lifecycle_interval_seconds'] = 0
                private_write(path, config, replace=True)
                candidate.start()
                status, init = candidate.call('POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1})
                if status != 200:
                    raise ScenarioFailure('candidate_init')
                candidate.token, key = init['root_token'], init['keys_base64'][0]
                if candidate.call('POST', 'sys/unseal', {'key': key})[0] != 200:
                    raise ScenarioFailure('candidate_unseal')
                sensitive.extend([candidate.token, key])
                client = Client(candidate.address, candidate.root / 'ca.crt', candidate.token)
                data_root = candidate.root
                def restart():
                    candidate.stop()
                    candidate.start()
                    if candidate.call('POST', 'sys/unseal', {'key': key})[0] != 200:
                        raise ScenarioFailure('candidate_restart')
            cases[side] = []
            trace = Trace(client, cluster, cases[side], sensitive)
            try:
                # Each independent Bao lifecycle gets a fresh 600-second manager
                # credential; the candidate must not inherit time spent by the oracle.
                manager = cluster.token('hb-review', 'reviewer', discovery['issuer'])
                sensitive.append(manager)
                scenarios(trace, side, manager, restart, worker['metadata']['uid'])
                scans[side] = safe_files(data_root, sensitive)
                if not scans[side]:
                    failures[side] = 'secret_scan_failed'
            except FixtureInterrupted:
                raise
            except Exception as error:
                failures[side] = next((row['case'] for row in reversed(trace.rows) if not row['passed']),
                                      'fixture_' + type(error).__name__)
            finally:
                if side == 'oracle':
                    stop_oracle(oracle)
                    oracle = None
                else:
                    candidate.stop()
                    candidate = None
    except Exception as error:
        failures['setup'] = 'fixture_' + type(error).__name__
    finally:
        try:
            if candidate is not None:
                candidate.stop()
            if oracle is not None:
                stop_oracle(oracle)
        finally:
            try:
                cluster.close()
            except Exception as error:
                failures['cleanup'] = 'fixture_' + type(error).__name__
            if previous is None:
                os.environ.pop('HB_ORACLE_WORK_ROOT', None)
            else:
                os.environ['HB_ORACLE_WORK_ROOT'] = previous
            restore_signal_handlers(handlers)
    after = source_identity(ROOT, binary or bao)
    unchanged = inputs == {'runner': file_hash(Path(__file__)), 'kind': file_hash(kind), 'bao': file_hash(bao), **helper_hashes()}
    equal = None if args.oracle_only else cases.get('oracle') == cases.get('candidate')
    passed = (not failures and unchanged and before == after and not before['source_dirty']
              and set(cases) == ({'oracle'} if args.oracle_only else {'oracle', 'candidate'})
              and all(complete(rows) for rows in cases.values()) and set(scans) == set(cases)
              and all(scans.values()) and (args.oracle_only or equal))
    report = {'schema': 'heptabao.kubernetes-batch-lease-comparison.v1', 'status': 'passed' if passed else 'failed',
        'cases': cases, 'failures': failures, 'cases_match': equal, 'secrets_absent': scans,
        'source': before, 'source_after': after, 'source_and_binary_unchanged': before == after,
        'inputs_sha256': inputs, 'inputs_unchanged': unchanged, 'build_source_commit': args.build_source_commit,
        'oracle_only': args.oracle_only, 'target_version': '2.6.2', 'kubernetes_version': 'v1.35.0',
        'node_image': kube.NODE_IMAGE, 'actual_kubernetes_cases_complete': all(complete(rows) for rows in cases.values()) and bool(cases),
        'configuration_adaptation': 'candidate process CA enrollment and service_account_token; oracle API CA and service_account_jwt',
        'secret_scan_excludes': ['private Kubernetes credential/control-plane stores'],
        'existing_serviceaccount_only': True, 'jwt_revocation_claim': False, 'mutating_requests_retried': False,
        'HA_covered': False, 'historical_upgrade_covered': False, 'provider_completion_race_covered': False,
        'full_openbao_compatibility': False, 'independent_qualification': False, 'production_authority': False,
        'retained_failure_work_dir': None if passed else str(work)}
    if any(value in json.dumps(report) for value in sensitive):
        raise ValueError('sensitive_report_rejected')
    if admit_output(output) != admitted:
        raise ValueError('report_parent_changed')
    private_write(output, report, replace=False)
    if passed:
        shutil.rmtree(work)
    print(json.dumps({'status': report['status'], 'cases': {side: len(rows) for side, rows in cases.items()}, 'failures': failures}))
    return int(not passed)


if __name__ == '__main__':
    raise SystemExit(main())
