#!/usr/bin/env python3
"""Socket-origin Kubernetes CIDRs across three local processes and mTLS forwarding.

Real HTTPS TokenReview against a synthetic server, not a kube-apiserver. Private
cold-cloned bootstrap and same-host SIGKILL are not production HA qualification.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import shutil
import tempfile
import time

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from ha_destructive import Cluster
from kubernetes_renewal_live import Reviewer, assertion, configuration, role
from online_evidence import admit_output, source_identity
from radius_cidrs_ha import health_snapshot
from radius_cidrs_live import SourceClient
from radius_renewal_live import renewal_token_shape
from remote_jwks_live import signing_key

BASE = 'auth/kubernetes-cidrs'
PREFIX = 'kubernetes_cidrs_ha.'
REQUIRED_BOOTSTRAP = frozenset({
    'fresh_seed_uninitialized', 'fresh_seed_initialized', 'seed_unsealed_before_ha',
    'seed_cluster_identity_read_back', 'three_distinct_service_processes',
    'node_1_unsealed', 'node_2_unsealed', 'node_3_unsealed',
})


class Trace:
    def __init__(self, client, reviewer, rows):
        self.client, self.reviewer, self.rows = client, reviewer, rows

    def check(self, label, passed, **safe):
        if (not isinstance(label, str) or re.fullmatch(r'[a-z0-9_.]{1,150}', label) is None
                or any(type(value) not in (bool, int) for value in safe.values())):
            raise ValueError('unsafe_observation')
        self.rows.append({'case': PREFIX + label, 'passed': passed is True, **safe})
        if passed is not True:
            raise ScenarioFailure(PREFIX + label)

    def call(self, label, path, body=None, *, method='POST', bearer=None,
             source='127.0.0.1', expected=200, reviews=0, spoof=False, wrap=None):
        before = len(self.reviewer.calls)
        response = self.client.request(method, path, body, token=bearer, source=source,
                                       spoof=spoof, wrap_ttl=wrap)
        count = len(self.reviewer.calls) - before
        self.check(label, response.status == expected and count == reviews
                   and (reviews == 0 or self.reviewer.request_valid), status=response.status,
                   tokenreviews=count, source_family=self.client.last_family)
        return response.body

    def login(self, label, *, source='127.0.0.2', expected=200, reviews=1, spoof=False, wrap=None):
        response = self.call(label, BASE + '/login', {'role': 'app', 'jwt': self.reviewer.presented},
                             bearer='', source=source, expected=expected, reviews=reviews, spoof=spoof, wrap=wrap)
        auth = response.get('auth', {})
        if expected == 200:
            self.check(label + '.issued', all(isinstance(auth.get(name), str) and bool(auth[name])
                       for name in ['client_token', 'accessor', 'entity_id']) and auth.get('renewable') is True)
        else:
            self.check(label + '.no_publication', not auth and not response.get('wrap_info'))
        return auth

    def bounds(self, label, auth):
        value = self.call(label, 'auth/token/lookup', {'token': auth['client_token']}).get('data', {})
        self.check(label + '.snapshot', value.get('bound_cidrs') == ['127.0.0.2'])

    def renew(self, label, auth):
        for entry, body, bearer, source in [
                ('renew-self', {}, auth['client_token'], '127.0.0.2'),
                ('renew', {'token': auth['client_token']}, None, '127.0.0.1'),
                ('renew-accessor', {'accessor': auth['accessor']}, None, '127.0.0.1')]:
            name = label + '.' + entry.replace('-', '_')
            result = self.call(name, 'auth/token/' + entry, dict(body, increment=300), bearer=bearer, source=source)
            self.check(name + '.shape', renewal_token_shape(result.get('auth'), auth['client_token'],
                       via_accessor=entry == 'renew-accessor'))


def unavailable_from_ha(body):
    errors = body.get('errors')
    return isinstance(errors, list) and bool(errors) and all(isinstance(v, str) and v.startswith('HA ') for v in errors)


def run(binary, root, rows, inherited, diagnostics):
    cluster = reviewer = None
    tokens = []
    try:
        cluster = Cluster(binary, root / 'cluster')
        first = cluster.nodes[0]
        reviewer = Reviewer(first.root / 'tls.crt', first.root / 'tls.key', 'candidate')
        private, jwk = signing_key('ES256', 'synthetic-kubernetes-cidrs-ha')
        reviewer.presented = assertion(private, jwk)
        for node in cluster.nodes:
            path = node.root / 'server.json'
            settings = json.loads(path.read_text())
            settings.update(outbound_endpoints=[], lifecycle_interval_seconds=0)
            private_write(path, settings, replace=True)
        cluster.bootstrap()
        inherited.extend(cluster.scenarios)
        leader = cluster.leader()
        follower = next(node for node in cluster.nodes if node is not leader)
        def trace(node):
            return Trace(SourceClient(f'https://127.0.0.1:{node.http_port}', cluster.root / 'ca.crt',
                                      cluster.root_token), reviewer, rows)
        primary, forwarded = trace(leader), trace(follower)
        primary.call('mount', 'sys/auth/kubernetes-cidrs', {'type': 'kubernetes'}, expected=204)
        primary.call('config', BASE + '/config', configuration('candidate', reviewer, private,
                     (cluster.root / 'ca.crt').read_text()), expected=204)
        primary.call('kv_mount', 'sys/mounts/cidr-kv', {'type': 'kv', 'options': {'version': '1'}}, expected=204)
        primary.call('policy', 'sys/policies/acl/cidr-user', {'policy': 'path "cidr-kv/*" { capabilities = ["read", "update"] }'}, expected=204)
        primary.call('seed', 'cidr-kv/item', {'value': 'synthetic'}, expected=204)
        # The shared SourceClient forges .1 in XFF/X-Real-IP/Forwarded. Here .1
        # is deliberately authorized, while its real socket source .2 is not.
        primary.call('spoof.role', BASE + '/role/app', role(token_ttl=600, token_max_ttl=1200,
                     token_policies=['cidr-user'], token_bound_cidrs=['127.0.0.1']), expected=204)
        for label, request in [('leader', primary), ('follower', forwarded)]:
            request.login('spoof.' + label + '.denied', source='127.0.0.2', expected=403,
                          reviews=0, spoof=True, wrap='60s')
        primary.call('role', BASE + '/role/app', {'token_bound_cidrs': ['127.0.0.2']}, expected=204)
        # HA peers themselves connect from .1. Successful .2 through follower
        # therefore requires the authenticated HBFQ3 origin rather than peer IP.
        auth = forwarded.login('forwarded.login')
        tokens.append(auth['client_token'])
        forwarded.bounds('forwarded.lookup', auth)
        forwarded.login('forwarded.wrong_login', source='127.0.0.1', expected=403, reviews=0, wrap='60s')
        for label, request in [('leader', primary), ('follower', forwarded)]:
            request.call(label + '.allowed_read', 'cidr-kv/item', method='GET', bearer=auth['client_token'], source='127.0.0.2')
            request.call(label + '.wrong_read', 'cidr-kv/item', method='GET', bearer=auth['client_token'], expected=403)
            request.call(label + '.wrong_write', 'cidr-kv/item', {'value': 'denied'}, bearer=auth['client_token'], expected=403)
            denied = request.call(label + '.wrong_renew', 'auth/token/renew-self', {'increment': 300},
                                  bearer=auth['client_token'], expected=403, wrap='60s')
            request.check(label + '.no_wrapper', not denied.get('auth') and not denied.get('wrap_info'))
        reviewer.mode = 'unavailable'
        forwarded.renew('forwarded.renew', auth)
        reviewer.mode = 'normal'
        primary.call('finite.role', BASE + '/role/app', {'token_num_uses': 2}, expected=204)
        finite = forwarded.login('finite.login')
        tokens.append(finite['client_token'])
        forwarded.call('finite.denied_no_use', 'cidr-kv/item', method='GET', bearer=finite['client_token'], expected=403)
        for label in ['first', 'second']:
            forwarded.call('finite.' + label, 'cidr-kv/item', method='GET', bearer=finite['client_token'], source='127.0.0.2')
        forwarded.call('finite.exhausted', 'cidr-kv/item', method='GET', bearer=finite['client_token'], source='127.0.0.2', expected=403)
        primary.call('clear.role', BASE + '/role/app', {'token_bound_cidrs': [], 'token_num_uses': 0}, expected=204)
        leader.stop()
        replacement = cluster.leader()
        after = trace(replacement)
        after.check('failover.new_leader', replacement is not leader)
        after.bounds('failover.lookup', auth)
        remaining = next(node for node in cluster.running() if node is not replacement)
        after_forward = trace(remaining)
        after_forward.call('failover.allowed_read', 'cidr-kv/item', method='GET', bearer=auth['client_token'], source='127.0.0.2')
        after_forward.call('failover.wrong_read', 'cidr-kv/item', method='GET', bearer=auth['client_token'], expected=403)
        reviewer.mode = 'unavailable'
        after_forward.renew('failover.renew', auth)
        cluster.restart(leader)
        cluster.leader()
        restarted = trace(leader)
        restarted.bounds('restart.lookup', auth)
        restarted.call('restart.allowed_read', 'cidr-kv/item', method='GET', bearer=auth['client_token'], source='127.0.0.2')
        restarted.call('restart.wrong_read', 'cidr-kv/item', method='GET', bearer=auth['client_token'], expected=403)
        # The role is clear, but the issued token snapshot must remain restricted.
        role_data = restarted.call('restart.role', BASE + '/role/app', method='GET').get('data', {})
        restarted.check('restart.cleared_role_preserved', role_data.get('token_bound_cidrs') == [])
        reviewer.mode = 'normal'
        retained = cluster.leader()
        for node in cluster.nodes:
            if node is not retained:
                node.stop()
        time.sleep(2)
        isolated = trace(retained)
        health = isolated.call('quorum.health', 'sys/health', method='GET', expected=503)
        isolated.check('quorum.not_active', health.get('ha_active') is False)
        denied = isolated.call('quorum.login_denied', BASE + '/login', {'role': 'app', 'jwt': reviewer.presented},
                               bearer='', source='127.0.0.2', expected=503, wrap='60s')
        isolated.check('quorum.no_publication', unavailable_from_ha(denied) and not denied.get('auth') and not denied.get('wrap_info'))
        denied = isolated.call('quorum.token_denied', 'cidr-kv/item', method='GET', bearer=auth['client_token'], source='127.0.0.2', expected=503)
        isolated.check('quorum.token_ha_denial', unavailable_from_ha(denied))
        sensitive = [cluster.root_token, cluster.unseal_key, reviewer.reviewer, reviewer.presented, *tokens]
        files = []
        for node in cluster.nodes:
            files += [p for directory in [node.data_dir, node.root / 'raft'] for p in directory.rglob('*') if p.is_file()]
            files += [node.root / 'audit.jsonl', node.root / 'process.log']
        isolated.check('secrets_absent', all(secret.encode() not in p.read_bytes() for p in files if p.exists() for secret in sensitive)
                       and not any(secret in json.dumps(rows) for secret in sensitive))
        isolated.check('all_tokenreviews_were_valid', reviewer.request_valid)
        isolated.check('complete', True)
    except Exception:
        if cluster is not None:
            diagnostics['before_cleanup'] = health_snapshot(cluster)
        raise
    finally:
        try:
            if cluster is not None:
                cluster.close()
        finally:
            if reviewer is not None:
                reviewer.close()


REQUIRED_CASES = frozenset({
    'spoof.leader.denied', 'spoof.follower.denied',
    'spoof.leader.denied.no_publication', 'spoof.follower.denied.no_publication',
    'forwarded.login', 'forwarded.wrong_login', 'forwarded.login.issued', 'forwarded.lookup.snapshot', 'forwarded.wrong_login.no_publication',
    'leader.allowed_read', 'leader.wrong_read', 'leader.wrong_write', 'leader.no_wrapper',
    'follower.allowed_read', 'follower.wrong_read', 'follower.wrong_write', 'follower.no_wrapper',
    'finite.login', 'finite.denied_no_use', 'finite.first', 'finite.second', 'finite.exhausted',
    'failover.new_leader', 'failover.lookup.snapshot', 'failover.allowed_read', 'failover.wrong_read',
    'restart.lookup.snapshot', 'restart.allowed_read', 'restart.wrong_read', 'restart.cleared_role_preserved',
    'quorum.not_active', 'quorum.login_denied', 'quorum.no_publication', 'quorum.token_ha_denial',
    'secrets_absent', 'all_tokenreviews_were_valid', 'complete',
}) | frozenset(phase + '.' + entry + '.shape' for phase in ['forwarded.renew', 'failover.renew']
              for entry in ['renew_self', 'renew', 'renew_accessor'])


def complete(rows, inherited):
    if not isinstance(rows, list) or not rows or not isinstance(inherited, list):
        return False
    if any(not isinstance(name, str) for name in inherited):
        return False
    if not REQUIRED_BOOTSTRAP.issubset(inherited) or len(set(inherited)) != len(inherited):
        return False
    names = []
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get('case'), str)
                or re.fullmatch(re.escape(PREFIX) + r'[a-z0-9_.]{1,150}', row['case']) is None
                or row.get('passed') is not True
                or any(type(v) not in (bool, int) for k, v in row.items() if k not in ('case', 'passed'))):
            return False
        names.append(row['case'])
    return len(names) == len(set(names)) and {PREFIX + n for n in REQUIRED_CASES}.issubset(names)


def main():
    parser = SafeArgumentParser(description=__doc__)
    for name in ['binary', 'build-source-commit', 'output']:
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    if re.fullmatch(r'[0-9a-f]{40}', args.build_source_commit) is None:
        parser.error('full build source commit required')
    binary = Path(args.binary).resolve(strict=True)
    output = Path(args.output).absolute()
    admitted = admit_output(output)
    before, runner = source_identity(ROOT, binary), file_hash(Path(__file__))
    root = Path(tempfile.mkdtemp(prefix='heptabao-kubernetes-cidrs-ha-'))
    root.chmod(0o700)
    rows, inherited, diagnostics, failure = [], [], {}, None
    try:
        run(binary, root, rows, inherited, diagnostics)
    except Exception as error:
        failure = next((row['case'] for row in reversed(rows) if row['passed'] is not True),
                       'fixture_' + type(error).__name__)
    finally:
        shutil.rmtree(root)
    unchanged, runner_unchanged = before == source_identity(ROOT, binary), runner == file_hash(Path(__file__))
    if not unchanged or not runner_unchanged:
        failure = 'source_binary_or_runner_changed'
    if not complete(rows, inherited):
        failure = failure or 'incomplete_observations'
    report = {'schema': 'heptabao.kubernetes-cidrs-ha.v1', 'status': 'passed' if failure is None else 'failed',
              'checks': rows, 'bootstrap_checks': inherited, 'failure': failure, 'diagnostics': diagnostics,
              'source_identity': before, 'source_and_binary_unchanged': unchanged,
              'build_source_commit': args.build_source_commit, 'candidate_binary_sha256': before['binary_sha256'],
              'build_source_binding_basis': 'caller-supplied commit and observed binary hash; not independent attestation',
              'runner_sha256': runner, 'runner_unchanged': runner_unchanged,
              'same_host': True, 'synthetic_only': True, 'actual_https_tokenreview': True,
              'actual_kube_apiserver': False, 'cold_cloned_encrypted_seed': True,
              'physical_fault_qualification': False, 'full_openbao_compatibility': False,
              'independent_qualification': False, 'production_authority': False}
    if admit_output(output) != admitted:
        raise ValueError('report_parent_changed')
    private_write(output, report, replace=False)
    print(json.dumps({'status': report['status'], 'checks': len(rows), 'failure': failure}))
    return 0 if failure is None else 1


if __name__ == '__main__':
    raise SystemExit(main())
