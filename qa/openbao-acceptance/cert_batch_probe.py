#!/usr/bin/env python3
"""Observed cert-token-type contract over real TLS; not a parity qualification.

Reuses the existing certificate fixture and official launcher. Candidate still
needs its explicit mandatory-client-CA listener adaptation. No certificate,
private key, bearer, accessor, entity identifier or raw error enters the receipt.
"""
from __future__ import annotations
import importlib
import json
import os
from pathlib import Path
import re
import signal
import tempfile

from bao_http import SafeArgumentParser, private_read, private_write
from cert_auth_live import Fixture
from cert_renewal_live import tls_client
from core_isolation import ROOT, ScenarioFailure, file_hash
from official_openbao_launcher import verify_inputs, start_oracle, stop_oracle, restart_oracle
from online_evidence import admit_output, source_identity
from userpass_password_live import free_port, private_parent, safe_files

MOUNT = 'cert-batch-probe'
POLICY = 'cert-batch-probe'
KV = 'cert-batch-kv/item'
MODES = ('default-service', 'default-batch', 'service', 'batch')
KINDS = ('default', 'service', 'batch')
API_CASES = (('omitted', {}), ('empty', {'token_type': ''}),
             ('null', {'token_type': None}), ('invalid', {'token_type': 'invalid'}),
             ('alias_service', {'token_type': 'default-service'}),
             ('alias_batch', {'token_type': 'default-batch'}))
LIMIT_CASES = (
    ('explicit_period', {'token_type': 'batch', 'token_period': 30}, 'default-service'),
    ('explicit_uses', {'token_type': 'batch', 'token_num_uses': 2}, 'default-service'),
    ('explicit_cap', {'token_type': 'batch', 'token_explicit_max_ttl': 20}, 'default-service'),
    ('forced_period', {'token_type': 'service', 'token_period': 30}, 'batch'),
    ('forced_uses', {'token_type': 'service', 'token_num_uses': 2}, 'batch'),
    ('forced_cap', {'token_type': 'service', 'token_explicit_max_ttl': 20}, 'batch'),
)
SCENARIOS = frozenset(
    ['matrix.'+mode.replace('-', '_')+'.'+kind for mode in MODES for kind in KINDS]
    + ['api.'+name for name, _ in API_CASES]
    + ['limits.'+name for name, _, _ in LIMIT_CASES]
    + ['partial', 'identity', 'wrapping', 'lifecycle', 'restart'])


def credential(body):
    value = (body.get('auth') or {}).get('client_token')
    if not isinstance(value, str) or len(value) < 16:
        raise ScenarioFailure('credential_not_issued')
    return value


class Trace:
    def __init__(self, client):
        self.client, self.rows, self.finished, self.sensitive = client, [], [], []

    def observe(self, case, **values):
        if not re.fullmatch(r'[a-z0-9_.]{1,140}', case) or any(row['case'] == case for row in self.rows):
            raise ValueError('invalid_case')
        self.rows.append({'case': case, **values})

    def call(self, case, method, path, body=None, *, token=None, wrap_ttl=None, role=None):
        response = self.client.request(method, '/v1/'+path, body, token=token, wrap_ttl=wrap_ttl)
        value = response.body
        auth, data, wrap = value.get('auth') or {}, value.get('data') or {}, value.get('wrap_info') or {}
        for secret in (auth.get('client_token'), auth.get('accessor'), auth.get('entity_id'),
                       data.get('id'), data.get('accessor'), data.get('entity_id'), wrap.get('token'), wrap.get('accessor')):
            if isinstance(secret, str) and secret:
                self.sensitive.append(secret)
        row = dict(status=response.status, auth=bool(auth), data=bool(data), wrap=bool(wrap),
                   errors=bool(value.get('errors')))
        if auth:
            row.update(token_type=auth.get('token_type') if auth.get('token_type') in KINDS else 'other',
                       renewable=auth.get('renewable') is True, accessor=bool(auth.get('accessor')),
                       orphan=auth.get('orphan') is True, entity=bool(auth.get('entity_id')))
            if type(auth.get('lease_duration')) is int:
                row['lease_duration'] = auth['lease_duration']
            if type(auth.get('num_uses')) is int:
                row['auth_num_uses'] = auth['num_uses']
            metadata = auth.get('metadata')
        elif 'meta' in data:
            metadata = data['meta']
            row.update(lookup_type=data.get('type') if data.get('type') in KINDS else 'other',
                       renewable=data.get('renewable') is True, accessor=bool(data.get('accessor')),
                       orphan=data.get('orphan') is True)
            row['lookup_period_present'] = 'period' in data
            for field in ('num_uses', 'period', 'explicit_max_ttl'):
                if type(data.get(field)) is int:
                    row['lookup_'+field] = data[field]
        else:
            metadata = None
        if isinstance(metadata, dict):
            expected_keys = {'cert_name', 'common_name', 'serial_number', 'subject_key_id', 'authority_key_id'}
            row['certificate_metadata_keys_exact'] = set(metadata) == expected_keys
            row['common_name_matches'] = metadata.get('common_name') == 'client.example.test'
            if role is not None:
                row['cert_name_matches'] = metadata.get('cert_name') == role
        for field in ('token_type', 'token_ttl', 'token_max_ttl', 'token_period', 'token_explicit_max_ttl', 'token_num_uses'):
            if field in data and path.startswith('auth/'+MOUNT+'/certs/'):
                item = data[field]
                if field == 'token_type':
                    row['role_type'] = item if item in KINDS else 'other'
                elif type(item) is int:
                    row[field] = item
        self.observe(case, **row)
        return response.status, value

    def require(self, case, method, path, body=None, *, status=200, **kwargs):
        observed, value = self.call(case, method, path, body, **kwargs)
        if observed != status:
            raise ScenarioFailure(case)
        return value

    def finish(self, case):
        if case not in SCENARIOS or case in self.finished:
            raise ValueError('invalid_scenario')
        self.finished.append(case)


def role_path(name):
    return 'auth/'+MOUNT+'/certs/'+name


def payload(certificate, **fields):
    value = dict(certificate=certificate, token_policies=[POLICY], token_ttl=300, token_max_ttl=600)
    value.update(fields)
    return value


def login(t, case, name, **kwargs):
    return t.call(case, 'POST', 'auth/'+MOUNT+'/login', {'name': name}, token='', role=name, **kwargs)


def observe_login(t, case, name):
    status, body = login(t, case+'.login', name)
    if status == 200:
        raw = credential(body)
        t.call(case+'.lookup', 'POST', 'auth/token/lookup', {'token': raw}, role=name)
        t.call(case+'.kv', 'GET', KV, token=raw)
    else:
        t.observe(case+'.no_issued_bearer', credential_issued=False)


def run(t, certificate, restart):
    t.require('setup.mount', 'POST', 'sys/auth/'+MOUNT, {'type': 'cert'}, status=204)
    t.require('setup.kv', 'POST', 'sys/mounts/cert-batch-kv', {'type': 'kv', 'options': {'version': '1'}}, status=204)
    t.require('setup.value', 'POST', KV, {'value': 'synthetic'}, status=204)
    t.require('setup.policy', 'PUT', 'sys/policies/acl/'+POLICY,
              {'policy': 'path "cert-batch-kv/*" { capabilities=["read"] }'}, status=204)
    for mode in MODES:
        for kind in KINDS:
            case = 'matrix.'+mode.replace('-', '_')+'.'+kind
            name = case.replace('.', '-')
            t.call(case+'.tune', 'POST', 'sys/auth/'+MOUNT+'/tune', {'token_type': mode})
            status, _ = t.call(case+'.write', 'POST', role_path(name), payload(certificate, token_type=kind))
            t.call(case+'.read', 'GET', role_path(name))
            if status < 300:
                observe_login(t, case, name)
            t.finish(case)
    for label, fields, mode in [*[(label, fields, 'default-service') for label, fields in API_CASES], *LIMIT_CASES]:
        case = ('api.' if label in dict(API_CASES) else 'limits.')+label
        name = case.replace('.', '-')
        t.call(case+'.tune', 'POST', 'sys/auth/'+MOUNT+'/tune', {'token_type': mode})
        status, _ = t.call(case+'.write', 'POST', role_path(name), payload(certificate, **fields))
        t.call(case+'.read', 'GET', role_path(name))
        if status < 300:
            observe_login(t, case, name)
        t.finish(case)
    t.require('partial.tune', 'POST', 'sys/auth/'+MOUNT+'/tune', {'token_type': 'default-service'}, status=204)
    t.require('partial.initial', 'POST', role_path('partial'), payload(certificate, token_type='batch'), status=204)
    for label, fields in (('omitted', {'token_ttl': 120}), ('null', {'token_type': None}),
                          ('service', {'token_type': 'service'}), ('empty', {'token_type': ''})):
        t.call('partial.'+label+'.write', 'POST', role_path('partial'), fields)
        t.call('partial.'+label+'.read', 'GET', role_path('partial'))
        observe_login(t, 'partial.'+label, 'partial')
    t.finish('partial')
    t.require('identity.role', 'POST', role_path('held'), payload(certificate, token_type='batch'), status=204)
    first = t.require('identity.login', 'POST', 'auth/'+MOUNT+'/login', {'name': 'held'}, token='', role='held')
    raw = credential(first)
    entity = (first.get('auth') or {}).get('entity_id')
    if not isinstance(entity, str) or not entity:
        raise ScenarioFailure('identity_missing')
    t.require('identity.disable', 'POST', 'identity/entity/id/'+entity, {'disabled': True}, status=204)
    login(t, 'identity.denied_login', 'held')
    t.call('identity.denied_bearer', 'GET', KV, token=raw)
    t.require('identity.enable', 'POST', 'identity/entity/id/'+entity, {'disabled': False}, status=204)
    again = t.require('identity.fresh_login', 'POST', 'auth/'+MOUNT+'/login', {'name': 'held'}, token='', role='held')
    fresh = credential(again)
    t.observe('identity.binding', same_entity=again['auth'].get('entity_id') == entity, distinct_bearer=fresh != raw)
    t.require('identity.restored_bearer', 'GET', KV, token=raw)
    t.finish('identity')
    wrapped = t.require('wrapping.login', 'POST', 'auth/'+MOUNT+'/login', {'name': 'held'}, token='', wrap_ttl='60s')
    wrapper = (wrapped.get('wrap_info') or {}).get('token')
    if not isinstance(wrapper, str) or len(wrapper) < 16 or wrapped.get('auth'):
        raise ScenarioFailure('wrapper_not_issued')
    unwrapped = t.require('wrapping.unwrap', 'POST', 'sys/wrapping/unwrap', {}, token=wrapper, role='held')
    credential(unwrapped)
    t.call('wrapping.second_unwrap', 'POST', 'sys/wrapping/unwrap', {}, token=wrapper)
    t.finish('wrapping')
    for operation, actor, body in (('renew-self', raw, {}), ('renew', None, {'token': raw}),
                                   ('revoke-self', raw, {}), ('revoke', None, {'token': raw})):
        t.call('lifecycle.'+operation.replace('-', '_'), 'POST', 'auth/token/'+operation, body, token=actor)
    t.observe('lifecycle.no_accessor', accessor_absent=not first['auth'].get('accessor'), accessor_endpoint_not_called=True)
    t.require('lifecycle.after_revoke_attempt', 'GET', KV, token=raw)
    t.require('lifecycle.delete_role', 'DELETE', role_path('held'), status=204)
    t.require('lifecycle.after_role_delete', 'GET', KV, token=raw)
    t.require('lifecycle.disable_mount', 'DELETE', 'sys/auth/'+MOUNT, status=204)
    t.require('lifecycle.after_mount_disable', 'GET', KV, token=raw)
    t.call('lifecycle.lookup', 'POST', 'auth/token/lookup', {'token': raw}, role='held')
    t.finish('lifecycle')
    restart()
    t.require('restart.kv', 'GET', KV, token=raw)
    t.require('restart.lookup', 'POST', 'auth/token/lookup', {'token': raw}, role='held')
    t.finish('restart')


def complete(trace):
    return bool(trace and trace.rows and set(trace.finished) == SCENARIOS
                and len(trace.finished) == len(SCENARIOS)
                and len({row['case'] for row in trace.rows}) == len(trace.rows))


def helper_hashes():
    names = ('bao_http', 'cert_auth_live', 'cert_renewal_live', 'core_isolation',
             'official_openbao_launcher', 'online_evidence', 'userpass_password_live', 'heptabao.transport')
    return {name: file_hash(Path(importlib.import_module(name).__file__)) for name in names}


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path); parser.add_argument('--build-source-commit')
    parser.add_argument('--expected-binary-sha256'); parser.add_argument('--oracle-only', action='store_true')
    parser.add_argument('--work-parent', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.oracle_only and (args.binary is None or not re.fullmatch('[0-9a-f]{40}', args.build_source_commit or '')
                                or not re.fullmatch('[0-9a-f]{64}', args.expected_binary_sha256 or '')):
        parser.error('candidate_binary_build_and_sha256_required')
    official = verify_inputs(); binary = args.binary.resolve(strict=True) if args.binary else official
    if not args.oracle_only and file_hash(binary) != args.expected_binary_sha256:
        parser.error('candidate_binary_sha256_mismatch')
    output = args.output.absolute(); admitted = admit_output(output)
    before = source_identity(ROOT, binary)
    archive = Path(os.environ['HB_ORACLE_ARCHIVE'])
    hashes = (file_hash(Path(__file__)), helper_hashes(), file_hash(official), file_hash(archive))
    work = Path(tempfile.mkdtemp(prefix='cert-batch-probe-', dir=private_parent(args.work_parent)))
    prior = os.environ.get('HB_ORACLE_WORK_ROOT'); os.environ['HB_ORACLE_WORK_ROOT'] = str(work)
    traces, failures, scans, processes, scan_roots = {}, {}, {}, [], {}
    fixture = oracle = None; side = 'setup'; after = None; unchanged = False
    def interrupted(signum, frame): raise ScenarioFailure('interrupted')
    handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        for side in ('oracle',) if args.oracle_only else ('oracle', 'candidate'):
            fixture = Fixture(binary, work/side)
            if side == 'oracle':
                oracle = start_oracle(free_port()); processes.append(oracle['process'])
                data_root = Path(oracle['root']); token = private_read(oracle['token_file']).decode().strip()
                key = private_read(data_root/'unseal.key').decode().strip()
                address, ca = oracle['address'], oracle['ca_file']
                def restart():
                    stop_oracle(oracle); restart_oracle(oracle); processes.append(oracle['process'])
            else:
                config = json.loads((fixture.root/'server.json').read_text()); config['lifecycle_interval_seconds'] = 0
                private_write(fixture.root/'server.json', config, replace=True)
                fixture.start(); processes.append(fixture.process)
                status, init = fixture.call('POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1})
                if status != 200: raise ScenarioFailure('candidate_init')
                fixture.token, fixture.unseal_key = init['root_token'], init['keys_base64'][0]
                if fixture.call('POST', 'sys/unseal', {'key': fixture.unseal_key})[0] != 200:
                    raise ScenarioFailure('candidate_unseal')
                data_root, token, key = fixture.root, fixture.token, fixture.unseal_key
                address, ca = fixture.address, fixture.root/'root.crt'
                def restart():
                    fixture.stop(); fixture.start(); processes.append(fixture.process)
                    if fixture.call('POST', 'sys/unseal', {'key': key})[0] != 200:
                        raise ScenarioFailure('candidate_restart')
            client = tls_client(address, ca, token, (fixture.root/'client-chain.pem', fixture.root/'client.key'))
            trace = traces[side] = Trace(client); trace.sensitive.extend((token, key))
            trace.sensitive.extend(private_read(p).decode() for p in fixture.root.glob('*.key'))
            scan_roots[side] = (data_root, fixture.root)
            run(trace, (fixture.root/'client.crt').read_text(), restart)
            if side == 'oracle': stop_oracle(oracle); oracle = None
            else: fixture.stop()
            scans[side] = safe_files(data_root, trace.sensitive) and safe_files(fixture.root, trace.sensitive)
            if not scans[side]: raise ScenarioFailure('secret_scan')
            fixture = None
    except Exception as error:
        failures[side] = str(error) if isinstance(error, ScenarioFailure) else 'fixture_'+type(error).__name__
    finally:
        for name, stop in (('candidate', lambda: fixture.stop() if fixture else None),
                           ('oracle', lambda: stop_oracle(oracle) if oracle else None)):
            try: stop()
            except Exception as error: failures[name+'_cleanup'] = type(error).__name__
        if prior is None: os.environ.pop('HB_ORACLE_WORK_ROOT', None)
        else: os.environ['HB_ORACLE_WORK_ROOT'] = prior
        for sig, handler in handlers.items(): signal.signal(sig, handler)
    try:
        for name, roots in scan_roots.items():
            scans[name] = all(safe_files(path, traces[name].sensitive) for path in roots)
        after = source_identity(ROOT, binary)
        unchanged = hashes == (file_hash(Path(__file__)), helper_hashes(), file_hash(official), file_hash(archive)) and before == after
    except Exception as error: failures['postcheck'] = type(error).__name__
    stopped = all(p.poll() is not None for p in processes)
    sides = {'oracle'} if args.oracle_only else {'oracle', 'candidate'}
    observed = (not failures and set(traces) == sides and set(scans) == sides and all(scans.values())
                and all(complete(t) for t in traces.values()) and unchanged and stopped and not before['source_dirty'])
    report = {'schema': 'heptabao.cert-batch-probe.v1', 'status': 'observed' if observed else 'failed',
        'target_version': '2.6.2', 'oracle_only': args.oracle_only, 'candidate_executed': not args.oracle_only,
        'cases': {name: t.rows for name, t in traces.items()}, 'completed_scenarios': {name: t.finished for name, t in traces.items()},
        'failures': failures, 'secrets_absent': scans, 'processes_stopped': stopped,
        'source_before': before, 'source_after': after, 'inputs_unchanged': unchanged,
        'build_source_commit': args.build_source_commit, 'runner_sha256': hashes[0], 'helper_sha256': hashes[1],
        'oracle_binary_sha256': hashes[2], 'oracle_archive_sha256': hashes[3],
        'configuration_adaptation': 'candidate mandatory client CA; oracle optional client certificate; both submit same leaf PEM and role fields',
        'retained_work_dir': str(work), 'mutating_requests_retried': False, 'full_openbao_compatibility': False,
        'parity_qualified': False, 'not_covered': ['CRL/OCSP', 'CA roles', 'CIDRs', 'MFA', 'alias-metadata configuration',
        'remote lease creation', 'HA', 'token expiry wait', 'old-state upgrade', 'plain TLS without client certificate']}
    if any(value in json.dumps(report) for t in traces.values() for value in t.sensitive):
        raise ValueError('sensitive_report')
    if admit_output(output) != admitted: raise ValueError('output_parent_changed')
    private_write(output, report, replace=False)
    print(json.dumps({'status': report['status'], 'cases': {name: len(t.rows) for name, t in traces.items()}, 'failures': failures}))
    return int(not observed)


if __name__ == '__main__': raise SystemExit(main())
