#!/usr/bin/env python3
"""Official-only ordinary JWT batch observations; completion is not parity."""
from __future__ import annotations
import importlib
import json
import os
from pathlib import Path
import re
import signal
import tempfile

from bao_http import BaoError, Client, SafeArgumentParser, private_read, private_write
from core_isolation import ScenarioFailure, file_hash
from official_openbao_launcher import verify_inputs, start_oracle, stop_oracle, restart_oracle
from online_evidence import admit_output
from remote_jwks_live import signing_key, token as sign_token, serialization
from userpass_password_live import free_port, private_parent, safe_files

MOUNT = 'jwt-batch-probe'
POLICY = 'jwt-batch-probe'
KV = 'jwt-batch-kv/item'
ISSUER = 'https://jwt-batch-issuer.invalid'
SUBJECT = 'synthetic-jwt-batch-subject'
MODES = ('default-service', 'default-batch', 'service', 'batch')
ROLE_TYPES = ('default', 'service', 'batch')
TYPES = frozenset(('default', '', 'service', 'batch', 'default-service', 'default-batch'))
SCENARIOS = frozenset('matrix.'+m.replace('-', '_')+'.'+r for m in MODES for r in ROLE_TYPES) | frozenset((
    'type.omitted', 'type.empty', 'type.null', 'type.invalid', 'alias.default_service', 'alias.default_batch',
    'partial', 'explicit.period', 'explicit.uses', 'explicit.cap', 'forced.period', 'forced.uses', 'forced.cap',
    'identity', 'reuse', 'wrapped', 'rejected_assertions', 'batch.operations', 'batch.role_deleted',
    'batch.mount_disabled', 'restart'))
REQUIRED_CASES = frozenset(s+'.read' for s in SCENARIOS if s.startswith((
    'matrix.', 'type.', 'alias.', 'explicit.', 'forced.'))) | frozenset((
    'partial.invalid.read', 'identity.binding', 'identity.enabled_bearer', 'reuse.relationship',
    'wrapped.second_unwrap', 'rejected_assertions.entity_set', 'batch.operations.child',
    'batch.role_deleted.kv', 'batch.mount_disabled.kv', 'restart.kv'))


def type_projection(data, field):
    if field not in data: return {'shape': 'missing'}
    value = data[field]
    if value is None: return {'shape': 'null'}
    return {'shape': 'string', 'value': value} if isinstance(value, str) and value in TYPES else {'shape': 'other'}


class Trace:
    def __init__(self, client):
        self.client, self.rows, self.finished, self.sensitive = client, [], [], []

    def record(self, name, **values):
        if not re.fullmatch(r'[a-z0-9_.]{1,150}', name) or any(r['case'] == name for r in self.rows):
            raise ValueError('invalid_case')
        self.rows.append({'case': name, **values})

    def call(self, name, method, path, body=None, *, token=None, role=None, wrap_ttl=None):
        response = self.client.request(method, '/v1/'+path, body, token=token, wrap_ttl=wrap_ttl)
        data, auth, wrap = (response.body.get(k) or {} for k in ('data', 'auth', 'wrap_info'))
        for value in (auth.get('client_token'), auth.get('accessor'), wrap.get('token'), wrap.get('accessor')):
            if isinstance(value, str) and value: self.sensitive.append(value)
        row = {'status': response.status, 'auth': bool(auth), 'data': bool(data), 'wrap': bool(wrap),
               'errors': bool(response.body.get('errors')), 'warnings': bool(response.body.get('warnings'))}
        if data and '/role/' in path:
            row['configured_type'] = type_projection(data, 'token_type')
            row['ordinary_jwt_role'] = data.get('role_type') == 'jwt'
        if auth:
            row.update(auth_type=type_projection(auth, 'token_type'), accessor=bool(auth.get('accessor')),
                renewable=auth.get('renewable') is True, orphan=auth.get('orphan') is True,
                entity=bool(auth.get('entity_id')), role_metadata=(auth.get('metadata') or {}).get('role') == role)
        if path.startswith('auth/token/lookup') and data:
            row.update(lookup_type=type_projection(data, 'type'), lookup_accessor=bool(data.get('accessor')),
                lookup_orphan=data.get('orphan') is True, lookup_entity=bool(data.get('entity_id')),
                lookup_role_metadata=(data.get('meta') or {}).get('role') == role,
                display_name_matches_mount_subject=data.get('display_name') == MOUNT+'-'+SUBJECT)
        for key in ('token_ttl', 'token_max_ttl', 'token_period', 'token_num_uses', 'token_explicit_max_ttl',
                    'num_uses', 'period', 'explicit_max_ttl'):
            if type(data.get(key)) is int: row[key] = data[key]
        for label, value in (('lease', auth.get('lease_duration')), ('ttl', data.get('ttl'))):
            if type(value) is int:
                row[label+'_positive'] = value > 0
                for bound in (20, 30, 60, 120, 300): row[label+'_le_'+str(bound)] = value <= bound
        self.record(name, **row)
        return response.status, response.body

    def require(self, name, method, path, body=None, *, status=200, **kwargs):
        observed, result = self.call(name, method, path, body, **kwargs)
        if observed != status: raise ScenarioFailure(name)
        return result

    def finish(self, name):
        if name not in SCENARIOS or name in self.finished: raise ValueError('invalid_scenario')
        self.finished.append(name)


def role_path(role): return 'auth/'+MOUNT+'/role/'+role


def role_payload(**changes):
    values = {'role_type': 'jwt', 'user_claim': 'sub', 'bound_audiences': ['heptabao-test'],
              'token_policies': [POLICY], 'token_ttl': 300, 'token_max_ttl': 600}
    values.update(changes)
    return values


def configure_role(t, case, role, fields, mode='default-service'):
    t.require(case+'.tune', 'POST', 'sys/auth/'+MOUNT+'/tune', {'token_type': mode,
        'default_lease_ttl': 300, 'max_lease_ttl': 600}, status=204)
    # Null is an observation too. Record a real transport failure without retrying the mutation.
    try: status, _ = t.call(case+'.write', 'POST', role_path(role), role_payload(**fields))
    except BaoError as error:
        if fields.get('token_type', 'not-null') is not None or error.code != 'transport_outcome_unknown': raise
        t.record(case+'.write', response_absent=True, mutation_outcome_unknown=True)
        status = None
    t.call(case+'.read', 'GET', role_path(role))
    return status


def login(t, name, role, assertion, **kwargs):
    return t.call(name, 'POST', 'auth/'+MOUNT+'/login', {'role': role, 'jwt': assertion},
                  token='', role=role, **kwargs)


def observe_token(t, case, body, role):
    raw = (body.get('auth') or {}).get('client_token')
    if raw:
        t.call(case+'.lookup', 'POST', 'auth/token/lookup', {'token': raw}, role=role)
        t.call(case+'.kv', 'GET', KV, token=raw)
    return raw


def role_scenarios(t, assertion):
    for mode in MODES:
        for kind in ROLE_TYPES:
            case = 'matrix.'+mode.replace('-', '_')+'.'+kind
            role = case.replace('.', '-')
            status = configure_role(t, case, role, {'token_type': kind}, mode)
            if status is not None and status < 300:
                _, body = login(t, case+'.login', role, assertion)
                observe_token(t, case, body, role)
            t.finish(case)
    for case, fields in [('type.omitted', {}), ('type.empty', {'token_type': ''}),
        ('type.null', {'token_type': None}), ('type.invalid', {'token_type': 'invalid'}),
        ('alias.default_service', {'token_type': 'default-service'}),
        ('alias.default_batch', {'token_type': 'default-batch'})]:
        role = case.replace('.', '-')
        status = configure_role(t, case, role, fields)
        if status is not None and status < 300:
            _, body = login(t, case+'.login', role, assertion)
            observe_token(t, case, body, role)
        t.finish(case)
    for case, fields, mode in [
        ('explicit.period', {'token_type': 'batch', 'token_period': 30}, 'default-service'),
        ('explicit.uses', {'token_type': 'batch', 'token_num_uses': 2}, 'default-service'),
        ('explicit.cap', {'token_type': 'batch', 'token_explicit_max_ttl': 20}, 'default-service'),
        ('forced.period', {'token_type': 'service', 'token_period': 30}, 'batch'),
        ('forced.uses', {'token_type': 'service', 'token_num_uses': 2}, 'batch'),
        ('forced.cap', {'token_type': 'service', 'token_explicit_max_ttl': 20}, 'batch')]:
        role = case.replace('.', '-')
        status = configure_role(t, case, role, fields, mode)
        if status is not None and status < 300:
            _, body = login(t, case+'.login', role, assertion)
            observe_token(t, case, body, role)
        t.finish(case)
    role = 'partial'
    configure_role(t, 'partial.initial', role, {'token_type': 'batch'})
    for label, fields in [('omitted', {'token_ttl': 120}), ('null', {'token_type': None}),
            ('service', {'token_type': 'service'}), ('empty', {'token_type': ''}),
            ('batch', {'token_type': 'batch'}), ('invalid', {'token_type': 'invalid'})]:
        payload = dict(fields, role_type='jwt')
        try: t.call('partial.'+label+'.write', 'POST', role_path(role), payload)
        except BaoError as error:
            if label != 'null' or error.code != 'transport_outcome_unknown': raise
            t.record('partial.null.write', response_absent=True, mutation_outcome_unknown=True)
        t.call('partial.'+label+'.read', 'GET', role_path(role))
        _, body = login(t, 'partial.'+label+'.login', role, assertion)
        observe_token(t, 'partial.'+label, body, role)
    t.finish('partial')


def lifecycle(t, assertion, wrong_signature, wrong_claims, restart):
    role = 'lifecycle'
    configure_role(t, 'identity.setup', role, {'token_type': 'batch'})
    first = t.require('identity.login', 'POST', 'auth/'+MOUNT+'/login', {'role': role, 'jwt': assertion}, token='', role=role)
    auth = first['auth']; raw, entity = auth['client_token'], auth['entity_id']
    details = t.require('identity.read', 'GET', 'identity/entity/id/'+entity)
    aliases = (details.get('data') or {}).get('aliases') or []
    t.record('identity.binding', alias_matches_subject=any(a.get('name') == SUBJECT for a in aliases),
             alias_role_metadata=any((a.get('metadata') or {}).get('role') == role for a in aliases),
             auth_role_metadata=auth.get('metadata') == {'role': role})
    t.call('identity.before_disable', 'GET', KV, token=raw)
    t.require('identity.disable', 'POST', 'identity/entity/id/'+entity, {'disabled': True}, status=204)
    t.call('identity.disabled_bearer', 'GET', KV, token=raw)
    login(t, 'identity.disabled_login', role, assertion)
    t.require('identity.enable', 'POST', 'identity/entity/id/'+entity, {'disabled': False}, status=204)
    t.call('identity.enabled_bearer', 'GET', KV, token=raw)
    t.finish('identity')
    _, repeated = login(t, 'reuse.login', role, assertion)
    again = (repeated.get('auth') or {})
    t.record('reuse.relationship', same_entity=again.get('entity_id') == entity,
             fresh_bearer=bool(again.get('client_token')) and again['client_token'] != raw)
    observe_token(t, 'reuse', repeated, role); t.finish('reuse')
    _, wrapped = login(t, 'wrapped.login', role, assertion, wrap_ttl='60s')
    wrapper = (wrapped.get('wrap_info') or {}).get('token')
    if not wrapper: raise ScenarioFailure('wrapped.wrapper_required')
    _, unwrapped = t.call('wrapped.unwrap', 'POST', 'sys/wrapping/unwrap', {}, token=wrapper, role=role)
    observe_token(t, 'wrapped', unwrapped, role)
    t.call('wrapped.second_unwrap', 'POST', 'sys/wrapping/unwrap', {}, token=wrapper)
    t.finish('wrapped')
    before_status, before = t.call('rejected_assertions.before_entities', 'LIST', 'identity/entity/id')
    for label, value in [('signature', wrong_signature), ('claims', wrong_claims)]:
        login(t, 'rejected_assertions.'+label, role, value, wrap_ttl='60s')
    after_status, after = t.call('rejected_assertions.after_entities', 'LIST', 'identity/entity/id')
    before_keys, after_keys = ((body.get('data') or {}).get('keys') for body in (before, after))
    valid_sets = before_status == after_status == 200 and all(isinstance(keys, list)
        and all(isinstance(key, str) for key in keys) for keys in (before_keys, after_keys))
    t.record('rejected_assertions.entity_set', readable=valid_sets,
             unchanged=valid_sets and set(before_keys) == set(after_keys))
    t.finish('rejected_assertions')
    for label, path, body, bearer in [('self', 'auth/token/renew-self', {}, raw),
            ('admin', 'auth/token/renew', {'token': raw}, None),
            ('child', 'auth/token/create', {'type': 'batch', 'policies': [POLICY]}, raw)]:
        t.call('batch.operations.'+label, 'POST', path, body, token=bearer)
    t.finish('batch.operations')
    t.require('batch.role_deleted.delete', 'DELETE', role_path(role), status=204)
    observe_token(t, 'batch.role_deleted', first, role); t.finish('batch.role_deleted')
    t.require('batch.mount_disabled.disable', 'DELETE', 'sys/auth/'+MOUNT, status=204)
    observe_token(t, 'batch.mount_disabled', first, role); t.finish('batch.mount_disabled')
    restart()
    observe_token(t, 'restart', first, role); t.finish('restart')


def run(t, private, jwk, restart):
    pem = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    t.require('setup.mount', 'POST', 'sys/auth/'+MOUNT, {'type': 'jwt'}, status=204)
    t.require('setup.config', 'POST', 'auth/'+MOUNT+'/config', {'bound_issuer': ISSUER,
        'jwt_validation_pubkeys': [pem], 'jwt_supported_algs': ['ES256']}, status=204)
    t.require('setup.kv', 'POST', 'sys/mounts/jwt-batch-kv', {'type': 'kv', 'options': {'version': '1'}}, status=204)
    t.require('setup.value', 'POST', KV, {'value': 'synthetic'}, status=204)
    t.require('setup.policy', 'PUT', 'sys/policies/acl/'+POLICY, {'policy':
        'path "jwt-batch-kv/*" { capabilities=["read"] } '
        'path "auth/token/*" { capabilities=["read","update","sudo"] }'}, status=204)
    assertion = sign_token(private, jwk, ISSUER, sub=SUBJECT)
    bad_private, _ = signing_key('ES256', jwk['kid'])
    wrong_signature = sign_token(bad_private, jwk, ISSUER, sub='rejected-signature-subject')
    wrong_claims = sign_token(private, jwk, ISSUER, sub='rejected-claims-subject', aud='wrong')
    t.sensitive.extend((assertion, wrong_signature, wrong_claims))
    role_scenarios(t, assertion)
    lifecycle(t, assertion, wrong_signature, wrong_claims, restart)


def helpers():
    return {name: file_hash(Path(importlib.import_module(name).__file__)) for name in (
        'bao_http', 'core_isolation', 'official_openbao_launcher', 'online_evidence', 'remote_jwks_live',
        'external_tls_fixtures', 'userpass_password_live', 'smoke', 'heptabao.transport')}


def complete_scenarios(t):
    return t is not None and bool(t.rows) and REQUIRED_CASES.issubset({r['case'] for r in t.rows}) and (
        len({r['case'] for r in t.rows}) == len(t.rows)) and (
        len(t.finished) == len(SCENARIOS) and set(t.finished) == SCENARIOS)


def main():
    p = SafeArgumentParser(description=__doc__)
    p.add_argument('--work-parent', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(); output = args.output.absolute(); admitted = admit_output(output)
    bao = verify_inputs(); bh, rh, hh = file_hash(bao), file_hash(Path(__file__)), helpers()
    work = Path(tempfile.mkdtemp(prefix='jwt-batch-', dir=private_parent(args.work_parent)))
    prior = os.environ.get('HB_ORACLE_WORK_ROOT'); os.environ['HB_ORACLE_WORK_ROOT'] = str(work)
    oracle = t = None; failure = None; scan = False
    def interrupted(signum, frame): raise ScenarioFailure('interrupted')
    handlers = {s: signal.signal(s, interrupted) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        oracle = start_oracle(free_port())
        root = Path(oracle['root']); bearer = private_read(oracle['token_file']).decode().strip()
        t = Trace(Client(oracle['address'], oracle['ca_file'], bearer, timeout=5))
        t.sensitive.extend((bearer, private_read(root/'unseal.key').decode().strip()))
        private, jwk = signing_key('ES256', 'jwt-batch-key')
        def restart(): stop_oracle(oracle); restart_oracle(oracle)
        run(t, private, jwk, restart)
    except Exception as error:
        failure = 'fixture_'+type(error).__name__
    finally:
        try:
            if oracle is not None: stop_oracle(oracle)
        finally:
            if prior is None: os.environ.pop('HB_ORACLE_WORK_ROOT', None)
            else: os.environ['HB_ORACLE_WORK_ROOT'] = prior
            for sig, handler in handlers.items(): signal.signal(sig, handler)
    if t is not None and oracle is not None: scan = safe_files(Path(oracle['root']), t.sensitive)
    stopped = oracle is None or oracle['process'].poll() is not None
    unchanged = bh == file_hash(bao) and rh == file_hash(Path(__file__)) and hh == helpers()
    observed = failure is None and complete_scenarios(t) and scan and unchanged and stopped
    report = {'schema': 'heptabao.jwt-batch-oracle-probe.v1', 'status': 'observed' if observed else 'failed',
        'failure': failure, 'failure_at': t.rows[-1]['case'] if failure and t and t.rows else None,
        'cases': t.rows if t else [], 'completed_scenarios': t.finished if t else [],
        'inputs_unchanged': unchanged, 'secrets_absent': scan, 'processes_stopped': stopped,
        'oracle_binary_sha256': bh, 'runner_sha256': rh, 'helper_sha256': hh, 'target_version': '2.6.2',
        'official_source_commit': 'dd9c19c37a878cf4a81b18efb8d6f0599c7da923',
        'oracle_only': True, 'source_qualified': False, 'candidate_run': False,
        'configuration': 'static ES256 jwt_validation_pubkeys PEM',
        'ordinary_jwt_only': True, 'OIDC_callback_covered': False, 'remote_JWKS_covered': False,
        'MFA_covered': False, 'HA_covered': False, 'key_watermark_or_token_map_inspected': False,
        'full_openbao_compatibility': False, 'retained_work_dir': str(work), 'mutating_requests_retried': False}
    if t and any(secret in json.dumps(report) for secret in t.sensitive): raise ValueError('sensitive_report')
    if admit_output(output) != admitted: raise ValueError('output_parent_changed')
    private_write(output, report, replace=False)
    print(json.dumps({'status': report['status'], 'cases': len(report['cases']), 'failure': failure}))
    return int(not observed)


if __name__ == '__main__': raise SystemExit(main())
