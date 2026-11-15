#!/usr/bin/env python3
"""Official-only AppRole token CIDR observations; no parity qualification."""
from __future__ import annotations
import importlib
import json
import os
from pathlib import Path
import re
import signal
import tempfile

from bao_http import SafeArgumentParser, private_read, private_write
from core_isolation import ScenarioFailure, file_hash
from official_openbao_launcher import verify_inputs, start_oracle, stop_oracle, restart_oracle
from online_evidence import admit_output
from radius_cidrs_live import SourceClient
from userpass_password_live import free_port, private_parent, safe_files

MOUNT = 'approle-cidr-probe'
POLICY = 'approle-cidr-probe'
KV = 'approle-cidr-kv/item'
FIELD = 'token_bound_cidrs'
BOUND = ['127.0.0.1/32']
SCENARIOS = frozenset({'api.whole', 'api.field', 'api.missing', 'constraints.whole',
    'constraints.field', 'constraints.delete', 'lifecycle.service', 'lifecycle.batch', 'restart'}) | frozenset(
    'constraints.'+phase+'_'+shape for phase, shapes in (
        ('fresh', ('omitted', 'null', 'empty')),
        ('existing', ('omitted', 'null', 'empty', 'bound'))) for shape in shapes)


def cidr_projection(data, field):
    if field not in data: return {'cidr_shape': 'missing'}
    value = data[field]
    if value is None: return {'cidr_shape': 'null'}
    if not isinstance(value, list) or any(not isinstance(v, str)
        or not re.fullmatch(r'[0-9a-fA-F:./]{1,80}', v) for v in value):
        raise ValueError('unsafe_cidr_observation')
    return {'cidr_shape': 'list', 'cidrs': value}


class Trace:
    def __init__(self, client):
        self.client, self.rows, self.finished, self.sensitive = client, [], [], []

    def call(self, name, method, path, body=None, *, token=None, source='127.0.0.1', spoof=False):
        if not re.fullmatch(r'[a-z0-9_.]{1,140}', name) or any(r['case'] == name for r in self.rows):
            raise ValueError('invalid_case')
        response = self.client.request(method, path, body, token=token, source=source, spoof=spoof)
        data, auth = response.body.get('data') or {}, response.body.get('auth') or {}
        for value in (auth.get('client_token'), auth.get('accessor'), data.get('secret_id'),
                      data.get('secret_id_accessor'), data.get('role_id')):
            if isinstance(value, str) and value: self.sensitive.append(value)
        row = {'case': name, 'status': response.status, 'auth': bool(auth), 'data': bool(data),
               'wrap': bool(response.body.get('wrap_info')), 'errors': bool(response.body.get('errors'))}
        for field in (FIELD, 'bound_cidrs'):
            if field in data: row.update(cidr_projection(data, field))
        if path.endswith('/token-bound-cidrs') and method == 'GET' and FIELD not in data:
            row.update(cidr_projection(data, FIELD))
        if type(data.get('secret_id_num_uses')) is int: row['secret_id_num_uses'] = data['secret_id_num_uses']
        if type(data.get('num_uses')) is int: row['num_uses'] = data['num_uses']
        if type(data.get('bind_secret_id')) is bool: row['bind_secret_id'] = data['bind_secret_id']
        if auth:
            row.update(token_type=auth.get('token_type') if auth.get('token_type') in ('service', 'batch') else 'other',
                       renewable=auth.get('renewable') is True, accessor=bool(auth.get('accessor')),
                       orphan=auth.get('orphan') is True)
        self.rows.append(row)
        return response.status, response.body

    def require(self, name, method, path, body=None, *, status=200, **kwargs):
        actual, value = self.call(name, method, path, body, **kwargs)
        if actual != status: raise ScenarioFailure(name)
        return value

    def finish(self, name):
        if name not in SCENARIOS or name in self.finished: raise ValueError('invalid_scenario')
        self.finished.append(name)


def role_path(role): return 'auth/'+MOUNT+'/role/'+role


def role_constraint_scenarios(t):
    """Fresh API mutations must not inherit permissive historical-load behavior."""
    for shape, fields in [('omitted', {}), ('null', {FIELD: None}), ('empty', {FIELD: []})]:
        name = 'constraints.fresh_'+shape
        path = role_path('fresh-no-secret-'+shape)
        t.call(name+'.write', 'POST', path, dict(fields, bind_secret_id=False))
        # Observe actual absence/status; do not assume an invalid creation left a role.
        t.call(name+'.whole_read', 'GET', path)
        t.call(name+'.field_read', 'GET', path+'/token-bound-cidrs')
        t.finish(name)
    for shape, fields in [('omitted', {}), ('null', {FIELD: None}),
                          ('empty', {FIELD: []}), ('bound', {FIELD: BOUND})]:
        name = 'constraints.existing_'+shape
        path = role_path('existing-no-secret-'+shape)
        t.require(name+'.create', 'POST', path, fields, status=204)
        t.require(name+'.before_whole', 'GET', path)
        t.require(name+'.before_field', 'GET', path+'/token-bound-cidrs')
        t.call(name+'.disable_secret', 'POST', path, {'bind_secret_id': False})
        # Both the binding flag and the exact CIDR representation remain observable.
        t.require(name+'.after_whole', 'GET', path)
        t.require(name+'.after_field', 'GET', path+'/token-bound-cidrs')
        t.finish(name)


def api_scenarios(t):
    for mode in ('whole', 'field'):
        name, path = 'api.'+mode, role_path('api-'+mode)
        t.require(name+'.create', 'POST', path, {}, status=204)
        t.require(name+'.initial_whole', 'GET', path)
        t.require(name+'.initial_field', 'GET', path+'/token-bound-cidrs')
        target = path if mode == 'whole' else path+'/token-bound-cidrs'
        for case, payload in (
            ('list', {FIELD: BOUND}), ('omitted', {}),
            ('csv', {FIELD: '127.0.0.1/32,127.0.0.2/32'}),
            ('null', {FIELD: None}), ('reset_null', {FIELD: BOUND}),
            ('empty_list', {FIELD: []}), ('reset_list', {FIELD: BOUND}),
            ('empty_string', {FIELD: ''}), ('reset_string', {FIELD: BOUND}),
            ('invalid_type', {FIELD: {'invalid': True}})):
            t.call(name+'.'+case+'.write', 'POST', target, payload)
            t.require(name+'.'+case+'.whole', 'GET', path)
            t.require(name+'.'+case+'.field', 'GET', path+'/token-bound-cidrs')
        t.call(name+'.delete', 'DELETE', path+'/token-bound-cidrs')
        t.require(name+'.after_delete_whole', 'GET', path)
        t.require(name+'.after_delete_field', 'GET', path+'/token-bound-cidrs')
        t.finish(name)
    path = role_path('missing')+'/token-bound-cidrs'
    for step, method, body in [('get', 'GET', None), ('post', 'POST', {FIELD: BOUND}), ('delete', 'DELETE', None)]:
        t.call('api.missing.'+step, method, path, body)
    t.finish('api.missing')
    for mode in ('whole', 'field', 'delete'):
        name, path = 'constraints.'+mode, role_path('constraint-'+mode)
        t.require(name+'.create', 'POST', path, {'bind_secret_id': False, FIELD: BOUND}, status=204)
        target = path if mode == 'whole' else path+'/token-bound-cidrs'
        t.call(name+'.clear', 'DELETE' if mode == 'delete' else 'POST', target,
               None if mode == 'delete' else {FIELD: []})
        t.require(name+'.whole_read', 'GET', path)
        t.require(name+'.field_read', 'GET', path+'/token-bound-cidrs')
        t.finish(name)
    role_constraint_scenarios(t)


def lifecycle(t, kind):
    name, path = 'lifecycle.'+kind, role_path(kind)
    t.require(name+'.role', 'POST', path, {'token_type': kind, FIELD: BOUND, 'secret_id_num_uses': 3,
        'token_ttl': 120, 'token_max_ttl': 300, 'token_policies': [POLICY]}, status=204)
    rid = t.require(name+'.role_id', 'GET', path+'/role-id')['data']['role_id']
    sid = t.require(name+'.secret_id', 'POST', path+'/secret-id', {})['data']['secret_id']
    credentials = {'role_id': rid, 'secret_id': sid}
    # Source differs from issued token's allowed CIDR. Role token CIDRs must not be confused with SecretID login CIDRs.
    auth = t.require(name+'.foreign_login', 'POST', 'auth/'+MOUNT+'/login', credentials,
                     token='', source='127.0.0.2')['auth']
    raw = auth['client_token']
    t.require(name+'.sid_after_login', 'POST', path+'/secret-id/lookup', {'secret_id': sid})
    t.require(name+'.snapshot', 'POST', 'auth/token/lookup', {'token': raw}, source='127.0.0.2')
    for label, method, route, body in [('lookup', 'GET', 'auth/token/lookup-self', None),
            ('read', 'GET', KV, None), ('renew', 'POST', 'auth/token/renew-self', {'increment': 120})]:
        t.call(name+'.foreign_'+label, method, route, body, token=raw, source='127.0.0.2', spoof=True)
    t.require(name+'.allowed_read', 'GET', KV, token=raw)
    t.call(name+'.allowed_renew', 'POST', 'auth/token/renew-self', {'increment': 120}, token=raw)
    if kind == 'service':
        for via, body in [('renew', {'token': raw}), ('renew-accessor', {'accessor': auth['accessor']})]:
            t.call(name+'.admin_'+via.replace('-', '_'), 'POST', 'auth/token/'+via,
                   dict(body, increment=120), source='127.0.0.2')
    for child_kind in ('service', 'batch'):
        for relationship, suffix in [('child', 'create'), ('orphan', 'create-orphan')]:
            prefix = name+'.'+child_kind+'_'+relationship
            _, body = t.call(prefix+'.issue', 'POST', 'auth/token/'+suffix,
                {'type': child_kind, 'policies': [POLICY], 'ttl': 90}, token=raw)
            child = (body.get('auth') or {}).get('client_token')
            if child:
                t.require(prefix+'.snapshot', 'POST', 'auth/token/lookup', {'token': child}, source='127.0.0.2')
                t.call(prefix+'.foreign_read', 'GET', KV, token=child, source='127.0.0.2')
                t.call(prefix+'.allowed_read', 'GET', KV, token=child)
    t.require(name+'.clear_role', 'POST', path, {FIELD: []}, status=204)
    t.require(name+'.old_snapshot_after_clear', 'POST', 'auth/token/lookup', {'token': raw}, source='127.0.0.2')
    t.call(name+'.old_foreign_after_clear', 'GET', KV, token=raw, source='127.0.0.2')
    t.call(name+'.renew_after_clear', 'POST', 'auth/token/renew-self', {'increment': 120}, token=raw)
    t.require(name+'.old_snapshot_after_renew', 'POST', 'auth/token/lookup', {'token': raw})
    fresh = t.require(name+'.fresh_login', 'POST', 'auth/'+MOUNT+'/login', credentials,
                      token='', source='127.0.0.2')['auth']['client_token']
    t.require(name+'.fresh_snapshot', 'POST', 'auth/token/lookup', {'token': fresh})
    t.call(name+'.fresh_foreign_read', 'GET', KV, token=fresh, source='127.0.0.2')
    t.require(name+'.sid_after_fresh', 'POST', path+'/secret-id/lookup', {'secret_id': sid})
    t.finish(name)
    return raw, fresh


def run(t, restart):
    t.require('setup.mount', 'POST', 'sys/auth/'+MOUNT, {'type': 'approle'}, status=204)
    t.require('setup.kv', 'POST', 'sys/mounts/approle-cidr-kv', {'type': 'kv', 'options': {'version': '1'}}, status=204)
    t.require('setup.value', 'POST', KV, {'value': 'synthetic'}, status=204)
    t.require('setup.policy', 'PUT', 'sys/policies/acl/'+POLICY, {'policy':
        'path "approle-cidr-kv/*" { capabilities=["read"] } '
        'path "auth/token/*" { capabilities=["read","update","sudo"] }'}, status=204)
    api_scenarios(t)
    held = {kind: lifecycle(t, kind) for kind in ('service', 'batch')}
    restart()
    for kind, (old, fresh) in held.items():
        t.call('restart.'+kind+'.old_foreign', 'GET', KV, token=old, source='127.0.0.2')
        t.call('restart.'+kind+'.old_allowed', 'GET', KV, token=old)
        t.require('restart.'+kind+'.old_snapshot', 'POST', 'auth/token/lookup', {'token': old})
        t.call('restart.'+kind+'.fresh_foreign', 'GET', KV, token=fresh, source='127.0.0.2')
    t.finish('restart')


def helpers():
    names = ('bao_http', 'core_isolation', 'official_openbao_launcher', 'online_evidence',
        'radius_cidrs_live', 'radius_native_live', 'radius_renewal_live', 'remote_jwks_live',
        'userpass_password_live', 'heptabao.transport', 'smoke')
    return {n: file_hash(Path(importlib.import_module(n).__file__)) for n in names}


def main():
    p = SafeArgumentParser(description=__doc__)
    p.add_argument('--work-parent', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(); output = args.output.absolute(); admitted = admit_output(output)
    bao = verify_inputs(); binary_hash, runner_hash, helper_hash = file_hash(bao), file_hash(Path(__file__)), helpers()
    work = Path(tempfile.mkdtemp(prefix='approle-token-cidrs-', dir=private_parent(args.work_parent)))
    prior = os.environ.get('HB_ORACLE_WORK_ROOT'); os.environ['HB_ORACLE_WORK_ROOT'] = str(work)
    oracle = t = None; failure = None; scan = False
    def interrupted(signum, frame): raise ScenarioFailure('interrupted')
    handlers = {s: signal.signal(s, interrupted) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        oracle = start_oracle(free_port())
        root = Path(oracle['root']); bearer = private_read(oracle['token_file']).decode().strip()
        t = Trace(SourceClient(oracle['address'], oracle['ca_file'], bearer))
        t.sensitive.extend((bearer, private_read(root/'unseal.key').decode().strip()))
        def restart(): stop_oracle(oracle); restart_oracle(oracle)
        run(t, restart)
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
    unchanged = binary_hash == file_hash(bao) and runner_hash == file_hash(Path(__file__)) and helper_hash == helpers()
    complete = t is not None and len(t.finished) == len(SCENARIOS) and set(t.finished) == SCENARIOS
    report = {'schema': 'heptabao.approle-token-cidrs-oracle-probe.v1', 'status':
        'observed' if failure is None and complete and scan and unchanged and stopped else 'failed',
        'failure': failure, 'failure_at': t.rows[-1]['case'] if failure and t and t.rows else None,
        'cases': t.rows if t else [], 'completed_scenarios': t.finished if t else [],
        'inputs_unchanged': unchanged, 'secrets_absent': scan, 'processes_stopped': stopped, 'oracle_binary_sha256': binary_hash,
        'runner_sha256': runner_hash, 'helper_sha256': helper_hash, 'target_version': '2.6.2',
        'oracle_only': True, 'source_qualified': False, 'numeric_CIDR_profile_only': True,
        'SecretID_CIDR_overrides_covered': False, 'HA_covered': False, 'full_openbao_compatibility': False,
        'retained_work_dir': str(work), 'mutating_requests_retried': False}
    if t and any(secret in json.dumps(report) for secret in t.sensitive): raise ValueError('sensitive_report')
    if admit_output(output) != admitted: raise ValueError('output_parent_changed')
    private_write(output, report, replace=False)
    print(json.dumps({'status': report['status'], 'cases': len(report['cases']), 'failure': failure}))
    return int(report['status'] != 'observed')


if __name__ == '__main__': raise SystemExit(main())
