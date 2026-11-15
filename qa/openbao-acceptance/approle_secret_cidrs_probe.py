#!/usr/bin/env python3
"""Official-only role SecretID source CIDR observations; no expected use-count guess."""
from __future__ import annotations
import importlib
import json
import os
from pathlib import Path
import signal
import tempfile

from bao_http import SafeArgumentParser, private_read, private_write
from core_isolation import ScenarioFailure, file_hash
from official_openbao_launcher import verify_inputs, start_oracle, stop_oracle, restart_oracle
from online_evidence import admit_output
from radius_cidrs_live import SourceClient
from userpass_password_live import free_port, private_parent, safe_files
from approle_token_cidrs_probe import Trace as TokenTrace, cidr_projection

MOUNT = 'approle-secret-cidr-probe'
POLICY = 'approle-secret-cidr-probe'
KV = 'approle-secret-cidr-kv/item'
FIELD = 'secret_id_bound_cidrs'
ALIAS = 'bound_cidr_list'
BOUND = ['127.0.0.1/32']
OTHER = ['127.0.0.2/32']
SCENARIOS = frozenset({'api.whole', 'api.field', 'api.alias_field', 'api.alias_priority',
    'api.missing', 'constraints.whole', 'constraints.field', 'constraints.delete',
    'constraints.bind_only', 'lifecycle.service', 'lifecycle.batch', 'restart'}
    | {f'consume.{kind}.{uses}' for kind in ('service', 'batch') for uses in ('one', 'two', 'unlimited')})


class Trace(TokenTrace):
    def call(self, name, method, path, body=None, **kwargs):
        status, value = super().call(name, method, path, body, **kwargs)
        data = value.get('data') or {}; row = self.rows[-1]
        for key, label in ((FIELD, 'role_login'), (ALIAS, 'legacy_alias'), ('cidr_list', 'sid_login')):
            if key in data:
                row.update({label+'_'+k: v for k, v in cidr_projection(data, key).items()})
        row['source_ipv4'] = self.client.last_family == 4
        row['warnings'] = bool(value.get('warnings'))
        if not row['source_ipv4']: raise ScenarioFailure('unexpected_source_family')
        return status, value

    def finish(self, name):
        if name not in SCENARIOS or name in self.finished: raise ValueError('invalid_scenario')
        self.finished.append(name)


def role_path(role): return 'auth/'+MOUNT+'/role/'+role


def read_role(t, name, path):
    t.call(name+'.whole', 'GET', path)
    t.call(name+'.field', 'GET', path+'/secret-id-bound-cidrs')
    t.call(name+'.alias', 'GET', path+'/bound-cidr-list')


def api_scenarios(t):
    for mode, suffix, key in (('whole', '', FIELD), ('field', '/secret-id-bound-cidrs', FIELD),
                              ('alias_field', '/bound-cidr-list', ALIAS)):
        name = 'api.'+mode; path = role_path('api-'+mode)
        t.require(name+'.create', 'POST', path, {}, status=204)
        read_role(t, name+'.initial', path)
        for case, payload in (
            ('list', {key: BOUND}), ('omitted', {}),
            ('csv', {key: '127.0.0.1/32,127.0.0.2/32'}),
            ('null', {key: None}), ('restore_null', {key: BOUND}),
            ('empty_list', {key: []}), ('restore_list', {key: BOUND}),
            ('empty_string', {key: ''}), ('restore_string', {key: BOUND}),
            ('bare_ip', {key: ['127.0.0.1']}), ('port', {key: ['127.0.0.1:80']}),
            ('bad_mask', {key: ['127.0.0.1/33']}), ('object', {key: {'invalid': True}}),
            ('ipv6', {key: ['::1/128']}), ('host_bits', {key: ['127.0.0.1/24']})):
            t.call(name+'.'+case+'.write', 'POST', path+suffix, payload)
            read_role(t, name+'.'+case, path)
        # Deleting the legacy alias field need not clear the native field.
        t.call(name+'.delete', 'DELETE', path+(suffix or '/secret-id-bound-cidrs'))
        read_role(t, name+'.after_delete', path); t.finish(name)
    name = 'api.alias_priority'; path = role_path('alias-priority')
    t.require(name+'.create', 'POST', path, {}, status=204)
    for case, payload in (
        ('legacy_only', {ALIAS: BOUND}), ('both', {FIELD: OTHER, ALIAS: BOUND}),
        ('native_null', {FIELD: None, ALIAS: BOUND}), ('native_empty', {FIELD: [], ALIAS: BOUND}),
        ('native_blank', {FIELD: '', ALIAS: BOUND}), ('legacy_null', {FIELD: OTHER, ALIAS: None})):
        t.call(name+'.'+case+'.write', 'POST', path, payload); read_role(t, name+'.'+case, path)
    t.call(name+'.native_route_other_alias', 'POST', path+'/secret-id-bound-cidrs', {ALIAS: BOUND})
    read_role(t, name+'.after_native_route_alias', path)
    t.call(name+'.legacy_route_native_field', 'POST', path+'/bound-cidr-list', {FIELD: BOUND})
    read_role(t, name+'.after_legacy_route_native', path); t.finish(name)
    path = role_path('missing')+'/secret-id-bound-cidrs'
    for case, method, body in [('get', 'GET', None), ('post', 'POST', {FIELD: BOUND}), ('delete', 'DELETE', None)]:
        t.call('api.missing.'+case, method, path, body)
    t.finish('api.missing')
    for mode in ('whole', 'field', 'delete'):
        name='constraints.'+mode; path=role_path('constraint-'+mode)
        t.require(name+'.create', 'POST', path, {'bind_secret_id': False, FIELD: BOUND}, status=204)
        target = path if mode == 'whole' else path+'/secret-id-bound-cidrs'
        t.call(name+'.clear', 'DELETE' if mode == 'delete' else 'POST', target, None if mode == 'delete' else {FIELD: []})
        read_role(t, name+'.after', path); t.finish(name)
    name='constraints.bind_only'; path=role_path('roleid-only')
    t.require(name+'.create', 'POST', path, {'bind_secret_id': False, FIELD: BOUND}, status=204)
    rid=t.require(name+'.role_id', 'GET', path+'/role-id')['data']['role_id']
    t.call(name+'.foreign', 'POST', 'auth/'+MOUNT+'/login', {'role_id':rid}, token='', source='127.0.0.2', spoof=True)
    t.call(name+'.allowed', 'POST', 'auth/'+MOUNT+'/login', {'role_id':rid}, token='')
    t.call(name+'.mint_sid', 'POST', path+'/secret-id', {})
    t.finish(name)


def credentials(t, name, path):
    rid=t.require(name+'.role_id', 'GET', path+'/role-id')['data']['role_id']
    sid=t.require(name+'.sid_issue', 'POST', path+'/secret-id', {})['data']['secret_id']
    return {'role_id':rid, 'secret_id':sid}


def sid_lookup(t, name, path, creds):
    return t.call(name, 'POST', path+'/secret-id/lookup', {'secret_id':creds['secret_id']})


def consumption(t, kind, label, uses):
    name=f'consume.{kind}.{label}'; path=role_path(kind+'-'+label)
    t.require(name+'.role', 'POST', path, {'token_type':kind, FIELD:BOUND, 'secret_id_num_uses':uses,
        'token_ttl':120, 'token_max_ttl':300, 'token_policies':[POLICY]}, status=204)
    creds=credentials(t, name, path)
    sid_lookup(t, name+'.before', path, creds)
    # Observation only: transaction rollback versus backend early consumption
    # is deliberately not encoded as an expected remaining-use count.
    t.call(name+'.denied_login', 'POST', 'auth/'+MOUNT+'/login', creds, token='', source='127.0.0.2', spoof=True)
    sid_lookup(t, name+'.after_denied', path, creds)
    _, body=t.call(name+'.allowed_login', 'POST', 'auth/'+MOUNT+'/login', creds, token='')
    sid_lookup(t, name+'.after_allowed', path, creds)
    raw=(body.get('auth') or {}).get('client_token')
    if raw:
        t.call(name+'.issued_foreign_use', 'GET', KV, token=raw, source='127.0.0.2')
    else:
        t.rows.append({'case':name+'.issued_foreign_use_pending', 'not_run':True, 'reason':'no_issued_token'})
    t.call(name+'.next_allowed_login', 'POST', 'auth/'+MOUNT+'/login', creds, token='')
    sid_lookup(t, name+'.after_next', path, creds)
    t.finish(name)


def lifecycle(t, kind):
    name='lifecycle.'+kind; path=role_path('lifecycle-'+kind)
    t.require(name+'.role', 'POST', path, {'token_type':kind, FIELD:BOUND,
        'token_ttl':180, 'token_max_ttl':600, 'token_policies':[POLICY]}, status=204)
    creds=credentials(t, name, path)
    auth=t.require(name+'.initial_login', 'POST', 'auth/'+MOUNT+'/login', creds, token='')['auth']; raw=auth['client_token']
    t.require(name+'.foreign_bearer', 'GET', KV, token=raw, source='127.0.0.2')
    t.require(name+'.snapshot', 'POST', 'auth/token/lookup', {'token':raw})
    t.require(name+'.move_login_constraint', 'POST', path, {FIELD:OTHER}, status=204)
    t.call(name+'.old_source_login', 'POST', 'auth/'+MOUNT+'/login', creds, token='')
    t.call(name+'.new_source_login', 'POST', 'auth/'+MOUNT+'/login', creds, token='', source='127.0.0.2')
    t.call(name+'.old_bearer_original', 'GET', KV, token=raw)
    t.call(name+'.old_bearer_other', 'GET', KV, token=raw, source='127.0.0.2')
    t.call(name+'.old_renew', 'POST', 'auth/token/renew-self', {'increment':180}, token=raw)
    t.require(name+'.after_renew_snapshot', 'POST', 'auth/token/lookup', {'token':raw})
    # Independent token restriction is the opposite of the login restriction.
    t.require(name+'.independent_token_constraint', 'POST', path, {FIELD:BOUND, 'token_bound_cidrs':OTHER}, status=204)
    restricted=t.require(name+'.independent_login', 'POST', 'auth/'+MOUNT+'/login', creds, token='')['auth']['client_token']
    t.call(name+'.restricted_original_bearer', 'GET', KV, token=restricted)
    t.call(name+'.restricted_other_bearer', 'GET', KV, token=restricted, source='127.0.0.2')
    t.require(name+'.restricted_snapshot', 'POST', 'auth/token/lookup', {'token':restricted})
    t.finish(name); return raw, restricted


def run(t, restart):
    t.require('setup.mount', 'POST', 'sys/auth/'+MOUNT, {'type':'approle'}, status=204)
    t.require('setup.kv', 'POST', 'sys/mounts/approle-secret-cidr-kv', {'type':'kv','options':{'version':'1'}}, status=204)
    t.require('setup.value', 'POST', KV, {'value':'synthetic'}, status=204)
    t.require('setup.policy', 'PUT', 'sys/policies/acl/'+POLICY,
        {'policy':'path "approle-secret-cidr-kv/*" { capabilities=["read"] }'}, status=204)
    api_scenarios(t)
    for kind in ('service','batch'):
        for label, uses in [('one',1),('two',2),('unlimited',0)]: consumption(t,kind,label,uses)
    held={kind:lifecycle(t,kind) for kind in ('service','batch')}
    restart()
    for kind,(raw,restricted) in held.items():
        t.call('restart.'+kind+'.old_original', 'GET', KV, token=raw)
        t.call('restart.'+kind+'.old_other', 'GET', KV, token=raw, source='127.0.0.2')
        t.call('restart.'+kind+'.restricted_original', 'GET', KV, token=restricted)
        t.call('restart.'+kind+'.restricted_other', 'GET', KV, token=restricted, source='127.0.0.2')
        read_role(t,'restart.'+kind+'.role',role_path('lifecycle-'+kind))
    t.finish('restart')


def helpers():
    names = ('approle_token_cidrs_probe', 'bao_http', 'core_isolation', 'official_openbao_launcher', 'online_evidence',
        'radius_cidrs_live', 'radius_native_live', 'radius_renewal_live', 'remote_jwks_live',
        'userpass_password_live', 'heptabao.transport', 'smoke')
    return {n: file_hash(Path(importlib.import_module(n).__file__)) for n in names}


def main():
    p = SafeArgumentParser(description=__doc__)
    p.add_argument('--work-parent', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(); output = args.output.absolute(); admitted = admit_output(output)
    bao = verify_inputs(); binary_hash, runner_hash, helper_hash = file_hash(bao), file_hash(Path(__file__)), helpers()
    work = Path(tempfile.mkdtemp(prefix='approle-secret-cidrs-', dir=private_parent(args.work_parent)))
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
    report = {'schema': 'heptabao.approle-secret-cidrs-oracle-probe.v1', 'status':
        'observed' if failure is None and complete and scan and unchanged and stopped else 'failed',
        'failure': failure, 'failure_at': t.rows[-1]['case'] if failure and t and t.rows else None,
        'cases': t.rows if t else [], 'completed_scenarios': t.finished if t else [],
        'inputs_unchanged': unchanged, 'secrets_absent': scan, 'processes_stopped': stopped, 'oracle_binary_sha256': binary_hash,
        'runner_sha256': runner_hash, 'helper_sha256': helper_hash, 'target_version': '2.6.2',
        'oracle_only': True, 'source_qualified': False, 'numeric_CIDR_profile_only': True,
        'role_SecretID_login_CIDRs_observed': True,
        'SecretID_CIDR_overrides_covered': False, 'HA_covered': False,
        'pending_cases': [row['case'] for row in t.rows if row.get('not_run')] if t else [], 'full_openbao_compatibility': False,
        'retained_work_dir': str(work), 'mutating_requests_retried': False}
    if t and any(secret in json.dumps(report) for secret in t.sensitive): raise ValueError('sensitive_report')
    if admit_output(output) != admitted: raise ValueError('output_parent_changed')
    private_write(output, report, replace=False)
    print(json.dumps({'status': report['status'], 'cases': len(report['cases']), 'failure': failure}))
    return int(report['status'] != 'observed')


if __name__ == '__main__': raise SystemExit(main())
