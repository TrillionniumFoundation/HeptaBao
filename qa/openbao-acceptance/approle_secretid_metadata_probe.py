#!/usr/bin/env python3
"""Official-only SecretID metadata parsing and immutable credential observations."""
from __future__ import annotations
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import tempfile
from bao_http import SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from official_openbao_launcher import verify_inputs, start_oracle, stop_oracle, restart_oracle
from online_evidence import admit_output, source_identity
from approle_token_cidrs_probe import Trace as BaseTrace
from radius_cidrs_live import SourceClient
from userpass_password_live import free_port, private_parent, safe_files

MOUNT = 'approle-metadata-probe'
POLICY = 'approle-metadata-read'
KV = 'approle-metadata-kv/item'
MODES = tuple((issue, kind) for issue in ('random', 'custom') for kind in ('service', 'batch'))
INPUTS = (
    ('omitted', {}), ('null', {'metadata': None}), ('empty', {'metadata': ''}),
    ('json_empty', {'metadata': '{}'}), ('json_null', {'metadata': 'null'}),
    ('json_map', {'metadata': '{"env":"prod","team":"ops"}'}),
    ('role_conflict', {'metadata': '{"role_name":"spoofed","env":"prod"}'}),
    ('json_duplicate', {'metadata': '{"env":"first","env":"last"}'}),
    ('json_number', {'metadata': '{"n":12}'}), ('json_bool', {'metadata': '{"flag":true}'}),
    ('json_value_null', {'metadata': '{"empty":null}'}),
    ('json_nested', {'metadata': '{"nested":{"env":"prod"}}'}),
    ('json_array_value', {'metadata': '{"values":["a","b"]}'}),
    ('json_array', {'metadata': '["a","b"]'}),
    ('json_scalar', {'metadata': '12'}), ('json_quoted', {'metadata': '"prod"'}),
    ('invalid_json', {'metadata': '{"env":'}),
    ('csv', {'metadata': 'env=prod,team=ops'}),
    ('csv_duplicate', {'metadata': 'env=first,env=last'}),
    ('csv_spaces', {'metadata': ' env = prod ,team= ops '}),
    ('csv_equals', {'metadata': 'note=a=b'}), ('csv_bare', {'metadata': 'env'}),
    ('csv_empty_key', {'metadata': '=prod'}), ('csv_empty_value', {'metadata': 'env='}),
    ('direct_map', {'metadata': {'env': 'prod'}}),
    ('direct_list', {'metadata': ['env=prod', 'team=ops']}),
    ('direct_number', {'metadata': 12}), ('direct_bool', {'metadata': False}),
)
SCENARIOS = frozenset(f'{phase}.{issue}.{kind}' for phase in ('parse', 'lifecycle') for issue, kind in MODES) | {'restart'}
SAFE_KEYS = {'env', 'team', 'role_name', 'n', 'flag', 'empty', 'nested', 'values', 'note', 'owner', '', ' env '}
SAFE_VALUES = {'prod', 'ops', 'spoofed', 'first', 'last', '12', 'true', 'false', '0', '', 'a=b',
               ' prod ', ' ops ', 'one', 'two', 'control', 'a', 'b'}


def metadata_projection(value):
    if value is None: return {'shape': 'null'}
    if not isinstance(value, dict): return {'shape': type(value).__name__}
    projected = {}
    for key, item in sorted(value.items()):
        safe_key = key if key in SAFE_KEYS else 'key_sha256_'+hashlib.sha256(key.encode()).hexdigest()
        if isinstance(item, str) and (item in SAFE_VALUES or re.fullmatch(r'meta-(random|custom)-(service|batch)(-life)?', item)):
            projected[safe_key] = item
        else:
            projected[safe_key] = {'type': type(item).__name__, 'sha256': hashlib.sha256(json.dumps(item, sort_keys=True).encode()).hexdigest()}
    return {'shape': 'map', 'value': projected}


class Trace(BaseTrace):
    def call(self, name, method, path, body=None, **kwargs):
        status, value = super().call(name, method, path, body, **kwargs)
        row = self.rows[-1]
        for label, container, key in (('auth_metadata', value.get('auth') or {}, 'metadata'),
                ('data_metadata', value.get('data') or {}, 'metadata'),
                ('lookup_meta', value.get('data') or {}, 'meta'),
                ('custom_metadata', value.get('data') or {}, 'custom_metadata')):
            row[label] = metadata_projection(container[key]) if key in container else {'shape': 'missing'}
        errors = value.get('errors') or []
        row['metadata_error'] = any(isinstance(e, str) and 'metadata' in e.lower() for e in errors)
        row['token_echo'] = bool((value.get('auth') or {}).get('client_token'))
        return status, value

    def observe(self, name, **facts):
        if not re.fullmatch(r'[a-z0-9_.]{1,140}', name) or any(r['case'] == name for r in self.rows) or any(type(v) is not bool for v in facts.values()):
            raise ValueError('invalid_observation')
        self.rows.append(dict(case=name, **facts))

    def finish(self, name):
        if name not in SCENARIOS or name in self.finished: raise ValueError('invalid_scenario')
        self.finished.append(name)


def credential(body):
    raw = (body.get('auth') or {}).get('client_token')
    if not isinstance(raw, str) or not raw: raise ScenarioFailure('successful_login_missing_credential')
    return raw


def role(t, prefix, issue, kind, life=False):
    name = f'meta-{issue}-{kind}'+('-life' if life else '')
    path = f'auth/{MOUNT}/role/{name}'
    t.require(prefix+'.role', 'POST', path, {'token_type': kind, 'token_ttl': 900,
        'token_max_ttl': 1800, 'secret_id_ttl': 1200, 'token_policies': [POLICY]}, status=204)
    rid = t.require(prefix+'.role_id', 'GET', path+'/role-id')['data']['role_id']
    return path, rid


def issue_sid(t, prefix, path, mode, fields):
    fields = dict(fields); custom = None
    if mode == 'custom':
        custom = 'synthetic-'+secrets.token_urlsafe(24); t.sensitive.append(custom); fields['secret_id'] = custom
    status, body = t.call(prefix+'.issue', 'POST', path+('/custom-secret-id' if mode == 'custom' else '/secret-id'), fields)
    if status != 200:
        if custom: t.call(prefix+'.rejected_absent', 'POST', path+'/secret-id/lookup', {'secret_id': custom})
        return None
    data = body.get('data') or {}; sid, accessor = data.get('secret_id'), data.get('secret_id_accessor')
    if not isinstance(sid, str) or not sid or not isinstance(accessor, str) or not accessor:
        raise ScenarioFailure('successful_issue_missing_secret')
    return sid, accessor


def lookup_sid(t, prefix, path, sid, accessor):
    raw = t.call(prefix+'.raw', 'POST', path+'/secret-id/lookup', {'secret_id': sid})
    by_accessor = t.call(prefix+'.accessor', 'POST', path+'/secret-id-accessor/lookup', {'secret_id_accessor': accessor})
    return raw, by_accessor


def login(t, prefix, rid, sid):
    status, body = t.call(prefix, 'POST', f'auth/{MOUNT}/login', {'role_id': rid, 'secret_id': sid}, token='')
    if status != 200: raise ScenarioFailure('accepted_secret_login_failed')
    credential(body)
    return body['auth']


def bearer(t, prefix, raw):
    if not isinstance(raw, str) or not raw: raise ScenarioFailure('missing_bearer_not_admin')
    t.call(prefix+'.kv', 'GET', KV, token=raw)
    t.call(prefix+'.self', 'GET', 'auth/token/lookup-self', token=raw)
    t.call(prefix+'.lookup', 'POST', 'auth/token/lookup', {'token': raw})


def renew(t, prefix, auth):
    raw = credential({'auth': auth})
    t.call(prefix+'.self', 'POST', 'auth/token/renew-self', {'increment': 900}, token=raw)
    t.call(prefix+'.token', 'POST', 'auth/token/renew', {'token': raw, 'increment': 900})
    accessor = auth.get('accessor')
    if accessor:
        t.call(prefix+'.accessor', 'POST', 'auth/token/renew-accessor', {'accessor': accessor, 'increment': 900})
    else:
        t.observe(prefix+'.accessor_not_applicable', absent_accessor=True, endpoint_not_called=True)


def alias(t, prefix, entity, rid):
    _, body = t.call(prefix+'.entity', 'GET', 'identity/entity/id/'+entity)
    aliases = (body.get('data') or {}).get('aliases') or []
    found = [a for a in aliases if a.get('name') == rid]
    if len(found) != 1: raise ScenarioFailure('expected_unique_roleid_alias')
    a = found[0]
    t.call(prefix+'.alias', 'GET', 'identity/entity-alias/id/'+a['id'])
    return a


def run(t, restart):
    t.require('setup.mount', 'POST', 'sys/auth/'+MOUNT, {'type': 'approle'}, status=204)
    t.require('setup.kv', 'POST', 'sys/mounts/approle-metadata-kv', {'type': 'kv', 'options': {'version': '1'}}, status=204)
    t.require('setup.value', 'POST', KV, {'value': 'synthetic'}, status=204)
    t.require('setup.policy', 'PUT', 'sys/policies/acl/'+POLICY, {'policy':
        'path "approle-metadata-kv/*" { capabilities=["read"] } '
        'path "auth/token/lookup-self" { capabilities=["read"] } '
        'path "auth/token/renew-self" { capabilities=["update"] }'}, status=204)
    held = []
    for mode, kind in MODES:
        prefix = f'parse.{mode}.{kind}'; path, rid = role(t, prefix, mode, kind)
        for case, fields in INPUTS:
            name = prefix+'.'+case
            issued = issue_sid(t, name, path, mode, fields)
            if issued is None: continue
            sid, accessor = issued
            lookup_sid(t, name+'.before', path, sid, accessor)
            auth = login(t, name+'.login', rid, sid)
            t.call(name+'.lookup', 'POST', 'auth/token/lookup', {'token': credential({'auth': auth})})
            lookup_sid(t, name+'.after', path, sid, accessor)
        t.finish(prefix)
        prefix = f'lifecycle.{mode}.{kind}'; path, rid = role(t, prefix, mode, kind, True)
        issued = issue_sid(t, prefix+'.initial', path, mode, {'metadata': '{"env":"one","role_name":"spoofed"}'})
        if issued is None: raise ScenarioFailure('lifecycle_issue_failed')
        sid, accessor = issued; auth = login(t, prefix+'.login', rid, sid); raw = credential({'auth': auth})
        entity = auth.get('entity_id')
        if not isinstance(entity, str) or not entity: raise ScenarioFailure('missing_entity')
        a = alias(t, prefix+'.before_custom', entity, rid)
        t.require(prefix+'.custom_write', 'POST', 'identity/entity-alias/id/'+a['id'], {
            'name': rid, 'canonical_id': entity, 'mount_accessor': a['mount_accessor'],
            'custom_metadata': {'owner': 'control'}}, status=200)
        fresh_sid = issue_sid(t, prefix+'.replacement', path, mode, {'metadata': '{"env":"two"}'})
        if fresh_sid is None: raise ScenarioFailure('replacement_issue_failed')
        fresh = login(t, prefix+'.fresh_login', rid, fresh_sid[0])
        t.observe(prefix+'.same_entity', matches=fresh.get('entity_id') == entity,
            distinct_bearer=credential({'auth': fresh}) != raw)
        a = alias(t, prefix+'.after_fresh', entity, rid)
        bearer(t, prefix+'.old', raw); renew(t, prefix+'.renew', auth)
        lookup_sid(t, prefix+'.stored', path, sid, accessor)
        t.call(prefix+'.delete_sid', 'POST', path+'/secret-id/destroy', {'secret_id': sid})
        t.call(prefix+'.deleted_sid', 'POST', path+'/secret-id/lookup', {'secret_id': sid})
        bearer(t, prefix+'.after_delete', raw); renew(t, prefix+'.renew_after_delete', auth)
        t.require(prefix+'.edit_role', 'POST', path, {'token_ttl': 800}, status=204)
        bearer(t, prefix+'.after_role_edit', raw); renew(t, prefix+'.renew_after_role_edit', auth)
        held.append((prefix, path, rid, auth, fresh, fresh_sid, entity))
        t.finish(prefix)
    restart()
    for prefix, path, rid, auth, fresh, sid, entity in held:
        name = 'restart.'+prefix.split('.', 1)[1]
        bearer(t, name+'.old', credential({'auth': auth})); renew(t, name+'.renew', auth)
        lookup_sid(t, name+'.sid', path, *sid)
        alias(t, name+'.identity', entity, rid)
        replayed = login(t, name+'.sid_login', rid, sid[0])
        t.observe(name+'.same_entity', matches=replayed.get('entity_id') == entity)
    t.finish('restart')


def complete(trace):
    return bool(trace and trace.rows and set(trace.finished) == SCENARIOS and len(trace.finished) == len(SCENARIOS)
        and len({r['case'] for r in trace.rows}) == len(trace.rows)
        and all(any(r['case'] == f'parse.{mode}.{kind}.{case}.issue' for r in trace.rows)
            for mode, kind in MODES for case, _ in INPUTS))


def helpers():
    names = ('approle_token_cidrs_probe', 'bao_http', 'core_isolation', 'official_openbao_launcher',
        'online_evidence', 'radius_cidrs_live', 'radius_native_live', 'radius_renewal_live',
        'remote_jwks_live', 'userpass_password_live', 'heptabao.transport', 'smoke')
    return {name: file_hash(Path(importlib.import_module(name).__file__)) for name in names}


def main():
    p = SafeArgumentParser(description=__doc__)
    p.add_argument('--work-parent', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(); output = args.output.absolute(); admitted = admit_output(output)
    bao = verify_inputs(); binary, runner, helper = file_hash(bao), file_hash(Path(__file__)), helpers()
    before = source_identity(ROOT, bao)
    work = Path(tempfile.mkdtemp(prefix='approle-sid-metadata-', dir=private_parent(args.work_parent)))
    prior = os.environ.get('HB_ORACLE_WORK_ROOT'); os.environ['HB_ORACLE_WORK_ROOT'] = str(work)
    oracle = trace = None; failure = None; scan = False; stopped = False; unchanged = False; after = None
    def failed(error):
        nonlocal failure
        failure = failure or 'fixture_'+type(error).__name__
    def interrupted(signum, frame): raise ScenarioFailure('interrupted')
    handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        oracle = start_oracle(free_port()); root = Path(oracle['root'])
        admin = private_read(oracle['token_file']).decode().strip()
        trace = Trace(SourceClient(oracle['address'], oracle['ca_file'], admin))
        trace.sensitive.extend((admin, private_read(root/'unseal.key').decode().strip()))
        def restart(): stop_oracle(oracle); restart_oracle(oracle)
        run(trace, restart)
    except Exception as error: failed(error)
    finally:
        try:
            if oracle is not None: stop_oracle(oracle)
        except Exception as error: failed(error)
        finally:
            if prior is None: os.environ.pop('HB_ORACLE_WORK_ROOT', None)
            else: os.environ['HB_ORACLE_WORK_ROOT'] = prior
            for sig, handler in handlers.items(): signal.signal(sig, handler)
    try:
        if trace is not None and oracle is not None: scan = safe_files(Path(oracle['root']), trace.sensitive)
        stopped = oracle is None or oracle['process'].poll() is not None
        after = source_identity(ROOT, bao)
        unchanged = binary == file_hash(bao) and runner == file_hash(Path(__file__)) and helper == helpers() and before == after
    except Exception as error: failed(error)
    status = 'observed' if failure is None and complete(trace) and scan and unchanged and stopped and not before['source_dirty'] else 'failed'
    report = {'schema': 'heptabao.approle-secretid-metadata-probe.v1', 'status': status,
        'failure': failure, 'failure_at': trace.rows[-1]['case'] if failure and trace and trace.rows else None,
        'cases': trace.rows if trace else [], 'completed_scenarios': trace.finished if trace else [],
        'inputs_unchanged': unchanged, 'secrets_absent': scan, 'processes_stopped': stopped,
        'oracle_binary_sha256': binary, 'runner_sha256': runner, 'helper_sha256': helper,
        'frozen_helpers_source': before, 'frozen_helpers_source_after': after,
        'runner_is_separately_hashed_staged_file': True, 'target_version': '2.6.2', 'oracle_only': True,
        'candidate_executed': False, 'source_qualified': False, 'full_openbao_compatibility': False,
        'mutating_requests_retried': False, 'not_covered': ['metadata size limits', 'local-only SecretIDs', 'MFA', 'HA'],
        'retained_work_dir': str(work)}
    if trace and any(secret in json.dumps(report) for secret in trace.sensitive): raise ValueError('sensitive_report')
    if admit_output(output) != admitted: raise ValueError('output_parent_changed')
    private_write(output, report, replace=False)
    print(json.dumps({'status': status, 'cases': len(report['cases']), 'scenarios': len(report['completed_scenarios']), 'failure': failure}))
    return int(status != 'observed')


if __name__ == '__main__': raise SystemExit(main())
