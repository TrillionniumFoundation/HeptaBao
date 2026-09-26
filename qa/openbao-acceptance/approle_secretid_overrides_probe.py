#!/usr/bin/env python3
"""Pinned official-only per-SecretID CIDR observations; no candidate parity claim."""
from __future__ import annotations
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
from approle_secret_cidrs_probe import Trace as RoleSourceTrace
from radius_cidrs_live import SourceClient
from userpass_password_live import free_port, private_parent, safe_files

MOUNT, POLICY, KV = 'approle-sid-overrides', 'approle-sid-overrides', 'approle-sid-overrides-kv/item'
MODES, FIELDS, KINDS = ('random', 'custom'), ('cidr_list', 'token_bound_cidrs'), ('service', 'batch')
SCENARIOS = frozenset(
    {f'api.{mode}.{field}' for mode in MODES for field in FIELDS}
    | {f'subset.{mode}.{field}' for mode in MODES for field in FIELDS}
    | {f'consume.{mode}.{kind}.{uses}' for mode in MODES for kind in KINDS for uses in ('one', 'two', 'unlimited')}
    | {f'source_change.{mode}.{uses}' for mode in MODES for uses in ('two', 'unlimited')}
    | {f'override.{mode}.{kind}' for mode in MODES for kind in KINDS}
    | {f'fallback.{mode}' for mode in MODES} | {'restart'})
SHAPES = (
    ('omitted', None, False), ('null', None, True), ('empty_list', [], True), ('empty_string', '', True),
    ('list', ['127.0.0.1/32'], True), ('csv', '127.0.0.1/32,127.0.0.2/32', True),
    ('host_bits', ['127.0.0.99/24'], True), ('bare_ip', ['127.0.0.1'], True),
    ('bad_mask', ['127.0.0.1/33'], True), ('object', {'invalid': True}, True),
    ('ipv6', ['::1/128'], True))
REQUIRED = frozenset({'setup.mount', 'setup.kv', 'setup.value', 'setup.policy'}
    | {f'api.{mode}.{field}.{case}.issue' for mode in MODES for field in FIELDS for case, _, _ in SHAPES}
    | {f'subset.{mode}.{field}.{case}.issue' for mode in MODES for field in FIELDS
       for case in ('narrow', 'equal', 'wider', 'outside', 'mixed', 'empty', 'null', 'union_parent')}
    | {f'consume.{mode}.{kind}.{uses}.{case}' for mode in MODES for kind in KINDS
       for uses in ('one', 'two', 'unlimited') for case in ('denied', 'after_denied.raw', 'allowed', 'after_subsequent.accessor')}
    | {f'source_change.{mode}.{uses}.{case}' for mode in MODES for uses in ('two', 'unlimited')
       for case in ('current_subset_denial', 'after_subset_denial.raw', 'role_cleared', 'final.accessor')}
    | {f'override.{mode}.{kind}.{case}' for mode in MODES for kind in KINDS
       for case in ('initial', 'role_token_moved', 'after_token_change', 'role_cleared', 'after_clear', 'before_restart.raw')}
    | {f'fallback.{mode}.{case}' for mode in MODES for case in ('initial', 'role_moved', 'after_change', 'role_cleared', 'after_clear', 'final.raw')}
    | {f'restart.override.{mode}.{kind}.{case}' for mode in MODES for kind in KINDS
       for case in ('sid.raw', 'snapshot', 'disallowed_source', 'new_login')})


class Trace(RoleSourceTrace):
    def call(self, name, method, path, body=None, **kwargs):
        status, value = super().call(name, method, path, body, **kwargs)
        errors = value.get('errors') or []
        if not isinstance(errors, list) or any(not isinstance(v, str) for v in errors):
            raise ValueError('unexpected_error_shape')
        self.rows[-1].update(subset_error=any('subset' in e.lower() for e in errors),
            source_error=any('source address' in e.lower() for e in errors))
        return status, value

    def observe(self, name, **facts):
        if (not re.fullmatch('[a-z0-9_.]{1,140}', name) or any(r['case'] == name for r in self.rows)
            or not facts or any(type(v) is not bool for v in facts.values())):
            raise ValueError('unsafe_observation')
        self.rows.append({'case': name, **facts})

    def finish(self, name):
        if name not in SCENARIOS or name in self.finished: raise ValueError('invalid_scenario')
        self.finished.append(name)


def complete(t):
    if t is None or not t.rows or len(t.finished) != len(SCENARIOS) or set(t.finished) != SCENARIOS:
        return False
    names = [row.get('case') for row in t.rows]
    return (all(isinstance(n, str) and re.fullmatch('[a-z0-9_.]{1,140}', n) for n in names)
        and len(names) == len(set(names)) and REQUIRED <= set(names))


def path(role): return f'auth/{MOUNT}/role/{role}'


def role(t, name, role_name, fields=None):
    fields = dict(fields or {})
    t.require(name+'.role', 'POST', path(role_name), dict(token_ttl=600, token_max_ttl=1800,
        token_policies=[POLICY], **fields), status=204)
    rid = t.require(name+'.role_id', 'GET', path(role_name)+'/role-id')['data']['role_id']
    return {'role': role_name, 'role_id': rid}


def issue(t, name, base, mode, fields):
    fields = dict(fields); raw = None
    if mode == 'custom':
        raw = 'synthetic-custom-'+secrets.token_urlsafe(24); fields['secret_id'] = raw; t.sensitive.append(raw)
    status, body = t.call(name, 'POST', path(base['role'])+('/custom-secret-id' if mode == 'custom' else '/secret-id'), fields)
    data = body.get('data') or {}
    raw = data.get('secret_id') or raw
    if status == 200:
        if not isinstance(raw, str) or not raw or not isinstance(data.get('secret_id_accessor'), str):
            raise ScenarioFailure('issued_sid_missing_credential')
        return dict(base, secret_id=raw, secret_id_accessor=data['secret_id_accessor'])
    # A custom input is already known, so confirm rejection did not install it.
    if raw is not None: t.call(name+'.rejected_custom_lookup', 'POST', path(base['role'])+'/secret-id/lookup', {'secret_id': raw})
    return None


def lookups(t, name, creds):
    raw_status, raw = t.call(name+'.raw', 'POST', path(creds['role'])+'/secret-id/lookup', {'secret_id': creds['secret_id']})
    accessor_status, accessor = t.call(name+'.accessor', 'POST', path(creds['role'])+'/secret-id-accessor/lookup',
        {'secret_id_accessor': creds['secret_id_accessor']})
    t.observe(name+'.pair', both_present=raw_status == accessor_status == 200,
        same_data=raw_status == accessor_status == 200 and raw.get('data') == accessor.get('data'))
    return raw_status, raw.get('data')


def login(t, name, creds, source='127.0.0.1', spoof=False):
    _, body = t.call(name, 'POST', 'auth/'+MOUNT+'/login',
        {'role_id': creds['role_id'], 'secret_id': creds['secret_id']}, token='', source=source, spoof=spoof)
    return body.get('auth') or {}


def bearer(t, name, auth):
    if not auth.get('client_token'):
        t.observe(name+'.not_issued', credential_issued=False); return
    raw = auth['client_token']
    t.call(name+'.lookup', 'POST', 'auth/token/lookup', {'token': raw})
    t.call(name+'.from_one', 'GET', KV, token=raw)
    t.call(name+'.from_two', 'GET', KV, token=raw, source='127.0.0.2')


def api(t):
    for mode in MODES:
        for field in FIELDS:
            name = f'api.{mode}.{field}'; base = role(t, name, name.replace('.', '-'))
            for label, value, present in SHAPES:
                creds = issue(t, name+'.'+label+'.issue', base, mode, {field: value} if present else {})
                if creds: lookups(t, name+'.'+label+'.lookup', creds)
            t.finish(name)


def subsets(t):
    for mode in MODES:
        for field in FIELDS:
            name = f'subset.{mode}.{field}'; role_field = 'secret_id_bound_cidrs' if field == 'cidr_list' else field
            base = role(t, name, name.replace('.', '-'), {role_field: ['127.0.0.0/24']})
            for label, value in (('narrow', ['127.0.0.1/32']), ('equal', ['127.0.0.0/24']),
                ('wider', ['127.0.0.0/8']), ('outside', ['127.0.1.0/24']),
                ('mixed', ['127.0.0.1/32', '127.0.1.1/32']), ('empty', []), ('null', None)):
                creds = issue(t, name+'.'+label+'.issue', base, mode, {field: value})
                if creds: lookups(t, name+'.'+label+'.lookup', creds)
            t.require(name+'.split_parent', 'POST', path(base['role']),
                {role_field: ['127.0.0.0/25', '127.0.0.128/25']}, status=204)
            creds = issue(t, name+'.union_parent.issue', base, mode, {field: ['127.0.0.0/24']})
            if creds: lookups(t, name+'.union_parent.lookup', creds)
            t.finish(name)


def consumption(t):
    for mode in MODES:
        for kind in KINDS:
            for label, uses in (('one', 1), ('two', 2), ('unlimited', 0)):
                name = f'consume.{mode}.{kind}.{label}'
                base = role(t, name, name.replace('.', '-'), {'token_type': kind, 'secret_id_num_uses': uses})
                creds = issue(t, name+'.issue', base, mode, {'cidr_list': ['127.0.0.1/32']})
                if creds is None: raise ScenarioFailure('valid_sid_setup_rejected')
                before_status, before = lookups(t, name+'.before', creds)
                login(t, name+'.denied', creds, '127.0.0.2', True)
                after_status, after = lookups(t, name+'.after_denied', creds)
                t.observe(name+'.denial_delta', both_present=before_status == after_status == 200,
                    unchanged=before_status == after_status == 200 and before == after)
                auth = login(t, name+'.allowed', creds); lookups(t, name+'.after_allowed', creds)
                bearer(t, name+'.issued_bearer', auth)
                login(t, name+'.subsequent', creds); lookups(t, name+'.after_subsequent', creds)
                t.finish(name)


def source_changes(t):
    for mode in MODES:
        for label, uses in (('two', 2), ('unlimited', 0)):
            name = f'source_change.{mode}.{label}'
            base = role(t, name, name.replace('.', '-'), {'secret_id_bound_cidrs': ['127.0.0.0/24'], 'secret_id_num_uses': uses})
            creds = issue(t, name+'.issue', base, mode, {'cidr_list': ['127.0.0.1/32']})
            if creds is None: raise ScenarioFailure('valid_sid_setup_rejected')
            before_status, before = lookups(t, name+'.before', creds)
            t.require(name+'.role_moved', 'POST', path(base['role']), {'secret_id_bound_cidrs': ['127.0.0.2/32']}, status=204)
            login(t, name+'.current_subset_denial', creds)
            after_status, after = lookups(t, name+'.after_subset_denial', creds)
            t.observe(name+'.subset_delta', both_present=before_status == after_status == 200,
                unchanged=before_status == after_status == 200 and before == after)
            t.require(name+'.role_cleared', 'POST', path(base['role']), {'secret_id_bound_cidrs': []}, status=204)
            auth = login(t, name+'.allowed_after_clear', creds); lookups(t, name+'.after_clear_login', creds)
            bearer(t, name+'.issued_after_clear', auth)
            login(t, name+'.sid_source_still_denied', creds, '127.0.0.2', True)
            lookups(t, name+'.final', creds); t.finish(name)


def overrides(t):
    held = []
    for mode in MODES:
        for kind in KINDS:
            name = f'override.{mode}.{kind}'
            base = role(t, name, name.replace('.', '-'), {'token_type': kind,
                'secret_id_bound_cidrs': ['127.0.0.1/32'], 'token_bound_cidrs': ['127.0.0.0/24']})
            creds = issue(t, name+'.issue', base, mode, {'cidr_list': ['127.0.0.1/32'], 'token_bound_cidrs': ['127.0.0.2/32']})
            if creds is None: raise ScenarioFailure('valid_sid_setup_rejected')
            initial = login(t, name+'.initial', creds); bearer(t, name+'.initial_bearer', initial)
            t.require(name+'.role_token_moved', 'POST', path(base['role']), {'token_bound_cidrs': ['127.0.0.1/32']}, status=204)
            moved = login(t, name+'.after_token_change', creds); bearer(t, name+'.changed_bearer', moved)
            t.require(name+'.role_cleared', 'POST', path(base['role']), {'token_bound_cidrs': [], 'secret_id_bound_cidrs': []}, status=204)
            login(t, name+'.sid_source_denied', creds, '127.0.0.2', True)
            current = login(t, name+'.after_clear', creds); bearer(t, name+'.cleared_bearer', current)
            bearer(t, name+'.old_still_bound', initial)
            before = lookups(t, name+'.before_restart', creds)
            held.append((name, creds, initial, current, before)); t.finish(name)
    return held


def fallback(t):
    for mode in MODES:
        name = 'fallback.'+mode
        base = role(t, name, name.replace('.', '-'), {'token_bound_cidrs': ['127.0.0.1/32']})
        creds = issue(t, name+'.issue', base, mode, {'token_bound_cidrs': [], 'cidr_list': []})
        if creds is None: raise ScenarioFailure('valid_sid_setup_rejected')
        initial = login(t, name+'.initial', creds, '127.0.0.2'); bearer(t, name+'.initial_bearer', initial)
        t.require(name+'.role_moved', 'POST', path(base['role']), {'token_bound_cidrs': ['127.0.0.2/32']}, status=204)
        moved = login(t, name+'.after_change', creds); bearer(t, name+'.changed_bearer', moved)
        t.require(name+'.role_cleared', 'POST', path(base['role']), {'token_bound_cidrs': []}, status=204)
        current = login(t, name+'.after_clear', creds); bearer(t, name+'.cleared_bearer', current)
        bearer(t, name+'.old_still_bound', initial); lookups(t, name+'.final', creds); t.finish(name)


def run(t, restart):
    t.require('setup.mount', 'POST', 'sys/auth/'+MOUNT, {'type': 'approle'}, status=204)
    t.require('setup.kv', 'POST', 'sys/mounts/approle-sid-overrides-kv', {'type': 'kv', 'options': {'version': '1'}}, status=204)
    t.require('setup.value', 'POST', KV, {'value': 'synthetic'}, status=204)
    t.require('setup.policy', 'PUT', 'sys/policies/acl/'+POLICY,
        {'policy': 'path "approle-sid-overrides-kv/*" { capabilities=["read"] }'}, status=204)
    api(t); subsets(t); consumption(t); source_changes(t); held = overrides(t); fallback(t)
    restart()
    for name, creds, initial, current, before in held:
        prefix = 'restart.'+name
        after = lookups(t, prefix+'.sid', creds)
        t.observe(prefix+'.snapshot', unchanged=before[0] == after[0] == 200 and before[1] == after[1])
        bearer(t, prefix+'.old', initial); bearer(t, prefix+'.current', current)
        login(t, prefix+'.disallowed_source', creds, '127.0.0.2', True)
        fresh = login(t, prefix+'.new_login', creds); bearer(t, prefix+'.fresh', fresh)
    t.finish('restart')


def helpers():
    names = ('approle_secret_cidrs_probe', 'approle_token_cidrs_probe', 'bao_http', 'core_isolation',
        'official_openbao_launcher', 'online_evidence', 'radius_cidrs_live', 'radius_native_live',
        'radius_renewal_live', 'remote_jwks_live', 'userpass_password_live', 'heptabao.transport', 'smoke')
    return {name: file_hash(Path(importlib.import_module(name).__file__)) for name in names}


def main():
    p = SafeArgumentParser(description=__doc__)
    p.add_argument('--work-parent', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(); output = args.output.absolute(); admitted = admit_output(output)
    bao = verify_inputs(); binary, runner, helper = file_hash(bao), file_hash(Path(__file__)), helpers()
    before = source_identity(ROOT, bao)
    work = Path(tempfile.mkdtemp(prefix='approle-sid-overrides-', dir=private_parent(args.work_parent)))
    prior = os.environ.get('HB_ORACLE_WORK_ROOT'); os.environ['HB_ORACLE_WORK_ROOT'] = str(work)
    oracle = t = None; failure = None; scan = False
    def interrupted(signum, frame): raise ScenarioFailure('interrupted')
    handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        oracle = start_oracle(free_port())
        root = Path(oracle['root']); bearer = private_read(oracle['token_file']).decode().strip()
        t = Trace(SourceClient(oracle['address'], oracle['ca_file'], bearer))
        t.sensitive.extend((bearer, private_read(root/'unseal.key').decode().strip()))
        def restart(): stop_oracle(oracle); restart_oracle(oracle)
        run(t, restart)
    except Exception as error: failure = 'fixture_'+type(error).__name__
    finally:
        try:
            if oracle is not None: stop_oracle(oracle)
        finally:
            if prior is None: os.environ.pop('HB_ORACLE_WORK_ROOT', None)
            else: os.environ['HB_ORACLE_WORK_ROOT'] = prior
            for sig, handler in handlers.items(): signal.signal(sig, handler)
    if t is not None and oracle is not None: scan = safe_files(Path(oracle['root']), t.sensitive)
    stopped = oracle is None or oracle['process'].poll() is not None
    after = source_identity(ROOT, bao)
    unchanged = binary == file_hash(bao) and runner == file_hash(Path(__file__)) and helper == helpers() and before == after
    status = 'observed' if failure is None and complete(t) and scan and unchanged and stopped and not before['source_dirty'] else 'failed'
    report = {'schema': 'heptabao.approle-secretid-overrides-probe.v1', 'status': status,
        'failure': failure, 'failure_at': t.rows[-1]['case'] if failure and t and t.rows else None,
        'cases': t.rows if t else [], 'completed_scenarios': t.finished if t else [],
        'inputs_unchanged': unchanged, 'secrets_absent': scan, 'processes_stopped': stopped,
        'oracle_binary_sha256': binary, 'runner_sha256': runner, 'helper_sha256': helper,
        'frozen_helpers_source': before, 'frozen_helpers_source_after': after,
        'runner_is_separately_hashed_staged_file': True, 'target_version': '2.6.2', 'oracle_only': True,
        'candidate_executed': False, 'source_qualified': False, 'full_openbao_compatibility': False,
        'numeric_CIDR_profile_only': True, 'mutating_requests_retried': False,
        'not_covered': ['metadata parsing', 'SecretID local-only setting', 'MFA', 'HA', 'token child delegation', 'IPv6 actual source sockets'],
        'retained_work_dir': str(work)}
    if t and any(secret in json.dumps(report) for secret in t.sensitive): raise ValueError('sensitive_report')
    if admit_output(output) != admitted: raise ValueError('output_parent_changed')
    private_write(output, report, replace=False)
    print(json.dumps({'status': status, 'cases': len(report['cases']), 'scenarios': len(report['completed_scenarios']), 'failure': failure}))
    return int(status != 'observed')


if __name__ == '__main__': raise SystemExit(main())
