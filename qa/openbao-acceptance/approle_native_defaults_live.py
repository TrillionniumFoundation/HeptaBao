#!/usr/bin/env python3
"""AppRole role defaults, null updates and SecretID issuance vs OpenBao 2.6.2.

SecretID lookup retains requested TTL while absolute expiry uses the issued mount
cap. The candidate rejects expired credentials immediately; official cleanup may
lag until its periodic tidy, so this difference is not claimed as parity.
"""
from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
import re
import shutil
import tempfile
import time
from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from official_openbao_launcher import BINARY_SHA256, start_oracle, stop_oracle, restart_oracle
from oidc_renewal_live import free_port
from online_evidence import admit_output, source_identity
from radius_renewal_live import renewal_token_shape
from remote_jwks_live import Instance

ROUTES = ('self', 'token', 'accessor')
FIELDS = ('token_ttl', 'token_max_ttl', 'token_period', 'token_explicit_max_ttl',
          'secret_id_ttl', 'token_num_uses', 'secret_id_num_uses')
REQUIRED = frozenset({
    'default.fields', 'default.issue.parameters', 'default.lookup.fields',
    'default.unlimited_unchanged', 'nullable.fields', 'nullable.partial.fields',
    'finite.issue.parameters', 'finite.lookup.fields', 'finite.accessor_equal',
    'finite.remaining.fields', 'finite.timestamps', 'finite.exhausted_lookup.status',
    'finite.exhausted_accessor.status', 'finite.exhausted_login.status',
    'finite.null_ttl.parameters', 'finite.null_uses.status', 'finite.zero_ttl.status',
    'finite.zero_uses.status', 'finite.larger_ttl.status', 'finite.larger_uses.status',
    'snapshot.lookup.fields', 'snapshot.unchanged', 'snapshot.old_valid.lease',
    'default.after_shrink.lease', 'periodic.null.fields', 'periodic.login.lease',
    'restart.default.fields', 'restart.default_login.lease', 'restart.snapshot_unchanged',
    'restart.snapshot_login.lease', 'secrets_absent', 'complete',
}) | frozenset(phase + '.' + via + suffix
    for phase in ['default.renew', 'default.current_mount', 'periodic.renew', 'restart.renew']
    for via in ROUTES for suffix in ['.status', '.lease', '.shape'])


def role_path(name):
    return 'auth/native-approle/role/' + name


def secret_timestamp(value):
    if not isinstance(value, str):
        raise ValueError('missing_secret_timestamp')
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def zero_expiry(value):
    return isinstance(value, str) and value in ('0001-01-01T00:00:00Z', '0001-01-01T00:00:00+00:00')


class Trace:
    def __init__(self, client, rows, diagnostics):
        self.client, self.rows, self.diagnostics = client, rows, diagnostics
        self.sensitive = []

    def check(self, name, condition, **observations):
        if (not isinstance(name, str) or re.fullmatch(r'[a-z0-9_.]{1,140}', name) is None
                or any(type(v) not in (int, bool) for v in observations.values())):
            raise ValueError('unsafe_observation')
        self.rows.append({'case': 'approle_native_defaults.' + name, 'passed': condition is True, **observations})
        if condition is not True:
            raise ScenarioFailure('approle_native_defaults.' + name)

    def call(self, name, path, fields=None, *, method='POST', bearer=None, status=200, wrap=None):
        response = self.client.request(method, '/v1/' + path, fields, token=bearer, wrap_ttl=wrap)
        self.check(name + '.status', response.status == status, status=response.status)
        return response.body

    def lease(self, name, auth, *, exact=None, maximum=None, nonexpiring=False):
        ttl = auth.get('lease_duration')
        diagnostic = {'case': 'approle_native_defaults.' + name, 'lease_is_integer': type(ttl) is int}
        if type(ttl) is int:
            diagnostic['lease_duration'] = ttl
        if exact is not None:
            diagnostic['expected_ttl'] = exact
        if maximum is not None:
            diagnostic['maximum_ttl'] = maximum
        self.diagnostics.append(diagnostic)
        self.check(name + '.lease', type(ttl) is int and (ttl == 0 if nonexpiring else ttl > 0)
                   and (exact is None or ttl == exact) and (maximum is None or ttl <= maximum))

    def auth(self, name, body, *, exact=None, maximum=None, nonexpiring=False):
        auth = body.get('auth') or {}
        self.check(name + '.credentials', all(isinstance(auth.get(k), str) and bool(auth[k])
                   for k in ('client_token', 'accessor')))
        self.sensitive.append(auth['client_token'])
        self.lease(name, auth, exact=exact, maximum=maximum, nonexpiring=nonexpiring)
        self.check(name + '.renewable', auth.get('renewable') is (not nonexpiring))
        return auth

    def renew(self, name, auth, *, via='self', increment=None, exact=None, maximum=None, status=200):
        fields = {} if increment is None else {'increment': increment}
        path = {'self': 'renew-self', 'token': 'renew', 'accessor': 'renew-accessor'}[via]
        if via == 'token':
            fields['token'] = auth['client_token']
        elif via == 'accessor':
            fields['accessor'] = auth['accessor']
        name += '.' + via
        body = self.call(name, 'auth/token/' + path, fields,
                         bearer=auth['client_token'] if via == 'self' else None, status=status)
        if status != 200:
            self.check(name + '.no_credentials', not body.get('auth') and not body.get('wrap_info'))
            return
        renewed = body.get('auth') or {}
        self.lease(name, renewed, exact=exact, maximum=maximum)
        self.check(name + '.shape', renewed.get('renewable') is True
                   and renewal_token_shape(renewed, auth['client_token'], via_accessor=via == 'accessor'))


def run_scenarios(client, restart, rows, diagnostics, *, wait=time.sleep):
    t = Trace(client, rows, diagnostics)
    def write(label, name, fields):
        return t.call(label, role_path(name), fields, status=204)
    def read(label, name, expected):
        data = t.call(label, role_path(name), method='GET').get('data') or {}
        t.check(label + '.fields', all(type(data.get(k)) is int and data[k] == v for k, v in zip(FIELDS, expected)))
        return data
    def issue(label, name, ttl, uses=0, fields=None):
        data = t.call(label, role_path(name) + '/secret-id', fields or {}).get('data') or {}
        t.check(label + '.parameters', data.get('secret_id_ttl') == ttl and data.get('secret_id_num_uses') == uses)
        t.check(label + '.credentials', all(isinstance(data.get(k), str) and bool(data[k]) for k in ['secret_id', 'secret_id_accessor']))
        t.sensitive.append(data['secret_id'])
        return data
    def lookup(label, name, secret, ttl, uses, delta, accessor=False):
        field = 'secret_id_accessor' if accessor else 'secret_id'
        suffix = '/secret-id-accessor/lookup' if accessor else '/secret-id/lookup'
        data = t.call(label, role_path(name) + suffix, {field: secret[field]}).get('data') or {}
        created = secret_timestamp(data.get('creation_time'))
        updated = secret_timestamp(data.get('last_updated_time'))
        expiry = data.get('expiration_time')
        time_ok = (zero_expiry(expiry) if delta == 0 else not zero_expiry(expiry)
                   and (secret_timestamp(expiry) - created).total_seconds() == delta)
        t.check(label + '.fields', data.get('secret_id_ttl') == ttl and data.get('secret_id_num_uses') == uses
                and data.get('secret_id_accessor') == secret['secret_id_accessor'] and updated >= created and time_ok)
        return data
    def login(label, name, secret, lease=None, status=200):
        role_id = t.call(label + '.role_id', role_path(name) + '/role-id', method='GET')['data']['role_id']
        t.sensitive.append(role_id)
        body = t.call(label, 'auth/native-approle/login', {'role_id': role_id, 'secret_id': secret['secret_id']}, bearer='', status=status)
        if status != 200:
            t.check(label + '.no_credentials', not body.get('auth') and not body.get('wrap_info'))
            return
        return t.auth(label, body, exact=lease)
    def tune(label, default, maximum):
        t.call(label, 'sys/auth/native-approle/tune', {'default_lease_ttl': default, 'max_lease_ttl': maximum}, status=204)

    t.call('mount', 'sys/auth/native-approle', {'type': 'approle'}, status=204)
    tune('mount.initial', 75, 600)
    write('default.create', 'default', {})
    read('default', 'default', (0, 0, 0, 0, 0, 0, 0))
    unlimited = issue('default.issue', 'default', 0)
    original = lookup('default.lookup', 'default', unlimited, 0, 0, 0)
    ordinary = login('default.login_one', 'default', unlimited, 75)
    login('default.login_two', 'default', unlimited, 75)
    latest = lookup('default.after_logins', 'default', unlimited, 0, 0, 0)
    t.check('default.unlimited_unchanged', all(original[k] == latest[k] for k in ['creation_time', 'expiration_time', 'last_updated_time']))
    for via in ROUTES:
        t.renew('default.renew', ordinary, via=via, exact=75)
    tune('mount.changed_default', 95, 600)
    for via in ROUTES:
        t.renew('default.current_mount', ordinary, via=via, exact=95)
    initial = dict(zip(FIELDS, [40, 300, 20, 180, 120, 3, 4]))
    write('nullable.create', 'nullable', initial)
    write('nullable.nulls', 'nullable', {key: None for key in FIELDS})
    read('nullable', 'nullable', (40, 300, 20, 180, 120, 0, 0))
    write('nullable.omit', 'nullable', {})
    read('nullable.partial', 'nullable', (40, 300, 20, 180, 120, 0, 0))

    tune('finite.mount_cap', 0, 60)
    write('finite.create', 'finite', {'token_ttl': 10, 'secret_id_ttl': 120, 'secret_id_num_uses': 2})
    finite = issue('finite.issue', 'finite', 60, 2)
    original_finite = lookup('finite.lookup', 'finite', finite, 120, 2, 60)
    accessor = lookup('finite.accessor', 'finite', finite, 120, 2, 60, accessor=True)
    t.check('finite.accessor_equal', all(original_finite[k] == accessor[k] for k in ['creation_time', 'expiration_time', 'last_updated_time', 'secret_id_ttl']))
    wait(1.1)
    login('finite.first', 'finite', finite, 10)
    remaining = lookup('finite.remaining', 'finite', finite, 120, 1, 60)
    t.check('finite.timestamps', remaining['creation_time'] == original_finite['creation_time']
            and remaining['expiration_time'] == original_finite['expiration_time']
            and secret_timestamp(remaining['last_updated_time']) > secret_timestamp(original_finite['last_updated_time']))
    login('finite.second', 'finite', finite, 10)
    t.call('finite.exhausted_lookup', role_path('finite') + '/secret-id/lookup', {'secret_id': finite['secret_id']}, status=204)
    t.call('finite.exhausted_accessor', role_path('finite') + '/secret-id-accessor/lookup', {'secret_id_accessor': finite['secret_id_accessor']}, status=404)
    login('finite.exhausted_login', 'finite', finite, status=400)
    null_ttl = issue('finite.null_ttl', 'finite', 60, 2, fields={'ttl': None})
    lookup('finite.null_ttl_lookup', 'finite', null_ttl, 120, 2, 60)
    for label, fields in [('null_uses', {'num_uses': None}), ('zero_ttl', {'ttl': 0}),
                          ('zero_uses', {'num_uses': 0}), ('larger_ttl', {'ttl': 121}), ('larger_uses', {'num_uses': 3})]:
        response = t.call('finite.' + label, role_path('finite') + '/secret-id', fields, status=400)
        t.check('finite.' + label + '.no_credentials', not response.get('data') and not response.get('wrap_info'))

    write('snapshot.create', 'snapshot', {'token_ttl': 10, 'secret_id_ttl': 120, 'secret_id_num_uses': 0})
    snapshot = issue('snapshot.issue', 'snapshot', 60)
    snapshot_before = lookup('snapshot.lookup', 'snapshot', snapshot, 120, 0, 60)
    write('snapshot.role_change', 'snapshot', {'secret_id_ttl': 1})
    tune('snapshot.mount_change', 0, 1)
    snapshot_after = lookup('snapshot.after', 'snapshot', snapshot, 120, 0, 60)
    t.check('snapshot.unchanged', all(snapshot_before[k] == snapshot_after[k] for k in ['creation_time', 'expiration_time', 'last_updated_time', 'secret_id_ttl']))
    wait(2)
    login('snapshot.old_valid', 'snapshot', snapshot, 1)
    login('default.after_shrink', 'default', unlimited, 1)
    tune('periodic.restore_mount', 75, 600)
    write('periodic.create', 'periodic', {'token_ttl': 40, 'token_max_ttl': 300,
                                        'token_period': 30, 'token_explicit_max_ttl': 180})
    write('periodic.nulls', 'periodic', {key: None for key in FIELDS[:5]})
    read('periodic.null', 'periodic', (40, 300, 30, 180, 0, 0, 0))
    period_secret = issue('periodic.secret', 'periodic', 0)
    periodic = login('periodic.login', 'periodic', period_secret, 30)
    for via in ROUTES:
        t.renew('periodic.renew', periodic, via=via, increment=700, exact=30)
    restart()
    read('restart.default', 'default', (0, 0, 0, 0, 0, 0, 0))
    login('restart.default_login', 'default', unlimited, 75)
    snapshot_reopened = lookup('restart.snapshot', 'snapshot', snapshot, 120, 0, 60)
    t.check('restart.snapshot_unchanged', all(snapshot_before[k] == snapshot_reopened[k] for k in ['creation_time', 'expiration_time', 'last_updated_time', 'secret_id_ttl']))
    login('restart.snapshot_login', 'snapshot', snapshot, 10)
    for via in ROUTES:
        t.renew('restart.renew', ordinary, via=via, exact=75)
    return t.sensitive



def expiry_denied(response):
    return (response.status in (400, 403) and isinstance(response.body, dict)
            and not response.body.get('auth') and not response.body.get('wrap_info'))


def run_candidate_expiry(client, rows, diagnostics, *, wait=time.sleep):
    # This is deliberately separate from the exact common trace. OpenBao 2.6.2
    # performs periodic expiry cleanup; the candidate must reject immediately.
    t = Trace(client, rows, diagnostics)
    t.call('candidate_expiry.role', role_path('expiry-boundary'),
           {'token_ttl': 10, 'secret_id_ttl': 1, 'secret_id_num_uses': 0}, status=204)
    role_id = t.call('candidate_expiry.id', role_path('expiry-boundary') + '/role-id', method='GET')['data']['role_id']
    data = t.call('candidate_expiry.issue', role_path('expiry-boundary') + '/secret-id', {})['data']
    secret = data['secret_id']; t.sensitive.extend([role_id, secret])
    t.check('candidate_expiry.finite_one_second', data.get('secret_id_ttl') == 1)
    wait(2)
    response = client.request('POST', '/v1/auth/native-approle/login',
                              {'role_id': role_id, 'secret_id': secret}, token='')
    t.check('candidate_expiry.rejected', expiry_denied(response), status=response.status)
    t.check('candidate_expiry.complete', True)
    return t.sensitive


def candidate_expiry_complete(rows):
    required = {'approle_native_defaults.candidate_expiry.' + name for name in
                ['role.status', 'id.status', 'issue.status', 'finite_one_second', 'rejected', 'complete']}
    return (isinstance(rows, list) and bool(rows)
            and all(isinstance(row, dict) and row.get('passed') is True for row in rows)
            and len({row.get('case') for row in rows}) == len(rows)
            and required.issubset({row.get('case') for row in rows})
            and rows[-1]['case'] == 'approle_native_defaults.candidate_expiry.complete')


def complete(rows):
    if not isinstance(rows, list) or not rows:
        return False
    names = []
    for row in rows:
        if (not isinstance(row, dict) or row.get('passed') is not True
                or not isinstance(row.get('case'), str)
                or re.fullmatch(r'approle_native_defaults\.[a-z0-9_.]{1,140}', row['case']) is None
                or any(type(v) not in (bool, int) for k, v in row.items() if k not in ('case', 'passed'))):
            return False
        names.append(row['case'])
    return (len(names) == len(set(names)) and names[-1] == 'approle_native_defaults.complete'
            and {'approle_native_defaults.' + n for n in REQUIRED}.issubset(names))


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--build-source-commit')
    parser.add_argument('--oracle-only', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.oracle_only and (args.binary is None or re.fullmatch(r'[0-9a-f]{40}', args.build_source_commit or '') is None):
        parser.error('candidate binary and full build source commit required')
    output = args.output.absolute(); admitted = admit_output(output)
    binary = args.binary.resolve(strict=True) if args.binary else None
    before = source_identity(ROOT, binary) if not args.oracle_only else None
    runner_hash = file_hash(Path(__file__))
    root = Path(tempfile.mkdtemp(prefix='heptabao-approle-native-defaults-')); root.chmod(0o700)
    oracle = instance = None
    cases, diagnostics, failures = {}, {}, {}
    candidate_expiry = []
    try:
        oracle = start_oracle(free_port())
        ca_root = Path(oracle['root'])
        root_token = private_read(oracle['token_file']).decode().strip()
        reference = Client(oracle['address'], oracle['ca_file'], root_token)
        def restart_reference():
            stop_oracle(oracle); restart_oracle(oracle)
        targets = [('oracle', reference, restart_reference, ca_root,
                    [root_token, private_read(ca_root / 'unseal.key').decode().strip()])]
        if not args.oracle_only:
            instance = Instance(binary, root / 'candidate')
            settings_path = instance.root / 'server.json'
            settings = json.loads(settings_path.read_text())
            settings.update(lifecycle_interval_seconds=0, outbound_endpoints=[])
            private_write(settings_path, settings, replace=True)
            instance.start()
            status, initialized = instance.call('POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1})
            if status != 200:
                raise ScenarioFailure('candidate_init')
            instance.token, key = initialized['root_token'], initialized['keys_base64'][0]
            if instance.call('POST', 'sys/unseal', {'key': key})[0] != 200:
                raise ScenarioFailure('candidate_unseal')
            def restart_candidate():
                instance.stop(); instance.start()
                if instance.call('POST', 'sys/unseal', {'key': key})[0] != 200:
                    raise ScenarioFailure('candidate_restart')
            targets.append(('candidate', Client(instance.address, str(instance.root / 'ca.crt'), instance.token),
                            restart_candidate, instance.root, [instance.token, key]))
        for side, client, restart, data_root, secrets in targets:
            cases[side], diagnostics[side] = [], []
            try:
                secrets += run_scenarios(client, restart, cases[side], diagnostics[side])
                if side == 'candidate':
                    secrets += run_candidate_expiry(client, candidate_expiry, diagnostics[side])
                files = [p for p in (data_root / 'data').rglob('*') if p.is_file()]
                files += [data_root / 'server.log', data_root / 'audit.jsonl']
                safe = (all(secret.encode() not in p.read_bytes() for p in files if p.exists() for secret in secrets)
                        and not any(secret in json.dumps({'cases': cases[side], 'diagnostics': diagnostics[side], 'candidate_expiry': candidate_expiry}) for secret in secrets))
                cases[side].append({'case': 'approle_native_defaults.secrets_absent', 'passed': safe is True})
                if not safe:
                    raise ScenarioFailure('secret_scan_failed')
                cases[side].append({'case': 'approle_native_defaults.complete', 'passed': True})
            except Exception as error:
                failures[side] = next((r['case'] for r in reversed(cases[side]) if r['passed'] is not True),
                                      'fixture_' + type(error).__name__)
    except Exception as error:
        failures['setup'] = 'fixture_' + type(error).__name__
    finally:
        try:
            if instance is not None:
                instance.stop()
        finally:
            if oracle is not None:
                stop_oracle(oracle); shutil.rmtree(oracle['root'])
            shutil.rmtree(root)
    unchanged = before == source_identity(ROOT, binary) if before else None
    runner_unchanged = runner_hash == file_hash(Path(__file__))
    equal = cases.get('candidate') == cases.get('oracle') if not args.oracle_only else None
    passed = (not failures and runner_unchanged
              and set(cases) == ({'oracle'} if args.oracle_only else {'oracle', 'candidate'})
              and all(complete(rows) for rows in cases.values())
              and (args.oracle_only or unchanged and equal and candidate_expiry_complete(candidate_expiry)))
    report = {'schema': 'heptabao.approle-native-defaults-comparison.v1', 'status': 'passed' if passed else 'failed',
              'candidate_source': before, 'build_source_commit': args.build_source_commit,
              'source_and_binary_unchanged': unchanged, 'runner_sha256': runner_hash, 'runner_unchanged': runner_unchanged,
              'oracle_binary_sha256': BINARY_SHA256, 'oracle_only': args.oracle_only, 'target_version': '2.6.2',
              'cases': cases, 'cases_match': equal, 'failures': failures, 'lease_diagnostics': diagnostics,
              'profile': 'native AppRole zero defaults, null fields, SecretID requested and effective lifetimes',
              'secret_id_default_parity': True, 'secret_id_ttl_and_timestamp_fields_covered': True,
              'candidate_immediate_expiry_checks': candidate_expiry,
              'candidate_immediate_expiry_status_profile': [400, 403],
              'immediate_expiry_rejection_parity': False, 'legacy_metadata_migration_covered': False,
              'http_startup_ttl_configuration_covered': False, 'secret_engine_leases_covered': False,
              'synthetic_only': True, 'full_openbao_compatibility': False,
              'independent_qualification': False, 'production_authority': False}
    if admit_output(output) != admitted:
        raise ValueError('report_parent_changed')
    private_write(output, report, replace=False)
    print(json.dumps({'status': report['status'], 'cases': {side: len(rows) for side, rows in cases.items()}, 'failures': failures}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
