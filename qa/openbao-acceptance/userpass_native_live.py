#!/usr/bin/env python3
"""Userpass native token lifetimes and local user renewal vs OpenBao 2.6.2.

This profile checks live user existence and policy equivalence at renewal, without
rechecking passwords. CIDRs, no-default policies, batch tokens, password-hash input,
username case folding and password-error status parity remain separate work.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import secrets
import shutil
import tempfile
import time
from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from official_openbao_launcher import BINARY_SHA256, start_oracle, stop_oracle, restart_oracle
from oidc_renewal_live import free_port
from online_evidence import admit_output, source_identity
from radius_renewal_live import renewal_token_shape, wrapped_renewal_shape
from remote_jwks_live import Instance

PREFIX = 'userpass_native.'
ROUTES = ('self', 'token', 'accessor')
FIELDS = ('token_ttl', 'token_max_ttl', 'token_period', 'token_explicit_max_ttl', 'token_num_uses')
OLD_POLICIES = ['default', 'userpass-native-old']
REQUIRED = frozenset({
    'fresh.read.fields', 'fresh.login.metadata', 'fresh.login.lease',
    'nullable.partial.fields', 'nullable.null.fields', 'nullable.zero.fields',
    'ordinary.login.metadata', 'ordinary.lookup.metadata', 'ordinary.child.lease', 'ordinary.orphan.lease',
    'ordinary.new_password.lease', 'policy.unchanged', 'policy.wrapped.unchanged',
    'wrapper.opaque', 'wrapper.unwrap.shape', 'wrapper.single_use.status',
    'past_max.unchanged', 'deleted.unchanged', 'deleted.lookup.metadata',
    'period.login.lease', 'period.shrunk.self.lease', 'period.changed.self.lease',
    'period.snapshot', 'period.off.self.lease', 'period.off_snapshot',
    'finite.period.self.lease', 'finite.period_snapshot', 'finite.off.self.lease',
    'explicit.snapshot', 'explicit.raised.self.lease', 'restart.lookup.metadata',
    'restart.explicit.snapshot', 'secrets_absent', 'complete',
}) | frozenset(phase + '.' + via + suffix
    for phase in ('fresh.current_mount', 'ordinary.initial', 'ordinary.raised', 'ordinary.password_changed',
                  'policy.restored', 'past_max.restored', 'deleted.child', 'deleted.orphan',
                  'recreated', 'restart.ordinary')
    for via in ROUTES for suffix in ('.status', '.lease', '.shape')) \
  | frozenset(phase + '.' + via + suffix
    for phase in ('policy.rejected', 'past_max.rejected', 'deleted.rejected')
    for via in ROUTES for suffix in ('.status', '.no_credentials'))


class Trace:
    def __init__(self, client, rows, diagnostics):
        self.client, self.rows, self.diagnostics = client, rows, diagnostics
        self.sensitive = []

    def check(self, name, condition, **observations):
        if (not isinstance(name, str) or re.fullmatch(r'[a-z0-9_.]{1,140}', name) is None
                or any(type(value) not in (int, bool) for value in observations.values())):
            raise ValueError('unsafe_observation')
        self.rows.append({'case': PREFIX + name, 'passed': condition is True, **observations})
        if condition is not True:
            raise ScenarioFailure(PREFIX + name)

    def call(self, name, path, fields=None, *, method='POST', bearer=None, status=200, wrap=None):
        response = self.client.request(method, '/v1/' + path, fields, token=bearer, wrap_ttl=wrap)
        self.check(name + '.status', response.status == status, status=response.status)
        return response.body

    def lease(self, name, auth, *, exact=None, maximum=None):
        ttl = auth.get('lease_duration')
        diagnostic = {'case': PREFIX + name, 'lease_is_integer': type(ttl) is int}
        if type(ttl) is int:
            diagnostic['lease_duration'] = ttl
        if exact is not None:
            diagnostic['expected_ttl'] = exact
        if maximum is not None:
            diagnostic['maximum_ttl'] = maximum
        self.diagnostics.append(diagnostic)
        self.check(name + '.lease', type(ttl) is int and ttl > 0
                   and (exact is None or ttl == exact) and (maximum is None or ttl <= maximum))

    def auth(self, name, body, *, exact=None, maximum=None, username=None, policies=None):
        auth = body.get('auth') or {}
        self.check(name + '.credentials', all(isinstance(auth.get(k), str) and bool(auth[k])
                   for k in ('client_token', 'accessor')))
        self.sensitive.append(auth['client_token'])
        self.lease(name, auth, exact=exact, maximum=maximum)
        self.check(name + '.renewable', auth.get('renewable') is True)
        if username is not None:
            self.check(name + '.metadata', auth.get('metadata') == {'username': username})
        if policies is not None:
            self.check(name + '.policies', sorted(auth.get('token_policies') or []) == policies)
        return auth

    def lookup(self, name, auth, *, username=None):
        data = self.call(name, 'auth/token/lookup', {'token': auth['client_token']}).get('data') or {}
        if username is not None:
            self.check(name + '.metadata', data.get('meta') == {'username': username})
        return data

    def renew(self, name, auth, *, via='self', increment=None, exact=None, maximum=None,
              status=200, policies=None, wrap=None):
        fields = {} if increment is None else {'increment': increment}
        path = {'self': 'renew-self', 'token': 'renew', 'accessor': 'renew-accessor'}[via]
        if via == 'token':
            fields['token'] = auth['client_token']
        elif via == 'accessor':
            fields['accessor'] = auth['accessor']
        name += '.' + via
        body = self.call(name, 'auth/token/' + path, fields,
                         bearer=auth['client_token'] if via == 'self' else None, status=status, wrap=wrap)
        if status != 200:
            self.check(name + '.no_credentials', not body.get('auth') and not body.get('wrap_info'))
            return body
        renewed = body.get('auth') or {}
        self.lease(name, renewed, exact=exact, maximum=maximum)
        self.check(name + '.shape', renewed.get('renewable') is True
                   and renewal_token_shape(renewed, auth['client_token'], via_accessor=via == 'accessor'))
        if policies is not None:
            self.check(name + '.policies', sorted(renewed.get('token_policies') or []) == policies)
        return body


def no_extension(before, after):
    return (isinstance(before.get('expire_time'), str) and bool(before['expire_time'])
            and before['expire_time'] == after.get('expire_time')
            and type(before.get('ttl')) is int and type(after.get('ttl')) is int
            and 0 < after['ttl'] <= before['ttl'])


def run_scenarios(client, restart, rows, diagnostics, *, wait=time.sleep):
    t = Trace(client, rows, diagnostics)
    password, changed_password = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    t.sensitive.extend([password, changed_password])
    def write(label, name, fields):
        return t.call(label, 'auth/native-userpass/users/' + name, fields, status=204)
    def read(label, name, values, policies):
        data = t.call(label, 'auth/native-userpass/users/' + name, method='GET').get('data') or {}
        t.check(label + '.fields', all(type(data.get(k)) is int and data[k] == v for k, v in zip(FIELDS, values))
                and data.get('token_policies') == policies)
        return data
    def login(label, name, *, pwd=password, exact=None, maximum=None, policies=None):
        body = t.call(label, 'auth/native-userpass/login/' + name, {'password': pwd})
        return t.auth(label, body, exact=exact, maximum=maximum, username=name, policies=policies)
    def all_renew(label, auth, **kwargs):
        for via in ROUTES:
            t.renew(label, auth, via=via, **kwargs)
    def rejected(label, auth, statuses=None, **kwargs):
        before = t.lookup(label + '.before', auth)
        for via in ROUTES:
            t.renew(label + '.rejected', auth, via=via,
                    status=(statuses or {}).get(via, 500), increment=300, **kwargs)
        after = t.lookup(label + '.after', auth)
        t.check(label + '.unchanged', no_extension(before, after))

    t.call('mount', 'sys/auth/native-userpass', {'type': 'userpass'}, status=204)
    t.call('tune', 'sys/auth/native-userpass/tune', {'default_lease_ttl': 75, 'max_lease_ttl': 600}, status=204)
    t.call('policy', 'sys/policies/acl/userpass-native-old', {'policy':
        'path "auth/token/create" { capabilities = ["update"] } '
        'path "auth/token/create-orphan" { capabilities = ["update", "sudo"] }'}, status=204)
    write('fresh.write', 'fresh', {'password': password})
    read('fresh.read', 'fresh', (0, 0, 0, 0, 0), [])
    fresh = login('fresh.login', 'fresh', exact=75, policies=['default'])
    t.call('fresh.tune', 'sys/auth/native-userpass/tune', {'default_lease_ttl': 95, 'max_lease_ttl': 900}, status=204)
    all_renew('fresh.current_mount', fresh, exact=95)
    write('nullable.write', 'nullable', {'password': password, 'token_ttl': 40, 'token_max_ttl': 300,
        'token_period': 20, 'token_explicit_max_ttl': 240, 'token_num_uses': 4, 'token_policies': ['userpass-native-old']})
    write('nullable.partial_write', 'nullable', {'token_max_ttl': 500})
    read('nullable.partial', 'nullable', (40, 500, 20, 240, 4), ['userpass-native-old'])
    write('nullable.null_write', 'nullable', {**dict.fromkeys(FIELDS), 'token_policies': None})
    read('nullable.null', 'nullable', (40, 500, 20, 240, 0), [])
    write('nullable.zero_write', 'nullable', dict.fromkeys(FIELDS, 0))
    read('nullable.zero', 'nullable', (0, 0, 0, 0, 0), [])

    ordinary_fields = {'token_ttl': 60, 'token_max_ttl': 90, 'token_policies': ['userpass-native-old']}
    write('ordinary.write', 'alice', {'password': password, **ordinary_fields})
    ordinary = login('ordinary.login', 'alice', exact=60, policies=OLD_POLICIES)
    t.lookup('ordinary.lookup', ordinary, username='alice')
    child = t.auth('ordinary.child', t.call('ordinary.child', 'auth/token/create',
        {'policies': ['default'], 'ttl': 120, 'renewable': True}, bearer=ordinary['client_token']), exact=120)
    orphan = t.auth('ordinary.orphan', t.call('ordinary.orphan', 'auth/token/create-orphan',
        {'policies': ['default'], 'ttl': 120, 'renewable': True}, bearer=ordinary['client_token']), exact=120)
    all_renew('ordinary.initial', ordinary, exact=60, policies=OLD_POLICIES)
    write('ordinary.raise', 'alice', {'token_max_ttl': 600})
    all_renew('ordinary.raised', ordinary, increment=300, exact=300, policies=OLD_POLICIES)
    write('ordinary.password_write', 'alice', {'password': changed_password})
    login('ordinary.new_password', 'alice', pwd=changed_password, exact=60, policies=OLD_POLICIES)
    all_renew('ordinary.password_changed', ordinary, exact=60, policies=OLD_POLICIES)
    write('policy.write', 'alice', {'token_policies': ['userpass-native-new']})
    rejected('policy', ordinary)
    rejected('policy.wrapped', ordinary, wrap='60s')
    write('policy.restore', 'alice', {'token_policies': ['default', 'userpass-native-old']})
    all_renew('policy.restored', ordinary, exact=60, policies=OLD_POLICIES)
    wrapped = t.call('wrapper', 'auth/token/renew-self', {'increment': 120}, bearer=ordinary['client_token'], wrap='60s')
    t.check('wrapper.opaque', wrapped_renewal_shape(wrapped, ordinary['client_token']))
    wrapper = wrapped['wrap_info']['token']; t.sensitive.append(wrapper)
    unwrapped = t.call('wrapper.unwrap', 'sys/wrapping/unwrap', {}, bearer=wrapper).get('auth') or {}
    t.lease('wrapper.unwrap', unwrapped, exact=120)
    t.check('wrapper.unwrap.shape', renewal_token_shape(unwrapped, ordinary['client_token'], via_accessor=False))
    t.call('wrapper.single_use', 'sys/wrapping/unwrap', {}, bearer=wrapper, status=400)
    wait(2)
    write('past_max.write', 'alice', {'token_ttl': 1, 'token_max_ttl': 1})
    rejected('past_max', ordinary)
    write('past_max.restore', 'alice', {'token_ttl': 60, 'token_max_ttl': 600})
    all_renew('past_max.restored', ordinary, exact=60)
    t.call('deleted.write', 'auth/native-userpass/users/alice', method='DELETE', status=204)
    t.lookup('deleted.lookup', ordinary, username='alice')
    rejected('deleted', ordinary, statuses={'self': 204, 'token': 204, 'accessor': 500})
    all_renew('deleted.child', child, exact=120)
    all_renew('deleted.orphan', orphan, exact=120)
    write('recreated.write', 'alice', {'password': changed_password, **ordinary_fields, 'token_max_ttl': 600})
    all_renew('recreated', ordinary, increment=120, exact=120, policies=OLD_POLICIES)

    write('period.write', 'period', {'password': password, 'token_ttl': 60, 'token_max_ttl': 90,
        'token_period': 20, 'token_explicit_max_ttl': 120})
    period = login('period.login', 'period', exact=20)
    t.renew('period.initial', period, increment=300, exact=20)
    wait(4)
    write('period.shrink', 'period', {'token_ttl': 3, 'token_max_ttl': 3, 'token_period': 20, 'token_explicit_max_ttl': 1})
    t.renew('period.shrunk', period, increment=300, exact=3)
    write('period.raise', 'period', {'token_ttl': 60, 'token_max_ttl': 90, 'token_period': 10})
    t.renew('period.changed', period, increment=300, exact=10)
    snapshot = t.lookup('period.lookup', period)
    t.check('period.snapshot', snapshot.get('period') == 20 and snapshot.get('explicit_max_ttl') == 120)
    write('period.off_write', 'period', {'token_period': 0, 'token_max_ttl': 600})
    t.renew('period.off', period, increment=300, maximum=120)
    snapshot = t.lookup('period.off_lookup', period)
    t.check('period.off_snapshot', snapshot.get('period') == 20 and snapshot.get('explicit_max_ttl') == 120)
    write('finite.write', 'finite', {'password': password, 'token_ttl': 60, 'token_max_ttl': 600})
    finite = login('finite.login', 'finite', exact=60)
    write('finite.period_write', 'finite', {'token_period': 30})
    t.renew('finite.period', finite, increment=300, exact=30)
    snapshot = t.lookup('finite.lookup', finite)
    t.check('finite.period_snapshot', snapshot.get('period', 0) == 0)
    write('finite.off_write', 'finite', {'token_period': 0})
    t.renew('finite.off', finite, increment=300, exact=300)
    write('explicit.write', 'explicit', {'password': password, 'token_ttl': 60, 'token_max_ttl': 90, 'token_explicit_max_ttl': 240})
    explicit = login('explicit.login', 'explicit', exact=60)
    write('explicit.raise', 'explicit', {'token_max_ttl': 600, 'token_explicit_max_ttl': 1})
    t.renew('explicit.raised', explicit, increment=300, maximum=240)
    snapshot = t.lookup('explicit.lookup', explicit)
    t.check('explicit.snapshot', snapshot.get('explicit_max_ttl') == 240)
    restart()
    t.lookup('restart.lookup', ordinary, username='alice')
    all_renew('restart.ordinary', ordinary, increment=120, exact=120, policies=OLD_POLICIES)
    t.renew('restart.period', period, increment=300, maximum=120)
    t.renew('restart.finite', finite, increment=300, exact=300)
    t.renew('restart.explicit', explicit, increment=300, maximum=240)
    snapshot = t.lookup('restart.explicit.lookup', explicit)
    t.check('restart.explicit.snapshot', snapshot.get('explicit_max_ttl') == 240)
    login('restart.password', 'alice', pwd=changed_password, exact=60)
    return t.sensitive


def complete(rows):
    if not isinstance(rows, list) or not rows:
        return False
    names = []
    for row in rows:
        if (not isinstance(row, dict) or row.get('passed') is not True
                or not isinstance(row.get('case'), str)
                or re.fullmatch(r'userpass_native\.[a-z0-9_.]{1,140}', row['case']) is None
                or any(type(v) not in (bool, int) for k, v in row.items() if k not in ('case', 'passed'))):
            return False
        names.append(row['case'])
    return (len(names) == len(set(names)) and names[-1] == PREFIX + 'complete'
            and {PREFIX + n for n in REQUIRED}.issubset(names))


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
    root = Path(tempfile.mkdtemp(prefix='heptabao-userpass-native-')); root.chmod(0o700)
    oracle = instance = None
    cases, diagnostics, failures = {}, {}, {}
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
        for side, client, restart, data_root, credentials in targets:
            cases[side], diagnostics[side] = [], []
            try:
                credentials += run_scenarios(client, restart, cases[side], diagnostics[side])
                files = [p for p in (data_root / 'data').rglob('*') if p.is_file()]
                files += [data_root / 'server.log', data_root / 'audit.jsonl']
                safe = (all(secret.encode() not in p.read_bytes() for p in files if p.exists() for secret in credentials)
                        and not any(secret in json.dumps({'cases': cases[side], 'diagnostics': diagnostics[side]}) for secret in credentials))
                cases[side].append({'case': PREFIX + 'secrets_absent', 'passed': safe is True})
                if not safe:
                    raise ScenarioFailure('secret_scan_failed')
                cases[side].append({'case': PREFIX + 'complete', 'passed': True})
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
              and (args.oracle_only or unchanged and equal))
    report = {'schema': 'heptabao.userpass-native-comparison.v1', 'status': 'passed' if passed else 'failed',
              'candidate_source': before, 'build_source_commit': args.build_source_commit,
              'source_and_binary_unchanged': unchanged, 'runner_sha256': runner_hash, 'runner_unchanged': runner_unchanged,
              'oracle_binary_sha256': BINARY_SHA256, 'oracle_only': args.oracle_only, 'target_version': '2.6.2',
              'cases': cases, 'cases_match': equal, 'failures': failures, 'lease_diagnostics': diagnostics,
              'profile': 'native userpass token defaults and current-user local renewal',
              'password_reauthentication_on_renewal': False, 'policy_equivalence_required': True,
              'deleted_user_renewal_statuses': {'self': 204, 'token': 204, 'accessor': 500},
              'legacy_provenance_migration_covered': False, 'password_error_status_parity': False,
              'username_case_parity': False, 'cidrs_no_default_batch_covered': False,
              'synthetic_only': True, 'full_openbao_compatibility': False,
              'independent_qualification': False, 'production_authority': False}
    if admit_output(output) != admitted:
        raise ValueError('report_parent_changed')
    private_write(output, report, replace=False)
    print(json.dumps({'status': report['status'], 'cases': {side: len(rows) for side, rows in cases.items()}, 'failures': failures}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
