#!/usr/bin/env python3
"""Fresh system and TokenAPI mount lifetime comparison with OpenBao 2.6.2.

Ordinary token renewal retains the last granted duration, constrained by current
mount max and issue age. SecretID defaults and historical state migration remain
separate profiles; explicit credential lifetimes are tested here.
"""
from __future__ import annotations
import json
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
from radius_renewal_live import renewal_token_shape, wrapped_renewal_shape
from remote_jwks_live import Instance

SYSTEM_TTL = 32 * 24 * 60 * 60
ROUTES = ('self', 'token', 'accessor')
REQUIRED = frozenset({
    'fresh.tune.fields', 'fresh.issue.lease', 'max_only.tune.fields', 'max_only.issue.lease',
    'tuned.issue.lease', 'grant.omitted.self.lease', 'grant.requested.self.lease',
    'grant.after_increment.self.lease', 'grant.zero.self.lease', 'raised_max.self.lease',
    'explicit.snapshot', 'period.capped.self.lease', 'period.restored.self.lease',
    'period.snapshot', 'past_max.expiry_unchanged', 'restored.self.lease',
    'reset.tune.fields', 'reset.issue.lease', 'root.omitted.lease', 'root.zero.lease',
    'root.explicit_only.lease', 'root.finite_parent_reject.no_credentials', 'rejected_create.no_credentials',
    'rejected_create.tune_unchanged', 'wrapper.opaque', 'wrapper.unwrap.shape', 'wrapper.single_use',
    'approle.secret_ttl', 'approle.secret_reusable', 'approle.direct.lease', 'approle.child.lease', 'approle.orphan.lease',
    'userpass.direct.lease', 'userpass.child.lease', 'userpass.orphan.lease',
    'restart.tune.fields', 'restart.secret_login.lease', 'secrets_absent', 'complete',
}) | frozenset(phase + '.' + via + suffix
               for phase in ['grant.all', 'explicit', 'restart.grant', 'restart.explicit']
               for via in ROUTES for suffix in ['.status', '.lease', '.shape']) \
  | frozenset('past_max.' + via + suffix for via in ROUTES for suffix in ['.status', '.no_credentials'])


def credential_role_fields():
    return {'token_ttl': 90, 'token_max_ttl': 600, 'secret_id_ttl': 120,
            'secret_id_num_uses': 0, 'token_policies': ['ttl-issuer']}


class Trace:
    def __init__(self, client, rows, diagnostics):
        self.client, self.rows, self.diagnostics = client, rows, diagnostics
        self.sensitive = []

    def check(self, name, condition, **observations):
        if (not isinstance(name, str) or re.fullmatch(r'[a-z0-9_.]{1,140}', name) is None
                or any(type(v) not in (int, bool) for v in observations.values())):
            raise ValueError('unsafe_observation')
        self.rows.append({'case': 'token_mount_ttl.' + name, 'passed': condition is True, **observations})
        if condition is not True:
            raise ScenarioFailure('token_mount_ttl.' + name)

    def call(self, name, path, fields=None, *, method='POST', bearer=None, status=200, wrap=None):
        response = self.client.request(method, '/v1/' + path, fields, token=bearer, wrap_ttl=wrap)
        self.check(name + '.status', response.status == status, status=response.status)
        return response.body

    def lease(self, name, auth, *, exact=None, maximum=None, nonexpiring=False):
        ttl = auth.get('lease_duration')
        diagnostic = {'case': 'token_mount_ttl.' + name, 'lease_is_integer': type(ttl) is int}
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

    def issue(self, name, *, fields=None, bearer=None, exact=None, maximum=None, nonexpiring=False):
        body = self.call(name, 'auth/token/create', {'policies': ['default'], **(fields or {})}, bearer=bearer)
        return self.auth(name, body, exact=exact, maximum=maximum, nonexpiring=nonexpiring)

    def tune(self, name, **fields):
        self.call(name, 'sys/auth/token/tune', fields, status=204)

    def tune_read(self, name, default, maximum):
        data = self.call(name, 'sys/auth/token/tune', method='GET').get('data') or {}
        self.check(name + '.fields', data.get('default_lease_ttl') == default and data.get('max_lease_ttl') == maximum)
        return data

    def lookup(self, name, auth):
        return self.call(name, 'auth/token/lookup-self', method='GET', bearer=auth['client_token']).get('data') or {}

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
    t.tune_read('fresh.tune', SYSTEM_TTL, SYSTEM_TTL)
    t.issue('fresh.issue', exact=SYSTEM_TTL)
    t.tune('max_only.write', default_lease_ttl=0, max_lease_ttl=60)
    t.tune_read('max_only.tune', SYSTEM_TTL, 60)
    t.issue('max_only.issue', exact=60)
    t.tune('tuned.write', default_lease_ttl=75, max_lease_ttl=600)
    ordinary = t.issue('tuned.issue', exact=75)
    t.tune('grant.default_change', default_lease_ttl=95)
    t.renew('grant.omitted', ordinary, exact=75)
    t.renew('grant.requested', ordinary, increment=300, exact=300)
    t.renew('grant.after_increment', ordinary, exact=300)
    t.renew('grant.zero', ordinary, increment=0, exact=300)
    for via in ROUTES:
        t.renew('grant.all', ordinary, via=via, exact=300)
    t.tune('raised_max.write', max_lease_ttl=900)
    t.renew('raised_max', ordinary, increment=700, exact=700)
    capped = t.issue('explicit.issue', fields={'explicit_max_ttl': 120}, exact=95)
    for via in ROUTES:
        t.renew('explicit', capped, via=via, increment=700, maximum=120)
    t.check('explicit.snapshot', t.lookup('explicit.lookup', capped).get('explicit_max_ttl') == 120)
    periodic = t.issue('period.issue', fields={'period': 30, 'explicit_max_ttl': 180}, exact=30)
    t.tune('period.cap', default_lease_ttl=0, max_lease_ttl=20)
    t.renew('period.capped', periodic, increment=700, exact=20)
    t.tune('period.restore', default_lease_ttl=75, max_lease_ttl=900)
    t.renew('period.restored', periodic, increment=700, exact=30)
    t.check('period.snapshot', t.lookup('period.lookup', periodic).get('period') == 30)
    before = t.lookup('past_max.before', ordinary).get('expire_time')
    t.check('past_max.has_expiry', isinstance(before, str) and bool(before))
    wait(3)
    t.tune('past_max.shrink', default_lease_ttl=0, max_lease_ttl=1)
    for via in ROUTES:
        t.renew('past_max', ordinary, via=via, increment=300, status=500)
    after = t.lookup('past_max.after', ordinary).get('expire_time')
    t.check('past_max.expiry_unchanged', before == after)
    t.tune('restored.write', default_lease_ttl=75, max_lease_ttl=900)
    t.renew('restored', ordinary, increment=300, exact=300)
    t.tune('reset.write', default_lease_ttl=0, max_lease_ttl=0)
    t.tune_read('reset.tune', SYSTEM_TTL, SYSTEM_TTL)
    t.issue('reset.issue', exact=SYSTEM_TTL)

    # Root special cases do not define the ordinary token default.
    t.tune('root.small_mount', default_lease_ttl=0, max_lease_ttl=60)
    t.issue('root.omitted', fields={'policies': ['root']}, nonexpiring=True)
    t.issue('root.zero', fields={'policies': ['root'], 'ttl': 0}, nonexpiring=True)
    t.issue('root.explicit_only', fields={'policies': ['root'], 'explicit_max_ttl': 180}, exact=180)
    finite_root = t.issue('root.finite', fields={'policies': ['root'], 'ttl': 30}, exact=30)
    rejected = t.call('root.finite_parent_reject', 'auth/token/create', {'policies': ['root']},
                      bearer=finite_root['client_token'], status=400)
    t.check('root.finite_parent_reject.no_credentials', not rejected.get('auth') and not rejected.get('wrap_info'))
    before_tune = t.tune_read('rejected_create.before', SYSTEM_TTL, 60)
    rejected = t.call('rejected_create', 'auth/token/create', {'policies': ['default'], 'ttl': -1}, status=400, wrap='60s')
    t.check('rejected_create.no_credentials', not rejected.get('auth') and not rejected.get('wrap_info'))
    after_tune = t.tune_read('rejected_create.after', SYSTEM_TTL, 60)
    t.check('rejected_create.tune_unchanged', before_tune == after_tune)
    t.tune('wrapper.restore', default_lease_ttl=75, max_lease_ttl=900)
    wrapped = t.call('wrapper.renew', 'auth/token/renew', {'token': ordinary['client_token'], 'increment': 300}, wrap='60s')
    t.check('wrapper.opaque', wrapped_renewal_shape(wrapped, ordinary['client_token']))
    wrapper = wrapped['wrap_info']['token']; t.sensitive.append(wrapper)
    unwrapped = t.call('wrapper.unwrap', 'sys/wrapping/unwrap', {}, bearer=wrapper)
    t.check('wrapper.unwrap.shape', renewal_token_shape(unwrapped.get('auth') or {}, ordinary['client_token'], via_accessor=False))
    t.call('wrapper.again', 'sys/wrapping/unwrap', {}, bearer=wrapper, status=400)
    t.check('wrapper.single_use', True)

    t.call('issuer.policy', 'sys/policies/acl/ttl-issuer',
           {'policy': 'path "auth/token/create*" { capabilities = ["update", "sudo"] }'}, status=204)
    t.call('approle.mount', 'sys/auth/ttl-approle', {'type': 'approle'}, status=204)
    t.call('approle.tune', 'sys/auth/ttl-approle/tune', {'default_lease_ttl': 90, 'max_lease_ttl': 600}, status=204)
    role = 'auth/ttl-approle/role/explicit'
    t.call('approle.role', role, credential_role_fields(), status=204)
    role_id = t.call('approle.id', role + '/role-id', method='GET')['data']['role_id']
    t.tune('isolation.token_mount', default_lease_ttl=0, max_lease_ttl=60)
    data = t.call('approle.secret', role + '/secret-id', {})['data']
    secret = data['secret_id']
    t.sensitive.extend([role_id, secret])
    t.check('approle.secret_ttl', data.get('secret_id_ttl') == 120)
    t.check('approle.secret_reusable', data.get('secret_id_num_uses') == 0)
    parent = t.auth('approle.direct', t.call('approle.login', 'auth/ttl-approle/login',
                    {'role_id': role_id, 'secret_id': secret}, bearer=''), exact=90)
    t.issue('approle.child', bearer=parent['client_token'], exact=60)
    t.issue('approle.orphan', fields={'no_parent': True}, bearer=parent['client_token'], exact=60)
    t.call('userpass.mount', 'sys/auth/ttl-userpass', {'type': 'userpass'}, status=204)
    t.call('userpass.tune', 'sys/auth/ttl-userpass/tune', {'default_lease_ttl': 120, 'max_lease_ttl': 600}, status=204)
    password = 'synthetic-token-mount-ttl-password'; t.sensitive.append(password)
    t.call('userpass.user', 'auth/ttl-userpass/users/alice', {'password': password, 'token_ttl': 120,
           'token_max_ttl': 600, 'token_policies': ['ttl-issuer']}, status=204)
    parent = t.auth('userpass.direct', t.call('userpass.login', 'auth/ttl-userpass/login/alice',
                    {'password': password}, bearer=''), exact=120)
    t.issue('userpass.child', bearer=parent['client_token'], exact=60)
    t.issue('userpass.orphan', fields={'no_parent': True}, bearer=parent['client_token'], exact=60)
    t.tune('restart.prepare', default_lease_ttl=95, max_lease_ttl=900)
    t.renew('restart.before', ordinary, increment=300, exact=300)
    restart()
    t.tune_read('restart.tune', 95, 900)
    for via in ROUTES:
        t.renew('restart.grant', ordinary, via=via, exact=300)
        t.renew('restart.explicit', capped, via=via, increment=700, maximum=120)
    t.auth('restart.secret_login', t.call('restart.approle_login', 'auth/ttl-approle/login',
           {'role_id': role_id, 'secret_id': secret}, bearer=''), exact=90)
    return t.sensitive


def complete(rows):
    if not isinstance(rows, list) or not rows:
        return False
    names = []
    for row in rows:
        if (not isinstance(row, dict) or row.get('passed') is not True
                or not isinstance(row.get('case'), str)
                or re.fullmatch(r'token_mount_ttl\.[a-z0-9_.]{1,140}', row['case']) is None
                or any(type(v) not in (bool, int) for k, v in row.items() if k not in ('case', 'passed'))):
            return False
        names.append(row['case'])
    return (len(names) == len(set(names)) and names[-1] == 'token_mount_ttl.complete'
            and {'token_mount_ttl.' + n for n in REQUIRED}.issubset(names))


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
    root = Path(tempfile.mkdtemp(prefix='heptabao-token-mount-ttl-')); root.chmod(0o700)
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
        for side, client, restart, data_root, secrets in targets:
            cases[side], diagnostics[side] = [], []
            try:
                secrets += run_scenarios(client, restart, cases[side], diagnostics[side])
                files = [p for p in (data_root / 'data').rglob('*') if p.is_file()]
                files += [data_root / 'server.log', data_root / 'audit.jsonl']
                safe = (all(secret.encode() not in p.read_bytes() for p in files if p.exists() for secret in secrets)
                        and not any(secret in json.dumps({'cases': cases[side], 'diagnostics': diagnostics[side]}) for secret in secrets))
                cases[side].append({'case': 'token_mount_ttl.secrets_absent', 'passed': safe is True})
                if not safe:
                    raise ScenarioFailure('secret_scan_failed')
                cases[side].append({'case': 'token_mount_ttl.complete', 'passed': True})
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
              and all(complete(rows) for rows in cases.values()) and (args.oracle_only or unchanged and equal))
    report = {'schema': 'heptabao.token-mount-ttl-comparison.v1', 'status': 'passed' if passed else 'failed',
              'candidate_source': before, 'build_source_commit': args.build_source_commit,
              'source_and_binary_unchanged': unchanged, 'runner_sha256': runner_hash, 'runner_unchanged': runner_unchanged,
              'oracle_binary_sha256': BINARY_SHA256, 'oracle_only': args.oracle_only, 'target_version': '2.6.2',
              'cases': cases, 'cases_match': equal, 'failures': failures, 'lease_diagnostics': diagnostics,
              'profile': 'fresh system and unnamed TokenAPI service tokens; current mount max; retained last grant',
              'secret_id_default_parity': False, 'secret_id_lookup_fields_parity': False, 'legacy_metadata_migration_covered': False,
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
