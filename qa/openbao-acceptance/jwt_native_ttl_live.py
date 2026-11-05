#!/usr/bin/env python3
"""JWT role zero/default/null TTL semantics against pinned OpenBao 2.6.2.

Both static ES256 and HTTPS JWKS use a mount tuned to default75/max600. This
selected profile does not assert global system TTL defaults or OIDC behavior.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import shutil
import tempfile

from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from jwt_renewal_live import configuration
from official_openbao_launcher import BINARY_SHA256, start_oracle, stop_oracle, restart_oracle
from oidc_renewal_live import free_port
from online_evidence import admit_output, source_identity
from radius_renewal_live import renewal_token_shape
from remote_jwks_live import Instance, JsonIssuer, signing_key, token

MODES = ('static', 'remote')
TTL_FIELDS = ('token_ttl', 'token_max_ttl', 'token_period', 'token_explicit_max_ttl')
ADAPTATION = {
    'static': 'candidate issuer/audiences/inline JWKS; official bound_issuer/PEM validation key',
    'remote': 'same HTTPS JWKS and explicit API jwks_ca_pem; candidate startup endpoints empty',
    'partial': 'every role write explicitly selects role_type=jwt; no OIDC default assertion',
    'scope': 'mount default75/max600; excludes global system defaults, OIDC, batch and unlimited duration profiles',
}


def role_fields(**fields):
    return {'role_type': 'jwt', 'user_claim': 'sub', 'bound_audiences': ['heptabao-test'],
            'token_policies': ['default'], **fields}


def creation_matrix():
    return [
        ('omitted', {}, (0, 0, 0, 0), 75),
        ('zero', {'token_ttl': 0, 'token_max_ttl': 0}, (0, 0, 0, 0), 75),
        ('ttl_only', {'token_ttl': 120, 'token_max_ttl': 0}, (120, 0, 0, 0), 120),
        ('max_only', {'token_ttl': 0, 'token_max_ttl': 90}, (0, 90, 0, 0), 75),
    ]


class Trace:
    def __init__(self, client, issuer, mode, rows, diagnostics=None):
        self.client, self.issuer, self.mode, self.rows = client, issuer, mode, rows
        self.sensitive = []
        self.diagnostics = diagnostics if diagnostics is not None else []

    def check(self, label, passed, **observed):
        if (not isinstance(label, str) or re.fullmatch(r'[a-z0-9_.]{1,150}', label) is None
                or any(type(value) not in (bool, int) for value in observed.values())):
            raise ValueError('unsafe_observation')
        case = 'jwt_native_ttl.' + self.mode + '.' + label
        self.rows.append({'case': case, 'passed': passed is True, **observed})
        if passed is not True:
            raise ScenarioFailure(case)

    def call(self, label, path, body=None, *, method='POST', bearer=None, expected=200, offline=True):
        before = len(self.issuer.calls)
        response = self.client.request(method, '/v1/' + path, body, token=bearer)
        observed = {'status': response.status}
        if offline:
            observed['no_provider_request'] = len(self.issuer.calls) == before
        self.check(label, response.status == expected and (not offline or len(self.issuer.calls) == before), **observed)
        return response.body

    def read_role(self, label, path, expected):
        data = self.call(label, path, method='GET').get('data', {})
        self.check(label + '.fields', all(type(data.get(name)) is int and data[name] == value
                   for name, value in zip(TTL_FIELDS, expected)) and data.get('role_type') == 'jwt')
        return data

    def write_role(self, label, path, fields):
        return self.call(label, path, dict(fields, role_type='jwt'), expected=204)

    def renew(self, label, auth, *, ttl=None, maximum=None, increment=None):
        for via, body, bearer in [('self', {}, auth['client_token']),
                                 ('token', {'token': auth['client_token']}, None),
                                 ('accessor', {'accessor': auth['accessor']}, None)]:
            path = {'self': 'renew-self', 'token': 'renew', 'accessor': 'renew-accessor'}[via]
            if increment is not None:
                body['increment'] = increment
            result = self.call(label + '.' + via, 'auth/token/' + path, body, bearer=bearer)
            renewed = result.get('auth', {})
            actual = renewed.get('lease_duration')
            diagnostic = {'case': 'jwt_native_ttl.' + self.mode + '.' + label + '.' + via,
                          'lease_is_integer': type(actual) is int}
            if type(actual) is int:
                diagnostic['lease_duration'] = actual
            for name, value in [('expected_ttl', ttl), ('maximum_ttl', maximum), ('increment', increment)]:
                if type(value) is int:
                    diagnostic[name] = value
            self.diagnostics.append(diagnostic)
            self.check(label + '.' + via + '.lease', type(actual) is int and actual > 0
                       and (ttl is None or actual == ttl) and (maximum is None or actual <= maximum))
            self.check(label + '.' + via + '.shape', renewed.get('renewable') is True
                       and renewal_token_shape(renewed, auth['client_token'], via_accessor=via == 'accessor'))


def run_mode(client, side, issuer, ca, private, jwk, mode, restart, rows, diagnostics=None):
    t = Trace(client, issuer, mode, rows, diagnostics)
    base = 'auth/jwt-native-ttl-' + mode
    tune_path = 'sys/auth/jwt-native-ttl-' + mode + '/tune'
    issuer.mode = 'normal'
    t.call('mount', 'sys/auth/jwt-native-ttl-' + mode, {'type': 'jwt'}, expected=204)
    t.call('tune', tune_path, {'default_lease_ttl': 75, 'max_lease_ttl': 600}, expected=204)
    t.call('config', base + '/config', configuration(side, mode, issuer, private, jwk, ca), expected=204, offline=False)

    def login(label, name, lease):
        issuer.mode = 'normal'
        signed = token(private, jwk, issuer.origin)
        t.sensitive.append(signed)
        body = t.call(label, base + '/login', {'role': name, 'jwt': signed}, bearer='', offline=False)
        auth = body.get('auth', {})
        t.check(label + '.lease', type(auth.get('lease_duration')) is int and auth['lease_duration'] == lease
                and auth.get('renewable') is True and all(isinstance(auth.get(key), str) and bool(auth[key])
                for key in ['client_token', 'accessor']))
        t.sensitive.append(auth['client_token'])
        return auth

    defaults = {}
    for name, fields, expected, lease in creation_matrix():
        path = base + '/role/' + name
        t.write_role('create.' + name, path, role_fields(**fields))
        t.read_role('create.' + name + '.read', path, expected)
        defaults[name] = login('create.' + name + '.login', name, lease)
    issuer.mode = 'unavailable'
    t.renew('default_renew', defaults['omitted'], ttl=75)
    t.renew('zero_renew', defaults['zero'], ttl=75)

    path = base + '/role/mutable'
    t.write_role('mutable.create', path, role_fields(token_ttl=40, token_max_ttl=300))
    t.write_role('mutable.null', path, {'token_ttl': None, 'token_max_ttl': None})
    t.read_role('mutable.null_read', path, (40, 300, 0, 0))
    mutable = login('mutable.null_login', 'mutable', 40)
    issuer.mode = 'unavailable'
    t.renew('mutable.null_renew', mutable, ttl=40)
    t.write_role('mutable.partial', path, {'token_ttl': 50})
    t.read_role('mutable.partial_read', path, (50, 300, 0, 0))
    t.renew('mutable.partial_renew', mutable, ttl=50)
    t.write_role('mutable.zero_ttl', path, {'token_ttl': 0})
    t.read_role('mutable.zero_ttl_read', path, (0, 300, 0, 0))
    t.renew('mutable.zero_ttl_renew', mutable, ttl=75)
    t.write_role('mutable.zero_max', path, {'token_max_ttl': 0})
    t.read_role('mutable.zero_read', path, (0, 0, 0, 0))
    mutable_fresh = login('mutable.zero_login', 'mutable', 75)
    issuer.mode = 'unavailable'
    t.renew('mutable.zero_renew', mutable_fresh, ttl=75)

    cap_path = base + '/role/cap'
    t.write_role('cap.create', cap_path, role_fields(token_ttl=0, token_max_ttl=0, token_explicit_max_ttl=120))
    limited = login('cap.login', 'cap', 75)
    t.call('cap.raise_mount_max', tune_path, {'max_lease_ttl': 900}, expected=204)
    t.write_role('cap.raise_role_explicit', cap_path, {'token_explicit_max_ttl': 600})
    issuer.mode = 'unavailable'
    t.renew('cap.issued_limit', limited, maximum=120, increment=700)
    data = t.call('cap.lookup', 'auth/token/lookup-self', method='GET', bearer=limited['client_token']).get('data', {})
    t.check('cap.explicit_snapshot', data.get('explicit_max_ttl') == 120)
    t.renew('mount_max_inherited', defaults['omitted'], ttl=700, increment=700)

    periodic_path = base + '/role/periodic'
    t.write_role('periodic.create', periodic_path, role_fields(token_ttl=40, token_max_ttl=300,
                                                            token_period=30, token_explicit_max_ttl=180))
    t.write_role('periodic.null', periodic_path, {field: None for field in TTL_FIELDS})
    t.read_role('periodic.null_read', periodic_path, (40, 300, 30, 180))
    periodic = login('periodic.login', 'periodic', 30)
    issuer.mode = 'unavailable'
    t.renew('periodic.null_renew', periodic, ttl=30, increment=700)
    restart()
    t.check('restart.same_store', True)
    t.read_role('restart.mutable', path, (0, 0, 0, 0))
    t.read_role('restart.periodic', periodic_path, (40, 300, 30, 180))
    t.read_role('restart.cap', cap_path, (0, 0, 0, 600))
    t.renew('restart.periodic_renew', periodic, ttl=30, increment=700)
    t.renew('restart.zero_renew', mutable_fresh, ttl=75)
    t.renew('restart.explicit_renew', limited, maximum=120, increment=700)
    data = t.call('restart.cap_lookup', 'auth/token/lookup-self', method='GET', bearer=limited['client_token']).get('data', {})
    t.check('restart.explicit_snapshot', data.get('explicit_max_ttl') == 120)
    t.check('receipt.no_credentials', not any(secret in json.dumps(rows) for secret in t.sensitive))
    t.check('complete', True)
    return t.sensitive


def required_cases():
    suffixes = {'mutable.null_read.fields', 'mutable.partial_read.fields', 'mutable.zero_read.fields',
                'cap.explicit_snapshot', 'periodic.null_read.fields', 'restart.same_store',
                'restart.mutable.fields', 'restart.periodic.fields', 'restart.cap.fields',
                'restart.explicit_snapshot', 'receipt.no_credentials', 'complete'}
    for name, *_ in creation_matrix():
        suffixes |= {'create.' + name + '.read.fields', 'create.' + name + '.login.lease'}
    for phase in ['default_renew', 'zero_renew', 'mutable.null_renew', 'mutable.partial_renew',
                  'mutable.zero_ttl_renew', 'mutable.zero_renew', 'cap.issued_limit', 'mount_max_inherited',
                  'periodic.null_renew', 'restart.periodic_renew', 'restart.zero_renew', 'restart.explicit_renew']:
        for via in ['self', 'token', 'accessor']:
            suffixes |= {phase + '.' + via, phase + '.' + via + '.lease', phase + '.' + via + '.shape'}
    return {'jwt_native_ttl.' + mode + '.' + suffix for mode in MODES for suffix in suffixes} | {'jwt_native_ttl.secrets_absent'}


def complete(rows):
    if not isinstance(rows, list) or not rows:
        return False
    names = []
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get('case'), str)
                or re.fullmatch(r'jwt_native_ttl\.[a-z0-9_.]{1,180}', row['case']) is None
                or row.get('passed') is not True
                or any(type(v) not in (int, bool) for k, v in row.items() if k not in ('case', 'passed'))):
            return False
        names.append(row['case'])
    return len(set(names)) == len(names) and required_cases().issubset(names)


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--build-source-commit')
    parser.add_argument('--oracle-only', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.oracle_only and (args.binary is None or re.fullmatch(r'[0-9a-f]{40}', args.build_source_commit or '') is None):
        parser.error('candidate binary and full build source commit required')
    output = args.output.absolute()
    admitted = admit_output(output)
    binary = args.binary.resolve(strict=True) if args.binary else None
    before = source_identity(ROOT, binary) if not args.oracle_only else None
    runner_hash = file_hash(Path(__file__))
    root = Path(tempfile.mkdtemp(prefix='heptabao-jwt-native-ttl-'))
    root.chmod(0o700)
    oracle = instance = issuer = None
    cases, failures, diagnostics = {}, {}, {}
    unenrolled = False
    try:
        oracle = start_oracle(free_port())
        ca_root = Path(oracle['root'])
        issuer = JsonIssuer(ca_root / 'tls.crt', ca_root / 'tls.key')
        ca = Path(oracle['ca_file']).read_text()
        oracle_token = private_read(oracle['token_file']).decode().strip()
        reference = Client(oracle['address'], oracle['ca_file'], oracle_token)
        def restart_reference():
            stop_oracle(oracle)
            restart_oracle(oracle)
        targets = [('oracle', reference, restart_reference, ca_root, [oracle_token, private_read(ca_root / 'unseal.key').decode().strip()])]
        if not args.oracle_only:
            instance = Instance(binary, root / 'candidate')
            settings_path = instance.root / 'server.json'
            settings = json.loads(settings_path.read_text())
            settings.update(lifecycle_interval_seconds=0, outbound_endpoints=[])
            private_write(settings_path, settings, replace=True)
            unenrolled = json.loads(settings_path.read_text())['outbound_endpoints'] == []
            instance.start()
            status, initialized = instance.call('POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1})
            if status != 200:
                raise ScenarioFailure('candidate_init')
            instance.token, key = initialized['root_token'], initialized['keys_base64'][0]
            if instance.call('POST', 'sys/unseal', {'key': key})[0] != 200:
                raise ScenarioFailure('candidate_unseal')
            def restart_candidate():
                instance.stop()
                instance.start()
                if instance.call('POST', 'sys/unseal', {'key': key})[0] != 200:
                    raise ScenarioFailure('candidate_restart')
            targets.append(('candidate', Client(instance.address, str(instance.root / 'ca.crt'), instance.token),
                            restart_candidate, instance.root, [instance.token, key]))
        for side, client, restart, data_root, sensitive in targets:
            cases[side], diagnostics[side] = [], []
            try:
                for mode in MODES:
                    private, jwk = signing_key('ES256', 'synthetic-native-ttl-' + mode)
                    issuer.documents['/keys'] = {'keys': [jwk]}
                    sensitive += run_mode(client, side, issuer, ca, private, jwk, mode, restart, cases[side], diagnostics[side])
                files = [p for p in (data_root / 'data').rglob('*') if p.is_file()]
                files += [data_root / 'server.log', data_root / 'audit.jsonl']
                safe = (all(secret.encode() not in p.read_bytes() for p in files if p.exists() for secret in sensitive)
                        and not any(secret in json.dumps({'cases': cases[side], 'diagnostics': diagnostics[side]}) for secret in sensitive))
                cases[side].append({'case': 'jwt_native_ttl.secrets_absent', 'passed': safe is True})
                if safe is not True:
                    raise ScenarioFailure('secret_scan_failed')
            except Exception as error:
                failures[side] = next((row['case'] for row in reversed(cases[side]) if row['passed'] is not True),
                                      'fixture_' + type(error).__name__)
    except Exception as error:
        failures['setup'] = 'fixture_' + type(error).__name__
    finally:
        try:
            if instance is not None:
                instance.stop()
        finally:
            try:
                if issuer is not None:
                    issuer.close()
            finally:
                if oracle is not None:
                    stop_oracle(oracle)
                    shutil.rmtree(oracle['root'])
                shutil.rmtree(root)
    unchanged = before == source_identity(ROOT, binary) if before else None
    runner_unchanged = runner_hash == file_hash(Path(__file__))
    equal = cases.get('candidate') == cases.get('oracle') if not args.oracle_only else None
    passed = (not failures and runner_unchanged and set(cases) == ({'oracle'} if args.oracle_only else {'oracle', 'candidate'})
              and all(complete(rows) for rows in cases.values()) and (args.oracle_only or unchanged and unenrolled and equal))
    report = {'schema': 'heptabao.jwt-native-ttl-comparison.v1', 'status': 'passed' if passed else 'failed',
              'candidate_source': before, 'build_source_commit': args.build_source_commit,
              'source_and_binary_unchanged': unchanged, 'runner_sha256': runner_hash, 'runner_unchanged': runner_unchanged,
              'oracle_binary_sha256': BINARY_SHA256, 'oracle_only': args.oracle_only, 'target_version': '2.6.2',
              'candidate_startup_enrollment_empty': unenrolled, 'cases': cases, 'cases_match': equal, 'failures': failures,
              'lease_diagnostics': diagnostics, 'configuration_adaptation': ADAPTATION, 'synthetic_only': True, 'oidc_covered': False,
              'global_system_default_parity': False, 'full_openbao_compatibility': False,
              'independent_qualification': False, 'production_authority': False}
    if admit_output(output) != admitted:
        raise ValueError('report_parent_changed')
    private_write(output, report, replace=False)
    print(json.dumps({'status': report['status'], 'cases': {side: len(rows) for side, rows in cases.items()}, 'failures': failures}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
