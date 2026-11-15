#!/usr/bin/env python3
"""Real schema-34 userpass users/tokens -> schema-35 native lifetime semantics.

The historical process creates all legacy state. Parentless tokens without an
issuing-account marker retain existing permissions but cannot renew; an account
name or fresh metadata is never guessed from their display names.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import secrets
import shutil
import tempfile

from bao_http import Client, SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from identity_upgrade import validate_binary_pins
from jwt_native_ttl_upgrade import scan_storage
from online_evidence import admit_output, source_identity
from provider_renewal_upgrade import durable_manifest
from radius_renewal_live import renewal_token_shape
from smoke import Instance
from userpass_native_live import no_extension

LEGACY_SOURCE = 'd26ed9d5c3bfd1cac6c669f7b767c753adc2f823'
LEGACY_SHA256 = 'ac818b3551fc7b5a9612d3a1778a91502a64c2ca0226923492c9dafffa49bb89'
LEGACY_RECEIPT = ROOT / 'qa/openbao-acceptance/evidence/approle-native-defaults-d26ed9d.json'
SYSTEM_TTL = 32 * 24 * 60 * 60
MOUNTS = {'default': 'userpass', 'tuned': 'workload-userpass'}
DURATIONS = ('token_ttl', 'token_max_ttl', 'token_period', 'token_explicit_max_ttl')
POLICIES = ['default', 'userpass-upgrade']
VALUE = 'secret/data/userpass-upgrade'
PREFIX = 'userpass_upgrade.'
ROUTES = ('self', 'token', 'accessor')


def require_legacy_pin():
    if (not isinstance(LEGACY_SOURCE, str) or re.fullmatch(r'[0-9a-f]{40}', LEGACY_SOURCE) is None
            or not isinstance(LEGACY_SHA256, str) or re.fullmatch(r'[0-9a-f]{64}', LEGACY_SHA256) is None
            or not isinstance(LEGACY_RECEIPT, Path)):
        raise ValueError('legacy_schema34_pin_not_available')


def admit_legacy_receipt(expected, receipt):
    require_legacy_pin()
    source = receipt.get('candidate_source', {})
    if (expected != LEGACY_SHA256 or receipt.get('status') != 'passed'
            or receipt.get('build_source_commit') != LEGACY_SOURCE
            or receipt.get('source_and_binary_unchanged') is not True
            or receipt.get('runner_unchanged') is not True
            or source.get('source_commit') != LEGACY_SOURCE
            or source.get('source_dirty') is not False
            or source.get('binary_sha256') != LEGACY_SHA256):
        raise ValueError('legacy_schema34_receipt_mismatch')


def user_path(mount, name='preserved'):
    return 'auth/' + mount + '/users/' + name


def retained_user(current, old):
    extras = {'token_period', 'token_explicit_max_ttl'} - set(old)
    return (all(type(current.get(key)) is int and current[key] == 0 for key in extras)
            and {key:value for key,value in current.items() if key not in extras} == old)


def retained_token(current, old):
    # TTL naturally counts down. Every other public field, including captured
    # expiry and the absence of username metadata, must remain exact.
    return (type(current.get('ttl')) is int and current['ttl'] > 0
            and {key:value for key,value in current.items() if key != 'ttl'} ==
                {key:value for key,value in old.items() if key != 'ttl'})


class Trace:
    def __init__(self, instance, rows):
        self.instance, self.rows = instance, rows
        self.client = Client(instance.address, str(instance.root / 'ca.crt'), instance.token)
        self.secrets = [instance.token]

    def check(self, label, condition, **observed):
        if (not isinstance(label, str) or re.fullmatch(r'[a-z0-9_.]{1,150}', label) is None
                or any(type(value) not in (int, bool) for value in observed.values())):
            raise ScenarioFailure('invalid_observation_shape')
        self.rows.append({'case': PREFIX + label, **observed, 'passed': condition is True})
        if condition is not True:
            raise ScenarioFailure(PREFIX + label)

    def call(self, label, path, body=None, *, method='POST', bearer=None, expected=200):
        result = self.client.request(method, '/v1/' + path, body, token=bearer)
        self.check(label, result.status == expected, status=result.status)
        return result.body

    def auth(self, label, body, lease, *, username=None):
        auth = body.get('auth') or {}
        self.check(label + '.issued', all(isinstance(auth.get(field), str) and bool(auth[field])
            for field in ('client_token', 'accessor')) and type(auth.get('lease_duration')) is int
            and auth['lease_duration'] == lease and auth.get('renewable') is True)
        if username is not None:
            self.check(label + '.metadata', auth.get('metadata') == {'username': username})
        self.secrets.append(auth['client_token'])
        return auth

    def login(self, label, mount, password, lease, *, name='preserved', native=False):
        body = self.call(label, 'auth/' + mount + '/login/' + name, {'password': password}, bearer='')
        return self.auth(label, body, lease, username=name if native else None)

    def lookup(self, label, auth):
        return self.call(label, 'auth/token/lookup', {'token': auth['client_token']}).get('data') or {}

    def renew(self, label, auth, *, lease=None, increment=None, rejected=None):
        for via in ROUTES:
            fields = {} if increment is None else {'increment': increment}
            if via == 'token':
                fields['token'] = auth['client_token']
            elif via == 'accessor':
                fields['accessor'] = auth['accessor']
            name = label + '.' + via
            status = 200 if rejected is None else rejected[via]
            body = self.call(name, 'auth/token/' + {'self':'renew-self', 'token':'renew', 'accessor':'renew-accessor'}[via],
                fields, bearer=auth['client_token'] if via == 'self' else None, expected=status)
            if status != 200:
                self.check(name + '.no_credentials', not body.get('auth') and not body.get('wrap_info'))
            else:
                response = body.get('auth') or {}
                self.check(name + '.lease', renewal_token_shape(response, auth['client_token'], via_accessor=via == 'accessor')
                    and type(response.get('lease_duration')) is int and response['lease_duration'] == lease)

    def denied_without_extension(self, label, auth, statuses):
        before = self.lookup(label + '.before', auth)
        self.renew(label, auth, increment=300, rejected=statuses)
        after = self.lookup(label + '.after', auth)
        self.check(label + '.expiry_unchanged', no_extension(before, after))


def prepare_legacy(instance, rows):
    instance.start()
    status, initialized = instance.call('POST', 'sys/init', {'secret_shares':1, 'secret_threshold':1})
    if status != 200:
        raise ScenarioFailure(PREFIX + 'initialization_failed')
    instance.token, key = initialized['root_token'], initialized['keys_base64'][0]
    t = Trace(instance, rows)
    password = secrets.token_urlsafe(32)
    t.secrets.extend([key, password])
    t.call('legacy.unseal', 'sys/unseal', {'key':key})
    t.call('legacy.value', VALUE, {'data':{'synthetic':True}})
    t.call('legacy.policy', 'sys/policies/acl/userpass-upgrade', {'policy':
        'path "secret/data/userpass-upgrade" { capabilities = ["read"] } '
        'path "auth/token/create" { capabilities = ["update"] } '
        'path "auth/token/create-orphan" { capabilities = ["update", "sudo"] }'}, expected=204)
    saved = {}
    for profile, mount in MOUNTS.items():
        prefix = 'legacy.' + profile
        ttl, maximum = (SYSTEM_TTL, SYSTEM_TTL) if profile == 'default' else (75, 600)
        if profile == 'tuned':
            t.call(prefix + '.mount', 'sys/auth/' + mount, {'type':'userpass'}, expected=204)
            t.call(prefix + '.tune', 'sys/auth/' + mount + '/tune',
                {'default_lease_ttl':75, 'max_lease_ttl':600}, expected=204)
        t.call(prefix + '.user', user_path(mount), {'password':password, 'token_policies':['userpass-upgrade']}, expected=204)
        user = t.call(prefix + '.user_read', user_path(mount), method='GET').get('data') or {}
        t.check(prefix + '.old_defaults', user.get('token_ttl') == ttl and user.get('token_max_ttl') == maximum
            and user.get('token_policies') == POLICIES and user.get('policies') == POLICIES
            and user.get('token_num_uses') == 0 and not {'token_period', 'token_explicit_max_ttl'}.intersection(user))
        auth = t.login(prefix + '.login', mount, password, ttl)
        lookup = t.lookup(prefix + '.token', auth)
        t.check(prefix + '.issuer_metadata_absent', not lookup.get('meta') and not auth.get('metadata'))
        child = t.auth(prefix + '.child', t.call(prefix + '.child', 'auth/token/create',
            {'policies':['default'], 'ttl':300, 'renewable':True}, bearer=auth['client_token']), 300)
        orphan = t.auth(prefix + '.orphan', t.call(prefix + '.orphan', 'auth/token/create-orphan',
            {'policies':['default'], 'ttl':300, 'renewable':True}, bearer=auth['client_token']), 300)
        saved[profile] = {'user':user, 'auth':auth, 'token':lookup, 'child':child, 'orphan':orphan, 'password':password,
                         'ttl':ttl, 'maximum':maximum}
    t.check('legacy.complete', True)
    return t, key, saved


def restart(instance, binary, key, t, label):
    instance.stop(); instance.binary = binary; instance.start()
    t.call(label + '.unseal', 'sys/unseal', {'key':key})


def run_upgrade(instance, candidate, legacy, rows):
    t, key, saved = prepare_legacy(instance, rows)
    store = instance.root / 'data'
    instance.stop()
    application = durable_manifest(store, application_only=True)
    for phase in ('current', 'untouched_restart'):
        restart(instance, candidate, key, t, phase)
        t.check(phase + '.application_unchanged', durable_manifest(store, application_only=True) == application)
        before = durable_manifest(store)
        value = t.call(phase + '.value', VALUE, method='GET')
        t.check(phase + '.value_preserved', value.get('data', {}).get('data') == {'synthetic':True})
        for profile, mount in MOUNTS.items():
            prefix, record = phase + '.' + profile, saved[profile]
            user = t.call(prefix + '.user', user_path(mount), method='GET').get('data') or {}
            t.check(prefix + '.positive_user_preserved', retained_user(user, record['user']))
            lookup = t.lookup(prefix + '.token', record['auth'])
            t.check(prefix + '.token_exact_no_guessed_meta', retained_token(lookup, record['token']))
        t.check(phase + '.reads_preserve_entire_store', durable_manifest(store) == before)
    native = {}
    for profile, mount in MOUNTS.items():
        prefix, record = 'migration.' + profile, saved[profile]
        t.denied_without_extension(prefix + '.legacy_renew', record['auth'], dict.fromkeys(ROUTES, 400))
        still_valid = t.call(prefix + '.legacy_still_authorized', VALUE, method='GET', bearer=record['auth']['client_token'])
        t.check(prefix + '.legacy_permission_preserved', still_valid.get('data', {}).get('data') == {'synthetic':True})
        t.renew(prefix + '.child', record['child'], lease=300)
        t.renew(prefix + '.orphan', record['orphan'], lease=300)
        t.call(prefix + '.null_update', user_path(mount), dict.fromkeys(DURATIONS), expected=204)
        user = t.call(prefix + '.null_read', user_path(mount), method='GET').get('data') or {}
        t.check(prefix + '.null_preserves_old_positive_and_policies', retained_user(user, record['user']))
        positive = t.login(prefix + '.positive_login', mount, record['password'], record['ttl'], native=True)
        t.call(prefix + '.retune', 'sys/auth/' + mount + '/tune', {'default_lease_ttl':95, 'max_lease_ttl':900}, expected=204)
        t.login(prefix + '.positive_after_tune', mount, record['password'], min(record['ttl'], 900), native=True)
        t.call(prefix + '.fresh', user_path(mount, 'fresh'), {'password':record['password']}, expected=204)
        fresh_user = t.call(prefix + '.fresh_read', user_path(mount, 'fresh'), method='GET').get('data') or {}
        t.check(prefix + '.fresh_native_defaults', all(fresh_user.get(field) == 0 for field in (*DURATIONS, 'token_num_uses'))
            and fresh_user.get('token_policies') == [] and fresh_user.get('policies') == [])
        fresh = t.login(prefix + '.fresh_login', mount, record['password'], 95, name='fresh', native=True)
        t.check(prefix + '.fresh_login_default_policy', fresh.get('token_policies') == ['default'])
        t.call(prefix + '.zero_old_user', user_path(mount), {'token_ttl':0, 'token_max_ttl':0}, expected=204)
        zeroed = t.call(prefix + '.zeroed_read', user_path(mount), method='GET').get('data') or {}
        t.check(prefix + '.only_explicit_zero_migrates', zeroed == {**user, 'token_ttl':0, 'token_max_ttl':0})
        t.renew(prefix + '.new_direct_current_user', positive, lease=95)
        t.renew(prefix + '.fresh_current_user', fresh, lease=95)
        t.denied_without_extension(prefix + '.old_still_unidentified', record['auth'], dict.fromkeys(ROUTES, 400))
        password2 = secrets.token_urlsafe(32); t.secrets.append(password2)
        t.call(prefix + '.password_change', user_path(mount), {'password':password2}, expected=204)
        t.renew(prefix + '.password_does_not_reauthenticate', positive, lease=95)
        t.call(prefix + '.policy_change', user_path(mount), {'token_policies':['userpass-changed']}, expected=204)
        t.denied_without_extension(prefix + '.policy_reject', positive, dict.fromkeys(ROUTES, 500))
        t.call(prefix + '.policy_restore', user_path(mount), {'token_policies':POLICIES}, expected=204)
        t.renew(prefix + '.policy_restored', positive, lease=95)
        t.call(prefix + '.delete', user_path(mount), method='DELETE', expected=204)
        t.denied_without_extension(prefix + '.deleted', positive, {'self':204, 'token':204, 'accessor':500})
        t.renew(prefix + '.child_after_delete', record['child'], lease=300)
        t.renew(prefix + '.orphan_after_delete', record['orphan'], lease=300)
        t.call(prefix + '.recreate', user_path(mount), {'password':password2, 'token_policies':POLICIES}, expected=204)
        t.renew(prefix + '.recreated', positive, lease=95)
        lookup = t.lookup(prefix + '.new_metadata', positive)
        t.check(prefix + '.native_metadata_persisted', lookup.get('meta') == {'username':'preserved'})
        native[profile] = {'auth':positive, 'fresh':fresh, 'password':password2}
    instance.stop()
    application = durable_manifest(store, application_only=True)
    restart(instance, candidate, key, t, 'reopen')
    t.check('reopen.application_unchanged', durable_manifest(store, application_only=True) == application)
    for profile in MOUNTS:
        lookup = t.lookup('reopen.' + profile + '.new_token', native[profile]['auth'])
        t.check('reopen.' + profile + '.native_meta', lookup.get('meta') == {'username':'preserved'})
        lookup = t.lookup('reopen.' + profile + '.old_token', saved[profile]['auth'])
        t.check('reopen.' + profile + '.old_token_exact', retained_token(lookup, saved[profile]['token']))
    instance.stop()
    application = durable_manifest(store, application_only=True)
    instance.binary = legacy; instance.start()
    t.call('downgrade.unseal_rejected', 'sys/unseal', {'key':key}, expected=503)
    t.call('downgrade.remains_sealed', 'sys/health', method='GET', expected=503)
    instance.stop()
    t.check('downgrade.application_unchanged', durable_manifest(store, application_only=True) == application)
    restart(instance, candidate, key, t, 'recovery')
    t.check('recovery.application_unchanged', durable_manifest(store, application_only=True) == application)
    for profile, mount in MOUNTS.items():
        record, old = native[profile], saved[profile]
        prefix = 'recovery.' + profile
        t.denied_without_extension(prefix + '.legacy_renew', old['auth'], dict.fromkeys(ROUTES, 400))
        t.renew(prefix + '.native_renew', record['auth'], lease=95)
        t.renew(prefix + '.child', old['child'], lease=300)
        t.renew(prefix + '.orphan', old['orphan'], lease=300)
        t.login(prefix + '.password_login', mount, record['password'], 95, native=True)
    instance.stop()
    t.check('plaintext_credentials_absent', scan_storage(instance.root, t.secrets))
    t.check('complete', True)


def required_cases(prepare):
    names = {'legacy.complete'}
    for profile in MOUNTS:
        names |= {'legacy.' + profile + '.' + suffix for suffix in
            ('old_defaults', 'login.issued', 'issuer_metadata_absent', 'child.issued', 'orphan.issued')}
    if prepare:
        names.add('legacy.plaintext_credentials_absent')
    else:
        for phase in ('current', 'untouched_restart'):
            names |= {phase + '.application_unchanged', phase + '.reads_preserve_entire_store'}
            for profile in MOUNTS:
                names |= {phase + '.' + profile + '.' + suffix for suffix in
                    ('positive_user_preserved', 'token_exact_no_guessed_meta')}
        names |= {'reopen.application_unchanged', 'downgrade.unseal_rejected', 'downgrade.remains_sealed',
            'downgrade.application_unchanged', 'recovery.application_unchanged', 'plaintext_credentials_absent', 'complete'}
        for profile in MOUNTS:
            names |= {'migration.' + profile + '.' + suffix for suffix in
                ('legacy_renew.expiry_unchanged', 'legacy_permission_preserved', 'null_preserves_old_positive_and_policies',
                 'positive_login.metadata', 'positive_after_tune.issued', 'fresh_native_defaults', 'fresh_login_default_policy',
                 'only_explicit_zero_migrates', 'old_still_unidentified.expiry_unchanged', 'policy_reject.expiry_unchanged',
                 'deleted.expiry_unchanged', 'native_metadata_persisted')}
            for phase, labels in (('migration', ('child', 'orphan', 'new_direct_current_user', 'fresh_current_user',
                    'password_does_not_reauthenticate', 'policy_restored', 'child_after_delete', 'orphan_after_delete', 'recreated')),
                    ('recovery', ('native_renew', 'child', 'orphan'))):
                names |= {phase + '.' + profile + '.' + label + '.' + via + '.lease' for label in labels for via in ROUTES}
            for phase, labels in (('migration', ('legacy_renew', 'old_still_unidentified', 'policy_reject', 'deleted')),
                                  ('recovery', ('legacy_renew',))):
                names |= {phase + '.' + profile + '.' + label + '.' + via + suffix
                          for label in labels for via in ROUTES for suffix in ('', '.no_credentials')}
            names |= {'reopen.' + profile + '.' + suffix for suffix in ('native_meta', 'old_token_exact')}
            names |= {'recovery.' + profile + '.' + suffix for suffix in ('legacy_renew.expiry_unchanged', 'password_login.metadata')}
    return {PREFIX + name for name in names}


def complete(rows, prepare):
    if not isinstance(rows, list) or not rows:
        return False
    if any(not isinstance(row, dict) or not isinstance(row.get('case'), str)
           or re.fullmatch(r'userpass_upgrade\.[a-z0-9_.]{1,150}', row['case']) is None
           or row.get('passed') is not True
           or any(type(value) not in (int, bool) for key,value in row.items() if key not in ('case', 'passed')) for row in rows):
        return False
    names = [row['case'] for row in rows]
    end = 'legacy.plaintext_credentials_absent' if prepare else 'complete'
    return len(names) == len(set(names)) and required_cases(prepare).issubset(names) and names[-1] == PREFIX + end

def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--prepare-legacy", action="store_true")
    for name in ("legacy-binary", "expected-legacy-sha256", "build-source-commit", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    require_legacy_pin()
    if re.fullmatch(r"[0-9a-f]{40}", args.build_source_commit) is None:
        parser.error("full build source commit required")
    legacy = Path(args.legacy_binary).resolve(strict=True)
    admit_legacy_receipt(args.expected_legacy_sha256, json.loads(LEGACY_RECEIPT.read_text()))
    if args.prepare_legacy:
        if args.binary is not None or args.build_source_commit != LEGACY_SOURCE or file_hash(legacy) != LEGACY_SHA256:
            parser.error("prepare requires only the pinned historical binary/source")
        candidate = legacy
        candidate_hash = legacy_hash = LEGACY_SHA256
    else:
        if args.binary is None:
            parser.error("candidate binary required")
        candidate = args.binary.resolve(strict=True)
        candidate_hash, legacy_hash = validate_binary_pins(candidate, legacy, args.expected_legacy_sha256)
    output = Path(args.output).absolute()
    admitted = admit_output(output)
    before = source_identity(ROOT, candidate)
    runner_hash = file_hash(Path(__file__))
    root = Path(tempfile.mkdtemp(prefix="heptabao-userpass-upgrade-"))
    root.chmod(0o700)
    instance = None
    rows, failure = [], None
    try:
        instance = Instance(legacy, root / "candidate")
        settings = json.loads((instance.root / "server.json").read_text())
        settings.update(lifecycle_interval_seconds=0, outbound_endpoints=[])
        private_write(instance.root / "server.json", settings)
        if args.prepare_legacy:
            t, _, _ = prepare_legacy(instance, rows)
            instance.stop()
            t.check("legacy.plaintext_credentials_absent", scan_storage(instance.root, t.secrets))
        else:
            run_upgrade(instance, candidate, legacy, rows)
    except Exception as error:
        failure = str(error) if isinstance(error, ScenarioFailure) else "fixture_" + type(error).__name__
    finally:
        if instance is not None:
            instance.stop()
        shutil.rmtree(root)
    after = source_identity(ROOT, candidate)
    binaries_unchanged = after["binary_sha256"] == candidate_hash and file_hash(legacy) == legacy_hash
    source_unchanged = before == after
    runner_unchanged = file_hash(Path(__file__)) == runner_hash
    if not binaries_unchanged or not source_unchanged or not runner_unchanged:
        failure = "source_binary_or_runner_changed"
    if not complete(rows, args.prepare_legacy):
        failure = failure or "incomplete_observations"
    report = {"schema":"heptabao.userpass-native-upgrade.v1", "status":"passed" if failure is None else "failed",
        "from_schema":34, "minimum_to_schema":None if args.prepare_legacy else 35,
        "prepare_legacy_only":args.prepare_legacy, "failure":failure, "cases":rows,
        "source_identity":before, "source_and_binary_unchanged":source_unchanged,
        "legacy_source_commit":LEGACY_SOURCE, "legacy_binary_sha256":legacy_hash,
        "legacy_receipt_sha256":file_hash(LEGACY_RECEIPT),
        "candidate_binary_sha256":None if args.prepare_legacy else candidate_hash,
        "build_source_commit":args.build_source_commit,
        "build_source_binding_basis":"caller-supplied build commit and observed binary hash, not independent attestation",
        "binaries_unchanged":binaries_unchanged, "runner_sha256":runner_hash, "runner_unchanged":runner_unchanged,
        "candidate_startup_enrollment_empty":True, "reopen_replay_ledger_may_change":True,
        "application_artifact_scope":"all store entries except root ledger.hbl, rebuilt before schema validation",
        "legacy_direct_renewal":"unidentified issuer refuses renewal without changing current token validity or inventing metadata",
        "explicit_tokenapi_descendants_renewable":True, "legacy_positive_parameters_and_policies_preserved":True,
        "synthetic_only":True, "rolling_upgrade_qualification":False, "full_migration_qualification":False,
        "independent_qualification":False, "production_authority":False}
    if admit_output(output) != admitted:
        raise ValueError("report_parent_changed")
    private_write(output, report, replace=False)
    print(json.dumps({"status":report["status"], "checks":len(rows), "failure":failure}))
    return 0 if failure is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
