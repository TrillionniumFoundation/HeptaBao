#!/usr/bin/env python3
"""Actual schema41 -> 42 AppRole batch and Kubernetes lease-owner upgrade.

Four stores are created by the pinned historical binary, never fabricated JSON.
Kubernetes TokenRequest is a synthetic TLS protocol peer, not kube-apiserver.
"""
from __future__ import annotations
import datetime as dt
import http.server
import importlib
import json
from pathlib import Path
import re
import secrets
import shutil
import signal
import ssl
import tempfile
import threading
import time

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from identity_upgrade import validate_binary_pins
from online_evidence import admit_output, complete_checks, source_identity
from provider_renewal_upgrade import durable_manifest
from remote_jwks_live import signing_key, token as signed_token
from userpass_password_live import private_parent, safe_files
from userpass_batch_live import complete as legacy_complete
from userpass_batch_upgrade import Trace, initialize, make_instance, restart

LEGACY_SOURCE = 'eeab30a66cccc1443635e0405c7549c76cede0db'
LEGACY_SHA256 = '0240c15a27d7f0e6fb1472eb0630f8730ad773c5832809b0977810a3ff8f56b5'
LEGACY_RECEIPT = ROOT/'qa/openbao-acceptance/evidence/userpass-batch-live-eeab30a.json'
LEGACY_RECEIPT_SHA256 = 'a37d5182b8d4f72c6870ce731300e214b7b260e77c10ca23fa84ae5855bb5877'
AUDIENCE = 'synthetic-batch42-upgrade'
REQUEST_PATH = '/api/v1/namespaces/upgrade/serviceaccounts/worker/token'
VALUE = {'value': 'synthetic-upgrade-value'}
APP_ROLE = 'auth/approle/role/preserved'
POLICY = 'batch42-upgrade'
REQUIRED = frozenset({'complete', 'processes_stopped', 'kube_legacy_old_post_count', 'kube_legacy_pending_unknown',
    'kube_legacy_current_no_retry', 'kube_legacy_restart_no_retry', 'kube_legacy_expiry_preserved',
    'kube_legacy_no_guessed_issue_time', 'kube_legacy_pending_retained_status', 'kube_legacy_secrets_absent',
    'kube_typed_pure_bytes', 'kube_typed_first_post', 'kube_typed_two_expiries',
    'kube_typed_downgrade_unseal_status', 'kube_typed_downgrade_application_unchanged',
    'kube_typed_recovered_expiry', 'kube_typed_restart_no_retry', 'kube_typed_retired_status',
    'kube_typed_secrets_absent'}) | frozenset(
    f'{mode}_{suffix}' for mode in ('role', 'mount') for suffix in (
        'old_service_shape', 'pure_application_unchanged', 'pure_reads_unchanged',
        'pure_restart_application_unchanged', 'pure_restart_reads_unchanged',
        'old_read_control', 'invalid_type_unchanged', 'format_trigger_status',
        'downgrade_unseal_status', 'downgrade_application_unchanged',
        'new_batch_shape', 'secret_consumed_once', 'reopened_batch_shape',
        'old_service_after_migration_shape', 'old_service_renewed_shape', 'secrets_absent'))


def complete(rows):
    if not isinstance(rows, list) or any(not isinstance(row, dict)
        or set(row)-{'case', 'passed', 'status'}
        or 'status' in row and (type(row['status']) is not int or not 100 <= row['status'] <= 599)
        for row in rows):
        return False
    return (complete_checks([{'case': r.get('case'), 'passed': r.get('passed')} for r in rows],
                            required_cases=REQUIRED) and rows[-1]['case'] == 'complete')


def admit_legacy(receipt, digest):
    before, sides = receipt.get('candidate_source') or {}, receipt.get('cases') or {}
    if (digest != LEGACY_RECEIPT_SHA256 or receipt.get('schema') != 'heptabao.userpass-batch-comparison.v1'
        or receipt.get('status') != 'passed' or receipt.get('build_source_commit') != LEGACY_SOURCE
        or before.get('source_commit') != LEGACY_SOURCE or before.get('binary_sha256') != LEGACY_SHA256
        or before.get('source_dirty') is not False or receipt.get('candidate_source_after') != before
        or receipt.get('oracle_only') is not False or receipt.get('failures')
        or set(sides) != {'candidate', 'oracle'} or sides['candidate'] != sides['oracle']
        or not all(legacy_complete(rows) for rows in sides.values())
        or any(receipt.get(name) is not True for name in ('source_and_binary_unchanged', 'cases_match',
            'runner_unchanged', 'helpers_unchanged', 'oracle_binary_unchanged'))):
        raise ValueError('qualified_schema41_binary_receipt_required')


def timestamp(value):
    if not isinstance(value, str): return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        return int(parsed.timestamp()) if parsed.tzinfo else None
    except (ValueError, OverflowError): return None


def retained_role(current, old):
    if not isinstance(current, dict) or not isinstance(old, dict): return False
    current = dict(current)
    return current.pop('token_type', 'default') == 'default' and current == old


def unknown_pending(body):
    return (isinstance(body, dict) and isinstance(body.get('lease_id'), str) and bool(body['lease_id'])
            and body.get('reconcile_required') is True and body.get('retry_allowed') is False
            and not any(body.get(k) for k in ('auth', 'data', 'wrap_info')))


def valid_token_request(path, authorization, body, manager):
    return (path == REQUEST_PATH and authorization == ['Bearer '+manager]
            and body == {'apiVersion': 'authentication.k8s.io/v1', 'kind': 'TokenRequest',
                         'spec': {'audiences': [AUDIENCE], 'expirationSeconds': 600}})


def downgrade(instance, candidate, legacy, t, key, prefix):
    instance.stop()
    before = durable_manifest(instance.root/'data', application_only=True)
    instance.binary = legacy
    instance.start()
    t.call(prefix+'_downgrade_unseal', 'POST', 'sys/unseal', {'key': key}, status=503)
    t.call(prefix+'_downgrade_health', 'GET', 'sys/health', status=503)
    instance.stop()
    t.check(prefix+'_downgrade_application_unchanged',
            durable_manifest(instance.root/'data', application_only=True) == before)
    restart(instance, candidate, t, key, prefix+'_recovery')


def seed_value(t, prefix):
    t.call(prefix+'_policy', 'PUT', 'sys/policies/acl/'+POLICY,
           {'policy': 'path "secret/data/upgrade" { capabilities=["read"] }\n'
                      'path "typed-kube/creds/worker" { capabilities=["update"] }'}, status=204)
    t.call(prefix+'_value', 'POST', 'secret/data/upgrade', {'data': VALUE})


def run_approle(instance, candidate, legacy, rows, mode):
    t, key = initialize(instance, rows, mode+'_legacy')
    seed_value(t, mode)
    t.call(mode+'_role', 'POST', APP_ROLE, {'token_ttl': 300, 'token_max_ttl': 600,
           'token_policies': [POLICY], 'secret_id_num_uses': 3, 'secret_id_ttl': 600}, status=204)
    old_role = t.call(mode+'_old_role', 'GET', APP_ROLE)['data']
    role_id = t.call(mode+'_role_id', 'GET', APP_ROLE+'/role-id')['data']['role_id']
    secret = t.call(mode+'_secret', 'POST', APP_ROLE+'/secret-id', {})['data']
    t.sensitive.extend((role_id, secret['secret_id'], secret['secret_id_accessor']))
    login = {'role_id': role_id, 'secret_id': secret['secret_id']}
    service = t.issued(mode+'_old_service', t.call(mode+'_old_login', 'POST', 'auth/approle/login', login, token=''), 'service')
    sid_body = {'secret_id': secret['secret_id']}
    old_sid = t.call(mode+'_old_sid', 'POST', APP_ROLE+'/secret-id/lookup', sid_body)['data']
    t.check(mode+'_old_sid_remaining', old_sid.get('secret_id_num_uses') == 2)
    instance.stop()
    original = durable_manifest(instance.root/'data', application_only=True)
    for phase in ('pure', 'pure_restart'):
        prefix = mode+'_'+phase
        restart(instance, candidate, t, key, prefix)
        t.check(prefix+'_application_unchanged', durable_manifest(instance.root/'data', application_only=True) == original)
        before = durable_manifest(instance.root/'data')
        got = t.call(prefix+'_role', 'GET', APP_ROLE)['data']
        t.check(prefix+'_role_preserved', retained_role(got, old_role))
        sid = t.call(prefix+'_sid', 'POST', APP_ROLE+'/secret-id/lookup', sid_body)['data']
        t.check(prefix+'_sid_preserved', sid == old_sid)
        t.lookup(prefix+'_service', service, 'service')
        t.value(prefix+'_kv', service)
        t.check(prefix+'_reads_unchanged', durable_manifest(instance.root/'data') == before)
    restart(instance, legacy, t, key, mode+'_control')
    t.lookup(mode+'_control_service', service, 'service')
    t.check(mode+'_old_read_control', durable_manifest(instance.root/'data', application_only=True) == original)
    restart(instance, candidate, t, key, mode+'_candidate')
    path = APP_ROLE if mode == 'role' else 'sys/auth/approle/tune'
    before = durable_manifest(instance.root/'data')
    t.call(mode+'_invalid_type', 'POST', path, {'token_type': 'invalid-kind'}, status=400)
    t.check(mode+'_invalid_type_unchanged', durable_manifest(instance.root/'data') == before)
    t.call(mode+'_format_trigger', 'POST', path,
           {'token_type': 'batch' if mode == 'role' else 'default-batch'}, status=204)
    # No login/SecretID consumption/new token precedes the real old-reader fence.
    downgrade(instance, candidate, legacy, t, key, mode)
    t.lookup(mode+'_old_service_after_migration', service, 'service')
    renewed = t.call(mode+'_old_renew', 'POST', 'auth/token/renew-self', {'increment': 90}, token=service['client_token'])
    t.issued(mode+'_old_service_renewed', renewed, 'service')
    batch = t.issued(mode+'_new_batch', t.call(mode+'_new_login', 'POST', 'auth/approle/login', login, token=''), 'batch')
    t.check(mode+'_batch_identity', batch.get('entity_id') == service.get('entity_id')
            and (batch.get('metadata') or {}).get('role_name') == 'preserved')
    sid = t.call(mode+'_new_sid', 'POST', APP_ROLE+'/secret-id/lookup', sid_body)['data']
    t.check(mode+'_secret_consumed_once', sid.get('secret_id_num_uses') == 1)
    t.value(mode+'_batch_value', batch)
    restart(instance, candidate, t, key, mode+'_reopened')
    t.lookup(mode+'_reopened_batch', batch, 'batch')
    t.value(mode+'_reopened_value', batch)
    instance.stop()
    t.check(mode+'_secrets_absent', safe_files(instance.root, t.sensitive))


class TokenProvider:
    """One test-owned TLS peer; captures counts/booleans, never request secrets."""
    def __init__(self, cert, key):
        self.manager = secrets.token_urlsafe(32)
        self.mode, self.calls, self.valid, self.last_expiry = 'normal', 0, True, None
        self.tokens = []
        private, jwk = signing_key('ES256', 'synthetic-tokenrequest')
        owner = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_POST(self):
                owner.calls += 1
                self.close_connection = True
                try:
                    lengths = self.headers.get_all('Content-Length', [])
                    length = int(lengths[0]) if len(lengths) == 1 else -1
                    if not 0 < length <= 65536: raise ValueError('request_bounds')
                    body = json.loads(self.rfile.read(length))
                    valid = valid_token_request(self.path, self.headers.get_all('Authorization'), body, owner.manager)
                    owner.valid &= valid
                    if not valid: raise ValueError('request_mismatch')
                    if owner.mode == 'normal':
                        expiry = int(time.time())+600
                        token = signed_token(private, jwk, 'synthetic-kubernetes-upgrade',
                            sub='system:serviceaccount:upgrade:worker', aud=[AUDIENCE], exp=expiry)
                        owner.tokens.append(token); owner.last_expiry = expiry
                        value = {'apiVersion': 'authentication.k8s.io/v1', 'kind': 'TokenRequest', 'status': {'token': token}}
                    else:
                        value = {'apiVersion': 'authentication.k8s.io/v1', 'kind': 'TokenRequest', 'status': {}}
                    payload = json.dumps(value).encode()
                    self.send_response(201)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(payload)))
                    self.send_header('Connection', 'close')
                    self.end_headers(); self.wfile.write(payload)
                except (ValueError, TypeError, KeyError, OSError):
                    owner.valid = False
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.origin = 'https://localhost:'+str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()

    def close(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=5)
        if self.thread.is_alive(): raise ScenarioFailure('provider_shutdown_failed')


def configure_provider(instance, provider):
    path = instance.root/'server.json'; config = json.loads(path.read_text())
    config['outbound_endpoints'] = [{'origin': provider.origin, 'address': '127.0.0.1:'+str(provider.server.server_port),
        'server_name': 'localhost', 'ca_pem': (instance.root/'ca.crt').read_text(), 'path_prefix': '/'}]
    private_write(path, config, replace=True)


def kube_setup(t, provider, mount, prefix):
    t.call(prefix+'_mount', 'POST', 'sys/mounts/'+mount, {'type': 'kubernetes'}, status=204)
    t.call(prefix+'_config', 'POST', mount+'/config', {'kubernetes_host': provider.origin,
           'service_account_token': provider.manager}, status=204)
    t.call(prefix+'_role', 'POST', mount+'/roles/worker', {'allowed_kubernetes_namespaces': ['upgrade'],
           'service_account_name': 'worker', 'token_default_ttl': 600, 'token_max_ttl': 600,
           'token_default_audiences': [AUDIENCE]}, status=204)


def credential(t, provider, mount, prefix, *, bearer=None, status=200):
    count = provider.calls
    value = t.call(prefix, 'POST', mount+'/creds/worker', {'kubernetes_namespace': 'upgrade',
           'ttl': 600, 'audiences': [AUDIENCE]}, token=bearer, status=status)
    t.check(prefix+'_one_post', provider.calls == count+1 and provider.valid)
    t.sensitive.extend(provider.tokens)
    if status == 200:
        t.check(prefix+'_actual_response', (value.get('data') or {}).get('service_account_token') == provider.tokens[-1]
                and value.get('renewable') is False and isinstance(value.get('lease_id'), str))
    return value


def run_kube_legacy(instance, candidate, rows, provider):
    t, key = initialize(instance, rows, 'kube_legacy')
    t.sensitive.append(provider.manager)
    for mount in ('legacy-kube', 'pending-kube'): kube_setup(t, provider, mount, mount.replace('-', '_'))
    response = credential(t, provider, 'legacy-kube', 'kube_legacy_issue')
    old_expiry = provider.last_expiry
    provider.mode = 'invalid-response'
    pending = credential(t, provider, 'pending-kube', 'kube_legacy_unknown', status=503)
    t.check('kube_legacy_pending_unknown', unknown_pending(pending))
    provider.mode = 'normal'
    t.check('kube_legacy_old_post_count', provider.calls == 2)
    for phase in ('current', 'restart'):
        prefix = 'kube_legacy_'+phase
        restart(instance, candidate, t, key, prefix)
        t.call(prefix+'_config', 'GET', 'pending-kube/config')
        t.call(prefix+'_role', 'GET', 'pending-kube/roles/worker')
        t.check(prefix+'_no_retry', provider.calls == 2 and provider.valid)
    # Failed old intent remains an administrative fence; no public replay exists.
    t.call('kube_legacy_pending_retained', 'DELETE', 'pending-kube/roles/worker', status=409)
    data = t.call('kube_legacy_lookup', 'PUT', 'sys/leases/lookup', {'lease_id': response['lease_id']})['data']
    t.check('kube_legacy_expiry_preserved', timestamp(data.get('expire_time')) == old_expiry)
    t.check('kube_legacy_no_guessed_issue_time', data.get('issue_time') is None)
    t.check('kube_legacy_final_no_retry', provider.calls == 2 and provider.valid)
    instance.stop(); t.check('kube_legacy_secrets_absent', safe_files(instance.root, t.sensitive))


def run_kube_typed(instance, candidate, legacy, rows, provider):
    t, key = initialize(instance, rows, 'kube_typed')
    t.sensitive.append(provider.manager)
    seed_value(t, 'kube_typed')
    kube_setup(t, provider, 'typed-kube', 'kube_typed')
    # The actor is issued by schema41 before the new typed-owner write.
    batch = t.issued('kube_typed_old_batch', t.call('kube_typed_old_issue', 'POST', 'auth/token/create-orphan',
                     {'type': 'batch', 'ttl': 120, 'policies': [POLICY]}), 'batch')
    instance.stop(); original = durable_manifest(instance.root/'data', application_only=True)
    restart(instance, candidate, t, key, 'kube_typed_candidate')
    t.lookup('kube_typed_pure_batch', batch, 'batch')
    t.call('kube_typed_pure_role', 'GET', 'typed-kube/roles/worker')
    t.check('kube_typed_pure_bytes', durable_manifest(instance.root/'data', application_only=True) == original)
    response = credential(t, provider, 'typed-kube', 'kube_typed_issue', bearer=batch['client_token'])
    t.check('kube_typed_first_post', provider.calls == 1)
    # No other successful new-binary mutation may mask the owner-format fence.
    downgrade(instance, candidate, legacy, t, key, 'kube_typed')
    owner = t.lookup('kube_typed_recovered_batch', batch, 'batch')
    lease = t.call('kube_typed_lookup', 'PUT', 'sys/leases/lookup', {'lease_id': response['lease_id']})['data']
    lease_expiry, batch_expiry = timestamp(lease.get('expire_time')), timestamp(owner.get('expire_time'))
    t.check('kube_typed_two_expiries', type(lease_expiry) is int and type(batch_expiry) is int
            and int(time.time()) < lease_expiry <= batch_expiry and provider.last_expiry > lease_expiry+400)
    restart(instance, candidate, t, key, 'kube_typed_restart')
    after = t.call('kube_typed_reopened_lookup', 'PUT', 'sys/leases/lookup', {'lease_id': response['lease_id']})['data']
    t.check('kube_typed_recovered_expiry', after.get('expire_time') == lease.get('expire_time'))
    t.check('kube_typed_restart_no_retry', provider.calls == 1 and provider.valid)
    t.call('kube_typed_revoke', 'PUT', 'sys/leases/revoke', {'lease_id': response['lease_id']}, status=204)
    t.call('kube_typed_retired', 'PUT', 'sys/leases/lookup', {'lease_id': response['lease_id']}, status=400)
    t.check('kube_typed_retire_no_provider', provider.calls == 1 and provider.valid)
    instance.stop(); t.check('kube_typed_secrets_absent', safe_files(instance.root, t.sensitive))


def helpers():
    names = ('bao_http', 'heptabao.transport', 'core_isolation', 'identity_upgrade', 'online_evidence',
        'provider_renewal_upgrade', 'remote_jwks_live', 'smoke', 'userpass_password_live',
        'userpass_batch_live', 'userpass_batch_contract', 'userpass_batch_upgrade')
    return {name: file_hash(Path(importlib.import_module(name).__file__)) for name in names}


def main():
    parser = SafeArgumentParser(description=__doc__)
    for name in ('binary', 'legacy-binary', 'work-parent', 'output'): parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--build-source-commit', required=True); parser.add_argument('--expected-binary-sha256', required=True)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.build_source_commit) or not re.fullmatch('[0-9a-f]{64}', args.expected_binary_sha256):
        parser.error('candidate_pins_required')
    candidate, legacy = args.binary.resolve(strict=True), args.legacy_binary.resolve(strict=True)
    actual, legacy_hash = validate_binary_pins(candidate, legacy, LEGACY_SHA256)
    if actual != args.expected_binary_sha256: parser.error('candidate_binary_mismatch')
    admit_legacy(json.loads(LEGACY_RECEIPT.read_text()), file_hash(LEGACY_RECEIPT))
    output = args.output.absolute(); admitted = admit_output(output)
    before, runner, helper = source_identity(ROOT, candidate), file_hash(Path(__file__)), helpers()
    work = Path(tempfile.mkdtemp(prefix='batch42-upgrade-', dir=private_parent(args.work_parent))); work.chmod(0o700)
    rows, instances, providers, failure = [], [], [], None
    def interrupted(signum, frame): raise ScenarioFailure('fixture_interrupted')
    signals = {kind: signal.signal(kind, interrupted) for kind in (signal.SIGTERM, signal.SIGINT)}
    try:
        for mode in ('role', 'mount'):
            instance = make_instance(legacy, work/mode); instances.append(instance)
            run_approle(instance, candidate, legacy, rows, mode)
        for mode in ('legacy', 'typed'):
            instance = make_instance(legacy, work/('kube-'+mode)); instances.append(instance)
            provider = TokenProvider(instance.root/'tls.crt', instance.root/'tls.key'); providers.append(provider)
            configure_provider(instance, provider)
            if mode == 'legacy': run_kube_legacy(instance, candidate, rows, provider)
            else: run_kube_typed(instance, candidate, legacy, rows, provider)
            provider.close(); providers.remove(provider)
    except Exception as error:
        failure = next((r['case'] for r in reversed(rows) if r['passed'] is not True), 'fixture_'+type(error).__name__)
    finally:
        try:
            for instance in instances:
                try: instance.stop()
                except Exception: failure = failure or 'candidate_cleanup_failed'
            for provider in providers:
                try: provider.close()
                except Exception: failure = failure or 'provider_cleanup_failed'
        finally:
            for kind, handler in signals.items(): signal.signal(kind, handler)
    stopped = all(instance.process is None for instance in instances)
    rows.append({'case': 'processes_stopped', 'passed': stopped})
    if not stopped: failure = failure or 'candidate_cleanup_failed'
    if failure is None: Trace(instances[-1], rows).check('complete', True)
    after = source_identity(ROOT, candidate)
    unchanged = before == after and file_hash(legacy) == legacy_hash
    runner_ok, helper_ok = file_hash(Path(__file__)) == runner, helpers() == helper
    if not unchanged or not runner_ok or not helper_ok or file_hash(LEGACY_RECEIPT) != LEGACY_RECEIPT_SHA256:
        failure = 'source_binary_or_helpers_changed'
    if before['source_dirty'] or after['source_dirty']: failure = 'source_dirty'
    if not complete(rows): failure = failure or 'incomplete_observations'
    report = {'schema': 'heptabao.approle-kubernetes-batch-upgrade.v1', 'status': 'failed' if failure else 'passed',
        'failure': failure, 'checks': rows, 'source_identity': before, 'source_identity_after': after,
        'source_and_binary_unchanged': unchanged, 'build_source_commit': args.build_source_commit,
        'runner_sha256': runner, 'runner_unchanged': runner_ok, 'helper_sha256': helper, 'helpers_unchanged': helper_ok,
        'legacy_source_commit': LEGACY_SOURCE, 'legacy_binary_sha256': legacy_hash,
        'legacy_receipt_sha256': LEGACY_RECEIPT_SHA256, 'from_schema': 41, 'minimum_to_schema': 42,
        'credential_storage_fabricated': False, 'mutating_requests_retried': False,
        'pure_read_profile': 'AppRole stores and Kubernetes store before any lease; legacy lease maintenance may write',
        'pending_observation': 'actual old POST then role-delete 409 and unchanged provider request count across reopen',
        'provider_profile': 'synthetic TLS TokenRequest with signed synthetic JWT, not Kubernetes API/RBAC qualification',
        'retained_failure_work_dir': str(work) if failure else None, 'synthetic_only': True,
        'actual_kubernetes_covered': False, 'HA_covered': False, 'physical_failure_covered': False,
        'full_openbao_compatibility': False, 'independent_qualification': False, 'production_authority': False}
    if admit_output(output) != admitted: raise ValueError('report_parent_changed')
    private_write(output, report, replace=False)
    if failure is None: shutil.rmtree(work)
    print(json.dumps({'status': report['status'], 'checks': len(rows), 'failure': failure}))
    return int(failure is not None)


if __name__ == '__main__': raise SystemExit(main())
