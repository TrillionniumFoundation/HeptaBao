#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import http.client
import json
import os
import re
import ssl
import stat
import sys
import time
import types
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).absolute().parent
WORKER_SCHEMA = 'heptabao.authbus.gateway-kv-consumer.r1'
REQUEST_SCHEMA = 'heptabao.authbus.gateway-kv-consumer-request.r1'
FROZEN = {
    'gateway_token_readonly_r1.py': 'e03a81f81807507bd927209f47f4068d1c80df93182b94d989f1ae06dfb038dd',
    'gateway_device_crypto_r1.mjs': '0e2e88817d10b3fc30e64292f39638f6cb3f303656e7b845d2b57f0a10da044b',
    'gateway_device_readonly_r1.py': 'ca2a2b20ee3f817ca20347a1cd8b31e4d3b7a4e5e2ec067846f89769e3ea3a0a',
    'gateway_device_probe_r1.py': '931550541fa8d4294e1d775e9fd98a23f172727345494704fee8e4858839266b',
}

def strict_json(raw):
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise ValueError('duplicate_json_key')
            out[k] = v
        return out
    def constant(_):
        raise ValueError('non_finite_json')
    return json.loads(raw.decode('utf-8-sig'), object_pairs_hook=pairs, parse_constant=constant)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')

def read_frozen(path, expected_sha, cap=65536):
    path = Path(path)
    if not re.fullmatch('[0-9a-f]{64}', expected_sha or ''):
        raise RuntimeError('public_source_expected_sha')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= cap:
            raise RuntimeError('public_source_shape')
        raw = bytearray()
        while len(raw) <= cap:
            chunk = os.read(fd, min(65536, cap + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if identity(before) != identity(after) or len(raw) != before.st_size:
            raise RuntimeError('public_source_changed')
        raw = bytes(raw)
        if hashlib.sha256(raw).hexdigest() != expected_sha:
            raise RuntimeError('public_source_sha')
        return raw
    finally:
        os.close(fd)

def load_public(path, expected_sha, name, cap=65536):
    raw = read_frozen(path, expected_sha, cap)
    module = types.ModuleType(name)
    module.__file__ = str(Path(path).absolute())
    sys.modules[name] = module
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module

def load_contracts(host, pocket4_wrapper_sha):
    for name, expected in FROZEN.items():
        read_frozen(HERE / name, expected)
    if host == 'pocket4':
        W = load_public(HERE / 'gateway_device_pocket4_scope_r2.py', pocket4_wrapper_sha, '_gateway_p4_scope_for_kv_r1')
        P, I, binding = W.load_contracts()
        return P, I, W, binding
    if host != 'rog' or pocket4_wrapper_sha is not None:
        raise RuntimeError('consumer_host_binding')
    P = load_public(HERE / 'gateway_device_probe_r1.py', FROZEN['gateway_device_probe_r1.py'], '_gateway_rog_probe_for_kv_r1')
    return P, P.I, None, {'frozenOriginalFileSha256': dict(FROZEN)}

class PinnedApi:
    def __init__(self, address, ca_pem, leaf_sha, budget):
        u = urlsplit(address)
        if (u.scheme != 'https' or u.hostname != '127.0.0.1' or u.username is not None
                or u.password is not None or u.path not in ('', '/') or u.query or u.fragment
                or u.port is None or not 1024 <= u.port <= 65535 or u.port == 18789
                or not re.fullmatch('[0-9a-f]{64}', leaf_sha or '')):
            raise RuntimeError('candidate_loopback_tls_binding')
        self.port = u.port
        self.leaf_sha = leaf_sha
        self.budget = budget
        self.context = ssl.create_default_context(cadata=ca_pem.decode('ascii'))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.peer_pin_checked_before_credentials = False
        self.tls_version = None
        self.calls = 0

    def call(self, method, path, value=None, token=None):
        if (method not in ('GET', 'POST', 'PUT', 'DELETE')
                or not re.fullmatch(r'[A-Za-z0-9_./-]+(?:\?version=[1-9][0-9]{0,8})?', path)
                or '..' in path.split('/')):
            raise RuntimeError('candidate_request_shape')
        if token is not None and (not isinstance(token, str) or not 16 <= len(token) <= 4096
                                  or not token.isascii() or any(ord(c) <= 32 or ord(c) >= 127 for c in token)):
            raise RuntimeError('candidate_bearer_shape')
        body = None if value is None else canonical(value)
        if body is not None and len(body) > 65536:
            raise RuntimeError('candidate_request_bound')
        conn = http.client.HTTPSConnection('127.0.0.1', self.port, context=self.context,
                                           timeout=min(5.0, self.budget.left()))
        try:
            conn.connect()
            if hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest() != self.leaf_sha:
                raise RuntimeError('candidate_peer_pin_mismatch')
            self.peer_pin_checked_before_credentials = True
            self.tls_version = conn.sock.version()
            conn.sock.settimeout(min(5.0, self.budget.left()))
            headers = {'Accept': 'application/json', 'Connection': 'close'}
            if body is not None:
                headers['Content-Type'] = 'application/json'
            if token is not None:
                headers['X-Vault-Token'] = token
            conn.request(method, '/v1/' + path, body=body, headers=headers)
            response = conn.getresponse()
            out = bytearray()
            while len(out) <= 1048576:
                if conn.sock is not None:
                    conn.sock.settimeout(min(5.0, self.budget.left()))
                else:
                    self.budget.left()
                chunk = response.read(min(65536, 1048577 - len(out)))
                if not chunk:
                    break
                out.extend(chunk)
            if len(out) > 1048576:
                raise RuntimeError('candidate_response_bound')
            self.budget.left()
            self.calls += 1
            value = strict_json(bytes(out)) if out else {}
            if not isinstance(value, dict):
                raise RuntimeError('candidate_response_shape')
            return response.status, value
        finally:
            conn.close()

def consumer(request):
    report = {
        'schema': WORKER_SCHEMA, 'ok': False,
        'candidateBackendUsed': False, 'productionClientRestartQualified': False,
        'productionCutoverQualified': False, 'productionGatewayRestartRequested': False,
        'pairingOrApprovalMutationRequested': False, 'cacheMetadataRepairPerformed': False,
        'privateMaterialExported': False, 'cases': [],
    }
    P = I = W = ctx = api = diagnostic = None
    bearer = None
    revoked = False
    source_binding = None
    try:
        expected_keys = {'schema', 'host', 'deadlineMonotonicNs', 'candidateAddress', 'candidateCaPath',
                         'candidateLeafSha256', 'workRoot', 'roleId', 'secretId', 'kvPath', 'expectedVersion',
                         'readVersion', 'expectAccepted', 'inspectionReceiptPath', 'inspectionReceiptSha256',
                         'pocket4WrapperSha256', 'phase'}
        if not isinstance(request, dict) or set(request) != expected_keys or request['schema'] != REQUEST_SCHEMA:
            raise RuntimeError('consumer_request_keys')
        host = request['host']
        P, I, W, code_binding = load_contracts(host, request['pocket4WrapperSha256'])
        need = I.need
        need(type(request['deadlineMonotonicNs']) is int, 'consumer_original_deadline_shape')
        available = (request['deadlineMonotonicNs'] - time.monotonic_ns()) / 1e9
        need(available > 3, 'consumer_original_deadline')
        budget = I.B.Budget(min(25.0, available))
        ctx = I.Context(host, budget)
        report.update({'host': host, 'pid': os.getpid(), 'phase': request['phase'], 'codeBinding': code_binding})
        need(request['phase'] in ('initial', 'fresh-client', 'cold-restart', 'negative-v2', 'rollback-v1', 'restored-v3'), 'consumer_phase')
        need(type(request['expectAccepted']) is bool, 'consumer_expectation_shape')
        need(type(request['expectedVersion']) is int and request['expectedVersion'] in (1, 2, 3), 'consumer_version_shape')
        need(type(request['readVersion']) is int and request['readVersion'] in (0, 1), 'consumer_read_version_shape')
        need(request['kvPath'] == 'secret/data/gateway-canary/source', 'consumer_exact_kv_path')
        need((request['phase'] == 'negative-v2') == (request['expectAccepted'] is False), 'consumer_negative_phase_binding')
        need((request['phase'] == 'rollback-v1') == (request['readVersion'] == 1), 'consumer_rollback_phase_binding')
        need(request['expectedVersion'] == (2 if request['phase'] == 'negative-v2' else 3 if request['phase'] == 'restored-v3' else 1), 'consumer_expected_version_binding')
        root = Path(request['workRoot'])
        need(root.is_absolute() and root.parent == ctx.home and '..' not in root.parts
             and re.fullmatch(r'heptabao-authbus-gateway-kv-r1-[A-Za-z0-9_.-]+', root.name) is not None, 'consumer_work_root_binding')
        root_stat = root.stat(follow_symlinks=False)
        need(stat.S_ISDIR(root_stat.st_mode) and root_stat.st_uid == os.getuid()
             and stat.S_IMODE(root_stat.st_mode) == 0o700, 'consumer_private_work_root')
        ca_path = Path(request['candidateCaPath'])
        need(ca_path.is_absolute() and root in ca_path.parents and '..' not in ca_path.parts, 'consumer_ca_path_binding')
        ctx.load_source(report)
        if W is not None:
            diagnostic = W.verify_diagnostic(I, budget)
        ca_file = ctx.anchor(ca_path, private=False, cap=65536)
        inspected_file = ctx.anchor(Path(request['inspectionReceiptPath']), private=False, cap=32768)
        need(I.sha(inspected_file.raw) == request['inspectionReceiptSha256'], 'consumer_inspection_sha')
        inspected = I.parse_json(inspected_file.raw)
        need(isinstance(inspected, dict) and inspected.get('schema') == I.SCHEMA and inspected.get('host') == host
             and inspected.get('ok') is True and inspected.get('existingTokenReusableForNormalCli') is True
             and inspected.get('readInputsAndFileIdentitiesUnchanged') is True, 'consumer_inspection_qualification')
        if W is not None:
            need(inspected.get('scopeDiagnosticReceiptSha256') == code_binding['scopeDiagnosticReceiptSha256']
                 and inspected.get('scopeBindingCodeSha256') == code_binding['scopeBindingCodeSha256'], 'consumer_scope_diagnostic_binding')
        before = {}
        device = I.inspect_devices(ctx, before)
        need(before.get('existingTokenReusableForNormalCli') is True
             and before.get('operatorTokenIssuerKind') == 'absent'
             and before.get('existingDeviceBrowserRelated') is False, 'consumer_existing_device_qualification')
        source_binding = device['binding']
        need(source_binding == inspected.get('binding'), 'consumer_current_inspection_binding')
        need(not hmac.compare_digest(ctx.token, device['cached_token']), 'consumer_distinct_gateway_and_device_tokens')
        listener = I.B.listener_binding(budget)
        ctx.recheck()
        P.release_mutable_snapshots(ctx, device)
        api = PinnedApi(request['candidateAddress'], ca_file.raw, request['candidateLeafSha256'], budget)
        role_id = I.token_text(request['roleId'])
        secret_id = I.token_text(request['secretId'])
        ctx.private_values.extend([role_id, secret_id])
        status, logged = api.call('POST', 'auth/approle/login', {'role_id': role_id, 'secret_id': secret_id})
        need(status == 200 and isinstance(logged.get('auth'), dict), 'consumer_approle_login')
        bearer = I.token_text(logged['auth'].get('client_token'))
        ctx.private_values.append(bearer)
        need(logged['auth'].get('renewable') is True, 'consumer_approle_renewable')
        status, _ = api.call('POST', 'secret/data/gateway-canary/denied',
                             {'data': {'probe': 'reader-policy-negative'}, 'options': {'cas': 0}}, bearer)
        need(status == 403, 'consumer_read_only_policy')
        path = request['kvPath'] + ('?version=1' if request['readVersion'] == 1 else '')
        status, fetched = api.call('GET', path, token=bearer)
        need(status == 200 and isinstance(fetched.get('data'), dict), 'consumer_kv_read')
        data = fetched['data']
        need(isinstance(data.get('data'), dict) and set(data['data']) == {'token'}
             and isinstance(data.get('metadata'), dict)
             and type(data['metadata'].get('version')) is int
             and data['metadata']['version'] == request['expectedVersion'], 'consumer_kv_version')
        backend_token = I.token_text(data['data']['token'])
        ctx.private_values.append(backend_token)
        need(len(backend_token) == 48, 'consumer_gateway_token_shape')
        same_source = hmac.compare_digest(backend_token, ctx.token)
        need(same_source is request['expectAccepted'], 'consumer_backend_source_expectation')
        need(not hmac.compare_digest(backend_token, device['cached_token']), 'consumer_no_cached_token_substitution')
        status, renewed = api.call('POST', 'auth/token/renew-self', {'increment': '60s'}, bearer)
        need(status == 200 and isinstance(renewed.get('auth'), dict)
             and hmac.compare_digest(I.token_text(renewed['auth'].get('client_token')), bearer), 'consumer_bearer_renewal')
        P.signed_probe(ctx, device, backend_token, negative=not request['expectAccepted'], case_results=report['cases'])
        status, _ = api.call('POST', 'auth/token/revoke-self', {}, bearer)
        need(status == 204, 'consumer_bearer_revoke')
        revoked = True
        status, _ = api.call('GET', path, token=bearer)
        need(status == 403, 'consumer_revocation_enforced')
        after = {}
        final_device = I.inspect_devices(ctx, after)
        need(final_device['binding'] == source_binding
             and after.get('existingTokenReusableForNormalCli') is True, 'consumer_source_or_device_grant_changed')
        ctx.recheck()
        need(I.B.listener_binding(budget) == listener, 'consumer_production_gateway_listener_changed')
        if diagnostic is not None:
            diagnostic.recheck()
        budget.left()
        report.update({
            'ok': True, 'candidateBackendUsed': True, 'backendVersion': request['expectedVersion'],
            'versionExplicitlySelected': request['readVersion'] or None,
            'backendCredentialSha256': I.sha(backend_token.encode('ascii')),
            'backendCredentialMatchesTrustedSource': same_source,
            'realConsumerProtectedReadQualified': request['expectAccepted'],
            'backendWrongCredentialRejected': not request['expectAccepted'],
            'readerAppRoleAuthenticated': True, 'readerWriteDenied': True,
            'readerBearerRenewed': True, 'renewalNaturalExpiryQualified': False,
            'readerBearerRevoked': True, 'revokedBearerReadDenied': True,
            'candidateTlsLeafPinnedBeforeSendingCredentials': api.peer_pin_checked_before_credentials,
            'candidateTlsVersion': api.tls_version, 'candidateApiCalls': api.calls,
            'sourceAndExistingDeviceBinding': source_binding,
            'sourceConfigSecretIdentityAndCacheUnchanged': True,
            'existingDeviceTokenAndApprovalGrantUnchanged': True,
            'selectedDevicePendingRequestsAfter': after.get('selectedDevicePendingRequests'),
            'productionGatewayListenerUnchanged': True,
            'consumerProcessCompletedAtUnixMs': int(time.time() * 1000),
        })
    except BaseException as exc:
        report['error'] = str(exc) if I is not None and isinstance(exc, I.Refused) else 'consumer_failure'
        report['exceptionClass'] = type(exc).__name__
    finally:
        if bearer is not None and not revoked and api is not None:
            try:
                status, _ = api.call('POST', 'auth/token/revoke-self', {}, bearer)
                report['failureCleanupBearerRevoked'] = status == 204
            except BaseException:
                report['failureCleanupBearerRevoked'] = False
        if diagnostic is not None:
            diagnostic.close()
        if ctx is not None:
            try:
                I.public_guard(report, ctx.private_values)
            except BaseException:
                report = {'schema': WORKER_SCHEMA, 'ok': False, 'error': 'consumer_public_redaction_guard',
                          'privateMaterialExported': False, 'productionCutoverQualified': False}
            ctx.close()
    return report

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--consumer', action='store_true', required=True)
    parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            raise RuntimeError('consumer_input_bound')
        request = strict_json(raw)
        report = consumer(request)
    except BaseException as exc:
        report = {'schema': WORKER_SCHEMA, 'ok': False, 'error': 'consumer_input_failure',
                  'exceptionClass': type(exc).__name__, 'privateMaterialExported': False,
                  'productionCutoverQualified': False}
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))
    return 0 if report.get('ok') is True else 2

if __name__ == '__main__':
    raise SystemExit(main())
