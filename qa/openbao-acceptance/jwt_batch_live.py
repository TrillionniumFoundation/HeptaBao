#!/usr/bin/env python3
"""Compare selected ordinary JWT batch behavior with the observed OpenBao2.6.2 contract."""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import shutil
import signal
import tempfile

from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from official_openbao_launcher import verify_inputs, start_oracle, stop_oracle, restart_oracle
from online_evidence import admit_output, source_identity
from remote_jwks_live import Instance, signing_key, serialization
from userpass_password_live import free_port, private_parent, safe_files
import jwt_batch_probe as contract

CALIBRATION_PATH = Path(__file__).parent/'evidence/jwt-batch-official-3588f54.json'
CALIBRATION_SHA256 = 'bd02ae048f2a56b338f4130beef02f94778e154b3402f6063ff22dc09d1274de'
CONTRACT_SHA256 = '31057665b002b3dc99d2bf4c1c265cc6f9bee2228450c77cb7fa8752f7db4941'


def type_shape(value):
    if not isinstance(value, dict): return False
    if value.get('shape') in ('missing', 'null', 'other'): return set(value) == {'shape'}
    return (set(value) == {'shape', 'value'} and value['shape'] == 'string'
            and isinstance(value['value'], str) and value['value'] in contract.TYPES)


def safe_rows(rows):
    if not isinstance(rows, list) or not rows: return False
    names = set()
    booleans = {'auth', 'data', 'wrap', 'errors', 'warnings', 'renewable', 'accessor', 'orphan',
        'ordinary_jwt_role', 'entity', 'role_metadata', 'lookup_accessor', 'lookup_orphan',
        'lookup_entity', 'lookup_role_metadata', 'display_name_matches_mount_subject'}
    booleans |= {prefix+suffix for prefix in ('lease', 'ttl')
                 for suffix in ('_positive', '_le_20', '_le_30', '_le_60', '_le_120', '_le_300')}
    numbers = {'token_ttl', 'token_max_ttl', 'token_period', 'token_num_uses',
               'token_explicit_max_ttl', 'num_uses', 'period', 'explicit_max_ttl'}
    types = {'configured_type', 'auth_type', 'lookup_type'}
    relationships = {
        'identity.binding': {'alias_matches_subject', 'alias_role_metadata', 'auth_role_metadata'},
        'reuse.relationship': {'same_entity', 'fresh_bearer'},
        'rejected_assertions.entity_set': {'readable', 'unchanged'}}
    for row in rows:
        if not isinstance(row, dict): return False
        name = row.get('case')
        if not isinstance(name, str) or not re.fullmatch(r'[a-z0-9_.]{1,150}', name) or name in names: return False
        names.add(name)
        if name in relationships:
            keys = relationships[name]
            if set(row) != keys | {'case'} or any(type(row[k]) is not bool for k in keys): return False
            continue
        if not {'case', 'status', 'auth', 'data', 'wrap', 'errors', 'warnings'} <= row.keys(): return False
        if set(row)-booleans-numbers-types-{'case', 'status'}: return False
        if type(row['status']) is not int or not 100 <= row['status'] <= 599: return False
        if any(type(row[k]) is not bool for k in booleans & row.keys()): return False
        if any(type(row[k]) is not int or not 0 <= row[k] < 2**63 for k in numbers & row.keys()): return False
        if any(not type_shape(row[k]) for k in types & row.keys()): return False
    return True


def complete(rows, finished, expected):
    return (isinstance(finished, list) and all(isinstance(x, str) for x in finished)
            and len(finished) == len(set(finished)) and set(finished) == contract.SCENARIOS
            and safe_rows(rows) and contract.REQUIRED_CASES <= {r['case'] for r in rows} and rows == expected)


class StaticConfigClient:
    """The sole adaptation: official static PEM config to candidate inline JWKS."""
    def __init__(self, inner, private, jwk):
        self.inner, self.jwk, self.adaptations = inner, jwk, 0
        self.pem = private.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def request(self, method, path, payload=None, **kwargs):
        if method == 'POST' and path == '/v1/auth/'+contract.MOUNT+'/config':
            expected = {'bound_issuer': contract.ISSUER, 'jwt_validation_pubkeys': [self.pem],
                        'jwt_supported_algs': ['ES256']}
            if payload != expected or self.adaptations: raise ValueError('unexpected_config_adaptation')
            payload = {'issuer': contract.ISSUER, 'audiences': ['heptabao-test'], 'jwks': {'keys': [self.jwk]}}
            self.adaptations += 1
        return self.inner.request(method, path, payload, **kwargs)


def calibrated_rows():
    if file_hash(CALIBRATION_PATH) != CALIBRATION_SHA256: raise ValueError('oracle_calibration_changed')
    value = json.loads(CALIBRATION_PATH.read_text())
    if (value.get('schema') != 'heptabao.jwt-batch-oracle-probe.v1'
        or value.get('status') != 'observed' or value.get('target_version') != '2.6.2'
        or value.get('oracle_only') is not True or value.get('source_qualified') is not False
        or value.get('failure') is not None or value.get('failure_at') is not None
        or any(value.get(key) is not True for key in ('inputs_unchanged', 'secrets_absent', 'processes_stopped'))
        or value.get('runner_sha256') != CONTRACT_SHA256
        or file_hash(Path(contract.__file__)) != CONTRACT_SHA256
        or not complete(value.get('cases'), value.get('completed_scenarios'), value.get('cases'))):
        raise ValueError('oracle_calibration_invalid')
    return value['cases']


def inputs():
    return {'runner': file_hash(Path(__file__)), 'contract': file_hash(Path(contract.__file__)),
            'calibration': file_hash(CALIBRATION_PATH), **contract.helpers()}


def main():
    p = SafeArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path); p.add_argument('--build-source-commit')
    p.add_argument('--expected-binary-sha256'); p.add_argument('--oracle-only', action='store_true')
    p.add_argument('--work-parent', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    if not args.oracle_only and (args.binary is None
            or not re.fullmatch('[0-9a-f]{40}', args.build_source_commit or '')
            or not re.fullmatch('[0-9a-f]{64}', args.expected_binary_sha256 or '')):
        p.error('candidate_binary_build_and_sha256_required')
    binary = args.binary.resolve(strict=True) if args.binary else None
    if binary and file_hash(binary) != args.expected_binary_sha256: p.error('candidate_binary_sha256_mismatch')
    expected = calibrated_rows(); before_inputs = inputs(); bao = verify_inputs(); bao_hash = file_hash(bao)
    before = source_identity(ROOT, binary) if not args.oracle_only else None
    output = args.output.absolute(); admitted = admit_output(output)
    work = Path(tempfile.mkdtemp(prefix='jwt-batch-dual-', dir=private_parent(args.work_parent)))
    prior = os.environ.get('HB_ORACLE_WORK_ROOT'); os.environ['HB_ORACLE_WORK_ROOT'] = str(work)
    cases, finished, scans, failures, all_sensitive = {}, {}, {}, {}, []
    adaptations, stopped = {}, {}
    oracle = candidate = None; side = 'setup'
    def interrupted(signum, frame): raise ScenarioFailure('interrupted')
    handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        for side in (('oracle',) if args.oracle_only else ('oracle', 'candidate')):
            private, jwk = signing_key('ES256', 'jwt-batch-key')
            if side == 'oracle':
                oracle = start_oracle(free_port()); data_root = Path(oracle['root'])
                root_token = private_read(oracle['token_file']).decode().strip()
                client = Client(oracle['address'], oracle['ca_file'], root_token, timeout=5)
                sensitive = [root_token, private_read(data_root/'unseal.key').decode().strip()]
                def restart(): stop_oracle(oracle); restart_oracle(oracle)
            else:
                candidate = Instance(binary, work/'candidate')
                path = candidate.root/'server.json'; config = json.loads(path.read_text())
                config.update(outbound_endpoints=[], lifecycle_interval_seconds=0)
                private_write(path, config, replace=True); candidate.start()
                status, init = candidate.call('POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1})
                if status != 200: raise ScenarioFailure('candidate_initialization_failed')
                candidate.token, key = init['root_token'], init['keys_base64'][0]
                if candidate.call('POST', 'sys/unseal', {'key': key})[0] != 200: raise ScenarioFailure('candidate_unseal_failed')
                client = StaticConfigClient(Client(candidate.address, candidate.root/'ca.crt', candidate.token, timeout=5), private, jwk)
                data_root, sensitive = candidate.root, [candidate.token, key]
                def restart():
                    candidate.stop(); candidate.start()
                    if candidate.call('POST', 'sys/unseal', {'key': key})[0] != 200: raise ScenarioFailure('candidate_restart_failed')
            trace = contract.Trace(client); trace.sensitive.extend(sensitive)
            all_sensitive.append(trace.sensitive); cases[side], finished[side] = trace.rows, trace.finished
            contract.run(trace, private, jwk, restart)
            adaptations[side] = client.adaptations if side == 'candidate' else 0
            if side == 'oracle':
                stop_oracle(oracle); stopped[side] = oracle['process'].poll() is not None; oracle = None
            else:
                candidate.stop(); stopped[side] = True; candidate = None
            scans[side] = safe_files(data_root, trace.sensitive)
            if not scans[side]: raise ScenarioFailure('secret_scan_failed')
    except Exception as error:
        failures[side] = 'fixture_'+type(error).__name__
    finally:
        try:
            if candidate is not None: candidate.stop(); stopped['candidate'] = True
        finally:
            try:
                if oracle is not None: stop_oracle(oracle); stopped['oracle'] = oracle['process'].poll() is not None
            finally:
                if prior is None: os.environ.pop('HB_ORACLE_WORK_ROOT', None)
                else: os.environ['HB_ORACLE_WORK_ROOT'] = prior
                for sig, handler in handlers.items(): signal.signal(sig, handler)
    after = source_identity(ROOT, binary) if before else None
    unchanged, oracle_unchanged = before_inputs == inputs(), bao_hash == file_hash(bao)
    equal = None if args.oracle_only else cases.get('candidate') == cases.get('oracle')
    expected_sides = {'oracle'} if args.oracle_only else {'oracle', 'candidate'}
    matches = {name: complete(rows, finished.get(name), expected) for name, rows in cases.items()}
    mismatch = {name: [row['case'] for row in expected if not any(actual == row for actual in rows)]
                for name, rows in cases.items()}
    passed = (not failures and unchanged and oracle_unchanged and set(cases) == expected_sides
        and set(scans) == expected_sides and all(scans.values()) and all(matches.values())
        and set(stopped) == expected_sides and all(stopped.values())
        and adaptations == ({'oracle': 0} if args.oracle_only else {'oracle': 0, 'candidate': 1})
        and (args.oracle_only or equal and before == after and not before['source_dirty'] and not after['source_dirty']))
    report = {'schema': 'heptabao.jwt-batch-comparison.v1', 'status': 'passed' if passed else 'failed',
        'cases': cases, 'completed_scenarios': finished, 'calibrated_cases_match': matches,
        'calibrated_case_mismatches': mismatch, 'cases_match': equal, 'failures': failures, 'secrets_absent': scans,
        'candidate_source': before, 'candidate_source_after': after,
        'source_and_binary_unchanged': before == after if before else None,
        'build_source_commit': args.build_source_commit, 'inputs_sha256': before_inputs, 'inputs_unchanged': unchanged,
        'oracle_binary_sha256': bao_hash, 'oracle_binary_unchanged': oracle_unchanged,
        'calibration_sha256': CALIBRATION_SHA256, 'target_version': '2.6.2', 'oracle_only': args.oracle_only,
        'retained_failure_work_dir': None if passed else str(work), 'mutating_requests_retried': False,
        'configuration_adaptation': {'oracle': 'static ES256 jwt_validation_pubkeys PEM',
            'candidate': 'static inline JWKS issuer/audiences', 'counts': adaptations},
        'processes_stopped': stopped, 'ordinary_jwt_only': True, 'OIDC_callback_covered': False,
        'remote_JWKS_covered': False, 'MFA_covered': False,
        'HA_covered': False, 'historical_upgrade_covered': False, 'full_openbao_compatibility': False,
        'independent_qualification': False, 'production_authority': False}
    if any(secret in json.dumps(report) for values in all_sensitive for secret in values): raise ValueError('sensitive_report')
    if admit_output(output) != admitted: raise ValueError('output_parent_changed')
    private_write(output, report, replace=False)
    if passed: shutil.rmtree(work)
    print(json.dumps({'status': report['status'], 'cases': {k: len(v) for k, v in cases.items()}, 'failures': failures}))
    return int(not passed)


if __name__ == '__main__': raise SystemExit(main())
