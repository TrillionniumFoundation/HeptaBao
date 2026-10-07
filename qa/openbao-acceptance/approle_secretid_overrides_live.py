#!/usr/bin/env python3
"""Compare per-SecretID CIDR issuance and consumption against pinned OpenBao 2.6.2 observations."""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import shutil
import signal
import tempfile

from bao_http import SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from official_openbao_launcher import verify_inputs, start_oracle, stop_oracle, restart_oracle
from online_evidence import admit_output, source_identity
from radius_cidrs_live import SourceClient
from remote_jwks_live import Instance
from userpass_password_live import free_port, private_parent, safe_files
import approle_secretid_overrides_probe as contract
import approle_secret_cidrs_live as role_comparison

CALIBRATION_PATH = Path(__file__).parent/'evidence/approle-secretid-overrides-official-c54e9b0.json'
CALIBRATION_SHA256 = 'f3be3085aec18b4bc81b749e35b510de72b5645a6217170058d307d03b491a2e'
CONTRACT_SHA256 = '4859a95028bfb55da33eeccd82a0549ad89ff869dabc32d711728fe67333f8ee'


def safe_rows(rows):
    if not isinstance(rows, list) or not rows: return False
    names = set()
    for row in rows:
        if not isinstance(row, dict): return False
        name = row.get('case')
        if not isinstance(name, str) or not re.fullmatch(r'[a-z0-9_.]{1,140}', name) or name in names: return False
        names.add(name)
        if 'status' in row:
            if any(type(row.get(key)) is not bool for key in ('source_error', 'subset_error')): return False
            projected = {key: value for key, value in row.items() if key not in ('source_error', 'subset_error')}
            if not role_comparison.safe_rows([projected]): return False
        else:
            # These compare paired reads / snapshots, not HTTP success statuses.
            # False is valid only where the fixed official observation is false.
            fields = None
            if name.endswith('.pair'): fields = {'both_present', 'same_data'}
            elif name.endswith(('.denial_delta', '.subset_delta')): fields = {'both_present', 'unchanged'}
            elif name.endswith('.snapshot'): fields = {'unchanged'}
            elif name in {f'consume.{mode}.{kind}.one.issued_bearer.not_issued'
                          for mode in contract.MODES for kind in contract.KINDS}:
                fields = {'credential_issued'}
                if row.get('credential_issued') is not False: return False
            if fields is None or set(row) != fields | {'case'}: return False
            if any(type(row[key]) is not bool for key in fields): return False
    return True


def complete(rows, finished, expected):
    return (isinstance(finished, list) and all(isinstance(x, str) for x in finished)
            and len(finished) == len(set(finished)) and set(finished) == contract.SCENARIOS
            and safe_rows(rows) and rows == expected)


def calibrated_rows():
    if file_hash(CALIBRATION_PATH) != CALIBRATION_SHA256: raise ValueError('oracle_calibration_changed')
    value = json.loads(CALIBRATION_PATH.read_text())
    if (value.get('schema') != 'heptabao.approle-secretid-overrides-probe.v1'
        or value.get('status') != 'observed' or value.get('target_version') != '2.6.2'
        or value.get('oracle_only') is not True or value.get('source_qualified') is not False
        or value.get('candidate_executed') is not False
        or value.get('failure') is not None or value.get('failure_at') is not None
        or any(value.get(key) is not True for key in ('inputs_unchanged', 'secrets_absent', 'processes_stopped'))
        or value.get('runner_sha256') != CONTRACT_SHA256
        or file_hash(Path(contract.__file__)) != CONTRACT_SHA256
        or not complete(value.get('cases'), value.get('completed_scenarios'), value.get('cases'))):
        raise ValueError('oracle_calibration_invalid')
    return value['cases']


def inputs():
    return {'runner': file_hash(Path(__file__)), 'contract': file_hash(Path(contract.__file__)),
            'calibration': file_hash(CALIBRATION_PATH),
            'role_projection': file_hash(Path(role_comparison.__file__)), **contract.helpers()}


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
    work = Path(tempfile.mkdtemp(prefix='approle-secretid-overrides-dual-', dir=private_parent(args.work_parent)))
    prior = os.environ.get('HB_ORACLE_WORK_ROOT'); os.environ['HB_ORACLE_WORK_ROOT'] = str(work)
    cases, finished, scans, failures, all_sensitive = {}, {}, {}, {}, []
    oracle = candidate = None; side = 'setup'; processes = []
    def interrupted(signum, frame): raise ScenarioFailure('interrupted')
    handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        for side in (('oracle',) if args.oracle_only else ('oracle', 'candidate')):
            if side == 'oracle':
                oracle = start_oracle(free_port()); processes.append(oracle['process']); data_root = Path(oracle['root'])
                root_token = private_read(oracle['token_file']).decode().strip()
                client = SourceClient(oracle['address'], oracle['ca_file'], root_token)
                sensitive = [root_token, private_read(data_root/'unseal.key').decode().strip()]
                def restart():
                    stop_oracle(oracle); restart_oracle(oracle); processes.append(oracle['process'])
            else:
                candidate = Instance(binary, work/'candidate')
                path = candidate.root/'server.json'; config = json.loads(path.read_text())
                config.update(outbound_endpoints=[], lifecycle_interval_seconds=0)
                private_write(path, config, replace=True); candidate.start(); processes.append(candidate.process)
                status, init = candidate.call('POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1})
                if status != 200: raise ScenarioFailure('candidate_initialization_failed')
                candidate.token, key = init['root_token'], init['keys_base64'][0]
                if candidate.call('POST', 'sys/unseal', {'key': key})[0] != 200: raise ScenarioFailure('candidate_unseal_failed')
                client = SourceClient(candidate.address, candidate.root/'ca.crt', candidate.token)
                data_root, sensitive = candidate.root, [candidate.token, key]
                def restart():
                    candidate.stop(); candidate.start(); processes.append(candidate.process)
                    if candidate.call('POST', 'sys/unseal', {'key': key})[0] != 200: raise ScenarioFailure('candidate_restart_failed')
            trace = contract.Trace(client); trace.sensitive.extend(sensitive)
            all_sensitive.append(trace.sensitive); cases[side], finished[side] = trace.rows, trace.finished
            contract.run(trace, restart)
            if side == 'oracle': stop_oracle(oracle); oracle = None
            else: candidate.stop(); candidate = None
            scans[side] = safe_files(data_root, trace.sensitive)
            if not scans[side]: raise ScenarioFailure('secret_scan_failed')
    except Exception as error:
        failures[side] = 'fixture_'+type(error).__name__
    finally:
        try:
            if candidate is not None: candidate.stop()
        finally:
            try:
                if oracle is not None: stop_oracle(oracle)
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
    stopped = all(process.poll() is not None for process in processes)
    passed = (not failures and stopped and unchanged and oracle_unchanged and set(cases) == expected_sides
        and set(scans) == expected_sides and all(scans.values()) and all(matches.values())
        and (args.oracle_only or equal and before == after and not before['source_dirty'] and not after['source_dirty']))
    report = {'schema': 'heptabao.approle-secretid-overrides-comparison.v1', 'status': 'passed' if passed else 'failed',
        'cases': cases, 'completed_scenarios': finished,
        'no_credential_observations': {name: [row['case'] for row in rows if row.get('credential_issued') is False]
                                       for name, rows in cases.items()},
        'http_case_counts': {name: sum('status' in row for row in rows) for name, rows in cases.items()},
        'comparison_observation_counts': {name: sum('status' not in row for row in rows) for name, rows in cases.items()},
        'no_credential_observations_are_bearer_tests': False, 'processes_stopped': stopped, 'calibrated_cases_match': matches,
        'calibrated_case_mismatches': mismatch, 'cases_match': equal, 'failures': failures, 'secrets_absent': scans,
        'candidate_source': before, 'candidate_source_after': after,
        'source_and_binary_unchanged': before == after if before else None,
        'build_source_commit': args.build_source_commit, 'inputs_sha256': before_inputs, 'inputs_unchanged': unchanged,
        'oracle_binary_sha256': bao_hash, 'oracle_binary_unchanged': oracle_unchanged,
        'calibration_sha256': CALIBRATION_SHA256, 'target_version': '2.6.2', 'oracle_only': args.oracle_only,
        'retained_failure_work_dir': None if passed else str(work), 'mutating_requests_retried': False,
        'numeric_CIDR_profile_only': True, 'role_SecretID_login_CIDRs_covered': passed, 'SecretID_CIDR_overrides_covered': passed,
        'HA_covered': False, 'historical_upgrade_covered': False, 'full_openbao_compatibility': False,
        'not_covered': ['metadata parsing', 'SecretID local-only setting', 'MFA', 'HA',
                        'token child delegation', 'IPv6 actual source sockets'],
        'independent_qualification': False, 'production_authority': False}
    if any(secret in json.dumps(report) for values in all_sensitive for secret in values): raise ValueError('sensitive_report')
    if admit_output(output) != admitted: raise ValueError('output_parent_changed')
    private_write(output, report, replace=False)
    if passed: shutil.rmtree(work)
    print(json.dumps({'status': report['status'], 'cases': {k: len(v) for k, v in cases.items()}, 'failures': failures}))
    return int(not passed)


if __name__ == '__main__': raise SystemExit(main())
