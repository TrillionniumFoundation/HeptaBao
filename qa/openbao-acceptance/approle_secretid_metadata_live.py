#!/usr/bin/env python3
"""Compare per-SecretID metadata parsing and immutable snapshots against pinned OpenBao 2.6.2 observations."""
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
import approle_secretid_metadata_probe as contract
import approle_secretid_metadata_supplement as supplementary

CALIBRATION_PATH = Path(__file__).parent/'evidence/approle-secretid-metadata-official-b56954e.json'
CALIBRATION_SHA256 = '7292a2c8f5ada19543b2536c1cbfc0648f515a2684aa3c12fe8d9145c6942023'
CONTRACT_SHA256 = '7a1946c002aa55508927b891690f61d6559e0f7bf0e9d365345c12d9abba35c8'
PROFILES = {
    'primary': (contract, CALIBRATION_PATH, CALIBRATION_SHA256, CONTRACT_SHA256,
                'heptabao.approle-secretid-metadata-probe.v1'),
    'supplementary': (supplementary,
        Path(__file__).parent/'evidence/approle-secretid-metadata-supplement-official-b56954e.json',
        'd46ee29bff78d8a57d131ad461738ab7b8a9687bd99adadfebe514ec1db82c56',
        '1a956d0783fba09967f072d17b5ba7d245f0febeef446382b025e137c1072f30',
        'heptabao.approle-secretid-metadata-supplement.v1'),
}



def safe_metadata(value):
    if not isinstance(value, dict): return False
    if value.get('shape') in ('missing', 'null'): return set(value) == {'shape'}
    if set(value) != {'shape', 'value'} or value['shape'] != 'map' or not isinstance(value['value'], dict): return False
    for key, item in value['value'].items():
        if not isinstance(key, str) or (key not in contract.SAFE_KEYS and not re.fullmatch(r'key_sha256_[0-9a-f]{64}', key)): return False
        if isinstance(item, str):
            if item not in contract.SAFE_VALUES and not re.fullmatch(r'meta-(random|custom)-(service|batch)(-life)?', item): return False
        elif not (isinstance(item, dict) and set(item) == {'type', 'sha256'}
            and item['type'] in ('str', 'int', 'bool', 'float', 'NoneType', 'dict', 'list')
            and isinstance(item['sha256'], str) and re.fullmatch('[0-9a-f]{64}', item['sha256'])): return False
    return True


def safe_rows(rows):
    if not isinstance(rows, list) or not rows: return False
    names = set()
    booleans = {'auth', 'data', 'wrap', 'errors', 'renewable', 'accessor', 'orphan', 'metadata_error', 'token_echo'}
    scalar = {'case', 'status', 'secret_id_num_uses', 'num_uses', 'token_type', 'cidr_shape', 'cidrs'}
    projections = {'auth_metadata', 'data_metadata', 'lookup_meta', 'custom_metadata'}
    for row in rows:
        if not isinstance(row, dict): return False
        name = row.get('case')
        if not isinstance(name, str) or not re.fullmatch(r'[a-z0-9_.]{1,140}', name) or name in names: return False
        names.add(name)
        if 'status' not in row:
            if name.endswith('.same_entity'):
                fields = {'matches'} if name.startswith('restart.') else {'matches', 'distinct_bearer'}
            elif name.endswith('.accessor_not_applicable') and '.batch.' in name:
                fields = {'absent_accessor', 'endpoint_not_called'}
            else: return False
            if set(row) != {'case'} | fields or any(type(row[k]) is not bool for k in fields): return False
            continue
        if not {'case', 'status', 'auth', 'data', 'wrap', 'errors', 'metadata_error', 'token_echo'} | projections <= row.keys(): return False
        if set(row)-booleans-scalar-projections: return False
        if type(row['status']) is not int or not 100 <= row['status'] <= 599: return False
        if any(type(row[k]) is not bool for k in booleans & row.keys()): return False
        if any(type(row[k]) is not int or row[k] < 0 for k in {'secret_id_num_uses', 'num_uses'} & row.keys()): return False
        if 'token_type' in row and row['token_type'] not in ('service', 'batch', 'other'): return False
        if any(not safe_metadata(row[k]) for k in projections): return False
        if 'cidr_shape' in row and row['cidr_shape'] not in ('missing', 'null', 'list'): return False
        if 'cidrs' in row and (row.get('cidr_shape') != 'list' or row['cidrs'] != []): return False
        if row.get('cidr_shape') == 'list' and 'cidrs' not in row: return False
    return True


def complete(rows, finished, expected, profile='primary'):
    return (isinstance(finished, list) and all(isinstance(x, str) for x in finished)
            and len(finished) == len(set(finished)) and set(finished) == PROFILES[profile][0].SCENARIOS
            and safe_rows(rows) and rows == expected)


def calibrated_rows(profile='primary'):
    module, path, digest, runner_digest, schema = PROFILES[profile]
    if file_hash(path) != digest: raise ValueError('oracle_calibration_changed')
    value = json.loads(path.read_text())
    if (value.get('schema') != schema
        or value.get('status') != 'observed' or value.get('target_version') != '2.6.2'
        or value.get('oracle_only') is not True or value.get('source_qualified') is not False
        or value.get('candidate_executed') is not False
        or value.get('failure') is not None or value.get('failure_at') is not None
        or any(value.get(key) is not True for key in ('inputs_unchanged', 'secrets_absent', 'processes_stopped'))
        or value.get('runner_sha256') != runner_digest
        or file_hash(Path(module.__file__)) != runner_digest
        or not complete(value.get('cases'), value.get('completed_scenarios'), value.get('cases'), profile)):
        raise ValueError('oracle_calibration_invalid')
    return value['cases']


def inputs():
    return {'runner': file_hash(Path(__file__)),
            'profiles': {name: {'contract': file_hash(Path(module.__file__)), 'calibration': file_hash(path)}
                         for name, (module, path, _, _, _) in PROFILES.items()},
            **contract.helpers()}


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
    expected = {profile: calibrated_rows(profile) for profile in PROFILES}; before_inputs = inputs(); bao = verify_inputs(); bao_hash = file_hash(bao)
    before = source_identity(ROOT, binary) if not args.oracle_only else None
    output = args.output.absolute(); admitted = admit_output(output)
    work = Path(tempfile.mkdtemp(prefix='approle-secretid-metadata-dual-', dir=private_parent(args.work_parent)))
    prior = os.environ.get('HB_ORACLE_WORK_ROOT'); os.environ['HB_ORACLE_WORK_ROOT'] = str(work)
    cases, finished, scans, failures, all_sensitive = {}, {}, {}, {}, []
    oracle = candidate = None; side = 'setup'; processes = []
    def interrupted(signum, frame): raise ScenarioFailure('interrupted')
    handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        for profile, side in ((profile, side) for profile in PROFILES
                for side in (('oracle',) if args.oracle_only else ('oracle', 'candidate'))):
            module = PROFILES[profile][0]
            observation_key = profile+'.'+side
            if side == 'oracle':
                oracle = start_oracle(free_port()); processes.append(oracle['process']); data_root = Path(oracle['root'])
                root_token = private_read(oracle['token_file']).decode().strip()
                client = SourceClient(oracle['address'], oracle['ca_file'], root_token)
                sensitive = [root_token, private_read(data_root/'unseal.key').decode().strip()]
                def restart():
                    stop_oracle(oracle); restart_oracle(oracle); processes.append(oracle['process'])
            else:
                candidate = Instance(binary, work/(profile+'-candidate'))
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
            trace = module.Trace(client); trace.sensitive.extend(sensitive)
            all_sensitive.append(trace.sensitive); cases[observation_key], finished[observation_key] = trace.rows, trace.finished
            module.run(trace, restart)
            if side == 'oracle': stop_oracle(oracle); oracle = None
            else: candidate.stop(); candidate = None
            scans[observation_key] = safe_files(data_root, trace.sensitive)
            if not scans[observation_key]: raise ScenarioFailure('secret_scan_failed')
    except Exception as error:
        failures[locals().get('observation_key', side)] = 'fixture_'+type(error).__name__
    finally:
        for label, stop in (('candidate', lambda: candidate.stop() if candidate is not None else None),
                            ('oracle', lambda: stop_oracle(oracle) if oracle is not None else None)):
            try: stop()
            except Exception as error: failures.setdefault(label, 'cleanup_'+type(error).__name__)
        if prior is None: os.environ.pop('HB_ORACLE_WORK_ROOT', None)
        else: os.environ['HB_ORACLE_WORK_ROOT'] = prior
        for sig, handler in handlers.items(): signal.signal(sig, handler)
    after = None; unchanged = oracle_unchanged = False
    try:
        after = source_identity(ROOT, binary) if before else None
        unchanged, oracle_unchanged = before_inputs == inputs(), bao_hash == file_hash(bao)
    except Exception as error: failures['postcheck'] = 'fixture_'+type(error).__name__
    equal = {profile: None if args.oracle_only else cases.get(profile+'.candidate') == cases.get(profile+'.oracle')
             for profile in PROFILES}
    expected_sides = {profile+'.'+side for profile in PROFILES
                      for side in (('oracle',) if args.oracle_only else ('oracle', 'candidate'))}
    matches = {name: complete(rows, finished.get(name), expected[name.split('.')[0]], name.split('.')[0])
               for name, rows in cases.items()}
    mismatch = {name: [row['case'] for row in expected[name.split('.')[0]] if not any(actual == row for actual in rows)]
                for name, rows in cases.items()}
    stopped = all(process.poll() is not None for process in processes)
    passed = (not failures and stopped and unchanged and oracle_unchanged and set(cases) == expected_sides
        and set(scans) == expected_sides and all(scans.values()) and all(matches.values())
        and (args.oracle_only or all(equal.values()) and before == after and not before['source_dirty'] and not after['source_dirty']))
    report = {'schema': 'heptabao.approle-secretid-metadata-comparison.v2', 'status': 'passed' if passed else 'failed',
        'cases': cases, 'completed_scenarios': finished,
        'batch_accessor_renew_not_called': True, 'processes_stopped': stopped, 'calibrated_cases_match': matches,
        'calibrated_case_mismatches': mismatch, 'cases_match': equal, 'failures': failures, 'secrets_absent': scans,
        'candidate_source': before, 'candidate_source_after': after,
        'source_and_binary_unchanged': before == after if before else None,
        'build_source_commit': args.build_source_commit, 'inputs_sha256': before_inputs, 'inputs_unchanged': unchanged,
        'oracle_binary_sha256': bao_hash, 'oracle_binary_unchanged': oracle_unchanged,
        'calibration_profiles': {name: {'receipt_sha256': values[2], 'runner_sha256': values[3],
            'named_scenarios': sorted(values[0].SCENARIOS)} for name, values in PROFILES.items()},
        'profiles_use_independent_fresh_instances': True, 'target_version': '2.6.2', 'oracle_only': args.oracle_only,
        'retained_failure_work_dir': None if passed else str(work), 'mutating_requests_retried': False,
        'SecretID_metadata_covered': passed, 'metadata_issuance_snapshots_covered': passed,
        'HA_covered': False, 'historical_upgrade_covered': False, 'full_openbao_compatibility': False,
        'not_covered': ['local-only SecretIDs', 'MFA', 'HA',
                        'token child delegation', 'maximum metadata size limits', 'supplementary custom/batch repetition'],
        'independent_qualification': False, 'production_authority': False}
    if any(secret in json.dumps(report) for values in all_sensitive for secret in values): raise ValueError('sensitive_report')
    if admit_output(output) != admitted: raise ValueError('output_parent_changed')
    private_write(output, report, replace=False)
    if passed: shutil.rmtree(work)
    print(json.dumps({'status': report['status'], 'cases': {k: len(v) for k, v in cases.items()}, 'failures': failures}))
    return int(not passed)


if __name__ == '__main__': raise SystemExit(main())
