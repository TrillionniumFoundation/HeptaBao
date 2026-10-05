#!/usr/bin/env python3
"""Source admission and independently bound eight-entry mechanical receipts."""
from __future__ import annotations
import argparse
import copy
import json
import re
import subprocess
from pathlib import Path

import h02_dependency_probe_v2 as probe
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = '.github/workflows/h02-probe-sbom-msrv-v2.yml'
SCHEMA = 'schemas/heptabao_dependency_probe_evidence_v2.schema.json'
TRIGGERS = [WORKFLOW, probe.PLAN, probe.LEGACY_PLAN, probe.FULL_CONTRACT,
            'scripts/h02_dependency_probe_v2.py', 'scripts/validate_h02_dependency_probe_v2.py',
            'scripts/h02_dependency_probe_v1.py', 'scripts/h02_openraft_fault_lab_evidence_v2.py',
            'scripts/h02_linearizability_checker_v1.py', 'scripts/yaml12_loader.py',
            SCHEMA, 'schemas/heptabao_dependency_probe_evidence_v1.schema.json',
            'tests/platform/test_h02_dependency_probe_v2.py', 'tests/platform/test_h02_dependency_probe_v1.py',
            'tests/platform/fixtures/h02_mechanical_hosted_37247651462.json',
            'probes/h02/**', 'requirements-plan.txt', 'scripts/validate_workflow_trust.py',
            'scripts/validate_workflow_trust_v1.py', 'scripts/workflow_trust_v2.py',
            'scripts/workflow_trust_action_registry_v2.json', 'scripts/validate_acceptance_immutability.py']


def source_contract():
    probe.legacy.validate_matrix(ROOT / probe.LEGACY_PLAN, ROOT)
    plan = probe.legacy.load_yaml(ROOT / probe.PLAN)
    probe.require(plan == {'schema': 'heptabao.h02-candidate-probe-matrix.v2', 'execution_profile_id': probe.PROFILE,
                          'status': 'SPECIFIED_UNEXECUTED', 'qualification': False, 'selection_effect': 'NONE', 'authority_effect': 'NONE',
                          'profiles': list(probe.profiles().values()), 'entry_count': 8,
                          'graph_policy': {'tokio': 'GENERATE_REAL_LOCK_ONCE_THEN_LOCKED', 'rustls': 'COMMITTED_LOCK_UNCHANGED', 'openraft': 'COMMITTED_LOCK_UNCHANGED'},
                          'behavioral_cases': 'UNEXECUTED', 'exact_head_remote_executions': 0,
                          'graph_scope': 'ALL_TARGET_ENABLED_NORMAL_BUILD_OBSERVATION',
                          'feature_artifact_kind': 'RESOLVED_PACKAGE_FEATURE_PROJECTION',
                          'root_dev_dependencies': 'UNSUPPORTED_IN_THIS_PROFILE'}, 'successor plan drift')
    probe.require(len(probe.entries()) == 8, 'entry count')
    expected_full_contract = {'schema': 'heptabao.h02-openraft-full-probe-profile.v1', 'profile_id': 'HB-H02-PROBE-OPENRAFT-TOKIO-FULL-CURRENT-V1', 'historical_minimal_profile_id': 'HB-H02-PROBE-OPENRAFT-TOKIO', 'execution_scope': 'FULL_COMMITTED_PROBE_WITH_TEST_MEMSTORE', 'expected_resolved_features': ['clap', 'default', 'serde', 'tokio-rt', 'type-alias'], 'forbidden_resolved_features': ['runtime-stats'], 'direct_openraft_dependency': {'default_features': False, 'features': ['serde', 'tokio-rt', 'type-alias']}, 'feature_chain': {'support_package': 'openraft-memstore', 'support_version': '0.10.0-alpha.33', 'candidate_dependency_default_features': True, 'candidate_dependency_features': ['serde', 'type-alias'], 'candidate_default_features': ['tokio-rt', 'clap']}, 'historical_effect': 'NONE_OLD_MINIMAL_PROHIBITION_AND_FAILED_RECEIPTS_RETAINED', 'qualification': False, 'selection_effect': 'NONE', 'authority_effect': 'NONE'}
    probe.require(probe.legacy.load_yaml(ROOT / probe.FULL_CONTRACT) == expected_full_contract, 'explicit full-probe contract drift')
    minimal = probe.minimal_profiles()['HB-H02-PROBE-OPENRAFT-TOKIO']
    probe.require(minimal['forbidden_feature_expansion'] == ['clap', 'runtime-stats'], 'historical minimal prohibition changed')
    probe.require(probe.profile_digest(probe.profiles()[probe.FULL_PROFILE]) != probe.profile_digest(minimal), 'full/minimal digest collision')
    for item in probe.profiles().values():
        expected = ['1.88.0', '1.99.0'] if item['package'] == 'openraft' else ['1.71.0', '1.99.0']
        probe.require(item['probe_toolchains'] == expected, 'floor/current compiler drift')
        probe.legacy.validate_manifest(item, ROOT)
        old = probe.legacy.profiles(probe.legacy.load_yaml(ROOT / probe.LEGACY_PLAN))[item.get('historical_minimal_profile_id', item['profile_id'])]
        probe.require(probe.legacy.profile_digest(old) != probe.profile_digest(item), 'reused historical profile digest')
        lock = ROOT / Path(item['probe_manifest']).with_name('Cargo.lock')
        probe.require(lock.is_file() == (item['package'] != 'tokio'), 'committed/generated graph policy drift')
    schema = probe.read(ROOT / SCHEMA); Draft202012Validator.check_schema(schema)
    probe.require(schema['properties']['schema'] == {'const': probe.SCHEMA}, 'schema identity')
    for key, value in [('qualification', False), ('selection_effect', 'NONE'), ('authority_effect', 'NONE')]:
        probe.require(schema['properties'][key] == {'const': value}, 'schema authority')
    import validate_workflow_trust as trust
    import validate_workflow_trust_v1 as yaml_parser
    text = (ROOT / WORKFLOW).read_text(); trust.validate_text(text, Path(WORKFLOW).name)
    workflow = yaml_parser.parse_workflow(text)
    probe.require(workflow['on'] == {'workflow_dispatch': None, 'pull_request': {'paths': TRIGGERS}}, 'scoped admission drift')
    probe.require(workflow['permissions'] == {'contents': 'read'}, 'workflow privilege drift')
    probe.require(set(workflow['jobs']) == {'validate-plan', 'mechanical'}, 'workflow jobs drift')
    job = workflow['jobs']['mechanical']
    probe.require(job['needs'] == 'validate-plan' and 'strategy' not in job, 'serial admission drift')
    # Source-validated fixed execution inputs; compare complete runner/validator steps.
    for step in [s for j in workflow['jobs'].values() for s in j['steps']]:
        if 'run' in step: subprocess.run(['bash', '-n'], input=step['run'], text=True, capture_output=True, check=True)
        if step.get('uses', '').startswith('actions/checkout@'):
            probe.require(step['with'] == {'ref': '${{ github.event.pull_request.head.sha || github.sha }}', 'fetch-depth': 0, 'persist-credentials': False}, 'checkout binding')
    for index, expected in EXECUTION_STEPS.items():
        probe.require(job['steps'][index] == expected, 'execution step drift: ' + str(index))
    return 8


def validate(evidence, execution, producer_source, source_commit, source_tree, run_id, attempt, runner, *, require_pass=False, runtime_base=None):
    probe.require(re.fullmatch(r'[a-f0-9]{40}', source_commit) and re.fullmatch(r'[a-f0-9]{40}', source_tree), 'expected source identity')
    probe.require(all(p.is_absolute() for p in [evidence, execution, producer_source]), 'absolute roots required')
    probe.require(evidence.is_dir() and not evidence.is_symlink(), 'invalid evidence root')
    probe.require({p.name for p in evidence.iterdir()} == set(probe.entries()), 'missing/extra/duplicate entries')
    base = probe.common.runtime_base_environment() if runtime_base is None else runtime_base
    schema = Draft202012Validator(probe.read(ROOT / SCHEMA))
    for name, (item, compiler) in probe.entries().items():
        entry = evidence / name
        probe.require(entry.is_dir() and not entry.is_symlink(), 'invalid entry directory')
        source = {'repository': 'TrillionniumFoundation/HeptaBao', 'commit': source_commit, 'tree': source_tree, 'clean_tree': True,
                  'manifest_sha256': probe.file_sha(ROOT / item['probe_manifest']),
                  'committed_lock_sha256': probe.file_sha(ROOT / Path(item['probe_manifest']).with_name('Cargo.lock'))}
        expected = probe.context(item, compiler, execution / name / 'probe', source, run_id, attempt, runner, base, producer_source)
        ctx = probe.read(entry / 'execution-context.json')
        for key in ('source_after', 'return_codes', 'configuration_checks', 'lock_before_sha256', 'lock_after_sha256', 'setup_error', 'package_error'):
            expected[key] = ctx[key]
        probe.require(probe.canonical(expected) == probe.canonical(ctx), 'independent context binding mismatch')
        codes, checks = ctx['return_codes'], ctx['configuration_checks']
        probe.require(set(codes) == set(checks) == set(probe.STAGES), 'stage set drift')
        for stage, code in codes.items():
            probe.require(code is None or type(code) is int and 0 <= code <= 255, 'invalid stage code')
            if ctx['argv'][stage] is None:
                probe.require(code is None and checks[stage] is None, 'committed lock claimed generation')
            elif code is None:
                probe.require(checks[stage] is None, 'unexecuted stage claimed config check')
            else:
                probe.require(isinstance(checks[stage], dict) and set(checks[stage]) == {'before', 'after'} and all(type(x) is bool for x in checks[stage].values()), 'invalid config checks')
        for key in ('setup_error', 'package_error'):
            probe.require(ctx[key] is None or isinstance(ctx[key], str) and bool(ctx[key]), 'invalid error diagnostic')
        probe.require(ctx['setup_error'] is None or all(v is None for v in codes.values()), 'stages after setup failure')
        allowed = {'Cargo.toml', 'Cargo.lock', 'package.crate', 'execution-context.json', 'evidence.json'}
        allowed |= {stage + '.' + suffix for stage in probe.STAGES if ctx['argv'][stage] is not None for suffix in ('stdout', 'stderr')}
        probe.require({p.name for p in entry.iterdir()} <= allowed, 'unexpected artifact')
        value = probe.read(entry / 'evidence.json'); schema.validate(value)
        probe.require(probe.canonical(value) == probe.canonical(probe.collect(entry, ctx, item)), 'receipt/raw artifact mismatch')
        if require_pass: probe.require(value['mechanical_status'] == 'EXECUTED_PASS', name + ': ' + str(value['problems']))


EXECUTION_STEPS = {3: {'name': 'Install exact compilers and retain failures',
     'shell': 'bash',
     'run': 'set -u\n'
            'mkdir -p "$RUNNER_TEMP/h02-mechanical-v2-setup"\n'
            'for compiler in 1.71.0 1.88.0 1.99.0; do\n'
            '  rc=0\n'
            '  rustup toolchain install "$compiler" --profile minimal '
            '>"$RUNNER_TEMP/h02-mechanical-v2-setup/$compiler.log" 2>&1 || '
            'rc=$?\n'
            '  printf \'%s\\n\' "$rc" '
            '>"$RUNNER_TEMP/h02-mechanical-v2-setup/$compiler.exit"\n'
            'done\n'
            'exit 0\n'},
 4: {'name': 'Execute all eight real mechanical probes serially',
     'if': '${{ always() }}',
     'shell': 'bash',
     'run': 'set -euo pipefail\n'
            'python scripts/h02_dependency_probe_v2.py \\\n'
            '  --source-root "$GITHUB_WORKSPACE" \\\n'
            '  --expected-commit "${{ github.event.pull_request.head.sha || '
            'github.sha }}" \\\n'
            '  --evidence-root "$RUNNER_TEMP/h02-mechanical-v2-evidence" \\\n'
            '  --execution-root "$RUNNER_TEMP/h02-mechanical-v2-work" \\\n'
            '  --run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT" '
            '--runner-name "$RUNNER_NAME"\n'},
 5: {'name': 'Verify retained receipts and raw artifacts',
     'if': '${{ always() }}',
     'shell': 'bash',
     'run': 'set -euo pipefail\n'
            'python scripts/validate_h02_dependency_probe_v2.py \\\n'
            '  --evidence-root "$RUNNER_TEMP/h02-mechanical-v2-evidence" \\\n'
            '  --execution-root "$RUNNER_TEMP/h02-mechanical-v2-work" \\\n'
            '  --producer-source-root "$GITHUB_WORKSPACE" \\\n'
            '  --source-commit "$(git rev-parse HEAD)" --source-tree "$(git '
            'rev-parse \'HEAD^{tree}\')" \\\n'
            '  --run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT" '
            '--runner-name "$RUNNER_NAME"\n'},
 6: {'name': 'Retain all outcomes before final gate',
     'if': '${{ always() }}',
     'uses': 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a',
     'with': {'name': 'h02-mechanical-v2-${{ github.run_id }}-${{ '
                      'github.run_attempt }}',
              'path': '${{ runner.temp }}/h02-mechanical-v2-evidence/\n'
                      '${{ runner.temp }}/h02-mechanical-v2-setup/\n',
              'if-no-files-found': 'error',
              'retention-days': 30}},
 7: {'name': 'Require mechanical passes without behavioral qualification',
     'if': '${{ always() }}',
     'shell': 'bash',
     'run': 'set -euo pipefail\n'
            'python scripts/validate_h02_dependency_probe_v2.py \\\n'
            '  --evidence-root "$RUNNER_TEMP/h02-mechanical-v2-evidence" \\\n'
            '  --execution-root "$RUNNER_TEMP/h02-mechanical-v2-work" \\\n'
            '  --producer-source-root "$GITHUB_WORKSPACE" \\\n'
            '  --source-commit "$(git rev-parse HEAD)" --source-tree "$(git '
            'rev-parse \'HEAD^{tree}\')" \\\n'
            '  --run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT" '
            '--runner-name "$RUNNER_NAME" \\\n'
            '  --require-pass\n'}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('evidence-root', 'execution-root', 'producer-source-root'): parser.add_argument('--' + name, type=Path)
    for name in ('source-commit', 'source-tree', 'run-id', 'run-attempt', 'runner-name', 'runtime-path', 'runtime-rustup-home'): parser.add_argument('--' + name)
    parser.add_argument('--require-pass', action='store_true')
    args = parser.parse_args(); source_contract()
    if args.evidence_root:
        probe.require(all((args.execution_root, args.producer_source_root, args.source_commit, args.source_tree, args.run_id, args.run_attempt, args.runner_name)), 'missing independent expected inputs')
        probe.require(bool(args.runtime_path) == bool(args.runtime_rustup_home), 'both independently supplied runtime inputs required')
        base = {'PATH': args.runtime_path, 'RUSTUP_HOME': args.runtime_rustup_home} if args.runtime_path else None
        validate(args.evidence_root, args.execution_root, args.producer_source_root, args.source_commit, args.source_tree, args.run_id, args.run_attempt, args.runner_name, require_pass=args.require_pass, runtime_base=base)
    print('H02 mechanical V2 validated; qualification=false authority=NONE')
    return 0

if __name__ == '__main__': raise SystemExit(main())
