#!/usr/bin/env python3
"""Check the retained original Mac 107 receipt, selection and supervisor output.

This checks captured evidence. Actual executable hashing remains the original
source-bound controller's recorded observation; no local binaries are invented.
"""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parent
PINS = {
    'result.public.json': '90753d3b4f9b966c43d3e29919239f8d9aa879616c821a3d9ce0b6aa854054d6',
    'test-selection.public.json': '7da0b1e3efe257b66d31d50af7c1327a4d320c512c1c8f82df30020898c66595',
    'controller.original.py': '76ab52614563287bdfe41cb9738c6992ae9360b3e34463c3b788701132a42d7c',
    'runtime-terminal.original.json': '76ec986884fc99d3bf96123ece9f361d21302a36af5b4ed2bd75f757a023c148',
    'runtime-stdout.original': 'e0f9b92fdf7dcb5f5b7f641ec8f66755d5aac4b9a4be4f57774332230ed585fd',
}

def main():
    for name, digest in PINS.items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest, name
    receipt = json.loads((ROOT / 'result.public.json').read_bytes())
    selection = json.loads((ROOT / 'test-selection.public.json').read_bytes())
    terminal = json.loads((ROOT / 'runtime-terminal.original.json').read_bytes())
    commit = '4bde9aee03fcd27c59e13607e529b1cee594b249'
    tree = 'f08493a23f8ea0637073651231865ea9607b790e'
    assert receipt['source_commit'] == selection['execution_source_commit'] == commit
    assert receipt['source_tree'] == selection['execution_source_tree'] == tree
    assert receipt['selection_sha256'] == PINS['test-selection.public.json']
    assert receipt['controller_sha256'] == PINS['controller.original.py']
    assert receipt['status'] == 'passed' and receipt['failure'] is None
    assert receipt['passed_cases'] == receipt['executed_passed_cases'] == 107
    assert receipt['observed_test_passed_cases'] == receipt['observed_test_executed_cases'] == 107
    assert receipt['observed_test_failed_cases'] == receipt['observed_test_ignored_cases'] == 0
    assert receipt['not_qualified_cases'] == receipt['unexecuted_or_ignored_required_cases'] == 0
    assert receipt['source_and_artifacts_unchanged'] and receipt['all_owned_processes_gone']
    expected = selection['legacy_groups'] + selection['legacy_additional_groups'] + selection['added_groups']
    names = [name for group in expected for name in group['tests']]
    assert len(names) == len(set(names)) == 107
    assert sum(len(g['tests']) for g in expected if g['crate'] == 'heptabao-server') == 90
    assert sum(len(g['tests']) for g in expected if g['crate'] == 'heptabao-ha-service') == 17
    assert len(receipt['groups']) == len(expected)
    groups = []
    for actual, wanted in zip(receipt['groups'], expected):
        assert actual['label'] == wanted['label'] and actual['crate'] == wanted['crate']
        assert actual['tests'] == wanted['tests']
        assert actual['status'] == 'passed'
        assert actual['passed'] == actual['expected_count'] == wanted['expected_count'] == len(wanted['tests'])
        assert actual['original_group_budget_seconds'] == wanted['runtime_seconds'] == 600
        assert actual['budget_renewed_per_case'] is False
        enumeration = receipt['enumeration'][wanted['label']]
        assert enumeration['matched_names'] == sorted(wanted['tests'])
        assert enumeration['matched_count'] == len(wanted['tests'])
        assert sum(r['passed'] for r in actual['results']) == wanted['expected_count']
        for result in actual['results']:
            assert result['reported_state'] == 'ok' and result['exact_denominator_passed'] is True
            assert result['failed'] == result['ignored'] == result['measured'] == 0
        groups.append({'group': wanted['label'], 'passed': actual['passed']})
    for artifact in receipt['artifacts'].values():
        assert artifact['source_commit'] == commit and artifact['source_tree'] == tree
        assert artifact['normal_features_profile_and_source_verified'] is True
    assert terminal['job_id'] == '1a1b116ba98-fc05-75a6'
    assert terminal['state'] == 'succeeded' and terminal['exit_code'] == 0
    assert terminal['timed_out'] is False and terminal['cancelled'] is False
    assert terminal['output_complete'] and terminal['output_durable'] and terminal['terminal_publication_confirmed']
    assert terminal['automatic_retry'] is False
    assert not any(terminal['log_truncated'].values())
    assert terminal['log_bytes']['stdout']['seen'] == terminal['log_bytes']['stdout']['stored'] == (ROOT / 'runtime-stdout.original').stat().st_size == 19702
    assert terminal['log_bytes']['stderr']['seen'] == terminal['log_bytes']['stderr']['stored'] == 0
    last = json.loads((ROOT / 'runtime-stdout.original').read_text().splitlines()[-1])
    assert last['event'] == 'terminal' and last['status'] == 'passed' and last['failure'] is None
    assert last['executed_passed_cases'] == 107
    for key in ('production_changed', 'production_server_started', 'formal_kv2_qualified',
                'physical_ha_qualified', 'authbus_migration_qualified', 'full_replacement_qualified'):
        assert receipt[key] is False
    print(json.dumps({'schema': 'heptabao.mac-107-retained-evidence-check.v1',
        'ok': True, 'source_commit': commit, 'source_tree': tree,
        'job_id': terminal['job_id'], 'actual_passed': 107, 'failed': 0,
        'ignored': 0, 'unexecuted': 0, 'groups': groups,
        'elapsed_seconds': receipt['elapsed_seconds'],
        'artifact_hash_validation_origin': 'original source-bound Mac build controller',
        'binaries_rehashed_by_this_offline_check': False,
        'full_replacement_qualified': False}, sort_keys=True))

if __name__ == '__main__':
    main()
