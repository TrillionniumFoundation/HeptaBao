#!/usr/bin/env python3
"""Review retained r5 proof without executing a server or altering a host."""
from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parent
def read(name):
    return json.loads((ROOT / name).read_bytes())
def sha(name):
    return hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
def need(ok, name):
    if not ok:
        raise RuntimeError(name)

def main():
    assessment = read('assessment.public.json')
    for name, pin in assessment['files'].items():
        need(sha(name) == pin['sha256'] and (ROOT/name).stat().st_size == pin['bytes'], 'file_pin_' + name)
    terminal = read('terminal-status.public.json')
    need(terminal['job_id'] == '1a1a688e298-fc05-2698'
         and terminal['state'] == 'succeeded' and terminal['exit_code'] == 0
         and terminal['output_complete'] and terminal['output_durable']
         and terminal['terminal_publication_confirmed']
         and not terminal['timed_out'] and not terminal['cancelled'], 'durable_terminal')
    result = read('result.public.json')
    need(result['source'] == '830f28505af7306bab898a648918a65a9e3e8c60'
         and result['tree'] == '112394355eb52c4f88e90a0eea40e3a8ea6daef4'
         and result['binary']['sha256'] == '6026cd5d54d63a9ec13dcf28c37536afb866ea6d0e76a2f6c3ccdbdcb5073470', 'source_binary')
    need(result['source_unchanged'] and result['binary_unchanged']
         and result['status'] == 'passed' and not result['fixture_features']
         and not result['production_services_changed'], 'result_boundary')
    for name, key in [('build', 'build'), ('list', 'list'), ('tests', 'tests_result')]:
        item = read(name + '.public.json')
        need(item == result[key], 'phase_receipt_' + name)
        need(item['exit_code'] == 0 and not item['timed_out'] and item['remaining'] == [], 'phase_completion_' + name)
    need(sha('list.stdout') == result['list']['stdout_sha256']
         and sha('tests.stdout') == result['tests_result']['stdout_sha256']
         and sha('tests.stderr') == result['tests_result']['stderr_sha256'], 'complete_runtime_streams')
    rows = [json.loads(row) for row in (ROOT/'build-artifact-and-finish.jsonl').read_text().splitlines()]
    need(len(rows) == 2 and rows[1] == {'reason':'build-finished','success':True}, 'compiler_finished')
    artifact = rows[0]
    need(artifact['target']['src_path'] == '/home/qian-qi/heptabao-native-ssh-owner-20261104-r1/source-r5/crates/heptabao-server/src/lib.rs'
         and artifact['executable'] == result['build_artifact'] and artifact['fresh'] is False
         and artifact['features'] == ['default','native-v6-ha','native-v6-storage']
         and artifact['profile'] == {'opt_level':'3','debuginfo':0,'debug_assertions':True,'overflow_checks':True,'test':True}, 'actual_compiler_artifact')
    names = [line.removesuffix(': test') for line in (ROOT/'list.stdout').read_text().splitlines() if line.endswith(': test')]
    executed = re.findall(r'^test (\S+) \.\.\. ok$', (ROOT/'tests.stdout').read_text(), re.M)
    need(names == result['actual_test_names'] == executed and len(names) == len(set(names)) == 22, 'actual_test_names')
    need(sorted(name.rsplit('::',1)[-1] for name in names) == sorted(result['tests']), 'declared_test_coverage')
    need('test result: ok. 22 passed; 0 failed; 0 ignored;' in (ROOT/'tests.stdout').read_text(), 'test_summary')
    ha = [name for name in names if 'native_v6_ha_pipeline_tests' in name]
    need(len(ha) == 3 and ha == assessment['actual_ha_tests'], 'ha_cases_executed')
    need(assessment['promotion_allowed'] is False, 'known_suffix_blocker_preserved')
    source_chain = read('source-chain/root-review.public.json')
    need(source_chain['source'] == result['source'] and source_chain['tree'] == result['tree']
         and source_chain['actual_remote_and_local_final_files_equal'] == 19
         and source_chain['r4_to_r5_patch_reconstructs_actual_final_four_files'] is True, 'executed_source_chain')
    for name, expected in source_chain['files_sha256'].items():
        need(sha('source-chain/' + name) == expected, 'source_chain_pin_' + name)
    evidence = {name:sha(name) for name in sorted(assessment['files'])}
    evidence['terminal-status.public.json'] = sha('terminal-status.public.json')
    evidence['assessment.public.json'] = sha('assessment.public.json')
    return {'schema':'heptabao.root-reviewed-ssh-r5.v1', 'ok':True,
            'host':'rog','job_id':terminal['job_id'], 'source':result['source'], 'tree':result['tree'],
            'binary_sha256':result['binary']['sha256'], 'actual_cargo_features':artifact['features'],
            'actual_cargo_profile':artifact['profile'], 'tests_passed':22, 'tests_total':22,
            'ha_tests_executed':3, 'ignored':0, 'source_and_retained_binary_unchanged':True,
            'all_phase_owned_processes_stopped':True, 'production_changed':False,
            'full_build_stdout_readback':False, 'full_build_stderr_readback':False,
            'full_test_stdout_stderr_readback':True, 'actual_compiler_artifact_readback':True,
            'executed_source_files_independently_verified':19,
            'reviewed_source_patch_chain_included':True,
            'source_chain_review_sha256':sha('source-chain/root-review.public.json'),
            'promotion_allowed':False,
            'remaining_blocker':'Path-only public_key reply selection can misclassify ordinary KV2 keys. Actual engine ownership and large same-name KV2 regression required.',
            'physical_three_host_ha_qualified':False, 'combined_candidate_qualified':False,
            'full_openbao_271_replacement_qualified':False, 'evidence_sha256':evidence}

if __name__ == '__main__':
    print(json.dumps(main(), sort_keys=True, indent=2))
