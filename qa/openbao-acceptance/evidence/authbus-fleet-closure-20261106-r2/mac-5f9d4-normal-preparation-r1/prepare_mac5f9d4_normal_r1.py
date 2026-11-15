#!/usr/bin/env python3
"""Prepare only: original Mac normal107 plus fifteen separate directed tests."""
import ast
import copy
import difflib
import hashlib
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
BASE = HERE.parent / 'HeptaBao-current-924b/qa/openbao-acceptance/evidence/authbus-fleet-closure-20261106-r2/mac-4bde9-canonical'
ROOT = '/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1'
COMMIT = '5f9d4263b136685244aba93e45a69139cb8aba41'
TREE = '2c69f04159c112a883abe57f0d367a2627197c7a'
PARENT = '7d9e933d5ccab83d51c4de9ae7f028fe70e92302'
ORIGINAL = '4bde9aee03fcd27c59e13607e529b1cee594b249'
ORIGINAL_TREE = 'f08493a23f8ea0637073651231865ea9607b790e'
BUNDLE_SHA = 'e57a93e8f3c13f83259cc6f1a5ca1ddb2ebe8451a0da5ff677c38c83ee8d3d72'
BUNDLE_BYTES = 9985724
BUNDLE_PATH = ROOT + '/control/candidate-5f9d4-from-4bde9.bundle'
sha = lambda value: hashlib.sha256(value).hexdigest()

raw = (BASE / 'controller.original.py').read_bytes()
assert len(raw) == 32288 and sha(raw) == '76ab52614563287bdfe41cb9738c6992ae9360b3e34463c3b788701132a42d7c'
selection_raw = (BASE / 'test-selection.public.json').read_bytes()
assert len(selection_raw) == 46133 and sha(selection_raw) == '7da0b1e3efe257b66d31d50af7c1327a4d320c512c1c8f82df30020898c66595'
manifest = json.loads(selection_raw)
old = copy.deepcopy(manifest)
prior_result_raw = (BASE / 'result.public.json').read_bytes()
assert sha(prior_result_raw) == '90753d3b4f9b966c43d3e29919239f8d9aa879616c821a3d9ce0b6aa854054d6'
prior = json.loads(prior_result_raw)
assert prior['status'] == 'passed' and prior['source_commit'] == ORIGINAL
assert prior['source_tree'] == ORIGINAL_TREE and prior['passed_cases'] == 107
manifest.update(execution_source=ROOT + '/source-5f9d4-r1',
                execution_output=ROOT + '/build-test-5f9d4-r1',
                execution_source_commit=COMMIT, execution_source_tree=TREE,
                execution_source_parent=PARENT, status='prepared_not_executed')
manifest['source_clone'] = {'path': ROOT + '/source-4bde9-r1',
    'commit': ORIGINAL, 'tree': ORIGINAL_TREE, 'required_clean': True}
manifest['offline_source_bundle'] = {'path': BUNDLE_PATH, 'bytes': BUNDLE_BYTES,
    'sha256': BUNDLE_SHA, 'head': COMMIT,
    'prerequisites': [ORIGINAL, '09c14eae7a3b52dee8ce3af3175dad5900ac59ec']}
for name, value in prior['artifacts'].items():
    key = 'canonical-4bde9-' + name
    assert key not in manifest['old_retained_artifacts']
    manifest['old_retained_artifacts'][key] = copy.deepcopy(value)
directed_path = HERE.parent / 'x230-migration-checkpoint/pocket4-stream-hmac-49d3b-preparation-r1/directed15-selection.prepared.public.json'
directed_raw = directed_path.read_bytes()
directed = json.loads(directed_raw)
assert directed['sourceCommit'] == '49d3bb88f548d7647c44cefe21e5e7ab75a77fe9' and directed['sourceTree'] == 'ad35130626cbfa172dddfaffa1d09d081c7ff4dc'
assert directed['expectedCount'] == 15 and directed['newCases'] == 5 and directed['unchangedExistingCases'] == 10
names = directed['expectedCases']
assert len(names) == len(set(names)) == 15 and all(isinstance(name, str) for name in names)
original_names = [name for key in ('legacy_groups', 'legacy_additional_groups', 'added_groups')
                  for group in old[key] for name in group['tests']]
assert len(original_names) == len(set(original_names)) == 107 and not set(names).intersection(original_names)
manifest['candidate_groups'] = [{'label': 'candidate-stream-payload15', 'crate': 'heptabao-server',
    'default_features': True, 'additional_features': [], 'exact': True,
    'selection_mode': 'per-test-exact', 'expected_count': 15, 'tests': names,
    'argv_suffixes': [[name, '--exact', '--nocapture', '--test-threads=1'] for name in names],
    'runtime_seconds': 600, 'test_threads': 1,
    'runtime_budget_scope': 'whole-group-not-renewed-per-test-and-within-original-8280-parent'}]
manifest['candidate_denominators'] = {'separate_directed_cases': 15, 'new_candidate_regressions': 5,
    'unchanged_hmac_and_memo_cases': 10, 'original_normal_compatibility': 107, 'combined_disjoint_cases': 122}
manifest['candidate_provenance'] = {'prior_qualified_source': ORIGINAL,
    'prior_controller_sha256': sha(raw), 'prior_selection_sha256': sha(selection_raw),
    'prior_result_sha256': sha(prior_result_raw),
    'original_107_names_and_commands_preserved': True,
    'original_budgets_features_environment_and_custody_preserved': True,
    'prior_results_do_not_qualify_current_source': True,
    'directed15_reported_separately': True,
    'same_directed_names_as_linux_preparation_sha256': sha(directed_raw),
    'directed_names_basis_commit': directed['sourceCommit'],
    'formatter_successor_runtime_must_enumerate_exact_same_fifteen_names': True,
    'old_canonical_four_artifacts_preserved_before_and_after_cache_reuse': True}
for key in ('legacy_groups', 'legacy_additional_groups', 'added_groups', 'denominators',
            'original_build', 'original_budgets', 'build_examples'):
    assert manifest[key] == old[key]
selection = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
(HERE / 'test-selection.public.json').write_bytes(selection)
source = raw.decode()


def assignment(name, expression):
    global source
    pattern = r'^' + re.escape(name) + r' = .*$'
    assert len(re.findall(pattern, source, re.MULTILINE)) == 1, name
    source = re.sub(pattern, lambda _match: name + ' = ' + expression, source, flags=re.MULTILINE)


def change(before, after):
    global source
    assert source.count(before) == 1, (before[:100], source.count(before))
    source = source.replace(before, after)


for name, expression in {
    'SOURCE': "ROOT / 'source-5f9d4-r1'", 'CLONE_SOURCE': "ROOT / 'source-4bde9-r1'",
    'CLONE_HEAD': repr(ORIGINAL), 'CLONE_TREE': repr(ORIGINAL_TREE),
    'OUT': "ROOT / 'build-test-5f9d4-r1'", 'COMMIT': repr(COMMIT), 'TREE': repr(TREE),
    'PARENT': repr(PARENT), 'BUNDLE_SHA': repr(BUNDLE_SHA),
    'BUNDLE': "ROOT / 'control/candidate-5f9d4-from-4bde9.bundle'",
    'SELECTION_SHA': repr(sha(selection)),
}.items():
    assignment(name, expression)
change("'steps': [], 'artifacts': {}, 'groups': [], 'enumeration': {},",
       "'steps': [], 'artifacts': {}, 'groups': [], 'enumeration': {},\n"
       "    'candidate_groups': [], 'candidate_enumeration': {},\n"
       "    'expected_candidate_regressions': 15, 'candidate_regressions_qualified': False,")
change('def execute_group(index, group, binary):',
       "def execute_group(index, group, binary, *, collection='groups'):")
change("    REPORT['groups'].append(row); checkpoint()",
       "    need(collection in ('groups', 'candidate_groups'), 'fixed_test_result_collection')\n"
       "    REPORT[collection].append(row); checkpoint()")
change("    need(all(g['runtime_seconds'] == 600 for g in groups), 'original_group_budgets')",
       "    need(all(g['runtime_seconds'] == 600 for g in groups), 'original_group_budgets')\n"
       "    candidate_groups = MANIFEST['candidate_groups']\n"
       "    candidate_names = [name for group in candidate_groups for name in group['tests']]\n"
       "    need(len(candidate_groups) == 1 and len(candidate_names) == len(set(candidate_names)) == 15\n"
       "         and not set(candidate_names).intersection(names), 'fifteen_disjoint_directed_candidate_tests')\n"
       "    need(all(g['runtime_seconds'] == 600 and g['crate'] == 'heptabao-server'\n"
       "         and g['selection_mode'] == 'per-test-exact' and g['default_features'] is True\n"
       "         and g['additional_features'] == [] for g in candidate_groups), 'candidate_original_profile_and_budget')")
change("BUNDLE.stat().st_size == 1393", "BUNDLE.stat().st_size == 9985724")
change("        REPORT['enumeration'][group['label']] = {'matched_names': sorted(selected), 'matched_count': len(selected)}\n    checkpoint()",
       "        REPORT['enumeration'][group['label']] = {'matched_names': sorted(selected), 'matched_count': len(selected)}\n"
       "    for group in candidate_groups:\n"
       "        expected = set(group['tests']); selected = all_names[group['crate']].intersection(expected)\n"
       "        need(selected == expected and len(selected) == group['expected_count'], 'candidate_exact_enumeration')\n"
       "        REPORT['candidate_enumeration'][group['label']] = {'matched_names': sorted(selected), 'matched_count': len(selected)}\n"
       "    checkpoint()")
change("    need(sum(g['passed'] for g in REPORT['groups']) == 107, 'final107')",
       "    need(sum(g['passed'] for g in REPORT['groups']) == 107, 'final107')\n"
       "    for index, group in enumerate(candidate_groups, start=len(groups)):\n"
       "        execute_group(index, group, binaries[group['crate']], collection='candidate_groups')\n"
       "    need(sum(g['passed'] for g in REPORT['candidate_groups']) == 15, 'candidate_final15')\n"
       "    REPORT['candidate_regressions_qualified'] = True")
change("        REPORT['unexecuted_or_ignored_required_cases'] = 107 - REPORT['observed_test_executed_cases']",
       "        REPORT['unexecuted_or_ignored_required_cases'] = 107 - REPORT['observed_test_executed_cases']\n"
       "        candidate_observed = [r for g in REPORT['candidate_groups'] for r in g['results']]\n"
       "        REPORT['candidate_passed_cases'] = sum(r['passed'] for r in candidate_observed)\n"
       "        REPORT['candidate_failed_cases'] = sum(r['failed'] for r in candidate_observed)\n"
       "        REPORT['candidate_ignored_cases'] = sum(r['ignored'] for r in candidate_observed)\n"
       "        REPORT['candidate_not_qualified_cases'] = 15 - sum(g['passed'] for g in REPORT['candidate_groups'])\n"
       "        REPORT['combined_disjoint_observed_passed_cases'] = REPORT['observed_test_passed_cases'] + REPORT['candidate_passed_cases']")
ast.parse(source)
before_nodes = {node.name: node for node in ast.parse(raw).body if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
after_nodes = {node.name: node for node in ast.parse(source).body if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
assert set(before_nodes) == set(after_nodes)
changed = [name for name in before_nodes if ast.dump(before_nodes[name], include_attributes=False)
           != ast.dump(after_nodes[name], include_attributes=False)]
assert set(changed) == {'main', 'execute_group'}, changed
(HERE / 'controller5f9d4.original.py').write_text(source)
(HERE / 'controller-4bde9-to-5f9d4.diff').write_text(''.join(difflib.unified_diff(
    raw.decode().splitlines(True), source.splitlines(True), fromfile='actual-mac-4bde9-controller',
    tofile='prepared-mac-5f9d4-controller')))
plan = {'schema': 'heptabao.mac5f9d4-normal-source-preparation.r1', 'executed': False,
    'commit': COMMIT, 'tree': TREE, 'parent': PARENT,
    'controller': {'bytes': len(source.encode()), 'sha256': sha(source.encode())},
    'selection': {'bytes': len(selection), 'sha256': sha(selection)},
    'originalController': {'bytes': len(raw), 'sha256': sha(raw)},
    'originalSelection': {'bytes': len(selection_raw), 'sha256': sha(selection_raw)},
    'changedFunctionDefinitions': changed, 'allOtherOriginalFunctionAstsUnchanged': True,
    'sourceClone': manifest['source_clone'], 'bundle': manifest['offline_source_bundle'],
    'output': ROOT + '/build-test-5f9d4-r1',
    'originalNormalCases': 107, 'directedCases': 15, 'newCandidateCases': 5,
    'unchangedDirectedHmacAndMemoCases': 10, 'combinedDisjointCases': 122,
    'linuxDirectedSelectionSha256': sha(directed_raw),
    'normal107OriginalNamesCommandsAndDenominatorUnchanged': True,
    'candidateCasesReportedSeparately': True, 'originalOuterSeconds': 8280,
    'originalEachBuildSeconds': 1800, 'originalEachGroupSeconds': 600,
    'originalMacSourceAndTargetCacheCustodyUnchanged': True,
    'oldRetainedArtifactCount': len(manifest['old_retained_artifacts']),
    'normalNoFixtureFeatures': True, 'noProductionServiceStart': True,
    'noCurrentCredentials': True, 'fullReplacementQualified': False}
(HERE / 'preparation.public.json').write_text(json.dumps(plan, indent=2) + '\n')
print(json.dumps(plan, sort_keys=True))
