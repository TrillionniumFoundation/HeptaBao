import ast
import copy
import hashlib
import json
from pathlib import Path
import re
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
rows = []


def check(name, condition):
    assert condition, name
    rows.append({'check': name, 'passed': True})


def read(path):
    return (ROOT / path).read_text()


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def git_blob(text):
    value = text.encode()
    return hashlib.sha1(b'blob ' + str(len(value)).encode() + b'\0' + value).hexdigest()


def strict_apply(before, delta):
    old = before.splitlines(keepends=True)
    diff = delta.splitlines(keepends=True)
    check('unified_diff_headers', len(diff) >= 2 and diff[0].startswith('--- ') and diff[1].startswith('+++ '))
    result, cursor, index, hunks = [], 0, 2, 0
    while index < len(diff):
        match = re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n', diff[index])
        assert match, diff[index]
        old_start, old_count = int(match[1]), int(match[2] or '1')
        new_start, new_count = int(match[3]), int(match[4] or '1')
        position = old_start - 1 if old_count else old_start
        assert cursor <= position <= len(old)
        result.extend(old[cursor:position]); cursor = position
        assert len(result) == (new_start - 1 if new_count else new_start)
        taken, added = 0, 0
        index += 1; hunks += 1
        while index < len(diff) and not diff[index].startswith('@@ '):
            line = diff[index]; sign, body = line[0], line[1:]
            assert sign in ' +-'
            if sign in ' -':
                assert cursor < len(old) and old[cursor] == body
                cursor += 1; taken += 1
            if sign in ' +':
                result.append(body); added += 1
            index += 1
        assert (taken, added) == (old_count, new_count)
    result.extend(old[cursor:])
    return ''.join(result), hunks


old = read('reference/phaseb_binding_df026.py')
new = read('candidate/phaseb_binding_r3.py')
check('old_exact_blob', git_blob(old) == 'f60dbb093d69641bc8cd4a367320ec6fc5bdc0fd')
changes = json.loads(read('review/transformations.public.json'))
inverse = new
for edit in reversed(changes['binder']):
    check('inverse_unique_' + edit['label'], inverse.count(edit['after']) == edit['count'])
    inverse = inverse.replace(edit['after'], edit['before'])
check('binder_inverse_whole_exact', inverse == old)
rebuilt, binder_hunks = strict_apply(old, read('review/binding.review.diff'))
check('binder_strict_whole_diff', rebuilt == new)

template_paths = [
    ('binding/partial-binding.private.json', 'reference/partial-binding.df026.private.json', 'review/binding-template.review.diff'),
    ('dispatch/requests.template.json', 'reference/requests.df026.template.json', 'review/dispatch-template.review.diff'),
]
template_hunks = {}
for after_path, before_path, diff_path in template_paths:
    after, before = read(after_path), read(before_path)
    rebuilt, count = strict_apply(before, read(diff_path))
    check('strict_whole_' + after_path, rebuilt == after)
    template_hunks[after_path] = count
    inverse = after
    for edit in reversed(changes['templates'][after_path]):
        check('template_inverse_unique_' + after_path + ':' + edit['label'], inverse.count(edit['after']) == edit['count'])
        inverse = inverse.replace(edit['after'], edit['before'])
    check('template_inverse_whole_' + after_path, inverse == before)

old_ast, new_ast = ast.parse(old), ast.parse(new)


def definitions(text, tree):
    lines = text.splitlines(keepends=True)
    result = {}
    for item in tree.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            result[item.name] = ''.join(lines[item.lineno - 1:item.end_lineno])
        if isinstance(item, ast.ClassDef):
            for node in item.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    result[item.name + '.' + node.name] = ''.join(lines[node.lineno - 1:node.end_lineno])
    return result


old_defs, new_defs = definitions(old, old_ast), definitions(new, new_ast)
check('all_definition_names_unchanged', set(old_defs) == set(new_defs))
unchanged = []
for name in old_defs:
    if name not in ('Binding.__init__', 'Binding.verify'):
        check('definition_whole_unchanged_' + name, old_defs[name] == new_defs[name])
        unchanged.append(name)
check('constructor_only_source_namespace',
      old_defs['Binding.__init__'].replace('normal-cold-h2-validation-source-r[0-9]+',
      'normal-same-root-publication-validation-source-r[0-9]+') == new_defs['Binding.__init__'])

base_manifest = json.loads(read('reference/base-manifest.public.json'))
retained_expected = {
    'phaseb_controller_r3.py': ('03497f1ee45be3228de99ab4872ae2f9ca869de0', 61210, '10816d06fd5ad59175872ccb7db1337d7677e92405a26a7ab1cae2796ee0a86c'),
    'phaseb_evidence_r3.py': ('e507fef5b87305f4b8e8a0d729aecec6da284bed', 15201, '4fb452f9eabbbc9f66913e0b824f7f3db5b2a75848b2adf4186e76078f2c9024'),
    'native_fixture_reference_r8.py': ('7e465b3ea72814726ed2e01355ab91412190a747', 68149, 'a0bac9972fbb9d65ed3edf537f732a08b5177864516b33ada0a6e98c4c6a0416'),
    'official_cli_reference_r4.py': ('4a4a60d1d52a0fd835b467f1e4687ee95314d1de', 46586, '18318841d3538e60fddf951708055a206402f5bf1ecdacc2bfceabec4f998dd9'),
}
for name, expected in retained_expected.items():
    body = read('candidate/' + name)
    check('retained_source_exact_' + name, (git_blob(body), len(body.encode()), sha(body)) == expected)
for name in ('phaseb_binding_r3.py', *retained_expected):
    compile(read('candidate/' + name), 'candidate/' + name, 'exec')
    check('whole_module_compile_only_' + name, True)

constants = {}
for item in new_ast.body:
    if isinstance(item, ast.Assign) and len(item.targets) == 1 and isinstance(item.targets[0], ast.Name):
        name = item.targets[0].id
        if name in {'COMMIT', 'TREE', 'OBSERVER_PATH', 'PRODUCT_PINS', 'BUDGETS', 'API_PORTS',
                    'SCHEMA', 'FEATURES', 'PROFILE', 'GROUPS_SHA', 'INGRESS_OBSERVER_TESTS',
                    'COLD_H2_TESTS', 'SAME_ROOT_PUBLICATION_TESTS'}:
            constants[name] = eval(compile(ast.Expression(item.value), '<literal-constants>', 'eval'),
                                   {'__builtins__': {}}, constants)
check('current_product_identity', constants['COMMIT'] == '4e808d0ecb1bcded22870a7ec960dfb2491cf6ec'
      and constants['TREE'] == 'eba5e650bd080b8ad41ea52a2bc68867f541d255')
old_constants = {}
for item in old_ast.body:
    if isinstance(item, ast.Assign) and len(item.targets) == 1 and isinstance(item.targets[0], ast.Name):
        name = item.targets[0].id
        if name in {'BUDGETS', 'API_PORTS', 'INGRESS_OBSERVER_TESTS', 'COLD_H2_TESTS', 'PROFILE', 'FEATURES'}:
            old_constants[name] = ast.literal_eval(item.value)
for name, value in old_constants.items():
    check('original_constant_unchanged_' + name, constants[name] == value)
check('one_separate_ABA_name', constants['SAME_ROOT_PUBLICATION_TESTS'] == (
    'service::native_v6_ha_install::tests::same_root_republication_tests::native_ha_same_root_republication_advances_warm_and_cold_cursors',))

tree_files = ('root', 'crates', 'heptabao-server', 'src')
trees = [json.loads(read('reference/canonical-trees/' + name + '.json')) for name in tree_files]
for name, tree in zip(tree_files, trees):
    entries = sorted(tree['tree'], key=lambda r: (r['path'] + ('/' if r['type'] == 'tree' else '')).encode())
    raw = b''.join((r['mode'].lstrip('0') + ' ' + r['path']).encode() + b'\0' + bytes.fromhex(r['sha']) for r in entries)
    digest = hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    check('canonical_merkle_' + name, digest == tree['sha'] and not tree.get('truncated', False))
check('canonical_root_matches_candidate', trees[0]['sha'] == constants['TREE'])
for parent, child, name in zip(trees, trees[1:], tree_files[1:]):
    check('canonical_member_link_' + name, any(r['path'] == name and r['sha'] == child['sha'] and r['type'] == 'tree' for r in parent['tree']))
for path, (expected_blob, expected_sha) in constants['PRODUCT_PINS'].items():
    source = read('reference/canonical/' + path)
    check('canonical_source_whole_' + path, git_blob(source) == expected_blob and sha(source) == expected_sha)
    name = Path(path).name
    check('canonical_source_member_' + name, any(r['path'] == name and r['sha'] == expected_blob and r['type'] == 'blob' and r['mode'] == '100644' for r in trees[-1]['tree']))

binding = json.loads(read('binding/partial-binding.private.json'))
old_binding = json.loads(read('reference/partial-binding.df026.private.json'))
dispatch = json.loads(read('dispatch/requests.template.json'))
old_dispatch = json.loads(read('reference/requests.df026.template.json'))
base = Path('/home/qian-qi/heptabao-ha-closure-20261103-r1')
control = base / 'official271-native-cli-phaseb-r3-control-r4'
work = base / 'official271-native-cli-phaseb-r3-live-r4'
check('future_exact_layout', binding['layout'] == {
    'control': str(control), 'work': str(work), 'prepare': str(control / 'prepare-r1'),
    'source': str(base / 'normal-same-root-publication-validation-source-r1')})
check('unresolved_binding_and_dispatch', binding['ready_for_readonly_prepare'] is False
      and dispatch['ready'] is False and dispatch['requests_authorized'] is False)
for role in ('server', 'native_receipt', 'release_receipt', 'combined_tests'):
    check('future_artifact_still_null_' + role, binding['artifacts'][role]['bytes'] is None
          and binding['artifacts'][role]['sha256'] is None)
for key in ('host', 'official_cli', 'utilities', 'old_fences', 'budgets'):
    check('existing_requirement_unchanged_' + key, binding[key] == old_binding[key])
for name, pin in binding['qa_files'].items():
    body = read('candidate/' + name)
    check('future_qa_exact_' + name, pin['path'] == str(control / 'qa' / name)
          and pin['bytes'] == len(body.encode()) and pin['sha256'] == sha(body)
          and pin['mode'] == 0o600 and pin['uid'] == 1000)
for name, pin in binding['artifacts'].items():
    check('future_artifact_owned_path_' + name, Path(pin['path']).parent == control / 'artifacts')
for mode, timeout in (('prepare', 330), ('live', 3000)):
    request = dispatch['templates'][mode]
    check('dispatch_timeout_' + mode, request['timeout_seconds'] == timeout == old_dispatch['templates'][mode]['timeout_seconds'])
    check('dispatch_private_basename_' + mode, request['args'][request['args'].index('--binding') + 1] == str(control / 'binding.private.json'))
    check('dispatch_controller_path_' + mode, request['args'][:4] == ['-I', '-S', '-B', str(control / 'qa' / 'phaseb_controller_r3.py')])
    check('dispatch_exact_host_tool_cwd_' + mode, request['host'] == 'desktop'
          and request['executable'] == '/usr/bin/python3.12' and request['cwd'] == str(base))
    check('dispatch_unresolved_digest_' + mode, request['args'][request['args'].index('--binding-sha256') + 1] == 'UNRESOLVED_ACTUAL_BINDING_SHA256')

# Execute only the actual data predicates below. No module, constructor, method,
# filesystem helper, subprocess, network function, or fixture entry point runs.
binding_class = next(n for n in new_ast.body if isinstance(n, ast.ClassDef) and n.name == 'Binding')
verify = next(n for n in binding_class.body if isinstance(n, ast.FunctionDef) and n.name == 'verify')
start = next(i for i, n in enumerate(verify.body) if isinstance(n, ast.For) and isinstance(n.target, ast.Name) and n.target.id == 'item')
stop = next(i for i, n in enumerate(verify.body) if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
            and len(n.value.args) == 2 and isinstance(n.value.args[1], ast.Constant)
            and n.value.args[1].value == 'build_all_owned_stopped') + 1
selected = ast.Module(body=verify.body[start:stop], type_ignores=[])
selected_code = compile(ast.fix_missing_locations(selected), '<actual-data-only-normal61-predicates>', 'exec')
selected_text = '\n'.join(new.splitlines()[verify.body[start].lineno - 1:verify.body[stop - 1].end_lineno]) + '\n'
ns = dict(constants)
for name in ('BindingError', 'need'):
    node = next(n for n in new_ast.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name == name)
    exec(compile(ast.Module(body=[node], type_ignores=[]), '<actual-predicate-helper>', 'exec'), ns)
refs = {name: read('reference/build/' + name) for name in (
    'normal61-combined.public.json', 'normal61-native.public.json', 'normal61-release.public.json',
    'groups.json', 'normal60-historical.public.json')}
expected_refs = {
    'normal61-combined.public.json': '162336b81e26f391b12d2e6c860c6eb9cc2a9c71',
    'normal61-native.public.json': '9e8a896dddf88bb1623981022568074fdc1ddab7',
    'normal61-release.public.json': '8817820102da001912a8ad5188dfbab01444f6cb',
    'groups.json': '302e5d5a5bfe501dcaf75f8c4cfc166acd58ea5f',
    'normal60-historical.public.json': 'bff1113f7c5b91d9eb0bcd4befd95a20a6812051',
}
for name, expected in expected_refs.items():
    check('original_build_reference_whole_' + name, git_blob(refs[name]) == expected)
native, release = json.loads(refs['normal61-native.public.json']), json.loads(refs['normal61-release.public.json'])
actual = json.loads(refs['normal61-combined.public.json'])
server = release['artifacts']['heptabao-server']
artifacts = {'server': {'bytes': server['bytes'], 'sha256': server['sha256']},
             'native_receipt': {'sha256': sha(refs['normal61-native.public.json'])},
             'release_receipt': {'sha256': sha(refs['normal61-release.public.json'])},
             'test_groups': {'sha256': sha(refs['groups.json'])}}


def run_case(label, combined, expected=None):
    context = dict(ns, native=copy.deepcopy(native), release=copy.deepcopy(release),
                   combined=combined, groups=json.loads(refs['groups.json']), self=SimpleNamespace(artifacts=artifacts))
    failure = None
    try:
        exec(selected_code, context)
    except ns['BindingError'] as error:
        failure = str(error)
    check('selected_predicate_' + label, failure == expected)
    return {'case': label, 'expected_failure': expected, 'observed_failure': failure, 'passed': True}


components = [run_case('actual_current61_receipts', copy.deepcopy(actual)),
              run_case('historical_df026_normal60_refused', json.loads(refs['normal60-historical.public.json']),
                       'diagnostic_original44_terminal_pass_required')]


def negative(label, keys, value, expected):
    value_copy = copy.deepcopy(actual)
    target = value_copy
    for key in keys[:-1]:
        target = target[key]
    target[keys[-1]] = value
    components.append(run_case(label, value_copy, expected))


gate = 'current_product_61_with_separate_same_root_one'
terminal = 'same_root_publication_regression_terminal'
negative('ABA_receipt_missing', ['same_root_publication_regression'], None, gate)
negative('ABA_name_changed', ['same_root_publication_regression', 'actual_test_names'], ['different_test'], gate)
negative('ABA_failed', ['same_root_publication_regression', 'tests', 0, 'tests', 'exit_code'], 101, terminal)
negative('ABA_timed_out', ['same_root_publication_regression', 'tests', 0, 'tests', 'timed_out'], True, terminal)
negative('ABA_unreaped', ['same_root_publication_regression', 'tests', 0, 'tests', 'direct_child_reaped'], False, terminal)
negative('ABA_survivor', ['same_root_publication_regression', 'tests', 0, 'tests', 'remaining'], [1], terminal)
negative('ABA_budget_changed', ['same_root_publication_regression', 'new_total_group_cap_seconds'], 601, gate)
negative('ABA_parent_clip_missing', ['same_root_publication_regression', 'clamped_to_original_outer_deadline'], False, gate)
negative('sixty_total_rejected', ['selected_test_total'], 60, gate)
negative('separate_count_missing', ['additional_test_counts'], {'ingress_observer': 7, 'cold_h2': 9}, gate)
negative('old_runner_rejected', ['controller_sha256'], '1a3fdc3a7cf6504447feb7d7dadf2f365b292512f6d0cf8cdfb4a2ea63d33d40',
         'exact_current_product_normal61_runner')
negative('old_candidate_rejected', ['source_commit'], 'df026fe323dd7cf0f0ec57d7d2d9c5a79897053c',
         'diagnostic_original44_terminal_pass_required')

constructor = next(n for n in binding_class.body if isinstance(n, ast.FunctionDef) and n.name == '__init__')
ready = next(n for n in constructor.body if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
             and len(n.value.args) == 2 and isinstance(n.value.args[1], ast.Constant)
             and n.value.args[1].value == 'unresolved_binding_is_not_admission')
failure = None
try:
    exec(compile(ast.Module(body=[ready], type_ignores=[]), '<actual-ready-guard-only>', 'exec'), dict(ns, spec=binding))
except ns['BindingError'] as error:
    failure = str(error)
check('actual_ready_guard_refuses_template', failure == 'unresolved_binding_is_not_admission')

result = {
    'schema': 'heptabao.phaseb-4e808-source-checks.v1', 'status': 'passed_source_only',
    'checks': rows, 'check_count': len(rows), 'selected_components': components,
    'selected_component_count': len(components), 'selected_predicates_sha256': sha(selected_text),
    'whole_modules_compiled_not_executed': 5,
    'selected_execution': 'Actual Binding.verify receipt-only AST statements, need/BindingError, literal constants and one ready guard; no module/Binding constructor/fixture execution.',
    'diff_hunks': {'binder': binder_hunks, **template_hunks},
    'unchanged_definitions': unchanged,
    'candidate_binding': {'bytes': len(new.encode()), 'sha256': sha(new), 'blob': git_blob(new)},
    'runtime_requests': 0, 'product_operations': 0, 'new_runtime_qualification': False,
    'limits': ['The actual normal61 receipts are data inputs to an offline admission predicate, not a new normal run.',
               'Host, source import, product transport, local-stage versions, prepare and live remain unresolved.',
               'No official CLI or archive/H2/component product test was executed by this verifier.'],
}
(ROOT / 'review/source-checks.public.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
(ROOT / 'review/selected-receipt-predicates.py.txt').write_text(selected_text)
print(json.dumps({'status': result['status'], 'checks': len(rows), 'selected_components': len(components),
                  'diff_hunks': result['diff_hunks'], 'unchanged_definitions': len(unchanged)}, sort_keys=True))
