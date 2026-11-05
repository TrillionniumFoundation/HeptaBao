"""Offline entry/path contract checks; execute only the actual AST assertion.

All source and payload reads happen before a rejecting audit hook. Filesystem
resolution is an explicit in-memory adapter; this is not a host filesystem or
prepare qualification. No launcher, carrier, helper, or service module runs.
"""
import ast
import base64
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys

ROOT = Path(__file__).resolve().parent
NAME = 'launch_normal_r10_pocket_postrecovery_cold_r2.py'
old = (ROOT / 'before/blocked-launcher.py').read_text()
new = (ROOT / 'candidate' / NAME).read_text()
carrier_old = (ROOT / 'before/blocked-inert-carrier.py').read_text()
carrier_new = (ROOT / 'inert_carrier_r2.py').read_text()
payload_raw = (ROOT / 'inert_stdin_r2.json').read_bytes()
payload = json.loads(payload_raw)
pins = json.loads((ROOT / 'candidate-pins.public.json').read_bytes())
dispatch = json.loads((ROOT / 'DISPATCH.proposed.json').read_bytes())
dispatch_old = json.loads((ROOT / 'before/blocked-DISPATCH.proposed.json').read_bytes())
original_pins = json.loads((ROOT / 'before/blocked-candidate-pins.public.json').read_bytes())
sources = {name: (ROOT / 'candidate' / name).read_bytes() for name in pins}
component_raw = Path(__file__).read_bytes()
rows = []


def deny_runtime(event, args):
    if event == 'open' or event.startswith(('socket.', 'subprocess.')) or event in {
        'os.system', 'os.fork', 'os.posix_spawn', 'os.exec', 'os.mkdir', 'os.rename',
        'os.remove', 'os.unlink', 'os.listdir', 'os.scandir', 'os.link', 'os.symlink'}:
        raise RuntimeError('offline_component_runtime_forbidden:' + event)


sys.addaudithook(deny_runtime)


def check(name, passed, **details):
    rows.append({'case': name, 'passed': passed is True, **details})
    if passed is not True:
        raise AssertionError(name)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def assigned(tree, name):
    return next(node for node in tree.body if isinstance(node, ast.Assign)
                and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == name)


def entry(tree):
    nodes = [node for node in tree.body if isinstance(node, ast.Assert)
             and any(isinstance(value, ast.Name) and value.id == '__file__'
                     for value in ast.walk(node))]
    check('exactly_one_actual_top_level_entry_assertion', len(nodes) == 1)
    return nodes[0]


old_tree, new_tree = ast.parse(old), ast.parse(new)
old_assert, new_assert = entry(old_tree), entry(new_tree)
namespace = {'Path': PurePosixPath}
exec(compile(ast.Module(body=[assigned(new_tree, 'ROOT'), assigned(new_tree, 'CONTROL')],
                        type_ignores=[]), '<actual-path-assignments-only>', 'exec'), namespace)
control = namespace['CONTROL']
target = control / NAME
check('actual_control_matches_carrier_and_dispatch',
      str(control) == dispatch['inert']['expected_control'])
old_literal = "assert Path(__file__).resolve(strict=True) == CONTROL / 'launch_normal_r10_pocket_postrecovery_cold_r1.py'"
new_literal = old_literal.replace('cold_r1.py', 'cold_r2.py')
check('only_single_guard_basename_literal_changed', old.count(old_literal) == 1
      and new == old.replace(old_literal, new_literal, 1))
old_without = copy.deepcopy(old_tree)
new_without = copy.deepcopy(new_tree)
for tree in (old_without, new_without):
    tree.body = [node for node in tree.body if not (isinstance(node, ast.Assert)
        and any(isinstance(value, ast.Name) and value.id == '__file__' for value in ast.walk(node)))]
check('all_other_launcher_AST_identical', ast.dump(old_without) == ast.dump(new_without))


def evaluate(node, supplied, resolved, expected_exception):
    observed = []
    class ExactPathAdapter:
        def __init__(self, value):
            observed.append(('Path', value))
        def resolve(self, *, strict):
            observed.append(('resolve', strict))
            if isinstance(resolved, BaseException):
                raise resolved
            return PurePosixPath(resolved)
    outcome = None
    try:
        exec(compile(ast.Module(body=[copy.deepcopy(node)], type_ignores=[]),
                     '<actual-entry-assertion-only>', 'exec'),
             {'Path': ExactPathAdapter, '__file__': supplied, 'CONTROL': control})
    except BaseException as error:
        outcome = type(error).__name__
    return outcome == expected_exception and observed == [('Path', supplied), ('resolve', True)], outcome


cases = [
    ('blocked_draft_reproduces_rejection_of_actual_r2_dispatch', old_assert, str(target), str(target), 'AssertionError'),
    ('blocked_draft_only_accepts_its_old_r1_name', old_assert, str(control / 'launch_normal_r10_pocket_postrecovery_cold_r1.py'),
     str(control / 'launch_normal_r10_pocket_postrecovery_cold_r1.py'), None),
    ('fixed_draft_accepts_actual_r2_dispatch', new_assert, str(target), str(target), None),
    ('fixed_draft_rejects_old_r1_basename', new_assert, str(control / 'launch_normal_r10_pocket_postrecovery_cold_r1.py'),
     str(control / 'launch_normal_r10_pocket_postrecovery_cold_r1.py'), 'AssertionError'),
    ('fixed_draft_rejects_other_control_root', new_assert, '/unrelated/' + NAME,
     '/unrelated/' + NAME, 'AssertionError'),
    ('fixed_draft_rejects_wrong_resolved_destination', new_assert, str(target),
     '/unrelated/' + NAME, 'AssertionError'),
    ('fixed_draft_keeps_strict_missing_path_refusal', new_assert, str(target),
     FileNotFoundError('in_memory_missing'), 'FileNotFoundError'),
]
for name, node, supplied, resolved, expected in cases:
    passed, actual = evaluate(node, supplied, resolved, expected)
    check(name, passed, expected_exception=expected, actual_exception=actual)

carrier_tree = ast.parse(carrier_new)
carrier_scope = {'Path': PurePosixPath}
exec(compile(ast.Module(body=[assigned(carrier_tree, 'PARENT'), assigned(carrier_tree, 'BASE'),
                             assigned(carrier_tree, 'PINS')], type_ignores=[]),
             '<actual-carrier-bindings-only>', 'exec'), carrier_scope)
check('actual_carrier_destination_equals_asserted_entry',
      carrier_scope['BASE'] / NAME == target and NAME in carrier_scope['PINS'])
check('prepare_and_live_argv_point_to_same_fixed_entry',
      dispatch['prepare']['args'][3] == dispatch['live']['args_template'][3] == str(target))
check('nine_payload_sources_match_full_bytes_size_sha_and_git', len(sources) == 9
      and set(sources) == set(payload['files']) == set(carrier_scope['PINS'])
      and all(base64.b64decode(payload['files'][name], validate=True) == raw
              and pin(raw) == pins[name]
              and carrier_scope['PINS'][name] == [len(raw), pin(raw)['sha256']]
              for name, raw in sources.items()))
check('other_eight_sources_exact_original_pins', all(pins[name] == original_pins[name]
      for name in sources if name != NAME))
check('carrier_only_launcher_digest_changed', carrier_new == carrier_old.replace(
      original_pins[NAME]['sha256'], pins[NAME]['sha256'], 1)
      and carrier_old.count(original_pins[NAME]['sha256']) == 1)
check('dispatch_carrier_and_stdin_whole_pins', dispatch['inert']['source'] == pin(carrier_new.encode())
      and dispatch['inert']['stdin'] == pin(payload_raw))
check('dispatch_all_expected_candidate_pins',
      {row['path']: {key: value for key, value in row.items() if key != 'path'}
       for row in dispatch['inert']['expected_files']} == pins)
expected_dispatch = copy.deepcopy(dispatch_old)
for row in expected_dispatch['inert']['expected_files']:
    if row['path'] == NAME:
        row.update(pins[NAME])
expected_dispatch['inert']['source'] = pin(carrier_new.encode())
expected_dispatch['inert']['stdin'] = pin(payload_raw)
for stage, field in [('inert', 'idempotency_key'), ('prepare', 'idempotency_key'),
                     ('live', 'idempotency_key_template')]:
    expected_dispatch[stage][field] = expected_dispatch[stage][field].replace(
        original_pins[NAME]['sha256'][:8], pins[NAME]['sha256'][:8])
check('all_other_dispatch_fields_exact_unchanged', dispatch == expected_dispatch)
check('all_dispatches_still_unauthorized_and_live_digest_unbound',
      dispatch['all_stages_authorized'] is False
      and all(dispatch[stage]['authorized'] is False for stage in ('inert', 'prepare', 'live'))
      and dispatch['live']['prepared_sha256'] is None)
for name, raw in sources.items():
    compile(ast.parse(raw, filename=name), name, 'exec', dont_inherit=True)
check('all_nine_complete_sources_compile_only', True, complete_modules_executed=False)
result = {'schema': 'heptabao.postcold-r2-entry-assertion-offline-components.v1',
          'status': 'passed', 'old_source_tree': '25525f6aa7ea8c6de5b09a82433053f6d90101d3',
          'old_launcher': pin(old.encode()), 'new_launcher': pin(new.encode()),
          'component': pin(component_raw), 'python_version': sys.version,
          'checks': rows, 'passed_checks': sum(row['passed'] for row in rows), 'total_checks': len(rows),
          'actual_AST_entry_assertion_executed': True, 'filesystem_resolution_adapter': 'PurePosixPath plus explicit in-memory resolve',
          'complete_module_execution': False, 'network_calls': 0, 'host_calls': 0,
          'product_processes': 0, 'child_processes': 0, 'runtime_qualification': False,
          'original_130_component_record_not_rewritten': True}
print(json.dumps(result, sort_keys=True, indent=2))
