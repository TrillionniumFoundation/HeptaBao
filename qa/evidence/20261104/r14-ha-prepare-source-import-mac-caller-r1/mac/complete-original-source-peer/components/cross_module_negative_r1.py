"""Actual selected source boundaries with synthetic values; no module imports.

The whole capture library stays frozen. The corrected consumer expression is
an explicit proposed one-line change; its check is not actual runtime proof.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

ROOT = Path(__file__).resolve().parent
NAMES = ['mac_guarded_current_capture_r3.py', 'mac_current_fixture_materializer_r1.py',
         'mac_current_phase_owner_r2.py', 'mac_current_outer_r3.py']
sources = {name: (ROOT / name).read_text() for name in NAMES}
own = Path(__file__).read_bytes()
rows = []


def audit(event, args):
    if event == 'open' or event.startswith(('socket.', 'subprocess.')) or event in {
        'os.system', 'os.fork', 'os.exec', 'os.posix_spawn', 'os.mkdir', 'os.rename',
        'os.remove', 'os.unlink', 'os.listdir', 'os.scandir', 'os.link', 'os.symlink'}:
        raise RuntimeError('offline_runtime_refused:' + event)


sys.addaudithook(audit)


def check(name, passed, **details):
    rows.append({'case': name, 'passed': passed is True, **details})
    if passed is not True:
        raise AssertionError(name)


def function(source, name):
    return next(n for n in ast.parse(source).body
                if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name == name)


def pin(text):
    raw = text.encode()
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


phase = sources['mac_current_phase_owner_r2.py']
outer = sources['mac_current_outer_r3.py']
phase_main = function(phase, 'main')
qa_loop = next(n for n in ast.walk(phase_main) if isinstance(n, ast.For)
               and isinstance(n.iter, ast.Tuple)
               and any(isinstance(c, ast.Constant) and c.value == 'authbus_native_login_custody.py'
                       for c in n.iter.elts))
required = ast.literal_eval(qa_loop.iter)
inventory = next(ast.literal_eval(n.value) for n in ast.parse(outer).body
                 if isinstance(n, ast.Assign) and len(n.targets) == 1
                 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == 'NAMES')
missing = sorted(set(required) - set(inventory))
check('actual_phase_requires_one_missing_frozen_inventory_member',
      missing == ['authbus_native_login_custody.py'], missing=missing)
phase_imports = [n.module for n in ast.walk(ast.parse(phase)) if isinstance(n, ast.ImportFrom)]
check('old_name_has_no_actual_import_and_retained_owner_is_imported',
      'authbus_native_login_custody' not in phase_imports and phase_imports.count('mac_owned_unreaped_r1') == 2)
check('proposed_removal_retains_all_other_eight_actual_guards',
      len(required) == 9 and len([n for n in required if n not in missing]) == 8
      and set(n for n in required if n not in missing) <= set(inventory))

capture = sources['mac_guarded_current_capture_r3.py']
materializer = sources['mac_current_fixture_materializer_r1.py']
capture_nodes = [function(capture, n) for n in ('CaptureRefused', 'need', 'encoded', 'sha', 'current_models')]
capture_tree = ast.parse(capture)
for name in ('AGENTS', 'CONFIG_SHA', 'LIVE'):
    capture_nodes.insert(0, next(n for n in capture_tree.body if isinstance(n, ast.Assign)
        and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name))
cap_env = {'hashlib': hashlib, 'json': json, 'Path': PurePosixPath, 're': re}
exec(compile(ast.Module(body=capture_nodes, type_ignores=[]), '<actual-pure-capture-functions>', 'exec'), cap_env)
mat_env = {'hashlib': hashlib, 'json': json}
exec(compile(ast.Module(body=[function(materializer, n) for n in ('Refused', 'need', 'encoded', 'sha', 'digest')],
                       type_ignores=[]), '<actual-pure-materializer-functions>', 'exec'), mat_env)
model_call = next(n for n in ast.walk(function(materializer, 'Materializer'))
                  if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
                  and any(isinstance(c, ast.Constant) and c.value == 'actual_per_agent_model_binding'
                          for c in n.value.args))
old_statement = ast.get_source_segment(materializer, model_call)
new_statement = old_statement.replace("captured['declaredModelSha256']==digest(selected)",
                                      "captured['declaredModelSha256']==sha(encoded(selected)+b'\\n')", 1)
check('proposed_consumer_change_is_only_one_hash_expression', old_statement != new_statement
      and old_statement.count("captured['declaredModelSha256']==digest(selected)") == 1)
old_code = compile(ast.Module(body=[model_call], type_ignores=[]), '<actual-old-consumer-assertion>', 'exec')
new_code = compile(ast.parse(new_statement), '<proposed-LF-consumer-assertion>', 'exec')


def evaluate(code, selected, captured, provider='openai', model='gpt-6.1-sol'):
    env = {**mat_env, 'selected': selected, 'captured': captured, 'provider': provider,
           'model_id': model, 'CONFIG_SHA': cap_env['CONFIG_SHA']}
    try:
        exec(code, env)
    except BaseException as error:
        return type(error).__name__, str(error)
    return None, None


for shape, selected in [('string', 'openai/gpt-6.1-sol'),
                        ('object', {'primary': 'openai/gpt-6.1-sol', 'fallbacks': ['openai/gpt-6.1-sol']})]:
    cfg = {'agents': {'defaults': {'model': selected},
                      'list': [{'id': a} for a in cap_env['AGENTS']]}}
    actual = cap_env['current_models'](cfg)
    check('actual_capture_hash_contains_LF.' + shape,
          cap_env['encoded'](selected).endswith(b'\n')
          and cap_env['encoded'](selected) == mat_env['encoded'](selected) + b'\n')
    for agent, captured in actual.items():
        error, code = evaluate(old_code, selected, captured)
        check('old_actual_model_boundary_rejects_equal_input.' + shape + '.' + agent,
              error == 'Refused' and code == 'actual_per_agent_model_binding',
              capture_sha256=captured['declaredModelSha256'], consumer_sha256=mat_env['digest'](selected))
        check('proposed_LF_boundary_accepts_equal_input.' + shape + '.' + agent,
              evaluate(new_code, selected, captured) == (None, None))
    sample = actual['main']
    for name, update in [('hash', {'declaredModelSha256': '0' * 64}),
                         ('source_config', {'sourceConfigSha256': '0' * 64}),
                         ('provider', {'provider': 'wrong'}), ('model', {'id': 'wrong'})]:
        error, code = evaluate(new_code, selected, {**sample, **update})
        check('proposed_LF_boundary_still_refuses_' + name + '.' + shape,
              error == 'Refused' and code == 'actual_per_agent_model_binding')
    wrong_selection = 'openai/different-model'
    check('proposed_LF_boundary_refuses_different_actual_declaration.' + shape,
          evaluate(new_code, wrong_selection, sample) == ('Refused', 'actual_per_agent_model_binding'))

result = {'schema': 'heptabao.mac-outer-0aca-cross-module-peer-components.v1',
          'status': 'passed_expected_negatives_and_proposed_closure',
          'source_tree': '0aca624b5d051ed55a62943a06b638c9b3090129',
          'sources': {name: pin(text) for name, text in sources.items()},
          'component': pin(own.decode()), 'checks': rows,
          'passed_checks': sum(row['passed'] for row in rows), 'total_checks': len(rows),
          'python_version': sys.version, 'host_calls': 0, 'network_calls': 0,
          'child_processes': 0, 'sqlite_connections': 0, 'complete_modules_executed': False,
          'capture_library_unchanged': True, 'materializer_global_digest_unchanged': True,
          'proposed_after_expression_only_not_author_candidate_qualification': True,
          'actual_T5_SQLite_TLS_launchd_consumer_runtime_qualified': False}
print(json.dumps(result, sort_keys=True, indent=2))
