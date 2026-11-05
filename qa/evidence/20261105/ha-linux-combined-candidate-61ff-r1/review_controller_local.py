"""Offline custody and syntax review; does not execute the candidate controller."""
import ast
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
CONTROL = ROOT / 'control'
REVIEW = ROOT / 'review'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def meta(relative):
    raw = (ROOT / relative).read_bytes()
    return {'path': relative, 'bytes': len(raw), 'sha256': sha(raw),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


driver_raw = (CONTROL / 'run_linux_candidate_r1.py').read_bytes()
driver = driver_raw.decode()
tree = ast.parse(driver, filename='run_linux_candidate_r1.py')
compile(tree, 'run_linux_candidate_r1.py', 'exec')
syntax = json.loads((REVIEW / 'controller-local-syntax.public.json').read_text())
assert syntax['driver']['sha256'] == sha(driver_raw)
assert syntax['owned_runner_class_byte_for_byte_unchanged'] is True
old_input = json.loads((CONTROL / 'candidate-input.draft.public.json').read_text())
new_input_raw = (CONTROL / 'candidate-input-r2.draft.public.json').read_bytes()
new_input = json.loads(new_input_raw)
comparison = dict(new_input)
assert comparison.pop('original_unknown_preflight_job') == '1a1a93e525e-fc05-3335'
assert comparison.pop('original_unknown_preflight_resolution') is None
assert comparison == old_input
draft = json.loads((CONTROL / 'candidate-controller.draft.public.json').read_text())
assert draft['driver_source'].encode() == driver_raw
assert draft['driver_sha256'] == sha(driver_raw)
assert draft['candidate_input'] == new_input
assert draft['input_sha256'] == sha(new_input_raw)
assert draft['execution_enabled'] is False
assert draft['process_request'] is None and draft['bootstrap'] is None
assert new_input['execution_enabled'] is False and new_input['mode'] is None
assert new_input['process_request'] is None and new_input['actual_start'] is None
assert new_input['actual_deadline'] is None
assert new_input['authoritative_preflight_resolution'] is None
assert new_input['current_toolchain_pins'] is None
assert new_input['current_resource_and_ownership_review'] is None
assert new_input['unresolved_preflight_job'] == '1a1a93e525e-fc05-3335'
assert sha(new_input['guard_source'].encode()) == 'b00ff78b2a341a752d489c3a677f7a912f0f79b39c42601cfb030a29bea45b59'
assert sha(new_input['base_frozen_source'].encode()) == 'ad59fb02e3affc08720c13f7349d93a99df646ca7616f9a10e41e1cc6ddbeff1'
catalog = new_input['critical_tests']
assert len(catalog['tests']) == len({x['name'] for x in catalog['tests']}) == 19
test_sources = []
for test in catalog['tests']:
    raw = (ROOT / 'source-input' / test['path']).read_bytes()
    name = test['name'].split('::')[-1]
    assert sha(raw) == test['source_sha256']
    assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == test['git_blob']
    assert len(re.findall(r'\bfn\s+' + re.escape(name) + r'\s*\(', raw.decode())) == 1
    test_sources.append({'name': test['name'], 'path': test['path'], 'git_blob': test['git_blob'],
                         'source_sha256': sha(raw), 'unique_definition': True})
assert not any('native_archive_rejects_truncation_concatenated_gzip_and_corruption' in x['name']
               for x in catalog['tests'])
assignments = {node.targets[0].id: ast.literal_eval(node.value)
               for node in tree.body if isinstance(node, ast.Assign)
               and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
               and node.targets[0].id in ('CRITICAL_TESTS', 'ORIGINAL_UNKNOWN_PREFLIGHT_JOB', 'SHARED_SECONDS')}
assert assignments['CRITICAL_TESTS'] == [x['name'] for x in catalog['tests']]
assert assignments['ORIGINAL_UNKNOWN_PREFLIGHT_JOB'] == '1a1a93e525e-fc05-3335'
assert assignments['SHARED_SECONDS'] == 3600.0
functions = {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
uid_checks = []
for name in ('read_owned', 'hash_owned', 'retain_artifact'):
    node = functions[name]
    code = '\n'.join(driver.splitlines()[node.lineno - 1:node.end_lineno])
    assert '501' not in code and code.count('== 1000') == 1
    uid_checks.append({'name': name, 'uid_1000_comparisons': 1, 'uid_501_present': False})
parent_review_path = ROOT.parent / 'heptabao_resume/combined-source-input-root-review.public.json'
parent_review_sha = sha(parent_review_path.read_bytes())
assert parent_review_sha == 'b9e4aff1c7dc8e5366929a01c253cb130bdc3bb6daf26c967f50d5799a582cd1'
report = {
    'schema': 'heptabao.linux.candidate-controller.static-review.v2',
    'scope': 'offline source composition, custody, AST/compile and narrow static review only',
    'execution_enabled': False, 'process_request': None, 'bootstrap': None,
    'remote_action_submitted': False, 'driver_executed': False, 'product_tests_executed': 0,
    'compiled_product': False, 'full_replacement_qualified': False,
    'source': {'commit': 'f80d2d54800ba7e932d91572c084f930af3e5714',
               'tree': '667ae96b264c5e7f4b9290933612125d883b9e69',
               'changed_files': 33, 'utf8_bytes': 1607590, 'frozen_catalog_union': 84,
               'parent_independent_review_sha256': parent_review_sha},
    'driver': meta('control/run_linux_candidate_r1.py'),
    'input_draft': meta('control/candidate-input-r2.draft.public.json'),
    'controller_draft': meta('control/candidate-controller.draft.public.json'),
    'syntax_receipt': meta('review/controller-local-syntax.public.json'),
    'original_owned_runner_unchanged': True,
    'original_owned_runner_sha256': '2e330d72944e02791b9a15bc91da07c9ca2abac9e9917b4bacf3b502e437f9e8',
    'original_guard_fragment_unchanged': True,
    'original_guard_fragment_sha256': 'b00ff78b2a341a752d489c3a677f7a912f0f79b39c42601cfb030a29bea45b59',
    'uid_adaptation': uid_checks,
    'nineteen_unique_definitions': test_sources,
    'admission': {
        'original_unknown_job_constant': '1a1a93e525e-fc05-3335',
        'original_unknown_resolution': None,
        'successful_current_preflight': None,
        'old_closure_and_new_success_are_separate_mandatory_inputs': True,
        'same_job_requires_same_successful_original_sdk': True,
        'review_binds_original_closure_canonical_json_sha256': True,
        'current_toolchain_pins': None, 'resource_ownership_review': None,
        'current_host_admitted': False, 'new_preflight_key_created': False},
    'narrow_static_findings': [
        'The disabled draft cannot reach evidence-directory creation or source mutation.',
        'The original unknown job identity is a code constant, not replaceable by a later successful job.',
        'Original UID/resource/compiler guards are retained; additional owned-boundary observations only restrict admission.',
        'Ordinary product and fixture ownership is a separate timed-stage requirement; no Mac window release is inferred.',
        'Source preparation requires exact clean physical7071, original62 pins, fresh branch/output and locked existing target; exact33 inputs produce full667 tree.',
        'Only reviewed22 Rust paths may change under rustfmt; physical source/tree and all84 pins are frozen before strict/compile.',
        'Every command uses the one new3600-second deadline;3900 is supervisory cleanup only.',
        'The unique actual current-source Cargo libtest artifact is retained by bytes/profile;19 names are each executed at most once only in enabled full mode.',
        'Compile-only ends with zero tests and no production link. Any component failure blocks server/seed link.',
        'OwnedRunner retains its original unreaped-child ownership anchor and forbids group signalling after reap.'
    ],
    'remaining_before_any_execution': [
        'Authoritative closure of original3335, not inferred from missing job directory or elapsed time.',
        'Successful complete actual readonly preflight and independent current source/toolchain/resource/ownership review.',
        'Explicit choice and review of compile_only or components_and_build; timed mode needs separate ROG fixture evidence.',
        'A new reviewed enabled control revision and exact fixed-runtime bootstrap/request. None exists in this archive.'
    ],
    'unqualified_scopes': [
        'current Linux product compilation or components', 'normal production binary HTTPS observer',
        'full workspace', 'physical multi-host HA', 'X230 new-source migration',
        'Mac window release', 'native-disabled V5 sync error precedence',
        'ordinary KV NoForward/global TTL precision closure', 'production cutover or removal'
    ]
}
(REVIEW / 'controller-static-review-r2.public.json').write_bytes(canonical(report))
print(json.dumps({'review': meta('review/controller-static-review-r2.public.json'),
                  'unique_tests': len(test_sources), 'driver_executed': False,
                  'process_request': None}, sort_keys=True))
