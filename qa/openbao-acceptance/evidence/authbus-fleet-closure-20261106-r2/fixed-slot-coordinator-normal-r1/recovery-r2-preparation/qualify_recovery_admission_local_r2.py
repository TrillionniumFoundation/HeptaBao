#!/usr/bin/env python3
"""Narrow local checks: exact closed-r1 admission and no-init dispatch barrier.

The two supplied public originals are the lossless request and stdout from the
failed attempt. There are no private response bytes, services or network calls.
This does not qualify Mac execution or the remaining coordinator workflow.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys
import types

HERE = Path(__file__).resolve().parent
ORIGINAL = HERE / 'local-public-originals'
for name in ('request.original.json', 'stdout.original.json'):
    assert (ORIGINAL / name).is_file()
raw_request = (ORIGINAL / 'request.original.json').read_bytes()
raw_stdout = (ORIGINAL / 'stdout.original.json').read_bytes()
assert len(raw_request) == 248444 and hashlib.sha256(raw_request).hexdigest() == '541a526c1aac1a0ab8974cd897421b2e457c079fb01d8b55b7e2d7d28a6b0762'
assert len(raw_stdout) == 10618 and hashlib.sha256(raw_stdout).hexdigest() == '05c2f864b2f6e72a8afacbbe622e55639d39a9850bdf3bffa475674927ff7ded'


class Refused(RuntimeError):
    pass


def need(condition, code):
    if not condition:
        raise Refused(code)


fragment = (HERE / 'original_initialized_fixture_r2.fragment.py').read_text()
cls = ast.parse(fragment).body[0]
admit = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'admit')
# Retain the exact executable prefix before any private file or directory read.
stop = next(i for i, n in enumerate(admit.body) if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == 'custody' for t in n.targets))
admit.body = admit.body[:stop] + [ast.Return(value=ast.Constant(True))]
ns = {'need': need, 'json': json, 'hashlib': hashlib,
      'PYTHON': Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')}
exec(compile(ast.fix_missing_locations(ast.Module(body=[admit], type_ignores=[])), '<exact-public-admission-prefix>', 'exec'), ns)
request = json.loads(raw_request)
stdout = json.loads(raw_stdout)
cases = []


def run_admission(label, mutate, success):
    a, b = copy.deepcopy(request), copy.deepcopy(stdout)
    mutate(a, b)
    reads = []
    def read(path, maximum, **kwargs):
        reads.append(path.name)
        assert maximum in (524288, 16384)
        return json.dumps(a if path.name == 'request.json' else b).encode()
    instance = types.SimpleNamespace(JOB=Path('/Users/qianqi/.local/state/hepta-runtime-mac-worker/jobs/1a1b3e976fc-fc05-8575'), read=read)
    try:
        accepted = ns['admit'](instance) is True
    except Refused:
        accepted = False
    assert accepted is success and reads in (['request.json'], ['request.json', 'stdout.log'])
    cases.append({'case': label, 'passed': True})


run_admission('actual_public_originals_accepted', lambda a, b: None, True)
run_admission('different_job_refused', lambda a, b: a.update(job_id='another-job'), False)
run_admission('changed_original_source_refused', lambda a, b: a['args'].__setitem__(4, a['args'][4] + '\n'), False)
run_admission('original_worker_unknown_refused', lambda a, b: b.update(nodeBusinessOutcomeUnknown=True), False)
run_admission('original_server_not_closed_refused', lambda a, b: b.update(allOriginalServersClosed=False), False)
run_admission('init_response_incomplete_refused', lambda a, b: b['apiPhases'][0]['requests'][1].update(responseComplete=False), False)
run_admission('init_receipt_not_durable_refused', lambda a, b: b['apiPhases'][0]['requests'][1].update(responsePrivatelyDurable=False), False)
run_admission('unrecorded_third_request_refused', lambda a, b: b['apiPhases'][0]['requests'].append(copy.deepcopy(b['apiPhases'][0]['requests'][1])), False)

sys.path.insert(0, str(HERE / 'python-source'))
import fixedslot_recovery_api_r2 as api_module
for label, route, category in (
    ('init_category_and_route_refused', '/v1/sys/init', 'init'),
    ('init_with_other_category_refused', '/v1/sys/init', 'health'),
    ('init_subpath_refused', '/v1/sys/init/extra', 'health'),
    ('init_category_on_other_route_refused', '/v1/sys/unseal', 'init'),
):
    api = object.__new__(api_module.Api)
    calls = []
    api.remaining = lambda cap: 10
    api.guard = types.SimpleNamespace(check=lambda: calls.append('guard'))
    api.rows = []
    api.unknown = False
    api.journal = types.SimpleNamespace(append=lambda *args: calls.append('journal'))
    try:
        api.call(label, 'POST', route, {}, token='', category=category)
        raise AssertionError('init reached dispatch')
    except api_module.Refused as error:
        assert error.args == ('recovery_initialization_forbidden',)
    assert calls == ['guard'] and api.rows == []
    cases.append({'case': label, 'passed': True})

out = {'schema': 'heptabao.fixed-slot-recovery-local-boundaries.r2', 'ok': True,
       'cases': cases, 'passed': len(cases), 'scope': 'local source prefix and no-init gate only',
       'privateOriginalMaterialRead': False, 'networkRequests': 0,
       'originalPublicReceiptBytePinsChecked': True,
       'sourcePins': {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in
           ('original_initialized_fixture_r2.fragment.py', 'python-source/fixedslot_recovery_api_r2.py')},
       'macExecutionQualified': False, 'remainingCoordinatorBusinessQualified': False}
print(json.dumps(out, sort_keys=True))
