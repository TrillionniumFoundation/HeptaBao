#!/usr/bin/env python3
"""Narrow failure-closure projection successor; retain prepared R1 bytes."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FROZEN = HERE / 'current-main3-relation-prepared-r1'


def exact(path, expected):
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected, path.name
    return raw.decode()


core = exact(FROZEN / 'code/mac_current_selected_main3_r1.py',
    '4399399cda5fc6131583b461870f5c35906abe07625ca2df57a38d6c6c2a90cd')
old_core = core
core = core.replace('        self.closure = closure\n', '        self.closure = public_closure(closure)\n', 1)
marker = '\ndef need(value, code):\n'
assert core.count(marker) == 1
projection = '''
CLOSURE_BOOLEANS = ('allOwnedDescriptorsClosed', 'allHeldDescriptorsClosed',
    'allReturnedConnectionsClosed', 'allExplicitCursorsClosed',
    'allPublicCodeDescriptorsClosed', 'emptyWalHeldFdRouteInvoked')
CLOSURE_COUNTS = ('connectionAttemptCount', 'returnedConnectionCount', 'cursorCount', 'queryCount')


def public_closure(value):
    """One identical closed allowlist for success and failure receipts.

    Bottom-layer error text and all unlisted keys remain private. A malformed
    receipt cannot be represented as known resource closure.
    """
    qualified = (type(value) is dict
        and all(type(value.get(key)) is bool for key in CLOSURE_BOOLEANS)
        and all(type(value.get(key)) is int and 0 <= value[key] <= 2147483647 for key in CLOSURE_COUNTS)
        and type(value.get('closeErrors')) is list and len(value['closeErrors']) <= 1024)
    if not qualified:
        return {**{key: False for key in CLOSURE_BOOLEANS},
            **{key: None for key in CLOSURE_COUNTS}, 'closeErrors': ['closure_shape_unavailable'],
            'closeErrorCount': None, 'closureShapeQualified': False}
    return {**{key: value[key] for key in CLOSURE_BOOLEANS},
        **{key: value[key] for key in CLOSURE_COUNTS},
        'closeErrors': [] if not value['closeErrors'] else ['original_resource_close_failed'],
        'closeErrorCount': len(value['closeErrors']), 'closureShapeQualified': True}

'''
core = core.replace(marker, '\n' + projection + marker, 1)
before = '''    return output, {key: closure[key] for key in (
        'allOwnedDescriptorsClosed', 'allHeldDescriptorsClosed', 'allReturnedConnectionsClosed',
        'allExplicitCursorsClosed', 'allPublicCodeDescriptorsClosed', 'closeErrors',
        'connectionAttemptCount', 'returnedConnectionCount', 'cursorCount', 'queryCount',
        'emptyWalHeldFdRouteInvoked')}
'''
assert core.count(before) == 1
core = core.replace(before, '''    projected = public_closure(closure)
    need(projected['closureShapeQualified'], 'current_three_typed_success_closure_projection')
    return output, projected
''')
worker = exact(FROZEN / 'code/read_current_main3_candidate_relation_r1.py',
    '08ecb096bcb40995bc78db1a868cdd2f490ae708f10e89bbc3623c783db2b009')
old_worker = worker
worker = worker.replace('mac_current_selected_main3_r1', 'mac_current_selected_main3_r2')
worker = worker.replace('current-main3-candidate-relation-20261107-r1', 'current-main3-candidate-relation-20261107-r2')
worker = worker.replace('heptabao.current-main3-candidate-relation.worker.r1', 'heptabao.current-main3-candidate-relation.worker.r2')
parent = exact(FROZEN / 'launcher/observe_current_main3_candidate_relation_r1.py',
    'c01bbba9b27101f3a72789e069fe4997a7767ac51428a274b552bcc29e9ca7f1')
node = next(item for item in ast.parse(parent).body if isinstance(item, ast.Assign)
    and any(isinstance(target, ast.Name) and target.id == 'PAYLOAD' for target in item.targets))
payload = ast.literal_eval(node.value)
assignment = ast.get_source_segment(parent, node)
template = parent.replace(assignment, 'PAYLOAD = __RELATION_PAYLOAD__', 1)
old_template = template
for old, new in (('mac_current_selected_main3_r1', 'mac_current_selected_main3_r2'),
                 ('read_current_main3_candidate_relation_r1', 'read_current_main3_candidate_relation_r2'),
                 ('current-main3-candidate-relation-20261107-r1', 'current-main3-candidate-relation-20261107-r2'),
                 ('heptabao.current-main3-candidate-relation.parent.r1', 'heptabao.current-main3-candidate-relation.parent.r2')):
    template = template.replace(old, new)
for name in ('mac_current_selected_main3_r1.py', 'read_current_main3_candidate_relation_r1.py'):
    del payload['readerSources'][name]
payload['readerSources']['mac_current_selected_main3_r2.py'] = core
payload['readerSources']['read_current_main3_candidate_relation_r2.py'] = worker
payload['readerPins'] = {name: hashlib.sha256(value.encode()).hexdigest()
                        for name, value in payload['readerSources'].items()}
prepared = template.replace('__RELATION_PAYLOAD__', repr(payload))
files = {'mac_current_selected_main3_r2.py': core,
         'read_current_main3_candidate_relation_r2.py': worker,
         'observe_current_main3_candidate_relation_r2.template.py': template,
         'observe_current_main3_candidate_relation_r2.py': prepared}
for name, value in files.items():
    compile(value, name, 'exec'); (HERE / name).write_text(value)
changes = []
for name, old, new in (('mac_current_selected_main3', old_core, core),
                       ('read_current_main3_candidate_relation', old_worker, worker),
                       ('observe_current_main3_candidate_relation.template', old_template, template)):
    changes.extend(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
        fromfile=name+'-r1.py', tofile=name+'-r2.py'))
(HERE / 'current-main3-relation-r1-to-r2.diff').write_text(''.join(changes))
manifest = json.loads((FROZEN / 'launcher/prepared.public.json').read_text())
manifest.update(schema='heptabao.current-main3-candidate-relation-prepared.r2',
    source='observe_current_main3_candidate_relation_r2.py', bytes=len(prepared.encode()),
    sha256=hashlib.sha256(prepared.encode()).hexdigest(), readerPins=payload['readerPins'],
    originalR1PreparedMap='2ad714ec1133a11c5d2540f128eac466490bab5a',
    successAndFailureUseSameTypedClosureAllowlist=True, rawBottomLayerCloseErrorTextPublished=False,
    originalR1PreparedUnchanged=True)
(HERE / 'current-main3-candidate-relation-prepared-r2.public.json').write_text(json.dumps(manifest, indent=2)+'\n')
print(json.dumps(manifest, sort_keys=True))
