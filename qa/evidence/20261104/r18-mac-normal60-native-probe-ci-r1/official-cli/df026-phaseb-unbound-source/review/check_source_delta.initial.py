#!/usr/bin/env python3
"""Offline source-only comparison: parse/compile text, never execute candidate modules."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
data = json.loads((ROOT / 'review-input.json').read_text())

def digest(text):
    raw = text.encode()
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

def definitions(text):
    tree = ast.parse(text)
    found = {}
    def visit(nodes, prefix=''):
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found[prefix + node.name] = ast.get_source_segment(text, node)
            elif isinstance(node, ast.ClassDef):
                visit(node.body, prefix + node.name + '.')
    visit(tree.body)
    return found

def literals(text):
    result = {}
    for node in ast.parse(text).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                result[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                pass
    return result

rows = []
for label in ('exporter', 'inert', 'binding'):
    before, after = data[label + '_before'], data[label + '_after']
    compile(before, label + '-before.py', 'exec')
    compile(after, label + '-after.py', 'exec')
    (ROOT / (label + '-before.py')).write_bytes(before.encode())
    (ROOT / (label + '-after.py')).write_bytes(after.encode())
    delta = ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                    fromfile='reference/' + label + '.py', tofile='candidate/' + label + '.py'))
    (ROOT / (label + '.review.diff')).write_bytes(delta.encode())
    old, new = definitions(before), definitions(after)
    assert set(old) == set(new)
    changed = [name for name in old if old[name] != new[name]]
    row = {'label': label, 'before': digest(before), 'after': digest(after),
           'diff': digest(delta), 'definition_count': len(old), 'changed_definitions': changed,
           'byte_identical_definitions': [name for name in old if old[name] == new[name]],
           'parse_and_compile_only': True, 'candidate_executed': False}
    if label in ('exporter', 'inert'):
        current = before
        for left, right in data[label + '_edits']:
            assert current.count(left) == 1
            current = current.replace(left, right, 1)
        assert current == after
        for left, right in reversed(data[label + '_edits']):
            assert current.count(right) == 1
            current = current.replace(right, left, 1)
        assert current == before
        row['exact_literal_inverse_whole_equal'] = True
        row['literal_replacements'] = len(data[label + '_edits'])
        assert changed == []
    else:
        assert changed == ['Binding.__init__', 'Binding.verify'], changed
        first, last = literals(before), literals(after)
        preserved = ('INGRESS_OBSERVER_TESTS', 'BUDGETS', 'API_PORTS', 'QA_NAMES',
                     'REFERENCE_PINS', 'FEATURES', 'PROFILE', 'GROUPS_SHA',
                     'OFFICIAL_SHA', 'OFFICIAL_BYTES', 'OFFICIAL_SOURCE_COMMIT', 'SCHEMA')
        for name in preserved:
            assert first[name] == last[name], name
        row['preserved_literal_contracts'] = list(preserved)
        assert len(last['COLD_H2_TESTS']) == 9
        assert len(set(last['COLD_H2_TESTS'])) == 9
        assert set(last['PRODUCT_PINS']) == set(first['PRODUCT_PINS']) | {
            'crates/heptabao-server/src/http_h2.rs',
            'crates/heptabao-server/src/service_native_v6_ha_read.rs'}
        for name in first['PRODUCT_PINS']:
            assert first['PRODUCT_PINS'][name] == last['PRODUCT_PINS'][name]
    rows.append(row)
report = {'schema': 'heptabao.df026-desktop-source-delta-offline.v1',
          'source_only': True, 'host_calls': 0, 'candidate_modules_executed': 0,
          'rows': rows, 'status': 'passed'}
(ROOT / 'source-delta-check.public.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
print(json.dumps(report, sort_keys=True))
