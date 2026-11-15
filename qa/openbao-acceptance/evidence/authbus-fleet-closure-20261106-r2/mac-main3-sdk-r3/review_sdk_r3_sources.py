#!/usr/bin/env python3
"""Independent, read-only binding review of the frozen SDK r2 -> r3 derivative."""
import ast
import base64
import difflib
import hashlib
import json
from pathlib import Path

WORK = Path('/workspace/scratch/c9fe536787d9')
OUT = WORK / 'main3-sdk-diagnostic-work'

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

bundles = []
manifests = []
for rev, expected in ((2, 'cb05709af723f61fb6e1bd7eb1397db8c066c2c13a992ae7cf25e64cb2fc633d'),
                      (3, '8cb911179b5e53822e364c467f10bf13cc0a23da833ee21ae3a12e124417adee')):
    directory = WORK / f'main3-sdk-outer-r{rev}-work'
    raw = (directory / f'staging-sdk-r{rev}.public.json').read_bytes()
    assert digest(raw) == expected
    bundles.append(json.loads(raw))
    manifests.append(json.loads((directory / f'manifest-sdk-r{rev}.public.json').read_bytes()))
old, new = bundles
before, after = manifests
assert old.keys() == new.keys()
assert old['sources'].keys() == new['sources'].keys()
assert old['assets'].keys() == new['assets'].keys()
pin_map = {}
for contents, pins in (('sources', 'sourcePins'), ('assets', 'assetPins')):
    for name, source in new[contents].items():
        assert {'bytes': len(source.encode()), 'sha256': digest(source.encode())} == after[pins][name]
        pin_map[before[pins][name]['sha256']] = after[pins][name]['sha256']
for name in before['capturePins']:
    pin_map[before['capturePins'][name]] = after['capturePins'][name]
assert {'bytes': len(new['preparerSource'].encode()), 'sha256': digest(new['preparerSource'].encode())} == after['preparer']

def scope_and_pins(source):
    for family in ('mac-authbus-main3-sdk', 'mac-authbus-main3-sdk-preparation',
                   'mac-authbus-main3-sdk-journal', 'main3-sdk-inline-capsule',
                   'main3-sdk-inline-capture'):
        source = source.replace(family + '-20261106-r2', family + '-20261106-r3')
    for schema in ('mac-main3-sdk-preparation-terminal', 'mac-main3-sdk-preparation',
                   'mac-main3-sdk-journal', 'mac-main3-current-sdk-qualification'):
        source = source.replace(schema + '.r2', schema + '.r3')
    source = source.replace('observation.sdk-r2', 'observation.sdk-r3')
    source = source.replace('readonly.sdk-r2', 'readonly.sdk-r3')
    for prior, revised in pin_map.items():
        source = source.replace(prior, revised)
    return source

def assignment(source, name, value):
    nodes = [node for node in ast.parse(source).body if isinstance(node, ast.Assign)
             and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    assert len(nodes) == 1
    lines = source.splitlines(True)
    node = nodes[0]
    lines[node.lineno - 1:node.end_lineno] = [name + '=' + repr(value) + '\n']
    return ''.join(lines)

ordinary = []
differences = {}
for name, source in old['sources'].items():
    if name.startswith('main3_capture_payload_'):
        continue
    revised = scope_and_pins(source)
    if revised == new['sources'][name]:
        ordinary.append(name)
    else:
        differences[name] = ''.join(difflib.unified_diff(revised.splitlines(True),
            new['sources'][name].splitlines(True), fromfile='normalized-frozen-r2', tofile='actual-r3'))
assert set(differences) == {'main3_sdk_phase.py'}, sorted(differences)
for name, source in old['assets'].items():
    assert scope_and_pins(source) == new['assets'][name], name
preparer = assignment(scope_and_pins(old['preparerSource']), 'EXPECTED_PINS', after['sourcePins'])
assert preparer == new['preparerSource']

def payload(bundle):
    encoded = ''.join(ast.literal_eval(ast.parse(bundle['sources'][name]).body[0].value)
                      for name in sorted(bundle['sources']) if name.startswith('main3_capture_payload_'))
    return json.loads(base64.b64decode(encoded, validate=True))

old_payload, new_payload = payload(old), payload(new)
assert old_payload.keys() == new_payload.keys()
def scoped_value(value):
    if isinstance(value, str):
        return scope_and_pins(value)
    if isinstance(value, dict):
        return {key: scoped_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [scoped_value(item) for item in value]
    return value
for name, source in old_payload.items():
    assert scoped_value(source) == new_payload[name], name

def profile(source, root):
    nodes = [node for node in ast.parse(source).body
             if isinstance(node, ast.FunctionDef) and node.name == 'sandbox_profile']
    assert len(nodes) == 1
    def need(value, code):
        assert value, code
    class ProjectedMacPath:
        @staticmethod
        def cwd():
            return Path('/Users/qianqi')
    namespace = {'ROOT': Path(root), 'STATE': Path(root) / 'state',
                 'LIVE': Path('/Users/qianqi/.openclaw'), 'Path': ProjectedMacPath,
                 'json': json, 'need': need}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<read-only-profile-review>', 'exec'), namespace)
    return namespace['sandbox_profile'](50090)

root = '/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r3'
old_profile = profile(old['sources']['main3_sdk_phase.py'], root)
new_profile = profile(new['sources']['main3_sdk_phase.py'], root)
prior_rule = b'(allow network-outbound (remote ip "127.0.0.1:50090"))'
revised_rule = b'(allow network-outbound (remote tcp "localhost:50090"))'
assert old_profile.count(prior_rule) == 1
assert new_profile == old_profile.replace(prior_rule, revised_rule)
assert before['budgets'] == after['budgets']
assert before['canonicalProductCommit'] == after['canonicalProductCommit']
assert before['canonicalBinarySha256'] == after['canonicalBinarySha256']
assert old['assets']['qa/main3_sdk_wire_r2.mjs'] == new['assets']['qa/main3_sdk_wire_r2.mjs']
report = {
    'schema': 'heptabao.mac-main3-sdk-r3-independent-source-review.r1', 'ok': True,
    'actualMacExecution': False, 'sourcesPinned': len(new['sources']), 'assetsPinned': len(new['assets']),
    'preparerPinned': True, 'stagingSha256': after['staging']['sha256'],
    'onlySemanticChange': 'one actual-qualified SBPL network rule; remaining changes are scope labels and source pins',
    'ordinarySourcesMatchedAfterScopeAndPins': len(ordinary), 'all13AssetsScopeOnlyOrUnchanged': True,
    'capturePayloadComponentsScopeOnlyOrUnchanged': list(new_payload),
    'generatedSandboxOnlyRuleChanged': True, 'wireBytesUnchanged': True,
    'profileComparisonUsesProjectedMacCwdOnly': True,
    'canonicalProductPinsUnchanged': True, 'budgetsUnchanged': True,
    'singleUseScopeProbeAuthority': '1a1b27ad919-fc05-7e36',
    'scopeProbeResultSha256': '9f389465f8df39807c6718a93bf34d1384838e35f76d07bccb60c4008da4ab43',
    'kernelIpv4OnlyClaimed': False, 'kernelLocalLanDeniedClaimed': False,
    'businessWireExactIpv4Required': True,
}
(OUT / 'sdk-r3-only-semantic-delta.diff').write_text(differences['main3_sdk_phase.py'])
(OUT / 'sdk-r3-independent-source-review.public.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
