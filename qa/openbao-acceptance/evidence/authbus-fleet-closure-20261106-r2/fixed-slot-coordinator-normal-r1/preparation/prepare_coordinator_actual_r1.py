#!/usr/bin/env python3
"""Freeze the normal/TLS fixture; this program performs no remote action."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = HERE.parent / 'production-deployment-work'
COORDINATOR = HERE.parent / 'fixed-slot-coordinator-r3-work'
sha = lambda raw: hashlib.sha256(raw).hexdigest()
original = (BASE / 'bootstrap_permanent_authbus_r2.py').read_bytes()
assert len(original) == 82341 and sha(original) == '2780c5fcef1aebd7b7fffa406af39521dc9cab02c372321df9ef4322bab46422'
tree = ast.parse(original)
original_payload = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
    and any(isinstance(target, ast.Name) and target.id == 'PAYLOAD' for target in node.targets))
for name, text in original_payload['sources'].items():
    assert len(text.encode()) == original_payload['pins'][name]['bytes'] and sha(text.encode()) == original_payload['pins'][name]['sha256']
sources = {}
derivations = []
for name, text in original_payload['sources'].items():
    if name == 'mac_production_t5_guard_r1.py':
        derived = text.replace("ROOT = MOUNT / 'hepta-vnext-recovery-20261013/heptabao-authbus-production'",
            "ROOT = MOUNT / 'hepta-vnext-recovery-20261013/fixed-slot-coordinator-normal-20261107-r1'")
        assert derived != text and text.count("ROOT = MOUNT / 'hepta-vnext-recovery-20261013/heptabao-authbus-production'") == 1
        target = 'mac_fixedslot_t5_guard_r1.py'
    elif name == 'permanent_bootstrap_api_r1.py':
        old = "ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-authbus-production')"
        assert text.count(old) == 1 and text.count("ROOT/'tls/ca.crt'") == 1
        derived = text.replace(old, "ROOT=Path('/Users/qianqi/heptabao-fixed-slot-coordinator-normal-20261107-r1')")
        derived = derived.replace("ROOT/'tls/ca.crt'", "ROOT/'pki/ca.crt'")
        target = 'fixedslot_actual_api_r1.py'
    else:
        derived, target = text, name
    sources[target] = derived
    if derived != text:
        diff = ''.join(difflib.unified_diff(text.splitlines(True), derived.splitlines(True), fromfile=name, tofile=target))
        (HERE / (target + '.diff')).write_text(diff)
        derivations.append({'originalName': name, 'originalSha256': sha(text.encode()), 'derivedName': target,
            'derivedSha256': sha(derived.encode()), 'changes': 'fixed fixture root and CA path only; all logic unchanged'})
    (HERE / 'python-source').mkdir(exist_ok=True)
    (HERE / 'python-source' / target).write_text(derived)
    compile(derived, target, 'exec')

base_template = (BASE / 'bootstrap_permanent_authbus_r2.template.py').read_text()
definitions = ('Refused', 'need', 'remaining', 'full9', 'encoded', 'own', 'close', 'open_fd', 'PrivateOperations')
nodes = {node.name: node for node in ast.parse(base_template).body if isinstance(node, (ast.ClassDef, ast.FunctionDef))}
operations = '\n\n'.join(ast.get_source_segment(base_template, nodes[name]) for name in definitions)
before_operations = operations
old = "'server-start-intent', 'server-stop-result', 'bootstrap-recovery')"
assert operations.count(old) == 1
operations = operations.replace(old, "'server-start-intent', 'server-stop-result', 'bootstrap-recovery',\n             'crypto-intent', 'crypto-result', 'node-request-intent', 'node-request-result')")
(HERE / 'original-operations-categories-only.diff').write_text(''.join(difflib.unified_diff(
    before_operations.splitlines(True), operations.splitlines(True), fromfile='qualified-bootstrap-operations', tofile='fixedslot-operations')))
body = (HERE / 'coordinator_actual_parent_r1.body.py').read_text()
assert body.count('# ORIGINAL_OPERATIONS_PLACEHOLDER') == 1 and body.count('# PAYLOAD_PLACEHOLDER') == 1
template = body.replace('# ORIGINAL_OPERATIONS_PLACEHOLDER', operations)
compile(template, 'coordinator_actual_parent_r1.template.py', 'exec')

runtime_manifest = json.loads((COORDINATOR / 'source-manifest.public.json').read_text())
assert runtime_manifest['implementationSha256'] == '248057b53a13708cc0650b73c83bc86729a7572e0d1bf24768ea94b8d3fd8265'
assets = {}
for row in runtime_manifest['runtimeFiles']:
    raw = (COORDINATOR / row['path']).read_bytes()
    assert len(raw) == row['bytes'] and sha(raw) == row['sha256']
    assets[row['path']] = raw.decode()
assets['package.json'] = (COORDINATOR / 'package.json').read_text()
assets['mac_coordinator_actual_worker_r1.mjs'] = (HERE / 'mac_coordinator_actual_worker_r1.mjs').read_text()
assert len(assets) == 11 and len(sources) == 6
pins = lambda entries: {name: {'bytes': len(text.encode()), 'sha256': sha(text.encode())} for name, text in entries.items()}
payload = {'sources': sources, 'pins': pins(sources), 'assets': assets, 'assetPins': pins(assets)}
assembled = template.replace('# PAYLOAD_PLACEHOLDER', 'PAYLOAD = ' + repr(payload))
assembled_tree = ast.parse(assembled)
recovered = next(ast.literal_eval(node.value) for node in assembled_tree.body if isinstance(node, ast.Assign)
    and any(isinstance(target, ast.Name) and target.id == 'PAYLOAD' for target in node.targets))
assert recovered == payload
compile(assembled, 'launch_coordinator_actual_r1.py', 'exec')
(HERE / 'coordinator_actual_parent_r1.template.py').write_text(template)
(HERE / 'launch_coordinator_actual_r1.py').write_text(assembled)
manifest = {'schema': 'heptabao.fixed-slot-normal-qualification-preparation.r1', 'actualExecuted': False,
    'launcher': {'bytes': len(assembled.encode()), 'sha256': sha(assembled.encode())},
    'body': {'bytes': len(body.encode()), 'sha256': sha(body.encode())},
    'template': {'bytes': len(template.encode()), 'sha256': sha(template.encode())},
    'qualifiedBootstrapLauncherOriginal': {'bytes': len(original), 'sha256': sha(original)},
    'operationsOriginalDefinitions': list(definitions), 'operationsDelta': 'four fixed intent/result category labels only',
    'pythonSourcePins': payload['pins'], 'nodeAssetPins': payload['assetPins'], 'derivations': derivations,
    'nineCoordinatorRuntimeFilesUnchanged': True, 'originalProductionTransportFilesUnchanged': True,
    'implementationSha256': runtime_manifest['implementationSha256'],
    'productCommit': '4bde9aee03fcd27c59e13607e529b1cee594b249',
    'normalBinarySha256': '5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c',
    'parentSeconds': 600, 'nodePhaseSeconds': 120, 'eachApiPhaseSeconds': 120,
    'strictClientRequestMs': 15000, 'coordinatorOperationMs': 30000, 'pythonHttpSeconds': 10,
    'readinessSeconds': 15, 'supervisorSeconds': 630,
    'newHomeRoot': '/Users/qianqi/heptabao-fixed-slot-coordinator-normal-20261107-r1',
    'newT5Root': '/Volumes/T5/hepta-vnext-recovery-20261013/fixed-slot-coordinator-normal-20261107-r1',
    'port': 31126, 'rustGenerations': 2, 'originalNodeWorkers': 2,
    'nativeCryptoCommands': 4, 'newCaAndServerKeyOnly': True, 'leafSkiAndAkiRequired': True,
    'strictTls501BeforeInit': True, 'initializationMaximum': 1,
    'localReceiptGapAfterReturnedAck': True, 'networkLossNotClaimed': True,
    'unknownOriginalReceiptRetained': True, 'noUnknownPreimageReplay': True,
    'kernelLocalSinglePortNotIpv4Only': True, 'originalStrictClientFixedIpv4': True,
    'productionCredentialReads': 0, 'sdkImported': False, 'providerCalls': 0, 'productionActions': 0}
(HERE / 'manifest.public.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest, sort_keys=True))
