#!/usr/bin/env python3
"""Source-bind a read-only inventory; never execute it or read private input."""
import ast
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
AUDIT = HERE.parent / 'authbus-refresh-work'
SDK_QA = HERE.parent / 'main3-sdk-outer-r4-work/source-sdk-r4'
sha = lambda raw: hashlib.sha256(raw).hexdigest()
sources = {name: (HERE / name).read_text() for name in (
    'capture_current_database_inventory_r2.py', 'mac_current_database_inventory_r1.py')}
for name in ('mac_current_gateway_observation_r2.py', 'mac_gateway_local_fallback_r1.py'):
    sources[name] = (AUDIT / name).read_text()
dependencies = json.loads((AUDIT / 'current-gateway-observer-dependencies.public.json').read_bytes())
for item in dependencies['sources']:
    raw = Path(item['localSource']).read_bytes()
    assert len(raw) == item['bytes'] and sha(raw) == item['sha256']
    sources[item['file']] = raw.decode()
    if item['definitions']:
        nodes = [node for node in ast.parse(raw).body
                 if isinstance(node, (ast.FunctionDef, ast.ClassDef))
                 and node.name in item['definitions']]
        assert {node.name for node in nodes} == set(item['definitions'])
        assert sha(ast.dump(ast.Module(body=nodes, type_ignores=[]),
                            include_attributes=False).encode()) == item['excerptAstSha256']
assert sha(sources['mac_current_gateway_observation_r2.py'].encode()) == 'bc558d3c58d81db4c16cad25e728512564931c2b32b9fb7c10ebc915a7036ecb'
for name, source in sources.items():
    compile(source, name, 'exec')
prior = ast.literal_eval(next(node.value for node in ast.parse(
    (HERE.parent / 'mac-rollout-source-work/launch_mac_whole_sqlite_qualification_r1.py').read_bytes()).body
    if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
        and target.id == 'PAYLOAD' for target in node.targets)))
capture = json.loads((AUDIT / 'fresh-capsule-r2/payload.public.json').read_bytes())
payload = {'sources': sources, 'sourcePins': {name: sha(raw.encode()) for name, raw in sources.items()},
           'custodyQualificationAuthority': prior['custodyQualificationAuthority'],
           'registryProof': capture['registryProof'], 'registryAuthority': capture['registryAuthority']}
assert len(payload['registryProof'].encode()) == 62662
assert sha(payload['registryProof'].encode()) == '7d08a18c21a5d754ea9fbe7711e6315daf8fbd80c7b5a6937756fea7ba4d1c82'
assert len(payload['registryAuthority'].encode()) == 733
assert sha(payload['registryAuthority'].encode()) == 'b564093e2300cdc44b2ae4724e869d5b24bfe3d94d269f8ebfa977e08b07505f'
template = (HERE / 'launch_current_database_inventory_r2.template.py').read_text()
assert template.count('# PAYLOAD_PLACEHOLDER') == 1
assembled = template.replace('# PAYLOAD_PLACEHOLDER', 'PAYLOAD=' + repr(payload))
compile(assembled, 'launch_current_database_inventory_r2.py', 'exec')
parsed = ast.literal_eval(next(node.value for node in ast.parse(assembled).body
    if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
        and target.id == 'PAYLOAD' for target in node.targets)))
assert parsed == payload
(HERE / 'launch_current_database_inventory_r2.py').write_text(assembled)
manifest = {'schema': 'heptabao.current-production-source-inventory-preparation.public.r2',
    'sourcePins': payload['sourcePins'], 'launcherBytes': len(assembled.encode()),
    'launcherSha256': sha(assembled.encode()), 'sharedSeconds': 45, 'supervisorSeconds': 70,
    'inventoryOriginalChildren': 1, 'gatewayOriginalPrintCount': 2,
    'memoryOriginalCommandCount': 1, 'gatewayPrintMaximumSeconds': 8,
    'memoryCommandMaximumSeconds': 3, 'productionWrites': 0, 'credentialRowsRead': 0,
    'providerCalls': 0, 'serviceMutations': 0, 'fullConsumerCoverageProven': False,
    'runningPluginMemoryFlagsProven': False,
    'registryPathsGrantAdditionalDatabaseOpenAuthority': False,
    'configuredAgentPathResolutionExecuted': False,
    'publicScope': 'ordinal metadata, scalar memory, finite registered gateway family, source-code pins'}
(HERE / 'current-inventory-manifest.public.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
print(json.dumps(manifest, sort_keys=True))
