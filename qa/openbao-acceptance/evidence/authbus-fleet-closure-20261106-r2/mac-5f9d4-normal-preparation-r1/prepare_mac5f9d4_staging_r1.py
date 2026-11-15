#!/usr/bin/env python3
"""Prepare fixed, create-only staging; no remote process or upload is performed."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = HERE.parent / 'fixed-slot-coordinator-actual-work'
sha = lambda raw: hashlib.sha256(raw).hexdigest()
original = (BASE / 'launch_coordinator_actual_r1.py').read_bytes()
assert len(original) == 242236 and sha(original) == '0399270ee35c5c47d3431e263d9a338028393c1b4ebf09babbb23d9fa7923752'
tree = ast.parse(original)
old = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
           and any(isinstance(t, ast.Name) and t.id == 'PAYLOAD' for t in n.targets))
sources = {name: old['sources'][name] for name in ('mac_owned_commands_r1.py', 'mac_owned_unreaped_r1.py',
                                                'mac_public_code_pin_excerpt_r1.py')}
guard = old['sources']['mac_fixedslot_t5_guard_r1.py']
needle = "ROOT = MOUNT / 'hepta-vnext-recovery-20261013/fixed-slot-coordinator-normal-20261107-r1'"
assert guard.count(needle) == 1
changed = guard.replace(needle, "ROOT = MOUNT / 'hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1'")
sources['mac_normal_build_t5_guard_r1.py'] = changed
files = {'controller.original.py': (HERE / 'controller5f9d4.original.py').read_text(),
         'test-selection.public.json': (HERE / 'test-selection.public.json').read_text()}
pins = lambda values: {name: {'bytes': len(value.encode()), 'sha256': sha(value.encode())} for name, value in values.items()}
payload = {'sources': sources, 'pins': pins(sources), 'files': files, 'filePins': pins(files)}
body = (HERE / 'stage_mac5f9d4_sources_r1.body.py').read_text()
assert body.count('# PAYLOAD_PLACEHOLDER') == 1
source = body.replace('# PAYLOAD_PLACEHOLDER', 'PAYLOAD = ' + repr(payload))
parsed = ast.parse(source)
recovered = next(ast.literal_eval(n.value) for n in parsed.body if isinstance(n, ast.Assign)
    and any(isinstance(t, ast.Name) and t.id == 'PAYLOAD' for t in n.targets))
assert recovered == payload
for name, value in sources.items():
    compile(value, name, 'exec')
compile(source, 'stage_mac5f9d4_sources_r1.py', 'exec')
(HERE / 'stage_mac5f9d4_sources_r1.py').write_text(source)
(HERE / 'staging-t5-scope-only.diff').write_text(''.join(difflib.unified_diff(
    guard.splitlines(True), changed.splitlines(True), fromfile='qualified-fixedslot-guard', tofile='normal5f9d4-staging-guard')))
plan = {'schema': 'heptabao.mac-normal5f9d4-create-only-staging-preparation.r1', 'executed': False,
    'executionKey': 'heptabao-mac-normal-5f9d4-source-staging-20261107-r1',
    'launcher': {'bytes': len(source.encode()), 'sha256': sha(source.encode())},
    'body': {'bytes': len(body.encode()), 'sha256': sha(body.encode())},
    'helperPins': payload['pins'], 'publishedFiles': payload['filePins'],
    'fixedT5Uuid': 'FB804D1B-24CB-4D6E-AEA7-A9E180807758', 'expectedT5Device': '16777244',
    'helperChange': 'one ROOT literal only; original Commands/Unreaped/PublicCodePin byte-unchanged',
    'parentSeconds': 45, 'volumeObservationSeconds': 10, 'supervisorSeconds': 70,
    'newOutputDirectory': 'build-test-5f9d4-r1', 'createdFiles': 2,
    'sourceCheckoutNotPerformed': True, 'bundleUploadNotPerformed': True,
    'productProcesses': 0, 'compilerCommands': 0, 'currentCredentialReads': 0,
    'productionWrites': 0, 'normal107Qualified': False, 'directed15Qualified': False}
(HERE / 'staging-plan.public.json').write_text(json.dumps(plan, indent=2) + '\n')
print(json.dumps(plan, sort_keys=True))
