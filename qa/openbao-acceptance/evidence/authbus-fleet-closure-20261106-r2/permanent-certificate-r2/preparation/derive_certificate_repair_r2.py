#!/usr/bin/env python3
"""Freeze a create-only certificate correction; this file does not run it."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

WORK = Path(__file__).resolve().parent
original = (WORK / 'bootstrap_permanent_authbus_r1.py').read_bytes()
assert len(original) == 82208 and hashlib.sha256(original).hexdigest() == '709e228b497f84ed93df0b30bc484d60350a76b9d44944bdd951b0bb077482c7'
tree = ast.parse(original)
payload = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'PAYLOAD' for t in n.targets))
names = ('mac_owned_unreaped_r1.py', 'mac_owned_commands_r1.py', 'mac_production_t5_guard_r1.py', 'mac_public_code_pin_excerpt_r1.py')
payload = {key: {name: payload[key][name] for name in names} for key in ('sources', 'pins')}
template = (WORK / 'bootstrap_permanent_authbus_r1.template.py').read_text()
prefix = template.split('def binary_pin():', 1)[0]
prefix = prefix.replace("OPERATIONS = CUSTODY / 'bootstrap-r1'", "OPERATIONS = CUSTODY / 'certificate-r2'")
prefix = prefix.replace('UNTIL = START + 300', 'UNTIL = START + 120')
prefix = prefix.replace('# PAYLOAD_PLACEHOLDER', 'PAYLOAD = ' + repr(payload))
prefix = prefix.replace("    '/bin/ps':", "    '/usr/bin/openssl': (1130832, 'f81b4fcec5048ea1eceb40fc08f4e06f1668181f0b5bacfa8be27d0da181dcb7'),\n    '/bin/ps':")
start = prefix.index("REPORT = {")
end = prefix.index('\n\nclass Refused', start)
prefix = prefix[:start] + '''REPORT = {'schema': 'heptabao.permanent-certificate-correction.r2', 'ok': False,
    'originalBootstrapJob': '1a1b386a389-fc05-836f', 'automaticRetry': False,
    'currentCredentialReads': 0, 'providerCalls': 0, 'httpRequests': 0,
    'serverProcessesStarted': 0, 'launchAgentInstalled': False, 'legacyChanges': 0,
    'privateKeyValuesOrDigestsPublished': False, 'parentSeconds': 120,
    'supervisorSeconds': 150, 'tlsVerificationRelaxed': False}
''' + prefix[end:]
body = (WORK / 'certificate_repair_r2.body.py').read_text()
source = prefix + '\n' + body
ast.parse(source)
(WORK / 'certificate_repair_r2.py').write_text(source)
manifest = {'schema': 'heptabao.permanent-certificate-correction-source.r2',
    'actualExecuted': False, 'launcherBytes': len(source.encode()),
    'launcherSha256': hashlib.sha256(source.encode()).hexdigest(),
    'originalBootstrapBytes': len(original), 'originalBootstrapSha256': hashlib.sha256(original).hexdigest(),
    'unchangedQualifiedSources': payload['pins'], 'parentSeconds': 120, 'supervisorSeconds': 150,
    'createdFilesOnly': True, 'sameCaAndServerPrivateKey': True,
    'oldLeafStrictMemoryBioMustFailWithVerifyCode': 85,
    'newLeafDefaultStrictMemoryBioMustSucceed': True,
    'serverStartOrApiRequestOrStoreInit': False}
(WORK / 'certificate-repair-r2.manifest.public.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest))
