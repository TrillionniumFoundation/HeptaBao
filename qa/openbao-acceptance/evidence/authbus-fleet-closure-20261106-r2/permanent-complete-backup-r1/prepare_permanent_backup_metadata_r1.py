#!/usr/bin/env python3
"""Assemble a bounded metadata-only view of the stopped new permanent store."""
import ast
import hashlib
import json
from pathlib import Path

WORK = Path(__file__).resolve().parent
old = (WORK / 'bootstrap_permanent_authbus_r1.py').read_bytes()
assert len(old) == 82208 and hashlib.sha256(old).hexdigest() == '709e228b497f84ed93df0b30bc484d60350a76b9d44944bdd951b0bb077482c7'
payload = next(ast.literal_eval(n.value) for n in ast.parse(old).body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'PAYLOAD' for t in n.targets))
names = ('mac_owned_unreaped_r1.py', 'mac_owned_commands_r1.py', 'mac_production_t5_guard_r1.py', 'mac_public_code_pin_excerpt_r1.py')
payload = {key: {name: payload[key][name] for name in names} for key in ('sources', 'pins')}
name = 'complete_cold_tree_backup_r1.py'; raw = (WORK / name).read_bytes()
assert len(raw) == 17361 and hashlib.sha256(raw).hexdigest() == '18c3e53d8bc1e0c068dd5ad0a1f0438f89abca705c54af20e61152d985916a38'
payload['sources'][name] = raw.decode(); payload['pins'][name] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
prefix = (WORK / 'bootstrap_permanent_authbus_r1.template.py').read_text().split('def binary_pin():', 1)[0]
prefix = prefix.replace("OPERATIONS = CUSTODY / 'bootstrap-r1'", "OPERATIONS = CUSTODY / 'backup-metadata-r1'")
prefix = prefix.replace('UNTIL = START + 300', 'UNTIL = START + 30')
prefix = prefix.replace('# PAYLOAD_PLACEHOLDER', 'PAYLOAD = ' + repr(payload))
start = prefix.index('REPORT = {'); end = prefix.index('\n\nclass Refused', start)
prefix = prefix[:start] + '''REPORT = {'schema': 'heptabao.permanent-backup-metadata.r1', 'ok': False,
    'sourceDataFileContentsRead': 0, 'privateCredentialReads': 0, 'networkRequests': 0,
    'providerCalls': 0, 'serviceActions': 0, 'sourceWrites': 0, 'backupExecuted': False,
    'productionBackupQualified': False, 'automaticRetry': False,
    'parentSeconds': 30, 'supervisorSeconds': 45}
''' + prefix[end:]
source = prefix + '\n' + (WORK / 'permanent_backup_metadata_r1.body.py').read_text()
ast.parse(source)
(WORK / 'permanent_backup_metadata_r1.py').write_text(source)
manifest = {'schema': 'heptabao.permanent-backup-metadata-source.r1', 'actualExecuted': False,
    'launcherBytes': len(source.encode()), 'launcherSha256': hashlib.sha256(source.encode()).hexdigest(),
    'sources': payload['pins'], 'scope': 'exact newly initialized permanent data subtree metadata under held nofollow directory descriptors and a nonblocking directory lock',
    'fileContentsRead': 0, 'commands': ['fixed diskutil info'], 'serverStarts': 0,
    'parentSeconds': 30, 'supervisorSeconds': 45,
    'doesNotClaimRustWriterLockInteroperability': True}
(WORK / 'permanent-backup-metadata-r1.source.public.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest))
