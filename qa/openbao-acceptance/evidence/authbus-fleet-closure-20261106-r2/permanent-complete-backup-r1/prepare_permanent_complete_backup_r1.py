#!/usr/bin/env python3
"""Freeze full-runtime backup, original writer-fence proof and cold recovery."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

WORK = Path(__file__).resolve().parent
original = (WORK / 'bootstrap_permanent_authbus_r2.py').read_bytes()
assert len(original) == 82341 and hashlib.sha256(original).hexdigest() == '2780c5fcef1aebd7b7fffa406af39521dc9cab02c372321df9ef4322bab46422'
payload = next(ast.literal_eval(n.value) for n in ast.parse(original).body
               if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'PAYLOAD' for t in n.targets))
old_api = payload['sources'].pop('permanent_bootstrap_api_r1.py')
payload['pins'].pop('permanent_bootstrap_api_r1.py')
api = old_api.replace("phase in ('initial','cold-new-process')", "phase in ('locked-positive','recovered','recovered-cold')")
api = api.replace("self.context=ssl.create_default_context(cafile=str(ROOT/'tls/ca.crt'))", """need(plan.get('caFile') in (
            str(ROOT/'tls/ca.crt'),
            '/Users/qianqi/heptabao-authbus-production-recovery-20261107-r1/runtime/tls/ca.crt'),
             'fixed_original_or_restored_ca_path')
        self.context=ssl.create_default_context(cafile=plan['caFile'])""")
assert api != old_api
ast.parse(api)
(WORK / 'permanent_recovery_api_r1.py').write_text(api)
(WORK / 'bootstrap-to-recovery-api-r1.diff').write_text(''.join(difflib.unified_diff(
    old_api.splitlines(True), api.splitlines(True), fromfile='qualified-bootstrap-api', tofile='complete-recovery-api')))
for name, text in (('permanent_recovery_api_r1.py', api),
                   ('complete_cold_tree_backup_r2.py', (WORK / 'complete_cold_tree_backup_r2.py').read_text())):
    payload['sources'][name] = text
    payload['pins'][name] = {'bytes': len(text.encode()), 'sha256': hashlib.sha256(text.encode()).hexdigest()}
prefix = (WORK / 'bootstrap_permanent_authbus_r2.template.py').read_text().split('def main():', 1)[0]
start = prefix.index('"""'); end = prefix.index('"""', start + 3)
prefix = prefix[:start] + '''"""Back up the initialized complete runtime and prove independent cold recovery.

The original initialized store is never initialized or reset. Its actual data
writer fence remains held across copying and restored lifecycle checks. The
restored binary and TLS materials come from the complete backup; the existing
separate HOME custody supplies the original unseal/root material privately.
No current client credential, provider, service registration or legacy action.
"""''' + prefix[end + 3:]
prefix = prefix.replace("OPERATIONS = CUSTODY / 'bootstrap-r2'", """OPERATIONS = CUSTODY / 'complete-backup-r1'
BACKUPS = CALLER_HOME / 'heptabao-authbus-production-backups'
BACKUP_ROUND = BACKUPS / 'complete-20261107-r1'
RECOVERY = CALLER_HOME / 'heptabao-authbus-production-recovery-20261107-r1'""")
prefix = prefix.replace("phase in ('initial', 'cold-new-process')", "phase in ('locked-positive', 'recovered', 'recovered-cold')")
prefix = prefix.replace("    '/bin/ps': (170432,", "    '/usr/bin/sandbox-exec': (None, 'abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a'),\n    '/bin/ps': (170432,")
start = prefix.index('REPORT = {'); end = prefix.index('\n\nclass Refused', start)
prefix = prefix[:start] + """REPORT = {'schema': 'heptabao.permanent-complete-runtime-backup.r1', 'ok': False,
    'productCommit': PRODUCT, 'automaticRetry': False, 'initializationRequests': 0,
    'currentCredentialReads': 0, 'providerCalls': 0, 'legacyChanges': 0,
    'productionClientChanges': 0, 'launchAgentInstalled': False, 'j3160Requests': 0,
    'rootKeyValuesOrDigestsPublished': False, 'backupManifestPublic': False,
    'productionCutoverQualified': False, 'productionBackupQualified': False,
    'parentSeconds': 300, 'supervisorSeconds': 330, 'eachApiPhaseSeconds': 120,
    'originalPermanentBootstrapJob': '1a1b396b21c-fc05-83b9',
    'serverProcesses': [], 'apiPhases': [], 'copyPhases': []}
""" + prefix[end:]
source = prefix + (WORK / 'permanent_complete_backup_r1.body.py').read_text()
ast.parse(source)
(WORK / 'permanent_complete_backup_r1.template.py').write_text(source)
assert source.count('# PAYLOAD_PLACEHOLDER') == 1
assembled = source.replace('# PAYLOAD_PLACEHOLDER', 'PAYLOAD = ' + repr(payload))
ast.parse(assembled)
(WORK / 'permanent_complete_backup_r1.py').write_text(assembled)
manifest = {'schema': 'heptabao.permanent-complete-runtime-backup-source.r1', 'actualExecuted': False,
    'launcher': {'bytes': len(assembled.encode()), 'sha256': hashlib.sha256(assembled.encode()).hexdigest()},
    'sources': payload['pins'], 'parentSeconds': 300, 'supervisorSeconds': 330,
    'actualOriginalNormalServerLockProofRequired': True, 'originalDataLockHeldThroughCopyRestoreAndColdLifecycle': True,
    'fullRuntimeTreeNoExclusions': True, 'newBackupAndRecoveryDirectoriesOnly': True,
    'restoredExecutableFromBackup': True, 'kernelDenyOriginalT5RuntimeRequired': True,
    'originalSeparateHomeUnsealCustodyRequired': True, 'currentCredentialOrProviderActions': 0,
    'productionBackupQualified': False}
(WORK / 'permanent-complete-backup-r1.source.public.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest))
