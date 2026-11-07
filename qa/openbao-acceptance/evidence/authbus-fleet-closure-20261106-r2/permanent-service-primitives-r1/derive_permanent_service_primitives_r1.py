#!/usr/bin/env python3
"""Prepare an exact-label permanent-service lifecycle adapter; no remote I/O.

The actual preserve-absent QA already proved the four launchd operations. This
derivation supplies the permanent normal server and corrected LAN config, and
adds same-parent API checkpoints. It is not an installation or execution.
"""
import ast
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = HERE.parent / 'authbus-refresh-work/mac_gateway_preserve_absent_primitives_r1.py'
raw = BASE.read_bytes()
assert len(raw) == 15375
assert hashlib.sha256(raw).hexdigest() == '32a471e45de11c653aa3eac3a2a76c7f8dea3da2666bea326f25e87f2f9fda48'
before = raw.decode()
after = before


def change(old, new, count=1):
    global after
    assert after.count(old) == count, (old, after.count(old))
    after = after.replace(old, new)


change('''"""Four once-only actions preserve an absent disabled override.

One new credential-free label uses KeepAlive=true and the same original plist
for both cold generations. No disable/enable command is available. Unknown
state dispatches no compensation; a remaining KeepAlive registration is
reported and requires reconciliation of its original identity. This is not a
production gateway, cold-credential-consumption, or full-state rollback proof.
"""''', '''"""Two cold generations of the exact new permanent HeptaBao label.

Prepared adapter only. The same parent must bind the complete normal binary,
corrected server config, TLS files, existing initialized data and separate key
custody before supplying runtime_fence and phase_action. It must require the
label and disabled override to be originally absent. The same create-only plist
is used for both generations. It is outside the autoload directory.

phase_action may only perform the bounded permanent-service TLS lifecycle on
the original existing initialized store, with its original key; never init,
provider refresh, OpenClaw client changes or unknown-request replay. It receives
the same original absolute deadline and actual bound service birth. Sealed
startup followed by explicit same-parent unseal is deliberate. No automatic
unseal daemon or new production client is introduced.

No disable/enable action exists. On failure, public() records whether the exact
registration may remain. The outer must reconcile that original action/birth;
this prepared adapter does not authorize compensating mutations after UNKNOWN.
"""''')
change("ROOT=Path('/Users/qianqi/heptabao-authbus-preserve-absent-20261106-r1')", """ROOT=Path('/Users/qianqi/heptabao-authbus-production-custody/service-lifecycle-r1')
RUNTIME=Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-authbus-production')
PRODUCT='4bde9aee03fcd27c59e13607e529b1cee594b249'
SERVER_BINARY=str(RUNTIME/'releases'/PRODUCT/'heptabao-server')
CONFIG=RUNTIME/'etc/server-r2.json'""")
change("LABEL='org.heptabao.qa.preserve-absent-20261106-r1'", "LABEL='org.heptabao.authbus'")
change("SLEEP='/bin/sleep'\nARGS=[SLEEP,'30']", "ARGS=[SERVER_BINARY,'--config',str(CONFIG)]")
after = after.replace('SLEEP', 'SERVER_BINARY')
change('def __init__(self,*,commands,reader,bsd_info,parse_print,missing_service,until,runtime_fence):',
       'def __init__(self,*,commands,reader,bsd_info,parse_print,missing_service,until,runtime_fence,phase_action):')
change("self.root_identity=identity(ROOT.lstat());self.events=[];self.mutations={};self.identities=[]", """need(callable(runtime_fence) and callable(phase_action),'permanent_service_actual_parent_callbacks')
  self.phase_action=phase_action
  self.root_identity=identity(ROOT.lstat());self.events=[];self.mutations={};self.identities=[]""")
change("'schema':'heptabao.mac-preserve-absent-service-primitives.r1'", "'schema':'heptabao.mac-permanent-service-primitives.r1'")
change("'productionServiceChanged':False,'providerCalls':0,'credentialReads':0,'configurationReads':0,", "'registeredOpenClawServiceChanged':False,'providerCalls':0,'existingPermanentStoreScope':True,")
change("'keepAliveTrueSyntheticServiceOnly':True,'actualGatewayRegistrationQualified':False,", "'keepAliveTruePermanentServerOnly':True,'autoloadPlistInstalled':False,'actualGatewayRegistrationQualified':False,")
change("'WorkingDirectory':str(ROOT),'StandardOutPath':str(ROOT/'service.stdout.private'),", """'WorkingDirectory':str(RUNTIME),'EnvironmentVariables':{'HOME':'/Users/qianqi',
    'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C','LC_ALL':'C'},
   'ThrottleInterval':10,'ExitTimeOut':30,'Umask':0o077,
   'StandardOutPath':str(ROOT/'service.stdout.private'),""")
change("need(self.disabled() is None,'first_running_override_absent')", """need(self.disabled() is None,'first_running_override_absent')
  self.phase_action('first',dict(first),self.until)
  self.same_running('first')""")
change("need(self.disabled() is None,'cold_restored_override_absent')", """need(self.disabled() is None,'cold_restored_override_absent')
  self.phase_action('recovery',dict(second),self.until)
  self.same_running('recovery')""")
change("'exact_synthetic_service_registration'", "'exact_permanent_service_registration'")
after = after.replace('owned_sleep', 'owned_permanent_server').replace('single_sleep', 'single_permanent_server')
after = after.replace('same_sleep', 'same_permanent_server')
after = after.replace('owned sleep', 'owned permanent server')
change("productionGatewayOrRollbackQualified=False)", "productionGatewayOrRollbackQualified=False,permanentServiceApiQualificationBelongsToOriginalParent=True)")
ast.parse(after)
target = HERE / 'mac_permanent_service_primitives_r1.py'
target.write_text(after)
diff = ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
    fromfile='actual-qualified-preserve-absent-r1', tofile='prepared-permanent-service-r1'))
(HERE / 'preserve-absent-to-permanent-service-r1.diff').write_text(diff)
manifest = {
    'schema':'heptabao.permanent-service-primitives-preparation.r1',
    'preparedOnly':True,'actualExecuted':False,'autoloadInstalled':False,
    'source':{'bytes':len(after.encode()),'sha256':hashlib.sha256(after.encode()).hexdigest()},
    'qualifiedOriginal':{'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
        'actualJob':'1a1b3d6ebd5-fc05-8503','actualHost':'mac'},
    'productCommit':'4bde9aee03fcd27c59e13607e529b1cee594b249',
    'normalBinarySha256':'5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c',
    'serviceLabel':'org.heptabao.authbus','serviceDomain':'gui/501',
    'correctedConfig':'/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-authbus-production/etc/server-r2.json',
    'parentBudgetSeconds':45,'originalHelperSeconds':4,'originalStartupSeconds':5,
    'exactFourActionGraph':['bootstrap-first','bootout-first','bootstrap-recovery','bootout-recovery'],
    'disabledOverrideMustRemainAbsent':True,'noDisableEnableOperation':True,
    'existingStoreMustNotBeInitializedAgain':True,'sameOriginalKeyExplicitUnseal':True,
    'automaticUnsealIntroduced':False,'phaseCallbackHasSameAbsoluteDeadline':True,
    'twoGenerationFinalKnownAbsenceRequired':True,
    'outerRequired':['fresh full source and data/key custody','strict TLS phase lifecycle',
        'known original-action failure reconciliation and closure','complete raw native receipts'],
    'productionOpenClawClientsChanged':0,'providerCalls':0,'legacyDeletion':0,
    'qualifiesPermanentProductionOperation':False,
}
(HERE / 'permanent-service-primitives-r1.manifest.public.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest,sort_keys=True))
