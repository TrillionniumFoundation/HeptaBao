#!/usr/bin/env python3
"""Prepare only the observed SBPL correction in a separate SDK attempt."""
import ast,difflib,hashlib,json,subprocess,sys
from pathlib import Path
BASE=Path('/workspace/scratch/c9fe536787d9')
OLD=BASE/'main3-sdk-outer-r2-work'
NEW=BASE/'main3-sdk-outer-r3-work'
OLD_ROOT='/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r2'
NEW_ROOT=OLD_ROOT.removesuffix('-r2')+'-r3'
manifest=json.loads((OLD/'manifest-sdk-r2.public.json').read_bytes())
phase=(OLD/'main3_sdk_phase.py').read_text()
assert hashlib.sha256(phase.encode()).hexdigest()==manifest['sourcePins']['main3_sdk_phase.py']['sha256']=='2ae860ba7fbfef5c48254cd74f0800fcd5ddc341653a7965c1d31c889397a910'
NEW.mkdir(exist_ok=False)
old_rule="        lines.append('(allow network-outbound (remote ip '+json.dumps('127.0.0.1:'+str(port))+'))')"
new_rule="        # Actual SBPL allows one port across this machine's local addresses.\n        # The original wire separately pins IPv4 127.0.0.1, CA and leaf identity.\n        # This is not a claim of a kernel-only IPv4 destination restriction.\n        lines.append('(allow network-outbound (remote tcp '+json.dumps('localhost:'+str(port))+'))')"
assert phase.count(old_rule)==1
phase=phase.replace(OLD_ROOT,NEW_ROOT).replace(old_rule,new_rule)
ast.parse(phase);(NEW/'main3_sdk_phase.py').write_text(phase)
seed=(OLD/'main3_sdk_seed_r1.mjs').read_text()
assert seed.count(OLD_ROOT)==1
(NEW/'main3_sdk_seed_r1.mjs').write_text(seed.replace(OLD_ROOT,NEW_ROOT))
for name in ('test_main3_sdk_seed_r1.mjs','mount-public-pin.json'):
 (NEW/name).write_bytes((OLD/name).read_bytes())
builder=(OLD/'build_main3_sdk_outer_r2.py').read_text()
for before,after in (
 ('main3-sdk-outer-r2-work','main3-sdk-outer-r3-work'),
 ('20261106-r2','20261106-r3'),
 ('sdk-r2','sdk-r3'),
 ('prepare_main3_sdk_r2.bound.py','prepare_main3_sdk_r3.bound.py'),
 ('heptabao.mac-main3-sdk-preparation-terminal.r2','heptabao.mac-main3-sdk-preparation-terminal.r3'),
 ('heptabao.mac-main3-sdk-preparation.r2','heptabao.mac-main3-sdk-preparation.r3'),
 ('heptabao.mac-main3-sdk-journal.r2','heptabao.mac-main3-sdk-journal.r3'),
 ('heptabao.mac-main3-current-sdk-qualification.r2','heptabao.mac-main3-current-sdk-qualification.r3'),
 ('heptabao.mac-main3-sdk-outer-preparation.r2','heptabao.mac-main3-sdk-outer-preparation.r3'),
 ('1a1b23ee0d9-fc05-7d25','1a1b263a649-fc05-7dda')):
 builder=builder.replace(before,after)
old="'sandboxChange':'only actual-qualified literal directory read chain; no extra subpath, write, network, cwd or environment grant',\n  'sandboxAuthorityJob':'1a1b254ed7d-fc05-7d90'"
new="'sandboxChange':'one actual-qualified SBPL tcp localhost port; kernel local-address scope and original exact IPv4/CA/leaf wire fence are distinct',\n  'kernelIpv4OnlyDestinationClaimed':False,'kernelLocalLanDeniedClaimed':False,\n  'wireEndpointAndTrustCodeUnchanged':True,'localAddressScopeObserved':True,\n  'directoryLiteralAuthorityJob':'1a1b254ed7d-fc05-7d90',\n  'sandboxAuthorityJob':'1a1b27ad919-fc05-7e36',\n  'sandboxAuthorityResultSha256':'9f389465f8df39807c6718a93bf34d1384838e35f76d07bccb60c4008da4ab43',\n  'priorFailedScopeProbeJob':'1a1b271da51-fc05-7e0a'"
assert builder.count(old)==1
builder=builder.replace(old,new)
ast.parse(builder);(NEW/'build_main3_sdk_outer_r3.py').write_text(builder)
r=subprocess.run([sys.executable,str(NEW/'build_main3_sdk_outer_r3.py')],cwd=NEW,capture_output=True,text=True,timeout=30)
assert r.returncode==0,(r.stdout,r.stderr)
new_manifest=json.loads((NEW/'manifest-sdk-r3.public.json').read_bytes())
assert new_manifest['nodeWireSourceUnchanged'] is True
assert new_manifest['sandboxAuthorityJob']=='1a1b27ad919-fc05-7e36'
assert new_manifest['inlineCaptureOperationKey'].endswith('sdk-inline-capture-20261106-r3')
assert new_manifest['budgets']==manifest['budgets']
parts=[]
for name in ('build_main3_sdk_outer_r3.py','main3_sdk_phase.py','main3_sdk_seed_r1.mjs'):
 oldname=name.replace('outer_r3','outer_r2')
 parts.extend(difflib.unified_diff((OLD/oldname).read_text().splitlines(True),(NEW/name).read_text().splitlines(True),fromfile='frozen-sdk-r2/'+oldname,tofile='new-sdk-r3/'+name))
(NEW/'sdk-r2-to-r3-minimal.diff').write_text(''.join(parts))
print(json.dumps({'prepared':True,'root':str(NEW),'staging':new_manifest['staging'],
 'phase':new_manifest['sourcePins']['main3_sdk_phase.py'],
 'controller':new_manifest['sourcePins']['main3_sdk_controller.py'],
 'preparer':new_manifest['preparer'],'actualMacExecuted':False}))
