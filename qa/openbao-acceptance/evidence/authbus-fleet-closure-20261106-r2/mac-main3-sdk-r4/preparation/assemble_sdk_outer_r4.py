#!/usr/bin/env python3
"""Create a source-bound SDK r4 draft from the exact frozen SDK r3 package."""
import ast,base64,difflib,hashlib,json
from pathlib import Path

BASE=Path('/workspace/scratch/c9fe536787d9')
OLD=BASE/'main3-sdk-outer-r3-work'
NEW=BASE/'main3-sdk-outer-r4-work'
WIRE=BASE/'main3-sdk-wire-r3-work/main3_sdk_wire_r3.mjs'
OLD_MANIFEST_SHA='139be10ee23d51d572e9e4d190ecddd152194b4772e492290afaf7724b5e5b53'
OLD_BUNDLE_SHA='8cb911179b5e53822e364c467f10bf13cc0a23da833ee21ae3a12e124417adee'
WIRE_SHA='e80c7eb22e2cd2fbc547eb085b8eb0b482e8e656baa8a59520e0cb93a4c0396c'
OLD_ROOT='/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r3'
NEW_ROOT=OLD_ROOT.removesuffix('-r3')+'-r4'
CHANGES=(
 ('mac-authbus-main3-sdk-preparation-20261106-r3','mac-authbus-main3-sdk-preparation-20261106-r4'),
 ('mac-authbus-main3-sdk-journal-20261106-r3','mac-authbus-main3-sdk-journal-20261106-r4'),
 ('mac-authbus-main3-sdk-20261106-r3','mac-authbus-main3-sdk-20261106-r4'),
 ('main3-sdk-inline-capture-20261106-r3','main3-sdk-inline-capture-20261106-r4'),
 ('heptabao-authbus-main3-sdk-inline-capsule-20261106-r3','heptabao-authbus-main3-sdk-inline-capsule-20261106-r4'),
 ('heptabao.mac-main3-sdk-preparation-terminal.r3','heptabao.mac-main3-sdk-preparation-terminal.r4'),
 ('heptabao.mac-main3-sdk-preparation.r3','heptabao.mac-main3-sdk-preparation.r4'),
 ('heptabao.mac-main3-sdk-journal.r3','heptabao.mac-main3-sdk-journal.r4'),
 ('heptabao.mac-main3-current-sdk-qualification.r3','heptabao.mac-main3-current-sdk-qualification.r4'),
 ('heptabao.current-sdk-selected-capsule-inline-owned-observation.sdk-r3','heptabao.current-sdk-selected-capsule-inline-owned-observation.sdk-r4'),
 ('heptabao.current-sdk-selected-capsule-readonly.sdk-r3','heptabao.current-sdk-selected-capsule-readonly.sdk-r4'),
)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(raw):return {'bytes':len(raw),'sha256':sha(raw)}
def revise(text):
 for before,after in CHANGES:text=text.replace(before,after)
 return text
def assignment(text,name,value):
 nodes=[n for n in ast.parse(text).body if isinstance(n,ast.Assign)
  and any(isinstance(t,ast.Name) and t.id==name for t in n.targets)]
 assert len(nodes)==1,(name,len(nodes))
 node=nodes[0];lines=text.splitlines(True)
 lines[node.lineno-1:node.end_lineno]=[name+'='+repr(value)+'\n']
 return ''.join(lines)
def once(text,before,after):
 assert text.count(before)==1,(before[:80],text.count(before))
 return text.replace(before,after)
manifest_raw=(OLD/'manifest-sdk-r3.public.json').read_bytes()
old_raw=(OLD/'staging-sdk-r3.public.json').read_bytes()
wire_raw=WIRE.read_bytes()
assert sha(manifest_raw)==OLD_MANIFEST_SHA
assert sha(old_raw)==OLD_BUNDLE_SHA
assert sha(wire_raw)==WIRE_SHA
old_manifest=json.loads(manifest_raw);base=json.loads(old_raw)
assert set(base)=={'sources','assets','preparerSource'}
for key,pins in (('sources','sourcePins'),('assets','assetPins')):
 assert set(base[key])==set(old_manifest[pins])
 for name,text in base[key].items():assert pin(text.encode())==old_manifest[pins][name],name
assert pin(base['preparerSource'].encode())==old_manifest['preparer']
sources={name:revise(text) for name,text in base['sources'].items()}

pieces=''.join(ast.literal_eval(ast.parse(base['sources'][name]).body[0].value)
 for name in sorted(base['sources']) if name.startswith('main3_capture_payload_'))
old_payload=base64.b64decode(pieces,validate=True)
assert sha(old_payload)==old_manifest['capturePins']['CAPTURE_PAYLOAD_SHA']
payload=json.loads(old_payload)
for name in ('worker','registryChild'):payload[name]=revise(payload[name])
payload_raw=(json.dumps(payload,sort_keys=True,separators=(',',':'))+'\n').encode()
text64=base64.b64encode(payload_raw).decode();part_pins={}
for i,start in enumerate(range(0,len(text64),60000)):
 name='main3_capture_payload_'+str(i)+'.py';text='DATA='+repr(text64[start:start+60000])+'\n'
 sources[name]=text;part_pins[name]=pin(text.encode())
assert set(part_pins)=={n for n in sources if n.startswith('main3_capture_payload_')}
launcher=assignment(sources['main3_capture_launcher.py'],'PAYLOAD_PART_PINS',part_pins)
launcher=once(launcher,old_manifest['capturePins']['CAPTURE_PAYLOAD_SHA'],sha(payload_raw))
sources['main3_capture_launcher.py']=launcher
capture_pins={'CAPTURE_WORKER_SHA':sha(payload['worker'].encode()),
 'CAPTURE_LAUNCHER_SHA':sha(launcher.encode()),'CAPTURE_GUARD_SHA':sha(payload['guard'].encode()),
 'CAPTURE_REGISTRY_SHA':sha(payload['registryChild'].encode()),'CAPTURE_PAYLOAD_SHA':sha(payload_raw)}
inline=sources['main3_inline_capture.py']
for name,value in capture_pins.items():inline=assignment(inline,name,value)
inline=assignment(inline,'OPERATION_KEY','heptabao-mac-authbus-main3-sdk-inline-capture-20261106-r4')
sources['main3_inline_capture.py']=inline

assets={name:revise(text) for name,text in base['assets'].items()}
assert 'qa/main3_sdk_wire_r3.mjs' not in assets
assert sha(assets.pop('qa/main3_sdk_wire_r2.mjs').encode())=='2b06342e30703611729788a522ba764ae30adfe1e47c4f4673b7aa8f647170e2'
assets['qa/main3_sdk_wire_r3.mjs']=wire_raw.decode()
cycle=assets['qa/main3_sdk_cycle_r2.mjs']
assert cycle.count('main3_sdk_wire_r2.mjs')==2
assets['qa/main3_sdk_cycle_r2.mjs']=cycle.replace('main3_sdk_wire_r2.mjs','main3_sdk_wire_r3.mjs')
phase=sources['main3_sdk_phase.py']
phase=once(phase,'main3_sdk_wire_r2.mjs','main3_sdk_wire_r3.mjs')
sources['main3_sdk_phase.py']=phase
asset_pins={name:pin(text.encode()) for name,text in assets.items()}
sources['main3_sdk_public_pins.py']=assignment(sources['main3_sdk_public_pins.py'],'ASSET_PINS',asset_pins)
source_pins={name:pin(text.encode()) for name,text in sources.items()}
preparer=revise(base['preparerSource'])
preparer=assignment(preparer,'EXPECTED_PINS',source_pins)
preparer=assignment(preparer,'EXPECTED_ASSETS',asset_pins)
for name,text in sources.items():ast.parse(text,filename=name)
ast.parse(preparer)
assert OLD_ROOT not in json.dumps(sources)
assert all(old not in json.dumps(payload) for old,new in CHANGES if 'capsule' in old)
assert set(sources)==set(base['sources']) and len(sources)==27 and len(assets)==13
for name,text in assets.items():
 if name.startswith('plugin/'):assert text==base['assets'][name]
bundle={'sources':sources,'assets':assets,'preparerSource':preparer}
raw=json.dumps(bundle,separators=(',',':')).encode()
assert len(raw)<=1048576
result=dict(old_manifest)
result.update(schema='heptabao.mac-main3-sdk-outer-preparation.r4',status='prepared-not-executed',
 sourcePins=source_pins,assetPins=asset_pins,capturePins=capture_pins,preparer=pin(preparer.encode()),staging=pin(raw),
 nodeWireSourceUnchanged=False,wireEndpointAndTrustCodeUnchanged=False,
 wireEndpointConfigurationUnchanged=True,wireResponsePeerValidationChanged=True,
 inlineCaptureOperationKey='heptabao-mac-authbus-main3-sdk-inline-capture-20261106-r4',
 originalFailedSdkJob='1a1b28a4d4c-fc05-7e81',
 derivationBaseManifestSha256=OLD_MANIFEST_SHA,derivationBaseStagingSha256=OLD_BUNDLE_SHA,
 wirePriorSourceSha256='2b06342e30703611729788a522ba764ae30adfe1e47c4f4673b7aa8f647170e2',
 wireSourceSha256=WIRE_SHA,wireDiagnosticAuthorityJob='1a1b29bacf3-fc05-7ee7',
 wireDiagnosticOriginalResultSha256='905f3173daa84153edfd59c6188158580c9ff89f5784fc01db0e74b6c8854182',
 wireChange='retain stateless handshake CA/host/leaf; verify actual authorized IPv4/port and complete current peer host/leaf for each response; no request-local callback flag',
 actualMacWireCandidateQualified=False,actualMacSdkQualified=False,
 priorOriginalSdkResultRemainsFailed=True,priorOriginalPluginUnknownResponseCount=1)
result['nodeWorkerOriginalPins']={name:old_manifest['assetPins'][name] for name in (
 'qa/main3_sdk_cycle_r2.mjs','qa/main3_sdk_wire_r2.mjs','qa/main3_auth_rows_cas_r1.mjs','qa/main3_authbus_cache_cas_r1.mjs')}
result['nodeWorkerRootOnlyChanges']={}
for name in ('qa/main3_auth_rows_cas_r1.mjs','qa/main3_authbus_cache_cas_r1.mjs'):
 before=base['assets'][name];after=assets[name]
 assert before.count(OLD_ROOT)==1 and after==before.replace(OLD_ROOT,NEW_ROOT)
 result['nodeWorkerRootOnlyChanges'][name]={'originalSha256':sha(before.encode()),'sha256':sha(after.encode()),
  'fixedRootLiteralReplacements':1,'allOtherBytesUnchanged':True}
cycle_name='qa/main3_sdk_cycle_r2.mjs'
assert assets[cycle_name]==base['assets'][cycle_name].replace(OLD_ROOT,NEW_ROOT).replace('main3_sdk_wire_r2.mjs','main3_sdk_wire_r3.mjs')
result['nodeWorkerRootAndWireModuleChanges']={cycle_name:{
 'originalSha256':sha(base['assets'][cycle_name].encode()),'sha256':sha(assets[cycle_name].encode()),
 'fixedRootLiteralReplacements':1,'fixedWireModuleNameReplacements':2,'allOtherBytesUnchanged':True}}
result['seedRootOnlyChange']={'originalSha256':sha(base['assets']['qa/main3_sdk_seed_r1.mjs'].encode()),
 'sha256':asset_pins['qa/main3_sdk_seed_r1.mjs']['sha256'],'fixedRootLiteralReplacements':1}
assert assets['qa/main3_sdk_seed_r1.mjs']==base['assets']['qa/main3_sdk_seed_r1.mjs'].replace(OLD_ROOT,NEW_ROOT)
assert result['budgets']==old_manifest['budgets'] and result['sdkWireMaximumSeconds']==15 and result['seedMaximumSeconds']==10
result['sandboxChange']='no change from r3: one actual-qualified localhost TCP port plus exact IPv4/CA/host/leaf wire admission'
NEW.mkdir(exist_ok=False)
(NEW/'source-sdk-r4').mkdir()
for name,text in sources.items():(NEW/'source-sdk-r4'/name).write_text(text)
for name,text in assets.items():
 target=NEW/'assets'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text)
(NEW/'main3_sdk_phase.py').write_text(phase)
(NEW/'main3_sdk_seed_r1.mjs').write_text(assets['qa/main3_sdk_seed_r1.mjs'])
(NEW/'test_main3_sdk_seed_r1.mjs').write_bytes((OLD/'test_main3_sdk_seed_r1.mjs').read_bytes())
(NEW/'mount-public-pin.json').write_bytes((OLD/'mount-public-pin.json').read_bytes())
(NEW/'prepare_main3_sdk_r4.bound.py').write_text(preparer)
(NEW/'staging-sdk-r4.public.json').write_bytes(raw)
(NEW/'manifest-sdk-r4.public.json').write_text(json.dumps(result,indent=2)+'\n')
parts=[]
for name,text in sources.items():
 if name.startswith('main3_capture_payload_'):continue
 parts.extend(difflib.unified_diff(base['sources'][name].splitlines(True),text.splitlines(True),fromfile='frozen-sdk-r3/'+name,tofile='new-sdk-r4/'+name))
for name,text in assets.items():
 old_name='qa/main3_sdk_wire_r2.mjs' if name=='qa/main3_sdk_wire_r3.mjs' else name
 if text!=base['assets'][old_name]:
  parts.extend(difflib.unified_diff(base['assets'][old_name].splitlines(True),text.splitlines(True),fromfile='frozen-sdk-r3/'+old_name,tofile='new-sdk-r4/'+name))
parts.extend(difflib.unified_diff(base['preparerSource'].splitlines(True),preparer.splitlines(True),fromfile='frozen-sdk-r3/preparer.py',tofile='new-sdk-r4/preparer.py'))
(NEW/'sdk-r3-to-r4-minimal.diff').write_text(''.join(parts))
(NEW/'qualification').mkdir()
print(json.dumps({'prepared':True,'newRoot':str(NEW),'staging':result['staging'],
 'wire':asset_pins['qa/main3_sdk_wire_r3.mjs'],'phase':source_pins['main3_sdk_phase.py'],
 'controller':source_pins['main3_sdk_controller.py'],'preparer':result['preparer'],
 'sourceCount':len(sources),'assetCount':len(assets),'actualMacExecuted':False}))
