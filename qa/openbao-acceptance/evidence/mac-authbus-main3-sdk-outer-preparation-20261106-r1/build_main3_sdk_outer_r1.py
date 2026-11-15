#!/usr/bin/env python3
"""Create a separate SDK fixture from the frozen API r5 ownership controller.

This is local source assembly only. No old attempt or remote path is modified.
"""
import ast,base64,difflib,hashlib,json
from pathlib import Path

WORK=Path('/workspace/scratch/c9fe536787d9/main3-sdk-outer-work')
API=Path('/workspace/scratch/c9fe536787d9/main3-authbus-work')
NODE_WORK=Path('/workspace/scratch/c9fe536787d9/main3-sdk-root-work')
OUT=WORK/'source-sdk-r1'
ROOT='/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r1'
SDK='/opt/homebrew/lib/node_modules/openclaw'
OLD_CAPTURE='/Users/qianqi/heptabao-authbus-main3-api-inline-capsule-20261106-r5'
NEW_CAPTURE='/Users/qianqi/heptabao-authbus-main3-sdk-inline-capsule-20261106-r1'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def once(text,before,after):
    assert text.count(before)==1,(before[:100],text.count(before));return text.replace(before,after)
def assignment(text,name,value):
    tree=ast.parse(text);nodes=[n for n in tree.body if isinstance(n,ast.Assign)
      and any(isinstance(t,ast.Name) and t.id==name for t in n.targets)]
    assert len(nodes)==1,(name,len(nodes));node=nodes[0];lines=text.splitlines(True)
    lines[node.lineno-1:node.end_lineno]=[name+'='+repr(value)+'\n'];return ''.join(lines)
def revise(text):
    for old,new in [
      ('mac-authbus-main3-api-preparation-20261106-r5','mac-authbus-main3-sdk-preparation-20261106-r1'),
      ('mac-authbus-main3-api-journal-20261106-r5','mac-authbus-main3-sdk-journal-20261106-r1'),
      ('mac-authbus-main3-api-20261106-r5','mac-authbus-main3-sdk-20261106-r1'),
      ('main3-api-inline-capture-20261106-r5','main3-sdk-inline-capture-20261106-r1'),
      (OLD_CAPTURE,NEW_CAPTURE),
      ('heptabao.mac-main3-api-preparation-terminal.r5','heptabao.mac-main3-sdk-preparation-terminal.r1'),
      ('heptabao.mac-main3-api-preparation.r5','heptabao.mac-main3-sdk-preparation.r1'),
      ('heptabao.mac-main3-api-journal.r5','heptabao.mac-main3-sdk-journal.r1'),
      ('heptabao.mac-main3-current-api-qualification.r5','heptabao.mac-main3-current-sdk-qualification.r1'),
      ('heptabao.current-sdk-selected-capsule-inline-owned-observation.r5','heptabao.current-sdk-selected-capsule-inline-owned-observation.sdk-r1'),
      ('heptabao.current-sdk-selected-capsule-readonly.r5','heptabao.current-sdk-selected-capsule-readonly.sdk-r1'),
    ]:text=text.replace(old,new)
    return text

base=json.loads((API/'staging-api-r5.public.json').read_text())
manifest=json.loads((API/'manifest-api-r5.public.json').read_text())
for name,text in base['sources'].items():assert sha(text.encode())==manifest['sourcePins'][name]['sha256'],name
sources={name:revise(text) for name,text in base['sources'].items()}
parts=''.join(ast.literal_eval(ast.parse(base['sources'][name]).body[0].value)
  for name in sorted(base['sources']) if name.startswith('main3_capture_payload_'))
old_payload=base64.b64decode(parts,validate=True)
assert sha(old_payload)==manifest['currentCapture']['sourcePins']['CAPTURE_PAYLOAD_SHA']
payload=json.loads(old_payload)
for name in ('worker','registryChild'):payload[name]=revise(payload[name])
payload_raw=(json.dumps(payload,sort_keys=True,separators=(',',':'))+'\n').encode()
text64=base64.b64encode(payload_raw).decode();part_pins={}
for i,start in enumerate(range(0,len(text64),60000)):
    name='main3_capture_payload_'+str(i)+'.py';source='DATA='+repr(text64[start:start+60000])+'\n'
    sources[name]=source;part_pins[name]={'bytes':len(source.encode()),'sha256':sha(source.encode())}
launcher=assignment(sources['main3_capture_launcher.py'],'PAYLOAD_PART_PINS',part_pins)
launcher=once(launcher,manifest['currentCapture']['sourcePins']['CAPTURE_PAYLOAD_SHA'],sha(payload_raw))
sources['main3_capture_launcher.py']=launcher
capture_pins={'CAPTURE_WORKER_SHA':sha(payload['worker'].encode()),
  'CAPTURE_LAUNCHER_SHA':sha(launcher.encode()),'CAPTURE_GUARD_SHA':sha(payload['guard'].encode()),
  'CAPTURE_REGISTRY_SHA':sha(payload['registryChild'].encode()),'CAPTURE_PAYLOAD_SHA':sha(payload_raw)}
helper=sources['main3_inline_capture.py']
for name,value in capture_pins.items():helper=assignment(helper,name,value)
sources['main3_inline_capture.py']=helper

assets={}
for name in ('main3_sdk_cycle_r2.mjs','main3_sdk_wire_r2.mjs','main3_auth_rows_cas_r1.mjs','main3_authbus_cache_cas_r1.mjs'):
    assets['qa/'+name]=(NODE_WORK/name).read_text()
assets['qa/main3_sdk_seed_r1.mjs']=(WORK/'main3_sdk_seed_r1.mjs').read_text()
plugin_names=('index.js','package.json','order-policy.js','runtime-refresh-policy.js',
  'codex-client-recycler.js','provider-error-classifier.js','bad-refresh-quarantine.js','lease-assignments.js')
for name in plugin_names:assets['plugin/'+name]=(API/'reference/current-plugin'/name).read_text()
asset_pins={name:{'bytes':len(text.encode()),'sha256':sha(text.encode())} for name,text in assets.items()}
assert asset_pins['qa/main3_sdk_cycle_r2.mjs']['sha256']=='37421c74a35f6939050909b4d770b3bc1e01bc3e6a3455dba4abe1b90fc1e7c6'
assert asset_pins['qa/main3_sdk_wire_r2.mjs']['sha256']=='2b06342e30703611729788a522ba764ae30adfe1e47c4f4673b7aa8f647170e2'
assert asset_pins['qa/main3_auth_rows_cas_r1.mjs']['sha256']=='b3dc14d160ae8c76a2b50ec21e245e68954e1a956b401a1daa306582bffaa584'
assert asset_pins['qa/main3_authbus_cache_cas_r1.mjs']['sha256']=='d0d2b19199d299dd8f163f0f18caade0153da9ccabaf9de20f42c89c8a255243'
assert asset_pins['plugin/index.js']['sha256']=='b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b'
mount=json.loads((WORK/'mount-public-pin.json').read_text())
assert mount['path']=='/sbin/mount' and len(mount['sha256'])==64 and set(mount['sha256'])<=set('0123456789abcdef')
extra={'package.json':'695b6ee36df7fc69606dc390cf97bb2ca809114337b18c573707637cd2a4e3db',
  'dist/profiles-DyU-YCq2.js':'075f9d6ecd43103c32a6908816bf42720076fd0aaedb2b5e7e96481d64a29ba5',
  'dist/openclaw-agent-db-DKpxi-Ll.js':'5c99ab6de1ccc1419ed1bdbc783b79203afc34e564f794df4d91bf10e0b53360',
  'dist/openclaw-state-db-DzSsA9Ji.js':'ba920b2e6f63293a27c34615fc31dcb16a20a68a1e1e34fbccdcac56a9608149',
  'dist/sqlite-wal-Bhk2Ro-u.js':'ef69e7cad95ff5cd5fe3087331294daae557833bcbc3d0ae140394d16855c3da'}
sources['main3_sdk_public_pins.py']='''"""Public installed sources and owned asset bindings; no private content pins."""\n'''+\
  'ASSET_PINS='+repr(asset_pins)+'\nSDK_EXTRA_PINS='+repr(extra)+'\n'+\
  "NODE_SHA='a46ed02589ca3af795237111ff854262064f8ff5c5b58d75c1509f37311eb15e'\nMOUNT_SHA="+repr(mount['sha256'])+'\n'
sources['main3_sdk_phase.py']=(WORK/'main3_sdk_phase.py').read_text()

controller=sources['main3_api_controller.py']
controller=once(controller,'    import main3_api_cycle as api_cycle\n','    import main3_sdk_phase as api_cycle\n')
controller=once(controller,'active_api=api_cycle.Api(plan,phase,phase_until,journal,guard)',
  'active_api=api_cycle.Api(plan,phase,phase_until,journal,guard,commands)')
controller=once(controller,"    need(Path(__file__).resolve()==QA/'main3_api_controller.py','only_pinned_remote_controller')",
  "    need(Path(__file__).resolve()==QA/'main3_sdk_controller.py','only_pinned_remote_controller')")
controller=once(controller,"        result['elapsedSeconds']=time.monotonic()-started\n",
  "        result['actualPluginSdkPhaseExecuted']=any(x.get('actualPluginSdkPhaseExecuted') for x in result['phases'])\n"
  "        result['actualPluginSdkQualified']=bool(result['ok'] and len(result['phases'])==2 and\n"
  "            all(len(x.get('sdkChildren',[]))==1 and x['sdkChildren'][0].get('ok') is True for x in result['phases']))\n"
  "        result['wholeProductionDatabaseRollback']=False\n"
  "        result['elapsedSeconds']=time.monotonic()-started\n")
sources.pop('main3_api_controller.py')
sources['main3_sdk_controller.py']=controller
tests=sources.pop('test_main3_api_controller.py').replace('main3_api_controller','main3_sdk_controller')
sources['test_main3_sdk_controller.py']=tests
sources['main3_sdk_controller.py']=assignment(sources['main3_sdk_controller.py'],'SOURCE_NAMES',tuple(sources))

preparer=revise(base['preparerSource'])
preparer=once(preparer,"need(set(bundle)=={'sources','preparerSource'},'fixed_bundle_schema')",
  "need(set(bundle)=={'sources','assets','preparerSource'},'fixed_bundle_schema')")
preparer=once(preparer,"        ast.parse(source)\n",
  "        ast.parse(source)\n"
  "    assets={name:text.encode() for name,text in bundle['assets'].items()}\n"
  "    need(set(assets)==set(EXPECTED_ASSETS),'exact_public_asset_inventory')\n"
  "    for name,source in assets.items():\n"
  "        pin=EXPECTED_ASSETS[name]\n"
  "        need(len(source)==pin['bytes'] and sha(source)==pin['sha256'],'exact_public_asset_pin')\n")
dirs=['','qa','plugin','node_modules','input','private','initial','cold-new-process','state','state/tmp',
  'state/tmp/openclaw-501','state/oauth','state/state','state/agents',
  *[part for agent in ('main','trnm','hepta-ui','hepta','hepta-backend') for part in ('state/agents/'+agent,'state/agents/'+agent+'/agent')],
  'launchd','bin','server','server/data','server/home','server/tmp','server/tls','server/private']
preparer=once(preparer,"for relative in ('','qa','launchd','bin','server','server/data','server/home','server/tmp','server/tls','server/private'):",
  'for relative in '+repr(tuple(dirs))+':')
preparer=once(preparer,"            need(actual['sha256']==EXPECTED_PINS[name]['sha256'],'staged_source_matches_pin')\n",
  "            need(actual['sha256']==EXPECTED_PINS[name]['sha256'],'staged_source_matches_pin')\n"
  "        for relative,source in assets.items():\n"
  "            actual=guard.write_new(ROOT/relative,source)\n"
  "            need(actual['sha256']==EXPECTED_ASSETS[relative]['sha256'],'staged_public_asset_matches_pin')\n"
  "        with guard.parent(ROOT/'node_modules/openclaw') as (parent,name):\n"
  "            os.symlink('/opt/homebrew/lib/node_modules/openclaw',name,dir_fd=parent);os.fsync(parent)\n"
  "            need(os.readlink(name,dir_fd=parent)=='/opt/homebrew/lib/node_modules/openclaw','fixed_bare_import_sdk_link')\n")
preparer=once(preparer,"'sourcePins':EXPECTED_PINS,'homeCopyPins':",
  "'sourcePins':EXPECTED_PINS,'assetPins':EXPECTED_ASSETS,'homeCopyPins':")
source_pins={name:{'bytes':len(text.encode()),'sha256':sha(text.encode())} for name,text in sources.items()}
preparer=assignment(preparer,'EXPECTED_PINS',source_pins)
preparer=once(preparer,'\ndef need(value,code):','\nEXPECTED_ASSETS='+repr(asset_pins)+'\n\ndef need(value,code):')
ast.parse(preparer)
OUT.mkdir(exist_ok=True)
for name,text in sources.items():ast.parse(text);(OUT/name).write_text(text)
for name,text in assets.items():
    target=WORK/'assets'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text)
(WORK/'prepare_main3_sdk_r1.bound.py').write_text(preparer)
bundle={'sources':sources,'assets':assets,'preparerSource':preparer}
raw=json.dumps(bundle,separators=(',',':')).encode();assert len(raw)<=1048576
(WORK/'staging-sdk-r1.public.json').write_bytes(raw)
result={'schema':'heptabao.mac-main3-sdk-outer-preparation.r1','status':'prepared-not-executed',
  'sourcePins':source_pins,'assetPins':asset_pins,'capturePins':capture_pins,
  'preparer':{'bytes':len(preparer.encode()),'sha256':sha(preparer.encode())},
  'staging':{'bytes':len(raw),'sha256':sha(raw)},'canonicalProductCommit':manifest['canonicalCommit'],
  'canonicalBinarySha256':manifest['canonicalBinarySha256'],
  'budgets':manifest['budgets'],'sdkWireMaximumSeconds':15,'seedMaximumSeconds':10,
  'nodeWorkerSourcesUnchanged':True,'installedPluginSourcesUnchanged':True,
  'productionChanged':False,'providerCalled':False,'productionRollbackQualified':False,
  'actualMacSdkQualified':False,'privateDigestOutputOnly':True}
(WORK/'manifest-sdk-r1.public.json').write_text(json.dumps(result,indent=2)+'\n')
diff=''.join(''.join(difflib.unified_diff(base['sources'].get(name,'').splitlines(True),text.splitlines(True),
  fromfile='retained-api-r5/'+name,tofile='new-sdk-r1/'+name))
  for name,text in sources.items() if not name.startswith('main3_capture_payload_'))
(WORK/'sdk-r1.derivation.diff').write_text(diff)
print(json.dumps({'sources':len(sources),'assets':len(assets),'bundleBytes':len(raw),'manifest':str(WORK/'manifest-sdk-r1.public.json')}))
