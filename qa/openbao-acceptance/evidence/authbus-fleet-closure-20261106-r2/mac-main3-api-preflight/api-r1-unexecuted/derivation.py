#!/usr/bin/env python3
"""Derive new main3 API fixture from actually qualified fresh-r2 custody seam."""
from pathlib import Path
import ast,difflib,hashlib,json
WORK=Path('/workspace/scratch/c9fe536787d9/main3-authbus-work')
OLD=Path('/workspace/scratch/c9fe536787d9/fresh-r2-work/source-r2')
OUT=WORK/'source-api-r1'
PINS={
'mac_owned_unreaped_r1.py':'d735a9e9330e1260d44ad9e4c854d50094e20d85fe5633ddd9042281b3346298',
'mac_owned_commands_r1.py':'71a11bf9a0510c991b78c9bc3f094f315bf4914485b9cfda81c6e501eaf73530',
'mac_t5_volume_guard_r1.py':'9d5a6ea743e5abe87f6f84bcbcf6ddb7ba9f080fd3f51e54040d56122159394a',
'mac_owned_launchd_r3.py':'9209144dd581ed547478e5210fffc8e1c75e7bc5511637ba02aed18a63129354',
'mac_native_process_observer_r1.py':'cc0fa9917d05c6dc2c295594f980c1f77d089c1196e6279a14f2fdaf2d77ae9b',
'mac_current_server_owner_r1.py':'c7eaf0a36bcfac4355c778d93e27bdff58fbcc0cba625987cee6e98e72909be5',
'mac_public_code_pin_excerpt_r1.py':'7ff262e7ff913eb97aab77855d988cb3a6af8cab5ea9c77940a2782afd91ca4f',
'tls_complete_http_probe.py':'7e92967416e0dcdc80b9c5d56e0655775630cef9198aba5541fa75bbf98c42fc',
'fresh_synthetic_controller_r1.py':'4697eb12c7af0b88fc8faec697518e0397cc8f620cf2581f301b18206f54f42c',
'test_fresh_synthetic_controller_r1.py':'5b4d3f2cc67196ef2eab036467493edcb90db5e5902e92619b5d78236f754e7a',
'test_suid_ps_tls_r2.py':'261d38cdf25e873a99fc99c901d1cefcbdc0d434388877caa26d57cac7496bc6'}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def once(text,old,new):
    assert text.count(old)==1,old[:100]
    return text.replace(old,new)
def revision(text):
    for old,new in (
      ('mac-fresh-synthetic-launchd-20261106-r2','mac-authbus-main3-api-20261106-r1'),
      ('mac-fresh-synthetic-preparation-20261106-r2','mac-authbus-main3-api-preparation-20261106-r1'),
      ('mac-fresh-synthetic-journal-20261106-r2','mac-authbus-main3-api-journal-20261106-r1'),
      ('mac-fresh-synthetic-20261106-r2','mac-authbus-main3-api-20261106-r1'),
      ('heptabao.mac-fresh-synthetic-preparation-terminal.r2','heptabao.mac-main3-api-preparation-terminal.r1'),
      ('heptabao.mac-fresh-synthetic-preparation.r2','heptabao.mac-main3-api-preparation.r1'),
      ('heptabao.mac-fresh-synthetic-journal.r2','heptabao.mac-main3-api-journal.r1'),
      ('heptabao.mac-fresh-synthetic-startup-qualification.r2','heptabao.mac-main3-current-api-qualification.r1'),
      ('fresh_synthetic_controller_r1','main3_api_controller'),
      ('syntheticStartupOnly','startupCustodyOnly'),
      ('Independent synthetic startup scope; canonical 4bde9 normal107 pin.',
       'Startup custody scope only; actual main3 capsule admission is independently fenced.')):
        text=text.replace(old,new)
    return text
sources={};originals={}
for name,pin in PINS.items():
    raw=(OLD/name).read_bytes();assert sha(raw)==pin,name
    new=name.replace('fresh_synthetic_controller_r1','main3_api_controller')
    originals[new]=raw.decode();sources[new]=revision(raw.decode())
key='main3_api_controller.py';s=sources[key]
s=once(s,"'test_main3_api_controller.py','test_suid_ps_tls_r2.py')",
       "'test_main3_api_controller.py','test_suid_ps_tls_r2.py',\n    'main3_source_fence.py','main3_api_cycle.py','test_main3_api_guards.py')")
s=once(s,'Separate synthetic launchd startup/retirement qualification; no client credentials.',
       'Actual selected main3 API qualification on separately owned launchd lifetimes.')
s=once(s,"return {'bytesRead':len(raw),'prefixSha256':sha(raw),'stages':values,'completeFileAtInitialStat':True}",
       "return {'bytesRead':len(raw),'stages':values,'completeFileAtInitialStat':True,\n                'rawServerDiagnosticsOrDigestsPublished':False}")
s=once(s,'    import tls_complete_http_probe as tls_probe',
       '    import main3_api_cycle as api_cycle\n    from main3_source_fence import CapsuleFence')
s=once(s,'    journal=None;guard=None;home=None;manager=None',
       '    journal=None;guard=None;home=None;manager=None;active_api=None;active_fence=None;private_state=None')
s=once(s,"'ok':False,'planSha256':plan_sha,'startupCustodyOnly':True,'businessCredentialInputsRead':False,",
       "'ok':False,'planSha256':plan_sha,'startupCustodyOnly':False,'businessCredentialInputsRead':False,\n        'providerValid':False,'providerCalled':False,'providerRefreshAttempted':False,\n        'productionTrafficCutover':False,'credentialValuesOrDigestsPublished':False,\n        'actualPluginSdkPhaseExecuted':False,'productionClientRollbackQualified':False,")
s=once(s,"'health':[],'stages':{},'mutationExecuted':False}",
       "'phases':[],'sourceFences':[],'stages':{},'mutationExecuted':False}")
s=once(s,"        if args.mode=='preflight':\n            result.update(ok=True,labelsInitiallyAbsent=True,mutationExecuted=False)",
       "        if args.mode=='preflight':\n            active_fence=CapsuleFence(min(until,time.monotonic()+45.0))\n            result['businessCredentialInputsRead']=True\n            active_fence.observe('preflight')\n            result.update(ok=True,labelsInitiallyAbsent=True,mutationExecuted=False)")
s=once(s,"'operationGraph':list(base.GRAPH),'businessCredentialInputsRead':False}",
       "'operationGraph':list(base.GRAPH),'realSelectedOwnerCount':3,\n                'providerValid':False,'productionCutover':False}")
old="""            for generation in ('server-initial','server-cold-new-process'):
                result['mutationExecuted']=True
                manager.start_server(generation)
                health=tls_probe.probe('127.0.0.1',plan['port'],'localhost',
                    ROOT/'server/tls/server.crt',plan['certificateLeafSha256'],generation)
                result['health'].append(health)
                need(health['passed'] is True,'actual_complete_pinned_tls_health')
                journal.append('actual-tls-health',health)
                manager.kill_server_for_cold_or_inverse(generation)
"""
new="""            for generation,phase in (('server-initial','initial'),('server-cold-new-process','cold-new-process')):
                phase_until=min(until,time.monotonic()+120.0)
                active_fence=CapsuleFence(phase_until)
                result['businessCredentialInputsRead']=True
                active_fence.observe('preflight')
                result['mutationExecuted']=True
                manager.start_server(generation)
                active_api=api_cycle.Api(plan,phase,phase_until,journal,guard)
                if phase=='initial':private_state=api_cycle.initial(active_api,active_fence)
                else:api_cycle.cold(active_api,active_fence,private_state)
                result['phases'].append(active_api.public());active_api=None
                result['sourceFences'].append(active_fence.public());active_fence=None
                need(time.monotonic()<phase_until,'business_phase_completed_within_original_120_seconds')
                manager.kill_server_for_cold_or_inverse(generation)
"""
s=once(s,old,new)
s=once(s,'    finally:\n        for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,signal.SIG_IGN)',
       "    finally:\n        if active_api is not None:result['phases'].append(active_api.public())\n        if active_fence is not None:result['sourceFences'].append(active_fence.public())\n        for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,signal.SIG_IGN)")
s=once(s,"result['ok']=bool(result['ok'] and closure and time.monotonic()<until)",
       "result['ok']=bool(result['ok'] and closure and time.monotonic()<until\n            and all(x['allReturnedDescriptorsClosed'] for x in result['sourceFences'])\n            and all(x['allReturnedSocketsClosed'] and x['unknownHttpOutcomeCount']==0\n                and x['allDispatchedResponsesComplete'] and all(c['passed'] for c in x['checks']) for x in result['phases']))")
sources[key]=s
for name in ('main3_source_fence.py','main3_api_cycle.py','test_main3_api_guards.py'):
    sources[name]=(OUT/name).read_text()
for name,source in sources.items():ast.parse(source);(OUT/name).write_text(source)
pins={name:{'bytes':len(source.encode()),'sha256':sha(source.encode())} for name,source in sources.items()}
preparer=Path('/workspace/scratch/c9fe536787d9/fresh-r2-work/prepare_fresh_synthetic_r2.bound.py').read_text()
preparer=revision(preparer)
preparer=once(preparer,"'server','server/data','server/home','server/tmp','server/tls'","'server','server/data','server/home','server/tmp','server/tls','server/private'")
lines=preparer.splitlines(True);indices=[i for i,l in enumerate(lines) if l.startswith('EXPECTED_PINS=')];assert len(indices)==1
lines[indices[0]]='EXPECTED_PINS='+repr(pins)+'\n';preparer=''.join(lines);ast.parse(preparer)
(WORK/'prepare_main3_api_r1.bound.py').write_text(preparer)
(WORK/'staging-api-r1.public.json').write_text(json.dumps({'sources':sources,'preparerSource':preparer},separators=(',',':')))
diff=''.join(''.join(difflib.unified_diff(originals.get(n,'').splitlines(True),s.splitlines(True),fromfile='qualified-r2/'+n,tofile='main3-api-r1/'+n)) for n,s in sources.items())
(WORK/'main3-api-r1-derivation.diff').write_text(diff)
manifest={'schema':'heptabao.mac-main3-api-source-derivation.r1','qualifiedR2OriginalPins':PINS,'sourcePins':pins,
    'preparer':{'bytes':len(preparer.encode()),'sha256':sha(preparer.encode())},
    'canonicalCommit':'4bde9aee03fcd27c59e13607e529b1cee594b249',
    'canonicalBinarySha256':'5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c',
    'budgets':{'outer':600,'phase':120,'sourceObservationMaximum':45,'wrapperReady':30,'execObservation':10,'health':15,'singleOtherHttp':10,'failureCleanup':60},
    'signalOwnershipUnchanged':True,'psSuidExceptionUnchanged':True,'actualCredentialScope':3,
    'providerValid':False,'productionCutover':False,'actualPluginSdkQualified':False,
    'publicCredentialValuesOrDigests':False,'productionClientRollbackQualified':False}
(WORK/'manifest-api-r1.public.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest,sort_keys=True))
