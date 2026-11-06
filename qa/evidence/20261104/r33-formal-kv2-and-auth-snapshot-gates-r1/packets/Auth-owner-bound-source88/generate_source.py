#!/usr/bin/env python3
"""Offline, create-only binding of reviewed owner repair to one actual entry."""
import ast
import base64
import difflib
import hashlib
import json
import os
from pathlib import Path

OWN=Path('/workspace/scratch/f86faac821c4/authbus_registration_body4_recovery_r1')
HERE=OWN/'owner-bound-renew-r1'
BASE=OWN/'owner-bound-r1/baseline'
OLD='mac-authbus-4e808-current-registry-wal-r1'
NEW='mac-authbus-4e808-current-owner-bind-r1'
OLD_LABEL='org.heptabao.qa.mac-authbus-4e808-wal-r1.'
NEW_LABEL='org.heptabao.qa.mac-authbus-4e808-owner-r1.'
ENTRY='/opt/homebrew/lib/node_modules/openclaw/dist/extensions/google/index.js'
ENTRY_SHA='f245758337a55924518852f542a27d49bd786d8e4b80821dc5f98f825ec3fc60'
REVIEWED={
    'mac_current_outer_inputs_r2.py':'1e2a0cfb1bdbaef2d418fd8eb941ac14ec28e9b6',
    'mac_current_fixture_materializer_r1.py':'570f9abdcad9cfdc4c2d06c3895f0f68a1bf8c1b',
    'mac_single_native_r2.mjs':'11d6b0bb0c26019b5a6e4035d42226b6666cab07',
    'mac_current_outer_wal_r1.py':'26622454186ba28ada489c9a10b34cf4ad254b97',
}

def sha(bs):return hashlib.sha256(bs).hexdigest()
def pin(bs):
    return {'blob':hashlib.sha1(b'blob '+str(len(bs)).encode()+b'\0'+bs).hexdigest(),
            'bytes':len(bs),'sha256':sha(bs)}
def save(path,bs):
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():
        assert path.read_bytes()==bs,('create_only_existing_bytes_differ',str(path))
        return
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:f.write(bs);f.flush();os.fsync(f.fileno())
def dump(path,value):save(path,(json.dumps(value,indent=2,ensure_ascii=False)+'\n').encode())
def delta(a,b,left,right):
    return ''.join(difflib.unified_diff(a.splitlines(keepends=True),b.splitlines(keepends=True),fromfile=left,tofile=right)).encode()

entry=(OWN/'google-entry/actual-r1/entry.original.js').read_bytes()
assert len(entry)==10582 and sha(entry)==ENTRY_SHA
meta=json.loads((OWN/'google-entry/actual-r1/metadata.native.original.json').read_text())
assert meta['path']==ENTRY and meta['sha256']==ENTRY_SHA and meta['size']==10582
assert meta['version']=='16777233:405237094:10582:1784843458496192413:1784843458496192413'
assert meta['mode']==420 and meta['metadata']['uid']==501 and meta['metadata']['gid']==80 and meta['metadata']['link_count']==1
release=json.loads((OWN/'google-entry/actual-r1/RELEASE.public.json').read_text())
assert release['allOriginalOperationsClosed'] is True and release['allOriginalPayloadsWhole'] is True
assert release['runtimeCallsInFlight']==release['knownNativeFuturesActive']==0

old_pins=json.loads((OWN/'blobs/329eebac590c138d73dbe15b6ef947586d185105.txt').read_text())
source_rows=[];bound={};old_sources={};reviewed_sources={};changed=[];unchanged=[];root_edits=0
old_binding=("# Source-only successor: the Google declared entry has not yet been observed.\n"
             "# A later exact public binding must fill OWNER_ENTRY_PINS before this can run.\n"
             "OWNER_PUBLIC_BINDING_READY=False\nOWNER_ENTRY_PINS={}")
new_binding=("# Current fixed public entry has been observed and whole-hash bound.\n"
             "# This does not authorize execution or prove the selected owner.\n"
             "OWNER_PUBLIC_BINDING_READY=True\nOWNER_ENTRY_PINS={\n"
             f'  "{ENTRY}": "{ENTRY_SHA}"\n'+'}')
for path in sorted((BASE/'source').iterdir()):
    name=path.name;original=path.read_bytes();assert sha(original)==old_pins[name]
    old_sources[name]=original
    reviewed=(OWN/'blobs'/f'{REVIEWED[name]}.txt').read_bytes() if name in REVIEWED else original
    if name in REVIEWED:assert pin(reviewed)['blob']==REVIEWED[name]
    reviewed_sources[name]=reviewed
    text=reviewed.decode();occurrences=text.count(OLD);root_edits+=occurrences
    after=text.replace(OLD,NEW)
    label_count=after.count(OLD_LABEL)
    assert label_count==(2 if name=='mac_owned_launchd_r3.py' else 0)
    after=after.replace(OLD_LABEL,NEW_LABEL)
    if name=='mac_current_outer_inputs_r2.py':
        assert after.count(old_binding)==1;after=after.replace(old_binding,new_binding)
    if name=='mac_current_outer_wal_r1.py':
        old_ready='BINDING_READY=False  # Source-only renewal increment; no runtime request or fresh candidate is bound.'
        new_ready='BINDING_READY=True  # Actual source pins and fresh candidate are bound; host execution requires separate root GO.'
        assert after.count(old_ready)==1;after=after.replace(old_ready,new_ready)
    inverse=after
    if name=='mac_current_outer_wal_r1.py':inverse=inverse.replace(new_ready,old_ready)
    if name=='mac_current_outer_inputs_r2.py':inverse=inverse.replace(new_binding,old_binding)
    inverse=inverse.replace(NEW_LABEL,OLD_LABEL).replace(NEW,OLD)
    assert inverse.encode()==reviewed,('mechanical_inverse',name)
    data=after.encode();bound[name]=data;save(HERE/'source'/name,data)
    if name.endswith('.py'):
        parsed=ast.parse(after,filename=name);compile(parsed,name,'exec')
    same=data==original;(unchanged if same else changed).append(name)
    save(HERE/'diff'/(name+'.from-baseline.diff'),delta(original.decode(),after,'baseline/'+name,'source/'+name))
    save(HERE/'diff'/(name+'.binding-only.diff'),delta(reviewed.decode(),after,'reviewed/'+name,'source/'+name))
    source_rows.append({'path':'source/'+name,'before':pin(original),'reviewedBefore':pin(reviewed),
                        'after':pin(data),'rootLiteralOccurrences':occurrences,'labelLiteralOccurrences':label_count,
                        'ownerEntryBinding':name=='mac_current_outer_inputs_r2.py','mechanicalInverseExact':True,
                        'originalWholeUnchanged':same})
assert len(bound)==22 and root_edits==11 and len(changed)==11 and len(unchanged)==11

candidate=json.loads((BASE/'documents/candidate-current-manager-wal-r1.public.json').read_text())
old_candidate=json.loads((BASE/'documents/candidate-current-manager-wal-r1.public.json').read_text())
new_pins={name:sha(raw) for name,raw in sorted(bound.items())}
candidate['sourcePins']=new_pins
assert {k:v for k,v in candidate.items() if k!='sourcePins'}=={k:v for k,v in old_candidate.items() if k!='sourcePins'}
assert candidate['budgets']=={'outer':900,'manager':600,'managerFailureCleanup':60,'phase':120,
                             'native':[15,8,3],'http':10,'capture':45,'listenerReady':30,'tlsCommand':30}
dump(HERE/'source-pins.public.json',new_pins)
dump(HERE/'documents/candidate-current-manager-wal-r1.public.json',candidate)
proof_rows=[]
for p in sorted((BASE/'documents/proofs').iterdir()):
    raw=p.read_bytes();save(HERE/'documents/proofs'/p.name,raw)
    proof_rows.append({'path':'documents/proofs/'+p.name,**pin(raw),'wholeUnchanged':True})
assert len(proof_rows)==7
anchor=(BASE/'volume-anchor.original.json').read_bytes()
save(HERE/'volume-anchor.original.json',anchor)
assert sha(anchor)==candidate['publicVolumeAnchorSha256']
payload={'schema':json.loads((OWN/'blobs/931383bbc295b82ad7ff6cf57c33af3395e20966.txt').read_text())['schema'],
         'files':{name:base64.b64encode(raw).decode() for name,raw in bound.items()},
         'documents':{},'anchorBase64':base64.b64encode(anchor).decode()}
for p in sorted((HERE/'documents').rglob('*')):
    if p.is_file():payload['documents'][str(p.relative_to(HERE/'documents'))]=base64.b64encode(p.read_bytes()).decode()
assert len(payload['documents'])==8
dump(HERE/'publisher-stdin.public.json',payload)
save(HERE/'diff/candidate.source-pins.diff',delta(
    (BASE/'documents/candidate-current-manager-wal-r1.public.json').read_text(),
    (HERE/'documents/candidate-current-manager-wal-r1.public.json').read_text(),
    'baseline/candidate-current-manager-wal-r1.public.json','documents/candidate-current-manager-wal-r1.public.json'))

report={'schema':'heptabao.mac-current-owner-bound-source.mechanical-binding.r1',
        'status':'SOURCE_ONLY_NO_EXECUTION_AUTHORIZATION','newRoot':'/Volumes/T5/hepta-vnext-recovery-20261013/'+NEW,
        'newLabels':{'server':NEW_LABEL+'server','consumer':NEW_LABEL+'consumer'},
        'baselinePayloadBlob':'931383bbc295b82ad7ff6cf57c33af3395e20966',
        'reviewedOwnerRepairTree':'d03ff2c5eeff00a6639f95d66c4c4fca3105056a',
        'actualEntryPacketTree':'135407c6d3156a8602da63184c0df4143aa137ea',
        'entry':{'path':ENTRY,**pin(entry),'observedVersion':meta['version'],'historicalQualificationInherited':False},
        'sourceRows':source_rows,'changedSourceCount':len(changed),'unchangedSourceCount':len(unchanged),
        'rootLiteralCount':root_edits,'newLabelLiteralCount':2,'proofRows':proof_rows,'anchor':pin(anchor),
        'sourcePins':pin((HERE/'source-pins.public.json').read_bytes()),
        'candidate':pin((HERE/'documents/candidate-current-manager-wal-r1.public.json').read_bytes()),
        'publisherStdin':pin((HERE/'publisher-stdin.public.json').read_bytes()),
        'sameFunctionAndWorkerSemanticsAfterReversingBindings':True,
        'renewalLookupIncrementIntegrated':True,'reviewedRenewalSource':'26622454186ba28ada489c9a10b34cf4ad254b97','allBudgetsUnchanged':True,
        'privateCapsuleRead':False,'SDKExecuted':False,'newHostIO':False,
        'freshRootOrLabelsObservedAbsent':False,'inertRequestSubmitted':False,'runtimeRequestSubmitted':False}
dump(HERE/'BINDING.public.json',report)
print(json.dumps({k:report[k] for k in ['status','newRoot','changedSourceCount','unchangedSourceCount',
      'rootLiteralCount','sourcePins','candidate','publisherStdin','allBudgetsUnchanged']}))
