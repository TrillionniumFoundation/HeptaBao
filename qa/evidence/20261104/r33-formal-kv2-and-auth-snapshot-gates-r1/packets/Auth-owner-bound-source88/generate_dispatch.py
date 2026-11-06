#!/usr/bin/env python3
"""Pure local binding of exact create-only publisher and future runtime requests."""
import ast,base64,difflib,hashlib,json,os
from pathlib import Path
OWN=Path('/workspace/scratch/f86faac821c4/authbus_registration_body4_recovery_r1')
HERE=OWN/'owner-bound-renew-r1'
OLD_ROOT='/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-registry-wal-r1'
ROOT='/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-owner-bind-r1'
PYTHON='/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
def sha(bs):return hashlib.sha256(bs).hexdigest()
def pin(bs):return {'blob':hashlib.sha1(b'blob '+str(len(bs)).encode()+b'\0'+bs).hexdigest(),'bytes':len(bs),'sha256':sha(bs)}
def save(path,bs):
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():assert path.read_bytes()==bs;return
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:f.write(bs);f.flush();os.fsync(f.fileno())
def encoded(v):return (json.dumps(v,indent=2,ensure_ascii=False)+'\n').encode()
def set_constant(source,name,value):
    a=ast.parse(source);nodes=[n for n in a.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id==name]
    assert len(nodes)==1;node=nodes[0];lines=source.splitlines(keepends=True)
    old=''.join(lines[node.lineno-1:node.end_lineno]);new=name+'='+json.dumps(value,indent=4,ensure_ascii=False)+'\n'
    return ''.join(lines[:node.lineno-1])+new+''.join(lines[node.end_lineno:]),old,new

before=(OWN/'blobs/b0d546989d09c9e97e0edafda1a8144735f37003.txt').read_text()
assert pin(before.encode())['blob']=='b0d546989d09c9e97e0edafda1a8144735f37003'
assert before.count(OLD_ROOT)==1
source=before.replace(OLD_ROOT,ROOT)
payload_raw=(HERE/'publisher-stdin.public.json').read_bytes();payload=json.loads(payload_raw)
original_assignments={n.targets[0].id:ast.literal_eval(n.value) for n in ast.parse(before).body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('PINS','DOCUMENT_PINS')}
pins={name:[len(base64.b64decode(payload['files'][name])),sha(base64.b64decode(payload['files'][name]))] for name in original_assignments['PINS']}
documents={name:[len(base64.b64decode(payload['documents'][name])),sha(base64.b64decode(payload['documents'][name]))] for name in original_assignments['DOCUMENT_PINS']}
binding=[]
for name,value in [('PINS',pins),('DOCUMENT_PINS',documents),('PAYLOAD_BYTES',len(payload_raw)),('PAYLOAD_SHA',sha(payload_raw))]:
    source,old,new=set_constant(source,name,value);binding.append((name,old,new))
inverse=source
for name,old,new in reversed(binding):assert inverse.count(new)==1;inverse=inverse.replace(new,old)
assert inverse.replace(ROOT,OLD_ROOT)==before
new_ast=ast.parse(source);old_ast=ast.parse(before);compile(new_ast,'owner-bound-inert.py','exec')
old_defs={n.name:ast.get_source_segment(before,n) for n in old_ast.body if isinstance(n,(ast.FunctionDef,ast.ClassDef,ast.AsyncFunctionDef))}
new_defs={n.name:ast.get_source_segment(source,n) for n in new_ast.body if isinstance(n,(ast.FunctionDef,ast.ClassDef,ast.AsyncFunctionDef))}
assert old_defs==new_defs
save(HERE/'dispatch/inert-publisher.py',source.encode())
save(HERE/'diff/inert-publisher.binding.diff',''.join(difflib.unified_diff(before.splitlines(keepends=True),source.splitlines(keepends=True),fromfile='baseline/inert-publisher.py',tofile='dispatch/inert-publisher.py')).encode())
pub_pin=pin(source.encode())
inert={'host':'mac','executable':PYTHON,'args':['-I','-S','-B','-c',source],
       'cwd':'/Users/qianqi','stdin_text':payload_raw.decode(),'timeout_seconds':60,
       'idempotency_key':'heptabao-mac-current-owner-renew-inert-'+pub_pin['sha256'][:8]+'-20261105-r1'}
save(HERE/'dispatch/inert.exact-request.public.json',encoded(inert))

old_request_raw=(OWN/'blobs/db1c0badddf800b253a5476cdb1ab49f2cabf543.txt').read_bytes()
old_request=json.loads(old_request_raw);request=json.loads(old_request_raw)
assert old_request['host']=='mac' and old_request['cwd']=='/Users/qianqi' and old_request['timeout_seconds']==1080
request['executable']=PYTHON
request['args']=[arg.replace(OLD_ROOT,ROOT) for arg in request['args']]
sources=(HERE/'source-pins.public.json').read_bytes();candidate=(HERE/'documents/candidate-current-manager-wal-r1.public.json').read_bytes();anchor=(HERE/'volume-anchor.original.json').read_bytes()
for flag,value in [('--candidate-sha256',sha(candidate)),('--public-source-pins-base64',base64.b64encode(sources).decode()),('--public-source-pins-sha256',sha(sources))]:
    assert request['args'].count(flag)==1;request['args'][request['args'].index(flag)+1]=value
assert base64.b64decode(request['args'][request['args'].index('--public-volume-anchor-base64')+1])==anchor
assert request['args'][request['args'].index('--public-volume-anchor-sha256')+1]==sha(anchor)
outer=(HERE/'source/mac_current_outer_wal_r1.py').read_bytes()
request['idempotency_key']='heptabao-mac-current-five-agent-owner-renew-'+sha(outer)[:8]+'-20261105-r1'
save(HERE/'dispatch/runtime.exact-request.public.json',encoded(request))
save(HERE/'diff/runtime.exact-request.diff',''.join(difflib.unified_diff(old_request_raw.decode().splitlines(keepends=True),encoded(request).decode().splitlines(keepends=True),fromfile='baseline/runtime.exact-request.public.json',tofile='dispatch/runtime.exact-request.public.json')).encode())

runtime_proof=json.loads((HERE/'documents/proofs/synthetic-r2.stdout.public.json').read_text())['runtime']['pythonExecutable']
assert runtime_proof=={'path':PYTHON,'bytes':34640,'sha256':'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'}
targets=[{'path':ROOT+'/qa/'+name,'kind':'source','bytes':pair[0],'sha256':pair[1]} for name,pair in pins.items()]
targets += [{'path':ROOT+'/'+name,'kind':'public_document','bytes':pair[0],'sha256':pair[1]} for name,pair in documents.items()]
targets += [{'path':ROOT+'/inert-registry-wal-4e808-result.public.json','kind':'inert_candidate_receipt','bytes':None,'sha256':None,'bindOnlyFromActualFinalStdout':True}]
save(HERE/'dispatch/post-inert-targets.public.json',encoded({'status':'SOURCE_ONLY_NO_READ_REQUESTS_BOUND','targets':targets,'newObservations':0,'candidateIsNotAuthority':True}))
report={'schema':'heptabao.mac-current-owner-renew.dispatch-binding.source.r1',
        'status':'SOURCE_ONLY_NO_INERT_OR_RUNTIME_GO','inertPublisher':pub_pin,
        'inertRequest':pin(encoded(inert)),'runtimeRequest':pin(encoded(request)),
        'publisherStdin':pin(payload_raw),'sourcePins':pin(sources),'candidate':pin(candidate),'anchor':pin(anchor),
        'oldPublisherBlob':'b0d546989d09c9e97e0edafda1a8144735f37003',
        'oldRuntimeRequestBlob':'db1c0badddf800b253a5476cdb1ab49f2cabf543',
        'publisherDefinitionsUnchanged':len(old_defs),'publisherConstantAndRootInverseWholeExact':True,
        'publicSources':22,'publicDocuments':8,'futureReadbackTargetsIncludingReceipt':31,
        'regularPythonFromActualQualifiedSynthetic':runtime_proof,
        'originalPythonAliasChangedToObservedRegularPath':True,
        'inertBudget':{'shared':45,'diskutilClamped':30,'supervisor':60},
        'runtimeBudget':{'controller':900,'manager':600,'managerFailureCleanup':60,'phase':120,
            'capture':45,'query':3,'native':[15,8,3],'http':10,'ready':30,'supervisor':1080},
        'fixedDataCaps':{'registryWalBytes':5969912,'rowBytes':1048576,'aggregateBytes':8388608,'capsuleBytes':4194304},
        'newRootObserved':False,'newLabelsObserved':False,'rootMustAuthorizeEachExactDispatch':True,
        'runtimeRequiresKnownActualStageAndWholeReadback':True,'businessOrProviderCalls':0}
save(HERE/'DISPATCH.public.json',encoded(report))
print(json.dumps(report))
