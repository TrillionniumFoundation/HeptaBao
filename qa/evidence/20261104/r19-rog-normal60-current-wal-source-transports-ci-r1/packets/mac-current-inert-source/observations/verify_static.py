#!/usr/bin/env python3
"""AST/compile and byte/payload verification only: never import or execute a candidate."""
import ast,base64,hashlib,json,pathlib,sys
root=pathlib.Path(__file__).parent
data=json.loads((root/'static-input-final.public.json').read_bytes())
request=data['request'];source=request['args'][-1];before=data['baseCarrier']
payload_raw=request['stdin'].encode();payload=json.loads(payload_raw)
def pin(raw):
    if isinstance(raw,str):raw=raw.encode()
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def definition(raw,node):
    return ''.join(raw.splitlines(keepends=True)[node.lineno-1:node.end_lineno])
old_ast=ast.parse(before);new_ast=ast.parse(source)
compile(new_ast,'candidate-inert.py','exec')
old_defs={x.name:x for x in old_ast.body if isinstance(x,(ast.FunctionDef,ast.ClassDef))}
new_defs={x.name:x for x in new_ast.body if isinstance(x,(ast.FunctionDef,ast.ClassDef))}
same=[]
for name in ('Refused','need','sha','encode','remaining','on_signal','critical','load_definition_module'):
    assert definition(before,old_defs[name])==definition(source,new_defs[name]),name
    same.append(name)
assert set(new_defs)-set(old_defs)=={'fresh_root_absent','publish_public'}
changed=[name for name in old_defs if definition(before,old_defs[name])!=definition(source,new_defs[name])]
assert set(changed)=={'stdin_once','main'}
assert request['host']=='mac' and request['executable']=='/opt/homebrew/bin/python3'
assert request['args'][:4]==['-I','-S','-B','-c'] and len(request['args'])==5
assert request['cwd']=='/Users/qianqi' and request['timeout_seconds']==60
assert pin(source)==data['expectedSource'] and pin(before)==data['basePin']
assert pin(payload_raw)==data['expectedPayload']
request_raw=json.dumps(request,ensure_ascii=False,indent=2)+'\n'
assert pin(request_raw)==data['expectedRequest']
assign={target.id:node.value for node in new_ast.body if isinstance(node,ast.Assign)
        for target in node.targets if isinstance(target,ast.Name)}
pins=ast.literal_eval(assign['PINS']);docs=ast.literal_eval(assign['DOCUMENT_PINS'])
assert len(pins)==21 and len(docs)==6
assert ast.literal_eval(assign['PAYLOAD_BYTES'])==len(payload_raw)
assert ast.literal_eval(assign['PAYLOAD_SHA'])==hashlib.sha256(payload_raw).hexdigest()
assert set(payload)=={'schema','files','documents','anchorBase64'}
assert payload['schema']=='heptabao.mac-current-native-df026-inert-public-inputs.r1'
assert set(payload['files'])==set(pins)==set(data['sourcePins'])
assert set(payload['documents'])==set(docs)==set(data['documentPins'])
compiled=[];raw_only=[]
for name,encoded in payload['files'].items():
    raw=base64.b64decode(encoded,validate=True);p=pin(raw)
    assert p==data['sourcePins'][name] and [p['bytes'],p['sha256']]==pins[name],name
    if name.endswith('.py'):
        compile(ast.parse(raw,filename=name),name,'exec');compiled.append(name)
    else:
        assert name.endswith('.mjs');raw_only.append(name)
assert len(compiled)==17 and len(raw_only)==4
decoded={}
for name,encoded in payload['documents'].items():
    raw=base64.b64decode(encoded,validate=True);p=pin(raw);decoded[name]=raw
    assert p==data['documentPins'][name] and [p['bytes'],p['sha256']]==docs[name],name
assert len([x for x in decoded if x.startswith('proofs/')])==5
candidate=json.loads(decoded['candidate-current-manager-native-r1.public.json'])
assert candidate['sourcePins']=={name:pair[1] for name,pair in pins.items()}
anchor=base64.b64decode(payload['anchorBase64'],validate=True)
assert len(anchor)==967
assert hashlib.sha256(anchor).hexdigest()==ast.literal_eval(assign['ANCHOR_SHA'])==candidate['publicVolumeAnchorSha256']
loads=[n for n in ast.walk(new_ast) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)
       and n.func.id=='load_definition_module']
assert [ast.literal_eval(n.args[0]) for n in loads]==[
 'mac_owned_unreaped_r1.py','mac_owned_commands_r1.py','mac_t5_volume_guard_r1.py']
assert not any(isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and
               n.func.id in ('eval','__import__') for n in ast.walk(new_ast))
report={'schema':'heptabao.mac-native-current-inert-static-review.r1',
 'ok':True,'mode':'AST_compile_and_exact_public_bytes_only',
 'candidateInertExecuted':False,'candidateModulesImported':False,'hostCalls':0,
 'privateReads':0,'childProcesses':0,'changedOriginalDefinitions':changed,
 'unchangedOriginalDefinitions':same,'newDefinitions':['fresh_root_absent','publish_public'],
 'compiledPythonSources':compiled,'javascriptWholeByteOnly':raw_only,
 'sourceCount':len(pins),'publicDocumentCount':len(docs),
 'payload':pin(payload_raw),'source':pin(source),'request':pin(request_raw),
 'outerSeconds':60,'originalInertSeconds':45,'originalDiskutilCapSeconds':30,
 'publicTransportCapExactBytes':len(payload_raw),
 'sourceAndDocumentPayloadMatchesPriorFrozenPins':True,
 'rawProofBytesNotReserialized':True,'allCandidateEntryExecutionForbidden':True}
raw=json.dumps(report,indent=2,sort_keys=True)+'\n'
(root/'static-result.public.json').write_text(raw)
print(raw,end='')
