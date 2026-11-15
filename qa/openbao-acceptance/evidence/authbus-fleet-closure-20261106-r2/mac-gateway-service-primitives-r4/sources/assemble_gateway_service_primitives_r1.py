#!/usr/bin/env python3
"""Freeze the reviewed six-action core with unchanged qualified helper bytes."""
import ast,hashlib,json
from pathlib import Path

HERE=Path(__file__).resolve().parent
QUAL=HERE.parent/'main3-authbus-work/source-api-r5'
NAMES=('mac_owned_unreaped_r1.py','mac_owned_commands_r1.py',
 'mac_native_process_observer_r1.py','mac_owned_launchd_r3.py','mac_gateway_service_primitives_r1.py')
def sha(raw):return hashlib.sha256(raw).hexdigest()
sources={}
for name in NAMES:
 raw=((HERE if name==NAMES[-1] else QUAL)/name).read_bytes()
 sources[name]={'text':raw.decode(),'bytes':len(raw),'sha256':sha(raw)}
assert sources[NAMES[-1]]['sha256']=='eab8ad884a50c2adb4f2e6b49c7defbdd3e06a66f4e9cd9a446f900e4a86a285'
parser_names=['ManagerRefused','need','parse_print','missing_service']
parser_tree=ast.parse(sources['mac_owned_launchd_r3.py']['text'])
selected=[n for n in parser_tree.body if isinstance(n,(ast.ClassDef,ast.FunctionDef)) and n.name in parser_names]
assert [n.name for n in selected]==parser_names
payload={'schema':'heptabao.gateway-service-primitives.payload.r1','sources':sources,'parserNames':parser_names}
template=(HERE/'launch_gateway_service_primitives_r1.template.py').read_text()
assert template.count('# PAYLOAD_PLACEHOLDER')==1
source=template.replace('# PAYLOAD_PLACEHOLDER','PAYLOAD='+repr(payload))
compile(source,'launch_gateway_service_primitives_r1.py','exec')
assembled=ast.parse(source)
value=next(n.value for n in assembled.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PAYLOAD' for t in n.targets))
assert ast.literal_eval(value)==payload
for name,record in ast.literal_eval(value)['sources'].items():
 original=((HERE if name==NAMES[-1] else QUAL)/name).read_bytes()
 assert record['text'].encode()==original and record['sha256']==sha(original)
result={'schema':'heptabao.gateway-service-primitives.assembled-source.r1','actualMacRun':False,
 'coreOriginalUnchanged':True,'qualifiedHelperBytesUnchanged':True,'embeddedSourceReadbackExact':True,
 'parserWholeSourceBoundFourDefinitionsOnly':True,'parserDefinitionNames':parser_names,
 'template':{'bytes':len(template.encode()),'sha256':sha(template.encode())},
 'assembled':{'bytes':len(source.encode()),'sha256':sha(source.encode())},
 'sources':{name:{k:v for k,v in row.items() if k!='text'} for name,row in sources.items()}}
(HERE/'launch_gateway_service_primitives_r1.py').write_text(source)
(HERE/'gateway-service-primitives-r1.assembly.public.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
print(json.dumps(result,sort_keys=True))
