#!/usr/bin/env python3
"""Create an immutable reviewable relay observer from exact qualified sources."""
import ast
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
PRIOR=HERE.parent/'mac-current-inventory-r3-work/launch_current_database_inventory_r3.py'
def sha(raw):return hashlib.sha256(raw).hexdigest()
parsed=ast.parse(PRIOR.read_bytes())
assignment=next(node for node in parsed.body if isinstance(node,ast.Assign)
 and any(isinstance(target,ast.Name) and target.id=='PAYLOAD' for target in node.targets))
prior=ast.literal_eval(assignment.value)
pins={
 'mac_owned_unreaped_r1.py':'d735a9e9330e1260d44ad9e4c854d50094e20d85fe5633ddd9042281b3346298',
 'mac_owned_commands_r1.py':'71a11bf9a0510c991b78c9bc3f094f315bf4914485b9cfda81c6e501eaf73530',
 'mac_native_process_observer_r1.py':'cc0fa9917d05c6dc2c295594f980c1f77d089c1196e6279a14f2fdaf2d77ae9b',
 'mac_owned_launchd_r3.py':'19c131fa1952a48e99f521fee024bb9ef34ccc94901cc604b0c75c7424689031',
 'mac_current_gateway_observation_r2.py':'bc558d3c58d81db4c16cad25e728512564931c2b32b9fb7c10ebc915a7036ecb'}
sources={}
for name,pin in pins.items():
 raw=prior['sources'][name].encode()
 assert sha(raw)==pin==prior['sourcePins'][name]
 sources[name]={'text':raw.decode(),'bytes':len(raw),'sha256':pin}
for name in ('mac_gateway_service_primitives_r4.py','mac_registered_relays_r1.py'):
 raw=(HERE/name).read_bytes()
 if name=='mac_gateway_service_primitives_r4.py':
  assert len(raw)==14867 and sha(raw)=='0f9f7fe2c3293c8790ca6e906906e7ce6797b382a1b314569fd33acecc0fb652'
 compile(raw,name,'exec')
 sources[name]={'text':raw.decode(),'bytes':len(raw),'sha256':sha(raw)}
payload={'schema':'heptabao.fixed-four-relay-observation.payload.r1','sources':sources,
 'custodyQualificationAuthority':prior['custodyQualificationAuthority']}
template=(HERE/'launch_registered_relays_r1.template.py').read_text()
assert template.count('# PAYLOAD_PLACEHOLDER')==1
output=template.replace('# PAYLOAD_PLACEHOLDER','PAYLOAD = '+repr(payload)).encode()
compile(output,'launch_registered_relays_r1.py','exec')
(HERE/'launch_registered_relays_r1.py').write_bytes(output)
manifest={'schema':'heptabao.fixed-four-relay-observation-prepared.public.r1',
 'preparedOnly':True,'runtimeExecuted':False,'actualPrivatePlistsOrCredentialsIncluded':False,
 'sourcePins':{name:{key:value[key] for key in ('bytes','sha256')} for name,value in sources.items()},
 'template':{'bytes':len(template.encode()),'sha256':sha(template.encode())},
 'assembled':{'bytes':len(output),'sha256':sha(output)},
 'originalLaunchctlCommandsExpected':10,'sharedSeconds':45,'supervisorSeconds':70,
 'originalRetainedCustodyIncludesItsOwnPsMetadataChildren':True,
 'serviceActions':0,'providerCalls':0,'databaseReads':0,
 'processArgumentsOrigin':'launchctl_registration_not_kernel_argv_or_memory'}
(HERE/'registered-relays-prepared-r1.public.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
print(json.dumps(manifest,sort_keys=True))
