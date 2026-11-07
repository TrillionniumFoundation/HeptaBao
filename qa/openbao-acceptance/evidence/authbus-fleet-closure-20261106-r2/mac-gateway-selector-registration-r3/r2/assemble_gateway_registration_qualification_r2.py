#!/usr/bin/env python3
"""Reproducible isolated qualification payload; contains no production data."""
import ast,hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT='/Users/qianqi/heptabao-authbus-gateway-registration-qualification-20261106-r2'
STATE=ROOT+'/output/home/.openclaw';CONFIG=ROOT+'/output/maintenance/fallback.json'
AUTH=ROOT+'/code/disabled-authbus';CONTROL=ROOT+'/code/control'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def payload_from(path):
 tree=ast.parse(path.read_bytes())
 return ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign)
  and any(isinstance(x,ast.Name) and x.id=='PAYLOAD' for x in n.targets)))
previous=payload_from(HERE/'launch_gateway_fallback_sdk_qualification_r1.py')
names=['mac_gateway_registration_cases_r2.mjs','mac_gateway_registration_qualification_r2.mjs']
sources={name:(HERE/name).read_text() for name in names}
sdk_pins={}
loader_names=['paths-C6ahtu79.js','pre-bootstrap-8G8HyMEQ.js','config-env-vars-DlUfO5Q_.js',
 'env-vars-CxBOhHoc.js','dotenv-global-BWJcNSxD.js','dotenv-global-mWLbBl_z.js','state-dir-dotenv-COuz1wV3.js',
 'server-plugin-bootstrap-CtU_XTUf.js','server-plugins-XoQmHCe9.js','loader-D8d2EvVh.js',
 'manifest-registry--UiRn6nq.js','runtime-D0xGMZdc.js','hook-runner-global-BmIrGlLG.js',
 'plugin-auto-enable-B2g1v2k7.js','plugin-activation-runtime-config-CAjq5WJb.js']
for name in loader_names:sdk_pins['dist/'+name]=sha((HERE/'reference/gateway-loader'/name).read_bytes())
selector_names=['runtime-hooks-Dp2OHV46.js','future-config-guard-Dsfo4DuW.js','env-BDmU26qh.js',
 'utils-DE-8o42N.js','shell-env-CQbFDviS.js','utils-CRO4LGEB.js','shell-env-DaE9Xx3-.js','env-CKdem44B.js','io-By0s-a_s.js']
for name in selector_names:sdk_pins['dist/'+name]=sha((HERE/'reference/gateway-selector'/name).read_bytes())
sdk_pins['dist/config/config.js']=sha((HERE/'reference/gateway-selector/config_config.js').read_bytes())
sdk_pins['dist/paths-BMBAvkNf.js']=sha((HERE/'reference/gateway-fallback/paths-BMBAvkNf.js').read_bytes())
for name in ['openclaw-state-db-DzSsA9Ji.js','sqlite-wal-Bhk2Ro-u.js']:
 sdk_pins['dist/'+name]=sha((HERE/'reference'/name).read_bytes())
sdk_pins['dist/config-state-CtMlHVRM.js']=previous['sdkPins']['dist/config-state-CtMlHVRM.js']
auth_files={name:(HERE.parent/'main3-authbus-work/reference/current-plugin'/name).read_text() for name in ['index.js','package.json']}
auth_files['openclaw.plugin.json']=(HERE/'reference/gateway-loader/openclaw.plugin.json').read_text()
control_js="""'use strict';
module.exports = {
 id: 'heptabao-qualification-control',
 name: 'Credential-free gateway qualification control',
 register(api) {
  const record=globalThis[Symbol.for('heptabao.gateway.registration.qualification.r1')];
  if(!record||record.registrations!==0)throw new Error('synthetic_control_registration_not_once');
  record.registrations++;
  api.on('gateway_start',async()=>{record.gatewayStartHooks++;});
 }
};
"""
def encoded(value):return json.dumps(value,sort_keys=True,indent=2)+'\n'
control_files={'index.cjs':control_js,
 'package.json':encoded({'name':'heptabao-qualification-control','version':'1.0.0','type':'commonjs',
  'openclaw':{'extensions':['./index.cjs']}}),
 'openclaw.plugin.json':encoded({'id':'heptabao-qualification-control','name':'Credential-free qualification control',
  'activation':{'onStartup':True},'configSchema':{'type':'object','additionalProperties':False,'properties':{}}})}
config={'gateway':{'mode':'local','controlUi':{'enabled':False},'auth':{'mode':'none'}},
 'agents':{'defaults':{'workspace':ROOT+'/output/workspace'}},
 'logging':{'level':'silent','consoleLevel':'silent','file':ROOT+'/output/logs/openclaw.log'},
 'env':{'vars':{'OPENCLAW_CONFIG_PATH':STATE+'/openclaw.json','OPENCLAW_STATE_DIR':ROOT+'/output/decoy-state',
  'HOME':ROOT+'/output/decoy-home','HEPTABAO_CONFIG_ENV_MARKER':'config-original-applied'},'shellEnv':{'enabled':False}},
 'plugins':{'enabled':True,'allow':['openclaw-authbus','heptabao-qualification-control'],
  'load':{'paths':[AUTH,CONTROL]},'slots':{'memory':'none'},
  'entries':{'openclaw-authbus':{'enabled':False,'config':{
   'address':'https://127.0.0.1:9','caFile':ROOT+'/output/synthetic-ca-not-opened.pem',
   'roleIdFile':ROOT+'/output/synthetic-role-not-opened','secretIdFile':ROOT+'/output/synthetic-secret-not-opened',
   'hostId':'heptabao-qualification'}},'heptabao-qualification-control':{'enabled':True,'config':{}}}}}
decoy={'gateway':{'mode':'local'},'plugins':{'entries':{'openclaw-authbus':{'enabled':True}}}}
dotenv='OPENCLAW_CONFIG_PATH='+STATE+'/openclaw.json\nOPENCLAW_STATE_DIR='+ROOT+'/output/decoy-state\nHOME='+ROOT+'/output/decoy-home\n'
synthetic={'output/maintenance/fallback.json':encoded(config),'output/home/.openclaw/openclaw.json':encoded(decoy),
 'output/decoy-state/openclaw.json':encoded(decoy),'output/home/.openclaw/.env':dotenv+'HEPTABAO_STATE_ENV_MARKER=state-original-read\n',
 'output/home/.config/openclaw/gateway.env':dotenv+'HEPTABAO_GATEWAY_ENV_MARKER=gateway-original-read\n'}
payload={'sources':sources,'sourcePins':{name:sha(text.encode()) for name,text in sources.items()},'sdkPins':sdk_pins,
 'publicPluginPins':{name:sha(text.encode()) for name,text in auth_files.items()},'authbusPublicFiles':auth_files,
 'controlFiles':control_files,'syntheticInputs':synthetic,'custodyQualificationAuthority':previous['custodyQualificationAuthority']}
template=(HERE/'launch_gateway_registration_qualification_r2.template.py').read_text()
assert template.count('# PAYLOAD_PLACEHOLDER')==1
source=template.replace('# PAYLOAD_PLACEHOLDER','PAYLOAD='+repr(payload))
compile(source,'launch_gateway_registration_qualification_r2.py','exec')
tree=ast.parse(source);again=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign)
 and any(isinstance(t,ast.Name) and t.id=='PAYLOAD' for t in n.targets)))
assert again==payload
for name in names:assert again['sources'][name].encode()==(HERE/name).read_bytes()
(HERE/'launch_gateway_registration_qualification_r2.py').write_text(source)
proof={'schema':'heptabao.gateway-registration-assembled-source.r2','actualRun':False,'embeddedSourceBytesExact':True,
 'originalOuterChildren':3,'expectedCases':15,'originalSharedSeconds':45,'supervisorSeconds':70,
 'sourcePins':payload['sourcePins'],'sdkPins':sdk_pins,'publicPluginPins':payload['publicPluginPins'],
 'template':{'bytes':len(template.encode()),'sha256':sha(template.encode())},
 'assembled':{'bytes':len(source.encode()),'sha256':sha(source.encode())}}
(HERE/'gateway-registration-r2.assembly.public.json').write_text(encoded(proof))
print(json.dumps(proof,sort_keys=True))
