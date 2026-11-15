#!/usr/bin/env python3
"""Create-only minimum successor for the recorded synthetic registration failure."""
from pathlib import Path
import hashlib

HERE=Path(__file__).resolve().parent
PINS={
 'mac_gateway_registration_cases_r1.mjs':'27c7709d10a28864aca2bcffc558bfd069c1a2fd2600ae6066616e4fb39d2e08',
 'mac_gateway_registration_qualification_r1.mjs':'ce5ba2caa28906423a6c5c3c632ab5dab07427f6e5c3496bfba5a489b61fdf8f',
 'launch_gateway_registration_qualification_r1.template.py':'c5718846781c2659a7cee11a2d9d5b10f15a95bf055ba3c3e3aa26e229e07a3f',
}
def replace(s,old,new):
 assert s.count(old)==1,(old,s.count(old))
 return s.replace(old,new)
def save(name,s):
 with (HERE/name).open('x') as f:f.write(s)
for name,pin in PINS.items():assert hashlib.sha256((HERE/name).read_bytes()).hexdigest()==pin
def successor(name):
 s=(HERE/name).read_text().replace('registration-qualification-20261106-r1','registration-qualification-20261106-r2')
 s=s.replace('registration_cases_r1','registration_cases_r2').replace('registration_qualification_r1','registration_qualification_r2')
 s=s.replace('registration.r1','registration.r2').replace('synthetic-plan.r1','synthetic-plan.r2')
 s=s.replace('registration-owned.r1','registration-owned.r2').replace("ROOT+'/output/state'","ROOT+'/output/home/.openclaw'")
 s=s.replace('output/state','output/home/.openclaw').replace('openclaw/global.env','openclaw/gateway.env')
 return s

cases=successor('mac_gateway_registration_cases_r1.mjs')
cases=replace(cases,'runGatewayCases({check,need,report,load,sourceFence})','runGatewayCases({check,need,report,load,sourceFence,recordPrivate})')
cases=replace(cases," const runtime={error:()=>{errors.push(true);},exit:code=>{exits.push(code);}};", """ const captureError=value=>{const message=String(value);need(message.length<=16384&&errors.length<32,
  'gateway_bounded_private_runtime_error');errors.push(message);};
 const runtime={error:captureError,exit:code=>{exits.push(code);}};
 try{""")
old="""  need(await pre.selectGatewayRunEnvironment({opts:{},runtime})===true&&selectorsExact(),
   'gateway_original_environment_selection_complete');
  selectionSnapshot=await configApi.readConfigFileSnapshot({isolateEnv:true,observe:false});
  snapshotExact(selectionSnapshot);
  need(errors.length===0&&exits.length===0,'gateway_no_initial_selector_refusal');"""
new="""  const selected=await pre.selectGatewayRunEnvironment({opts:{},runtime});
  selectionSnapshot=await configApi.readConfigFileSnapshot({isolateEnv:true,observe:false});
  recordPrivate('selection',{selected,selectorsExact:selectorsExact(),path:selectionSnapshot.path,
   exists:selectionSnapshot.exists,valid:selectionSnapshot.valid,issues:selectionSnapshot.issues,
   warnings:selectionSnapshot.warnings,legacyIssues:selectionSnapshot.legacyIssues});
  need(selected===true&&selectorsExact(),'gateway_original_environment_selection_complete');
  snapshotExact(selectionSnapshot);
  need(report.originalDotenvReads.state>0&&report.originalDotenvReads.gateway>0
   &&process.env.HEPTABAO_STATE_ENV_MARKER==='state-original-read'
   &&process.env.HEPTABAO_GATEWAY_ENV_MARKER==='gateway-original-read'
   &&process.env.HEPTABAO_CONFIG_ENV_MARKER==='config-original-applied',
   'gateway_actual_conflicting_dotenv_reads_and_harmless_markers');
  report.actualStateAndGatewayDotenvReadsObserved=true;
  const invalid=structuredClone(selectionSnapshot.sourceConfig);
  invalid.plugins.entries[AUTHBUS].config={};
  const invalidResult=configApi.validateConfigObjectWithPlugins(invalid,{env:process.env});
  recordPrivate('empty-config',{ok:invalidResult.ok,issues:invalidResult.issues,warnings:invalidResult.warnings});
  need(invalidResult.ok===false&&Array.isArray(invalidResult.issues)&&invalidResult.issues.length>0
   &&invalidResult.issues.every(issue=>issue.path.startsWith('plugins.entries.'+AUTHBUS+'.config')),
   'gateway_original_validator_rejects_previous_empty_disabled_plugin_config');
  report.previousEmptyDisabledConfigRejectedByOriginalValidator=true;
  need(errors.length===0&&exits.length===0,'gateway_no_initial_selector_refusal');"""
cases=replace(cases,old,new)
cases=replace(cases,"log:{info:()=>{},error:()=>{errors.push(true);}}","log:{info:()=>{},error:captureError}")
cases=replace(cases," report.gatewayServiceMutationAttempted=false;\n}",""" report.gatewayServiceMutationAttempted=false;
 }finally{recordPrivate('runtime',{errors,exits});}
}""")
save('mac_gateway_registration_cases_r2.mjs',cases)

worker=successor('mac_gateway_registration_qualification_r1.mjs')
worker=replace(worker," authbusModuleLoadAttempts:0,controlModuleLoadAttempts:0,loadedEntryModules:[],", " authbusModuleLoadAttempts:0,controlModuleLoadAttempts:0,loadedEntryModules:[],\n originalDotenvReads:{state:0,gateway:0},privateDiagnosticFiles:[],")
anchor="function sourceFence(){"
insert="""function recordPrivate(name,value){
 need(['selection','empty-config','runtime'].includes(name),'gateway_fixed_private_diagnostic_name');
 const raw=Buffer.from(JSON.stringify(value)+'\\n');need(raw.length<=262144,'gateway_bounded_private_diagnostics');
 const fd=originalFs.openSync(ROOT+'/output/'+name+'-diagnostic.private.json',
  fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
 const row={role:'private-synthetic-diagnostic',closeAttempts:0,closed:false};report.fileDescriptors.push(row);
 try{let offset=0;while(offset<raw.length){remainingMs();const n=fs.writeSync(fd,raw,offset,raw.length-offset,null);
  need(n>0,'gateway_private_diagnostic_write_progress');offset+=n;}fs.fsyncSync(fd);}
 finally{row.closeAttempts++;originalFs.closeSync(fd);row.closed=true;}
 const directory=originalFs.openSync(ROOT+'/output',fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
 const dirRow={role:'private-diagnostic-directory',closeAttempts:0,closed:false};report.fileDescriptors.push(dirRow);
 try{fs.fsyncSync(directory);}finally{dirRow.closeAttempts++;originalFs.closeSync(directory);dirRow.closed=true;}
 report.privateDiagnosticFiles.push(name);
}
"""
worker=replace(worker,anchor,insert+anchor)
worker=replace(worker,"const original=object[key];replace(object,key,function(file,...args){productionGuard(file);return original.call(this,file,...args);});", """const original=object[key];replace(object,key,function(file,...args){
    const name=productionGuard(file),value=original.call(this,file,...args);
    if(object===fs&&key==='readFileSync'){
     if(name===STATE+'/.env')report.originalDotenvReads.state++;
     if(name===HOME+'/.config/openclaw/gateway.env')report.originalDotenvReads.gateway++;
    }return value;
   });""")
worker=replace(worker,'runGatewayCases({check,need,report,load,sourceFence});','runGatewayCases({check,need,report,load,sourceFence,recordPrivate});')
save('mac_gateway_registration_qualification_r2.mjs',worker)

template=successor('launch_gateway_registration_qualification_r1.template.py')
old="""   'output/home/.openclaw','output/home/.openclaw/state','output/home/.openclaw/oauth','output/home','output/home/.config','output/home/.config/openclaw',"""
new="""   'output/home','output/home/.openclaw','output/home/.openclaw/state','output/home/.openclaw/oauth','output/home/.config','output/home/.config/openclaw',"""
template=replace(template,old,new)
template=replace(template,"    and value.get('actualPreBootstrapFinalFallbackSelected') is True", "    and value.get('actualStateAndGatewayDotenvReadsObserved') is True\n    and value.get('previousEmptyDisabledConfigRejectedByOriginalValidator') is True\n    and value.get('actualPreBootstrapFinalFallbackSelected') is True")
save('launch_gateway_registration_qualification_r2.template.py',template)

assembler=successor('assemble_gateway_registration_qualification_r1.py')
assembler=assembler.replace('gateway-registration-r1.assembly','gateway-registration-r2.assembly').replace('assembled-source.r1','assembled-source.r2')
assembler=replace(assembler,"  'HOME':ROOT+'/output/decoy-home'},'shellEnv':{'enabled':False}},", "  'HOME':ROOT+'/output/decoy-home','HEPTABAO_CONFIG_ENV_MARKER':'config-original-applied'},'shellEnv':{'enabled':False}},")
assembler=replace(assembler,"'entries':{'openclaw-authbus':{'enabled':False,'config':{}},", """'entries':{'openclaw-authbus':{'enabled':False,'config':{
   'address':'https://127.0.0.1:9','caFile':ROOT+'/output/synthetic-ca-not-opened.pem',
   'roleIdFile':ROOT+'/output/synthetic-role-not-opened','secretIdFile':ROOT+'/output/synthetic-secret-not-opened',
   'hostId':'heptabao-qualification'}},""")
assembler=replace(assembler,"'output/home/.openclaw/.env':dotenv,'output/home/.config/openclaw/gateway.env':dotenv}", "'output/home/.openclaw/.env':dotenv+'HEPTABAO_STATE_ENV_MARKER=state-original-read\\n',\n 'output/home/.config/openclaw/gateway.env':dotenv+'HEPTABAO_GATEWAY_ENV_MARKER=gateway-original-read\\n'}")
save('assemble_gateway_registration_qualification_r2.py',assembler)
print('Created four r2 sources; r1 bytes remained pinned and unchanged.')
