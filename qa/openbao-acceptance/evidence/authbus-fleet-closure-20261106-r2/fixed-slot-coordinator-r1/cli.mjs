#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { openCoordinator } from './coordinator.mjs';
import { readPrivateJson } from './private-journal.mjs';
import { need, UUID } from './protocol.mjs';

const COMMANDS=new Set(['initialize','authorize','revoke-authorization','bootstrap','enroll','recover','once','serve','shutdown']);
let coordinator,stopping=false,exitCode=1;
const signals=[];
for(const name of ['SIGINT','SIGTERM','SIGHUP'])process.on(name,()=>{signals.push(name);stopping=true;});
const report={schema:'heptabao.fixed-slot-coordinator-cli.r1',ok:false,credentialValuesOrDigestsPublished:false,
  providerCalls:0,schedulerActions:0,legacyInboxTouched:false};
try{
  const [command,configPath,input,...extra]=process.argv.slice(2);
  need(COMMANDS.has(command)&&typeof configPath==='string'&&path.isAbsolute(configPath)&&extra.length===0,'coordinator_cli_arguments');
  const config=readPrivateJson(configPath,131072);coordinator=openCoordinator(config);report.command=command;
  if(command==='authorize'||command==='bootstrap'){
    need(typeof input==='string'&&path.isAbsolute(input),'coordinator_private_input_required');
    const value=readPrivateJson(input,131072);report.result=await coordinator[command](value);
  }else if(command==='revoke-authorization'){
    need(typeof input==='string'&&UUID.test(input),'coordinator_authorization_id_required');report.result=await coordinator.revokeAuthorization(input);
  }else if(command==='serve'){
    const maxCycles=input===undefined?null:Number(input);need(maxCycles===null||Number.isSafeInteger(maxCycles)&&maxCycles>=1&&maxCycles<=1000000,'coordinator_cycle_bound');
    let cycles=0;
    while(!stopping&&(maxCycles===null||cycles<maxCycles)){
      const result=await coordinator.once();cycles++;
      process.stdout.write(JSON.stringify({schema:'heptabao.fixed-slot-coordinator-cycle.r1',cycle:cycles,...result})+'\n');
      if(!stopping&&(maxCycles===null||cycles<maxCycles))await new Promise(resolve=>setTimeout(resolve,config.pollMs));
    }
    report.result={completedCycles:cycles,admissionStopped:stopping};
  }else if(command==='shutdown'){
    need(input===undefined,'coordinator_unexpected_cli_input');
    report.result=await coordinator.close({revoke:true,deadlineMs:Date.now()+15000});
  }else{need(input===undefined,'coordinator_unexpected_cli_input');report.result=await coordinator[command]();}
  report.ok=true;exitCode=0;
}catch(error){const code=error?.code??error?.message;report.errorCode=typeof code==='string'&&/^[a-z][a-z0-9_]{0,100}$/.test(code)?code:'coordinator_local_or_dependency_failure';
  report.outcomeUnknown=error?.unknown===true;}
finally{
  if(coordinator){try{report.close=await coordinator.close({revoke:false});}catch(error){report.closeFailed=true;report.ok=false;exitCode=1;}}
  report.cancellationObserved=signals.length>0;
  process.stdout.write(JSON.stringify(report)+'\n');
}
process.exitCode=exitCode;
