/** Use the installed SDK to initialize or observe a private gateway store. */
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
process.umask(0o077);
const plan=JSON.parse(fs.readFileSync(process.argv[2]));
const stable=v=>Array.isArray(v)?v.map(stable):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])])):v;
const digest=v=>createHash('sha256').update(JSON.stringify(stable(v))).digest('hex');
const sdk=await import(pathToFileURL(path.join(plan.sdkRoot,'dist/plugin-sdk/agent-runtime.js')));
const storeApi=await import(pathToFileURL(path.join(plan.sdkRoot,'dist/store-DH33UrUj.js')));
const agentDir=path.join(plan.stateRoot,'agents/main/agent');
let report={ok:false,mode:plan.mode,providerCalled:false,productionChanged:false};
try{
  if(path.resolve(sdk.resolveDefaultAgentDir({}))!==agentDir)throw Error('default_agent_scope');
  if(plan.mode==='initialize'){
    const baseline={version:1,profiles:{}};
    const value=await storeApi.m({agentDir,updater:store=>{
      for(const k of Object.keys(store))delete store[k];Object.assign(store,baseline);return true;
    }});
    if(!value)throw Error('initial_store_write');
  }
  sdk.clearRuntimeAuthProfileStoreSnapshots();
  const store=sdk.loadAuthProfileStoreWithoutExternalProfiles(agentDir,{allowKeychainPrompt:false});
  report.storeSha256=digest(store);report.profileCount=Object.keys(store.profiles).length;
  if(plan.mode==='observe-selected'){
    const selection=JSON.parse(fs.readFileSync(plan.selectionPath));
    report.exactSelectedCredential=digest(store.profiles[selection.profileId])===selection.credentialSha256;
    report.onlyRealOwnedProfile=Object.keys(store.profiles).length===1&&Object.hasOwn(store.profiles,selection.profileId);
    report.managedOrderExact=Array.isArray(store.order?.openai)&&store.order.openai.length===1&&store.order.openai[0]===selection.profileId;
    if(!(report.exactSelectedCredential&&report.onlyRealOwnedProfile&&report.managedOrderExact))throw Error('actual_store_selection');
  }
  report.ok=true;
}catch(e){report.error=e?.message??'store_observation_failed';}
process.stdout.write(JSON.stringify(report)+'\n');process.exitCode=report.ok?0:1;
