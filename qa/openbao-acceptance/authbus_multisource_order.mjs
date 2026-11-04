#!/usr/bin/env node
/** Pure installed-SDK ordering on a private auth-only database. No provider I/O. */
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import cp from 'node:child_process';
import {createHash} from 'node:crypto';
import {syncBuiltinESMExports} from 'node:module';
import {pathToFileURL} from 'node:url';
process.umask(0o077);
const root=path.resolve(process.argv[2]),sdk='/opt/homebrew/lib/node_modules/openclaw';
const sha=x=>createHash('sha256').update(x).digest('hex');
const stable=x=>Array.isArray(x)?x.map(stable):x&&typeof x==='object'?Object.fromEntries(Object.keys(x).sort().map(k=>[k,stable(x[k])])):x;
const digest=x=>sha(JSON.stringify(stable(x)));
const save=(name,x)=>{const b=Buffer.from(JSON.stringify(x,null,2));const fd=fs.openSync(path.join(root,name),fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);try{fs.writeFileSync(fd,b);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}return sha(b);};
const r={schema:'heptabao.actual-sdk-multisource-order.v1',ok:false,providerCalls:0,refreshCalls:0,modelCalls:0,productionChanged:false,checks:[]};
const check=(caseName,v)=>{r.checks.push({case:caseName,passed:v===true});if(!v)throw Object.assign(new Error(caseName),{safeCode:caseName});};
let blocked=0;
const deny=()=>{blocked++;throw new Error('network_or_child_refused');};
try{
 check('private_state_scope',process.env.OPENCLAW_STATE_DIR===path.join(root,'order-sdk-state')&&process.env.OPENCLAW_AUTH_STORE_READONLY==='1');
 const origExec=cp.execFileSync;for(const n of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])cp[n]=deny;
 cp.execFileSync=(file,args,options)=>{if(file!=='mount'||!Array.isArray(args)||args.length||options!==undefined)return deny();return origExec('/sbin/mount',[],{timeout:3000,maxBuffer:262144,env:{PATH:'/usr/bin:/bin:/usr/sbin:/sbin'}});};
 globalThis.fetch=deny;http.request=deny;https.request=deny;http.get=deny;https.get=deny;net.connect=deny;net.createConnection=deny;syncBuiltinESMExports();
 const core=JSON.parse(fs.readFileSync('/Volumes/T5/hepta-vnext-recovery-20261013/authbus-profile2-selector-c138-20261104-r1/final360-core-r2/result.public.json'));
 r.sdkSourcePins={};
 for(const name of ['dist/plugin-sdk/agent-runtime.js','dist/order-CeBlX0NH.js','dist/store-DH33UrUj.js']){
   const full=path.join(sdk,name),actual=sha(fs.readFileSync(full));
   check('source.'+path.basename(name),core.sourcePins[full]===actual);r.sdkSourcePins[full]=actual;
 }
 const api=await import(pathToFileURL(path.join(sdk,'dist/plugin-sdk/agent-runtime.js')));
 const order=await import(pathToFileURL(path.join(sdk,'dist/order-CeBlX0NH.js')));
 const cfg=JSON.parse(fs.readFileSync(path.join(root,'original-config.private.json')));
 const bundle=JSON.parse(fs.readFileSync(path.join(root,'source-bundle.private.json')));
 const before=api.loadAuthProfileStoreWithoutExternalProfiles(path.join(process.env.OPENCLAW_STATE_DIR,'agents/main/agent'),{allowKeychainPrompt:false});
 const ids=Object.keys(before.profiles),ordinal=id=>ids.indexOf(id)+1;
 const originalStoreDigest=digest(before);
 const originalOrder=order.i({cfg,store:structuredClone(before),provider:'openai'});
 const projected=originalOrder.filter(id=>Object.hasOwn(bundle.credentials,id));
 check('original_sdk_order_covers_both_trusted_accounts',projected.length===2&&new Set(projected).size===2);
 const candidate=structuredClone(before);candidate.usageStats??={};
 for(const [id,credential] of Object.entries(bundle.credentials)){
  candidate.profiles[id]=structuredClone(credential);
  candidate.usageStats[id]={...candidate.usageStats[id],...bundle.observedUsageByProfile[id]};
 }
 const candidateBeforeManagedOrder=order.i({cfg,store:structuredClone(candidate),provider:'openai'});
 candidate.order??={};candidate.order.openai=[...projected];
 const finalOrder=order.i({cfg,store:structuredClone(candidate),provider:'openai'});
 check('trusted_only_managed_order',finalOrder.length===2&&finalOrder.every(id=>Object.hasOwn(bundle.credentials,id)));
 check('confirmed_invalid_refresh_excluded',bundle.excludedProfileIds.every(id=>!finalOrder.includes(id)));
 const p1=bundle.targetProfileIds[0];
 check('actual_future_quota_preserved',candidate.usageStats[p1].blockedUntil===bundle.observedUsageByProfile[p1].blockedUntil
    &&candidate.usageStats[p1].blockedReason==='subscription_limit');
 check('original_sdk_read_unchanged',digest(api.loadAuthProfileStoreWithoutExternalProfiles(path.join(process.env.OPENCLAW_STATE_DIR,'agents/main/agent'),{allowKeychainPrompt:false}))===originalStoreDigest);
 const policy={schemaVersion:1,generation:1,providers:{openai:{candidates:projected.map(id=>({profileId:id,digest:digest(bundle.credentials[id]),enrolledAt:Date.now()})),activeProfile:projected[0],enforceManagedOrder:true}}};
 const documents=JSON.parse(fs.readFileSync(path.join(root,'seed-documents-without-order.private.json')));documents['order-policy']=policy;
 r.seedDocumentsSha256=save('seed-documents.private.json',documents);
 r.orderBindingSha256=save('order-binding.private.json',{originalOrder,projectedManagedOrder:projected,candidateBeforeManagedOrder,actualFinalOrder:finalOrder,originalStore:before,candidateStore:candidate});
 r.originalSdkOrderOrdinals=originalOrder.map(ordinal);r.projectedManagedOrderOrdinals=projected.map(ordinal);
 r.candidateBeforeManagedOrderOrdinals=candidateBeforeManagedOrder.map(ordinal);r.actualFinalOrderOrdinals=finalOrder.map(ordinal);
 r.orderPolicy='Preserve the original installed-SDK resolved relative order for the two exact same-account trusted sources; exclude only the confirmed invalid-refresh account. Let the same installed SDK apply its unchanged quota/cooldown ordering.';
 r.originalConfigUntouched=true;r.originalProviderDefaultUnchanged=true;r.actualFutureQuotaPreserved=true;r.businessAvailabilityQualified=false;
 r.blockedOperationCount=blocked;check('no_network_or_child_attempt',blocked===0);r.ok=true;
}catch(e){r.error=e?.safeCode??e?.name??'Error';}
save('order.public.json',r);process.stdout.write(JSON.stringify({ok:r.ok,error:r.error,result:path.join(root,'order.public.json')})+'\n');process.exitCode=r.ok?0:1;
