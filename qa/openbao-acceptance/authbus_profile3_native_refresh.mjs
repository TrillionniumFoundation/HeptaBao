#!/usr/bin/env node
/** One native, identity-bound refresh; seal the response before adopting it.
 * The installed SDK's cross-agent lock serializes local refreshes. The existing
 * production credentials are only read. No login, retry, or live pointer update.
 */
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import cp from 'node:child_process';
import dns from 'node:dns/promises';
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import { pathToFileURL } from 'node:url';

process.umask(0o077);
const root=path.resolve(process.argv[2]);
const sdk='/opt/homebrew/lib/node_modules/openclaw';
const live='/Users/qianqi/.openclaw';
const expectedAccount='dfe45608d591590e55167d33f097a2a7f7119cd2256d8ebdc149e06d1befd1ae';
const configPin='ca2dd7d7879fa901dfb24e00837b56a4e0fd230600d7ed1e3086eda194187d4d';
const endpoint='https://auth.openai.com/oauth/token';
const canonicalLedger=path.join(path.dirname(root),'profile3-native-refresh-single-dispatch.private.json');
const nativeClient='app_EMoamEEZ73f0CkXaXp7hrann';
const sourcePins={
 'runtime-snapshots-D6VA-VN8.js':'a1b70fb7664f40fd0a7e6a62f8d1215bca7d6aa465360a5762424100d0dafa4f',
 'file-lock-B0CJDvN6.js':'d0b3f14b8830100e9f433980383f7483761a3ba117db99621d6ff52f6aa84a26',
 'file-lock-CnWt2hZ7.js':'c559f538d982d580938b116e5d9dd67bf25587b849fbcd5d81b284f05083f91e',
 'source-check-ZSz5NzGW.js':'9c02bbf2df3cf123efe8c34c423ae4ea044371aab91d727f38986351695ce1c9',
 'oauth-B4aOCsid.js':'505d561b6fe271c95d29d7b93b44cd0780ac5859342a98e46f20b4e08487234e',
 'openai-chatgpt-oauth-flow.runtime-DOVvnAqe.js':'e3852eb201e21b907beed38facea3b115f1058a80ba66436dc7202d36c6df07d',
 'undici-runtime-BL8ZN-Ey.js':'3528db33bb716a2e30fe895cd93c4027750c2da57379c8107d0b748cb0857978',
 'runtime-fetch-k5Zth7kk.js':'9bf76247c5901725af5db78bbab2830a5e0fd7caf19953b095be74d4382db611',
 'fetch-guard-6VNcgVVc.js':'ef4befea09e2fbf0bece7bfc5cc46102843ee1070182fdab5b98f3c632a88bfc'
};
const sha=x=>createHash('sha256').update(x).digest('hex');
const stable=x=>Array.isArray(x)?x.map(stable):x&&typeof x==='object'
 ?Object.fromEntries(Object.keys(x).sort().map(k=>[k,stable(x[k])])):x;
const digest=x=>sha(JSON.stringify(stable(x)));
const need=(v,code)=>{if(!v)throw Object.assign(new Error(code),{safeCode:code});};
const report={schema:'heptabao.native-profile3-one-refresh.v1',ok:false,checks:[],
  selectedProfileOrdinal:3,expectedAccountIdSha256:expectedAccount,
  installedSdkRoot:sdk,sourcePins,productionCredentialStoreChanged:false,
  productionTrafficCutover:false,productionCoordinationLockUsed:false,
  interactiveLoginAttempted:false,priorUnknownLoginReplayed:false,
  providerRefreshBudget:1,providerRequests:[],modelRequests:0,
  credentialValuesPublished:false,accountIdentitiesPublished:false,
  startedUnixMs:Date.now()};
const check=(code,v)=>{report.checks.push({case:code,passed:v===true});need(v,code);};
function save(p,value,raw=false){
 const bytes=raw?value:Buffer.from(JSON.stringify(value,null,2));
 const fd=fs.openSync(p,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
 try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
 return sha(bytes);
}
function readPrivate(p){
 const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{const a=fs.fstatSync(fd);need(a.isFile()&&a.uid===process.getuid()&&a.nlink===1&&(a.mode&0o077)===0,'private_file_custody');
  const bytes=fs.readFileSync(fd),b=fs.fstatSync(fd),c=fs.lstatSync(p);
  need([b,c].every(x=>x.dev===a.dev&&x.ino===a.ino&&x.size===a.size&&x.mtimeMs===a.mtimeMs),'private_file_changed');return bytes;
 }finally{fs.closeSync(fd);}
}
function capture(){
 const docs={};
 for(const agent of ['main','trnm','hepta-ui','hepta','hepta-backend']){
  const file=path.join(live,'agents',agent,'agent','openclaw-agent.sqlite');
  const stat=fs.lstatSync(file);need(stat.isFile()&&!stat.isSymbolicLink()&&stat.uid===process.getuid(),'production_database_custody');
  const db=new DatabaseSync(file,{readOnly:true});
  try{db.exec('BEGIN');docs[agent]={store:db.prepare('SELECT store_key,store_json,updated_at FROM auth_profile_store ORDER BY store_key').all(),
    state:db.prepare('SELECT state_key,state_json,updated_at FROM auth_profile_state ORDER BY state_key').all()};db.exec('COMMIT');}
  finally{db.close();}
 }
 return docs;
}
function selected(snapshot){
 need(snapshot.main.store.length===1,'single_main_store');
 const s=JSON.parse(snapshot.main.store[0].store_json),ids=Object.keys(s.profiles);
 const matches=ids.filter(id=>s.profiles[id]?.type==='oauth'&&s.profiles[id]?.provider==='openai'
  &&sha(s.profiles[id]?.accountId??'')===expectedAccount);
 need(matches.length===1&&ids.indexOf(matches[0])===2,'unique_exact_profile3_identity');
 return {profileId:matches[0],credential:s.profiles[matches[0]]};
}
function claim(token){return JSON.parse(Buffer.from(token.split('.')[1],'base64url').toString('utf8'));}
let lock=null,before,credential,profileId,responseBytes,responseDoc,refreshResult;
let inFlight=false;let lockReleased=false;let sourceGeneration;
const secrets=[];
try{
 fs.mkdirSync(root,{mode:0o700});
 check('no_prior_refresh_dispatch',!fs.existsSync(canonicalLedger));
 check('actual_state_lock_scope',process.env.OPENCLAW_STATE_DIR===live);
 check('no_trust_or_proxy_overrides',!process.env.NODE_TLS_REJECT_UNAUTHORIZED&&!process.env.HTTPS_PROXY&&!process.env.HTTP_PROXY
   &&!process.env.https_proxy&&!process.env.http_proxy&&!process.env.NODE_EXTRA_CA_CERTS);
 for(const [name,pin] of Object.entries(sourcePins))check('source.'+name,sha(fs.readFileSync(path.join(sdk,'dist',name)))===pin);
 const config=JSON.parse(readPrivate(path.join(live,'openclaw.json')));
 check('production_config_pin',sha(readPrivate(path.join(live,'openclaw.json')))===configPin);
 check('authbus_provider_refresh_not_leader',config.plugins.entries['openclaw-authbus'].config.leader===false);
 const quarantine=JSON.parse(readPrivate(path.join(live,'authbus/bad-refresh-quarantine.json')));
 before=capture();({profileId,credential}=selected(before));
 sourceGeneration=digest(credential);secrets.push(profileId,...Object.values(credential).filter(x=>typeof x==='string'&&x.length>7));
 check('source_identity_claim',claim(credential.access)['https://api.openai.com/auth']?.chatgpt_account_id===credential.accountId);
 check('source_refresh_authority_present',typeof credential.refresh==='string'&&credential.refresh.length>20);
 check('target_not_quarantined',!Object.hasOwn(quarantine.profiles??{},profileId));
 check('existing_expired_access_requires_refresh',credential.expires<Date.now());
 save(path.join(root,'original-source.private.json'),{snapshot:before,profileId,credential});
 report.sourceCredentialSha256=sourceGeneration;report.sourceSnapshotSha256=digest(before);
 report.sourceExpiresUnixMs=credential.expires;
 const lockApi=await import(pathToFileURL(path.join(sdk,'dist/file-lock-B0CJDvN6.js')));
 const pathApi=await import(pathToFileURL(path.join(sdk,'dist/runtime-snapshots-D6VA-VN8.js')));
 const optionsApi=await import(pathToFileURL(path.join(sdk,'dist/source-check-ZSz5NzGW.js')));
 const flow=await import(pathToFileURL(path.join(sdk,'dist/openai-chatgpt-oauth-flow.runtime-DOVvnAqe.js')));
 const lockPath=pathApi.f('openai',profileId);
 check('native_global_lock_path',path.dirname(lockPath)===path.join(live,'locks/oauth-refresh'));
 check('no_existing_refresh_lock',!fs.existsSync(lockPath+'.lock'));
 const lockOptions={...optionsApi.M,retries:{...optionsApi.M.retries,retries:0}};
 lock=await lockApi.r(lockPath,lockOptions);report.productionCoordinationLockUsed=true;
 check('source_generation_stable_under_native_lock',digest(selected(capture()).credential)===sourceGeneration);
 report.lockPathSha256=sha(lockPath);report.lockSidecarObserved=fs.existsSync(lock.lockPath);
 check('native_lock_sidecar_owned',report.lockSidecarObserved);
 const intent={schema:'heptabao.native-one-refresh-private-intent.v1',createdUnixMs:Date.now(),profileId,
   accountId:credential.accountId,sourceCredentialSha256:sourceGeneration,sourceSnapshotSha256:digest(before),
   endpoint,grantType:'refresh_token',nativeClientId:nativeClient,requestBudget:1,
   noAutomaticReplay:true,priorUnknownLoginReplayed:false,productionCredentialStoreWrite:false,
   nativeGlobalLockPath:lockPath,sourcePins};
 report.intentSha256=save(path.join(root,'intent.private.json'),intent);
 save(path.join(root,'intent.public.json'),{schema:'heptabao.native-one-refresh-intent.v1',
   selectedProfileOrdinal:3,accountIdSha256:expectedAccount,sourceCredentialSha256:sourceGeneration,
   sourceSnapshotSha256:digest(before),endpoint,grantType:'refresh_token',requestBudget:1,noAutomaticReplay:true,
   nativeInstalledRefreshFunction:'refreshOpenAICodexToken',productionCredentialStoreWrite:false,
   localRefreshSerialized:true,priorUnknownLoginReplayed:false,sourcePins});
 const allowedIps=(await dns.lookup('auth.openai.com',{all:true})).map(x=>x.address);
 check('native_refresh_dns',allowedIps.length>0);
 const undici=createRequire(pathToFileURL(path.join(sdk,'package.json')))('undici');
 const nativeUndiciFetch=undici.fetch,nativeGlobalFetch=globalThis.fetch,nativeTls=tls.connect;
 const deny=()=>{report.unexpectedOperationRefused=true;throw Object.assign(new Error('Request was aborted'),{name:'AbortError',safeCode:'unexpected_operation'});};
 for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])cp[name]=deny;
 http.request=deny;http.get=deny;https.request=deny;https.get=deny;
 tls.connect=(...args)=>{
  const o=args[0];need(inFlight&&o&&typeof o==='object'&&String(o.port)==='443'&&o.servername==='auth.openai.com'
    &&(o.host==='auth.openai.com'||allowedIps.includes(o.host))&&o.rejectUnauthorized!==false,'native_refresh_tls_scope');
  const socket=nativeTls(...args);socket.once('secureConnect',()=>{const item=report.providerRequests[0];
   if(item){const cert=socket.getPeerCertificate();item.tlsVerified=socket.authorized===true;item.peerSha256=cert.raw?sha(cert.raw):null;}});return socket;
 };
 async function observedFetch(fn,entryPoint,input,options={}){
  const u=new URL(typeof input==='string'||input instanceof URL?input:input.url);
  need(u.href===endpoint&&options.method==='POST','native_refresh_endpoint_contract');
  const form=options.body instanceof URLSearchParams?options.body:new URLSearchParams(options.body);
  need([...form.keys()].sort().join(',')==='client_id,grant_type,refresh_token'
    &&form.get('grant_type')==='refresh_token'&&form.get('client_id')===nativeClient
    &&form.get('refresh_token')===credential.refresh,'native_refresh_exact_form');
  need(digest(selected(capture()).credential)===sourceGeneration,'source_generation_changed_before_dispatch');
  const item={endpoint,method:'POST',entryPoint,atUnixMs:Date.now(),actualNativeFormMatched:true,
    actualInstalledDispatcherPreserved:true,requestCount:1,timeoutMs:30000,redirect:'error'};
  report.canonicalDispatchLedgerSha256=save(canonicalLedger,{...item,workRoot:root,sourceCredentialSha256:sourceGeneration});
  report.dispatchLedgerSha256=save(path.join(root,'dispatch.private.json'),{...item,sourceCredentialSha256:sourceGeneration});
  report.providerRequests.push(item);inFlight=true;
  try{
   const res=await fn(input,{...options,redirect:'error'});item.httpStatus=res.status;item.headersReceived=true;
   need(item.tlsVerified===true,'refresh_tls_verified');
   const reader=res.clone().body?.getReader();need(reader,'refresh_response_body');
   const parts=[];let size=0;
   for(;;){const x=await reader.read();if(x.done)break;size+=x.value.byteLength;need(size<=1048576,'native_response_bound');parts.push(Buffer.from(x.value));}
   responseBytes=Buffer.concat(parts);item.responseBytes=size;item.complete=true;
   item.responseSha256=save(path.join(root,'provider-response.private.json'),responseBytes,true);
   report.responseSealedBeforeNativeParse=true;
   try{responseDoc=JSON.parse(responseBytes);}catch{responseDoc=null;}
   save(path.join(root,'provider-response-meta.public.json'),item);inFlight=false;
   // Return the real original Response unchanged after its clone is durable.
   return res;
  }catch(error){inFlight=false;item.errorClass=error?.name??'Error';item.outcomeUnknown=!item.complete;throw error;}
 }
 undici.fetch=(input,opts)=>observedFetch(nativeUndiciFetch,'actual-installed-undici',input,opts);
 globalThis.fetch=(input,opts)=>observedFetch(nativeGlobalFetch,'global-fetch',input,opts);
 syncBuiltinESMExports();
 try{refreshResult=await flow.r(credential.refresh);}catch(error){report.nativeRefreshErrorClass=error?.name??'Error';report.nativeRefreshErrorMessageSha256=sha(String(error?.message??''));}
 check('one_native_refresh_dispatch',report.providerRequests.length===1);
 const wire=report.providerRequests[0];
 if(wire.complete&&wire.httpStatus!==200){
  const e=responseDoc?.error;const values=[typeof e==='string'?e:null,e?.type,e?.code,responseDoc?.code].filter(x=>typeof x==='string');
  report.providerErrorCodes=values.filter(x=>/^[a-z0-9_]{1,80}$/.test(x));
  report.providerTerminalFailure=true;report.outcomeUnknown=false;
  report.refreshCredentialRejected=report.providerErrorCodes.some(x=>['invalid_refresh_token','invalid_grant','refresh_token_reused','refresh_token_expired','refresh_token_invalidated'].includes(x));
 }
 check('source_stores_unchanged_after_refresh',digest(capture())===digest(before));
 check('production_config_unchanged',sha(readPrivate(path.join(live,'openclaw.json')))===configPin);
 check('native_refresh_success',!!refreshResult&&wire.httpStatus===200&&wire.complete===true&&report.responseSealedBeforeNativeParse===true);
 check('same_account_refreshed_generation',refreshResult.accountId===credential.accountId
   &&claim(refreshResult.access)['https://api.openai.com/auth']?.chatgpt_account_id===credential.accountId);
 check('valid_new_access_and_refresh',typeof refreshResult.refresh==='string'&&refreshResult.refresh.length>20
   &&refreshResult.expires>Date.now()+600000&&refreshResult.access===responseDoc.access_token&&refreshResult.refresh===responseDoc.refresh_token);
 const next={...credential,...refreshResult};
 if(typeof responseDoc.id_token==='string'){
  const idClaim=claim(responseDoc.id_token);check('optional_new_id_token_same_account',idClaim['https://api.openai.com/auth']?.chatgpt_account_id===credential.accountId);
  next.idToken=responseDoc.id_token;
 }
 secrets.push(...Object.values(next).filter(x=>typeof x==='string'&&x.length>7));
 report.newCredentialSha256=digest(next);report.newExpiresUnixMs=next.expires;
 report.preparedGenerationPacketSha256=save(path.join(root,'refreshed-generation.private.json'),{
   schema:'heptabao.native-provider-refreshed-generation.v1',profileId,credential:next,
   sourceCredentialSha256:sourceGeneration,newCredentialSha256:digest(next),
   providerResponseSha256:wire.responseSha256,providerProof:{endpoint,status:200,tlsVerified:true,requestCount:1},
   publishedToProduction:false});
 report.recoveredSameAccountCurrentCredential=true;report.ok=true;
}catch(error){report.error=error?.safeCode??error?.name??'Error';report.errorClass=error?.name??'Error';}
finally{
 if(lock){try{await lock.release();lockReleased=true;}catch(error){report.lockReleaseErrorClass=error?.name??'Error';}}
 report.nativeGlobalLockReleased=lock?lockReleased:null;
 if(before){try{report.productionStoreSnapshotUnchanged=digest(capture())===digest(before);}catch{report.productionStoreSnapshotUnchanged=false;}}
 report.outcomeUnknown=report.providerRequests.some(x=>x.outcomeUnknown===true||!x.complete);
 report.finishedUnixMs=Date.now();
 if(report.productionStoreSnapshotUnchanged===false||lock&&!lockReleased)report.ok=false;
 const raw=JSON.stringify(report);need(!secrets.some(x=>raw.includes(x)),'public_report_contains_secret');
 if(fs.existsSync(root))save(path.join(root,'result.public.json'),report);
 process.stdout.write(JSON.stringify({ok:report.ok,error:report.error,requestCount:report.providerRequests.length,
   responseStatus:report.providerRequests[0]?.httpStatus,unknown:report.outcomeUnknown,
   result:path.join(root,'result.public.json'),sha256:sha(JSON.stringify(report,null,2))})+'\n');
}
process.exitCode=report.ok?0:1;
