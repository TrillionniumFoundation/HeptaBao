#!/usr/bin/env node
/** Offline classification of the already sealed real HTTP 401 response.
 * This is a diagnostic fixture, never a substitute for a live provider result.
 * No refresh, model request, live store mutation, or quarantine write occurs.
 */
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import cp from 'node:child_process';
import {createHash} from 'node:crypto';
import {syncBuiltinESMExports} from 'node:module';
import {pathToFileURL} from 'node:url';
process.umask(0o077);
const root=path.resolve(process.argv[2]);
const base='/Volumes/T5/hepta-vnext-recovery-20261013';
const refresh=path.join(base,'authbus-profile3-native-refresh-36076-20261104-r1');
const sdk='/opt/homebrew/lib/node_modules/openclaw/dist';
const plugin='/Users/qianqi/.openclaw/extensions/openclaw-authbus';
const sha=x=>createHash('sha256').update(x).digest('hex');
const report={schema:'heptabao.installed-refresh-classification-real-error-fixture.v1',ok:false,
  scope:'Offline classification of the already sealed single native HTTP 401, not a new provider execution.',
  providerRequests:0,refreshRequests:0,productionChanged:false,installedFilesChanged:false,checks:[],sourcePins:{}};
const check=(name,v)=>{report.checks.push({case:name,passed:v===true});if(!v)throw Object.assign(new Error(name),{safeCode:name});};
let blocked=0;
const deny=()=>{blocked++;throw new Error('offline_network_or_child_refused');};
function save(name,x){const bytes=Buffer.from(JSON.stringify(x,null,2));const fd=fs.openSync(path.join(root,name),fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}return sha(bytes);}
try{
 fs.mkdirSync(root,{mode:0o700});
 for(const name of ['state','home','tmp'])fs.mkdirSync(path.join(root,name),{mode:0o700});
 fs.writeFileSync(path.join(root,'state/openclaw.json'),'{}',{flag:'wx',mode:0o600});
 process.env.OPENCLAW_STATE_DIR=path.join(root,'state');
 process.env.OPENCLAW_CONFIG_PATH=path.join(root,'state/openclaw.json');
 process.env.OPENCLAW_HOME=path.join(root,'home');
 process.env.OPENCLAW_OAUTH_DIR=path.join(root,'state/oauth');
 process.env.TMPDIR=path.join(root,'tmp');
 const raw=fs.readFileSync(path.join(refresh,'provider-response.private.json'));
 const previous=JSON.parse(fs.readFileSync(path.join(refresh,'result.public.json')));
 check('exact_sealed_provider_response',sha(raw)==='7f4779a716146c8192f86c11b7e4d8376209d61b8c5ad5e7b4f5bd25de86322f');
 const response=JSON.parse(raw);
 check('actual_terminal_invalid_refresh',previous.providerRequests.length===1&&previous.providerRequests[0].httpStatus===401
  &&previous.providerRequests[0].complete===true&&previous.outcomeUnknown===false&&response.error?.code==='invalid_refresh_token');
 const rawError='OpenAI Codex token refresh failed (401): '+raw.toString('utf8');
 check('byte_exact_actual_native_error',sha(rawError)===previous.nativeRefreshErrorMessageSha256);
 const manager='OAuth token refresh failed for openai: '+rawError;
 const outer=manager+'. Please try again or re-authenticate.';
 const expected={
  [path.join(plugin,'bad-refresh-quarantine.js')]:'916617f296bd2e4b97b240a13418ac6220bb6513a1a0b83f5ee21854edc62286',
  [path.join(plugin,'provider-error-classifier.js')]:'3f9470edea686a0eb46400efecc4c12a284e7fdef018565c34185b0cff102d77',
  [path.join(plugin,'runtime-refresh-policy.js')]:'8257a6d2ee04868f3a7de5ff8ffaa7fdd3b37bb12a07ac993a3e9c7480c83547',
  [path.join(sdk,'oauth-B4aOCsid.js')]:'505d561b6fe271c95d29d7b93b44cd0780ac5859342a98e46f20b4e08487234e',
  [path.join(sdk,'errors-XbAR6hS3.js')]:'9164b1fc19f4e5afdd53e6bb53620f1d46b4cefa673c401c05af3dac9223a3d5',
  [path.join(sdk,'usage-CXFpqZhT.js')]:'074b8f5efb881753177ca23b616a67cfe1243d2dd3681f683b85bd26abaacff8',
  [path.join(sdk,'failover-error-B2zFYEnG.js')]:'28f495586451ca7bc8ae0ecdec7ad53950ac2ec67a2736e064386e22f00c1b74',
  [path.join(sdk,'embedded-agent-DGUuxGR2.js')]:'a1fd6d325758a6a96323027ab2778fa9779fbef55bc597b1a629fc6d0ad1acec',
  [path.join(sdk,'openai-chatgpt-oauth-flow.runtime-DOVvnAqe.js')]:'e3852eb201e21b907beed38facea3b115f1058a80ba66436dc7202d36c6df07d',
 };
 for(const [p,pin]of Object.entries(expected)){check('source.'+path.basename(p),sha(fs.readFileSync(p))===pin);report.sourcePins[p]=pin;}
 const oauthSource=fs.readFileSync(path.join(sdk,'oauth-B4aOCsid.js'),'utf8');
 check('actual_manager_and_outer_wrapper_contract',oauthSource.includes('message: `OAuth token refresh failed for ${params.credential.provider}: ${causeMessage}`')
  &&oauthSource.includes('message: `OAuth token refresh failed for ${cred.provider}: ${message}. Please try again or re-authenticate.`'));
 globalThis.fetch=deny;http.request=deny;http.get=deny;https.request=deny;https.get=deny;net.connect=deny;net.createConnection=deny;tls.connect=deny;
 const originalExec=cp.execFileSync;for(const n of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])cp[n]=deny;
 cp.execFileSync=(f,args,opts)=>{if(f!=='mount'||!Array.isArray(args)||args.length||opts!==undefined)return deny();return originalExec('/sbin/mount',[],{timeout:3000,maxBuffer:262144,env:{PATH:'/usr/bin:/bin:/usr/sbin:/sbin'}});};
 syncBuiltinESMExports();
 report.stage='import-quarantine';
 const quarantine=await import(pathToFileURL(path.join(plugin,'bad-refresh-quarantine.js')));
 report.stage='import-plugin-classifier';
 const classifier=await import(pathToFileURL(path.join(plugin,'provider-error-classifier.js')));
 report.stage='import-sdk-oauth-classifier';
 const failure=await import(pathToFileURL(path.join(sdk,'oauth-refresh-failure-Df54GmgP.js')));
 report.stage='import-sdk-errors';
 const errors=await import(pathToFileURL(path.join(sdk,'errors-XbAR6hS3.js')));
 report.stage='classification';
 const actualFailover=await import(pathToFileURL(path.join(sdk,'failover-error-B2zFYEnG.js')));
 report.wrapperClassifications=[];
 for(const [kind,message]of [['manager',manager],['outer',outer]]){
  const permanent=quarantine.classifyPermanentRefreshFailure(message);
  const provider=classifier.classifyProviderFailure(message);
  const sdkFailure=failure.r(message);
  // The native function throws Error(message); neither it nor the real outer
  // OAuthRefreshFailureError supplies an HTTP status field. Exercise the actual
  // installed extractor and the embedded-agent's message-only path unchanged.
  const nativeError=new Error(rawError);
  const wrapped=new failure.t({provider:'openai',profileId:'synthetic-fixture-only',message,cause:nativeError});
  const extractedReason=actualFailover.u(wrapped,'openai');
  const coerced=actualFailover.i(wrapped,{provider:'openai',authMode:'oauth'});
  const messageOnlyReason=errors.i(message,{provider:'openai'});
  const auxiliaryExplicitHttpSignal=errors.a({message,status:401,provider:'openai'});
  report.wrapperClassifications.push({kind,permanent,provider,sdkFailure,extractedReason,messageOnlyReason,
    coercedReason:coerced?.reason,coercedStatus:coerced?.status,
    nativeAndWrapperHaveNoExplicitStatus:nativeError.status===undefined&&wrapped.status===undefined,
    auxiliaryExplicitHttpSignal,runtimeKind:errors.o({message,provider:'openai'})});
  check(kind+'.authbus_permanent_exact',permanent?.provider==='openai'&&permanent?.reason==='invalid_refresh_token'
    &&provider?.classification==='auth_permanent'&&provider?.reason==='invalid_refresh_token');
  check(kind+'.actual_error_shape_has_no_synthetic_http_status',nativeError.status===undefined&&wrapped.status===undefined);
  check(kind+'.sdk_permanent_classification',extractedReason==='auth_permanent'&&messageOnlyReason==='auth_permanent'&&coerced?.reason==='auth_permanent');
 }
 const now=Date.now();
 const synthetic={profiles:{'fixture-failed':{type:'oauth',provider:'openai'},'fixture-other':{type:'oauth',provider:'openai'}},
  usageStats:{'fixture-failed':{disabledReason:'auth_permanent',lastFailureAt:now,failureCounts:{auth_permanent:1}}}};
 check('same_provider_unique_permanent_generation_selected',quarantine.selectRecentlyFailedOAuthProfile(synthetic,'openai',now)?.profileId==='fixture-failed');
 const ambiguous=structuredClone(synthetic);ambiguous.usageStats['fixture-other']=structuredClone(ambiguous.usageStats['fixture-failed']);
 check('ambiguous_generation_fails_closed',quarantine.selectRecentlyFailedOAuthProfile(ambiguous,'openai',now)===null);
 const wrongProvider=quarantine.selectRecentlyFailedOAuthProfile(synthetic,'anthropic',now);
 check('other_provider_not_selected',wrongProvider===null);
 const original=JSON.parse(fs.readFileSync(path.join(refresh,'result.public.json')));
 check('original_failed_receipt_not_rewritten',sha(fs.readFileSync(path.join(refresh,'result.public.json')))==='3926b7f90c408c6bc0381a2cf98dc906c250cf2d31891a9e69dd4222e1a7d81d'
  &&original.ok===false&&original.refreshCredentialRejected===false);
 const qa=fs.readFileSync(new URL('./authbus_profile3_native_refresh.mjs',import.meta.url),'utf8');
 check('qa_descriptive_code_list_corrected',qa.includes("['invalid_refresh_token','invalid_grant','refresh_token_reused','refresh_token_expired','refresh_token_invalidated']"));
 check('offline_only',blocked===0);
 check('all_installed_sources_unchanged',Object.entries(expected).every(([p,pin])=>sha(fs.readFileSync(p))===pin));
 report.qaOnlyDescriptiveOmission=true;report.runtimePermanentClassificationQualified=true;
 report.auxiliaryExplicitStatusCase='The earlier fixture artificially supplied status 401; the generic provider-status path classifies that different shape as auth. It is retained separately and does not replace the actual native Error/extractor input.';
 report.originalLiveRunStillFailed=true;report.automaticRetryPerformed=false;report.ok=true;
}catch(error){report.error=error?.safeCode??error?.name??'Error';report.errorCode=typeof error?.code==='string'?error.code:null;
 report.errorMessageSha256=sha(String(error?.message??''));report.sourceFrames=String(error?.stack??'').split('\n').slice(1,5)
  .map(line=>line.match(/([A-Za-z0-9_.-]+\.(?:js|mjs)):(\d+):(\d+)/)?.slice(1)??['native']);}
report.blockedOperations=blocked;
const hash=save('result.public.json',report);
process.stdout.write(JSON.stringify({ok:report.ok,error:report.error,sha256:hash,receipt:path.join(root,'result.public.json')})+'\n');
process.exitCode=report.ok?0:1;
