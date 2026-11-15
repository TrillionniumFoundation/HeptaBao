#!/usr/bin/env node
/** Actual installed-Mac SDK import/Agent compatibility, followed by explicitly
 * synthetic OAuth transport cases. No provider endpoint is contacted. */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import net from "node:net";
import childProcess from "node:child_process";
import dnsPromises from "node:dns/promises";
import {createRequire,syncBuiltinESMExports} from "node:module";
import {pathToFileURL} from "node:url";
import {isDeepStrictEqual} from "node:util";
import {loadQualifiedMacProvider,makeProviderRegistry,observeOriginalDispatcherClosure,ProviderOnceRefused,
  PROVIDER_SDK_ROOT,PROVIDER_SOURCE_PINS,PROVIDER_UNDICI_PINS,REGISTRY_SYMBOL,TOKEN_URL,CLIENT_ID} from "./mac_refresh_provider_hooks_r2.mjs";

const ROOT="/Users/qianqi/heptabao-authbus-provider-isolated-qualification-20261106-r1";
const started=process.hrtime.bigint(),budget=Number(process.argv[2]),until=started+BigInt(Math.trunc(budget*1000000));
const report={schema:"heptabao.actual-mac-provider-isolated-qualification.r1",ok:false,
  actualInstalledSdk:true,syntheticCredentialsOnly:true,productionCredentialReads:0,productionWrites:0,
  actualProviderCalls:0,networkRequests:0,productionMutexAcquired:false,productionOnceLedgerOpened:false,
  productionRefreshControllerExecuted:false,actualNativeSocketClosureClaimed:false,
  fixtureBoundaryScope:"original SDK OAuth parser/guard and actual Agent cleanup; DNS and native fetch deliberately synthetic",
  cases:[],agents:[],syntheticFlows:[],fileDescriptors:[],childAttempts:0,sqliteAttempts:0};
const emit=process.stdout.write.bind(process.stdout),oldOut=process.stdout.write,oldErr=process.stderr.write;
let suppressedDiagnostics=0,activeCase=null,actual=null,flow=null,ssrf=null,runtime=null,native=null,base=null;
let childOriginals=null,sqliteOriginal=null,sqlite=null,lookupOriginal=null,fixtureGlobal=false,ctx=null;
const codes=new Set(),symbol=Symbol.for(REGISTRY_SYMBOL),override="__OPENCLAW_TEST_UNDICI_RUNTIME_DEPS__";
const req=createRequire(path.join(PROVIDER_SDK_ROOT,"dist/undici-runtime-BL8ZN-Ey.js"));
const sha=x=>crypto.createHash("sha256").update(x).digest("hex");
function need(v,c){if(!v){codes.add(c);throw new Error(c);}}
function remaining(){need(process.hrtime.bigint()<until,"provider_fixture_original_deadline");return until;}
function same(a,b){return isDeepStrictEqual(a,b);}
function full(s){return ["dev","ino","uid","gid","mode","nlink","size","mtimeNs","ctimeNs"].map(k=>String(s[k]));}
function publicPins(){
 for(const [relative,pin]of Object.entries({...PROVIDER_SOURCE_PINS,...PROVIDER_UNDICI_PINS})){
  remaining();const name=path.join(PROVIDER_SDK_ROOT,relative),fd=fs.openSync(name,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  const row={kind:"public-source",closed:false,closeAttempts:0};report.fileDescriptors.push(row);
  try{
   const s=fs.fstatSync(fd,{bigint:true});need(s.isFile()&&s.nlink===1n&&[0n,501n].includes(s.uid)&&(s.mode&18n)===0n&&s.size>0n&&s.size<=1048576n,"provider_fixture_public_source_custody");
   const b=Buffer.alloc(Number(s.size)+1);let n=0;
   while(n<b.length){remaining();const k=fs.readSync(fd,b,n,b.length-n,null);if(!k)break;n+=k;}
   need(n===Number(s.size)&&same(full(s),full(fs.fstatSync(fd,{bigint:true})))&&same(full(s),full(fs.lstatSync(name,{bigint:true})))&&sha(b.subarray(0,n))===pin,"provider_fixture_current_public_source_pin");
  }finally{row.closeAttempts++;fs.closeSync(fd);row.closed=true;}
 }
}
function privateCapture(number,value){
 remaining();const filename=ROOT+"/output/case-"+String(number).padStart(2,"0")+"-response.synthetic.private";
 const fd=fs.openSync(filename,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
 const row={kind:"synthetic-response",closed:false,closeAttempts:0};report.fileDescriptors.push(row);
 try{fs.writeFileSync(fd,value.bytes);fs.fsyncSync(fd);}finally{row.closeAttempts++;fs.closeSync(fd);row.closed=true;}
 const dir=fs.openSync(ROOT+"/output",fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
 const d={kind:"synthetic-response-parent",closed:false,closeAttempts:0};report.fileDescriptors.push(d);
 try{fs.fsyncSync(dir);}finally{d.closeAttempts++;fs.closeSync(dir);d.closed=true;}
 return filename;
}
function agentRow(agent,kind){
 const row={kind,terminalClosed:false,terminalDestroyed:false};report.agents.push(row);
 return {agent,row,finish(){row.terminalClosed=agent.closed===true;row.terminalDestroyed=agent.destroyed===true;
  need(row.terminalClosed&&row.terminalDestroyed,"provider_fixture_original_agent_terminal_state");}};
}
async function check(id,fn){
 remaining();activeCase=id;await fn();report.cases.push({id,passed:true});activeCase=null;
}
async function originalObserver(agent,action){
 const receipt={},observer=observeOriginalDispatcherClosure(agent,receipt);
 try{await action();await observer.settleOriginalPromises();return {receipt,known:observer.known()};}
 finally{observer.restore();}
}
async function deniedNetwork(host,port){
 return await new Promise(resolve=>{
  const socket=new net.Socket();let error=null,connected=false;
  const timer=setTimeout(()=>socket.destroy(),Math.min(750,Math.max(1,Number((until-process.hrtime.bigint())/1000000n))));
  socket.once("error",e=>{error=e.code;socket.destroy();});socket.once("connect",()=>{connected=true;socket.destroy();});
  socket.once("close",()=>{clearTimeout(timer);resolve(!connected&&["EACCES","EPERM"].includes(error));});socket.connect(port,host);
 });
}
async function guards(){
 for(const [name,mode]of [["protected-read",fs.constants.O_RDONLY],["protected-write",fs.constants.O_WRONLY]]){
  let fd,denied=false;try{fd=fs.openSync(ROOT+"/"+name,mode|fs.constants.O_NOFOLLOW);}catch(e){denied=["EACCES","EPERM"].includes(e.code);}
  finally{if(fd!==undefined)fs.closeSync(fd);}need(denied,"provider_fixture_kernel_file_refusal");
 }
 need(await deniedNetwork("127.0.0.1",9)&&await deniedNetwork("203.0.113.1",443),"provider_fixture_kernel_network_refusal");
 childOriginals=Object.fromEntries(["spawn","spawnSync","exec","execSync","execFile","execFileSync","fork"].map(k=>[k,childProcess[k]]));
 for(const k of Object.keys(childOriginals))childProcess[k]=()=>{report.childAttempts++;throw new Error("provider_fixture_child_forbidden");};
 sqlite=createRequire(import.meta.url)("node:sqlite");sqliteOriginal=sqlite.DatabaseSync;
 sqlite.DatabaseSync=new Proxy(sqliteOriginal,{construct(){report.sqliteAttempts++;throw new Error("provider_fixture_sqlite_forbidden");}});
 syncBuiltinESMExports();report.kernelReadWriteAndBothNetworkRefusalsObserved=true;report.deniedNetworkConnectAttempts=2;
}
const oldCredential={type:"oauth",provider:"openai",refresh:"synthetic-only-old-refresh",accountId:"synthetic-account"};
const access="synthetic."+Buffer.from(JSON.stringify({"https://api.openai.com/auth":{chatgpt_account_id:"synthetic-account"}})).toString("base64url")+".synthetic";
function receipt(){return {flowEntrypointChecks:0,postFormEntries:0,guardEntries:0,runtimeEntries:0,
 finalNativeSendEntries:0,originalNativeFetchInvocations:0,originalNativeFetchSettlements:0,
 completeBodyCaptures:0,originalDispatcherMethodCalls:0,originalDispatcherReleaseCompletions:0};}
async function syntheticFlow(kind,number){
 remaining();const events=[],rows=[],abort=new AbortController(),r=receipt();let returned=false,value,failed=false,capturedFile=null;
 const row={kind,syntheticNativeBoundary:true,actualProviderCalls:0,rawResponseCapturedBeforeSdkResult:false,normalizedResultReturned:false,
  fakeDnsCalls:0,syntheticFetchBoundaryCalls:0,originalAgentsClosed:false,originalMethodPromisesSettled:false};
 report.syntheticFlows.push(row);
 ctx={oldCredential,until,signal:abort.signal,closed:false,receipt:r,dispatcherObservers:[],nativePromises:[],
  assertLive(){remaining();},finalDispatch(send){events.push("once-latch-fixture");return send();},
  responseCapture(response){
   need(!returned&&response.bytes.length<=1048576,"provider_fixture_capture_before_parser");
   if(kind==="capture-failure")throw new Error("provider_fixture_injected_capture_failure");
   capturedFile=privateCapture(number,response);events.push("raw-file-and-directory-fsynced");row.rawResponseCapturedBeforeSdkResult=true;
  }};
 const registry=makeProviderRegistry({current:()=>ctx,sourceFence(){publicPins();if(kind==="source-changed"&&row.fakeDnsCalls>0)throw new ProviderOnceRefused("provider_fixture_source_changed_after_dns");}});
 Object.defineProperty(globalThis,symbol,{value:registry,writable:false,configurable:true});fixtureGlobal=true;
 lookupOriginal=dnsPromises.lookup;
 dnsPromises.lookup=async(host,options)=>{need(host==="auth.openai.com"&&options?.all===true,"provider_fixture_exact_synthetic_dns");row.fakeDnsCalls++;return [{address:"8.8.8.8",family:4}];};
 syncBuiltinESMExports();need((await import("node:dns/promises")).lookup===dnsPromises.lookup,"provider_fixture_live_builtin_dns_binding");
 const Agent=new Proxy(native.Agent,{construct(target,args){const a=Reflect.construct(target,args,target),owned=agentRow(a,"synthetic-flow-"+kind);rows.push(owned);return a;}});
 const syntheticFetch=async(url,init)=>{
  remaining();need(url===TOKEN_URL&&init?.method==="POST"&&init.dispatcher instanceof native.Agent,"provider_fixture_exact_synthetic_native_boundary");
  need(same([...new URLSearchParams(init.body).entries()],[["grant_type","refresh_token"],["refresh_token",oldCredential.refresh],["client_id",CLIENT_ID]]),"provider_fixture_exact_synthetic_form");
  row.syntheticFetchBoundaryCalls++;need(row.syntheticFetchBoundaryCalls===1,"provider_fixture_synthetic_native_once");events.push("synthetic-native-fetch");
  if(kind==="native-reject")throw new Error("provider_fixture_synthetic_transport_rejection");
  if(kind==="redirect")return new Response("synthetic redirect",{status:302,headers:{location:"https://example.invalid/forbidden"}});
  if(kind==="bad-json")return new Response("synthetic-invalid-json",{status:200});
  if(kind==="over-limit")return new Response(Buffer.alloc(1048577,120),{status:200});
  if(kind==="http-error")return new Response('{"error":"synthetic-refusal"}',{status:400});
  return new Response(JSON.stringify({access_token:kind==="missing-account"?"synthetic.invalid.synthetic":access,
   refresh_token:"synthetic-only-new-refresh",expires_in:3600}),{status:200,headers:{"Content-Type":"application/json"}});
 };
 Object.defineProperty(globalThis,override,{value:{Agent,EnvHttpProxyAgent:native.EnvHttpProxyAgent,ProxyAgent:native.ProxyAgent,FormData:native.FormData,fetch:syntheticFetch},configurable:true});
 try{try{value=await flow.r(oldCredential.refresh);returned=true;row.normalizedResultReturned=true;events.push("sdk-normalized-result");}catch{failed=true;}}
 finally{
  ctx.closed=true;await Promise.all(ctx.nativePromises);
  for(const o of ctx.dispatcherObservers)await o.settleOriginalPromises();
  row.originalMethodPromisesSettled=true;
  row.originalTransportObserverKnown=ctx.dispatcherObservers.length===1&&ctx.dispatcherObservers.every(o=>o.known());
  for(const o of ctx.dispatcherObservers)o.restore();
  for(const a of rows)a.finish();row.originalAgentsClosed=rows.every(a=>a.row.terminalClosed&&a.row.terminalDestroyed);
  delete globalThis[override];delete globalThis[symbol];fixtureGlobal=false;
  dnsPromises.lookup=lookupOriginal;lookupOriginal=null;syncBuiltinESMExports();abort.abort();ctx=null;
 }
 need(row.fakeDnsCalls===1&&rows.length===1&&row.originalAgentsClosed,"provider_fixture_actual_flow_agent_and_dns");
 if(kind==="source-changed"){
  need(failed&&!returned&&row.syntheticFetchBoundaryCalls===0&&r.originalNativeFetchInvocations===0&&r.completeBodyCaptures===0,"provider_fixture_changed_source_prevents_send");
 }else{
  need(row.syntheticFetchBoundaryCalls===1&&r.originalNativeFetchInvocations===1&&r.originalNativeFetchSettlements===1&&r.originalDispatcherReleaseCompletions===1&&row.originalTransportObserverKnown,"provider_fixture_actual_flow_complete_original_cleanup");
  if(kind==="success")need(!failed&&returned&&value.access===access&&value.refresh==="synthetic-only-new-refresh"&&value.accountId==="synthetic-account"&&value.expires>Date.now()&&
    r.flowEntrypointChecks===2&&r.completeBodyCaptures===1&&events.indexOf("raw-file-and-directory-fsynced")<events.indexOf("sdk-normalized-result"),"provider_fixture_actual_parser_and_durable_order");
  else need(failed&&!returned,"provider_fixture_negative_does_not_return_credentials");
  if(["http-error","bad-json","missing-account"].includes(kind))need(capturedFile&&r.completeBodyCaptures===1,"provider_fixture_failure_preserves_complete_response");
  if(["redirect","capture-failure","over-limit","native-reject"].includes(kind))need(!capturedFile&&r.completeBodyCaptures===0,"provider_fixture_no_invented_response_capture");
 }
 row.receipt=r;row.passed=true;
}
try{
 need(process.platform==="darwin"&&process.getuid()===501&&budget>0&&budget<=30000,"provider_fixture_exact_mac_budget");
 process.stdout.write=()=>{suppressedDiagnostics++;return true;};process.stderr.write=()=>{suppressedDiagnostics++;return true;};
 await check("M01_actual_kernel_and_child_sqlite_fences",guards);
 await check("M02_actual_production_source_loader_import",async()=>{
  report.productionLoader={};actual=await loadQualifiedMacProvider(report.productionLoader);
  need(report.productionLoader.modules.filter(x=>x.loaded).length>=3&&actual.contextIsClosed(),"provider_fixture_actual_three_hooks_loaded");
  need(req.resolve("undici")===PROVIDER_SDK_ROOT+"/node_modules/undici/index.js","provider_fixture_actual_undici_resolution");
  flow=await import(pathToFileURL(PROVIDER_SDK_ROOT+"/dist/openai-chatgpt-oauth-flow.runtime-DOVvnAqe.js").href);
  ssrf=await import(pathToFileURL(PROVIDER_SDK_ROOT+"/dist/ssrf-BayeDjCv.js").href);
  runtime=await import(pathToFileURL(PROVIDER_SDK_ROOT+"/dist/undici-runtime-BL8ZN-Ey.js").href);
 });
 await check("M03_actual_empty_agent_close_and_callback_recursion",async()=>{
  const a=agentRow(runtime.t(),"actual-empty-close");native=req.cache[req.resolve("undici")].exports;
  base=req.cache[PROVIDER_SDK_ROOT+"/node_modules/undici/lib/dispatcher/dispatcher-base.js"].exports;
  need(a.agent instanceof native.Agent&&a.agent.close===base.prototype.close&&a.agent.destroy===base.prototype.destroy,"provider_fixture_actual_base_methods");
  const v=await originalObserver(a.agent,()=>ssrf.i(a.agent));a.finish();
  need(v.known&&v.receipt.originalDispatcherMethodCalls===4&&v.receipt.originalDispatcherPromiseCalls===2&&v.receipt.originalDispatcherInternalCallbackCalls===2,"provider_fixture_actual_close_shape");report.actualEmptyClose=v.receipt;
 });
 await check("M04_actual_empty_agent_destroy_and_callback_recursion",async()=>{
  const a=agentRow(runtime.t(),"actual-empty-destroy"),v=await originalObserver(a.agent,()=>a.agent.destroy());a.finish();
  need(v.known&&v.receipt.originalDispatcherMethodCalls===2&&v.receipt.originalDispatcherPromiseCalls===1&&v.receipt.originalDispatcherInternalCallbackCalls===1,"provider_fixture_actual_destroy_shape");
 });
 await check("M05_original_100ms_helper_return_with_delayed_ack",async()=>{
  const a=agentRow(runtime.t(),"actual-close-delayed-ack"),original=a.agent.close;let finish;
  const gate=new Promise(resolve=>{finish=resolve;});Object.defineProperty(a.agent,"close",{configurable:true,value:function(...args){const value=original.apply(this,args);return args.length===0?value.then(()=>gate):value;}});
  const r={},o=observeOriginalDispatcherClosure(a.agent,r),keep=setTimeout(()=>{},1000);
  try{await ssrf.i(a.agent);need(!o.known(),"provider_fixture_helper_return_not_settlement");let done=false;const settled=o.settleOriginalPromises().then(()=>{done=true;});await Promise.resolve();need(!done,"provider_fixture_pending_ack_not_closed");
   finish();await settled;need(o.known()&&r.originalDispatcherPromiseCalls===3&&r.originalDispatcherInternalCallbackCalls===3,"provider_fixture_actual_timeout_and_internal_destroy");a.finish();}
  finally{clearTimeout(keep);o.restore();}
 });
 await check("M06_original_closed_agent_lost_ack_remains_unknown",async()=>{
  const a=agentRow(runtime.t(),"actual-close-lost-ack"),original=a.agent.close;
  Object.defineProperty(a.agent,"close",{configurable:true,value:function(...args){const value=original.apply(this,args);return args.length===0?value.then(()=>{throw new Error("synthetic lost close acknowledgement");}):value;}});
  const v=await originalObserver(a.agent,()=>ssrf.i(a.agent));a.finish();need(!v.known,"provider_fixture_lost_ack_not_forged_closed");
 });
 await check("M07_production_loader_rejects_test_override",async()=>{
  Object.defineProperty(globalThis,override,{value:{},configurable:true});let refused=false;
  try{actual.sourceFence();}catch(e){refused=e instanceof ProviderOnceRefused&&e.code==="provider_no_injected_undici_test_runtime";}finally{delete globalThis[override];}
  need(refused,"provider_fixture_production_override_guard");actual.sourceFence();actual.dispose();actual=null;
  report.productionLoaderDisposedBeforeSyntheticRuntimeOverride=true;
 });
 for(const [id,kind]of [["M08_actual_sdk_parser_synthetic_success","success"],["M09_redirect_not_followed","redirect"],
  ["M10_complete_http_error_response_preserved","http-error"],["M11_complete_bad_json_response_preserved","bad-json"],
  ["M12_missing_account_does_not_return_credentials","missing-account"],["M13_capture_failure_before_parser","capture-failure"],
  ["M14_original_one_mib_body_limit","over-limit"],["M15_synthetic_native_rejection_closes_actual_agent","native-reject"],
  ["M16_source_changed_after_dns_prevents_send","source-changed"]])await check(id,()=>syntheticFlow(kind,report.cases.length+1));
 publicPins();remaining();need(report.childAttempts===0&&report.sqliteAttempts===0,"provider_fixture_no_child_or_database_access");
 report.ok=true;
}catch(e){report.failedCase=activeCase;report.errorType=e?.name??"Error";report.errorCode=e instanceof ProviderOnceRefused?e.code:codes.has(e?.message)?e.message:"provider_isolated_qualification_refused";}
finally{
 if(actual){try{if(actual.contextIsClosed())actual.dispose();else report.ok=false;}catch{report.ok=false;report.productionLoaderCloseFailed=true;}}
 if(lookupOriginal){dnsPromises.lookup=lookupOriginal;lookupOriginal=null;syncBuiltinESMExports();}
 if(fixtureGlobal){delete globalThis[override];delete globalThis[symbol];fixtureGlobal=false;report.ok=false;}
 if(childOriginals){for(const [name,value]of Object.entries(childOriginals))childProcess[name]=value;syncBuiltinESMExports();}
 if(sqliteOriginal)sqlite.DatabaseSync=sqliteOriginal;
 process.stdout.write=oldOut;process.stderr.write=oldErr;
 report.noFixtureRuntimeOverridesRemaining=!Object.hasOwn(globalThis,symbol)&&!Object.hasOwn(globalThis,override);
 report.allRecordedFileDescriptorsClosedOnce=report.fileDescriptors.every(x=>x.closed&&x.closeAttempts===1);
 report.allOriginalAgentsClosed=report.agents.every(x=>x.terminalClosed&&x.terminalDestroyed);
 if(!report.noFixtureRuntimeOverridesRemaining||!report.allRecordedFileDescriptorsClosedOnce||!report.allOriginalAgentsClosed)report.ok=false;
 report.suppressedDiagnosticWrites=suppressedDiagnostics;report.executed=report.cases.length+(activeCase?1:0);report.passed=report.cases.filter(x=>x.passed).length;
 report.elapsedSeconds=Number(process.hrtime.bigint()-started)/1e9;
 emit(JSON.stringify(report)+"\n");if(!report.ok)process.exitCode=1;
}
