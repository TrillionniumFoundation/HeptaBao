#!/usr/bin/env node
/** Current configured refresh flags and three already selected owner-state matches.
 * No plugin service, provider request, mutex acquisition, or production write.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import net from "node:net";
import {createRequire} from "node:module";
import {pathToFileURL} from "node:url";
import {isDeepStrictEqual} from "node:util";
import {protectReadPhase} from "./authbus_sdk_read_guard.mjs";
const ROOT="/Users/qianqi/heptabao-authbus-current-refresh-flags-20261106-r2";
const LIVE="/Users/qianqi/.openclaw",SDK="/opt/homebrew/lib/node_modules/openclaw";
const PLUGIN=LIVE+"/extensions/openclaw-authbus";
const started=process.hrtime.bigint(),budget=Number(process.argv[2]),until=started+BigInt(Math.trunc(budget*1000000));
const report={schema:"heptabao.current-main3-refresh-flags-readonly.r2",ok:false,
  providerCalled:false,refreshDispatched:false,productionWrites:0,productionMutexAcquired:false,
  j3160Contacted:false,activeGatewayBindingProven:false,pluginServiceStarted:false,
  credentialValuesOrDigestsPublished:false,profileIdsPublished:false,rawConfigurationHashPublished:false,
  selectionOrderReexecuted:false,scopeFromPriorActualSdkMainThree:true};
const errors=new Set(),diagnostics={stdout:[],stderr:[],bytes:0,blockedAttempts:0};
let restore=null,sqlGuard=null;
function need(value,code){if(!value){errors.add(code);throw Object.assign(new Error(code),{code});}}
function remaining(){need(process.hrtime.bigint()<until,"original_refresh_flags_deadline");}
const plain=x=>x!==null&&typeof x==="object"&&!Array.isArray(x);
const sha=raw=>crypto.createHash("sha256").update(raw).digest("hex");
const identity=s=>["dev","ino","uid","gid","mode","nlink","size","mtimeNs","ctimeNs"].map(k=>String(s[k]));
function read(file,max=1048576,privateFile=false){
 remaining();const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
 try{
  const s=fs.fstatSync(fd,{bigint:true});need(s.isFile()&&s.nlink===1n&&s.size>=0n&&s.size<=BigInt(max)&&
    [0n,501n].includes(s.uid)&&(s.mode&18n)===0n,"bounded_refresh_flags_source");
  if(privateFile)need(s.uid===501n&&(s.mode&511n)===384n,"private_refresh_flags_input");
  const bytes=Buffer.alloc(Number(s.size)+1);let count=0;
  while(count<bytes.length){remaining();const n=fs.readSync(fd,bytes,count,bytes.length-count,null);if(!n)break;count+=n;}
  need(BigInt(count)===s.size&&isDeepStrictEqual(identity(s),identity(fs.fstatSync(fd,{bigint:true})))&&
    isDeepStrictEqual(identity(s),identity(fs.lstatSync(file,{bigint:true}))),"stable_refresh_flags_source");
  return bytes.subarray(0,count);
 }finally{fs.closeSync(fd);}
}
function installSqlite(){
 const sqlite=createRequire(import.meta.url)("node:sqlite"),Original=sqlite.DatabaseSync;
 const ledger={memory:0,readonly:0,denied:0,connections:[]};
 sqlite.DatabaseSync=new Proxy(Original,{construct(target,args){
  const [file,options]=args,memory=file===":memory:";
  if(!memory&&!(file===LIVE+"/agents/main/agent/openclaw-agent.sqlite"&&options?.readOnly===true)){
    ledger.denied++;need(false,"main_owner_readonly_database_only");
  }
  const db=Reflect.construct(target,args,target),row={closed:false,closeAttempts:0};
  if(memory)ledger.memory++;else ledger.readonly++;ledger.connections.push(row);
  const close=db.close.bind(db);Object.defineProperty(db,"close",{value:()=>{row.closeAttempts++;const v=close();row.closed=true;return v;}});
  return db;
 }});
 return {ledger,restore(){sqlite.DatabaseSync=Original;}};
}
function exactPart(text,start,end){
 need(text.split(start).length===2&&text.split(end).length===2,"unique_pinned_plugin_function_region");
 const a=text.indexOf(start),b=text.indexOf(end,a);need(a>=0&&b>a,"ordered_pinned_plugin_function_region");return text.slice(a,b);
}
function purePlugin(index){
 const base=exactPart(index,"function isRecord(value) {","function identityDigest(credential) {");
 const normalized=exactPart(index,"function normalizedConfig(raw) {","export default definePluginEntry({");
 const backoff=exactPart(index,"function readRefreshBackoff(stateDir) {","function writeRefreshBackoff(stateDir, profiles) {");
 const quarantine=exactPart(index,"function readBadRefreshQuarantine(stateDir) {","function writeBadRefreshQuarantine(stateDir, profiles) {");
 const statePath=exactPart(index,"function authBusStatePath(stateDir, name) {","function readDigestMap(stateDir, name) {");
 const build=new Function("crypto","fs","path",base+statePath+normalized+backoff+quarantine+
   "return {credentialDigest,normalizedConfig,readRefreshBackoff,readBadRefreshQuarantine};");
 return projections=>build(crypto,{readFileSync(file){
   const name=path.basename(file);need(file===LIVE+"/authbus/"+name&&Object.hasOwn(projections,name),"only_selected_private_state_projection");
   const projection=projections[name];if(!projection.present)throw Object.assign(new Error("absent"),{code:"ENOENT"});
   return JSON.stringify({profiles:projection.profiles});
 }},path);
}
function validateSelectedState(value,kind,ids){
 need(plain(value)&&typeof value.present==="boolean"&&plain(value.profiles)&&Object.keys(value.profiles).every(id=>ids.includes(id)),"selected_state_projection_scope");
 if(!value.present)need(Object.keys(value.profiles).length===0,"absent_state_has_no_selected_entries");
 for(const row of Object.values(value.profiles)){
  need(plain(row)&&typeof row.digest==="string"&&/^[0-9a-f]{64}$/.test(row.digest),"typed_selected_state_generation");
  if(kind==="quarantine")need(typeof row.provider==="string"&&typeof row.reason==="string"&&Number.isFinite(row.firstDetectedAt)&&Number.isFinite(row.lastDetectedAt),"typed_selected_quarantine_entry");
  else need(Number.isFinite(row.failures)&&Number.isFinite(row.nextAttemptAt),"typed_selected_backoff_entry");
 }
}
async function kernelProbes(){
 for(const [name,flag]of [["protected-read",fs.constants.O_RDONLY],["protected-write",fs.constants.O_WRONLY]]){
  let fd,denied=false;try{fd=fs.openSync(ROOT+"/"+name,flag|fs.constants.O_NOFOLLOW);}catch(e){denied=["EPERM","EACCES"].includes(e.code);}
  finally{if(fd!==undefined)fs.closeSync(fd);}need(denied,"owned_kernel_data_refusal");
 }
 const denied=await new Promise(resolve=>{
  const socket=new net.Socket();let code=null,connected=false;
  const timer=setTimeout(()=>socket.destroy(),Math.min(750,Math.max(1,Number((until-process.hrtime.bigint())/1000000n))));
  socket.once("error",e=>{code=e.code;socket.destroy();});socket.once("connect",()=>{connected=true;socket.destroy();});
  socket.once("close",()=>{clearTimeout(timer);resolve(!connected&&["EACCES","EPERM"].includes(code));});socket.connect(9,"127.0.0.1");
 });need(denied,"owned_kernel_network_refusal");report.kernelReadWriteNetworkRefusalsObserved=true;
}
try{
 need(process.platform==="darwin"&&process.getuid()===501&&Number.isFinite(budget)&&budget>0&&budget<=45000,"actual_mac_refresh_flags_runtime");
 await kernelProbes();
 need(process.env.TMPDIR===ROOT+"/output/tmp","exact_owned_sdk_temp");
 const tmp=fs.lstatSync(ROOT+"/output/tmp/openclaw-501");
 need(tmp.isDirectory()&&!tmp.isSymbolicLink()&&tmp.uid===501&&(tmp.mode&511)===448,"precreated_owned_sdk_temp");
 fs.accessSync(ROOT+"/output/tmp/openclaw-501",fs.constants.W_OK|fs.constants.X_OK);
 const input=JSON.parse(read(ROOT+"/input.private.json",1048576,true));
 need(input.schema==="heptabao.current-main3-refresh-flags-input.private.r1"&&input.host==="mac"&&
   input.selectionAuthorityJob==="1a1b197fa0e-fc05-79c0"&&input.currentConfigurationSameAsOriginal===true,"exact_refresh_flags_authority");
 const ids=input.selectedOwners?.map(row=>row.profileId);
 need(Array.isArray(ids)&&ids.length===3&&new Set(ids).size===3&&input.selectedOwners.every(row=>
   row.ownerAgent==="main"&&row.ownerAgentDir===LIVE+"/agents/main/agent"&&row.actualProvider==="openai"&&
   typeof row.profileId==="string"&&row.profileId.length>0&&row.profileId.length<=256),"exact_previously_selected_three_main_owners");
 for(const [relative,pin]of Object.entries(input.sdkPins))need(sha(read(SDK+"/"+relative))===pin,"current_sdk_source_pin");
 const index=read(PLUGIN+"/index.js");
 need(sha(index)===input.pluginPins["index.js"]&&sha(read(PLUGIN+"/bad-refresh-quarantine.js"))===input.pluginPins["bad-refresh-quarantine.js"],"current_plugin_pure_source_pins");
 const configBefore=read(LIVE+"/openclaw.json",1048576,true);
 need(sha(configBefore)===input.configurationSha256,"original_config_generation_still_current");
 const current=JSON.parse(configBefore),entry=current.plugins?.entries?.["openclaw-authbus"];
 need(plain(entry)&&plain(entry.config)&&isDeepStrictEqual(entry.config,input.pluginRawConfig)&&
   (entry.enabled??null)===input.pluginEntryEnabled,"exact_current_plugin_configuration");
 validateSelectedState(input.states["bad-refresh-quarantine.json"],"quarantine",ids);
 validateSelectedState(input.states["refresh-backoff.json"],"backoff",ids);
 const pure=purePlugin(index.toString("utf8"))(input.states),normalized=pure.normalizedConfig(entry.config);
 // Pure-source synthetic gates prove raw opt-in/default and generation matching
 // semantics without service registration or provider requests.
 need(pure.normalizedConfig({}).leader===false&&pure.normalizedConfig({leader:true}).leader===true&&
   pure.normalizedConfig({leader:"true"}).leader===false&&pure.normalizedConfig({enforceRefreshLeases:true}).enforceRefreshLeases===true&&
   pure.normalizedConfig({enforceRefreshLeases:"true"}).enforceRefreshLeases===false,"actual_pure_flag_semantics");
 sqlGuard=installSqlite();restore=protectReadPhase(diagnostics);
 const sdk=await import(pathToFileURL(SDK+"/dist/store-DH33UrUj.js").href);
 const quarantineApi=await import(pathToFileURL(PLUGIN+"/bad-refresh-quarantine.js").href);
 const q=pure.readBadRefreshQuarantine(LIVE),b=pure.readRefreshBackoff(LIVE),now=Date.now();
 need(q.size===Object.keys(input.states["bad-refresh-quarantine.json"].profiles).length&&
   b.size===Object.keys(input.states["refresh-backoff.json"].profiles).length,"actual_plugin_selected_state_parser_accepts_all_selected_entries");
 const counts={selectedOwnerCount:3,actualSdkCredentialLookups:0,oauthCount:0,expiredAccessCount:0,refreshFieldPresentCount:0,
   quarantineSelectedEntryCount:q.size,quarantineCurrentGenerationMatchCount:0,quarantineOtherGenerationCount:0,
   backoffSelectedEntryCount:b.size,backoffCurrentGenerationMatchCount:0,backoffOtherGenerationCount:0,
   currentBackoffDeferredCount:0,currentBackoffElapsedCount:0,quarantineReasonCounts:{}};
 const reasons=new Set(["refresh_token_reused","invalid_refresh_token","token_invalidated","invalid_grant","revoked"]);
 for(const id of ids){
   remaining();sdk.t();const credential=sdk.a({agentDir:LIVE+"/agents/main/agent",profileId:id});
   need(plain(credential)&&credential.type==="oauth"&&credential.provider==="openai"&&
     typeof credential.access==="string"&&credential.access.length>0&&typeof credential.refresh==="string"&&credential.refresh.length>0&&
     Number.isFinite(credential.expires)&&!["keyRef","tokenRef","accessRef","refreshRef","oauthRef"].some(key=>key in credential),"actual_main_selected_oauth_credential");
   counts.actualSdkCredentialLookups++;counts.oauthCount++;counts.refreshFieldPresentCount++;
   if(credential.expires<=now)counts.expiredAccessCount++;
   const digest=pure.credentialDigest(credential),quarantine=q.get(id),backoff=b.get(id);
   if(quarantine){
     if(quarantineApi.isDigestQuarantined(q,id,digest))counts.quarantineCurrentGenerationMatchCount++;
     else counts.quarantineOtherGenerationCount++;
     const reason=reasons.has(quarantine.reason)?quarantine.reason:"other";
     counts.quarantineReasonCounts[reason]=(counts.quarantineReasonCounts[reason]??0)+1;
   }
   if(backoff){
     if(backoff.digest===digest){counts.backoffCurrentGenerationMatchCount++;
       if(backoff.nextAttemptAt>now)counts.currentBackoffDeferredCount++;else counts.currentBackoffElapsedCount++;}
     else counts.backoffOtherGenerationCount++;
   }
 }
 sdk.t();need(diagnostics.blockedAttempts===0&&sqlGuard.ledger.denied===0&&
   sqlGuard.ledger.connections.every(x=>x.closed&&x.closeAttempts===1),"readonly_sdk_no_effects_and_all_handles_closed");
 restore();restore=null;sqlGuard.restore();
 need(sha(read(LIVE+"/openclaw.json",1048576,true))===input.configurationSha256,"current_config_unchanged_after_sdk");
 for(const [relative,pin]of Object.entries(input.sdkPins))need(sha(read(SDK+"/"+relative))===pin,"sdk_source_after");
 for(const [name,pin]of Object.entries(input.pluginPins))need(sha(read(PLUGIN+"/"+name))===pin,"plugin_source_after");
 report.configuredFlags={pluginEntryEnabled:typeof entry.enabled==="boolean"?entry.enabled:null,pluginsGloballyDisabled:current.plugins?.enabled===false,
   leader:normalized.leader,enforceRefreshLeases:normalized.enforceRefreshLeases,publishNew:normalized.publishNew,
   manageOrder:normalized.manageOrder,schedulerMode:normalized.schedulerMode};
 report.selectedCurrentState=counts;
 report.stateFilePresence=Object.fromEntries(Object.entries(input.states).map(([name,value])=>[name,value.present]));
 report.purePluginFlagGatesPassed=5;report.actualPluginPureReadersExecuted=true;report.actualSdkCurrentOwnerLookupExecuted=true;
 report.pluginRefreshBranchDependsOnConfiguredLeader=true;report.configurationDoesNotProveAlreadyRunningServiceFlags=true;
 report.providerValidityQualified=false;remaining();report.ok=true;
}catch(error){
 report.errorCode=errors.has(error?.code)?error.code:"current_refresh_flags_refused";
 report.errorType=["Error","TypeError","RangeError","SyntaxError"].includes(error?.name)?error.name:"Other";
}finally{
 if(restore)restore();
 if(sqlGuard){sqlGuard.restore();const l=sqlGuard.ledger;report.sqliteReadScope={memoryOpenCount:l.memory,readOnlyFileOpenCount:l.readonly,
   returnedHandleCount:l.connections.length,deniedOpenCount:l.denied,allReturnedHandlesClosedOnce:l.connections.every(x=>x.closed&&x.closeAttempts===1)};}
 report.guardDeniedAttempts=diagnostics.blockedAttempts;report.capturedDiagnosticBytes=diagnostics.bytes;
 diagnostics.stdout.length=0;diagnostics.stderr.length=0;report.elapsedSeconds=Number(process.hrtime.bigint()-started)/1e9;
 process.stdout.write(JSON.stringify(report)+"\n");
}
process.exitCode=report.ok?0:1;
