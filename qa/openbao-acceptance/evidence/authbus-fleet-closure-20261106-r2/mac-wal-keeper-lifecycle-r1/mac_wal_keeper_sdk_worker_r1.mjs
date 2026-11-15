#!/usr/bin/env node
/** Five isolated phases using the unchanged, qualified installed-SDK raw adapter. */
import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import childProcess from "node:child_process";
import {createRequire,syncBuiltinESMExports} from "node:module";
import {isDeepStrictEqual as same} from "node:util";
import {bindSdkRawOwnerCas,CasRefused,loadActualMacRawSdk,SDK_PINS} from "./mac_sdk_raw_owner_cas_r1.mjs";

const ROOT="/Users/qianqi/heptabao-authbus-wal-keeper-lifecycle-20261106-r1";
const modes=["read-cold","read-held","write-held","read-committed","read-after-close"];
const mode=process.argv[2],budget=Number(process.argv[3]);
const started=process.hrtime.bigint();
const until=started+BigInt(Number.isFinite(budget)&&budget>0?Math.trunc(budget*1000000):0);
const output=process.stdout.write.bind(process.stdout),originalStderr=process.stderr.write;
const sqlite=createRequire(import.meta.url)("node:sqlite");
const ids=["synthetic-main-one","synthetic-main-two","synthetic-main-three"];
const ownerDir=ROOT+"/output/fixtures/"+(mode==="read-cold"?"cold":"held")+"/agents/main/agent";
const dbPath=ownerDir+"/openclaw-agent.sqlite";
const responsePath=ROOT+"/output/responses/held-response.private.json";
const report={schema:"heptabao.actual-sdk-synthetic-wal-phase.r1",ok:false,mode,
 actualInstalledSdk:true,syntheticCredentialsOnly:true,productionReads:0,productionWrites:0,
 providerCalls:0,serviceMutations:0,upperSdkLifecycleUsed:false,keeperOwnedByParent:true,
 keeperUsedAsLatestSource:false,readOutcome:null,admissionStages:[],receipts:[],sqliteErrors:[]};
let actual=null,sqlOriginal=null,fsOriginal=null,childOriginals=null,netOriginal=null,fetchOriginal=null;
let diagnostics=0,childAttempts=0,networkAttempts=0;
const sqlRows=[],fdRows=[];
const sqlLedger={attempts:0,opened:0,readOnly:0,writable:0,memory:0,denied:0};
function need(v,c){if(!v)throw new CasRefused(c);}
function time(){need(process.hrtime.bigint()<until,"original_wal_phase_deadline");}
function clone(v){return structuredClone(v);}
function ident(s){return ["dev","ino","uid","gid","mode","nlink","size","mtimeNs","ctimeNs"].map(k=>String(s[k]));}
function synthetic(n){return {type:"oauth",provider:"openai",access:"synthetic-access-"+n,
 refresh:"synthetic-refresh-"+n,expires:1,accountId:"synthetic-account-"+n,
 email:"synthetic-"+n+"@invalid.example",retainedExtension:{purpose:"wal-lifecycle-only",value:7}};}
function expectedStore(){
 const value={version:1,profiles:Object.fromEntries(ids.map((id,i)=>[id,synthetic(String(i+1))])),
  preservedUnknown:{nested:[1,"unchanged",{flag:true}]},order:{openai:[ids[2],ids[0],ids[1]]},
  usageStats:{[ids[0]]:{lastUsed:123,errorCount:2}},lastGood:{openai:ids[1]}};
 value.profiles["synthetic-other-provider"]={type:"api_key",provider:"anthropic",key:"synthetic-other-key"};
 return value;
}
const expectedState={version:1,order:{openai:[ids[2],ids[0],ids[1]]},usageStats:{[ids[1]]:{lastUsed:27}},lastGood:{openai:ids[2]}};
function checkSnapshot(value,after){
 const expected=expectedStore();
 if(after){
  const found=value.store.profiles[ids[0]];
  need(typeof found.expires==="number"&&found.expires>Date.now(),"synthetic_committed_expiry");
  expected.profiles[ids[0]]={...expected.profiles[ids[0]],access:"synthetic-access-after",refresh:"synthetic-refresh-after",expires:found.expires};
 }
 need(same(value.store,expected)&&same(value.state,expectedState)&&
  value.stateRow?.updated_at===1700000000002&&value.storeRow?.store_key==="primary",
  "actual_sdk_complete_synthetic_owner");
}
function observeSqliteError(error){
 const code=["ERR_SQLITE_ERROR","SQLITE_READONLY","SQLITE_CANTOPEN"].includes(error?.code)?error.code:"other";
 const number=Number.isSafeInteger(error?.errcode)&&error.errcode>=0&&error.errcode<65536?error.errcode:null;
 if(report.sqliteErrors.length<8)report.sqliteErrors.push({code,number});
}
function installSqlite(){
 sqlOriginal=sqlite.DatabaseSync;
 sqlite.DatabaseSync=new Proxy(sqlOriginal,{construct(target,args){
  const [file,options]=args,memory=file===":memory:",readOnly=options?.readOnly===true;
  if(!memory&&!(file===dbPath&&typeof options==="object"&&options!==null&&
    (readOnly||mode==="write-held"))){sqlLedger.denied++;throw new CasRefused("synthetic_exact_database_scope");}
  sqlLedger.attempts++;let db;
  try{db=Reflect.construct(target,args,target);}catch(error){observeSqliteError(error);throw error;}
  const row={closeAttempts:0,closed:false};sqlRows.push(row);sqlLedger.opened++;
  if(memory)sqlLedger.memory++;else if(readOnly)sqlLedger.readOnly++;else sqlLedger.writable++;
  const close=db.close.bind(db);
  Object.defineProperty(db,"close",{configurable:true,value:()=>{
   need(row.closeAttempts===0,"one_original_sqlite_close");row.closeAttempts++;
   const result=close();row.closed=true;return result;
  }});
  for(const key of ["prepare","exec"]){const original=db[key].bind(db);
   Object.defineProperty(db,key,{configurable:true,value:(...values)=>{
    try{return original(...values);}catch(error){observeSqliteError(error);throw error;}
   }});
  }
  return db;
 }});
}
function installFdLedger(){
 fsOriginal={openSync:fs.openSync,closeSync:fs.closeSync};
 fs.openSync=function(...args){const fd=fsOriginal.openSync(...args);fdRows.push({fd,closeAttempts:0,closed:false});return fd;};
 fs.closeSync=function(fd){const row=fdRows.findLast(x=>x.fd===fd&&!x.closed);
  need(row&&row.closeAttempts===0,"one_original_recorded_fd_close");row.closeAttempts++;
  const result=fsOriginal.closeSync(fd);row.closed=true;return result;
 };
}
async function kernelGuards(){
 for(const [name,flag]of [["protected-read",fs.constants.O_RDONLY],["protected-write",fs.constants.O_WRONLY]]){
  let fd,denied=false;
  try{fd=fs.openSync(ROOT+"/"+name,flag|fs.constants.O_NOFOLLOW);}catch(e){denied=["EPERM","EACCES"].includes(e.code);}
  finally{if(fd!==undefined)fs.closeSync(fd);}
  need(denied,"kernel_protected_synthetic_file_refused");
 }
 if(mode!=="write-held"){
  let fd,denied=false;
  try{fd=fs.openSync(dbPath,fs.constants.O_WRONLY|fs.constants.O_NOFOLLOW);}catch(e){denied=["EPERM","EACCES"].includes(e.code);}
  finally{if(fd!==undefined)fs.closeSync(fd);}
  need(denied,"kernel_database_write_refused_in_read_phase");
 }
 const refused=await new Promise(resolve=>{
  const socket=new net.Socket();let code=null,connected=false;
  const timer=setTimeout(()=>socket.destroy(),Math.min(500,Math.max(1,Number((until-process.hrtime.bigint())/1000000n))));
  socket.once("error",error=>{code=error.code;socket.destroy();});
  socket.once("connect",()=>{connected=true;socket.destroy();});
  socket.once("close",()=>{clearTimeout(timer);resolve(!connected&&["EPERM","EACCES"].includes(code));});
  socket.connect(9,"127.0.0.1");
 });
 need(refused,"kernel_network_refusal_and_socket_close");
 report.kernelProtectedFileAndNetworkRefusalsObserved=true;
 childOriginals=Object.fromEntries(["spawn","spawnSync","exec","execSync","execFile","execFileSync","fork"].map(k=>[k,childProcess[k]]));
 for(const k of Object.keys(childOriginals))childProcess[k]=()=>{childAttempts++;throw new CasRefused("no_worker_child");};
 netOriginal=net.Socket.prototype.connect;net.Socket.prototype.connect=function(){networkAttempts++;throw new CasRefused("no_worker_network");};
 fetchOriginal=globalThis.fetch;globalThis.fetch=()=>{networkAttempts++;throw new CasRefused("no_worker_fetch");};
 syncBuiltinESMExports();
}
function fsyncedResponse(value){
 const fd=fs.openSync(responsePath,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
 try{fs.writeFileSync(fd,JSON.stringify({synthetic:true,credential:value}));fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
 const directory=fs.openSync(path.dirname(responsePath),fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
 try{fs.fsyncSync(directory);}finally{fs.closeSync(directory);}
 const token=Object.freeze({}),identity=ident(fs.lstatSync(responsePath,{bigint:true}));
 return {token,assert(provided,credential){
  need(provided===token&&same(credential,value)&&same(identity,ident(fs.lstatSync(responsePath,{bigint:true}))),"exact_fsynced_synthetic_response_witness");
 }};
}
try{
 process.umask(0o077);
 need(process.platform==="darwin"&&process.getuid()===501&&modes.includes(mode)&&Number.isFinite(budget)&&budget>0&&budget<=10000,"fixed_actual_wal_worker_scope");
 need(process.env.OPENCLAW_STATE_DIR===ROOT+"/output/state/initial"&&process.env.OPENCLAW_CONFIG_PATH===ROOT+"/output/config.json"&&
  process.env.TMPDIR===ROOT+"/output/tmp","synthetic_wal_environment");
 await kernelGuards();installFdLedger();installSqlite();syncBuiltinESMExports();
 process.stderr.write=function(data,...args){diagnostics+=Buffer.byteLength(data);const cb=args.find(x=>typeof x==="function");if(cb)cb();return true;};
 actual=await loadActualMacRawSdk();process.stderr.write=originalStderr;
 const initial=fs.lstatSync(dbPath,{bigint:true}),fixed=ident(initial).slice(0,6);
 need(initial.isFile()&&initial.uid===501n&&initial.nlink===1n&&(initial.mode&511n)===384n,"owned_synthetic_database_identity");
 let witness=null;
 const adapter=bindSdkRawOwnerCas({...actual,ownerDir,
  admit:(stage,file)=>{time();need(file===dbPath&&same(fixed,ident(fs.lstatSync(file,{bigint:true})).slice(0,6)),"held_synthetic_database_identity");report.admissionStages.push(stage);},
  assertResponse:(token,value)=>{need(witness!==null,"synthetic_response_precedes_cas");witness.assert(token,value);}});
 const readReceipt={};let before;
 try{before=adapter.readBefore(until,readReceipt);}catch(error){
  const expected=["read-cold","read-after-close"].includes(mode)&&error instanceof CasRefused&&
   readReceipt.errorCode==="sdk_raw_read_refused"&&report.sqliteErrors.some(x=>
    x.code!=="other"&&(x.number!==null?[8,14].includes(x.number&255):["SQLITE_READONLY","SQLITE_CANTOPEN"].includes(x.code)));
  need(expected,"only_observed_sqlite_readonly_refusal_is_diagnostic");report.readOutcome="known-readonly-refusal";
 }
 report.receipts.push({phase:"read",...readReceipt});
 if(before){
  checkSnapshot(before,["read-committed","read-after-close"].includes(mode));
  need(readReceipt.ok&&readReceipt.allReturnedConnectionsClosedOnce&&readReceipt.readonlyTransactionBegins===1&&readReceipt.readonlyTransactionEnds===1,
   "original_sdk_read_and_close_known");report.readOutcome="complete";
 }
 if(mode==="write-held"){
  need(before!==undefined,"original_synthetic_before_required");
  const next={...clone(before.store.profiles[ids[0]]),access:"synthetic-access-after",refresh:"synthetic-refresh-after",expires:Date.now()+3600000};
  witness=fsyncedResponse(next);report.syntheticResponseFsyncedBeforeCas=true;
  const r={},after=adapter.apply({before,targetProfileId:ids[0],newCredential:next,authorizedProfileIds:ids,responseWitness:witness.token,until},r);
  report.receipts.push({phase:"cas",...r});checkSnapshot(after,true);
  need(r.ok&&r.commitKnown&&r.commitDispatches===1&&r.writeDispatches===1&&r.rollbackDispatches===0&&r.independentPostCommitReadback&&
   r.allReturnedConnectionsClosedOnce&&r.otherProfilesAndOrderUnchanged&&r.ownerStateRowUnchanged,"one_original_sdk_cas_complete");
  report.actualRawCasCommitted=true;
 }
 time();actual.sourceFence();need(diagnostics===0,"no_unclassified_sdk_diagnostics");
 report.nodeVersion=process.versions.node;report.sqliteVersion=process.versions.sqlite;report.sdkSourcePins=SDK_PINS;
 report.ok=true;
}catch(error){report.errorCode=error instanceof CasRefused?error.code:"synthetic_wal_phase_failed";report.errorType=error?.constructor?.name??"Error";}
finally{
 process.stderr.write=originalStderr;
 report.sqliteScope={...sqlLedger,allReturnedOriginalHandlesClosedOnce:sqlRows.every(x=>x.closed&&x.closeAttempts===1)};
 report.recordedSourceAndResponseFds={opened:fdRows.length,allReturnedDescriptorsClosedOnce:fdRows.every(x=>x.closed&&x.closeAttempts===1)};
 if(!report.sqliteScope.allReturnedOriginalHandlesClosedOnce||!report.recordedSourceAndResponseFds.allReturnedDescriptorsClosedOnce||sqlLedger.denied)report.ok=false;
 if(sqlOriginal)sqlite.DatabaseSync=sqlOriginal;
 if(fsOriginal){fs.openSync=fsOriginal.openSync;fs.closeSync=fsOriginal.closeSync;}
 if(childOriginals)for(const [k,v]of Object.entries(childOriginals))childProcess[k]=v;
 if(netOriginal)net.Socket.prototype.connect=netOriginal;
 if(fetchOriginal)globalThis.fetch=fetchOriginal;
 syncBuiltinESMExports();
 report.childAttempts=childAttempts;report.networkAttempts=networkAttempts;report.capturedDiagnosticBytes=diagnostics;
 report.installedGuardsRestored=(!sqlOriginal||sqlite.DatabaseSync===sqlOriginal)&&(!fsOriginal||fs.openSync===fsOriginal.openSync&&fs.closeSync===fsOriginal.closeSync)&&
  (!netOriginal||net.Socket.prototype.connect===netOriginal)&&(!fetchOriginal||globalThis.fetch===fetchOriginal)&&
  (!childOriginals||Object.entries(childOriginals).every(([k,v])=>childProcess[k]===v));
 if(childAttempts||networkAttempts||!report.installedGuardsRestored)report.ok=false;
 report.elapsedSeconds=Number(process.hrtime.bigint()-started)/1e9;
}
output(JSON.stringify(report)+"\n");process.exitCode=report.ok?0:1;
