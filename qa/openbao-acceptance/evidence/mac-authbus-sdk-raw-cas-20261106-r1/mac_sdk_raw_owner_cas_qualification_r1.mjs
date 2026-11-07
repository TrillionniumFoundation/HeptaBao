#!/usr/bin/env node
/** Real node:sqlite fixtures; actual installed SDK on Mac, explicit local harness otherwise. */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import {createRequire,syncBuiltinESMExports} from "node:module";
import {isDeepStrictEqual} from "node:util";
import vm from "node:vm";
import net from "node:net";
import childProcess from "node:child_process";
import {bindSdkRawOwnerCas,CasRefused,loadActualMacRawSdk,makeAuthStoreAuthorizer,SDK_PINS} from "./mac_sdk_raw_owner_cas_r1.mjs";

const local=process.argv[2]==="local";
const ACTUAL_ROOT="/Users/qianqi/heptabao-authbus-sdk-raw-cas-qualification-20261106-r1";
const root=local?fs.mkdtempSync(path.join(path.dirname(new URL(import.meta.url).pathname),"raw-cas-local-")):ACTUAL_ROOT+"/output";
const started=process.hrtime.bigint(),budget=local?30000:Number(process.argv[2]);
const until=started+BigInt(Math.trunc(budget*1000000));
const report={schema:"heptabao.sdk-raw-owner-cas-isolated-qualification.r1",ok:false,
  actualInstalledSdk:!local,localHarnessOnly:local,syntheticCredentialsOnly:true,productionReads:0,productionWrites:0,
  providerCalls:0,productionMutexAcquired:false,upperSdkLifecycleUsed:false,otherProcessCacheInvalidationClaimed:false,
  privateCredentialDigestsPublished:false,cases:[],receipts:[]};
const output=process.stdout.write.bind(process.stdout),originalStderr=process.stderr.write;
let diagnostics=0,lastCase=null,actual=null,caseNumber=0,sqlGuard=null,childOriginals=null,childDenied=0;
function need(value,code){if(!value)throw new CasRefused(code);}
function remaining(){need(process.hrtime.bigint()<until,"original_qualification_deadline");return until;}
function same(a,b){return isDeepStrictEqual(a,b);}
function copy(v){return structuredClone(v);}
const sqlite=createRequire(import.meta.url)("node:sqlite");
function installSqliteScope(){
 const Original=sqlite.DatabaseSync,ledger={attempts:0,opened:0,memory:0,readOnly:0,writable:0,denied:0,connections:[]};
 sqlite.DatabaseSync=new Proxy(Original,{construct(target,args){
   const [file,options]=args,memory=file===":memory:";
   if(!memory&&!(typeof file==="string"&&path.resolve(file)===file&&
     file.startsWith(root+"/")&&/^case-[0-9]{2}\/agents\/main\/agent\/openclaw-agent\.sqlite$/.test(file.slice(root.length+1)))){
     ledger.denied++;throw new CasRefused("sqlite_outside_synthetic_fixture_scope");
   }
   ledger.attempts++;const db=Reflect.construct(target,args,target),row={closeAttempts:0,closed:false};
   ledger.opened++;if(memory)ledger.memory++;else if(options?.readOnly===true)ledger.readOnly++;else ledger.writable++;
   ledger.connections.push(row);const close=db.close.bind(db);
   Object.defineProperty(db,"close",{configurable:true,value:()=>{need(row.closeAttempts===0,"original_sqlite_close_once");row.closeAttempts++;
     const result=close();row.closed=true;return result;}});
   return db;
 }});
 return {ledger,restore(){sqlite.DatabaseSync=Original;}};
}
async function kernelGuards(){
 for(const [name,flag]of [["protected-read",fs.constants.O_RDONLY],["protected-write",fs.constants.O_WRONLY]]){
   let fd,denied=false;
   try{fd=fs.openSync(ACTUAL_ROOT+"/"+name,flag|fs.constants.O_NOFOLLOW);}catch(e){denied=["EACCES","EPERM"].includes(e.code);}
   finally{if(fd!==undefined)fs.closeSync(fd);}
   need(denied,"kernel_synthetic_data_fence_required");
 }
 const observed=await new Promise(resolve=>{
   const socket=new net.Socket();let code=null,connected=false;
   const ms=Math.min(750,Math.max(1,Number((until-process.hrtime.bigint())/1000000n)));
   const timer=setTimeout(()=>socket.destroy(),ms);
   socket.once("error",error=>{code=error.code;socket.destroy();});socket.once("connect",()=>{connected=true;socket.destroy();});
   socket.once("close",()=>{clearTimeout(timer);resolve(!connected&&["EACCES","EPERM"].includes(code));});
   socket.connect(9,"127.0.0.1");
 });
 need(observed,"kernel_network_refusal_required");
 childOriginals=Object.fromEntries(["spawn","spawnSync","exec","execSync","execFile","execFileSync","fork"].map(name=>[name,childProcess[name]]));
 for(const name of Object.keys(childOriginals))childProcess[name]=()=>{childDenied++;throw new CasRefused("fixture_child_forbidden");};
 syncBuiltinESMExports();report.kernelReadWriteAndNetworkRefusalsObserved=true;
}
const SQL={
 store:"CREATE TABLE auth_profile_store(store_key TEXT PRIMARY KEY, store_json TEXT NOT NULL, updated_at INTEGER NOT NULL)",
 state:"CREATE TABLE auth_profile_state(state_key TEXT PRIMARY KEY, state_json TEXT NOT NULL, updated_at INTEGER NOT NULL)"
};
const ids=["synthetic-main-one","synthetic-main-two","synthetic-main-three"];
const synthetic=(name)=>({type:"oauth",provider:"openai",access:"synthetic-access-"+name,
 refresh:"synthetic-refresh-"+name,expires:Date.now()-60000,accountId:"synthetic-account-"+name,
 email:"synthetic-"+name+"@invalid.example",retainedExtension:{purpose:"isolated-only",value:7}});
function fsynced(filename,value){
 const fd=fs.openSync(filename,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
 try{fs.writeFileSync(fd,JSON.stringify(value));fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
 const parent=fs.openSync(path.dirname(filename),fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
 try{fs.fsyncSync(parent);}finally{fs.closeSync(parent);}
}
function localSdk(){
 // The local harness uses a verbatim, pin-verified installed-SDK transaction
 // region, but substitutes raw SQL for Kysely. It is never actual-Mac proof.
 const source=fs.readFileSync(new URL("./reference/openclaw-state-db-DzSsA9Ji.js",import.meta.url),"utf8");
 need(crypto.createHash("sha256").update(source).digest("hex")===SDK_PINS["dist/openclaw-state-db-DzSsA9Ji.js"],"local_original_transaction_source_pin");
 const begin=source.indexOf("const transactionDepthByDatabase ="),end=source.indexOf("//#endregion",begin);
 need(begin>0&&end>begin,"actual_transaction_region");
 const transaction=vm.runInNewContext(source.slice(begin,end)+"\nrunSqliteImmediateTransactionSync",{});
 const snapshots=new Map();
 const sdk={transaction,readStore:(_dir,{db})=>{const r=db.prepare("SELECT store_json FROM auth_profile_store WHERE store_key = ?").get("primary");return r?JSON.parse(r.store_json):null;},
  readState:(_dir,{db})=>{const r=db.prepare("SELECT state_json FROM auth_profile_state WHERE state_key = ?").get("primary");return r?JSON.parse(r.state_json):null;},
  writeStore:(value,_dir,{db})=>db.prepare("INSERT INTO auth_profile_store (store_key,store_json,updated_at) VALUES (?,?,?) ON CONFLICT (store_key) DO UPDATE SET store_json=excluded.store_json,updated_at=excluded.updated_at").run("primary",JSON.stringify(value),Date.now()),
  clearConnectionCache:()=>{},clearSnapshots:()=>snapshots.clear()};
 return {sdk,sqlite,sourceFence:()=>{},snapshots:{o:(value,dir)=>snapshots.set(dir,copy(value)),n:dir=>snapshots.get(dir)}};
}
function fixture(options={}){
 remaining();const base=path.join(root,"case-"+String(++caseNumber).padStart(2,"0"));
 const ownerDir=path.join(base,"agents/main/agent");fs.mkdirSync(ownerDir,{recursive:true,mode:0o700});
 const database=path.join(ownerDir,"openclaw-agent.sqlite"),db=new sqlite.DatabaseSync(database);
 db.exec(SQL.store+";"+SQL.state+"; CREATE TABLE unrelated(value TEXT);");
 const store={version:1,profiles:Object.fromEntries(ids.map((id,i)=>[id,synthetic(String(i+1))])),
   preservedUnknown:{nested:[1,"unchanged",{flag:true}]},order:{openai:[ids[2],ids[0],ids[1]]},
   usageStats:{[ids[0]]:{lastUsed:123,errorCount:2}},lastGood:{openai:ids[1]}};
 store.profiles["synthetic-other-provider"]={type:"api_key",provider:"anthropic",key:"synthetic-other-key"};
 const state={version:1,order:{openai:[ids[2],ids[0],ids[1]]},usageStats:{[ids[1]]:{lastUsed:27}},lastGood:{openai:ids[2]}};
 db.prepare("INSERT INTO auth_profile_store VALUES (?,?,?)").run("primary",JSON.stringify(store),1700000000001);
 db.prepare("INSERT INTO auth_profile_state VALUES (?,?,?)").run("primary",JSON.stringify(state),1700000000002);
 db.prepare("INSERT INTO unrelated VALUES (?)").run("untouched-control");
 db.close();fs.chmodSync(database,0o600);
 const initial=fs.lstatSync(database,{bigint:true});
 const expectedName=[initial.dev,initial.ino,initial.uid,initial.gid,initial.mode,initial.nlink];
 const stateLocal={fault:options.fault,expired:false,opens:0,commitCalls:0,closeCalls:0};
 const permits=new WeakMap();
 const clock=()=>stateLocal.expired?until:process.hrtime.bigint();
 const DatabaseSync=new Proxy(sqlite.DatabaseSync,{construct(target,args){
   const database=Reflect.construct(target,args,target);stateLocal.opens++;
   const originalExec=database.exec.bind(database),originalClose=database.close.bind(database);
   Object.defineProperty(database,"exec",{configurable:true,value:sql=>{
     if(sql==="COMMIT"){
       stateLocal.commitCalls++;
       if(stateLocal.fault==="commit-busy")throw Object.assign(new Error("synthetic_busy"),{code:"SQLITE_BUSY"});
       if(stateLocal.fault==="commit-lost-return"){originalExec(sql);throw Object.assign(new Error("synthetic_lost_commit_return"),{code:"SQLITE_IOERR"});}
     }
     return originalExec(sql);
   }});
   Object.defineProperty(database,"close",{configurable:true,value:()=>{
     stateLocal.closeCalls++;const value=originalClose();
     if(stateLocal.fault==="close-lost-return")throw new Error("synthetic_lost_close_return");
     return value;
   }});
   if(stateLocal.fault==="authorizer-install")Object.defineProperty(database,"setAuthorizer",{value:()=>{throw new Error("synthetic_authorizer_install_failure");}});
   return database;
 }});
 const sdk={...actual.sdk,writeStore:(value,dir,handle)=>{
   const fault=stateLocal.fault;
   if(fault==="state-write")handle.db.prepare("UPDATE auth_profile_state SET state_json = ? WHERE state_key = ?").run("{}","primary");
   if(fault==="foreign-write")handle.db.prepare("INSERT INTO unrelated VALUES (?)").run("forbidden");
   if(fault==="ddl")handle.db.prepare("CREATE TABLE forbidden(value TEXT)").run();
   if(fault==="attach")handle.db.prepare("ATTACH ':memory:' AS outside").run();
   if(fault==="temp-write")handle.db.prepare("CREATE TEMP TABLE forbidden(value TEXT)").run();
   const sent=copy(value);if(fault==="other-profile")sent.profiles[ids[1]].access="unexpected-synthetic-change";
   actual.sdk.writeStore(sent,dir,handle);
   if(fault==="throw-after-write")throw new Error("synthetic_after_write");
   if(fault==="expire-after-write")stateLocal.expired=true;
  }};
 const response=(credential)=>{
   const token=Object.freeze({});fsynced(path.join(base,"response-"+permitsCount++ +".private.json"),{synthetic:true,credential});
   permits.set(token,copy(credential));return token;
 };
 let permitsCount=0;
 const adapter=bindSdkRawOwnerCas({sdk,sqlite:{...sqlite,DatabaseSync},ownerDir,clock,
   sourceFence:actual.sourceFence,
   admit:()=>{
     const s=fs.lstatSync(database,{bigint:true});need(s.isFile()&&same([s.dev,s.ino,s.uid,s.gid,s.mode,s.nlink],expectedName),"synthetic_fixed_owner_identity");
   },
   assertResponse:(permit,credential)=>need(permits.has(permit)&&same(permits.get(permit),credential),"durable_response_witness_required")});
 const before=adapter.readBefore(until),next={...copy(before.store.profiles[ids[0]]),
   access:"synthetic-new-access",refresh:"synthetic-new-refresh",expires:Date.now()+3600000};
 const params={before,targetProfileId:ids[0],newCredential:next,authorizedProfileIds:ids,responseWitness:response(next),until};
 const observe=()=>{
   const read=new sqlite.DatabaseSync(database,{readOnly:true});
   try{return {store:read.prepare("SELECT * FROM auth_profile_store ORDER BY store_key").all().map(x=>({...x})),
     state:read.prepare("SELECT * FROM auth_profile_state ORDER BY state_key").all().map(x=>({...x})),
     unrelated:read.prepare("SELECT * FROM unrelated").all().map(x=>({...x}))};}finally{read.close();}
 };
 const original=observe();
 return {base,ownerDir,database,adapter,params,stateLocal,response,before,next,observe,original,
   mutate:(sql,...bindings)=>{const db=new sqlite.DatabaseSync(database);try{db.prepare(sql).run(...bindings);}finally{db.close();}},
   exec:sql=>{const db=new sqlite.DatabaseSync(database);try{db.exec(sql);}finally{db.close();}}};
}
function expectRefusal(f,receipt={},predicate=()=>true){
 let refused=false;try{f.adapter.apply(f.params,receipt);}catch(error){refused=error instanceof CasRefused;}
 need(refused&&receipt.ok===false&&predicate(receipt),"expected_cas_refusal");return receipt;
}
async function run(name,operation){lastCase=name;remaining();const receipt=await operation();
 report.cases.push({case:name,passed:true});if(receipt)report.receipts.push({case:name,...receipt});}
try{
 process.umask(0o077);need(Number.isFinite(budget)&&budget>0&&budget<=45000,"bounded_original_qualification_allocation");
 if(!local){
   need(process.platform==="darwin"&&process.getuid()===501,"actual_mac_qualification_owner");
   need(process.env.OPENCLAW_STATE_DIR===root+"/state/initial"&&process.env.OPENCLAW_CONFIG_PATH===root+"/config.json"&&
     process.env.TMPDIR===root+"/tmp","owned_synthetic_sdk_environment");
   await kernelGuards();sqlGuard=installSqliteScope();syncBuiltinESMExports();
   const original=process.stderr.write;process.stderr.write=function(data,...args){diagnostics+=Buffer.byteLength(data);const cb=args.find(x=>typeof x==="function");if(cb)cb();return true;};
   actual=await loadActualMacRawSdk();process.stderr.write=original;
 }else actual=localSdk();
 report.nodeVersion=process.versions.node;report.sqliteVersion=process.versions.sqlite;
 report.authorizerAvailable=typeof sqlite.DatabaseSync.prototype.setAuthorizer==="function";
 await run("C01_complete_multi_profile_commit_and_snapshot_clear",()=>{
   const f=fixture(),r={};actual.snapshots.o(f.before.store,f.ownerDir);
   need(actual.snapshots.n(f.ownerDir)!==undefined,"runtime_snapshot_seeded");
   const result=f.adapter.apply(f.params,r),after=f.observe();
   const expected=copy(f.before.store);expected.profiles[ids[0]]=f.next;
   need(r.ok&&r.writeDispatches===1&&r.commitDispatches===1&&r.rollbackDispatches===0&&r.independentPostCommitReadback&&
     same(result.store,expected)&&same(after.state,f.original.state)&&same(after.unrelated,f.original.unrelated)&&
     actual.snapshots.n(f.ownerDir)===undefined&&r.allReturnedConnectionsClosedOnce,"complete_multi_profile_commit");return r;
 });
 await run("C02_unselected_profile_refused",()=>{const f=fixture();f.params.targetProfileId="synthetic-other-provider";return expectRefusal(f,{},r=>r.openedConnections===0&&r.writeDispatches===0);});
 await run("C03_changed_target_before_image_refused",()=>{const f=fixture(),s=copy(f.before.store);s.profiles[ids[0]].access="concurrent-synthetic";f.mutate("UPDATE auth_profile_store SET store_json=? WHERE store_key='primary'",JSON.stringify(s));return expectRefusal(f,{},r=>r.writeDispatches===0&&r.rollbackKnown);});
 await run("C04_changed_other_profile_refused",()=>{const f=fixture(),s=copy(f.before.store);s.profiles[ids[1]].refresh="concurrent-synthetic";f.mutate("UPDATE auth_profile_store SET store_json=? WHERE store_key='primary'",JSON.stringify(s));return expectRefusal(f,{},r=>r.writeDispatches===0&&r.rollbackKnown);});
 await run("C05_changed_state_order_refused",()=>{const f=fixture();f.mutate("UPDATE auth_profile_state SET state_json=? WHERE state_key='primary'",JSON.stringify({...f.before.state,order:{openai:ids}}));return expectRefusal(f,{},r=>r.writeDispatches===0&&r.rollbackKnown);});
 await run("C06_changed_raw_timestamp_refused",()=>{const f=fixture();f.mutate("UPDATE auth_profile_store SET updated_at=updated_at+1 WHERE store_key='primary'");return expectRefusal(f,{},r=>r.writeDispatches===0&&r.rollbackKnown);});
 await run("C07_missing_durable_response_before_open",()=>{const f=fixture();f.params.responseWitness={};return expectRefusal(f,{},r=>r.openedConnections===0&&r.writeDispatches===0);});
 await run("C08_wrong_provider_refused",()=>{const f=fixture();f.params.newCredential.provider="anthropic";return expectRefusal(f,{},r=>r.openedConnections===0);});
 await run("C09_changed_owner_identity_refused",()=>{const f=fixture();f.params.newCredential.accountId="another-synthetic-account";return expectRefusal(f,{},r=>r.openedConnections===0);});
 await run("C10_unknown_target_metadata_preserved",()=>{const f=fixture();delete f.params.newCredential.retainedExtension;return expectRefusal(f,{},r=>r.openedConnections===0);});
 for(const [name,fault]of [["C11_callback_failure_rolls_back_original_rows","throw-after-write"],["C12_other_profile_write_detected_and_rolled_back","other-profile"],
   ["C13_state_table_write_denied_and_rolled_back","state-write"],["C14_other_table_write_denied_and_rolled_back","foreign-write"],
   ["C15_ddl_denied_and_rolled_back","ddl"],["C16_attach_denied_and_rolled_back","attach"],["C17_temp_schema_denied_and_rolled_back","temp-write"]]){
   await run(name,()=>{const f=fixture();f.stateLocal.fault=fault;const r=expectRefusal(f,{},r=>r.rollbackKnown&&r.commitDispatches===0);
     need(same(f.observe(),f.original),"failed_transaction_original_rows_restored");
     if(!["throw-after-write","other-profile"].includes(fault))need(r.authorizerDeniedCount>0,"real_authorizer_denied_sql");return r;});
 }
 await run("C18_existing_trigger_refused_before_write",()=>{const f=fixture();f.exec("CREATE TRIGGER forbidden AFTER UPDATE ON auth_profile_store BEGIN INSERT INTO unrelated VALUES ('triggered'); END");return expectRefusal(f,{},r=>r.writeDispatches===0&&r.beginDispatches===0);});
 await run("C19_view_instead_of_auth_table_refused",()=>{const f=fixture();f.exec("ALTER TABLE auth_profile_state RENAME TO hidden_state; CREATE VIEW auth_profile_state AS SELECT * FROM hidden_state");return expectRefusal(f,{},r=>r.writeDispatches===0&&r.beginDispatches===0);});
 await run("C20_original_deadline_expired_before_open",()=>{const f=fixture();f.params.until=process.hrtime.bigint()-1n;return expectRefusal(f,{},r=>r.openedConnections===0);});
 await run("C21_deadline_after_write_rolls_back_no_commit",()=>{const f=fixture();f.stateLocal.fault="expire-after-write";const r=expectRefusal(f,{},r=>r.commitDispatches===0&&r.rollbackKnown);need(same(f.observe(),f.original),"expired_transaction_original_rows");return r;});
 await run("C22_sdk_busy_commit_retry_prevented",()=>{const f=fixture();f.stateLocal.fault="commit-busy";const r=expectRefusal(f,{},r=>r.commitDispatches===1&&r.preventedCommitRetries===1&&r.rollbackKnown);need(f.stateLocal.commitCalls===1&&same(f.observe(),f.original),"one_original_commit_dispatch");return r;});
 await run("C23_commit_lost_return_unknown_not_replayed",()=>{const f=fixture();f.stateLocal.fault="commit-lost-return";const r=expectRefusal(f,{},r=>r.commitDispatches===1&&r.outcomeUnknown&&!r.commitKnown);need(f.stateLocal.commitCalls===1&&f.observe().store[0].store_json===JSON.stringify({...f.before.store,profiles:{...f.before.store.profiles,[ids[0]]:f.next}}),"lost_commit_return_fixture_applied_once");return r;});
 await run("C24_close_lost_return_unknown_not_replayed",()=>{const f=fixture();f.stateLocal.fault="close-lost-return";const start=f.stateLocal.closeCalls;const r=expectRefusal(f,{},r=>r.commitKnown&&r.outcomeUnknown&&r.closeAttempts===1&&r.knownClosedConnections===0);need(f.stateLocal.closeCalls-start===1,"unknown_original_close_not_replayed");return r;});
 await run("C25_postcommit_external_change_is_unfinished",()=>{
   const f=fixture();let afterCalls=0;
   const source=actual.sourceFence;const originalSdk=actual.sdk;
   const adapter=bindSdkRawOwnerCas({sdk:originalSdk,sqlite,ownerDir:f.ownerDir,sourceFence:source,
     admit:stage=>{if(stage==="after-commit"){afterCalls++;f.mutate("UPDATE auth_profile_state SET updated_at=updated_at+1 WHERE state_key='primary'");}},
     assertResponse:()=>{},clock:()=>process.hrtime.bigint()});
   f.adapter=adapter;const r=expectRefusal(f,{},r=>r.commitKnown&&!r.independentPostCommitReadback&&r.writeDispatches===1);
   need(afterCalls===1,"postcommit_change_injected_once");return r;
 });
 await run("C26_real_authorizer_rejects_trigger_context",()=>{
   const db=new sqlite.DatabaseSync(":memory:");db.exec(SQL.store+"; CREATE TABLE unrelated(value TEXT); INSERT INTO auth_profile_store VALUES('primary','{}',1); CREATE TRIGGER forbidden AFTER UPDATE ON auth_profile_store BEGIN INSERT INTO unrelated VALUES('triggered'); END");
   const r={authorizerDeniedCount:0};db.setAuthorizer(makeAuthStoreAuthorizer(sqlite.constants,{live:()=>true,withinDeadline:()=>true,writing:()=>true,transactions:()=>true,schema:()=>false},r));
   let refused=false;try{db.prepare("UPDATE auth_profile_store SET store_json='{}' WHERE store_key='primary'").run();}catch{refused=true;}finally{db.close();}
   need(refused&&r.authorizerDeniedCount===1,"actual_trigger_authorizer_rejection");return r;
 });
 await run("C27_closed_handle_never_accepted",()=>{
   const f=fixture();const badSdk={...actual.sdk,transaction:(db,fn)=>{db.close();return actual.sdk.transaction(db,fn);}};
   f.adapter=bindSdkRawOwnerCas({sdk:badSdk,sqlite,sourceFence:actual.sourceFence,ownerDir:f.ownerDir,admit:()=>{},assertResponse:()=>{}});
   const r=expectRefusal(f,{},r=>r.writeDispatches===0&&r.closeAttempts===1&&r.knownClosedConnections===1);
   need(same(f.observe(),f.original),"closed_handle_original_rows_unchanged");return r;
 });
 await run("C28_authorizer_install_failure_closes_once",()=>{
   const f=fixture();f.stateLocal.fault="authorizer-install";
   const r=expectRefusal(f,{},r=>r.writeDispatches===0&&r.openedConnections===1&&r.closeAttempts===1&&r.knownClosedConnections===1&&r.connectionCacheClears===1);
   need(same(f.observe(),f.original),"authorizer_setup_failure_original_rows_unchanged");return r;
 });
 await run("C29_readonly_owner_snapshot_is_wal_consistent",()=>{
   const f=fixture();f.exec("PRAGMA journal_mode=WAL");let injected=false;
   const wrapped={...actual.sdk,readStore:(dir,handle)=>{const value=actual.sdk.readStore(dir,handle);
     if(!injected){injected=true;f.mutate("UPDATE auth_profile_state SET updated_at=updated_at+1 WHERE state_key='primary'");}return value;}};
   const adapter=bindSdkRawOwnerCas({sdk:wrapped,sqlite,sourceFence:actual.sourceFence,ownerDir:f.ownerDir,admit:()=>{},assertResponse:()=>{}}),r={};
   const observed=adapter.readBefore(until,r);
   need(injected&&same(observed,f.before)&&f.observe().state[0].updated_at===f.original.state[0].updated_at+1&&
     r.readonlyTransactionBegins===1&&r.readonlyTransactionEnds===1&&r.allReturnedConnectionsClosedOnce,"real_wal_reader_consistent_owner_snapshot");return r;
 });
 remaining();actual.sourceFence();need(report.cases.length===29&&diagnostics===0,"all_actual_raw_cas_cases_complete");
 report.ok=true;report.caseCount=29;report.sdkSourcePins=SDK_PINS;
}catch(error){report.failedCase=lastCase;report.errorCode=error instanceof CasRefused?error.code:"isolated_sdk_raw_cas_failed";
 report.errorType=error?.constructor?.name??"Error";}
finally{
 process.stderr.write=originalStderr;
 if(sqlGuard){const l=sqlGuard.ledger;report.sqliteScope={attempts:l.attempts,opened:l.opened,memory:l.memory,readOnly:l.readOnly,
   writable:l.writable,denied:l.denied,allOriginalHandlesClosedOnce:l.connections.every(x=>x.closed&&x.closeAttempts===1)};
   if(l.denied||!report.sqliteScope.allOriginalHandlesClosedOnce)report.ok=false;sqlGuard.restore();}
 if(childOriginals)for(const [name,original]of Object.entries(childOriginals))childProcess[name]=original;
 syncBuiltinESMExports();report.childAttempts=childDenied;if(childDenied)report.ok=false;
 report.elapsedSeconds=Number(process.hrtime.bigint()-started)/1e9;report.capturedDiagnosticBytes=diagnostics;
}
output(JSON.stringify(report)+"\n");process.exitCode=report.ok?0:1;
