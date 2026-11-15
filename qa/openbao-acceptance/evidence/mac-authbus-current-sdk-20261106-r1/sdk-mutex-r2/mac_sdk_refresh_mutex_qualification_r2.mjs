#!/usr/bin/env node
/** Isolated actual Mac SDK mutex qualification. No production auth source read. */
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import net from "node:net";
import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import childProcess from "node:child_process";
import {createRequire} from "node:module";
import {loadQualifiedMacSdkMutex} from "./mac_sdk_refresh_mutex_r3.mjs";
const ROOT="/Users/qianqi/heptabao-authbus-sdk-mutex-qualification-20261106-r2";
const modes=new Set(["unit","hold-standard","contend-adapter","hold-adapter","contend-standard"]);
const mode=process.argv[2],budgetMs=Number(process.argv[3]);
const start=process.hrtime.bigint(),until=start+BigInt(Math.trunc(budgetMs*1e6));
const PROFILE="heptabao-synthetic-mutex-fixture";
const output=process.stdout.write.bind(process.stdout),errout=process.stderr.write.bind(process.stderr);
const report={schema:"heptabao.actual-sdk-mutex-isolated-qualification.r2",mode,ok:false,cases:[],
  actualProviderCalls:0,productionProfileReads:0,productionMutexAcquired:false,authDatabaseOpens:0,
  credentialOrProfileIdDigestsPublished:false,syntheticStateOnly:true,sourceHooksRestored:false};
function fail(code){throw Object.assign(new Error(code),{code});}
function need(value,code){if(!value)fail(code);}
function remaining(){need(process.hrtime.bigint()<until,"mutex_fixture_original_deadline");}
function emit(value){output(JSON.stringify(value)+"\n");}
function stateFor(name){
  const root=path.join(ROOT,"output/state",name);
  fs.mkdirSync(path.join(root,"locks/oauth-refresh"),{recursive:true,mode:0o700});
  process.env.OPENCLAW_STATE_DIR=root;return root;
}
function options(stateRoot,override={}){return {provider:"openai",profileId:PROFILE,stateRoot,until,...override};}
function identity(s){return [s.dev,s.ino,s.uid,s.gid,s.mode,s.nlink,s.size,s.mtimeMs,s.ctimeMs];}
function same(a,b){return JSON.stringify(identity(a))===JSON.stringify(identity(b));}
function absent(file){try{fs.lstatSync(file);return false;}catch(e){if(e.code==="ENOENT")return true;throw e;}}
function write(file,raw){fs.writeFileSync(file,raw,{flag:"wx",mode:0o600});}
function closure(receipt){
  need(receipt.originalHandleClosed&&receipt.guardianClosed&&receipt.parentDescriptorsClosed&&
    receipt.processHooksRestored&&receipt.sourcePinsVerifiedAfter,"mutex_fixture_all_descriptors_and_hooks_closed");
}
let restore=null,diagBytes=0,sdk=null,lastReceipt=null,networkDenied=0,childDenied=0,sqlDenied=0;
function protect(){
  const changes=[],replace=(obj,key,fn)=>{changes.push([obj,key,obj[key]]);obj[key]=fn;};
  const denyNetwork=()=>{networkDenied++;fail("mutex_fixture_network_forbidden");};
  const denyChild=()=>{childDenied++;fail("mutex_fixture_child_forbidden");};
  for(const key of ["request","get"])for(const obj of [http,https])replace(obj,key,denyNetwork);
  replace(globalThis,"fetch",denyNetwork);replace(net,"connect",denyNetwork);replace(net,"createConnection",denyNetwork);
  replace(net.Socket.prototype,"connect",denyNetwork);replace(tls,"connect",denyNetwork);
  for(const key of ["spawn","spawnSync","exec","execSync","execFile","execFileSync","fork"])replace(childProcess,key,denyChild);
  const sqlite=createRequire(import.meta.url)("node:sqlite");
  replace(sqlite,"DatabaseSync",new Proxy(sqlite.DatabaseSync,{construct(){sqlDenied++;fail("mutex_fixture_sqlite_forbidden");}}));
  replace(process.stdout,"write",function(data,...args){diagBytes+=Buffer.byteLength(data);const cb=args.find(x=>typeof x==="function");if(cb)cb();return true;});
  replace(process.stderr,"write",function(data,...args){diagBytes+=Buffer.byteLength(data);const cb=args.find(x=>typeof x==="function");if(cb)cb();return true;});
  return ()=>{for(const [obj,key,value]of changes.reverse())obj[key]=value;};
}
async function test(name,run){
  remaining();const receipt={};lastReceipt=null;
  try{await run(receipt);report.cases.push({case:name,passed:true,...receipt});}
  catch(error){report.failedCase={case:name,...receipt,mutex:lastReceipt?receiptProjection(lastReceipt):null};throw error;}
}
async function refusal(promise,expected){
  let code=null;
  try{await promise;}catch(e){code=e?.code;}
  need(code===expected,"mutex_fixture_expected_refusal");return code;
}
function receiptProjection(r){
  const keys=["acquireAttempts","existingLockRefusals","snapshotReadAttempts","ownedSnapshotBytesRead",
    "foreignSnapshotReadRefusals","removeAttempts","foreignRemovalRefusals","acquired","released",
    "originalHandleCloseAttempts","originalHandleClosed","guardianClosed","parentDescriptorsClosed",
    "processHooksRestored","sourcePinsVerifiedAfter","releaseAttempted","returnedHandleToSdk",
    "primaryErrorCode","releaseErrorCode","automaticAcquisitionRetries","staleTakeoverAttempts",
    "asyncUnlinkIsAtomicCompareAndDeleteClaimed"];
  return Object.fromEntries(keys.filter(k=>Object.hasOwn(r,k)).map(k=>[k,r[k]]));
}
async function unit(){
  await test("M01_original_acquire_release",async row=>{
    const root=stateFor("m01"),r={};let invoked=0;
    const value=await sdk.withLock(options(root),({verifyHeld})=>{invoked++;verifyHeld();return 7;},r);
    need(value===7&&invoked===1&&r.acquired&&r.released&&r.acquireAttempts===1&&r.removeAttempts===1,
      "mutex_fixture_original_success");
    closure(r);row.mutex=receiptProjection(r);
  });
  for(const [name,kind]of[["M02_existing_fresh","fresh"],["M03_existing_stale","stale"],["M04_existing_unparseable","malformed"]]){
    await test(name,async row=>{
      const root=stateFor(name.toLowerCase()),file=sdk.resolveActualPath("openai",PROFILE)+".lock",r={};
      const raw=kind==="malformed"?"not-json\n":JSON.stringify({pid:process.pid,
        createdAt:kind==="stale"?"1970-01-01T00:00:00.000Z":new Date().toISOString()})+"\n";
      write(file,raw);const before=fs.lstatSync(file);let invoked=0;
      await refusal(sdk.withLock(options(root),()=>invoked++,r),"sdk_mutex_existing_lock_refused");
      need(invoked===0&&r.acquireAttempts===1&&r.existingLockRefusals===1&&r.snapshotReadAttempts===0&&
        r.ownedSnapshotBytesRead===0&&r.removeAttempts===0&&same(before,fs.lstatSync(file))&&
        fs.readFileSync(file,"utf8")===raw,"mutex_fixture_existing_untouched");
      closure(r);row.mutex=receiptProjection(r);row.existingNameUnchanged=true;fs.unlinkSync(file);
    });
  }
  await test("M05_existing_symlink",async row=>{
    const root=stateFor("m05"),file=sdk.resolveActualPath("openai",PROFILE)+".lock",target=root+"/sentinel",r={};
    write(target,"synthetic-no-follow\n");fs.symlinkSync(target,file);const before=fs.lstatSync(file);
    await refusal(sdk.withLock(options(root),()=>fail("mutex_fixture_unexpected_callback"),r),"sdk_mutex_existing_lock_refused");
    need(r.snapshotReadAttempts===0&&r.ownedSnapshotBytesRead===0&&r.removeAttempts===0&&
      same(before,fs.lstatSync(file))&&fs.readFileSync(target,"utf8")==="synthetic-no-follow\n","mutex_fixture_symlink_untouched");
    closure(r);row.mutex=receiptProjection(r);row.targetUnchanged=true;fs.unlinkSync(file);
  });
  await test("M06_existing_directory",async row=>{
    const root=stateFor("m06"),file=sdk.resolveActualPath("openai",PROFILE)+".lock",r={};
    fs.mkdirSync(file,{mode:0o700});const before=fs.lstatSync(file);
    await refusal(sdk.withLock(options(root),()=>fail("mutex_fixture_unexpected_callback"),r),"sdk_mutex_existing_lock_refused");
    need(r.snapshotReadAttempts===0&&r.removeAttempts===0&&same(before,fs.lstatSync(file)),"mutex_fixture_directory_untouched");
    closure(r);row.mutex=receiptProjection(r);fs.rmdirSync(file);
  });
  await test("M07_callback_throw_releases",async row=>{
    const root=stateFor("m07"),r={};
    await refusal(sdk.withLock(options(root),()=>fail("sdk_mutex_fixture_callback_refused"),r),
      "sdk_mutex_fixture_callback_refused");
    need(r.acquired&&r.released&&r.originalHandleCloseAttempts===1,"mutex_fixture_callback_released");
    closure(r);row.mutex=receiptProjection(r);
  });
  await test("M08_same_process_nested_refused",async row=>{
    const root=stateFor("m08"),r={},nested={};
    await sdk.withLock(options(root),async()=>{
      await refusal(sdk.withLock(options(root),()=>fail("mutex_fixture_unexpected_callback"),nested),
        "sdk_mutex_one_original_context");
    },r);
    need(r.released&&Object.keys(nested).length===0,"mutex_fixture_nested_no_acquire");closure(r);
    row.mutex=receiptProjection(r);row.nestedAcquireAttempts=0;
  });
  await test("M09_lock_contents_changed",async row=>{
    const root=stateFor("m09"),file=sdk.resolveActualPath("openai",PROFILE)+".lock",r={};
    await refusal(sdk.withLock(options(root),()=>fs.appendFileSync(file,"synthetic-change"),r),
      "sdk_mutex_lock_generation_changed");
    need(!r.released&&r.originalHandleClosed&&r.removeAttempts===0&&
      fs.readFileSync(file,"utf8").endsWith("synthetic-change"),"mutex_fixture_changed_content_preserved");
    closure(r);row.mutex=receiptProjection(r);row.changedNamePreserved=true;fs.unlinkSync(file);
  });
  await test("M10_lock_name_replaced",async row=>{
    const root=stateFor("m10"),file=sdk.resolveActualPath("openai",PROFILE)+".lock",r={};
    let replacement=null;
    await refusal(sdk.withLock(options(root),()=>{
      fs.renameSync(file,file+".original");write(file,"synthetic-foreign\n");replacement=fs.lstatSync(file);
    },r),"sdk_mutex_lock_generation_changed");
    need(!r.released&&r.originalHandleClosed&&r.removeAttempts===0&&r.foreignSnapshotReadRefusals>0&&
      same(replacement,fs.lstatSync(file))&&fs.readFileSync(file,"utf8")==="synthetic-foreign\n",
      "mutex_fixture_replacement_preserved");
    closure(r);row.mutex=receiptProjection(r);row.replacementUnchanged=true;fs.unlinkSync(file);fs.unlinkSync(file+".original");
  });
  await test("M11_parent_name_replaced",async row=>{
    const root=stateFor("m11"),dir=root+"/locks/oauth-refresh",file=sdk.resolveActualPath("openai",PROFILE)+".lock",r={};
    let replacement=null;
    await refusal(sdk.withLock(options(root),()=>{
      fs.renameSync(dir,dir+".original");fs.mkdirSync(dir,{mode:0o700});write(file,"synthetic-foreign-parent\n");
      replacement=fs.lstatSync(file);
    },r),"sdk_mutex_parent_replaced");
    need(!r.released&&r.originalHandleClosed&&r.removeAttempts===0&&same(replacement,fs.lstatSync(file))&&
      fs.readFileSync(file,"utf8")==="synthetic-foreign-parent\n","mutex_fixture_parent_replacement_preserved");
    closure(r);row.mutex=receiptProjection(r);row.replacementUnchanged=true;
    fs.unlinkSync(file);fs.unlinkSync(path.join(dir+".original",path.basename(file)));
  });
  await test("M12_unrelated_child_directory_allowed",async row=>{
    const root=stateFor("m12"),r={};
    await sdk.withLock(options(root),()=>fs.mkdirSync(root+"/locks/oauth-refresh/unrelated",{mode:0o700}),r);
    need(r.released,"mutex_fixture_parent_nlink_change_allowed");closure(r);row.mutex=receiptProjection(r);
  });
  await test("M13_original_deadline_prevents_acquire",async row=>{
    const root=stateFor("m13"),r={};
    await refusal(sdk.withLock(options(root,{until:process.hrtime.bigint()-1n}),()=>{},r),"sdk_mutex_original_deadline");
    need(Object.keys(r).length===0&&absent(sdk.resolveActualPath("openai",PROFILE)+".lock"),"mutex_fixture_expired_no_acquire");
    row.acquireAttempts=0;
  });
  await test("M14_original_deadline_during_callback",async row=>{
    const root=stateFor("m14"),r={};
    await refusal(sdk.withLock(options(root,{until:process.hrtime.bigint()+50000000n}),
      async()=>{await new Promise(resolve=>setTimeout(resolve,70));},r),"sdk_mutex_original_deadline");
    need(r.acquired&&r.released,"mutex_fixture_expired_callback_released");closure(r);row.mutex=receiptProjection(r);
  });
  await test("M15_wrong_state_root",async row=>{
    const root=stateFor("m15"),r={};
    await refusal(sdk.withLock(options(root+"/wrong"),()=>{},r),"sdk_mutex_same_actual_state_root");
    need(Object.keys(r).length===0,"mutex_fixture_namespace_no_acquire");row.acquireAttempts=0;
  });
  await test("M16_wrong_provider",async row=>{
    const root=stateFor("m16"),r={};
    await refusal(sdk.withLock(options(root,{provider:"synthetic-unadmitted"}),()=>{},r),"sdk_mutex_exact_profile_shape");
    need(Object.keys(r).length===0,"mutex_fixture_provider_no_acquire");row.acquireAttempts=0;
  });
  await test("M17_wrong_umask",async row=>{
    const root=stateFor("m17"),r={},prior=process.umask(0o022);
    try{await refusal(sdk.withLock(options(root),()=>{},r),"sdk_mutex_private_umask_required");}
    finally{process.umask(prior);}
    need(Object.keys(r).length===0,"mutex_fixture_umask_no_acquire");row.acquireAttempts=0;
  });
  await test("M18_payload_failure_sdk_cleanup",async row=>{
    const root=stateFor("m18"),file=sdk.resolveActualPath("openai",PROFILE)+".lock",r={},original=fsp.open;
    let injected=0;
    fsp.open=async function(name,flags,...rest){const handle=await original.call(fsp,name,flags,...rest);
      if(name===file&&flags==="wx"){handle.writeFile=async()=>{injected++;fail("synthetic_payload_write");};}return handle;};
    try{await refusal(sdk.withLock(options(root),()=>{},r),"sdk_mutex_io_or_core_failure");}
    finally{fsp.open=original;}
    need(injected===1&&!r.acquired&&r.removeAttempts===1&&r.originalHandleCloseAttempts===1&&absent(file),
      "mutex_fixture_payload_failure_closed");closure(r);row.mutex=receiptProjection(r);
  });
  await test("M19_pre_return_stat_failure_closes_once",async row=>{
    const root=stateFor("m19"),file=sdk.resolveActualPath("openai",PROFILE)+".lock",r={},original=fsp.open;
    let injected=0,openedIdentity=null;
    fsp.open=async function(name,flags,...rest){const handle=await original.call(fsp,name,flags,...rest);
      if(name===file&&flags==="wx"){
        openedIdentity=await handle.stat();handle.stat=async()=>{injected++;fail("synthetic_stat_failure");};
      }return handle;};
    try{await refusal(sdk.withLock(options(root),()=>{},r),"sdk_mutex_io_or_core_failure");}
    finally{fsp.open=original;}
    need(injected===1&&!r.returnedHandleToSdk&&!r.acquired&&r.originalHandleCloseAttempts===1&&r.removeAttempts===0&&
      same(openedIdentity,fs.lstatSync(file)),"mutex_fixture_early_failure_closed_preserved");
    closure(r);row.mutex=receiptProjection(r);row.unadmittedCreatedNamePreserved=true;fs.unlinkSync(file);
  });
  await test("M20_close_failure_not_retried",async row=>{
    const root=stateFor("m20"),file=sdk.resolveActualPath("openai",PROFILE)+".lock",r={},original=fsp.open;
    let realCloses=0,created=null;
    fsp.open=async function(name,flags,...rest){const handle=await original.call(fsp,name,flags,...rest);
      if(name===file&&flags==="wx"){
        created=handle;const close=handle.close.bind(handle);
        handle.close=async()=>{realCloses++;await close();fail("synthetic_close_failed_after_os_completion");};
      }return handle;};
    try{await refusal(sdk.withLock(options(root),()=>{},r),"sdk_mutex_original_handle_not_closed");}
    finally{fsp.open=original;}
    need(realCloses===1&&created.fd===-1&&r.originalHandleCloseAttempts===1&&!r.originalHandleClosed&&
      r.guardianClosed&&r.parentDescriptorsClosed&&r.processHooksRestored&&absent(file),
      "mutex_fixture_unknown_close_refused_without_retry");
    row.mutex=receiptProjection(r);row.injectedErrorAfterActualOsClose=true;row.realUnderlyingCloseCalls=1;
  });
  await test("M21_failed_payload_replacement_preserved",async row=>{
    const root=stateFor("m21"),file=sdk.resolveActualPath("openai",PROFILE)+".lock",r={},original=fsp.open;
    let replaced=null;
    fsp.open=async function(name,flags,...rest){const handle=await original.call(fsp,name,flags,...rest);
      if(name===file&&flags==="wx"){handle.writeFile=async()=>{
        fs.renameSync(file,file+".original");write(file,"synthetic-foreign-after-failed-payload\n");
        replaced=fs.lstatSync(file);fail("synthetic_payload_replaced");
      };}return handle;};
    try{await refusal(sdk.withLock(options(root),()=>{},r),"sdk_mutex_lock_generation_changed");}
    finally{fsp.open=original;}
    need(!r.acquired&&r.originalHandleCloseAttempts===1&&r.originalHandleClosed&&r.foreignRemovalRefusals===1&&
      same(replaced,fs.lstatSync(file))&&fs.readFileSync(file,"utf8")==="synthetic-foreign-after-failed-payload\n",
      "mutex_fixture_failed_payload_foreign_preserved");
    closure(r);row.mutex=receiptProjection(r);row.foreignNameUnchanged=true;fs.unlinkSync(file);fs.unlinkSync(file+".original");
  });
  await test("M22_parent_symlink_rejected_before_acquire",async row=>{
    const root=stateFor("m22"),dir=root+"/locks/oauth-refresh",r={};
    fs.renameSync(dir,dir+".real");fs.symlinkSync(dir+".real",dir);
    await refusal(sdk.withLock(options(root),()=>{},r),"sdk_mutex_io_or_core_failure");
    need(Object.keys(r).length===0&&fs.readdirSync(dir+".real").length===0,"mutex_fixture_symlink_parent_refused");
    row.acquireAttempts=0;fs.unlinkSync(dir);
  });
  await test("M23_public_source_pin_mismatch",async row=>{
    const root=stateFor("m23"),r={},originalOpen=fs.openSync,originalRead=fs.readSync;
    const source="/opt/homebrew/lib/node_modules/openclaw/dist/file-lock-CnWt2hZ7.js";
    let sourceFd=null,injected=0;
    fs.openSync=function(name,...args){const fd=originalOpen.call(fs,name,...args);if(name===source)sourceFd=fd;return fd;};
    fs.readSync=function(fd,buffer,offset,length,position){
      const count=originalRead.call(fs,fd,buffer,offset,length,position);
      if(fd===sourceFd&&count>0&&injected===0){buffer[offset]^=1;injected++;}return count;
    };
    try{await refusal(sdk.withLock(options(root),()=>{},r),"sdk_mutex_source_pin");}
    finally{fs.openSync=originalOpen;fs.readSync=originalRead;}
    need(injected===1&&Object.keys(r).length===0&&absent(sdk.resolveActualPath("openai",PROFILE)+".lock"),
      "mutex_fixture_source_pin_refused_before_acquire");
    sdk.sourceFence();row.acquireAttempts=0;row.installedSourceUnchanged=true;
  });
}
function releaseLine(){
  return new Promise((resolve,reject)=>{
    let raw="";const timer=setTimeout(()=>done(false),Math.min(8000,Math.max(1,Number((until-process.hrtime.bigint())/1000000n))));
    const onData=chunk=>{raw+=chunk; if(raw.length>32||raw.includes("\n"))done(raw==="release\n");};
    const onEnd=()=>done(false);
    function done(ok){clearTimeout(timer);process.stdin.off("data",onData);process.stdin.off("end",onEnd);
      process.stdin.pause();ok?resolve():reject(Object.assign(new Error("mutex_fixture_control_refused"),{code:"mutex_fixture_control_refused"}));}
    process.stdin.setEncoding("utf8");process.stdin.on("data",onData);process.stdin.once("end",onEnd);process.stdin.resume();
  });
}
async function interprocess(){
  const root=stateFor(mode==="hold-standard"||mode==="contend-adapter"?"interop-standard":"interop-adapter");
  const target=sdk.resolveActualPath("openai",PROFILE),r={};
  if(mode==="hold-standard"){
    const held=await sdk.acquireStandardSdkLock(target,{stale:180000,
      retries:{retries:0,factor:1,minTimeout:0,maxTimeout:0,randomize:false}});
    try{emit({event:"ready",mode,syntheticStateOnly:true});await releaseLine();}
    finally{await held.release();}
    need(absent(target+".lock"),"mutex_fixture_standard_holder_closed");
    report.originalSdkHolderReleased=true;
  }else if(mode==="hold-adapter"){
    await sdk.withLock(options(root),async({verifyHeld})=>{
      emit({event:"ready",mode,syntheticStateOnly:true});await releaseLine();verifyHeld();
    },r);closure(r);need(r.released,"mutex_fixture_adapter_holder_closed");report.mutex=receiptProjection(r);
  }else if(mode==="contend-adapter"){
    const before=fs.lstatSync(target+".lock");
    await refusal(sdk.withLock(options(root),()=>fail("mutex_fixture_unexpected_callback"),r),"sdk_mutex_existing_lock_refused");
    need(r.existingLockRefusals===1&&r.snapshotReadAttempts===0&&r.removeAttempts===0&&same(before,fs.lstatSync(target+".lock")),
      "mutex_fixture_original_sdk_blocks_adapter");
    closure(r);report.mutex=receiptProjection(r);report.actualSdkHolderNameUnchanged=true;
  }else if(mode==="contend-standard"){
    const before=fs.lstatSync(target+".lock");
    await refusal(sdk.acquireStandardSdkLock(target,{stale:180000,
      retries:{retries:0,factor:1,minTimeout:0,maxTimeout:0,randomize:false}}),"file_lock_timeout");
    need(same(before,fs.lstatSync(target+".lock")),"mutex_fixture_adapter_blocks_original_sdk");
    report.originalSdkRefusedWithTimeout=true;report.actualAdapterHolderNameUnchanged=true;
  }
}
try{
  need(process.platform==="darwin"&&process.getuid()===501&&modes.has(mode)&&Number.isFinite(budgetMs)&&
    budgetMs>0&&budgetMs<=45000,"mutex_fixture_exact_actual_mac_and_budget");
  need(process.umask()===0o077&&process.env.TMPDIR===ROOT+"/output/tmp"&&
    process.env.OPENCLAW_CONFIG_PATH===ROOT+"/output/config.json","mutex_fixture_exact_private_environment");
  let writeDenied=false;try{const fd=fs.openSync(ROOT+"/protected-write",fs.constants.O_WRONLY);fs.closeSync(fd);}
  catch(e){writeDenied=["EPERM","EACCES"].includes(e.code);}
  need(writeDenied,"mutex_fixture_kernel_write_fence");
  const networkBlocked=await new Promise(resolve=>{
    const socket=new net.Socket();let finished=false;
    const done=value=>{if(finished)return;finished=true;clearTimeout(timer);socket.destroy();resolve(value);};
    const timer=setTimeout(()=>done(false),750);socket.once("error",e=>done(["EPERM","EACCES"].includes(e.code)));
    socket.once("connect",()=>done(false));socket.connect(9,"127.0.0.1");
  });
  need(networkBlocked,"mutex_fixture_kernel_network_fence");report.kernelWriteAndNetworkDenied=true;
  stateFor("initial");
  restore=protect();const actualSdk=await loadQualifiedMacSdkMutex();
  sdk={...actualSdk,withLock(opts,callback,receipt={}){lastReceipt=receipt;return actualSdk.withLock(opts,callback,receipt);}};
  const denied=fn=>{let hit=false;try{fn();}catch{hit=true;}need(hit,"mutex_fixture_js_guard_negative");};
  denied(()=>globalThis.fetch("http://127.0.0.1:9"));denied(()=>childProcess.spawn("/usr/bin/true",[]));
  denied(()=>new (createRequire(import.meta.url)("node:sqlite").DatabaseSync)(":memory:"));
  need(networkDenied===1&&childDenied===1&&sqlDenied===1,"mutex_fixture_three_js_guard_negatives");
  if(mode==="unit")await unit();else await interprocess();
  sdk.sourceFence();remaining();
  need(networkDenied===1&&childDenied===1&&sqlDenied===1&&diagBytes===0,
    "mutex_fixture_no_unexpected_sdk_side_effect");
  report.sourcePinsVerifiedAfter=true;report.jsGuardNegativeCasesPassed=3;report.ok=true;
}catch(error){
  const code=String(error?.code??"");
  report.errorCode=/^(mutex_fixture_|sdk_mutex_)[a-z_]{1,100}$/.test(code)?code:"mutex_fixture_failed";
}finally{
  if(restore){restore();report.sourceHooksRestored=true;}
  report.unexpectedDiagnosticBytes=diagBytes;report.networkDeniedCount=networkDenied;
  report.childDeniedCount=childDenied;report.sqliteDeniedCount=sqlDenied;
  report.elapsedSeconds=Number(process.hrtime.bigint()-start)/1e9;
  emit(report);
}
process.exitCode=report.ok?0:1;
