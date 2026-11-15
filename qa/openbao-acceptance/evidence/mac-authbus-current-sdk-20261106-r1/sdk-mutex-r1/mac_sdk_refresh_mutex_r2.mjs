/** Actual installed Mac SDK cooperative refresh mutex, with restrictive
 * path-local adapters. Qualification uses isolated synthetic state only.
 * This module does not read credentials, call providers, admit a refresh,
 * or write an auth store. Its caller owns the allowlist, original deadline,
 * durable once ledger, response capture, CAS and sandbox.
 */
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import {pathToFileURL} from "node:url";
import {isDeepStrictEqual} from "node:util";
const SDK="/opt/homebrew/lib/node_modules/openclaw";
export const SDK_MUTEX_SOURCE_PINS=Object.freeze({
  "dist/file-lock-CnWt2hZ7.js": "c559f538d982d580938b116e5d9dd67bf25587b849fbcd5d81b284f05083f91e",
  "dist/file-lock-B0CJDvN6.js": "d0b3f14b8830100e9f433980383f7483761a3ba117db99621d6ff52f6aa84a26",
  "dist/sidecar-lock-CyPvXk-D.js": "8f5c18b21519da86f6a7c3354edb365506600e61a1b114c049439c3db9dfe1b7",
  "dist/lock-config-jq3S1M_e.js": "1870826caf82d01365d577348f8414d55e796a0cc573418220599e1080a006d2",
  "dist/fs-safe-defaults-B7hUN42l.js": "012e89c2a94a1e640df88097c8f01e3024cdfaff619d0cea61aa1b1c93b40d7a",
  "dist/file-identity-C0fBiekR.js": "0b6268916543e024b15ed8b93887b1e0b431c1d0ee1bd4c3330082aa188dc6c2",
  "dist/pid-alive-C4bVUgUC.js": "60307078f6200503ed9c048b15e45592f589fb59e514e99e18efa31323e6ff21",
  "dist/runtime-snapshots-D6VA-VN8.js": "a1b70fb7664f40fd0a7e6a62f8d1215bca7d6aa465360a5762424100d0dafa4f"
});

const MANAGER_KEY="openclaw.plugin-sdk.file-lock";
const fail=code=>{throw Object.assign(new Error(code),{code});};
const need=(value,code)=>{if(!value)fail(code);};
const full=s=>["dev","ino","uid","gid","mode","nlink","size","mtimeNs","ctimeNs"].map(k=>String(s[k]));
const sameParent=(a,b)=>["dev","ino","uid","gid","mode"].every(k=>a[k]===b[k]);
const sameObject=(a,b)=>sameParent(a,b)&&a.nlink===b.nlink;
const safeError=error=>{
  const code=typeof error?.code==="string"&&/^sdk_mutex_[a-z_]{1,80}$/.test(error.code)
    ?error.code:"sdk_mutex_io_or_core_failure";
  return Object.assign(new Error(code),{code});
};
const remain=until=>{
  const now=process.hrtime.bigint();
  need(typeof until==="bigint"&&now<until,"sdk_mutex_original_deadline");
  return Number((until-now)/1000000n);
};
function readBounded(file,cap,{privateFile=false}={}){
  const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  try{
    const before=fs.fstatSync(fd,{bigint:true});
    need(before.isFile()&&before.nlink===1n&&before.size>=0n&&before.size<=BigInt(cap),
      "sdk_mutex_bounded_regular_file");
    need((before.mode&18n)===0n,"sdk_mutex_nonwritable_public_file");
    if(privateFile)need(before.uid===501n&&(before.mode&511n)===384n,"sdk_mutex_private_lock_file");
    const bytes=Buffer.alloc(Number(before.size)+1);let count=0;
    while(count<bytes.length){const n=fs.readSync(fd,bytes,count,bytes.length-count,null);if(!n)break;count+=n;}
    need(count===Number(before.size)&&isDeepStrictEqual(full(before),full(fs.fstatSync(fd,{bigint:true})))&&
      isDeepStrictEqual(full(before),full(fs.lstatSync(file,{bigint:true}))),"sdk_mutex_stable_read");
    return {bytes:bytes.subarray(0,count),identity:before};
  }finally{fs.closeSync(fd);}
}
function sourceFence(){
  for(const [relative,pin]of Object.entries(SDK_MUTEX_SOURCE_PINS)){
    const bytes=readBounded(path.join(SDK,relative),1048576).bytes;
    need(crypto.createHash("sha256").update(bytes).digest("hex")===pin,"sdk_mutex_source_pin");
  }
}
function holdParents(directory){
  const chain=[];let cursor=path.resolve(directory);
  for(;;){chain.unshift(cursor);if(cursor===path.dirname(cursor))break;cursor=path.dirname(cursor);}
  const held=[];
  try{
    for(const item of chain){
      const row={path:item,fd:fs.openSync(item,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW),
        identity:null,closeAttempted:false,closed:false};
      held.push(row);
      row.identity=fs.fstatSync(row.fd,{bigint:true});
      need(row.identity.isDirectory()&&[0n,501n].includes(row.identity.uid)&&
        (row.identity.mode&18n)===0n,"sdk_mutex_parent_custody");
    }
    return held;
  }catch(error){
    for(const row of held.reverse()){
      row.closeAttempted=true;
      try{fs.closeSync(row.fd);row.closed=true;}catch{}
    }
    if(held.some(row=>!row.closed))fail("sdk_mutex_parent_close_unknown");
    throw error;
  }
}
function verifyParents(rows){
  for(const row of rows){
    const held=fs.fstatSync(row.fd,{bigint:true}),named=fs.lstatSync(row.path,{bigint:true});
    // Creating an unrelated child directory may change nlink/mtime/size.
    // Parent custody compares only stable identity, owner and permissions.
    need(sameParent(held,row.identity)&&sameParent(named,row.identity),"sdk_mutex_parent_replaced");
  }
}
let active=false;
export async function loadQualifiedMacSdkMutex(){
  need(process.platform==="darwin"&&process.getuid()===501,"sdk_mutex_exact_mac_owner");
  sourceFence();
  const core=await import(pathToFileURL(path.join(SDK,"dist/file-lock-CnWt2hZ7.js")).href);
  const paths=await import(pathToFileURL(path.join(SDK,"dist/runtime-snapshots-D6VA-VN8.js")).href);
  const standard=await import(pathToFileURL(path.join(SDK,"dist/file-lock-B0CJDvN6.js")).href);
  need(typeof core.t==="function"&&typeof paths.f==="function"&&typeof standard.r==="function",
    "sdk_mutex_actual_exports");
  sourceFence();
  async function run({provider,profileId,stateRoot,until},callback,receipt){
    need(!active&&typeof callback==="function","sdk_mutex_one_original_context");
    need(receipt!==null&&typeof receipt==="object"&&Object.isExtensible(receipt),"sdk_mutex_mutable_receipt_required");
    need(provider==="openai"&&typeof profileId==="string"&&profileId.length>0&&profileId.length<=256,
      "sdk_mutex_exact_profile_shape");
    need(typeof stateRoot==="string"&&path.isAbsolute(stateRoot)&&path.resolve(stateRoot)===stateRoot&&
      process.env.OPENCLAW_STATE_DIR===stateRoot,"sdk_mutex_same_actual_state_root");
    need(process.umask()===0o077,"sdk_mutex_private_umask_required");
    remain(until);sourceFence();
    const target=paths.f(provider,profileId),directory=path.join(stateRoot,"locks","oauth-refresh");
    need(path.dirname(target)===directory&&/^lock-[0-9a-f]{32}$/.test(path.basename(target)),
      "sdk_mutex_actual_shared_namespace");
    const lockPath=target+".lock",parents=holdParents(directory);
    const base={open:fsp.open,rm:fsp.rm,readFile:fsp.readFile};
    let createdHandle=null,createdIdentity=null,guardian=null,snapshot=null,lock=null,result;
    let returnedHandleToSdk=false,primaryError=null,releaseError=null,closeCompleted=false;
    let closeAttempts=0,releaseTried=false;
    Object.assign(receipt,{schema:"heptabao.actual-sdk-refresh-mutex.r2",acquireAttempts:0,
      existingLockRefusals:0,snapshotReadAttempts:0,ownedSnapshotBytesRead:0,foreignSnapshotReadRefusals:0,
      removeAttempts:0,foreignRemovalRefusals:0,
      acquired:false,released:false,originalHandleCloseAttempts:0,originalHandleClosed:false,
      guardianClosed:false,parentDescriptorsClosed:false,sourcePins:SDK_MUTEX_SOURCE_PINS,
      providerCalled:false,profileIdOrLockPathPublished:false,automaticAcquisitionRetries:0,
      staleTakeoverAttempts:0,asyncUnlinkIsAtomicCompareAndDeleteClaimed:false});
    const matching=value=>typeof value==="string"&&value===lockPath;
    const readOwn=()=>{
      need(createdIdentity!==null,"sdk_mutex_unowned_lock_read");
      const named=fs.lstatSync(lockPath,{bigint:true});
      if(!sameObject(named,createdIdentity)){receipt.foreignSnapshotReadRefusals++;fail("sdk_mutex_lock_generation_changed");}
      const value=readBounded(lockPath,4096,{privateFile:true});
      receipt.ownedSnapshotBytesRead+=value.bytes.length;return value;
    };
    const guardedOpen=async function(file,flags,...args){
      if(!matching(file))return await base.open.call(fsp,file,flags,...args);
      need(flags==="wx"&&createdHandle===null,"sdk_mutex_only_one_exclusive_creation");
      receipt.acquireAttempts++;
      let handle;
      try{handle=await base.open.call(fsp,file,flags,...args);}
      catch(error){
        // Refuse before the SDK's EEXIST branch can read, retry or reclaim.
        if(error?.code==="EEXIST"){receipt.existingLockRefusals++;fail("sdk_mutex_existing_lock_refused");}
        throw error;
      }
      createdHandle=handle;
      const actualClose=handle.close.bind(handle);
      Object.defineProperty(handle,"close",{configurable:true,writable:true,value:async()=>{
        need(closeAttempts===0,"sdk_mutex_duplicate_original_close_refused");
        closeAttempts++;receipt.originalHandleCloseAttempts=closeAttempts;
        const value=await actualClose();closeCompleted=true;return value;
      }});
      createdIdentity=await handle.stat({bigint:true});
      need(createdIdentity.isFile()&&createdIdentity.uid===501n&&createdIdentity.nlink===1n&&
        (createdIdentity.mode&511n)===384n,"sdk_mutex_created_lock_custody");
      // Retain the inode through the SDK's release, which closes its handle
      // before reading and removing the name. This prevents inode reuse.
      guardian=fs.openSync(lockPath,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
      need(sameObject(fs.fstatSync(guardian,{bigint:true}),createdIdentity),
        "sdk_mutex_original_guardian");
      returnedHandleToSdk=true;return handle;
    };
    const guardedRead=async function(file,options,...args){
      if(!matching(file))return await base.readFile.call(fsp,file,options,...args);
      need(options==="utf8"&&args.length===0,"sdk_mutex_exact_snapshot_read_shape");
      receipt.snapshotReadAttempts++;return readOwn().bytes.toString("utf8");
    };
    const guardedRemove=async function(file,options,...args){
      if(!matching(file))return await base.rm.call(fsp,file,options,...args);
      receipt.removeAttempts++;
      try{
        need(options?.force===true&&Object.keys(options).length===1&&args.length===0,
          "sdk_mutex_exact_remove_shape");
        verifyParents(parents);
        const current=readOwn();
        if(snapshot)need(isDeepStrictEqual(full(current.identity),full(snapshot.identity))&&
          current.bytes.equals(snapshot.bytes),"sdk_mutex_lock_generation_changed");
      }catch(error){receipt.foreignRemovalRefusals++;throw error;}
      // This is the SDK's cooperative lock protocol. The preceding identity
      // check is not an atomic compare-and-unlink against noncooperating actors.
      return await base.rm.call(fsp,file,options);
    };
    const verifyHeld=()=>{
      remain(until);verifyParents(parents);
      need(lock&&guardian!==null&&snapshot,"sdk_mutex_held_original_required");
      const current=readOwn();
      need(sameObject(fs.fstatSync(guardian,{bigint:true}),snapshot.identity)&&
        isDeepStrictEqual(full(current.identity),full(snapshot.identity))&&current.bytes.equals(snapshot.bytes),
        "sdk_mutex_lock_generation_changed");
    };
    try{
      active=true;fsp.open=guardedOpen;fsp.readFile=guardedRead;fsp.rm=guardedRemove;
      lock=await core.t(target,{managerKey:MANAGER_KEY,allowReentrant:false,
        retry:{retries:0,factor:1,minTimeout:0,maxTimeout:0,randomize:false},
        staleMs:180000,staleRecovery:"fail-closed",
        timeoutMs:Math.max(1,Math.min(1000,remain(until))),
        shouldReclaim:()=>false,shouldRemoveStaleLock:()=>false,
        payload:()=>({pid:process.pid,createdAt:new Date().toISOString(),heptabaoOnceNonce:crypto.randomUUID()})});
      need(createdHandle!==null&&returnedHandleToSdk&&receipt.acquireAttempts===1&&
        receipt.existingLockRefusals===0,"sdk_mutex_original_exclusive_open_observed");
      snapshot=readOwn();receipt.acquired=true;verifyHeld();
      result=await callback(Object.freeze({verifyHeld}));verifyHeld();
    }catch(error){primaryError=safeError(error);}
    finally{
      if(lock){
        releaseTried=true;
        try{
          await lock.release();
          receipt.originalHandleClosed=closeCompleted&&createdHandle.fd===-1&&closeAttempts===1;
          need(receipt.originalHandleClosed,"sdk_mutex_original_handle_not_closed");
          verifyParents(parents);
          let absent=false;
          try{fs.lstatSync(lockPath);}catch(error){if(error?.code==="ENOENT")absent=true;else throw error;}
          need(absent&&receipt.foreignRemovalRefusals===0,"sdk_mutex_lock_not_retired");
          receipt.released=true;
        }catch(error){releaseError=safeError(error);}
      }else if(createdHandle){
        // If guardedOpen failed before returning, only this adapter received
        // the descriptor. If the SDK already attempted close, never retry it.
        if(!returnedHandleToSdk&&closeAttempts===0){
          try{await createdHandle.close();}catch(error){releaseError=safeError(error);}
        }
        receipt.originalHandleClosed=closeCompleted&&createdHandle.fd===-1&&closeAttempts===1;
        if(!receipt.originalHandleClosed&&!releaseError)
          releaseError=safeError({code:"sdk_mutex_original_handle_not_closed"});
      }else receipt.originalHandleClosed=true;
      if(guardian!==null){
        try{fs.closeSync(guardian);guardian=null;receipt.guardianClosed=true;}
        catch(error){if(!releaseError)releaseError=safeError(error);}
      }else receipt.guardianClosed=true;
      for(const row of parents.reverse()){
        row.closeAttempted=true;
        try{fs.closeSync(row.fd);row.closed=true;}catch(error){if(!releaseError)releaseError=safeError(error);}
      }
      receipt.parentDescriptorsClosed=parents.every(row=>row.closed);
      const unchanged=fsp.open===guardedOpen&&fsp.readFile===guardedRead&&fsp.rm===guardedRemove;
      fsp.open=base.open;fsp.readFile=base.readFile;fsp.rm=base.rm;active=false;
      receipt.processHooksRestored=unchanged;receipt.releaseAttempted=releaseTried;
      receipt.returnedHandleToSdk=returnedHandleToSdk;
      try{sourceFence();receipt.sourcePinsVerifiedAfter=true;}catch(error){if(!releaseError)releaseError=safeError(error);}
      if(!unchanged&&!releaseError)releaseError=safeError({code:"sdk_mutex_hook_replaced"});
    }
    receipt.primaryErrorCode=primaryError?.code??null;
    receipt.releaseErrorCode=releaseError?.code??null;
    if(primaryError)throw primaryError;
    if(releaseError)throw releaseError;
    remain(until);return result;
  }
  return Object.freeze({
    resolveActualPath:paths.f,
    acquireStandardSdkLock:standard.r,
    sourceFence,
    async withLock(options,callback,receipt={}){
      try{return await run(options,callback,receipt);}catch(error){throw safeError(error);}
    }
  });
}
