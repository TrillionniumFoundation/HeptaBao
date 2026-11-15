/**
 * Prepared main3 refresh controller. No module-level I/O or provider dispatch.
 *
 * The production launcher must bind the separately qualified actual SDK mutex,
 * raw-CAS adapter, source-qualified provider hook, current source authority and
 * running-writer authority. This file is not a standalone production launcher.
 * All credential-bearing records stay in the fixed private ledger. Public
 * receipts contain only ordinals, closed codes, counters and closure evidence.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import {isDeepStrictEqual} from "node:util";

export const FIXED_LEDGER_ROOT="/Users/qianqi/heptabao-authbus-refresh-once-ledger-20261106";
export const FIXED_STATE_ROOT="/Users/qianqi/.openclaw";
const MAX=1048576;
const plain=x=>x!==null&&typeof x==="object"&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;
const sha=x=>crypto.createHash("sha256").update(x).digest("hex");
const full=s=>["dev","ino","uid","gid","mode","nlink","size","mtimeNs","ctimeNs"].map(k=>String(s[k]));
const stable=s=>["dev","ino","uid","gid","mode"].map(k=>String(s[k]));
export class RefreshOnceRefused extends Error {
  constructor(code){super(code);this.name="RefreshOnceRefused";this.code=code;}
}
const need=(x,code)=>{if(!x)throw new RefreshOnceRefused(code);};
const errorCode=e=>e instanceof RefreshOnceRefused?e.code:"refresh_once_dependency_refused";
const sync=(fn,args,code)=>{const r=fn(...args);need(r!==false&&(!r||typeof r.then!=="function"),code);return r;};
function encode(value){
  let text;try{text=JSON.stringify(value);}catch{throw new RefreshOnceRefused("refresh_once_private_json_shape");}
  need(typeof text==="string"&&Buffer.byteLength(text)<=MAX&&isDeepStrictEqual(JSON.parse(text),value),"refresh_once_private_json_shape");
  return Buffer.from(text+"\n");
}
function boundedError(receipt,error){receipt.errorCode=errorCode(error);return new RefreshOnceRefused(receipt.errorCode);}

/**
 * Fixed root is prepared create-only by the owned launcher, not by each run.
 * Existing scope must match byte-for-byte; an existing owner directory always
 * consumes that owner's once slot, even when the preceding outcome is UNKNOWN.
 * Namespace checks use retained descriptors. They are not an atomic openat
 * protocol against an arbitrary same-UID, noncooperating namespace replacer.
 */
export function openPrivateOnceLedger({root,scope,uid,io=fs,allowSyntheticRoot=false},receipt={}){
  need(typeof root==="string"&&path.isAbsolute(root)&&path.resolve(root)===root,"refresh_once_ledger_absolute_root");
  need(allowSyntheticRoot||root===FIXED_LEDGER_ROOT,"refresh_once_fixed_persistent_ledger_root");
  need(Number.isInteger(uid)&&uid>=0,"refresh_once_ledger_owner");
  need(plain(scope)&&scope.schema==="heptabao.main3-once-private-scope.r1"&&scope.provider==="openai"&&
    typeof scope.ownerDir==="string"&&path.isAbsolute(scope.ownerDir)&&Array.isArray(scope.profileIds)&&
    scope.profileIds.length===3&&new Set(scope.profileIds).size===3&&scope.profileIds.every(x=>typeof x==="string"&&x.length>0&&x.length<=256),
    "refresh_once_exact_main_three_scope");
  if(!allowSyntheticRoot)need(uid===501&&scope.ownerDir===path.join(FIXED_STATE_ROOT,"agents/main/agent"),"refresh_once_actual_main_owner");
  scope=structuredClone(scope);Object.freeze(scope.profileIds);Object.freeze(scope);
  const scopeBytes=encode(scope),parents=[],files=[],slots=new Map();let closed=false;
  Object.assign(receipt,{schema:"heptabao.private-main3-once-ledger.public.r1",openedDescriptors:0,closeAttempts:0,
    knownClosedDescriptors:0,fileCreateAttempts:0,fileFsyncs:0,directoryFsyncs:0,existingSlotRefusals:0,
    existingScopeMatched:false,privateValuesOrDigestsPublished:false,atomicNamespaceCompareDeleteClaimed:false});
  const ownFd=(fd,filename,kind)=>{const row={fd,filename,kind,closed:false,closeAttempted:false};files.push(row);receipt.openedDescriptors++;return row;};
  const closeOne=row=>{
    need(!row.closeAttempted,"refresh_once_descriptor_close_not_replayed");row.closeAttempted=true;receipt.closeAttempts++;
    try{io.closeSync(row.fd);row.closed=true;receipt.knownClosedDescriptors++;}catch{throw new RefreshOnceRefused("refresh_once_descriptor_close_unknown");}
  };
  const holdDir=filename=>{
    const row=ownFd(io.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW),filename,"directory");
    row.identity=io.fstatSync(row.fd,{bigint:true});
    need(row.identity.isDirectory()&&[0n,BigInt(uid)].includes(row.identity.uid)&&(row.identity.mode&18n)===0n,"refresh_once_directory_custody");
    need(isDeepStrictEqual(full(row.identity),full(io.lstatSync(filename,{bigint:true}))),"refresh_once_directory_open_matches_name");
    return row;
  };
  const verifyDir=row=>{
    need(!row.closeAttempted&&isDeepStrictEqual(stable(row.identity),stable(io.fstatSync(row.fd,{bigint:true})))&&
      isDeepStrictEqual(stable(row.identity),stable(io.lstatSync(row.filename,{bigint:true}))),"refresh_once_directory_replaced");
  };
  const verify=()=>{need(!closed,"refresh_once_ledger_closed");for(const row of parents)verifyDir(row);for(const slot of slots.values())verifyDir(slot.dir);};
  const fsyncDir=row=>{verifyDir(row);io.fsyncSync(row.fd);receipt.directoryFsyncs++;verifyDir(row);};
  const readHeld=row=>{
    need(!row.closeAttempted,"refresh_once_live_private_witness");
    const before=io.fstatSync(row.fd,{bigint:true});
    need(before.isFile()&&before.uid===BigInt(uid)&&before.nlink===1n&&(before.mode&511n)===384n&&
      before.size>=0n&&before.size<=BigInt(MAX+1),"refresh_once_private_regular_file");
    const bytes=Buffer.alloc(Number(before.size)+1);let offset=0;
    while(offset<bytes.length){const n=io.readSync(row.fd,bytes,offset,bytes.length-offset,offset);if(!n)break;offset+=n;}
    need(offset===Number(before.size)&&isDeepStrictEqual(full(before),full(io.fstatSync(row.fd,{bigint:true})))&&
      isDeepStrictEqual(full(before),full(io.lstatSync(row.filename,{bigint:true}))),"refresh_once_private_file_changed");
    if(row.identity)need(isDeepStrictEqual(full(before),row.identity),"refresh_once_private_witness_generation_changed");
    return {bytes:bytes.subarray(0,offset),identity:full(before)};
  };
  function holdFile(filename){
    const row=ownFd(io.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK),filename,"file");
    const value=readHeld(row);row.identity=value.identity;row.bytes=value.bytes;return row;
  }
  function writeNew(parent,name,bytes){
    need(Buffer.isBuffer(bytes)&&bytes.length<=MAX+1&&/^[a-z0-9.-]+$/.test(name),"refresh_once_private_record_shape");
    verify();verifyDir(parent);const filename=path.join(parent.filename,name);receipt.fileCreateAttempts++;
    const row=ownFd(io.openSync(filename,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600),filename,"write");
    try{
      const s=io.fstatSync(row.fd,{bigint:true});need(s.isFile()&&s.uid===BigInt(uid)&&s.nlink===1n&&(s.mode&511n)===384n,"refresh_once_created_record_custody");
      let offset=0;while(offset<bytes.length){const n=io.writeSync(row.fd,bytes,offset,bytes.length-offset,offset);need(n>0,"refresh_once_private_short_write");offset+=n;}
      io.fsyncSync(row.fd);receipt.fileFsyncs++;
    }finally{closeOne(row);}
    fsyncDir(parent);verify();const witness=holdFile(filename);
    need(witness.bytes.equals(bytes),"refresh_once_private_record_readback");return witness;
  }
  function assertFile(row){verify();const value=readHeld(row);need(value.bytes.equals(row.bytes),"refresh_once_private_witness_bytes_changed");}
  function close(){
    if(closed)return;closed=true;let error;
    for(const row of [...files].reverse())if(!row.closeAttempted){try{closeOne(row);}catch(e){error??=e;}}
    receipt.allOwnedDescriptorsClosedOnce=receipt.openedDescriptors===receipt.closeAttempts&&receipt.closeAttempts===receipt.knownClosedDescriptors;
    if(error)throw error;
  }
  try{
    const chain=[];for(let p=root;;p=path.dirname(p)){chain.unshift(p);if(p===path.dirname(p))break;}
    for(const p of chain)parents.push(holdDir(p));
    const directory=parents.at(-1);need(directory.identity.uid===BigInt(uid)&&(directory.identity.mode&511n)===448n,"refresh_once_private_ledger_directory");
    let scopeRecord;
    try{scopeRecord=holdFile(path.join(root,"scope.private.json"));receipt.existingScopeMatched=true;}
    catch(e){if(e?.code!=="ENOENT")throw e;scopeRecord=writeNew(directory,"scope.private.json",scopeBytes);}
    need(scopeRecord.bytes.equals(scopeBytes),"refresh_once_scope_cannot_rebind_existing_ledger");
    const getSlot=ordinal=>{need(Number.isInteger(ordinal)&&ordinal>=0&&ordinal<3,"refresh_once_selected_ordinal");const slot=slots.get(ordinal);need(slot,"refresh_once_original_slot_required");verify();assertFile(scopeRecord);return slot;};
    const api={
      verify,close,
      begin(ordinal,intent){
        need(Number.isInteger(ordinal)&&ordinal>=0&&ordinal<3&&!slots.has(ordinal),"refresh_once_one_slot_per_owner");
        need(plain(intent)&&intent.ordinal===ordinal&&intent.provider===scope.provider&&intent.profileId===scope.profileIds[ordinal]&&
          intent.ownerDir===scope.ownerDir,"refresh_once_intent_matches_fixed_scope");
        verify();assertFile(scopeRecord);const filename=path.join(root,`owner-0${ordinal+1}`);
        try{io.mkdirSync(filename,{mode:0o700});}
        catch(e){if(e?.code==="EEXIST"){receipt.existingSlotRefusals++;throw new RefreshOnceRefused("refresh_once_existing_slot_never_replayed");}throw e;}
        fsyncDir(directory);const dir=holdDir(filename);need((dir.identity.mode&511n)===448n,"refresh_once_private_slot_directory");
        const slot={dir,dispatch:null,response:null,normalized:null,outcome:null};slots.set(ordinal,slot);
        slot.intent=writeNew(dir,"intent.private.json",encode(intent));return Object.freeze({ordinal});
      },
      assertIntent(handle){const slot=getSlot(handle.ordinal);assertFile(slot.intent);return JSON.parse(slot.intent.bytes);},
      markDispatch(handle,value){const slot=getSlot(handle.ordinal);need(!slot.dispatch,"refresh_once_dispatch_record_once");slot.dispatch=writeNew(slot.dir,"dispatch-unknown.private.json",encode(value));assertFile(slot.intent);assertFile(slot.dispatch);},
      captureResponse(handle,{status,headers,bytes}){
        const slot=getSlot(handle.ordinal);need(slot.dispatch&&!slot.response&&!slot.normalized,"refresh_once_one_complete_response");
        need(Number.isInteger(status)&&status>=100&&status<=599&&Buffer.isBuffer(bytes)&&bytes.length<=MAX&&Array.isArray(headers),"refresh_once_bounded_response_shape");
        assertFile(slot.dispatch);
        const body=writeNew(slot.dir,"provider-response.private.bin",bytes);
        const meta=writeNew(slot.dir,"provider-response.private.json",encode({schema:"heptabao.provider-response-private.r1",status,headers,bodySha256:sha(bytes),bodyBytes:bytes.length}));
        slot.response={body,meta,status};return Object.freeze({ordinal:handle.ordinal});
      },
      persistNormalized(handle,{credential,beforeFingerprint}){
        const slot=getSlot(handle.ordinal);need(slot.response&&!slot.normalized&&slot.response.status>=200&&slot.response.status<300,"refresh_once_success_response_before_normalized");
        assertFile(slot.response.body);assertFile(slot.response.meta);
        const record=writeNew(slot.dir,"normalized-credential.private.json",encode({schema:"heptabao.normalized-response-private.r1",credential,beforeFingerprint,responseBodySha256:sha(slot.response.body.bytes)}));
        const witness=Object.freeze({ordinal:handle.ordinal});slot.normalized={record,witness};return witness;
      },
      assertNormalized(witness,credential){
        const slot=getSlot(witness?.ordinal);need(slot.normalized?.witness===witness,"refresh_once_original_normalized_witness");
        for(const row of [slot.intent,slot.dispatch,slot.response.body,slot.response.meta,slot.normalized.record])assertFile(row);
        const value=JSON.parse(slot.normalized.record.bytes);need(isDeepStrictEqual(value.credential,credential)&&value.responseBodySha256===sha(slot.response.body.bytes),"refresh_once_durable_normalized_matches_response");
      },
      finish(handle,value){const slot=getSlot(handle.ordinal);need(!slot.outcome,"refresh_once_terminal_record_once");slot.outcome=writeNew(slot.dir,"outcome.private.json",encode(value));},
      responseStatus(handle){return getSlot(handle.ordinal).response?.status??null;}
    };
    verify();return Object.freeze(api);
  }catch(e){try{close();}catch{}throw e;}
}

/**
 * One original attempt for ONE selected owner. A caller may select another
 * ordinal only after all closures are known and a new source observation has
 * admitted its current before-image under the SAME outer absolute deadline.
 * It may never change the fixed ledger root or reuse a consumed owner slot.
 *
 * source.observe() returns private current authority; source.verify() and
 * writer.verify() MUST be synchronous. writer admission is independent of the
 * configured-only flags observation. rawFactory must use the actual qualified
 * bindSdkRawOwnerCas, with source-owned namespace admission. provider.refresh
 * must use the reviewed source hooks and call finalDispatch synchronously at
 * the final native send after DNS/dispatcher awaits, then responseCapture on a
 * complete bounded body BEFORE the actual SDK JSON parser sees that body.
 */
export function bindMain3RefreshOnce({scope,ledger,mutex,source,writer,rawFactory,provider,clock=()=>process.hrtime.bigint()}){
  need(plain(scope)&&scope.provider==="openai"&&Array.isArray(scope.profileIds)&&scope.profileIds.length===3&&
    new Set(scope.profileIds).size===3&&typeof scope.stateRoot==="string"&&path.isAbsolute(scope.stateRoot)&&
    scope.ownerDir===path.join(scope.stateRoot,"agents/main/agent"),"refresh_once_fixed_owner_scope_binding");
  scope=structuredClone(scope);Object.freeze(scope.profileIds);Object.freeze(scope);
  for(const f of [ledger.begin,ledger.verify,ledger.markDispatch,ledger.captureResponse,ledger.persistNormalized,ledger.assertNormalized,
    ledger.assertIntent,ledger.finish,mutex.withLock,source.observe,source.verify,writer.verify,rawFactory,provider.refresh])need(typeof f==="function","refresh_once_complete_binding");
  let active=false;
  return Object.freeze({async runOne({ordinal,until},receipt={}){
    need(!active,"refresh_once_one_original_context");active=true;
    Object.assign(receipt,{schema:"heptabao.main3-refresh-once.public.r1",ok:false,ordinal,providerDispatches:0,
      completeResponsesCaptured:0,normalizedResponsesDurable:0,rawCasInvocations:0,providerResponseStatus:null,
      providerExchangeAccepted:false,providerApplicationLivenessProven:false,localOwnerCommitKnown:false,
      outcomeUnknown:false,knownTerminalPrivateRecord:false,productionTrafficSwitched:false,
      credentialValuesOrDigestsPublished:false,automaticRetries:0,sourceObserved:false,runningWriterAdmissionRequired:true,
      configuredFlagsAloneAccepted:false,mutexReceipt:{},rawBeforeReceipt:{},rawCasReceipt:{}});
    let handle=null,observed=null,before=null,live=true,deadlineTimer=null,primary=null,terminalAttempted=false;
    const abort=new AbortController();
    const within=()=>need(live&&typeof until==="bigint"&&clock()<until&&!abort.signal.aborted,"refresh_once_original_absolute_deadline");
    const fence=stage=>{within();ledger.verify();sync(source.verify,[observed,stage],"refresh_once_sync_source_fence_required");sync(writer.verify,[observed,stage],"refresh_once_sync_running_writer_fence_required");within();};
    try{
      need(Number.isInteger(ordinal)&&ordinal>=0&&ordinal<3&&Array.isArray(scope.profileIds)&&scope.profileIds.length===3,"refresh_once_exact_selected_ordinal");
      within();const remaining=Number((until-clock())/1000000n);need(remaining>0&&remaining<=600000,"refresh_once_bounded_original_window");
      deadlineTimer=setTimeout(()=>{live=false;abort.abort();},remaining);deadlineTimer.unref?.();
      observed=await source.observe({ordinal,until});receipt.sourceObserved=true;fence("before-lock");
      await mutex.withLock({provider:"openai",profileId:scope.profileIds[ordinal],stateRoot:scope.stateRoot,until},async held=>{
        const heldFence=stage=>{fence(stage);sync(held.verifyHeld,[],"refresh_once_sync_mutex_fence_required");within();};
        heldFence("under-lock");
        const raw=rawFactory({observed,heldFence,assertResponse:ledger.assertNormalized,until});
        before=raw.readBefore(until,receipt.rawBeforeReceipt);heldFence("after-current-owner-read");
        const old=before?.store?.profiles?.[scope.profileIds[ordinal]];
        need(plain(old)&&old.type==="oauth"&&old.provider==="openai"&&typeof old.refresh==="string"&&old.refresh.length>0&&
          Number.isFinite(old.expires)&&old.expires<=Date.now(),"refresh_once_current_expired_selected_oauth");
        need(observed&&isDeepStrictEqual(observed.credential,old),"refresh_once_observed_current_selected_credential");
        const beforeFingerprint=sha(encode(before));
        handle=ledger.begin(ordinal,{schema:"heptabao.refresh-once-intent-private.r1",ordinal,provider:"openai",
          profileId:scope.profileIds[ordinal],ownerDir:scope.ownerDir,beforeFingerprint,attemptId:crypto.randomUUID(),
          createdAt:Date.now(),originalRemainingMs:Number((until-clock())/1000000n)});
        heldFence("intent-durable");
        const callbacks={
          signal:abort.signal,until,
          assertLive:()=>heldFence("provider-preparation"),
          finalDispatch(send){
            need(typeof send==="function"&&receipt.providerDispatches===0,"refresh_once_no_second_provider_dispatch");
            heldFence("before-dispatch-record");
            const intent=ledger.assertIntent(handle);need(intent.beforeFingerprint===beforeFingerprint,"refresh_once_original_before_binding");
            ledger.markDispatch(handle,{schema:"heptabao.provider-dispatch-private.r1",state:"UNKNOWN",attemptId:intent.attemptId,createdAt:Date.now()});
            // No await between the last synchronous authority check and native
            // send. A throw after this latch remains consumed and unreplayed.
            heldFence("final-native-send");receipt.providerDispatches++;receipt.outcomeUnknown=true;
            return send();
          },
          responseCapture({status,headers,bytes}){
            within();need(receipt.providerDispatches===1&&receipt.completeResponsesCaptured===0,"refresh_once_response_after_one_dispatch");
            ledger.captureResponse(handle,{status,headers,bytes});receipt.completeResponsesCaptured++;
            receipt.providerResponseStatus=status;within();
          }
        };
        const response=await new Promise((resolve,reject)=>{
          const aborted=()=>reject(new RefreshOnceRefused("refresh_once_original_absolute_deadline"));
          abort.signal.addEventListener("abort",aborted,{once:true});
          let original;
          try{original=provider.refresh({oldCredential:old,...callbacks});}
          catch(e){abort.signal.removeEventListener("abort",aborted);reject(e);return;}
          Promise.resolve(original).then(value=>{abort.signal.removeEventListener("abort",aborted);resolve(value);},
            error=>{abort.signal.removeEventListener("abort",aborted);reject(error);});
        });
        heldFence("after-provider-return");
        need(receipt.providerDispatches===1&&receipt.completeResponsesCaptured===1&&receipt.providerResponseStatus>=200&&
          receipt.providerResponseStatus<300&&plain(response),"refresh_once_complete_success_response_required");
        need(typeof response.access==="string"&&typeof response.refresh==="string"&&Number.isFinite(response.expires)&&response.expires>Date.now()&&
          isDeepStrictEqual(response.accountId,old.accountId),"refresh_once_provider_identity_unchanged");
        const credential={...structuredClone(old),access:response.access,refresh:response.refresh,expires:response.expires};
        if(Object.hasOwn(response,"idToken"))credential.idToken=response.idToken;
        const witness=ledger.persistNormalized(handle,{credential,beforeFingerprint});receipt.normalizedResponsesDurable++;
        heldFence("before-original-owner-cas");receipt.rawCasInvocations++;
        raw.apply({before,targetProfileId:scope.profileIds[ordinal],newCredential:credential,authorizedProfileIds:scope.profileIds,
          responseWitness:witness,until},receipt.rawCasReceipt);
        need(receipt.rawCasReceipt.ok===true&&receipt.rawCasReceipt.commitKnown===true&&receipt.rawCasReceipt.independentPostCommitReadback===true&&
          receipt.rawCasReceipt.allReturnedConnectionsClosedOnce===true,"refresh_once_complete_original_commit_required");
        receipt.localOwnerCommitKnown=true;receipt.providerExchangeAccepted=true;
        // source.verify after the expected write belongs to rawFactory/admit:
        // the original full9 capsule is never silently relabelled as current.
        sync(writer.verify,[observed,"after-own-commit"],"refresh_once_sync_running_writer_fence_required");
        ledger.verify();within();
      },receipt.mutexReceipt);
      need(receipt.mutexReceipt.released===true&&receipt.mutexReceipt.originalHandleClosed===true&&
        receipt.mutexReceipt.parentDescriptorsClosed===true&&receipt.mutexReceipt.guardianClosed===true,"refresh_once_known_mutex_closure_required");
      terminalAttempted=true;ledger.finish(handle,{schema:"heptabao.refresh-once-terminal-private.r1",state:"COMMITTED",createdAt:Date.now(),
        providerStatus:receipt.providerResponseStatus,originalOwnerCasKnown:true});receipt.knownTerminalPrivateRecord=true;
      receipt.outcomeUnknown=false;receipt.ok=true;
    }catch(e){
      primary=boundedError(receipt,e);
      if(handle&&!terminalAttempted){
        try{terminalAttempted=true;ledger.finish(handle,{schema:"heptabao.refresh-once-terminal-private.r1",state:receipt.localOwnerCommitKnown?"COMMITTED_CLOSURE_UNFINISHED":
          receipt.providerDispatches>0?"UNFINISHED_NO_REPLAY":"NO_DISPATCH_CONSUMED",errorCode:receipt.errorCode,createdAt:Date.now()});
          receipt.knownTerminalPrivateRecord=true;
        }catch{receipt.terminalPersistenceUnknown=true;}
      }
      if(receipt.providerDispatches>0)receipt.outcomeUnknown=true;
    }finally{
      live=false;abort.abort();if(deadlineTimer!==null)clearTimeout(deadlineTimer);active=false;
      receipt.contextClosed=true;receipt.abortSignalClosed=abort.signal.aborted;
    }
    if(primary)throw primary;return receipt;
  }});
}
