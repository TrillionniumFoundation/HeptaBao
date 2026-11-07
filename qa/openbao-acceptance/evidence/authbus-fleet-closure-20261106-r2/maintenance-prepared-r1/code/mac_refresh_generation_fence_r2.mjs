/** Private current-generation fence for one source-bound main-owner refresh.
 *
 * Before the original SQLite write window every observed full9/absence remains
 * exact. During that one original handle's known transaction/readback, only the
 * main database's SQLite namespace may change. The original main inode remains
 * held and bound. This never relabels the old capsule as a new current capture.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import {isDeepStrictEqual} from "node:util";
import {SDK_SOURCE_PINS,SOURCE_SELECTION_AUTHORITY} from "./mac_refresh_source_authority_r1.mjs";

export const LIVE="/Users/qianqi/.openclaw";
export const AGENTS=Object.freeze(["main","trnm","hepta-ui","hepta","hepta-backend"]);
export const SDK="/opt/homebrew/lib/node_modules/openclaw";
export class GenerationRefused extends Error{
 constructor(code){super(code);this.name="GenerationRefused";this.code=code;}
}
function need(value,code){if(!value)throw new GenerationRefused(code);}
const same=isDeepStrictEqual;
const sha=bytes=>crypto.createHash("sha256").update(bytes).digest("hex");
const full=s=>["dev","ino","uid","gid","mode","nlink","size","mtimeNs","ctimeNs"].map(k=>String(s[k]));
/** Private equality only. Distinct profile labels do not authorize consuming
 * the same refresh object twice. Ambiguous aliases require a separate reviewed
 * fanout transaction; this controller does not invent one or hash credentials. */
export function assertSelectedRefreshObjectSeparation(entries){
 need(Array.isArray(entries)&&entries.length===3,"generation_three_refresh_objects_required");
 const targets=new Set(),refreshes=new Set();
 for(const entry of entries){
  need(entry&&typeof entry.ownerAgentDir==="string"&&typeof entry.profileId==="string"&&entry.profileId.length>0&&
   entry.credential?.type==="oauth"&&entry.credential?.provider==="openai"&&
   typeof entry.credential.refresh==="string"&&entry.credential.refresh.length>0&&entry.credential.refresh.length<=131072,
   "generation_selected_refresh_object_shape");
  const target=entry.ownerAgentDir+"\0"+entry.profileId;
  need(!targets.has(target)&&!refreshes.has(entry.credential.refresh),"generation_selected_refresh_objects_ambiguous");
  targets.add(target);refreshes.add(entry.credential.refresh);
 }
 return Object.freeze({privateEqualityChecked:true,distinctSelectedTargetKeys:3,distinctSelectedRefreshObjects:3});
}
function typed(value){
 need(Array.isArray(value)&&value.length===9&&value.every(x=>typeof x==="string"&&/^[0-9]{1,30}$/.test(x)),
  "generation_full9_shape");return value;
}
function absolute(value){return typeof value==="string"&&path.isAbsolute(value)&&path.normalize(value)===value;}
function bundleShape(bundle,base){
 need(bundle&&typeof bundle==="object"&&bundle.sourceIdentities&&typeof bundle.sourceIdentities==="object"
  &&!Array.isArray(bundle.sourceIdentities)&&Array.isArray(bundle.sourceAbsences),"generation_database_bundle_shape");
 const allowed=[base,base+"-wal",base+"-shm",base+"-journal"].sort();
 const present=Object.keys(bundle.sourceIdentities),absent=bundle.sourceAbsences;
 need(absent.every(x=>typeof x==="string")&&new Set(absent).size===absent.length
  &&!present.some(x=>absent.includes(x))&&same([...present,...absent].sort(),allowed)
  &&present.includes(base)&&absent.includes(base+"-journal"),"generation_exact_database_namespace");
 for(const id of Object.values(bundle.sourceIdentities))typed(id);
 if(absent.includes(base+"-wal"))need(absent.includes(base+"-shm"),"generation_absent_wal_has_no_shm");
 if(present.includes(base+"-wal")&&BigInt(bundle.sourceIdentities[base+"-wal"][6])>0n)
  need(present.includes(base+"-shm")&&BigInt(bundle.sourceIdentities[base+"-shm"][6])>0n,
   "generation_nonempty_wal_requires_shm");
 return allowed;
}

/** Close every original returned descriptor at most once. A failed close is
 * unknown, never retried, and does not skip the other original handles. The
 * same helper is used when construction fails and on normal context close. */
export function retireGenerationDescriptorsOnce(rows,closeOne,report){
 for(const row of [...rows].reverse())if(!row.closed&&row.closeAttempts===0){
  try{closeOne(row);}catch{}
 }
 report.descriptorsOpened=rows.length;
 report.descriptorsCloseAttempts=rows.reduce((n,row)=>n+row.closeAttempts,0);
 report.descriptorsClosed=rows.filter(row=>row.closed).length;
 report.descriptorCloseErrors=rows.filter(row=>row.closeErrorType).map(row=>row.closeErrorType);
 report.allOwnedDescriptorsClosedOnce=rows.every(row=>row.closed&&row.closeAttempts===1);
 return report.allOwnedDescriptorsClosedOnce;
}

/** The outer production loader supplies only its exact, already admitted
 * private capture. Tests may supply a synthetic root; this component has no
 * provider, SQL, process, journal, or production path discovery operation. */
export function bindObservedGeneration({stateRoot,capsulePath,expectedCapsuleIdentity,expectedCapsuleBytes,
 until,uid,clock=()=>process.hrtime.bigint(),io=fs,checkSdkSources=true},report={}){
 need(absolute(stateRoot)&&absolute(capsulePath)&&typeof until==="bigint"
  &&Number.isInteger(uid)&&uid>=0&&Buffer.isBuffer(expectedCapsuleBytes)
  &&expectedCapsuleBytes.length>0&&expectedCapsuleBytes.length<=1048576,
  "generation_explicit_private_capture_binding");
 typed(expectedCapsuleIdentity);
 let closed=false,failed=false,phase="exact",observations=0,totalBytes=0,heldMain=null;
 let readonlyBefore=false,readonlyAfter=false,mainBeforeBegin=null,mainAfterCommit=null,observedToken=null;
 const fds=[],originalCapsule=Buffer.from(expectedCapsuleBytes);
 Object.assign(report,{schema:"heptabao.main3-original-generation-fence.public.r2",scopeAgents:5,
  selectedOwners:3,metadataFiles:145,observations:[],beforeAfterObservationsOnly:true,
  continuousLockClaimed:false,originalCapsuleRelabelled:false,
  ownSqliteWindowEntered:false,knownOriginalCommitObserved:false,
  independentReadbackObserved:false,newGenerationCaptureRequiredAfterWrite:false,
  credentialValuesOrDigestsPublished:false,privateConfigurationDigestsPublished:false});
 const within=()=>need(!closed&&!failed&&clock()<until,"generation_original_deadline_and_context");
 function trackedOpen(filename,flags){
  const fd=io.openSync(filename,flags),row={fd,closed:false,closeAttempts:0};fds.push(row);return row;
 }
 function closeOne(row){
  need(!row.closed&&row.closeAttempts===0,"generation_descriptor_close_once");row.closeAttempts++;
  try{io.closeSync(row.fd);row.closed=true;}
  catch(error){row.closeErrorType=error?.constructor?.name??"Error";throw error;}
 }
 function regular(s,privateFile){
  need(s.isFile()&&s.nlink===1n&&(s.mode&18n)===0n&&[0n,BigInt(uid)].includes(s.uid),
   "generation_owned_regular_file");
  if(privateFile)need(s.uid===BigInt(uid)&&(s.mode&511n)===384n,"generation_private_file_custody");
 }
 function read(filename,maximum,privateFile=false,expected=null){
  within();const row=trackedOpen(filename,io.constants.O_RDONLY|io.constants.O_NOFOLLOW|io.constants.O_NONBLOCK);
  try{
   const s=io.fstatSync(row.fd,{bigint:true});regular(s,privateFile);
   need(s.size>=0n&&s.size<=BigInt(maximum),"generation_bounded_whole_file");
   if(expected)need(same(full(s),typed(expected)),"generation_expected_full9");
   const data=Buffer.alloc(Number(s.size)+1);let offset=0;
   while(offset<data.length){within();const n=io.readSync(row.fd,data,offset,data.length-offset,null);if(!n)break;offset+=n;}
   totalBytes+=offset;need(totalBytes<=512*1048576,"generation_cumulative_byte_budget");
   need(offset===Number(s.size)&&same(full(s),full(io.fstatSync(row.fd,{bigint:true})))
    &&same(full(s),full(io.lstatSync(filename,{bigint:true}))),"generation_stable_whole_file");
   return data.subarray(0,offset);
  }finally{closeOne(row);}
 }
 function absent(filename){
  within();try{io.lstatSync(filename,{bigint:true});}
  catch(error){if(error.code==="ENOENT")return;throw error;}
  throw new GenerationRefused("generation_expected_absence_changed");
 }
 function exactBundle(bundle,base){
  bundleShape(bundle,base);
  for(const [filename,id] of Object.entries(bundle.sourceIdentities)){
   within();const s=io.lstatSync(filename,{bigint:true});regular(s,true);
   need(same(full(s),typed(id)),"generation_current_source_full9_exact");
  }
  for(const filename of bundle.sourceAbsences)absent(filename);
 }
 let doc;
 try{
  need(same(read(capsulePath,1048576,true,expectedCapsuleIdentity),originalCapsule),"generation_same_private_capsule_bytes");
  doc=JSON.parse(originalCapsule.toString("utf8"));
  need(doc.schema==="heptabao.actual-sdk-selected-owner-credentials.private.r1"&&doc.host==="mac"
   &&same(doc.sdkSourcePins,SDK_SOURCE_PINS)&&same(doc.sourceSelectionAuthority,SOURCE_SELECTION_AUTHORITY),
   "generation_original_sdk_selection_authority");
  const c=doc.constraints;
  need(c?.containsCredentialValues===true&&c.containsCredentialDigests===false&&c.selectedOwnerCount===3
   &&c.containsUnselectedCredentials===false&&["productionChanged","providerLivenessVerified","oauthRefreshAttempted","productionCutover"]
    .every(k=>c[k]===false),"generation_private_capture_scope");
  need(Array.isArray(doc.sourceGenerations)&&doc.sourceGenerations.length===5
   &&same(doc.sourceGenerations.map(x=>x.agent).toSorted(),[...AGENTS].sort()),"generation_five_registered_agents");
  for(const b of doc.sourceGenerations)bundleShape(b,path.join(stateRoot,"agents",b.agent,"agent/openclaw-agent.sqlite"));
  bundleShape(doc.registryGeneration,path.join(stateRoot,"state/openclaw.sqlite"));
  typed(doc.configurationIdentity);
  need(typeof doc.configurationSha256==="string"&&/^[0-9a-f]{64}$/.test(doc.configurationSha256),"generation_private_configuration_binding");
  need(Array.isArray(doc.registeredMetadataFileBindings)&&doc.registeredMetadataFileBindings.length===145,
   "generation_exact_registered_metadata_count");
  need(Array.isArray(doc.ownerEntries)&&doc.ownerEntries.length===3
   &&new Set(doc.ownerEntries.map(x=>x.profileId)).size===3,"generation_exact_three_owner_entries");
  for(const entry of doc.ownerEntries)need(typeof entry.profileId==="string"&&entry.profileId.length>0&&entry.profileId.length<=240
   &&entry.ownerAgent==="main"&&entry.ownerAgentDir===path.join(stateRoot,"agents/main/agent")
   &&entry.actualProvider==="openai"&&entry.credential?.type==="oauth"&&entry.credential?.provider==="openai",
   "generation_actual_main_three_owner_scope");
  report.selectedRefreshObjectSeparation=assertSelectedRefreshObjectSeparation(doc.ownerEntries);
  const ids=doc.ownerEntries.map(x=>x.profileId),refs=doc.consumerBindings;
  need(Array.isArray(refs)&&refs.length===15&&new Set(refs.map(x=>x.scopeAgent+"\0"+x.profileId)).size===15,
   "generation_fifteen_unique_consumer_references");
  for(const agent of AGENTS){
   const rows=refs.filter(x=>x.scopeAgent===agent);
   need(rows.length===3&&same(rows.map(x=>x.actualSdkOrderRank).toSorted(),[0,1,2]),"generation_each_actual_sdk_order");
   for(const row of rows)need(ids.includes(row.profileId)&&row.scopeAgentDir===path.join(stateRoot,"agents",agent,"agent")
    &&row.ownerAgent==="main"&&row.ownerAgentDir===path.join(stateRoot,"agents/main/agent")
    &&row.persistedOwnerMatchesEffective===true&&row.selectedByActualSdkOrder===true&&row.configuredProfileId===false,
    "generation_actual_consumer_owner_binding");
  }
  const main=doc.sourceGenerations.find(x=>x.agent==="main"),base=path.join(stateRoot,"agents/main/agent/openclaw-agent.sqlite");
  heldMain=trackedOpen(base,io.constants.O_RDONLY|io.constants.O_NOFOLLOW|io.constants.O_NONBLOCK);
  regular(io.fstatSync(heldMain.fd,{bigint:true}),true);
  need(same(full(io.fstatSync(heldMain.fd,{bigint:true})),main.sourceIdentities[base])
   &&same(full(io.lstatSync(base,{bigint:true})),main.sourceIdentities[base]),"generation_original_main_inode_held");
 }catch(error){
  failed=true;closed=true;retireGenerationDescriptorsOnce(fds,closeOne,report);
  report.finalPhase="construction-failed";report.observationFailed=true;
  report.closedDuringConstructionFailure=true;throw error;
 }
 const mainBase=path.join(stateRoot,"agents/main/agent/openclaw-agent.sqlite");
 const originalMain=doc.sourceGenerations.find(x=>x.agent==="main");
 const mainFixed=originalMain.sourceIdentities[mainBase].slice(0,6);
 function mainLifecycle(previous,allowDisappearance){
  within();const current={};
  const held=io.fstatSync(heldMain.fd,{bigint:true}),named=io.lstatSync(mainBase,{bigint:true});
  regular(held,true);regular(named,true);
  need(same(full(held).slice(0,6),mainFixed)&&same(full(named).slice(0,6),mainFixed),
   "generation_same_held_main_database_identity");
  for(const filename of [mainBase,mainBase+"-wal",mainBase+"-shm"]){
   try{
    const s=io.lstatSync(filename,{bigint:true});regular(s,true);const id=full(s);current[filename]=id;
    if(previous[filename])need(same(id.slice(0,6),previous[filename].slice(0,6)),
     "generation_existing_main_namespace_identity_changed");
   }catch(error){
    if(error.code!=="ENOENT")throw error;
    need(filename!==mainBase&&(!previous[filename]||allowDisappearance),"generation_main_namespace_unexpected_disappearance");
   }
  }
  absent(mainBase+"-journal");
  if(current[mainBase+"-wal"]&&BigInt(current[mainBase+"-wal"][6])>0n)
   need(Boolean(current[mainBase+"-shm"]),"generation_postwrite_nonempty_wal_requires_shm");
  return current;
 }
 function observe(label,ownMain=false){
  within();need(++observations<=64,"generation_finite_observation_count");
  const started=clock(),fenceUntil=started+45000000000n<until?started+45000000000n:until;
  const bounded=()=>need(clock()<fenceUntil,"generation_observation_original_45_seconds");
  bounded();need(same(read(capsulePath,1048576,true,expectedCapsuleIdentity),originalCapsule),"generation_same_private_capsule_bytes");
  for(const bundle of doc.sourceGenerations){bounded();if(ownMain&&bundle.agent==="main")continue;
   exactBundle(bundle,path.join(stateRoot,"agents",bundle.agent,"agent/openclaw-agent.sqlite"));}
  exactBundle(doc.registryGeneration,path.join(stateRoot,"state/openclaw.sqlite"));
  need(sha(read(path.join(stateRoot,"openclaw.json"),1048576,true,doc.configurationIdentity))===doc.configurationSha256,
   "generation_private_configuration_whole_bytes_exact");
  for(const item of doc.registeredMetadataFileBindings){
   bounded();need(item&&same(Object.keys(item).sort(),["identity","nominal","path","sha256"])
    &&absolute(item.nominal)&&absolute(item.path)&&typeof item.sha256==="string"&&/^[0-9a-f]{64}$/.test(item.sha256),
    "generation_registered_metadata_binding_shape");
   need(io.realpathSync(item.nominal)===item.path,"generation_registered_metadata_alias_bound");
   need(sha(read(item.path,2*1048576,false,typed(item.identity)))===item.sha256
    &&io.realpathSync(item.nominal)===item.path,"generation_registered_metadata_whole_bytes_exact");
  }
  if(checkSdkSources)for(const [relative,pin]of Object.entries(SDK_SOURCE_PINS)){
   bounded();need(sha(read(path.join(SDK,relative),2*1048576))===pin,"generation_actual_sdk_source_pin");
  }
  bounded();within();
  report.observations.push({label,allOtherFourAgentFull9Exact:true,currentRegistryFull9Exact:true,
   currentConfigurationExact:true,registeredMetadataFilesExact:145,
   originalMainFull9Required:!ownMain,ownMainSqliteLifecycleWindow:ownMain,
   elapsedMs:Number((clock()-started)/1000000n)});
 }
 function guarded(action){try{return action();}catch(error){failed=true;throw error;}}
 return Object.freeze({
  profileIds:Object.freeze(doc.ownerEntries.map(x=>x.profileId)),
  source:Object.freeze({
   async observe({ordinal,until:requiredUntil}){return guarded(()=>{
    need(phase==="exact"&&observedToken===null&&requiredUntil===until&&Number.isInteger(ordinal)&&ordinal>=0&&ordinal<3,
     "generation_one_original_selected_ordinal");observe("source-observe");
    observedToken=Object.freeze({ordinal,credential:structuredClone(doc.ownerEntries[ordinal].credential)});
    return observedToken;
   });},
   verify(observed,label){return guarded(()=>{
    need(phase==="exact"&&observed===observedToken&&observed&&Number.isInteger(observed.ordinal)&&typeof label==="string"
     &&same(observed.credential,doc.ownerEntries[observed.ordinal].credential),
     "generation_old_full9_only_before_own_write");observe(label);
   });}
  }),
  admit(stage,databasePath,receipt){return guarded(()=>{
   need(databasePath===mainBase,"generation_only_selected_main_database");
   if(stage==="before-read"){
    need(phase==="exact"&&!readonlyBefore,"generation_read_before_once");readonlyBefore=true;observe(stage);
   }else if(stage==="after-read"){
    need(phase==="exact"&&readonlyBefore&&!readonlyAfter&&receipt?.openedConnections===1
     &&receipt.closeAttempts===1&&receipt.knownClosedConnections===1
     &&receipt.readonlyTransactionBegins===1&&receipt.readonlyTransactionEnds===1,
     "generation_read_after_known_original_closure");readonlyAfter=true;observe(stage);
   }else if(stage==="before-write-open"){
    need(phase==="exact"&&readonlyAfter,"generation_write_after_exact_read");observe(stage);phase="write-admitted";
   }else if(stage==="before-begin"){
    need(phase==="write-admitted"&&receipt?.openedConnections===1&&receipt.closeAttempts===0
     &&receipt.beginDispatches===0&&receipt.writeDispatches===0,"generation_original_rw_handle_before_begin");
    mainBeforeBegin=mainLifecycle(originalMain.sourceIdentities,false);observe(stage,true);phase="original-rw";
    report.ownSqliteWindowEntered=true;report.newGenerationCaptureRequiredAfterWrite=true;
   }else if(stage==="after-commit"){
    need(phase==="original-rw"&&receipt?.commitKnown===true&&receipt.commitDispatches===1
     &&receipt.writeDispatches===1&&receipt.inTransactionFullReadback===true
     &&receipt.openedConnections===1&&receipt.closeAttempts===1&&receipt.knownClosedConnections===1,
     "generation_known_original_commit_and_rw_close");
    mainAfterCommit=mainLifecycle(mainBeforeBegin,true);observe(stage,true);phase="commit-known";
    report.knownOriginalCommitObserved=true;
   }else if(stage==="after-readback"){
    need(phase==="commit-known"&&receipt?.commitKnown===true&&receipt.openedConnections===2
     &&receipt.closeAttempts===2&&receipt.knownClosedConnections===2
     &&receipt.readonlyTransactionBegins===1&&receipt.readonlyTransactionEnds===1,
     "generation_original_independent_readback_handles_closed");
    mainLifecycle(mainAfterCommit,true);observe(stage,true);phase="readback-known";
    report.independentReadbackObserved=true;
   }else throw new GenerationRefused("generation_only_original_raw_adapter_stage");
  });},
  close(){
   need(!closed,"generation_context_close_once");closed=true;
   retireGenerationDescriptorsOnce(fds,closeOne,report);
   report.finalPhase=phase;report.observationFailed=failed;
   need(report.allOwnedDescriptorsClosedOnce,"generation_all_descriptors_closed_once");
  }
 });
}
