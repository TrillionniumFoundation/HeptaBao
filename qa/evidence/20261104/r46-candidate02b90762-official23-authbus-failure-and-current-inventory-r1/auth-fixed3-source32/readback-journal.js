/* SOURCE ONLY: native-call archival substitute proposed for the local outage.
 * Requires pure_helpers.js plus git_archive_once.js in the same V8 evaluation.
 * No function below is invoked by loading this file. Root exact GO is separate.
 * No loop starts/retries a native call; all status/page steps are explicit.
 * Every original SDK is store'd, serialized, Git-created once and whole-read
 * before isError or native text is inspected.
 */
const GF_SLOT = "owner_authbus_home_r3_fixed_readback_gitfirst_r1";
const GF_READBACK_PLAN = {
  "schema": "heptabao.mac-home-r3-fixed-three-target-readback.v1",
  "host": "mac",
  "oldSlot": "owner_authbus_current_home_inert_gitfirst_r3",
  "newSlot": "owner_authbus_home_r3_fixed_readback_gitfirst_r1",
  "originalState": {
    "blob": "d087853e217e00f48e676fdd17e91a97d814cb82",
    "bytes": 927251,
    "sha256": "5e171021ed9a14dde7e54ffebc47011f2dedf97ad4afc84fba1876bb27c229f9"
  },
  "originalJob": "1a1b19aef7b-fc05-79d3",
  "originalGo": {
    "blob": "b2fd06b25b4131e542df9ad539cc8022c1ca396a",
    "bytes": 4967,
    "sha256": "2fb8a2be027d8efc0d783d114dfde2d74ca1e4b3ca607021f4f27d704faac88d"
  },
  "sourcePacket": "1b9f6f07249d0757ac0efa0227827e834a750260",
  "actualPacket": "7ca43a7e2a81d89e377cb00e38ead927c896d8dc",
  "finalStdout": {
    "blob": "0c1ac73af42e57c324be188a0d162bc2fd72003c",
    "bytes": 20680,
    "sha256": "0180bc98a766e41d357084dc957446906d3ac7afe8301f27346151138b57d151"
  },
  "authority": {
    "blob": "3dd7eb3a01bfbba19e37e1dc88d999f091bd0b19",
    "bytes": 733,
    "sha256": "5d6a0d14560141f7f449427f44180b561190cfadb5267fa754117dba853a5fa6"
  },
  "release": {
    "blob": "8d381debb6aa2336dfa369dfa2fbf2938a9eeb4a",
    "bytes": 10571,
    "sha256": "5b4b3616d7ec0022955a0087417d3435ac8a0cd6a0ce0a9f0993edd963c66dd9"
  },
  "targets": [
    {
      "ordinal": 1,
      "id": "outer",
      "path": "/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-home-launch-r3/qa/mac_current_outer_wal_r1.py",
      "bytes": 73918,
      "sha256": "7f3bec1e572b624844fe5ba477dea895a2fcd94d6c9e4a88b5001f4d957a05d0",
      "stageFull9": [
        "16777244",
        "72739433",
        "501",
        "20",
        "33152",
        "1",
        "73918",
        "1793981090642500588",
        "1793981090642506588"
      ],
      "sourcePin": {
        "blob": "6952e205d0cb50f2066c0d2bf56a567239aa8a1e",
        "bytes": 73918,
        "sha256": "7f3bec1e572b624844fe5ba477dea895a2fcd94d6c9e4a88b5001f4d957a05d0"
      },
      "bodyChunks": [
        65536,
        8382
      ]
    },
    {
      "ordinal": 2,
      "id": "candidate",
      "path": "/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-home-launch-r3/candidate-current-manager-wal-r1.public.json",
      "bytes": 7499,
      "sha256": "2ca16e7421d9cfba8802029e6125a2efbdae39ac0a6a52ef1962fca864871d81",
      "stageFull9": [
        "16777244",
        "72739447",
        "501",
        "20",
        "33152",
        "1",
        "7499",
        "1793981090651310355",
        "1793981090651318729"
      ],
      "sourcePin": {
        "blob": "c5a520313563ec821c1b80d49249a8cef1573709",
        "bytes": 7499,
        "sha256": "2ca16e7421d9cfba8802029e6125a2efbdae39ac0a6a52ef1962fca864871d81"
      },
      "bodyChunks": [
        7499
      ]
    },
    {
      "ordinal": 3,
      "id": "receipt",
      "path": "/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-home-launch-r3/inert-registry-wal-4e808-result.public.json",
      "bytes": 15237,
      "sha256": "d64535852bd697b0fd8f1cf314621d50236c0f398c068f8f4e276d480a1eedd3",
      "stageFull9": [
        "16777244",
        "72739455",
        "501",
        "20",
        "33152",
        "1",
        "15237",
        "1793981090656143173",
        "1793981090656148839"
      ],
      "sourcePin": null,
      "bodyChunks": [
        15237
      ]
    }
  ],
  "metadataRequests": [
    "{\n  \"idempotency_key\": \"heptabao-mac-home-r3-readback-0180bc98-info-01\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"mac\",\n      \"path\": \"/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-home-launch-r3/qa/mac_current_outer_wal_r1.py\"\n    }\n  }\n}\n",
    "{\n  \"idempotency_key\": \"heptabao-mac-home-r3-readback-0180bc98-info-02\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"mac\",\n      \"path\": \"/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-home-launch-r3/candidate-current-manager-wal-r1.public.json\"\n    }\n  }\n}\n",
    "{\n  \"idempotency_key\": \"heptabao-mac-home-r3-readback-0180bc98-info-03\",\n  \"operation\": {\n    \"tool\": \"file_info\",\n    \"arguments\": {\n      \"host\": \"mac\",\n      \"path\": \"/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-home-launch-r3/inert-registry-wal-4e808-result.public.json\"\n    }\n  }\n}\n"
  ],
  "keyPrefix": "heptabao-mac-home-r3-readback-0180bc98-",
  "metadataOperations": 3,
  "conditionalBodyOperations": 4,
  "bodyTotalBytes": 96654,
  "bodyChunkMaximum": 65536,
  "immutablePageMaximum": 8192,
  "immutablePayloadMaximum": 1048576,
  "metadataHashCostIsSeparate": true,
  "maxStatusesPerOperation": 8,
  "metadataSubmitted": 0,
  "bodySubmitted": 0,
  "runtimeSubmitted": 0,
  "readThenExecAtomicityClaim": false,
  "old952f964cScopesNotInherited": true,
  "oldR1PartialUnchanged": true,
  "actualRootQualification": null,
  "actualRootQualificationPacket": null,
  "actualRootQualificationPendingThisScopeGO": true,
  "oldReadbackBodyBytesRemainConsumed": 96654,
  "newAdditionalBodyBytes": 96654,
  "twoReadbackScopesCumulativeBodyBytes": 193308
};

/* Pure fixed-plan validation and body derivation. No tool, import, Native, SDK, file or process invocation. */
function validateFixedReadbackInfo(plan,index,v){
 const need=(x,c)=>{if(!x)throw Error(c);};
 need(Number.isSafeInteger(index)&&index>=0&&index<3,"fixed_info_ordinal");
 const t=plan.targets[index];
 need(v&&v.path===t.path&&v.size===t.bytes&&v.sha256===t.sha256,"actual_fixed_info_path_size_sha");
 need(v.mode===384&&v.metadata?.mode===384&&v.metadata.uid===501&&v.metadata.gid===20
      &&v.metadata.link_count===1&&v.metadata.metadata_platform==="darwin","actual_regular_0600_owner_single_link");
 need(typeof v.version==="string"&&/^[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9]+$/.test(v.version),"actual_version_opaque_decimal_shape");
 const z=v.version.split(":");
 need(z[2]===String(v.size),"version_size_agrees");
 const full9=[z[0],z[1],String(v.metadata.uid),String(v.metadata.gid),String(32768+v.mode),
              String(v.metadata.link_count),z[2],z[3],z[4]];
 need(JSON.stringify(full9)===JSON.stringify(t.stageFull9),"actual_full9_matches_final_inert_observation");
 return {ordinal:index+1,path:v.path,bytes:v.size,sha256:v.sha256,version:v.version,full9,
  regularFileTypeSource:"file_info rejects symlinks and non-regular targets; mode is permission bits"};
}

function deriveFixedReadbackBodies(plan,infos){
 const need=(x,c)=>{if(!x)throw Error(c);};
 need(Array.isArray(infos)&&infos.length===3,"all_three_original_infos_required");
 const validated=infos.map((v,i)=>validateFixedReadbackInfo(plan,i,v));
 const requests=[];let total=0;
 for(let i=0;i<3;i++){
  const t=plan.targets[i],m=validated[i];let offset=0;
  for(const limit of t.bodyChunks){
   need(Number.isSafeInteger(limit)&&limit>0&&limit<=65536&&offset+limit<=m.bytes,"fixed_body_chunk_bound");
   const request={idempotency_key:plan.keyPrefix+"body-"+String(requests.length+1).padStart(2,"0"),
    operation:{tool:"binary_read",arguments:{host:"mac",path:m.path,offset,limit,expected_version:infos[i].version}}};
   const raw=JSON.stringify(request,null,2)+"\n";
   requests.push({ordinal:requests.length+1,targetOrdinal:i+1,target:t.id,requestRaw:raw,requestPin:gitBlobMeta(raw)});
   offset+=limit;total+=limit;
  }
  need(offset===m.bytes,"fixed_complete_target_extent");
 }
 need(requests.length===4&&total===plan.bodyTotalBytes&&total===96654,"exact_four_body_total");
 return {metadata:validated,requests,totalBytes:total,bodyRequestVersionsComeFromActualInfos:true,
         NativeCalls:0,runtimeGO:false};
}

function validateFixedReadbackBody(plan,infos,partIndex,q,v,previousParts){
 const need=(x,c)=>{if(!x)throw Error(c);};
 const derived=deriveFixedReadbackBodies(plan,infos),e=derived.requests[partIndex];
 need(e&&JSON.stringify(q)===JSON.stringify(JSON.parse(e.requestRaw)),"exact_derived_body_arguments");
 const a=q.operation.arguments,t=plan.targets[e.targetOrdinal-1];
 need(v&&v.path===a.path&&v.version===a.expected_version&&v.size===t.bytes&&v.offset===a.offset,
      "actual_binary_path_version_size_offset");
 need(typeof v.data_base64==="string"&&typeof v.chunk_sha256==="string","actual_binary_encoding_and_hash");
 const bytes=unb64(v.data_base64);
 need(bytes.length===a.limit&&v.next_offset===a.offset+bytes.length&&v.eof===(v.next_offset===t.bytes),
      "exact_binary_length_next_eof");
 need(sha256Latin1(byteString(bytes))===v.chunk_sha256,"actual_chunk_sha256");
 const part={target:e.target,targetOrdinal:e.targetOrdinal,path:v.path,version:v.version,
  offset:v.offset,next_offset:v.next_offset,eof:v.eof,base64:v.data_base64,bytes:bytes.length,
  chunkSha256:v.chunk_sha256};
 let whole=null;
 if(v.eof){
  const selected=previousParts.filter(p=>p.target===e.target).concat(part);
  let all=[],next=0;
  for(const p of selected){need(p.offset===next&&p.version===v.version,"same_version_contiguous_whole");all=all.concat(unb64(p.base64));next=p.next_offset;}
  need(next===t.bytes&&all.length===t.bytes,"whole_file_exact_extent");
  const raw=utf8Text(all),pin=gitBlobMeta(raw);
  need(pin.bytes===t.bytes&&pin.sha256===t.sha256,"whole_file_matches_stage_sha256");
  if(t.sourcePin)need(pin.blob===t.sourcePin.blob,"whole_file_matches_frozen_public_source_blob");
  whole={target:e.target,path:t.path,version:v.version,full9:derived.metadata[e.targetOrdinal-1].full9,
   raw,pin,independentOriginalBinaryRead:true};
 }
 return {part,whole};
}

const GF_REQUEST = {blob:"a9b40fb0c03bbda404e8bdbbef2e398e34c2f8af",
 bytes:875570,sha256:"c85ff3e246279e367039128a59f0b2a894bda727577e0d2de317a972696ca9de"};

function gfNeed(value, code) { if(!value) throw new Error(code); }
function gfMetaEquals(raw,pin) {
 const actual=gitBlobMeta(raw);
 return actual.blob===pin.blob && actual.bytes===pin.bytes && actual.sha256===pin.sha256;
}
function gfState() {
 const s=load(GF_SLOT);
 gfNeed(s && s.rootGoWhole===true, "root_go_not_initialized");
 return s;
}
function gfSave(s) { store(GF_SLOT,s); }
function gfIntegerText(value) {
 if(Number.isSafeInteger(value))return String(value);
 gfNeed(value && Object.keys(value).join(",")==="$exactInteger"
   && /^-?[0-9]+$/.test(value.$exactInteger),"lossless_integer_token");
 return value.$exactInteger;
}
function gfInitializeOnlyAfterRootGO({goRaw,goPin,goWholeReadback}){
 gfNeed(load(GF_SLOT)===undefined,"existing_or_armed_readback_context_must_be_recovered");
 gfNeed(goWholeReadback===true&&gfMetaEquals(goRaw,goPin),"exact_whole_root_go");
 const old=load(GF_READBACK_PLAN.oldSlot),oldRaw=JSON.stringify(old,null,2)+"\n";
 gfNeed(old&&gfMetaEquals(oldRaw,GF_READBACK_PLAN.originalState),"exact_closed_inert_context_unchanged");
 gfNeed(old.job===GF_READBACK_PLAN.originalJob&&old.startCalled===true&&!old.paused
  &&old.pending===null&&old.activeObserver===null&&old.nativeCallInFlight===false
  &&old.completedObservers.length===3&&old.completedObservers.every(x=>x.completedInactive===true),
  "qualified_original_inert_closed_before_readback");
 // The old context is neither mutated nor reinitialized. No process_start is allowed here.
 store(GF_SLOT,{rootGoWhole:true,goRaw,goPin,digest:old.digest,fingerprint:old.fingerprint,
  job:old.job,startCalled:true,inheritedOriginalStart:true,processStartsInThisScope:0,
  originalInertState:GF_READBACK_PLAN.originalState,readbackRequests:GF_READBACK_PLAN.metadataRequests.slice(),
  readbackInfos:[],readbackParts:[],readbackWholeFiles:[],bodyReturnAccounting:[],
  pending:null,activeObserver:null,nativeCallInFlight:false,paused:false,calls:{},
  completedObservers:[],nextStdout:old.nextStdout,nextStderr:old.nextStderr,
  localJournalAvailable:false,gitFirstExplicitlyRequiredByThisRootGO:true});
}
function gfValidateRequest(s,kind,q,raw) {
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null,"single_call_boundary");
 if(kind==="process_start") {
  throw new Error("readback_scope_never_process_start");
 } else if(kind==="operation_start") {
  const index=s.completedObservers.length,expected=s.readbackRequests[index];
  gfNeed(s.job===GF_READBACK_PLAN.originalJob&&s.activeObserver===null
    &&index<7&&typeof expected==="string"&&raw===expected,
    "one_fixed_sequential_metadata_or_actual_version_body_request");
  const expectedTool=index<3?"file_info":"binary_read";
  gfNeed(q.operation?.tool===expectedTool&&q.operation.arguments.host==="mac",
    "closed_file_read_tool_set");
 } else if(kind==="operation_status") {
  gfNeed(Object.values(s.calls).filter(x=>x.kind==="operation_status"&&x.called===true
    &&JSON.parse(x.requestRaw).operation_id===s.activeObserver?.id).length<8,"fixed_status_call_bound");
  gfNeed(s.activeObserver && !s.activeObserver.futureClosed
   && Object.keys(q).join(",")==="operation_id"
   && q.operation_id===s.activeObserver.id,"same_live_original_operation_status");
 } else if(kind==="operation_result") {
  gfNeed(s.activeObserver?.futureClosed===true
   && Object.keys(q).sort().join(",")==="limit,offset,operation_id"
   && q.operation_id===s.activeObserver.id && q.limit===8192
   && q.offset===s.activeObserver.nextPageOffset && !s.activeObserver.eof,
   "same_closed_original_operation_next_page");
 } else throw new Error("closed_native_tool_set");
}
async function gfPrepareOne({callKey,kind,requestRaw}) {
 const s=gfState();
 gfNeed(/^[a-z0-9][a-z0-9-]{0,70}$/.test(callKey) && !s.calls[callKey],"fresh_call_record");
 const q=JSON.parse(requestRaw); // Public exact request, no native response.
 gfValidateRequest(s,kind,q,requestRaw);
 const requestPin=gitBlobMeta(requestRaw);
 const intent={schema:"heptabao.gitfirst.fixed-native-call-intent.r1",
  callKey,kind,request:requestPin,rootGo:s.goPin,originalJob:s.job,
  originalOperation:s.activeObserver?.id??null,maximumNativeCalls:1,
  nativeNotYetCalled:true,lossOfAcknowledgmentNeverGrantsReplay:true,
  localFirstExplicitlyReplacedByExactRootGO:true};
 const armed={...intent,schema:"heptabao.gitfirst.fixed-native-call-armed.r1",
  mayHaveDispatchedAfterThisCheckpoint:true,
  recovery:"Read exact original job/operation only; absence of later ACK is UNKNOWN."};
 s.pending=callKey;
 s.calls[callKey]={kind,requestRaw,requestPin,phase:"arming",called:false};
 gfSave(s);
 try {
  const archive=await archiveFlatPublicTextsOnce({
   key:"gfa-"+callKey,repository:"TrillionniumFoundation/HeptaBao",
   texts:{"request.json":requestRaw,"intent.json":JSON.stringify(intent,null,2)+"\n",
          "armed.json":JSON.stringify(armed,null,2)+"\n"}});
  s.calls[callKey].armed=archive;s.calls[callKey].phase="armed_whole";gfSave(s);
  return {callKey,armedTree:archive.tree,request:requestPin,nativeCalled:false};
 } catch(error) {
  s.paused=true;s.calls[callKey].archiveFailure=String(error);gfSave(s);throw error;
 }
}
async function gfInvokePreparedOnce(callKey) {
 const s=gfState(),c=s.calls[callKey];
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===callKey
  && c?.phase==="armed_whole" && c.armed?.whole===true && !c.called,
  "completed_external_arm_before_once_call");
 const q=JSON.parse(c.requestRaw);
 gfNeed(gfMetaEquals(c.requestRaw,c.requestPin),"armed_request_unchanged");
 c.called=true;c.phase="native_call_entered";s.nativeCallInFlight=true;
 if(c.kind==="process_start")s.startCalled=true;
 gfSave(s); // No await or second dispatch between this marker and the one call.
 let sdk;
 try {
  if(c.kind==="process_start")sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_process_start(q);
  else if(c.kind==="operation_start")sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_start(q);
  else if(c.kind==="operation_status")sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_status(q);
  else if(c.kind==="operation_result")sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_result(q);
  else throw new Error("unreachable_closed_dispatch_kind");
 } catch(error) {
  const record={name:error.name,message:String(error.message),nativeCallMayHaveCompleted:true,
    originalRequest:c.requestPin,replayAllowed:false};
  store(GF_SLOT+":native_exception:"+callKey,record); // Preserve before any Git operation.
  s.nativeCallInFlight=false;s.paused=true;c.phase="transport_unknown";gfSave(s);
  try {c.exceptionArchive=await archiveFlatPublicTextsOnce({
   key:"gfx-"+callKey,repository:"TrillionniumFoundation/HeptaBao",
   texts:{"transport-exception.json":JSON.stringify(record,null,2)+"\n"}});gfSave(s);}
  catch(archiveError){store(GF_SLOT+":exception_archive_error:"+callKey,String(archiveError));}
  throw error;
 }
 store(GF_SLOT+":original_sdk:"+callKey,sdk); // First operation on the returned SDK.
 recordGitSDKImmutable(GF_SLOT+":native:"+callKey,"original_return",sdk);
 s.nativeCallInFlight=false;c.phase="sdk_returned_uninterpreted";gfSave(s);
 const raw=JSON.stringify(sdk,null,2)+"\n";
 store(GF_SLOT+":original_sdk_raw:"+callKey,raw);
 c.sdkPin=gitBlobMeta(raw);gfSave(s);
 try {
  c.sdkArchive=await archiveFlatPublicTextsOnce({
   key:"gfs-"+callKey,repository:"TrillionniumFoundation/HeptaBao",
   texts:{"original.sdk.json":raw}});
  c.phase="sdk_whole_uninterpreted";gfSave(s);
  return {callKey,sdk:c.sdkPin,tree:c.sdkArchive.tree,interpreted:false};
 } catch(error) {
  // The native response remains in store. Recover only the identical Git objects.
  s.paused=true;c.phase="sdk_git_archive_unresolved";c.archiveFailure=String(error);
  gfSave(s);throw error;
 }
}
function gfAcceptArchivedSDK(callKey) {
 const s=gfState(),c=s.calls[callKey];
 gfNeed(!s.paused && s.pending===callKey && !s.nativeCallInFlight
  && c?.phase==="sdk_whole_uninterpreted" && c.sdkArchive?.whole===true,
  "SDK_whole_before_isError");
 const raw=load(GF_SLOT+":original_sdk_raw:"+callKey);
 gfNeed(gfMetaEquals(raw,c.sdkPin),"whole_SDK_unchanged");
 const sdk=JSON.parse(raw); // Only now interpret isError/shape/native contents.
 try {
  gfNeed(sdk.isError!==true,"native_tool_error_preserved_stop");
  gfNeed(sdk.content?.length===1 && sdk.content[0].type==="text",
         "single_original_native_text");
  const nativeRaw=sdk.content[0].text;
  store(GF_SLOT+":native_raw:"+callKey,nativeRaw);
  const v=parseLosslessIntegers(nativeRaw),q=JSON.parse(c.requestRaw);
  if(c.kind==="process_start") {
   gfNeed(v.audit_recorded===true && v.local_record_pending===false && v.reused===false
    && v.launch?.ok===true && v.job?.host==="mac" && v.job.execution_mode==="operator"
    && v.job.idempotency_key===q.idempotency_key && v.job.executable===q.executable
    && v.job.cwd===q.cwd && JSON.stringify(v.job.args)===JSON.stringify(q.args)
    && v.job.request_digest===s.digest && gfIntegerText(v.job.request_fingerprint)===s.fingerprint
    && /^[a-z0-9-]{1,100}$/.test(v.job.id),"exact_unique_native_start_binding");
   s.job=v.job.id;
  } else if(c.kind==="operation_start") {
   gfNeed(/^[a-f0-9]{64}$/.test(v.operation_id) && v.tool_name===q.operation.tool
     && v.reused===false && v.automatic_retry===false,"original_observer_admission");
   s.activeObserver={id:v.operation_id,request:q,tool:v.tool_name,futureClosed:false,
    nextPageOffset:0,eof:false,pages:[],total:null,digest:null};
  } else if(c.kind==="operation_status") {
   const a=s.activeObserver;
   gfNeed(v.operation_id===a.id && v.tool_name===a.tool && v.automatic_retry===false,
          "same_original_status");
   if(v.async_state==="completed") {
    gfNeed(v.owned_future_active===false && v.result_state==="stored_observed"
      && v.payload_available===true,"completed_original_payload_available");
    a.futureClosed=true;
   } else gfNeed(v.async_state==="running" || v.async_state==="queued",
                 "unexpected_original_status_stop");
  } else {
   const a=s.activeObserver;
   gfNeed(v.operation_id===a.id && v.offset===q.offset && v.immutable_snapshot===true
    && v.payload_kind==="native_result"
    && v.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization"
    && Number.isSafeInteger(v.total_bytes) && v.total_bytes>=0 && v.total_bytes<=1048576
    && /^[a-f0-9]{64}$/.test(v.result_sha256),"exact_original_immutable_payload");
   const b=unb64(v.data_base64);
   gfNeed(b.length<=8192 && v.next_offset===q.offset+b.length
     && v.next_offset<=v.total_bytes && v.eof===(v.next_offset===v.total_bytes)
     && (b.length>0||v.eof),"exact_original_page_extent");
   gfNeed(a.total===null || (a.total===v.total_bytes && a.digest===v.result_sha256),
          "one_original_payload_identity");
   a.total=v.total_bytes;a.digest=v.result_sha256;
   a.pages.push({offset:q.offset,next:v.next_offset,base64:v.data_base64,
                 originalSDK:c.sdkPin,nativeText:gitBlobMeta(nativeRaw)});
   a.nextPageOffset=v.next_offset;a.eof=v.eof;
  }
  c.nativePin=gitBlobMeta(nativeRaw);c.phase="accepted";
  s.pending=null;gfSave(s);
  return {callKey,nativeRaw,value:v,job:s.job,operation:s.activeObserver?.id??null,
          nativeCallInFlight:false};
 } catch(error) {
  s.paused=true;c.phase="native_interpretation_refused";c.interpretationFailure=String(error);
  gfSave(s);throw error;
 }
}
async function gfCloseOriginalObserver() {
 const s=gfState(),a=s.activeObserver;
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null
   && a?.futureClosed===true && a.eof,"closed_whole_original_observer_boundary");
 let bytes=[],next=0;
 for(const p of a.pages){gfNeed(p.offset===next,"page_continuity");bytes=bytes.concat(unb64(p.base64));next=p.next;}
 gfNeed(next===a.total,"complete_original_payload_length");
 const raw=utf8Text(bytes),pin=gitBlobMeta(raw);
 gfNeed(pin.bytes===a.total && pin.sha256===a.digest,"complete_original_payload_hash");
 // Persist the full immutable envelope before interpreting original SDK success.
 const archiveKey="gfc-"+a.id;
 let archive;
 try {
  archive=await archiveFlatPublicTextsOnce({key:archiveKey,repository:"TrillionniumFoundation/HeptaBao",
   texts:{"payload.original.json":raw}});
 } catch(error) {
  s.paused=true;s.originalPayloadArchiveFailure=String(error);gfSave(s);throw error;
 }
 const p=parseLosslessIntegers(raw);
 try {
  gfNeed(p.resultType==="complete" && p.isError===false
    && p.content?.length===1 && p.content[0].type==="text","original_native_result_success");
  const nativeRaw=p.content[0].text,v=parseLosslessIntegers(nativeRaw);
  const index=s.completedObservers.length;
  gfNeed(index<7&&JSON.stringify(a.request)===JSON.stringify(JSON.parse(s.readbackRequests[index])),
         "closed_original_exact_readback_request");
  if(a.tool==="file_info") {
   validateFixedReadbackInfo(GF_READBACK_PLAN,index,v);
   s.readbackInfos.push(v);
   if(s.readbackInfos.length===3) {
    const derived=deriveFixedReadbackBodies(GF_READBACK_PLAN,s.readbackInfos);
    s.readbackRequests=s.readbackRequests.concat(derived.requests.map(x=>x.requestRaw));
    s.derivedBodyPlan=derived;
   }
  } else {
   gfNeed(a.tool==="binary_read"&&index>=3,"closed_original_binary_read_only");
   const accounting={ordinal:index-2,returnedEncodingObserved:typeof v.data_base64==="string",
                     bytes:null,byteCountUnknown:true};
   s.bodyReturnAccounting.push(accounting);gfSave(s);
   const returned=unb64(v.data_base64);
   accounting.bytes=returned.length;accounting.byteCountUnknown=false;gfSave(s);
   const result=validateFixedReadbackBody(GF_READBACK_PLAN,s.readbackInfos,index-3,a.request,v,s.readbackParts);
   s.readbackParts.push(result.part);
   if(result.whole)s.readbackWholeFiles.push(result.whole);
  }
  const original={id:a.id,tool:a.tool,payload:pin,payloadTree:archive.tree,
    nativeText:gitBlobMeta(nativeRaw),pages:a.pages.length,completedInactive:true};
  s.completedObservers.push(original);s.activeObserver=null;gfSave(s);
  store(GF_SLOT+":closed_native:"+a.id,nativeRaw);
  return {original,nativeRaw,value:v};
 } catch(error) {
  s.paused=true;gfSave(s);throw error;
 }
}
/* Recovery rule (not automatic):
 * If any Git mutation ACK is unclear, use its stored expectedTree/entries/texts
 * only for immutable Git GET and exact whole comparison. Never call create_tree
 * again. If a native ACK is unclear, keep the armed record UNKNOWN; never rerun
 * gfInvokePreparedOnce or create a new native key. Root directs same-ID/job reads.
 * A cache loss requires restoring the external armed/SDK objects and call map.
 * Initialization from an empty store must not replace such an earlier context.
 */


/* Git-only recovery, never a second mutation or native call. The caller retains
 * the original prepared-state map; it may inspect the returned completion and
 * request root review. This function does not unpause or dispatch anything. */
async function gfReconcileSameGitArchiveReadOnly(archiveKey) {
 const prefix="pure_git_once:"+archiveKey,prior=load(prefix);
 gfNeed(prior && prior.expectedTree && prior.entries && prior.texts,
        "original_git_admission_required_no_guessed_content");
 const treeSDK=await tools.mcp__codex_apps__github_fetch({
  url:"https://api.github.com/repos/TrillionniumFoundation/HeptaBao/git/trees/"
      +prior.expectedTree+"?recursive=1"});
 recordGitSDKImmutable(prefix,"recovery_tree",treeSDK);
 store(prefix+":recovery_tree_sdk",treeSDK);
 gfNeed(treeSDK.isError!==true,"original_expected_tree_not_observed");
 const treeText=treeSDK.structuredContent?.content;
 gfNeed(typeof treeText==="string","original_tree_text");
 const tree=JSON.parse(treeText);
 const audit=gitTreeAudit(tree);
 gfNeed(audit.root_sha===prior.expectedTree && audit.leaf_count===prior.entries.length,
        "original_expected_tree_complete");
 const expected=new Map(prior.entries.map(x=>[x.path,x]));
 gfNeed(tree.tree.filter(x=>x.type==="blob").every(x=>expected.get(x.path)?.blob===x.sha
   && x.mode==="100644"),"original_exact_tree_members");
 const verified=[];
 for(const x of prior.entries) {
  const sdk=await tools.mcp__codex_apps__github_fetch_blob({
   repository_full_name:"TrillionniumFoundation/HeptaBao",blob_sha:x.blob});
  recordGitSDKImmutable(prefix,"recovery_whole:"+x.path,sdk);
  store(prefix+":recovery_whole_sdk:"+x.path,sdk);
  gfNeed(sdk.isError!==true && typeof sdk.structuredContent?.content==="string",
         "original_blob_not_observed");
  const raw=sdk.structuredContent.content;
  gfNeed(raw===prior.texts[x.path] && gfMetaEquals(raw,x),"original_same_bytes_only");
  verified.push({...x,whole:true});
 }
 const record={tree:prior.expectedTree,entries:verified,count:verified.length,
  bytes:verified.reduce((a,x)=>a+x.bytes,0),whole:true,
  recoveryReadOnly:true,mutationRepeated:false,nativeCalled:false};
 store(prefix+":recovery_complete",record);
 return record;
}


/* The only invocation entry point. It always returns normally after retaining
 * failures, so a failed cell cannot roll back V8 state by an uncaught throw.
 * Internal functions may throw; they must only be invoked through gfRun.
 */
async function gfRun(action,args) {
 try {
  let value;
  if(action==="initialize")value=gfInitializeOnlyAfterRootGO(args);
  else if(action==="prepare")value=await gfPrepareOne(args);
  else if(action==="invoke")value=await gfInvokePreparedOnce(args.callKey);
  else if(action==="accept")value=gfAcceptArchivedSDK(args.callKey);
  else if(action==="close_observer")value=await gfCloseOriginalObserver();
  else if(action==="git_readonly_reconcile")value=await gfReconcileSameGitArchiveReadOnly(args.archiveKey);
  else throw new Error("closed_gfRun_action");
  return {ok:true,action,value:value===undefined?null:value};
 } catch(error) {
  const record={schema:"heptabao.gitfirst.outer-caught-failure.r1",action,
   name:error?.name??"Error",message:String(error?.message??error),
   automaticRetry:false,newAdmissionAllowed:false,returnedNormally:true};
  try {
   const state=load(GF_SLOT);
   if(state){state.paused=true;state.outerFailure=record;store(GF_SLOT,state);}
   const raw=JSON.stringify(record,null,2)+"\n",pin=gitBlobMeta(raw);
   const key="gitfirst-failure-by-blob:"+pin.blob,old=load(key);
   if(old===undefined)store(key,raw);
   const history=load(GF_SLOT+":outer_failures")||[];
   history.push({ordinal:history.length+1,pin,immutableStoreKey:key});
   store(GF_SLOT+":outer_failures",history);
   store(GF_SLOT+":latest_outer_failure",record);
   return {ok:false,action,failure:record,pin};
  } catch(recordError) {
   store(GF_SLOT+":last_resort_caught_failure",
      {record,recordError:String(recordError?.message??recordError),newAdmissionAllowed:false});
   return {ok:false,action,failure:record,recordingIncomplete:true};
  }
 }
}
