/* SOURCE ONLY: native-call archival substitute proposed for the local outage.
 * Requires pure_helpers.js plus git_archive_once.js in the same V8 evaluation.
 * No function below is invoked by loading this file. Root exact GO is separate.
 * No loop starts/retries a native call; all status/page steps are explicit.
 * Every original SDK is store'd, serialized, Git-created once and whole-read
 * before isError or native text is inspected.
 */
const GF_SLOT = "official271_x230_acl23_r2_body02_status_reconcile_r1";
const GF_ORIGINAL_SLOT = "official271_x230_acl23_oracle_gitfirst_r2";
const GF_ORIGINAL_PAUSED_STATE = {"blob":"652b0103388657f5515e30c077ce927c24b19cf2","bytes":454676,"sha256":"dd4a465e95e91c8aa23ddcde138d4541a52e79e7482297eb418bb89e16f83aa3"};
const GF_ORIGINAL_BODY_OPERATION = "6220e2762757d7afa1ba315c7beb2a985c59c147ac7cb3852aa17ba9c21c7a9e";
const GF_ORIGINAL_FAILED_STATUS_KEY = "official271-x230-acl23-r2-body02-status0";
const GF_ORIGINAL_FAILED_STATUS_SDK = {"blob":"0cede4881f37869cfd279b69b738c87eb62b4889","bytes":248,"sha256":"b85d625e0a8999ce34020675f0a2f8ba093e807dc725c16053a63c92fbbc9c70"};
const GF_RECONCILE_STATUS_REQUEST = {"blob":"182980da62d3a27a098c8fb974e6a68dd7926318","bytes":84,"sha256":"f99d18d13005ea9de9e2426fcc8fbce4e668450f52fdd726234aa3f8e4cc7317"};

const GF_ORIGINAL_BODY_REQUEST = {"blob":"3be4277978fa7422d4d70d4ca3239f91a7006ce6","bytes":331,"sha256":"917bfc19c6b300654f742555eccee4d5d8d1a6b60472da0d686e97a0432e0ae2"};
const GF_ORIGINAL_BODY_TARGET = {"path":"/home/qian/heptabao-official271-acl23-oracle-20261106-r2/result.public.json","bytes":651803,"sha256":"9048f3b5c854a190dadde86f5d7eec180c497313065bd70bd23a87124789a62d","version":"2053:2098461:651803:1793982810542000556:1793982810542000556","offset":131072,"limit":65536};

const GF_ORIGINAL_ADMIT_KEY = "official271-x230-acl23-r2-body02-admit";

function gfNeed(value, code) { if(!value) throw new Error(code); }
function gfMetaEquals(raw,pin) {
 const actual=gitBlobMeta(raw);
 return actual.blob===pin.blob && actual.bytes===pin.bytes && actual.sha256===pin.sha256;
}
function gfState() {
 const s=load(GF_SLOT);
 gfNeed(s && s.rootGoWhole===true, "root_go_not_initialized");
 gfNeed(gfMetaEquals(JSON.stringify(load(GF_ORIGINAL_SLOT),null,2)+"\n",GF_ORIGINAL_PAUSED_STATE),
        "original_paused_status_error_context_byte_identical");
 return s;
}
function gfSave(s) { store(GF_SLOT,s); }
function gfIntegerText(value) {
 if(Number.isSafeInteger(value))return String(value);
 gfNeed(value && Object.keys(value).join(",")==="$exactInteger"
   && /^-?[0-9]+$/.test(value.$exactInteger),"lossless_integer_token");
 return value.$exactInteger;
}
function gfInitializeOnlyAfterRootGO({goRaw,goPin,goWholeReadback,originalStateRaw}) {
 gfNeed(load(GF_SLOT)===undefined,"new_readonly_reconciliation_context_once");
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin),"whole_same_ID_reconciliation_GO");
 const g=JSON.parse(goRaw);
 gfNeed(g.authorization==="GO" && g.scope==="official271_r2_original_body02_same_id_status_reconciliation_only"
  && g.original_job==="1a1b1b4fbfa-fc05-7a60" && g.original_operation_id===GF_ORIGINAL_BODY_OPERATION
  && g.maximum_new_operation_status_calls===1 && g.original_operation_status_calls===1
  && g.maximum_combined_operation_status_calls===8 && g.maximum_operation_result_calls===128
  && g.maximum_operation_start_calls===0 && g.maximum_process_start_calls===0
  && g.immutable_page_bytes===16384 && g.maximum_payload_bytes===1048576
  && JSON.stringify(g.exact_status_request)===JSON.stringify(GF_RECONCILE_STATUS_REQUEST),
  "one_new_status_then_only_original_payload_if_closed");
 gfNeed(gfMetaEquals(originalStateRaw,GF_ORIGINAL_PAUSED_STATE)
  && JSON.stringify(load(GF_ORIGINAL_SLOT),null,2)+"\n"===originalStateRaw,"old_paused_context_whole_unchanged");
 const prior=JSON.parse(originalStateRaw),oldCall=prior.calls[GF_ORIGINAL_FAILED_STATUS_KEY],observer=prior.activeObserver;
 gfNeed(prior.paused===true && prior.pending===GF_ORIGINAL_FAILED_STATUS_KEY
  && prior.nativeCallInFlight===false && Object.keys(prior.calls).length===28
  && prior.completedObservers.length===5 && prior.job==="1a1b1b4fbfa-fc05-7a60"
  && prior.oracleReportBodyStarted===3 && prior.oracleReportBodyRanges.length===2
  && observer.id===GF_ORIGINAL_BODY_OPERATION && observer.tool==="binary_read"
  && observer.futureClosed===false && observer.nextPageOffset===0 && observer.pages.length===0
  && observer.eof===false
  && gfMetaEquals(prior.calls[GF_ORIGINAL_ADMIT_KEY].requestRaw,GF_ORIGINAL_BODY_REQUEST)
  && JSON.stringify(observer.request)===JSON.stringify(JSON.parse(prior.calls[GF_ORIGINAL_ADMIT_KEY].requestRaw))
  && oldCall.called===true && oldCall.phase==="native_interpretation_refused"
  && oldCall.sdkArchive?.whole===true
  && gfMetaEquals(load(GF_ORIGINAL_SLOT+":original_sdk_raw:"+GF_ORIGINAL_FAILED_STATUS_KEY),GF_ORIGINAL_FAILED_STATUS_SDK),
  "returned_original_BINARY_ACK_and_unknown_status_not_reset");
 gfNeed(Object.values(prior.calls).filter(c=>c.kind==="operation_status"
  && JSON.parse(c.requestRaw).operation_id===GF_ORIGINAL_BODY_OPERATION).length===1,
  "one_original_status_query_before_one_new_query");
 store(GF_SLOT,{rootGoWhole:true,goRaw,goPin,digest:null,fingerprint:null,
  job:prior.job,startCalled:false,pending:null,nativeCallInFlight:false,paused:false,
  calls:{},completedObservers:[],nextStdout:0,nextStderr:0,
  activeObserver:observer,reconcileStatusCalls:0,originalStatusCalls:1,
  originalPausedContext:{slot:GF_ORIGINAL_SLOT,state:GF_ORIGINAL_PAUSED_STATE,
   failedStatusKey:GF_ORIGINAL_FAILED_STATUS_KEY,failedStatusSDK:GF_ORIGINAL_FAILED_STATUS_SDK},
  onlyOriginalBodyRange:true,originalBodyRange:null,
  localJournalAvailable:false,gitFirstExplicitlyRequiredByThisRootGO:true});
}
function gfValidateRequest(s,kind,q,raw) {
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null,"single_call_boundary");
 if(kind==="operation_status") {
  gfNeed(s.reconcileStatusCalls===0 && s.originalStatusCalls===1 && s.originalStatusCalls+s.reconcileStatusCalls<8
   && s.activeObserver?.id===GF_ORIGINAL_BODY_OPERATION && !s.activeObserver.futureClosed
   && gfMetaEquals(raw,GF_RECONCILE_STATUS_REQUEST)
   && Object.keys(q).join(",")==="operation_id" && q.operation_id===GF_ORIGINAL_BODY_OPERATION,
   "one_new_readonly_status_for_same_returned_original_ID");
 } else if(kind==="operation_result") {
  gfNeed(s.reconcileStatusCalls===1 && s.activeObserver?.futureClosed===true
   && s.activeObserver.id===GF_ORIGINAL_BODY_OPERATION && !s.activeObserver.eof
   && s.activeObserver.pages.length<128 && Object.keys(q).sort().join(",")==="limit,offset,operation_id"
   && q.operation_id===GF_ORIGINAL_BODY_OPERATION && q.limit===16384
   && q.offset===s.activeObserver.nextPageOffset,"closed_original_immutable_next_page_only");
 } else throw new Error("only_same_ID_status_and_original_result_no_admission");
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
 if(c.kind==="operation_status")s.reconcileStatusCalls++;
 gfSave(s); // No await or second dispatch between this marker and the one call.
 let sdk;
 try {
  if(c.kind==="operation_status")sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_status(q);
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
  if(c.kind==="operation_status") {
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
   gfNeed(b.length<=16384 && v.next_offset===q.offset+b.length
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
  const t=GF_ORIGINAL_BODY_TARGET,asked=a.request.operation.arguments;
  gfNeed(a.id===GF_ORIGINAL_BODY_OPERATION && a.tool==="binary_read"
    && s.onlyOriginalBodyRange===true && s.originalBodyRange===null
    && s.reconcileStatusCalls===1 && s.originalStatusCalls===1
    && asked.host==="x230" && asked.path===t.path && asked.offset===t.offset
    && asked.limit===t.limit && asked.expected_version===t.version
    && v.path===t.path && v.version===t.version && v.size===t.bytes
    && v.offset===t.offset && v.next_offset===t.offset+t.limit
    && v.eof===(v.next_offset===t.bytes) && typeof v.data_base64==="string"
    && /^[a-f0-9]{64}$/.test(v.chunk_sha256),
    "same_original_body02_version_and_range");
  const bodyBytes=unb64(v.data_base64);
  gfNeed(bodyBytes.length===65536 && bodyBytes.length===t.limit
    && sha256Latin1(byteString(bodyBytes))===v.chunk_sha256,
    "whole_original_body02_chunk_SHA_no_report_semantic_parse");
  s.originalBodyRange={offset:t.offset,limit:t.limit,next:v.next_offset,
    chunkSHA256:v.chunk_sha256,base64:v.data_base64,originalOperation:a.id,
    originalPayload:pin,originalPayloadTree:archive.tree};
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
