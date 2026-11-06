/* SOURCE ONLY: explicit admission reconciliation of one timed-out public read.
 * The original context, error SDK and UNKNOWN are immutable historical evidence.
 * This is NOT lookup-only: exact same-key start may return Existing or admit New.
 * A separate exact root GO is required; no function is invoked on source load.
 * No business START, metadata refresh, second body range, key or path change.
 * Original SDK is Git-whole before isError/parse; unknown stops this new context.
 */
const GF_SLOT = "snapshot_2379_formatter_body0_admission_reconcile_r1";
const GF_ORIGINAL_SLOT = "snapshot_2379_rog_formatter_gitfirst_r1";
const GF_ORIGINAL_CALL = "snapshot-2379-formatter-body0-admit";
const GF_REQUEST = {blob:"06f7a3eccf5de1c877b552cab886d14086d0c51c",
 bytes:432,sha256:"35921fca79a714035d0033a003d481862326e4a8dc6409f5017bbc4fb37ea992"};
const GF_OLD_SDK = {blob:"f181c1e93e7b64c402b332fd29b23d0141762082",
 bytes:247,sha256:"20bc68d840783af5cc8e791289d5ac77c6941d45f79768c397c95e629784e3fa"};
const GF_OLD_UNKNOWN = {blob:"b174296c1b46c119356df90d5c68b6ca5bc4c19c",
 bytes:1629,sha256:"8e94eed174a2e88206fb6e27685df93d404eba8512cdb052e6528690656e6f3c"};
const GF_OLD_UNKNOWN_TREE = "29b6302cc3cb329566b6f66c0441c0899b0cc811";
const GF_BODY_EXPECTED = {"path":"/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/result.public.json","bytes":118925,"sha256":"5755903ce5696b6745d7af2b27a69a30e0d001697eeb85282df75eb25cea40d8","version":"66306:31236133:118925:1793956739343592677:1793956739343592677","infoOperation":"6040da16c66f2a7b6f2f4a3939721c0e78afddf8f9070d76c77a0ffe49e82cff","infoNative":{"blob":"45d1709e3bbbf74caee996369a1eefdfbf855a31","bytes":483,"sha256":"8430d3a4b0c79f274222678fd30f8f0cec8f7f546602c6a1a1a2a8c749c5a4c2"}};
const GF_PAGE_BYTES = 16384;

function gfNeed(value, code) { if(!value) throw new Error(code); }
function gfMetaEquals(raw,pin) {
 const actual=gitBlobMeta(raw);
 return actual.blob===pin.blob && actual.bytes===pin.bytes && actual.sha256===pin.sha256;
}
function gfOriginalUnknownView() {
 const old=load(GF_ORIGINAL_SLOT),call=old?.calls?.[GF_ORIGINAL_CALL];
 gfNeed(old?.paused===true && old.nativeCallInFlight===false
   && old.pending===GF_ORIGINAL_CALL && old.activeObserver===null
   && old.job==="1a1b02771c2-fc05-6e9f"
   && old.formatResultBodyStarted===1 && old.formatResultBodyRanges?.length===0
   && call?.called===true && call.phase==="native_interpretation_refused"
   && call.sdkArchive?.whole===true && gfMetaEquals(call.requestRaw,GF_REQUEST)
   && call.sdkPin?.blob===GF_OLD_SDK.blob
   && gfMetaEquals(load(GF_ORIGINAL_SLOT+":original_sdk_raw:"+GF_ORIGINAL_CALL),GF_OLD_SDK),
   "unchanged_original_UNKNOWN_boundary");
 const bodyCalls=Object.values(old.calls).filter(c=>c.kind==="operation_start"
   && JSON.parse(c.requestRaw).operation?.tool==="binary_read");
 gfNeed(bodyCalls.length===1 && bodyCalls[0]===call,
   "original_BODY1_still_unsubmitted");
 return {slot:GF_ORIGINAL_SLOT,job:old.job,paused:old.paused,pending:old.pending,
   called:call.called,phase:call.phase,request:call.requestPin,sdk:call.sdkPin,
   started:old.formatResultBodyStarted,ranges:old.formatResultBodyRanges.length,
   activeObserver:old.activeObserver,nativeCallInFlight:old.nativeCallInFlight,
   oldUnknown:GF_OLD_UNKNOWN,oldUnknownTree:GF_OLD_UNKNOWN_TREE};
}
function gfState() {
 const s=load(GF_SLOT);
 gfNeed(s && s.rootGoWhole===true, "root_go_not_initialized");
 gfNeed(JSON.stringify(gfOriginalUnknownView())===s.originalUnknownView,
   "original_paused_context_must_remain_unchanged");
 return s;
}
function gfSave(s) { store(GF_SLOT,s); }
function gfIntegerText(value) {
 if(Number.isSafeInteger(value))return String(value);
 gfNeed(value && Object.keys(value).join(",")==="$exactInteger"
   && /^-?[0-9]+$/.test(value.$exactInteger),"lossless_integer_token");
 return value.$exactInteger;
}
function gfInitializeOnlyAfterRootGO({goRaw,goPin,goWholeReadback,oldUnknownRaw}) {
 gfNeed(load(GF_SLOT)===undefined,
   "existing_or_armed_reconciliation_context_must_not_be_reinitialized");
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin)
   && gfMetaEquals(oldUnknownRaw,GF_OLD_UNKNOWN),"exact_whole_new_GO_and_old_UNKNOWN");
 const g=JSON.parse(goRaw),old=JSON.parse(oldUnknownRaw),view=gfOriginalUnknownView();
 gfNeed(g.authorization==="GO"
   && g.scope==="format_body0_exact_admission_reconciliation"
   && g.slot===GF_SLOT && g.original_slot===GF_ORIGINAL_SLOT
   && g.lookup_only===false && g.may_create_first_admission===true
   && g.maximum_operation_start_calls===1 && g.process_start_authorized===false
   && g.second_body_range_authorized===false && g.immutable_page_bytes===GF_PAGE_BYTES
   && g.maximum_retained_payload_bytes===1048576
   && g.old_unknown?.blob===GF_OLD_UNKNOWN.blob
   && g.original_error_sdk?.blob===GF_OLD_SDK.blob
   && g.exact_request?.blob===GF_REQUEST.blob
   && g.exact_request?.bytes===GF_REQUEST.bytes
   && g.exact_request?.sha256===GF_REQUEST.sha256,
   "separate_root_one_exact_admission_reconciliation_scope");
 gfNeed(old.originalSlot===GF_ORIGINAL_SLOT && old.uniqueCallKey===GF_ORIGINAL_CALL
   && old.readonlyAdmissionOutcome==="UNKNOWN" && old.paused===true
   && old.observedOperationId===null && old.secondBodySubmitted===false
   && old.uniqueRequest.blob===GF_REQUEST.blob && old.originalSDK.blob===GF_OLD_SDK.blob,
   "whole_original_failure_evidence_exact");
 store(GF_SLOT,{rootGoWhole:true,goRaw,goPin,job:view.job,
   originalUnknownView:JSON.stringify(view),originalUnknownRaw:oldUnknownRaw,
   originalAttemptOutcome:"UNKNOWN",lookupOnly:false,admissionCalled:false,
   pending:null,activeObserver:null,nativeCallInFlight:false,paused:false,
   calls:{},completedObservers:[],reconciliationAdmission:null,reconciledRange:null,
   localJournalAvailable:false,gitFirstExplicitlyRequiredByThisRootGO:true});
 return {slot:GF_SLOT,originalSlotUnchanged:true,originalAttemptOutcome:"UNKNOWN",
   exactRequest:GF_REQUEST,maximumOperationStarts:1,lookupOnly:false};
}
function gfValidateRequest(s,kind,q,raw) {
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null,"single_call_boundary");
 if(kind==="operation_start") {
  const a=q.operation?.arguments;
  gfNeed(!s.admissionCalled && s.activeObserver===null
    && s.completedObservers.length===0 && s.reconciledRange===null
    && gfMetaEquals(raw,GF_REQUEST)
    && Object.keys(q).sort().join(",")==="idempotency_key,operation"
    && q.idempotency_key==="heptabao-native-snapshot-2379d02b-formatter-observe-r1-result-body0"
    && Object.keys(q.operation).sort().join(",")==="arguments,tool"
    && q.operation.tool==="binary_read"
    && a && Object.keys(a).sort().join(",")==="expected_version,host,limit,offset,path"
    && a.host==="rog" && a.path===GF_BODY_EXPECTED.path && a.offset===0
    && a.limit===65536 && a.expected_version===GF_BODY_EXPECTED.version,
    "one_exact_original_key_typed_BODY0_admission_reconciliation");
 } else if(kind==="operation_status") {
  gfNeed(s.activeObserver && !s.activeObserver.futureClosed
    && Object.keys(q).join(",")==="operation_id"
    && q.operation_id===s.activeObserver.id,"same_returned_binding_status");
 } else if(kind==="operation_result") {
  gfNeed(s.activeObserver?.futureClosed===true
    && Object.keys(q).sort().join(",")==="limit,offset,operation_id"
    && q.operation_id===s.activeObserver.id && q.limit===GF_PAGE_BYTES
    && q.offset===s.activeObserver.nextPageOffset && !s.activeObserver.eof,
    "same_closed_returned_binding_next_page");
 } else throw new Error("closed_reconciliation_tool_set");
}
async function gfPrepareOne({callKey,kind,requestRaw}) {
 const s=gfState();
 gfNeed(/^[a-z0-9][a-z0-9-]{0,70}$/.test(callKey) && !s.calls[callKey],"fresh_call_record");
 const q=JSON.parse(requestRaw); // Public exact request, no native response.
 gfValidateRequest(s,kind,q,requestRaw);
 const requestPin=gitBlobMeta(requestRaw);
 const intent={schema:"heptabao.gitfirst.fixed-native-call-intent.r1",
  callKey,kind,request:requestPin,
  rootGo:s.goPin,oldUnknown:GF_OLD_UNKNOWN,originalErrorSDK:GF_OLD_SDK,
  lookupOnly:false,mayCreateFirstAdmission:kind==="operation_start",
  oldAttemptRemainsUNKNOWN:true,oldContextWillNotBeChanged:true,
  originalJob:s.job,
  originalOperation:s.activeObserver?.id??null,maximumNativeCalls:1,
  nativeNotYetCalled:true,lossOfAcknowledgmentNeverGrantsReplay:true,
  localFirstExplicitlyReplacedByExactRootGO:true};
 const armed={...intent,schema:"heptabao.gitfirst.fixed-native-call-armed.r1",
  mayHaveDispatchedAfterThisCheckpoint:true,
  recovery:"Never repeat this admission; preserve the original UNKNOWN and this attempt separately. Only an actually returned binding ID permits status/pages."};
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
 if(c.kind==="operation_start")s.admissionCalled=true;
 gfSave(s); // No await or second dispatch between this marker and the one call.
 let sdk;
 try {
  if(c.kind==="operation_start")sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_start(q);
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
  if(c.kind==="operation_start") {
   gfNeed(/^[a-f0-9]{64}$/.test(v.operation_id) && v.tool_name==="binary_read"
     && typeof v.reused==="boolean" && v.automatic_retry===false
     && v.idempotency_binding_retained===true
     && v.admission_is_not_dispatch_completion===true,
     "actual_reconciliation_receipt_without_old_attempt_inference");
   s.reconciliationAdmission={operationId:v.operation_id,reused:v.reused,
     classification:v.reused?"existing_binding_returned":"new_admission_receipt_observed",
     originalAttemptOutcome:"UNKNOWN",lookupOnly:false,
     nativeCompletionProven:false,bodyDeliveryProven:false};
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
   gfNeed(b.length<=GF_PAGE_BYTES
     && v.next_offset===q.offset+b.length
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
   && a?.futureClosed===true && a.eof && s.completedObservers.length===0
   && s.reconciledRange===null && s.reconciliationAdmission?.operationId===a.id,
   "closed_whole_returned_binding_boundary");
 let bytes=[],next=0;
 for(const p of a.pages){gfNeed(p.offset===next,"page_continuity");bytes=bytes.concat(unb64(p.base64));next=p.next;}
 gfNeed(next===a.total,"complete_original_payload_length");
 const raw=utf8Text(bytes),pin=gitBlobMeta(raw);
 gfNeed(pin.bytes===a.total && pin.sha256===a.digest,"complete_original_payload_hash");
 let archive;
 try {
  archive=await archiveFlatPublicTextsOnce({key:"gfc-"+a.id,
   repository:"TrillionniumFoundation/HeptaBao",texts:{"payload.original.json":raw}});
 } catch(error) {
  s.paused=true;s.originalPayloadArchiveFailure=String(error);gfSave(s);throw error;
 }
 const p=parseLosslessIntegers(raw);
 try {
  gfNeed(p.resultType==="complete" && p.isError===false
    && p.content?.length===1 && p.content[0].type==="text","original_native_result_success");
  const nativeRaw=p.content[0].text,v=parseLosslessIntegers(nativeRaw),need=GF_BODY_EXPECTED;
  gfNeed(a.tool==="binary_read" && a.request.operation.arguments.offset===0
    && a.request.operation.arguments.limit===65536
    && v.path===need.path && v.version===need.version && v.size===need.bytes
    && v.offset===0 && v.next_offset===65536 && v.eof===false
    && typeof v.data_base64==="string" && /^[a-f0-9]{64}$/.test(v.chunk_sha256),
    "exact_reconciled_BODY0_extent_no_BODY1");
  const bodyBytes=unb64(v.data_base64);
  gfNeed(bodyBytes.length===65536
    && sha256Latin1(byteString(bodyBytes))===v.chunk_sha256,
    "reconciled_BODY0_actual_bytes_SHA");
  const nativePin=gitBlobMeta(nativeRaw);
  const row={offset:0,limit:65536,next:65536,chunkSHA256:v.chunk_sha256,
    base64:v.data_base64,operationId:a.id,originalPayload:pin,payloadTree:archive.tree,
    nativeText:nativePin,metadataOperation:need.infoOperation,
    sourceFileVersion:need.version,sourceFileHashFromPriorMetadata:need.sha256,
    completeFileBody:false,oldAttemptOutcome:"UNKNOWN",
    reconciliationAdmission:s.reconciliationAdmission};
  const closedArchive=await archiveFlatPublicTextsOnce({
   key:"gfrc-"+a.id,repository:"TrillionniumFoundation/HeptaBao",
   texts:{"range0.native.original.json":nativeRaw,
     "closure.public.json":JSON.stringify({...row,base64:undefined},null,2)+"\n"}});
  const original={id:a.id,tool:a.tool,payload:pin,payloadTree:archive.tree,
    nativeText:nativePin,pages:a.pages.length,completedInactive:true,
    reconciliationOnly:true,oldAttemptOutcome:"UNKNOWN",closureTree:closedArchive.tree};
  s.reconciledRange=row;s.completedObservers.push(original);s.activeObserver=null;gfSave(s);
  store(GF_SLOT+":closed_native:"+a.id,nativeRaw);
  return {original,nativeRaw,value:v,oldAttemptOutcome:"UNKNOWN",
    nextRangeAuthorized:false,oldContextChanged:false};
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
