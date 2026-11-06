/* SOURCE ONLY: native-call archival substitute proposed for the local outage.
 * Requires pure_helpers.js plus git_archive_once.js in the same V8 evaluation.
 * No function below is invoked by loading this file. Root exact GO is separate.
 * No loop starts/retries a native call; all status/page steps are explicit.
 * Every original SDK is store'd, serialized, Git-created once and whole-read
 * before isError or native text is inspected.
 */
const GF_SLOT = "combined_5767739c_fresh_build_gitfirst_r1";
const GF_REQUEST = {blob:"43b4a12ca91aa73e60e90b30b6a5884b969b82a9",
 bytes:155691,sha256:"9a3b483d4b36206a21984882c0abc63dda539fb866354f0e5bfff6ebb18767e7"};

/* One separately approved observation of the newly owned public stage report.
 * This does not authorize binary_read or any new process. Existing state is kept.
 */
const GF_STAGE_RESULT_PATH = "/home/qian-qi/hb-5767739c-controls-20261106-r1/build-tests-r1/result.public.json";
const GF_STAGE_RESULT_MAX_BYTES = 4194304;
const GF_STAGE_INFO_REQUEST = {"blob":"8069ed61b56112eb670d41aff81066c4554152d5","bytes":227,"sha256":"48dc80cd6e5ae5da31df7bac0915542ba27f026f835772544ed93a50f2aa516e"};
const GF_STAGE_INFO_PREREQUISITES = [{"id":"772814f1351e54d5797a44c3a56add38a8378dbc3944023c757fad82bf011527","tool":"process_status","nativeText":{"blob":"bb8c059a1f8d53774b616a508a6217fc2699359f","bytes":728,"sha256":"8bc3ab47193437a3a61b4b8df3ccc546ef8753511d0cb4e4b5f86df9fc30627d"}},{"id":"72f32b784463daa3d31a7e3ca1f34e0a85d71740779bb54cad2b5d537ea8db88","tool":"process_read","nativeText":{"blob":"0fcf42fb3d7208e2c20be6e9d0db12e0134a008b","bytes":6440,"sha256":"18a789cadab12aa52b3c2714bbd184ab954f83a524c681ef63d065163d2906ee"}},{"id":"461b3092964e7cb149905a79143bbc626890fc6c980b7b0e9dd442aa13feefa8","tool":"process_read","nativeText":{"blob":"c5042a86ec32bb02bb44e98c46c080b0e5d8376c","bytes":326,"sha256":"8faa717c4775c8787c6671f9918fb7fea2d54bf6fb8a2a6554a36a0b77289a5d"}},{"id":"89aa336fc6ced09db40c932af2999042f14edf59b26962fb25008f5bf30056b3","tool":"process_read","nativeText":{"blob":"5850bf4c3d57b6ecab857925c1f80baebdb7de0b","bytes":4376,"sha256":"9286b820e1789c6a5978e4f909323483ebe95ce671f53c4604b465e23e1d9844"}},{"id":"473b9bbece624dd1a45dc00e9ba2fb96075f4b8ffd6608670e12bf314bc8efaf","tool":"process_read","nativeText":{"blob":"711d46431fe77b9469f5eb1495ef87e17ece61bf","bytes":326,"sha256":"1491f1fd3e84507c03545b02b0c8dee06c31115ff0386bb95b960d1f442c8a19"}},{"id":"001b3b129f9386dc04fd6998d647734b40944e265cd34decb71495f2fc1520ba","tool":"process_read","nativeText":{"blob":"711d46431fe77b9469f5eb1495ef87e17ece61bf","bytes":326,"sha256":"1491f1fd3e84507c03545b02b0c8dee06c31115ff0386bb95b960d1f442c8a19"}},{"id":"9b54607739383b9a4729c17120002fd5cc26505fa9d3bbcb5c21a57e4e39a64c","tool":"process_read","nativeText":{"blob":"fa574837c1ad55354d6606796595d220f57f2107","bytes":1536,"sha256":"d58103ffc76691abd4c1fb9d0809d09fed926488f450b4e646756f20a178c612"}}];

function gfAuthorizeStageResultInfoOnly({goRaw,goPin,goWholeReadback}) {
 const s=gfState();
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null
   && s.activeObserver===null && s.startCalled===true
   && s.job==="1a1b2d90976-fc05-7fff" && s.stageResultInfoGO===undefined
   && s.stageResultInfoStarted!==true,"closed_existing_stage_before_info_only_GO");
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin)
   && goPin.blob!==s.goPin.blob,"separate_whole_info_only_GO");
 const g=JSON.parse(goRaw);
 gfNeed(g.authorization==="GO" && g.scope==="build_result_file_info_only"
   && g.original_job===s.job && g.maximum_file_info_starts===1
   && g.binary_read_authorized===false
   && g.exact_request?.blob===GF_STAGE_INFO_REQUEST.blob
   && g.exact_request?.bytes===GF_STAGE_INFO_REQUEST.bytes
   && g.exact_request?.sha256===GF_STAGE_INFO_REQUEST.sha256,
   "exact_new_root_file_info_scope");
 for(const need of GF_STAGE_INFO_PREREQUISITES) {
  const prior=s.completedObservers.find(o=>o.id===need.id);
  const priorRaw=load(GF_SLOT+":closed_native:"+need.id);
  gfNeed(prior?.completedInactive===true && prior.tool===need.tool
    && gfMetaEquals(priorRaw,need.nativeText)
    && prior.nativeText.blob===need.nativeText.blob,"original_stage_closure_pin");
 }
 const authority=parseLosslessIntegers(load(GF_SLOT+":closed_native:"+GF_STAGE_INFO_PREREQUISITES[0].id));
 let stdout="",stderr="",so=0,se=0,last=null;
 for(const need of GF_STAGE_INFO_PREREQUISITES.slice(1)) {
  const v=parseLosslessIntegers(load(GF_SLOT+":closed_native:"+need.id));
  gfNeed(v.job_id===s.job && v.stdout.offset===so && v.stderr.offset===se,
         "original_stream_sequence");
  stdout+=v.stdout.text;stderr+=v.stderr.text;
  so=v.stdout.next_offset;se=v.stderr.next_offset;last=v;
 }
 gfNeed(last.stdout.eof===true && last.stderr.eof===true
   && so===3707 && se===0 && s.nextStdout===so && s.nextStderr===se
   && gitBlobMeta(stdout).sha256==="1303094bd399ea2bec2ea148fb147da4777255fc5116e9fe9a3faafb44fb5172"
   && gitBlobMeta(stdout).bytes===3707 && stderr==="","whole_current_streams");
 const lines=stdout.trimEnd().split("\n");
 gfNeed(lines.length===4,"four_original_public_output_lines");
 const terminal=JSON.parse(lines[3]);
 gfNeed(authority.job_id===s.job && authority.exit_code===1
   && authority.output_complete===true && authority.output_durable===true
   && authority.terminal_publication_confirmed===true
   && authority.log_bytes.stdout.stored===3707 && authority.log_bytes.stderr.stored===0
   && !authority.timed_out && !authority.cancelled
   && terminal.all_owned_stopped===true && terminal.status==="failed"
   && terminal.publication_within_original_outer===true
   && terminal.source_commit==="5767739cd25e458ac052dc8d384019bab8688ae0"
   && terminal.source_tree==="42477d622dcf96e1e2b0929fe9ecc6b7ba484740"
   && terminal.result_sha256==="95743757382a6828e622ce3f39ec1eaddb9da1db20df70a1b1ad3f87ec78d639"
   && terminal.result_path===GF_STAGE_RESULT_PATH,"known_failed_build_safe_public_result");
 s.stageResultInfoGO={pin:goPin,raw:goRaw,whole:true};
 gfSave(s);
 return {originalJob:s.job,exactRequest:GF_STAGE_INFO_REQUEST,
   maximumFileInfoStarts:1,binaryReadAuthorized:false};
}

/* One exact whole-report chunk after independently closed actual metadata.
 * Only this 46828-byte range is admitted; no body/listing fallback exists.
 */
const GF_STAGE_BODY_REQUEST = {"blob":"201efd07a150f7e3aa7384209cefa3368348fb5b","bytes":336,"sha256":"de1143488f34b5a05be74cc64bb187166f9c1c0db56bf179ba2b2ca420f36fde"};
const GF_STAGE_BODY_EXPECTED = {"path":"/home/qian-qi/hb-5767739c-controls-20261106-r1/build-tests-r1/result.public.json","bytes":46828,"sha256":"95743757382a6828e622ce3f39ec1eaddb9da1db20df70a1b1ad3f87ec78d639","version":"66306:33208049:46828:1794003951175308589:1794003951175308589","infoOperation":"cb2ea67ea2179e98073723441b12ca6f828ac09d9fe2842d779424e13ad9420b","infoNative":{"blob":"570abe6a64a14c8f702a61cd517093f761834c9a","bytes":468,"sha256":"be12f8bb38e926c8d81e0d1ba275e4883c613e99ff8bce0a8d63cd6ffe598601"}};

function gfAuthorizeStageResultBodyOnly({goRaw,goPin,goWholeReadback}) {
 const s=gfState(),need=GF_STAGE_BODY_EXPECTED,info=s.stageResultInfo;
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null
   && s.activeObserver===null && s.job==="1a1b2d90976-fc05-7fff"
   && s.stageResultInfoGO?.whole===true && s.stageResultInfoStarted===true
   && s.stageResultBodyGO===undefined && s.stageResultBodyStarted!==true,
   "closed_info_before_one_exact_body_GO");
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin)
   && goPin.blob!==s.goPin.blob && goPin.blob!==s.stageResultInfoGO.pin.blob,
   "separate_whole_body_only_GO");
 const g=JSON.parse(goRaw);
 gfNeed(g.authorization==="GO" && g.scope==="build_result_binary_read_only"
   && g.original_job===s.job && g.info_operation===need.infoOperation
   && g.maximum_binary_read_starts===1
   && g.exact_request?.blob===GF_STAGE_BODY_REQUEST.blob
   && g.exact_request?.bytes===GF_STAGE_BODY_REQUEST.bytes
   && g.exact_request?.sha256===GF_STAGE_BODY_REQUEST.sha256,
   "exact_new_root_body_scope");
 const prior=s.completedObservers.find(o=>o.id===need.infoOperation);
 gfNeed(prior?.completedInactive===true && prior.tool==="file_info"
   && prior.nativeText.blob===need.infoNative.blob
   && gfMetaEquals(load(GF_SLOT+":closed_native:"+need.infoOperation),need.infoNative)
   && info?.path===need.path && info.size===need.bytes && info.sha256===need.sha256
   && info.version===need.version && info.originalOperation===need.infoOperation
   && need.bytes>0 && need.bytes<=65536 && need.bytes<=GF_STAGE_RESULT_MAX_BYTES,
   "whole_current_info_identity_and_single_chunk");
 s.stageResultBodyGO={pin:goPin,raw:goRaw,whole:true};
 gfSave(s);
 return {originalJob:s.job,infoOperation:need.infoOperation,
   exactRequest:GF_STAGE_BODY_REQUEST,maximumBinaryReadStarts:1,wholeBytes:need.bytes};
}

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
function gfInitializeOnlyAfterRootGO({goRaw,goPin,goWholeReadback,digest,fingerprint}) {
 gfNeed(load(GF_SLOT)===undefined,"existing_or_armed_context_must_be_recovered_not_reinitialized");
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin),"exact_whole_root_go");
 gfNeed(/^[0-9a-f]{64}$/.test(digest) && /^[0-9]{1,20}$/.test(fingerprint),
        "root_independently_bound_native_identity");
 // The caller must supply the separately reviewed actual GO, not the SOURCE contract.
 store(GF_SLOT,{rootGoWhole:true,goRaw,goPin,digest,fingerprint,job:null,
  startCalled:false,pending:null,activeObserver:null,nativeCallInFlight:false,
  paused:false,calls:{},completedObservers:[],nextStdout:0,nextStderr:0,
  localJournalAvailable:false,gitFirstExplicitlyRequiredByThisRootGO:true});
}
function gfValidateRequest(s,kind,q,raw) {
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null,"single_call_boundary");
 if(kind==="process_start") {
  gfNeed(!s.startCalled && s.job===null && s.activeObserver===null
    && gfMetaEquals(raw,GF_REQUEST),"one_exact_diagnostic_start");
 } else if(kind==="operation_start") {
  gfNeed(s.job!==null && s.activeObserver===null,"original_job_no_unclosed_observer");
  gfNeed(Object.keys(q).sort().join(",")==="idempotency_key,operation"
    && typeof q.idempotency_key==="string" && q.idempotency_key.length<=128
    && /^heptabao-combined-5767739c-fresh-observe-r1-/.test(q.idempotency_key),
    "bounded_original_observer_key");
  const op=q.operation,a=op?.arguments;
  gfNeed(op && Object.keys(op).sort().join(",")==="arguments,tool"
    && a && a.host==="rog","same_original_host_only");
  if(op.tool==="binary_read") {
   gfNeed(s.stageResultBodyGO?.whole===true && s.stageResultBodyStarted!==true
     && gfMetaEquals(raw,GF_STAGE_BODY_REQUEST)
     && Object.keys(a).sort().join(",")==="expected_version,host,limit,offset,path"
     && a.path===GF_STAGE_BODY_EXPECTED.path && a.offset===0
     && a.limit===GF_STAGE_BODY_EXPECTED.bytes && a.limit<=65536
     && a.expected_version===GF_STAGE_BODY_EXPECTED.version,
     "one_exact_version_bound_whole_report_chunk");
  } else if(op.tool==="file_info") {
   gfNeed(s.stageResultInfoGO?.whole===true && s.stageResultInfoStarted!==true
     && gfMetaEquals(raw,GF_STAGE_INFO_REQUEST)
     && Object.keys(a).sort().join(",")==="host,path"
     && a.path===GF_STAGE_RESULT_PATH,"one_exact_newly_owned_stage_result_info");
  } else if(op.tool==="process_status") {
   gfNeed(a.job_id===s.job,"same_original_job_only");
   gfNeed(Object.keys(a).sort().join(",")==="host,job_id","exact_status_arguments");
  } else {
   gfNeed(op.tool==="process_read" && a.job_id===s.job
     && Object.keys(a).sort().join(",")==="host,job_id,limit,stderr_offset,stdout_offset"
     && a.limit===16384 && a.stdout_offset===s.nextStdout
     && a.stderr_offset===s.nextStderr,"original_stream_cursors_and_cap");
  }
 } else if(kind==="operation_status") {
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
  callKey,kind,request:requestPin,
  rootGo:((kind==="operation_start" && q.operation.tool==="binary_read")
    || s.activeObserver?.tool==="binary_read") ? s.stageResultBodyGO.pin
    : ((kind==="operation_start" && q.operation.tool==="file_info")
      || s.activeObserver?.tool==="file_info") ? s.stageResultInfoGO.pin : s.goPin,
  originalJob:s.job,
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
 if(c.kind==="operation_start" && q.operation.tool==="file_info")s.stageResultInfoStarted=true;
 if(c.kind==="operation_start" && q.operation.tool==="binary_read")s.stageResultBodyStarted=true;
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
    && v.launch?.ok===true && v.job?.host==="rog" && v.job.execution_mode==="operator"
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
  if(a.tool==="binary_read") {
   const need=GF_STAGE_BODY_EXPECTED;
   gfNeed(v.path===need.path && v.version===need.version && v.size===need.bytes
     && v.offset===0 && v.next_offset===need.bytes && v.eof===true
     && typeof v.data_base64==="string" && v.chunk_sha256===need.sha256,
     "whole_report_original_binary_extent");
   const bodyBytes=unb64(v.data_base64),bodyRaw=utf8Text(bodyBytes),bodyPin=gitBlobMeta(bodyRaw);
   gfNeed(bodyBytes.length===need.bytes && bodyPin.bytes===need.bytes
     && bodyPin.sha256===need.sha256,"whole_report_actual_bytes_SHA");
   store(GF_SLOT+":stage_result_body_original",bodyRaw);
   s.stageResultBody={path:need.path,version:need.version,body:bodyPin,
     originalOperation:a.id,metadataOperation:need.infoOperation,
     originalPayload:pin,semanticQualification:false};
  } else if(a.tool==="file_info") {
   const md=v.metadata,parts=typeof v.version==="string"?v.version.split(":"):[];
   gfNeed(v.path===GF_STAGE_RESULT_PATH && Number.isSafeInteger(v.size)
     && v.size>0 && v.size<=GF_STAGE_RESULT_MAX_BYTES
     && v.sha256==="95743757382a6828e622ce3f39ec1eaddb9da1db20df70a1b1ad3f87ec78d639" && v.mode===384
     && md?.metadata_platform==="linux" && md.mode===384
     && md.uid===1000 && md.gid===1000 && md.link_count===1
     && parts.length===5 && parts.every(x=>/^[0-9]+$/.test(x))
     && parts[2]===String(v.size),"fixed_report_content_metadata_and_version");
   s.stageResultInfo={path:v.path,size:v.size,sha256:v.sha256,version:v.version,
     nativeText:gitBlobMeta(nativeRaw),originalOperation:a.id,
     full9Strings:[parts[0],parts[1],"1000","1000",String(32768|v.mode),
       "1",String(v.size),parts[3],parts[4]],
     regularFileFromNativeFileInfoContract:true,
     binaryReadAuthorized:false};
  } else gfNeed(v.job_id===s.job,"original_job_native_result_binding");
  if(a.tool==="process_read") {
   for(const stream of ["stdout","stderr"]) {
    const row=v[stream],asked=a.request.operation.arguments[stream+"_offset"];
    gfNeed(row && row.offset===asked && Number.isSafeInteger(row.next_offset)
      && typeof row.text==="string" && typeof row.bytes_hex==="string"
      && /^[a-f0-9]*$/.test(row.bytes_hex),"lossless_original_stream_shape");
    const b=[];for(let i=0;i<row.bytes_hex.length;i+=2)b.push(parseInt(row.bytes_hex.slice(i,i+2),16));
    gfNeed(row.bytes_hex.length%2===0 && b.length<=16384 && row.next_offset===asked+b.length
      && utf8Text(b)===row.text && Number.isSafeInteger(row.size)
      && row.size>=row.next_offset && typeof row.eof==="boolean"
      && (!row.eof||row.next_offset===row.size),
      "lossless_original_stream_text_hex_extent");
    s[stream==="stdout"?"nextStdout":"nextStderr"]=row.next_offset;
   }
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
  else if(action==="authorize_stage_result_info")value=gfAuthorizeStageResultInfoOnly(args);
  else if(action==="authorize_stage_result_body")value=gfAuthorizeStageResultBodyOnly(args);
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
