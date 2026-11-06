/* SOURCE ONLY: native-call archival substitute proposed for the local outage.
 * Requires pure_helpers.js plus git_archive_once.js in the same V8 evaluation.
 * No function below is invoked by loading this file. Root exact GO is separate.
 * No loop starts/retries a native call; all status/page steps are explicit.
 * Every original SDK is store'd, serialized, Git-created once and whole-read
 * before isError or native text is inspected.
 */
const GF_SLOT = "jwt_pki_025b05a3_build149_failed_test2_logs_info_gitfirst_r1";
const GF_PRIOR_SLOT = "jwt_pki_025b05a3_build149_gitfirst_r2";
const GF_PRIOR_PIN = {"blob":"0de1e779d07917e4aab2e75cc571bdd14742ac60","bytes":135910,"sha256":"0185be3350a5b23748e39e8db8867b6eb95932e42a690de8650256d21fa989e7"};
const GF_ORIGINAL_SLOT = "jwt_pki_025b05a3_build149_gitfirst_r2";
const GF_ORIGINAL_STATE = {"blob":"0de1e779d07917e4aab2e75cc571bdd14742ac60","bytes":135910,"sha256":"0185be3350a5b23748e39e8db8867b6eb95932e42a690de8650256d21fa989e7"};
const GF_ORIGINAL_RESULT = {"blob":"5bf4476672f08c251826efc1dc9833af30bdd5b4","bytes":49775,"sha256":"47748eadb948f08973d7de202272823cd5f031ed99ec62286868236a8cbaa318","tree":"e68190618b8a9a1655f9f63277e8b16c8acaa167"};
const GF_LOG_TARGETS = [{"role":"test-stderr","path":"/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r2/build-tests-r1/native-jwt-pki-file17-2.stderr","sha256":"9829d15840c80e4a69ccf1afeab7025cd42dc94c421c3421271c973c801167cf"},{"role":"test-stdout","path":"/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r2/build-tests-r1/native-jwt-pki-file17-2.stdout","sha256":"baaffbccd60cd36f53810a4a49dc1ca9ae55883a1abb21253d29970d8dbf79ad"}];
const GF_REQUESTS = [{"blob":"9544655b6318cbce522c99f5e3249cb2778abbbe","bytes":311,"sha256":"89191105baec90a3834d074985a5f6b8a028e47e34f5ad7c8fa8b300d6dcfa13"},{"blob":"f54c0e83145aa26e5482738b6c4ddcdc9b956dd3","bytes":311,"sha256":"88db304a9452f4d97155de290025c34facb9749ed23dcb50dc7cf352cf214458"}];
const GF_LOG_METADATA_MAX_BYTES = 1048576;

/* Separate exact GO: failed-test stderr191 then stdout375, total566.
 * Both original INFOs closed. Only new binary payload pages use16KiB.
 */
const GF_LOG_BODY_REQUESTS = [{"blob":"b8a6cdfc57c4af38b09c17308cf3e3b82e61ba80","bytes":440,"sha256":"6f608f38a8ae79f43a09f98c5dd5120736ee9687ce16ce3194b66d58db24240c"},{"blob":"3b9d51d53f0b10ef67077bb34d7805196b45cd3b","bytes":440,"sha256":"10e36468d51b3976bc8d52c2a16eca8356e19025de8e641597bdf0070bde6f47"}];
const GF_LOG_BODY_EXPECTED = [{"path":"/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r2/build-tests-r1/native-jwt-pki-file17-2.stderr","bytes":191,"sha256":"9829d15840c80e4a69ccf1afeab7025cd42dc94c421c3421271c973c801167cf","version":"66306:33202269:191:1793974566577453065:1793974566577453065","infoOperation":"c105e55622c387d8c53614daf0f7c6f213fe78eacead907abe5b9b1e4ffbb085","infoNative":{"blob":"b1b5c5c6831ff668ce0443043a92d65483acf5bd","bytes":488,"sha256":"f9447947dcd44bbf9be9397f5cd3a49c1e4d49d746ce0cfd9266f771c1c23892"},"full9Strings":["66306","33202269","1000","1000","33152","1","191","1793974566577453065","1793974566577453065"]},{"path":"/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r2/build-tests-r1/native-jwt-pki-file17-2.stdout","bytes":375,"sha256":"baaffbccd60cd36f53810a4a49dc1ca9ae55883a1abb21253d29970d8dbf79ad","version":"66306:33202268:375:1793974566577453065:1793974566577453065","infoOperation":"e1460c7b8a33765b4b451f76157fd1603bc8a659e324125542f5318c816924c1","infoNative":{"blob":"98463cbd918907c6051a36bef453efe2136a48d3","bytes":488,"sha256":"43c902958091f331f4fdb1b749957832b6d96dac93544a4298901ef0e6a4fc15"},"full9Strings":["66306","33202268","1000","1000","33152","1","375","1793974566577453065","1793974566577453065"]}];
const GF_LOG_INFO_PREREQUISITES = [{"id":"c105e55622c387d8c53614daf0f7c6f213fe78eacead907abe5b9b1e4ffbb085","tool":"file_info","nativeText":{"blob":"b1b5c5c6831ff668ce0443043a92d65483acf5bd","bytes":488,"sha256":"f9447947dcd44bbf9be9397f5cd3a49c1e4d49d746ce0cfd9266f771c1c23892"}},{"id":"e1460c7b8a33765b4b451f76157fd1603bc8a659e324125542f5318c816924c1","tool":"file_info","nativeText":{"blob":"98463cbd918907c6051a36bef453efe2136a48d3","bytes":488,"sha256":"43c902958091f331f4fdb1b749957832b6d96dac93544a4298901ef0e6a4fc15"}}];
function gfAuthorizeFailedTestLogBodiesOnly({goRaw,goPin,goWholeReadback}) {
 const s=gfState();
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null && s.activeObserver===null
   && s.onlyFixedCompilerLogInfos===true && s.logInfos.length===2
   && s.completedObservers.length===2 && s.logInfoStarted.every(x=>x===true)
   && Object.keys(s.calls).length===6 && Object.values(s.calls).every(c=>c.phase==="accepted"&&c.sdkArchive.whole===true)
   && s.failedTestLogBodiesGO===undefined && s.failedTestLogBodies===undefined,
   "both_original_log_infos_closed_before_two_bodies");
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin) && goPin.blob!==s.goPin.blob,
   "separate_whole_two_log_bodies_GO");
 const g=JSON.parse(goRaw);
 gfNeed(g.authorization==="GO" && g.scope==="build_failed_test2_logs_binary_read_only"
   && g.original_job==="1a1b10cad9b-fc05-7560"
   && g.maximum_binary_read_starts===2 && g.maximum_file_info_starts===0
   && g.maximum_process_start_calls===0 && g.immutable_body_page_bytes===16384
   && Array.isArray(g.exact_requests) && g.exact_requests.length===2
   && g.exact_requests.every((x,i)=>x.blob===GF_LOG_BODY_REQUESTS[i].blob
    && x.bytes===GF_LOG_BODY_REQUESTS[i].bytes && x.sha256===GF_LOG_BODY_REQUESTS[i].sha256)
   && JSON.stringify(g.info_operations)===JSON.stringify(GF_LOG_INFO_PREREQUISITES.map(x=>x.id)),
   "two_exact_original_test_bodies_only_scope");
 for(let i=0;i<2;i++) {
  const p=GF_LOG_INFO_PREREQUISITES[i],o=s.completedObservers[i],info=s.logInfos[i],need=GF_LOG_BODY_EXPECTED[i];
  gfNeed(o?.id===p.id && o.completedInactive===true && o.tool==="file_info"
   && o.nativeText.blob===p.nativeText.blob
   && gfMetaEquals(load(GF_SLOT+":closed_native:"+p.id),p.nativeText),
   "both_independent_log_infos_whole");
  gfNeed(info.path===need.path && info.size===need.bytes && info.sha256===need.sha256
   && info.version===need.version && info.originalOperation===need.infoOperation
   && JSON.stringify(info.full9Strings)===JSON.stringify(need.full9Strings)
   && need.bytes===[191,375][i] && need.bytes<=65536,"whole_actual_log_info_binding");
 }
 s.failedTestLogBodiesGO={pin:goPin,raw:goRaw,whole:true};
 s.failedTestLogBodies=[];s.failedTestLogBodyStarted=[false,false];
 gfSave(s);
 return {exactRequests:GF_LOG_BODY_REQUESTS,maximumBinaryReads:2,bytes:566};
}

function gfNeed(value, code) { if(!value) throw new Error(code); }
function gfMetaEquals(raw,pin) {
 const actual=gitBlobMeta(raw);
 return actual.blob===pin.blob && actual.bytes===pin.bytes && actual.sha256===pin.sha256;
}
function gfState() {
 const s=load(GF_SLOT);
 gfNeed(s && s.rootGoWhole===true, "root_go_not_initialized");
 gfNeed(gfMetaEquals(JSON.stringify(load(GF_PRIOR_SLOT),null,2)+"\n",GF_PRIOR_PIN)
   && gfMetaEquals(JSON.stringify(load(GF_ORIGINAL_SLOT),null,2)+"\n",GF_ORIGINAL_STATE),
   "prior_closed_retrieval_and_old_paused_history_unchanged");
 return s;
}
function gfSave(s) { store(GF_SLOT,s); }
function gfIntegerText(value) {
 if(Number.isSafeInteger(value))return String(value);
 gfNeed(value && Object.keys(value).join(",")==="$exactInteger"
   && /^-?[0-9]+$/.test(value.$exactInteger),"lossless_integer_token");
 return value.$exactInteger;
}
function gfInitializeOnlyAfterRootGO({goRaw,goPin,goWholeReadback,priorStateRaw}) {
 gfNeed(load(GF_SLOT)===undefined,"existing_or_armed_context_must_be_recovered_not_reinitialized");
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin),"exact_whole_new_root_go");
 const g=JSON.parse(goRaw);
 gfNeed(g.authorization==="GO" && g.scope==="build_failed_test_logs_file_info_only"
   && g.original_job==="1a1b10cad9b-fc05-7560"
   && g.maximum_file_info_operations===2 && g.maximum_process_start_calls===0
   && g.maximum_binary_read_operations===0
   && Array.isArray(g.exact_requests) && g.exact_requests.length===2
   && g.exact_requests.every((p,i)=>p.blob===GF_REQUESTS[i].blob
     && p.bytes===GF_REQUESTS[i].bytes && p.sha256===GF_REQUESTS[i].sha256),
   "exact_new_two_log_metadata_GO");
 gfNeed(gfMetaEquals(priorStateRaw,GF_PRIOR_PIN),"exact_completed_immutable_retrieval_state");
 const prior=JSON.parse(priorStateRaw),live=load(GF_PRIOR_SLOT);
 gfNeed(live && JSON.stringify(live,null,2)+"\n"===priorStateRaw
   && prior.pending===null && prior.activeObserver===null
   && prior.nativeCallInFlight===false && prior.paused===false
   && prior.startCalled===true && prior.job==="1a1b10cad9b-fc05-7560"
   && Object.keys(prior.calls).length===41 && prior.completedObservers.length===12
   && prior.completedObservers.every(o=>o.completedInactive===true)
   && Object.values(prior.calls).every(c=>c.phase==="accepted"&&c.sdkArchive.whole===true)
   && prior.stageResultBody?.originalOperation==="8a6ff767b74a82cc46818dd50f52f2599317f267cdf384ca5523e7f7f80798c7"
   && prior.stageResultBody.body.blob===GF_ORIGINAL_RESULT.blob,
   "previous_original_build_and_whole_body_closed_no_new_effect");
 gfNeed(gfMetaEquals(JSON.stringify(load(GF_ORIGINAL_SLOT),null,2)+"\n",GF_ORIGINAL_STATE),
   "old_paused_error_history_unchanged");
 const body=load(GF_PRIOR_SLOT+":stage_result_body_original");
 gfNeed(gfMetaEquals(body,GF_ORIGINAL_RESULT),"original_failed_build_report_whole");
 const result=parseLosslessIntegers(body);
 const family=result.group_results?.[0],test=family?.tests?.[1];
 gfNeed(result.status==="failed" && result.failure_type==="AssertionError" && result.failure===""
   && result.source_commit==="025b05a340de841b8161c1120344e86eae30eb97"
   && result.source_tree==="1d8160c9385f8053b9a683cc1834da0f912e2d37"
   && result.normal_release_build.exit_code===0 && result.runtime_tests_started===true
   && result.group_results.length===1 && family.label==="native-jwt-pki-file17"
   && family.tests.length===2 && family.tests[0].tests.exit_code===0
   && test.name==="service::native_auth::jwt_tests::native_jwt_rejects_remote_batch_and_bad_signature_without_candidate_delta"
   && test.tests.label==="native-jwt-pki-file17-2"
   && test.tests.exit_code===101 && test.tests.timed_out===false
   && test.tests.direct_child_reaped===true && test.tests.remaining.length===0
   && test.tests.stderr_sha256===GF_LOG_TARGETS[0].sha256
   && test.tests.stdout_sha256===GF_LOG_TARGETS[1].sha256,
   "logs_bind_actual_failed_second_test_SHA");
 store(GF_SLOT,{rootGoWhole:true,goRaw,goPin,digest:null,fingerprint:null,job:null,
  startCalled:false,pending:null,activeObserver:null,nativeCallInFlight:false,
  paused:false,calls:{},completedObservers:[],nextStdout:0,nextStderr:0,
  localJournalAvailable:false,gitFirstExplicitlyRequiredByThisRootGO:true,
  priorClosedContext:{slot:GF_PRIOR_SLOT,state:GF_PRIOR_PIN},
  originalPausedContext:{slot:GF_ORIGINAL_SLOT,state:GF_ORIGINAL_STATE},
  onlyFixedCompilerLogInfos:true,logInfos:[],logInfoStarted:[false,false]});
}
function gfValidateRequest(s,kind,q,raw) {
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null,"single_call_boundary");
 if(kind==="process_start") {
  throw new Error("metadata_scope_has_no_process_start_authorization");
 } else if(kind==="operation_start") {
  if(s.failedTestLogBodiesGO?.whole===true) {
   const i=s.failedTestLogBodies.length,need=GF_LOG_BODY_EXPECTED[i],a=q.operation?.arguments;
   gfNeed(i<2 && s.activeObserver===null && s.failedTestLogBodyStarted[i]===false
     && s.logInfos.length===2 && s.completedObservers.length===2+i
     && Object.values(s.calls).filter(c=>c.kind==="operation_start").length===2+i
     && gfMetaEquals(raw,GF_LOG_BODY_REQUESTS[i])
     && Object.keys(q).sort().join(",")==="idempotency_key,operation"
     && q.operation?.tool==="binary_read"
     && Object.keys(q.operation).sort().join(",")==="arguments,tool"
     && a && Object.keys(a).sort().join(",")==="expected_version,host,limit,offset,path"
     && a.host==="rog" && a.path===need.path && a.offset===0
     && a.limit===need.bytes && a.expected_version===need.version,
     "two_sequential_exact_log_bodies_no_path_or_version_fallback");
   return;
  }
  const i=s.logInfos.length,need=GF_LOG_TARGETS[i];
  gfNeed(s.onlyFixedCompilerLogInfos===true && s.job===null && s.activeObserver===null
    && i<2 && s.completedObservers.length===i && s.logInfoStarted[i]===false
    && Object.values(s.calls).filter(c=>c.kind==="operation_start").length===i,
    "two_sequential_fixed_metadata_admissions_only");
  gfNeed(gfMetaEquals(raw,GF_REQUESTS[i])
    && Object.keys(q).sort().join(",")==="idempotency_key,operation",
    "exact_original_compile_log_metadata_request");
  const op=q.operation,a=op?.arguments;
  gfNeed(op && Object.keys(op).sort().join(",")==="arguments,tool"
    && op.tool==="file_info" && a
    && Object.keys(a).sort().join(",")==="host,path"
    && a.host==="rog" && a.path===need.path,"fixed_compile_log_path_only");
 } else if(kind==="operation_status") {
  gfNeed(s.activeObserver && !s.activeObserver.futureClosed
   && Object.keys(q).join(",")==="operation_id"
   && q.operation_id===s.activeObserver.id,"same_live_original_operation_status");
 } else if(kind==="operation_result") {
  gfNeed(s.activeObserver?.futureClosed===true
   && Object.keys(q).sort().join(",")==="limit,offset,operation_id"
   && q.operation_id===s.activeObserver.id && q.limit===(s.activeObserver.tool==="binary_read"?16384:8192)
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
 if(c.kind==="operation_start" && q.operation.tool==="file_info")s.logInfoStarted[s.logInfos.length]=true;
 if(c.kind==="operation_start" && q.operation.tool==="binary_read")s.failedTestLogBodyStarted[s.failedTestLogBodies.length]=true;
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
   gfNeed(b.length<=(a.tool==="binary_read"?16384:8192) && v.next_offset===q.offset+b.length
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
   const i=s.failedTestLogBodies.length,need=GF_LOG_BODY_EXPECTED[i];
   gfNeed(i<2 && s.failedTestLogBodiesGO?.whole===true && s.failedTestLogBodyStarted[i]===true
    && a.request.operation.arguments.path===need.path
    && v.path===need.path && v.size===need.bytes && v.offset===0
    && v.next_offset===need.bytes && v.eof===true
    && v.version===need.version && v.chunk_sha256===need.sha256,
    "exact_versioned_original_test_log_body");
   const b=unb64(v.data_base64),bodyRaw=utf8Text(b),bodyPin=gitBlobMeta(bodyRaw);
   gfNeed(b.length===need.bytes && bodyPin.bytes===need.bytes
     && bodyPin.sha256===need.sha256,"whole_original_test_log_bytes");
   const bodyArchive=await archiveFlatPublicTextsOnce({
    key:"gcc-testlog-"+a.id,repository:"TrillionniumFoundation/HeptaBao",
    texts:{[GF_LOG_TARGETS[i].role+".original.txt"]:bodyRaw,"native.original.json":nativeRaw}});
   s.failedTestLogBodies.push({...bodyPin,index:i,role:GF_LOG_TARGETS[i].role,
     archiveTree:bodyArchive.tree,whole:true,originalOperation:a.id,version:need.version,path:need.path});
   store(GF_SLOT+":test_log_original:"+i,bodyRaw);
  } else if(a.tool==="file_info") {
   const i=s.logInfos.length,need=GF_LOG_TARGETS[i],md=v.metadata;
   const parts=typeof v.version==="string"?v.version.split(":"):[];
   gfNeed(i<2 && s.onlyFixedCompilerLogInfos===true && s.logInfoStarted[i]===true
     && a.request.operation.arguments.host==="rog"
     && a.request.operation.arguments.path===need.path && v.path===need.path
     && Number.isSafeInteger(v.size) && v.size>=0 && v.size<=GF_LOG_METADATA_MAX_BYTES
     && v.sha256===need.sha256 && v.mode===384
     && md?.metadata_platform==="linux" && md.mode===384
     && md.uid===1000 && md.gid===1000 && md.link_count===1
     && parts.length===5 && parts.every(x=>/^[0-9]+$/.test(x))
     && parts[2]===String(v.size),"exact_compile_log_metadata_content_version_mode");
   const full9=[parts[0],parts[1],"1000","1000",String(32768|v.mode),
     "1",String(v.size),parts[3],parts[4]];
   s.logInfos.push({index:i,role:need.role,path:v.path,size:v.size,sha256:v.sha256,
     version:v.version,full9Strings:full9,originalOperation:a.id,
     nativeText:gitBlobMeta(nativeRaw),regularFileFromNativeFileInfoContract:true,
     expectedVersionBeforeObservation:null,bodyReadAuthorized:false});
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
  if(action==="authorize_failed_test_log_bodies")value=gfAuthorizeFailedTestLogBodiesOnly(args);
  else if(action==="initialize")value=gfInitializeOnlyAfterRootGO(args);
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
