/* SOURCE ONLY: native-call archival substitute proposed for the local outage.
 * Requires pure_helpers.js plus git_archive_once.js in the same V8 evaluation.
 * No function below is invoked by loading this file. Root exact GO is separate.
 * No loop starts/retries a native call; all status/page steps are explicit.
 * Every original SDK is store'd, serialized, Git-created once and whole-read
 * before isError or native text is inspected.
 */
const GF_SLOT = "combined_4a49405b_exact_key_conditional_admission_r1";
const GF_REQUEST = {blob:"f2c05f2d50e494b1046b57e727f89ce49a4d5d5a",
 bytes:158691,sha256:"0e16d0235233595463dbdb53f51cc5790ea4fd62700b6f3a4529f907eb7d547e"};

const GF_ORIGINAL_BUILD_SLOT="combined_4a49405b_fresh_build_gitfirst_r1";
const GF_ORIGINAL_BUILD_PIN={blob:"2d512764d26256fabaaaf7deb3eae41120d92d3e",bytes:181122,sha256:"196a33b53ea752d27a5226e06f90e75383b1f621a44791e0e240ded17f0bac82"};
const GF_ORIGINAL_INFO_SLOT="combined_4a49405b_unknown_report_info_gitfirst_r1";
const GF_ORIGINAL_INFO_PIN={blob:"24f7020e488bea35ab336990345c4d767d89da66",bytes:11134,sha256:"d4105a16656aa555e755da451da41801438ab779947d3efbae66466aac82ccbb"};
const GF_EXACT_DIGEST="33dcdfaa308ff7e6669737a1326ec90e9f6275038ee7f27d896aeb95981f2d50";
const GF_EXACT_FP="3737107712862844902";
function gfOriginalFrozen(){
 gfNeed(gfMetaEquals(JSON.stringify(load(GF_ORIGINAL_BUILD_SLOT),null,2)+"\n",GF_ORIGINAL_BUILD_PIN)
  &&gfMetaEquals(JSON.stringify(load(GF_ORIGINAL_INFO_SLOT),null,2)+"\n",GF_ORIGINAL_INFO_PIN),
  "original_unknown_and_failed_info_states_frozen");
}

/* One separately approved observation of the newly owned public stage report.
 * This does not authorize binary_read or any new process. Existing state is kept.
 */
const GF_STAGE_RESULT_PATH = "/home/qian-qi/hb-4a49405b-controls-20261106-r1/build-tests-r1/result.public.json";
const GF_STAGE_RESULT_MAX_BYTES = 4194304;
const GF_STAGE_INFO_BEFORE = {"blob":"ffd08542730b5033fdc564c1b38a000f6515c6c8","bytes":286087,"sha256":"f55033d773c001c3e058c4d359f790f76ca9dd7402f9d1756fa29bff7ccda6a0"};
const GF_STAGE_INFO_REQUEST = {"blob":"28b3d72790e25a1058351341bf2c32d0f2e63eff","bytes":234,"sha256":"932bb58bd27f555bd0986bbb3ba7129c493e64113a30ab6ce3c1e275cc8e76bb"};
const GF_STAGE_INFO_PREREQUISITES = [{"id":"5acdbb39ce24831a5585a34a563642c22f3b68308d4362510c0b367402179a13","tool":"process_status","nativeText":{"blob":"f81998dab23b195fa1fb79b89c69ba50d4ac61a4","bytes":728,"sha256":"1118cc928b4f22ff7c78a2d0b9829b767b17cc0e8cf18e93babb65c254bb20c4"}},{"id":"48d722e432fec62b561ae4353214e13a9420873c0f2dd96fee23296175ea5242","tool":"process_read","nativeText":{"blob":"976c1c097669aeb0ec6eb9145dc0760e19a68466","bytes":6443,"sha256":"a60b4841ea0cf03bf8eb3a3ca4d520e18ebe84abd49fff4549cbc9efd5d61461"}},{"id":"ed44c34ac2f6f5d1e88e0b342694429c0ceb2671092a6262c9a7e2dc3ef9d283","tool":"process_read","nativeText":{"blob":"996e92717645f9d160756aa3d37281e367aa2483","bytes":326,"sha256":"8b48c450775d816b4bee4eadb732e74851f52d6d3d9e853079ccd16d9b6a5440"}},{"id":"e9033788bd03b7265dc888b1e8a421c6d6dc8e7806ae10d957c2328a1fc63cdf","tool":"process_read","nativeText":{"blob":"b85718627b2f3678699037e6bfdcb98fdd8bebfd","bytes":4376,"sha256":"d9dea77fd31170d047433385379c367f4fe73ad70e0ab5e4a9f2db38c5b97efd"}},{"id":"e97d26590aa21f0af8dde21d5be5f7cf94b3ac29fef37a614c69cc9ef6591800","tool":"process_read","nativeText":{"blob":"afd0fcdd466a9ce89913b968ed458307b5f0b040","bytes":326,"sha256":"ee572a7252709aecf4b661559ff1c5cc20b587f93e18f088561987a4164f4bd2"}},{"id":"f9e5fef704a65ab3561e2bf8469734c42f973103325a8e4914bc5c12147cfa45","tool":"process_read","nativeText":{"blob":"afd0fcdd466a9ce89913b968ed458307b5f0b040","bytes":326,"sha256":"ee572a7252709aecf4b661559ff1c5cc20b587f93e18f088561987a4164f4bd2"}},{"id":"68153da9ef547ad897b66e4776c882fb4d04994a69181f64b03ae44620f5503d","tool":"process_read","nativeText":{"blob":"afd0fcdd466a9ce89913b968ed458307b5f0b040","bytes":326,"sha256":"ee572a7252709aecf4b661559ff1c5cc20b587f93e18f088561987a4164f4bd2"}},{"id":"ecb2f1c0a9840f7aebdd397ddb97275a68c79b0c04a296ffae90cee1c0393dc2","tool":"process_read","nativeText":{"blob":"0f72064027e0dbd6d3e3a6548182a8392abefbc0","bytes":1536,"sha256":"09fad07fae2aaecf4d3b75d319ecba70f7e6c65b4bf14299dbe76b646312a545"}}];

function gfAuthorizeStageResultInfoOnly({goRaw,goPin,goWholeReadback}) {
 const s=gfState();
 gfNeed(gfMetaEquals(JSON.stringify(s,null,2)+"\n",GF_STAGE_INFO_BEFORE),"exact_current_terminal_state_before_info");
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null
   && s.activeObserver===null && s.startCalled===true
   && s.job==="1a1b3978da9-fc05-83bd" && s.stageResultInfoGO===undefined
   && s.stageResultInfoStarted!==true,"closed_existing_stage_before_info_only_GO");
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin)
   && goPin.blob!==s.goPin.blob,"separate_whole_info_only_GO");
 const g=JSON.parse(goRaw);
 gfNeed(g.authorization==="GO" && g.scope==="build_result_file_info_only"
   && g.original_job===s.job && g.maximum_file_info_starts===1
   && g.binary_read_authorized===false
   && g.actualClosedState?.blob===GF_STAGE_INFO_BEFORE.blob
   && g.actualClosedState?.bytes===GF_STAGE_INFO_BEFORE.bytes
   && g.actualClosedState?.sha256===GF_STAGE_INFO_BEFORE.sha256
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
   && so===3708 && se===0 && s.nextStdout===so && s.nextStderr===se
   && gitBlobMeta(stdout).sha256==="0e0729d57e5a44f68632174c68cd535c5341004a00c9bd0df8b9a24f689be9f1"
   && gitBlobMeta(stdout).bytes===3708 && stderr==="","whole_current_streams");
 const lines=stdout.trimEnd().split("\n");
 gfNeed(lines.length===4,"four_original_public_output_lines");
 const terminal=JSON.parse(lines[3]);
 gfNeed(authority.job_id===s.job && authority.exit_code===1
   && authority.output_complete===true && authority.output_durable===true
   && authority.terminal_publication_confirmed===true
   && authority.log_bytes.stdout.stored===3708 && authority.log_bytes.stderr.stored===0
   && !authority.timed_out && !authority.cancelled
   && terminal.all_owned_stopped===true && terminal.status==="failed"
   && terminal.publication_within_original_outer===true
   && terminal.source_commit==="4a49405b93c45ab1c25ecba11cde63a7ede20dce"
   && terminal.source_tree==="f02dd113d208d79f5275005dc65a5e8aecd0e9d3"
   && terminal.result_sha256==="7be18adad000805344acf09d01b91fbd1ed99e561bfbc97c9faf0fd56a07b250"
   && terminal.result_path===GF_STAGE_RESULT_PATH,"known_failed_build_safe_public_result");
 s.stageResultInfoGO={pin:goPin,raw:goRaw,whole:true};
 gfSave(s);
 return {originalJob:s.job,exactRequest:GF_STAGE_INFO_REQUEST,
   maximumFileInfoStarts:1,binaryReadAuthorized:false};
}

function gfNeed(value, code) { if(!value) throw new Error(code); }
function gfMetaEquals(raw,pin) {
 const actual=gitBlobMeta(raw);
 return actual.blob===pin.blob && actual.bytes===pin.bytes && actual.sha256===pin.sha256;
}
function gfState() {
 gfOriginalFrozen();
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
 gfOriginalFrozen();
 gfNeed(load(GF_SLOT)===undefined,"existing_or_armed_context_must_be_recovered_not_reinitialized");
 gfNeed(goWholeReadback===true&&gfMetaEquals(goRaw,goPin),"exact_whole_root_go");
 const g=JSON.parse(goRaw);
 gfNeed(g.authorization==="GO"&&g.scope==="combined4a_exact_key_conditional_admission_once"
  &&g.maximumProcessStartCalls===1&&g.allowFirstAdmission===true&&g.lookupOnly===false
  &&g.sameJobObservationsAuthorized===false
  &&JSON.stringify(g.request)===JSON.stringify(GF_REQUEST)
  &&JSON.stringify(g.originalBuildState)===JSON.stringify(GF_ORIGINAL_BUILD_PIN)
  &&JSON.stringify(g.originalInfoState)===JSON.stringify(GF_ORIGINAL_INFO_PIN),
  "explicit_conditional_admission_not_lookup_only");
 gfNeed(digest===GF_EXACT_DIGEST&&fingerprint===GF_EXACT_FP
  &&g.digest===GF_EXACT_DIGEST&&g.fingerprint===GF_EXACT_FP,
  "unchanged_original_typed_identity");
 store(GF_SLOT,{rootGoWhole:true,goRaw,goPin,digest,fingerprint,job:null,
  startCalled:false,pending:null,activeObserver:null,nativeCallInFlight:false,
  paused:false,calls:{},completedObservers:[],nextStdout:0,nextStderr:0,
  conditionalAdmission:null,originalStartOutcome:"UNKNOWN",sameJobObservationsAuthorized:false,
  localJournalAvailable:false,gitFirstExplicitlyRequiredByThisRootGO:true});
}

const GF_OBSERVE_BEFORE={"blob":"a4fea6d283d0fb3d58d8045a8f4c7df637ecd578","bytes":168445,"sha256":"535d5821d952b3a0d4558523bee33388e2256a1f8a66093f00da82afa5a7e270"};
const GF_OBSERVE_JOB="1a1b3978da9-fc05-83bd";
const GF_OBSERVE_ACK={"blob":"cb1009bdcaf5706e9f3f1578baf49ee171f23ee5","bytes":8279,"sha256":"d94d84a0016cc16eb1e560fea3f57a320d6d7a1ba3d72115b176ec3dbc22ed1a"};
function gfAuthorizeActualJobObservers({goRaw,goPin,goWholeReadback}){
 const s=gfState();
 gfNeed(gfMetaEquals(JSON.stringify(s,null,2)+"\n",GF_OBSERVE_BEFORE)
  &&s.job===GF_OBSERVE_JOB&&s.startCalled===true&&!s.paused
  &&s.pending===null&&!s.nativeCallInFlight&&s.activeObserver===null
  &&s.sameJobObservationsAuthorized===false,"exact_actual_ack_state_before_observation");
 gfNeed(goWholeReadback===true&&gfMetaEquals(goRaw,goPin),"whole_actual_job_observation_go");
 const g=JSON.parse(goRaw),c=s.calls["c4a-exact-key-reconcile-r1-start"];
 gfNeed(g.authorization==="GO"&&g.scope==="combined4a_actual_job_observations_only"
  &&g.jobId===GF_OBSERVE_JOB&&g.host==="rog"
  &&JSON.stringify(g.actualAck)===JSON.stringify(GF_OBSERVE_ACK)
  &&JSON.stringify(g.beforeState)===JSON.stringify(GF_OBSERVE_BEFORE)
  &&g.maximumStatusObservers===256&&g.maximumReadObservers===129
  &&g.statusCallsPerObserver===8&&g.pagesPerObserver===128&&g.pageBytes===8192
  &&g.payloadCap===1048576&&g.streamReadLimit===16384&&g.streamByteCap===2097152
  &&g.processStartAuthorized===false
  &&c.phase==="accepted"&&c.sdkArchive.whole===true
  &&JSON.stringify(c.sdkPin)===JSON.stringify(GF_OBSERVE_ACK),"actual_job_scope_and_original_caps");
 s.observationGo={pin:goPin,raw:goRaw,actualBeforeState:GF_OBSERVE_BEFORE,actualAck:GF_OBSERVE_ACK};
 s.sameJobObservationsAuthorized=true;s.statusObserversCalled=0;s.readObserversCalled=0;
 gfSave(s);return {job:s.job,authorized:true,processStartAuthorized:false,underlyingBuildDeadlineUnchanged:true};
}

function gfValidateRequest(s,kind,q,raw) {
 gfNeed(s.sameJobObservationsAuthorized===true&&["operation_start","operation_status","operation_result"].includes(kind),
  "actual_bound_job_observations_only_no_start");
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null,"single_call_boundary");
 if(kind==="process_start") {
  gfNeed(!s.startCalled && s.job===null && s.activeObserver===null
    && gfMetaEquals(raw,GF_REQUEST),"one_exact_diagnostic_start");
 } else if(kind==="operation_start") {
  gfNeed(s.job!==null && s.activeObserver===null,"original_job_no_unclosed_observer");
  gfNeed(Object.keys(q).sort().join(",")==="idempotency_key,operation"
    && typeof q.idempotency_key==="string" && q.idempotency_key.length<=128
    && /^heptabao-combined-4a49405b-fresh-observe-r1-/.test(q.idempotency_key),
    "bounded_original_observer_key");
  const op=q.operation,a=op?.arguments;
  gfNeed(op && Object.keys(op).sort().join(",")==="arguments,tool"
    && a && a.host==="rog","same_original_host_only");
  gfNeed(!s.stageResultInfoGO || op.tool==="file_info","new_info_GO_does_not_extend_job_observations");
  if(op.tool==="file_info") {
   gfNeed(s.stageResultInfoGO?.whole===true && s.stageResultInfoStarted!==true
     && gfMetaEquals(raw,GF_STAGE_INFO_REQUEST)
     && Object.keys(a).sort().join(",")==="host,path"
     && a.path===GF_STAGE_RESULT_PATH,"one_exact_newly_owned_stage_result_info");
  } else if(op.tool==="process_status") {
   gfNeed(a.job_id===s.job,"same_original_job_only");
   gfNeed(s.statusObserversCalled<256,"status_observer_cap");
   gfNeed(Object.keys(a).sort().join(",")==="host,job_id","exact_status_arguments");
  } else {
   gfNeed(s.readObserversCalled<129&&s.nextStdout<=2097152&&s.nextStderr<=2097152,"read_observer_and_stream_caps");
   gfNeed(op.tool==="process_read" && a.job_id===s.job
     && Object.keys(a).sort().join(",")==="host,job_id,limit,stderr_offset,stdout_offset"
     && a.limit===16384 && a.stdout_offset===s.nextStdout
     && a.stderr_offset===s.nextStderr,"original_stream_cursors_and_cap");
  }
 } else if(kind==="operation_status") {
  gfNeed(s.activeObserver && !s.activeObserver.futureClosed && s.activeObserver.statusCalls<8
   && Object.keys(q).join(",")==="operation_id"
   && q.operation_id===s.activeObserver.id,"same_live_original_operation_status");
 } else if(kind==="operation_result") {
  gfNeed(s.activeObserver?.futureClosed===true && s.activeObserver.pageCalls<128
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
  rootGo:(kind==="operation_start" && q.operation.tool==="file_info")
    || s.activeObserver?.tool==="file_info" ? s.stageResultInfoGO.pin : s.observationGo.pin,
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
 if(c.kind==="operation_start"){
  if(q.operation.tool==="file_info")s.stageResultInfoStarted=true;
  else if(q.operation.tool==="process_status")s.statusObserversCalled++;
  else s.readObserversCalled++;
 }else if(c.kind==="operation_status")s.activeObserver.statusCalls++;
 else if(c.kind==="operation_result")s.activeObserver.pageCalls++;
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
   gfNeed(v.audit_recorded===true && v.local_record_pending===false && typeof v.reused==="boolean"
    && typeof v.launch?.ok==="boolean" && v.job?.host==="rog" && v.job.execution_mode==="operator"
    && v.job.idempotency_key===q.idempotency_key && v.job.executable===q.executable
    && v.job.cwd===q.cwd && JSON.stringify(v.job.args)===JSON.stringify(q.args)
    && v.job.request_digest===s.digest && gfIntegerText(v.job.request_fingerprint)===s.fingerprint
    && /^[a-z0-9-]{1,100}$/.test(v.job.id),"exact_same_key_typed_conditional_native_binding");
   s.job=v.job.id;
   s.conditionalAdmission={
    reused:v.reused,
    classification:v.reused?"existing_durable_job_reconciled":"first_admission_possible_under_new_go",
    originalStartOutcome:"UNKNOWN",originalTimeoutPreserved:true,
    originalNeverAdmittedInferred:false,lookupOnly:false,launchOk:v.launch.ok,
    authoritativeLiveStatus:false,sameJobObservationsAuthorized:false,
    originalBuildState:GF_ORIGINAL_BUILD_PIN,originalInfoState:GF_ORIGINAL_INFO_PIN};
  } else if(c.kind==="operation_start") {
   gfNeed(/^[a-f0-9]{64}$/.test(v.operation_id) && v.tool_name===q.operation.tool
     && v.reused===false && v.automatic_retry===false,"original_observer_admission");
   s.activeObserver={id:v.operation_id,request:q,tool:v.tool_name,futureClosed:false,
    statusCalls:0,pageCalls:0,nextPageOffset:0,eof:false,pages:[],total:null,digest:null};
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
          conditionalAdmission:s.conditionalAdmission,nativeCallInFlight:false};
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
  if(a.tool==="file_info") {
   const md=v.metadata,parts=typeof v.version==="string"?v.version.split(":"):[];
   gfNeed(v.path===GF_STAGE_RESULT_PATH && Number.isSafeInteger(v.size)
     && v.size>0 && v.size<=GF_STAGE_RESULT_MAX_BYTES
     && v.sha256==="7be18adad000805344acf09d01b91fbd1ed99e561bfbc97c9faf0fd56a07b250" && v.mode===384
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
      && row.size<=2097152 && row.size>=row.next_offset && typeof row.eof==="boolean"
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
  if(action==="authorize_actual_job_observers")value=gfAuthorizeActualJobObservers(args);
  else if(action==="authorize_stage_result_info")value=gfAuthorizeStageResultInfoOnly(args);
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
