/* SOURCE ONLY: native-call archival substitute proposed for the local outage.
 * Requires pure_helpers.js plus git_archive_once.js in the same V8 evaluation.
 * No function below is invoked by loading this file. Root exact GO is separate.
 * No loop starts/retries a native call; all status/page steps are explicit.
 * Every original SDK is store'd, serialized, Git-created once and whole-read
 * before isError or native text is inspected.
 */
const GF_SLOT = "native_pki_lease400_formatter10_collector_gitfirst_r1";
const GF_REQUEST = {"blob":"22dd45be52462f7a001abf985abe48c523dc48a4","bytes":33330,"sha256":"d16edddff2f496d84fb41eb50fdf266716b274388beb1031baec8111579e2c0f"};

/* One separately approved independent file_info of the actual public collector report.
 * Original collector state is retained. No binary_read or new process is authorized. */
const GF_COLLECTOR_REPORT_EXPECTED = {"path":"/home/qian-qi/heptabao-native-pki-lease400-format-observe-20261106-r1/observation.public.json","bytes":30131,"sha256":"f2d35f46f7fec2d9d9ce81d7e3bd8dca21c9c6f44d5f990314cfd4dcb5c4da46","version":"66306:30842948:30131:1793946915079275200:1793946915079275200","full9":["66306","30842948","1000","1000","33152","1","30131","1793946915079275200","1793946915079275200"]};
const GF_COLLECTOR_REPORT_INFO_REQUEST = {"blob":"da2d04756281187d875950219a8c1e584ea5a029","bytes":291,"sha256":"ef290e736dc818892e12dd00e0a32523b21b3a24b30734fd1aa7fe561cce7e51"};
const GF_COLLECTOR_REPORT_INFO_PREREQUISITES = [{"id":"3ebfdff449e99f89163aa16c0e183420cf29b710506c0f3357cf74c2282c22eb","tool":"process_status","nativeText":{"blob":"1f785781e47d8637ac2249f5f245bdca4435fdcd","bytes":731,"sha256":"ce499b2a8443c1d82364d688198fd01172f10a548a01042aba8a8bc1823c92d5"}},{"id":"db6e1476ae45cbada5e78cfafd6860ad22ad0b2f08192396f64b0abe94174dcf","tool":"process_read","nativeText":{"blob":"a71bdddadc0fa795f0422d17df988f9fc07e831c","bytes":15321,"sha256":"3d868afe45885e93200dea23aa235e80e074cd443d8cfa77e5422857eacf4203"}}];

function gfAuthorizeCollectorReportInfoOnly({goRaw,goPin,goWholeReadback}) {
 const s=gfState();
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null
   && s.activeObserver===null && s.startCalled===true
   && s.job==="1a1af917594-fc05-69b4" && s.collectorReportInfoGO===undefined
   && s.collectorReportInfoStarted!==true,"closed_existing_collector_before_info_only_GO");
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin)
   && goPin.blob!==s.goPin.blob,"separate_whole_info_only_GO");
 const g=JSON.parse(goRaw);
 gfNeed(g.authorization==="GO" && g.scope==="collector_report_file_info_only"
   && g.original_job===s.job && g.maximum_file_info_starts===1
   && g.binary_read_authorized===false
   && g.exact_request?.blob===GF_COLLECTOR_REPORT_INFO_REQUEST.blob
   && g.exact_request?.bytes===GF_COLLECTOR_REPORT_INFO_REQUEST.bytes
   && g.exact_request?.sha256===GF_COLLECTOR_REPORT_INFO_REQUEST.sha256,
   "exact_new_root_file_info_scope");
 for(const need of GF_COLLECTOR_REPORT_INFO_PREREQUISITES) {
  const prior=s.completedObservers.find(o=>o.id===need.id);
  const priorRaw=load(GF_SLOT+":closed_native:"+need.id);
  gfNeed(prior?.completedInactive===true && prior.tool===need.tool
    && gfMetaEquals(priorRaw,need.nativeText)
    && prior.nativeText.blob===need.nativeText.blob,"original_collector_closure_pin");
 }
 const authority=parseLosslessIntegers(load(GF_SLOT+":closed_native:"+GF_COLLECTOR_REPORT_INFO_PREREQUISITES[0].id));
 const streams=parseLosslessIntegers(load(GF_SLOT+":closed_native:"+GF_COLLECTOR_REPORT_INFO_PREREQUISITES[1].id));
 const terminal=parseLosslessIntegers(streams.stdout.text);
 gfNeed(authority.exit_code===0 && authority.output_complete===true
   && authority.output_durable===true && authority.terminal_publication_confirmed===true
   && !authority.timed_out && !authority.cancelled
   && streams.stdout.eof===true && streams.stderr.eof===true
   && s.nextStdout===4775 && s.nextStderr===0
   && terminal.schema==="heptabao.native-pki-formatter10-terminal.v1"
   && terminal.status==="passed" && terminal.error===null && terminal.within_deadline===true
   && terminal.all_owned_fds_once_closed===true && terminal.handlers_restored===true
   && terminal.umask_restored===true && terminal.pending_signal===null
   && terminal.fd_ledger.length===18
   && terminal.fd_ledger.every(x=>x.close_attempted===true && x.closed===true && x.close_error===null)
   && terminal.report.path===GF_COLLECTOR_REPORT_EXPECTED.path
   && terminal.report.bytes===GF_COLLECTOR_REPORT_EXPECTED.bytes
   && terminal.report.sha256===GF_COLLECTOR_REPORT_EXPECTED.sha256
   && terminal.report.version===GF_COLLECTOR_REPORT_EXPECTED.version
   && JSON.stringify(terminal.report.full9)===JSON.stringify(GF_COLLECTOR_REPORT_EXPECTED.full9)
   && terminal.report.same_fd_readback===true && terminal.report.eof===true,
   "collector_zero_full_stdout_and_expected_report");
 s.collectorReportInfoGO={pin:goPin,raw:goRaw,whole:true};
 gfSave(s);
 return {originalJob:s.job,exactRequest:GF_COLLECTOR_REPORT_INFO_REQUEST,
   maximumFileInfoStarts:1,binaryReadAuthorized:false};
}

/* One fixed binary range; SOURCE unbound until the independent info closes.
 * Only these new binary_read observers use 16384-byte immutable pages. */
const GF_COLLECTOR_REPORT_BODY_BOUND = false;
const GF_COLLECTOR_REPORT_BODY_EXPECTED = {"path":"/home/qian-qi/heptabao-native-pki-lease400-format-observe-20261106-r1/observation.public.json","bytes":30131,"sha256":"f2d35f46f7fec2d9d9ce81d7e3bd8dca21c9c6f44d5f990314cfd4dcb5c4da46","version":"66306:30842948:30131:1793946915079275200:1793946915079275200","full9":["66306","30842948","1000","1000","33152","1","30131","1793946915079275200","1793946915079275200"],"infoOperation":null,"infoNative":null};
const GF_COLLECTOR_REPORT_BODY_RANGES = [
  {
    "offset": 0,
    "limit": 30131,
    "request": {
      "blob": "2425ced7f4789632651b30e5b2c95b10a15e51de",
      "bytes": 425,
      "sha256": "9024255e19ba7d8b210147b584c5f2e8a039da384c1843f06bc2fa60fe577fd8"
    }
  }
];
const GF_COLLECTOR_REPORT_BODY_PAGE_BYTES = 16384;

function gfAuthorizeCollectorReportBodyOnly({goRaw,goPin,goWholeReadback}) {
 const s=gfState(),need=GF_COLLECTOR_REPORT_BODY_EXPECTED,info=s.collectorReportInfo;
 gfNeed(GF_COLLECTOR_REPORT_BODY_BOUND===true,"actual_info_binding_required");
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null
   && s.activeObserver===null && s.job==="1a1af917594-fc05-69b4"
   && s.collectorReportInfoGO?.whole===true && s.collectorReportInfoStarted===true
   && s.collectorReportBodyGO===undefined && s.collectorReportBodyStarted===undefined
   && s.collectorReportBodyRanges===undefined,"closed_current_info_before_exact_body_GO");
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin)
   && goPin.blob!==s.goPin.blob && goPin.blob!==s.collectorReportInfoGO.pin.blob,
   "separate_whole_collector_report_body_GO");
 const g=JSON.parse(goRaw);
 gfNeed(g.authorization==="GO" && g.scope==="collector_report_binary_read_ranges_only"
   && g.original_job===s.job && g.info_operation===need.infoOperation
   && g.maximum_binary_read_starts===1 && g.immutable_body_page_bytes===GF_COLLECTOR_REPORT_BODY_PAGE_BYTES
   && g.fixed_report?.path===need.path && g.fixed_report?.bytes===need.bytes
   && g.fixed_report?.sha256===need.sha256 && g.fixed_report?.version===need.version
   && Array.isArray(g.exact_requests) && g.exact_requests.length===GF_COLLECTOR_REPORT_BODY_RANGES.length
   && GF_COLLECTOR_REPORT_BODY_RANGES.every((x,i)=>g.exact_requests[i]?.blob===x.request.blob
     && g.exact_requests[i]?.bytes===x.request.bytes
     && g.exact_requests[i]?.sha256===x.request.sha256),"exact_new_root_one_range_scope");
 const prior=s.completedObservers.find(o=>o.id===need.infoOperation);
 gfNeed(prior?.completedInactive===true && prior.tool==="file_info"
   && prior.nativeText.blob===need.infoNative.blob
   && gfMetaEquals(load(GF_SLOT+":closed_native:"+need.infoOperation),need.infoNative)
   && info?.path===need.path && info.size===need.bytes && info.sha256===need.sha256
   && info.version===need.version && info.originalOperation===need.infoOperation
   && need.bytes>0 && need.bytes<=GF_COLLECTOR_REPORT_EXPECTED.bytes,
   "whole_current_info_exact_identity");
 s.collectorReportBodyGO={pin:goPin,raw:goRaw,whole:true};
 s.collectorReportBodyStarted=0;s.collectorReportBodyRanges=[];
 gfSave(s);
 return {originalJob:s.job,infoOperation:need.infoOperation,
   exactRequests:GF_COLLECTOR_REPORT_BODY_RANGES,maximumBinaryReadStarts:1,
   bodyPageBytes:GF_COLLECTOR_REPORT_BODY_PAGE_BYTES,wholeBytes:need.bytes};
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
    && /^heptabao-native-pki-lease400-format10-observe-r1-/.test(q.idempotency_key),
    "bounded_original_observer_key");
  const op=q.operation,a=op?.arguments;
  gfNeed(op && Object.keys(op).sort().join(",")==="arguments,tool"
    && a && a.host==="rog","same_original_host_only");
  if(op.tool==="binary_read") {
   const index=s.collectorReportBodyRanges?.length,range=GF_COLLECTOR_REPORT_BODY_RANGES[index];
   gfNeed(s.collectorReportBodyGO?.whole===true && range
     && s.collectorReportBodyStarted===index && gfMetaEquals(raw,range.request)
     && Object.keys(a).sort().join(",")==="expected_version,host,limit,offset,path"
     && a.path===GF_COLLECTOR_REPORT_BODY_EXPECTED.path && a.offset===range.offset
     && a.limit===range.limit && a.limit>0 && a.limit<=65536
     && a.expected_version===GF_COLLECTOR_REPORT_BODY_EXPECTED.version,
     "one_exact_next_version_bound_collector_report_body_range");
  } else if(op.tool==="file_info") {
   gfNeed(s.collectorReportInfoGO?.whole===true && s.collectorReportInfoStarted!==true
     && gfMetaEquals(raw,GF_COLLECTOR_REPORT_INFO_REQUEST)
     && Object.keys(a).sort().join(",")==="host,path"
     && a.path===GF_COLLECTOR_REPORT_EXPECTED.path,"one_exact_collector_report_info");
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
   && q.operation_id===s.activeObserver.id
   && q.limit===(s.activeObserver.tool==="binary_read"?GF_COLLECTOR_REPORT_BODY_PAGE_BYTES:8192)
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
    || s.activeObserver?.tool==="binary_read") ? s.collectorReportBodyGO.pin
    : ((kind==="operation_start" && q.operation.tool==="file_info")
      || s.activeObserver?.tool==="file_info") ? s.collectorReportInfoGO.pin : s.goPin,
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
 if(c.kind==="operation_start" && q.operation.tool==="file_info")s.collectorReportInfoStarted=true;
 if(c.kind==="operation_start" && q.operation.tool==="binary_read")s.collectorReportBodyStarted++;
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
   gfNeed(b.length<=(a.tool==="binary_read"?GF_COLLECTOR_REPORT_BODY_PAGE_BYTES:8192)
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
   const need=GF_COLLECTOR_REPORT_BODY_EXPECTED,index=s.collectorReportBodyRanges.length,
     range=GF_COLLECTOR_REPORT_BODY_RANGES[index],asked=a.request.operation.arguments;
   gfNeed(range && s.collectorReportBodyStarted===index+1
     && asked.offset===range.offset && asked.limit===range.limit
     && v.path===need.path && v.version===need.version && v.size===need.bytes
     && v.offset===range.offset && v.next_offset===range.offset+range.limit
     && v.eof===(v.next_offset===need.bytes)
     && typeof v.data_base64==="string" && /^[a-f0-9]{64}$/.test(v.chunk_sha256),
     "exact_collector_report_body_original_range_extent");
   const bodyBytes=unb64(v.data_base64);
   gfNeed(bodyBytes.length===range.limit
     && sha256Latin1(byteString(bodyBytes))===v.chunk_sha256,
     "collector_report_body_actual_chunk_bytes_SHA");
   const row={offset:range.offset,limit:range.limit,next:v.next_offset,
     chunkSHA256:v.chunk_sha256,base64:v.data_base64,originalOperation:a.id,
     originalPayload:pin,originalPayloadTree:archive.tree};
   if(index+1===GF_COLLECTOR_REPORT_BODY_RANGES.length) {
    const ranges=s.collectorReportBodyRanges.concat([row]);
    let complete=[],at=0;
    for(const part of ranges) {
     gfNeed(part.offset===at,"collector_report_body_whole_continuity");
     complete=complete.concat(unb64(part.base64));at=part.next;
    }
    gfNeed(at===need.bytes && complete.length===need.bytes
      && sha256Latin1(byteString(complete))===need.sha256,"collector_report_body_whole_exact_SHA");
    const wholeRaw=utf8Text(complete),wholePin=gitBlobMeta(wholeRaw);
    gfNeed(wholePin.bytes===need.bytes && wholePin.sha256===need.sha256,
      "collector_report_report_whole_UTF8_roundtrip");
    store(GF_SLOT+":collector_report_body_original",wholeRaw);
    const wholeArchive=await archiveFlatPublicTextsOnce({
     key:"pki-format10-collector-public-report-whole-r1",repository:"TrillionniumFoundation/HeptaBao",
     texts:{"observation.public.json":wholeRaw}});
    s.collectorReportBody={path:need.path,version:need.version,body:wholePin,
      wholeTree:wholeArchive.tree,originalOperations:ranges.map(x=>x.originalOperation),
      metadataOperation:need.infoOperation,semanticQualification:false};
   }
   s.collectorReportBodyRanges.push(row);
  } else if(a.tool==="file_info") {
   const md=v.metadata,parts=typeof v.version==="string"?v.version.split(":"):[];
   gfNeed(v.path===GF_COLLECTOR_REPORT_EXPECTED.path
     && v.size===GF_COLLECTOR_REPORT_EXPECTED.bytes
     && v.sha256===GF_COLLECTOR_REPORT_EXPECTED.sha256
     && v.version===GF_COLLECTOR_REPORT_EXPECTED.version && v.mode===384
     && md?.metadata_platform==="linux" && md.mode===384
     && md.uid===1000 && md.gid===1000 && md.link_count===1
     && parts.length===5 && parts.every(x=>/^[0-9]+$/.test(x))
     && parts[2]===String(v.size),"fixed_report_exact_content_metadata_and_version");
   const full9=[parts[0],parts[1],"1000","1000",String(32768|v.mode),
     "1",String(v.size),parts[3],parts[4]];
   gfNeed(JSON.stringify(full9)===JSON.stringify(GF_COLLECTOR_REPORT_EXPECTED.full9),
     "fixed_report_exact_full9");
   s.collectorReportInfo={path:v.path,size:v.size,sha256:v.sha256,version:v.version,
     nativeText:gitBlobMeta(nativeRaw),originalOperation:a.id,full9Strings:full9,
     regularFileFromNativeFileInfoContract:true,binaryReadAuthorized:false};
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
  else if(action==="authorize_collector_report_info")value=gfAuthorizeCollectorReportInfoOnly(args);
  else if(action==="authorize_collector_report_body")value=gfAuthorizeCollectorReportBodyOnly(args);
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
