/* SOURCE ONLY: native-call archival substitute proposed for the local outage.
 * Requires pure_helpers.js plus git_archive_once.js in the same V8 evaluation.
 * No function below is invoked by loading this file. Root exact GO is separate.
 * No loop starts/retries a native call; all status/page steps are explicit.
 * Every original SDK is store'd, serialized, Git-created once and whole-read
 * before isError or native text is inspected.
 */
const GF_SLOT = "official271_x230_acl23_oracle_gitfirst_r2";
const GF_REQUEST = {"blob":"e2a92c388ec7167f14b33cc9c2a03d82aae3bda4","bytes":164759,"sha256":"9ea5802b1ed39410eb2e83d5d7bebd6dfe44812271ac53da47863b884214f190"};

const GF_ORACLE_REPORT_INFO_REQUEST = {"blob":"75ae686fdb5be9d3d4f083f810e84513fbe7631f","bytes":267,"sha256":"ff233ed978f5812858c1012cdc3411b2c6b6b2fa8f86558c869dfc4415b8e006"};
const GF_ORACLE_REPORT_INFO_TARGET = {"path":"/home/qian/heptabao-official271-acl23-oracle-20261106-r2/result.public.json","bytes":651803,"sha256":"9048f3b5c854a190dadde86f5d7eec180c497313065bd70bd23a87124789a62d","full9Strings":["2053","2098461","1000","1000","33152","1","651803","1793982810542000556","1793982810542000556"]};
const GF_ORACLE_REPORT_PRIOR_STATE = {"blob":"f75c8cdfbda60bf8059b5ddf2ef058431d97ec02","bytes":214063,"sha256":"ea3a61cc35c1d17dd6b187d36ff6f5ca7ac289d9bed387345ea326886a61f178"};
const GF_ORACLE_REPORT_STDOUT = {"blob":"8ba51a89419cb8be7c215bea6f29677c9de258d8","bytes":681,"sha256":"958d53e5de547b3a36a048411eae3ed457ee20d336e4c52a4f7abb9a6c41d875"};

/* One actual version, ten contiguous ranges; only new binary observers use 16 KiB pages. */
const GF_ORACLE_BODY_EXPECTED = {"path":"/home/qian/heptabao-official271-acl23-oracle-20261106-r2/result.public.json","bytes":651803,"sha256":"9048f3b5c854a190dadde86f5d7eec180c497313065bd70bd23a87124789a62d","version":"2053:2098461:651803:1793982810542000556:1793982810542000556","infoOperation":"fb33dec05df1603940b92929c9cb75c6990fa6d0c1ca281f1a317d8221edfc47","infoNative":{"blob":"5de2fd1d0891ce3fee0bb3b4e3968452e7715dcd","bytes":463,"sha256":"50afd94d7cb022e910476f5812f78beb008323cb042a378182a32c99761893d7"},"full9Strings":["2053","2098461","1000","1000","33152","1","651803","1793982810542000556","1793982810542000556"]};
const GF_ORACLE_BODY_RANGES = [
  {
    "offset": 0,
    "limit": 65536,
    "request": {
      "blob": "af4e5d3b2a3e4a3e995c87b3b5c8edf902910a68",
      "bytes": 326,
      "sha256": "93a2f825b56df42871bc8e4529d27e9f5ace353aec6c6abed678497a5eab4979"
    }
  },
  {
    "offset": 65536,
    "limit": 65536,
    "request": {
      "blob": "4064a4b95b3333f4c4f5b487decb7c1d299cd1e6",
      "bytes": 330,
      "sha256": "70feb42f03317c7589056b8b1a639932cdfe608ac2e806a1daaacf9a52acd02e"
    }
  },
  {
    "offset": 131072,
    "limit": 65536,
    "request": {
      "blob": "3be4277978fa7422d4d70d4ca3239f91a7006ce6",
      "bytes": 331,
      "sha256": "917bfc19c6b300654f742555eccee4d5d8d1a6b60472da0d686e97a0432e0ae2"
    }
  },
  {
    "offset": 196608,
    "limit": 65536,
    "request": {
      "blob": "5bb0631c792c014e14dd772f522fd5bca6198621",
      "bytes": 331,
      "sha256": "8da81d14bf4c561ce4c0560c23a46a15cadfa571dda943e3905e15d4aa05ac4c"
    }
  },
  {
    "offset": 262144,
    "limit": 65536,
    "request": {
      "blob": "5589350ca22a464f0655d34b277558a41c537b46",
      "bytes": 331,
      "sha256": "1f399bb67128888b8d72d5a05d602c980845b5f527f949376b40e7a6cbec2b4e"
    }
  },
  {
    "offset": 327680,
    "limit": 65536,
    "request": {
      "blob": "1e4b5491e3507fe198fa71f139ea52f94672f6a5",
      "bytes": 331,
      "sha256": "4ea9b21ed5b45381ff569fe74b00c0b2268606541ce550f5d912441e03c97984"
    }
  },
  {
    "offset": 393216,
    "limit": 65536,
    "request": {
      "blob": "83f4a370ba4fbc52971e4a4142cbe013532507d5",
      "bytes": 331,
      "sha256": "f3c32901ac9cb9d9e921cbbf580d2eee9f65385847f0ad785db747cc280269bd"
    }
  },
  {
    "offset": 458752,
    "limit": 65536,
    "request": {
      "blob": "279f53810a412e76b2b1f0a8e4341ef7fab6d0d2",
      "bytes": 331,
      "sha256": "5c5dd34279d052e8282ef0ca5977a8cf52da72cb2ab679e0e33aa540a14dd58c"
    }
  },
  {
    "offset": 524288,
    "limit": 65536,
    "request": {
      "blob": "2acf5b82bffb12ca4fadaff883b1255c90edffb8",
      "bytes": 331,
      "sha256": "83ef20e19bf5cef3fc0e6d8c186faf46f0bad2fd0ed2bd120eca68d61ef03bcc"
    }
  },
  {
    "offset": 589824,
    "limit": 61979,
    "request": {
      "blob": "107e4cd0d7cbe4c2f1aed3422d120e8cbda448aa",
      "bytes": 331,
      "sha256": "19f1f7c23373d1ea2627af34676e6676748bb6a56370ab24a7de31159a86eaf1"
    }
  }
];
const GF_ORACLE_BODY_PRIOR_STATE = {"blob":"b4206a027c1584bf5a0bcaaf54d1cec9dc1ce036","bytes":227036,"sha256":"0fe475c8bebb1fa287c9aa9e944731ae4618edd9f87ced4e852b3b9b48e9faba"};
const GF_ORACLE_BODY_PAGE_BYTES = 16384;

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
function gfAuthorizeOracleReportInfo({goRaw,goPin,goWholeReadback,priorStateRaw,stdoutRaw}) {
 const s=gfState();
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin),"whole_report_info_GO");
 const g=JSON.parse(goRaw);
 gfNeed(g.authorization==="GO" && g.scope==="official271_oracle_result_file_info_only"
   && g.original_job==="1a1b1b4fbfa-fc05-7a60"
   && g.maximum_file_info_operations===1 && g.maximum_process_start_calls===0
   && g.maximum_binary_read_operations===0
   && JSON.stringify(g.exact_request)===JSON.stringify(GF_ORACLE_REPORT_INFO_REQUEST),
   "one_exact_oracle_report_info_authority");
 gfNeed(gfMetaEquals(priorStateRaw,GF_ORACLE_REPORT_PRIOR_STATE)
   && JSON.stringify(s,null,2)+"\n"===priorStateRaw
   && s.job==="1a1b1b4fbfa-fc05-7a60" && s.startCalled===true
   && !s.paused && !s.nativeCallInFlight && s.pending===null && s.activeObserver===null
   && Object.keys(s.calls).length===7 && s.completedObservers.length===2
   && s.completedObservers.every(o=>o.completedInactive===true)
   && Object.values(s.calls).every(c=>c.phase==="accepted"&&c.sdkArchive?.whole===true)
   && s.oracleReportInfoGO===undefined,"original_r2_fixture_whole_closed_boundary");
 gfNeed(gfMetaEquals(stdoutRaw,GF_ORACLE_REPORT_STDOUT),"actual_terminal_stdout_whole");
 const terminal=JSON.parse(stdoutRaw),r=terminal.report;
 gfNeed(terminal.capture_complete===true && terminal.failure===null
   && terminal.all_entry_file_descriptors_closed===true && terminal.entry_fd_count===12
   && terminal.pending_signal===null && r?.relative==="result.public.json" && r.closed===true
   && r.bytes===GF_ORACLE_REPORT_INFO_TARGET.bytes && r.sha256===GF_ORACLE_REPORT_INFO_TARGET.sha256
   && JSON.stringify(r.full9_decimal)===JSON.stringify(GF_ORACLE_REPORT_INFO_TARGET.full9Strings),
   "actual_r2_terminal_binds_one_report_only");
 s.oracleReportInfoGO={raw:goRaw,pin:goPin,whole:true};
 s.onlyOracleReportInfo=true;s.oracleReportInfoStarted=false;s.oracleReportInfo=null;
 gfSave(s);
 return {authorized:true,scope:g.scope,maximumNativeAdmissions:1,processStartAllowed:false,binaryReadAllowed:false};
}
function gfAuthorizeOracleReportBody({goRaw,goPin,goWholeReadback,priorStateRaw}) {
 const s=gfState(),need=GF_ORACLE_BODY_EXPECTED,info=s.oracleReportInfo;
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null && s.activeObserver===null
   && s.job==="1a1b1b4fbfa-fc05-7a60" && s.oracleReportInfoGO?.whole===true
   && s.oracleReportInfoStarted===true && s.oracleReportBodyGO===undefined
   && s.oracleReportBodyStarted===undefined && s.oracleReportBodyRanges===undefined
   && Object.keys(s.calls).length===10 && s.completedObservers.length===3
   && s.completedObservers.every(o=>o.completedInactive===true)
   && Object.values(s.calls).every(c=>c.phase==="accepted"&&c.sdkArchive?.whole===true)
   && gfMetaEquals(priorStateRaw,GF_ORACLE_BODY_PRIOR_STATE)
   && JSON.stringify(s,null,2)+"\n"===priorStateRaw,
   "whole_closed_current_r2_INFO_before_exact_body_GO");
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin)
   && goPin.blob!==s.goPin.blob && goPin.blob!==s.oracleReportInfoGO.pin.blob,
   "separate_whole_oracle_body_GO");
 const g=JSON.parse(goRaw);
 gfNeed(g.authorization==="GO" && g.scope==="official271_oracle_result_binary_read_ranges_only"
   && g.original_job===s.job && g.info_operation===need.infoOperation
   && g.maximum_binary_read_starts===10 && g.maximum_file_info_operations===0
   && g.maximum_process_start_calls===0 && g.immutable_body_page_bytes===GF_ORACLE_BODY_PAGE_BYTES
   && g.maximum_operation_status_calls_per_id===8 && g.maximum_immutable_pages_per_id===128
   && g.fixed_report?.path===need.path && g.fixed_report?.bytes===need.bytes
   && g.fixed_report?.sha256===need.sha256 && g.fixed_report?.version===need.version
   && Array.isArray(g.exact_requests) && g.exact_requests.length===GF_ORACLE_BODY_RANGES.length
   && GF_ORACLE_BODY_RANGES.every((x,i)=>g.exact_requests[i]?.blob===x.request.blob
     && g.exact_requests[i]?.bytes===x.request.bytes
     && g.exact_requests[i]?.sha256===x.request.sha256),
   "exact_root_ten_range_scope");
 const prior=s.completedObservers.find(o=>o.id===need.infoOperation);
 gfNeed(prior?.completedInactive===true && prior.tool==="file_info"
   && prior.nativeText.blob===need.infoNative.blob
   && gfMetaEquals(load(GF_SLOT+":closed_native:"+need.infoOperation),need.infoNative)
   && info?.path===need.path && info.size===need.bytes && info.sha256===need.sha256
   && info.version===need.version && info.originalOperation===need.infoOperation
   && JSON.stringify(info.full9Strings)===JSON.stringify(need.full9Strings)
   && need.bytes>0 && need.bytes<=1048576,
   "whole_current_INFO_version_SHA_full9");
 s.oracleReportBodyGO={pin:goPin,raw:goRaw,whole:true};
 s.onlyOracleReportInfo=false;s.onlyOracleReportBody=true;
 s.oracleReportBodyStarted=0;s.oracleReportBodyRanges=[];
 gfSave(s);
 return {originalJob:s.job,infoOperation:need.infoOperation,
   exactRequests:GF_ORACLE_BODY_RANGES,maximumBinaryReadStarts:10,
   bodyPageBytes:GF_ORACLE_BODY_PAGE_BYTES,wholeBytes:need.bytes};
}
function gfValidateRequest(s,kind,q,raw) {
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null,"single_call_boundary");
 gfNeed(s.oracleReportBodyGO?.whole===true && s.onlyOracleReportBody===true,
        "separate_report_body_GO_before_any_new_call");
 if(kind==="process_start") {
  throw new Error("report_body_has_no_process_start_authorization");
 } else if(kind==="operation_start") {
  const index=s.oracleReportBodyRanges.length,range=GF_ORACLE_BODY_RANGES[index],a=q.operation?.arguments;
  gfNeed(s.activeObserver===null && range && s.oracleReportBodyStarted===index
   && s.completedObservers.length===3+index && gfMetaEquals(raw,range.request)
   && q.operation?.tool==="binary_read" && a?.host==="x230"
   && Object.keys(a).sort().join(",")==="expected_version,host,limit,offset,path"
   && a.path===GF_ORACLE_BODY_EXPECTED.path && a.offset===range.offset
   && a.limit===range.limit && a.limit>0 && a.limit<=65536
   && a.expected_version===GF_ORACLE_BODY_EXPECTED.version,
   "one_exact_next_version_bound_oracle_body_range");
 } else if(kind==="operation_status") {
  gfNeed(s.activeObserver && !s.activeObserver.futureClosed
   && Object.keys(q).join(",")==="operation_id"
   && q.operation_id===s.activeObserver.id
   && Object.values(s.calls).filter(c=>c.kind==="operation_status"&&c.called===true
      && JSON.parse(c.requestRaw).operation_id===q.operation_id).length<8,
   "same_live_original_operation_status_within_eight");
 } else if(kind==="operation_result") {
  gfNeed(s.activeObserver?.futureClosed===true
   && Object.keys(q).sort().join(",")==="limit,offset,operation_id"
   && q.operation_id===s.activeObserver.id
   && q.limit===(s.activeObserver.tool==="binary_read"?GF_ORACLE_BODY_PAGE_BYTES:8192)
   && q.offset===s.activeObserver.nextPageOffset && !s.activeObserver.eof
   && s.activeObserver.pages.length<128,
   "same_closed_original_operation_next_page_within_128");
 } else throw new Error("closed_native_tool_set");
}
async function gfPrepareOne({callKey,kind,requestRaw}) {
 const s=gfState();
 gfNeed(/^[a-z0-9][a-z0-9-]{0,70}$/.test(callKey) && !s.calls[callKey],"fresh_call_record");
 const q=JSON.parse(requestRaw); // Public exact request, no native response.
 gfValidateRequest(s,kind,q,requestRaw);
 const requestPin=gitBlobMeta(requestRaw);
 const intent={schema:"heptabao.gitfirst.fixed-native-call-intent.r1",
  callKey,kind,request:requestPin,rootGo:s.oracleReportBodyGO?.pin??s.oracleReportInfoGO?.pin??s.goPin,originalJob:s.job,
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
 if(c.kind==="operation_start")s.oracleReportBodyStarted+=1;
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
    && v.launch?.ok===true && v.job?.host==="x230" && v.job.execution_mode==="operator"
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
   gfNeed(b.length<=(a.tool==="binary_read"?GF_ORACLE_BODY_PAGE_BYTES:8192) && v.next_offset===q.offset+b.length
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
   const need=GF_ORACLE_BODY_EXPECTED,index=s.oracleReportBodyRanges.length,
     range=GF_ORACLE_BODY_RANGES[index],asked=a.request.operation.arguments;
   gfNeed(range && s.oracleReportBodyStarted===index+1
     && asked.offset===range.offset && asked.limit===range.limit
     && v.path===need.path && v.version===need.version && v.size===need.bytes
     && v.offset===range.offset && v.next_offset===range.offset+range.limit
     && v.eof===(v.next_offset===need.bytes)
     && typeof v.data_base64==="string" && /^[a-f0-9]{64}$/.test(v.chunk_sha256),
     "exact_oracle_body_original_range_extent");
   const bodyBytes=unb64(v.data_base64);
   gfNeed(bodyBytes.length===range.limit
     && sha256Latin1(byteString(bodyBytes))===v.chunk_sha256,
     "oracle_body_actual_chunk_bytes_SHA");
   const row={offset:range.offset,limit:range.limit,next:v.next_offset,
     chunkSHA256:v.chunk_sha256,base64:v.data_base64,originalOperation:a.id,
     originalPayload:pin,originalPayloadTree:archive.tree};
   if(index+1===GF_ORACLE_BODY_RANGES.length) {
    const ranges=s.oracleReportBodyRanges.concat([row]);
    let complete=[],at=0;
    for(const part of ranges) {
     gfNeed(part.offset===at,"oracle_body_whole_continuity");
     complete=complete.concat(unb64(part.base64));at=part.next;
    }
    gfNeed(at===need.bytes && complete.length===need.bytes
      && sha256Latin1(byteString(complete))===need.sha256,"oracle_body_whole_exact_SHA");
    const wholeRaw=utf8Text(complete),wholePin=gitBlobMeta(wholeRaw);
    gfNeed(wholePin.bytes===need.bytes && wholePin.sha256===need.sha256,
      "oracle_report_whole_UTF8_roundtrip");
    store(GF_SLOT+":oracle_report_body_original",wholeRaw);
    const wholeArchive=await archiveFlatPublicTextsOnce({
     key:"official271-acl23-r2-report-whole",repository:"TrillionniumFoundation/HeptaBao",
     texts:{"result.public.json":wholeRaw}});
    s.oracleReportBody={path:need.path,version:need.version,body:wholePin,
      wholeTree:wholeArchive.tree,originalOperations:ranges.map(x=>x.originalOperation),
      metadataOperation:need.infoOperation,semanticQualification:false};
   }
   s.oracleReportBodyRanges.push(row);
  } else if(a.tool==="file_info") {
   const t=GF_ORACLE_REPORT_INFO_TARGET,md=v.metadata,parts=typeof v.version==="string"?v.version.split(":"):[];
   gfNeed(s.onlyOracleReportInfo===true && s.oracleReportInfoStarted===true && s.oracleReportInfo===null
    && a.request.operation.arguments.host==="x230" && a.request.operation.arguments.path===t.path
    && v.path===t.path && v.size===t.bytes && v.size<=1048576 && v.sha256===t.sha256
    && v.mode===384 && md?.metadata_platform==="linux" && md.mode===384
    && md.uid===1000 && md.gid===1000 && md.link_count===1
    && parts.length===5 && parts.every(x=>/^[0-9]+$/.test(x)) && parts[2]===String(v.size),
    "exact_report_metadata_SHA_mode_version");
   const full9=[parts[0],parts[1],"1000","1000",String(32768|v.mode),"1",String(v.size),parts[3],parts[4]];
   gfNeed(JSON.stringify(full9)===JSON.stringify(t.full9Strings),"actual_stdout_and_independent_report_full9_equal");
   s.oracleReportInfo={path:v.path,size:v.size,sha256:v.sha256,version:v.version,
    full9Strings:full9,originalOperation:a.id,nativeText:gitBlobMeta(nativeRaw),
    regularFileFromNativeFileInfoContract:true,bodyReadAuthorized:false};
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
  if(action==="authorize_oracle_report_body")value=gfAuthorizeOracleReportBody(args);
  else if(action==="authorize_oracle_report_info")value=gfAuthorizeOracleReportInfo(args);
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
