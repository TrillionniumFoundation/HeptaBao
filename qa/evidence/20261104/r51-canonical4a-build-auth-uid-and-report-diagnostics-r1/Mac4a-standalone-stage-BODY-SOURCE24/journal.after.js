/* Standalone single-report BODY successor of the executed exact-version report journal.
 * Original paused stage/INFO and completed immutable retrieval contexts are read-only.
 * One new exact BODY GO is required; no function runs on load. Original SDK/payload/body whole order retained.
 * Status8/pages128/payload1MiB; binary16KiB versus INFO8KiB acceptance is unchanged. */
const GF_SLOT = "successor4a_mac_stage_report_body_gitfirst_r1";
const GF_ORACLE_REPORT_BODY_REQUEST = {"blob":"a24a188ed159093a3f60ab439deb7dc53ba6ef61","bytes":428,"sha256":"9966fa785adda9eb2b855277fab800e71a59ebfe5810a7a3247bea70f089f142"};
const GF_ORACLE_REPORT_BODY_TARGET = {"host":"mac","path":"/Volumes/T5/hepta-vnext-recovery-20261013/hb-4a49405b-src-20261106-r1/control/stage-result.public.json","bytes":7685,"sha256":"4300d0cd7fc96eee76d2e8430b75991f50e07971018d2a9c6bd03fe5b6ccdaa2","version":"16777244:72771947:7685:1794013039551370413:1794013039551379746","full9Strings":["16777244","72771947","501","20","33152","1","7685","1794013039551370413","1794013039551379746"],"platform":"darwin","infoOperation":"de877b50d2ab34adac0ab37da7e2de06bb44b9b993da97c20b7bca92592bdd39","infoNative":{"blob":"fe58365faf209bc91dac4a87c5ada5a7a6d6ecf3","bytes":489,"sha256":"5a38716e9743604e6b829a9178f5ad642a65bfb858a58118c8c2aa79ad2b664f"}};
const GF_ORACLE_REPORT_BODY_PAGE_BYTES = 16384;
const GF_OLD_SLOT = "successor4a_mac_source_only_stage_gitfirst_r1";
const GF_OLD_STATE = {"blob":"c430ef8d263c59dfced528e9a6b35a19004b162f","bytes":69161,"sha256":"61b9e20f71244ac11c2b304a70eee0ee6f218cacb5a7fe382483f61cb632b93b"};
const GF_RETRIEVAL_SLOT = "successor4a_mac_stage_info_page0_retrieval_r1";
const GF_RETRIEVAL_STATE = {"blob":"670606feaab7a5947d02374ddf8773c7a4928d73","bytes":2815,"sha256":"25be8ac2e6f5c72a684401865aff56958f8dc3906245580038cad3e650d5d5c9"};
const GF_RETRIEVAL_PAYLOAD = {"blob":"abe5bfbf7fe74a688651876df7e2d05e46f94459","bytes":606,"sha256":"cc0144f9aba8b7c97b0cdea0233ba674e76803777ed263a37a1b14359dd5350f"};

function gfFrozenPredecessors() {
 gfNeed(gfMetaEquals(JSON.stringify(load(GF_OLD_SLOT),null,2)+"\n",GF_OLD_STATE),
  "original_paused_stage_INFO_unchanged");
 const s=load(GF_RETRIEVAL_SLOT),raw=load(GF_RETRIEVAL_SLOT+":payload-original");
 gfNeed(gfMetaEquals(JSON.stringify(s,null,2)+"\n",GF_RETRIEVAL_STATE)
  && s.closed===true && s.paused===false && s.inflight===false
  && s.payloadArchive?.whole===true && gfMetaEquals(raw,GF_RETRIEVAL_PAYLOAD),
  "completed_independent_original_INFO_retrieval_unchanged");
 const p=parseLosslessIntegers(raw);
 gfNeed(p.resultType==="complete" && p.isError===false && p.content?.length===1
  && p.content[0].type==="text" && gfMetaEquals(p.content[0].text,GF_ORACLE_REPORT_BODY_TARGET.infoNative),
  "whole_original_INFO_native_exact");
}
function gfNeed(value, code) { if(!value) throw new Error(code); }
function gfMetaEquals(raw,pin) {
 const actual=gitBlobMeta(raw);
 return actual.blob===pin.blob && actual.bytes===pin.bytes && actual.sha256===pin.sha256;
}
function gfState() {
 gfFrozenPredecessors();
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
function gfInitializeOnlyAfterRootGO({goRaw,goPin,goWholeReadback}) {
 gfFrozenPredecessors();
 gfNeed(load(GF_SLOT)===undefined,"new_BODY_context_once_no_old_slot_reset");
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin),"exact_whole_new_BODY_GO");
 const g=JSON.parse(goRaw),t=GF_ORACLE_REPORT_BODY_TARGET;
 gfNeed(g.authorization==="GO" && g.scope==="mac4a_stage_result_binary_read_only"
  && g.info_operation===t.infoOperation && g.maximum_binary_read_operations===1
  && g.maximum_file_info_operations===0 && g.maximum_process_start_calls===0
  && g.immutable_body_page_bytes===GF_ORACLE_REPORT_BODY_PAGE_BYTES
  && JSON.stringify(g.exact_request)===JSON.stringify(GF_ORACLE_REPORT_BODY_REQUEST)
  && JSON.stringify(g.original_paused_state)===JSON.stringify(GF_OLD_STATE)
  && JSON.stringify(g.completed_retrieval_state)===JSON.stringify(GF_RETRIEVAL_STATE)
  && g.no_old_slot_handback===true && g.fixed_report?.path===t.path
  && g.fixed_report?.bytes===t.bytes && g.fixed_report?.sha256===t.sha256
  && g.fixed_report?.version===t.version
  && JSON.stringify(g.fixed_report?.full9Strings)===JSON.stringify(t.full9Strings),
  "exact_standalone_body_scope_and_actual_metadata");
 const p=parseLosslessIntegers(load(GF_RETRIEVAL_SLOT+":payload-original")),
  v=parseLosslessIntegers(p.content[0].text),md=v.metadata,parts=v.version.split(":");
 gfNeed(v.path===t.path && v.size===t.bytes && v.sha256===t.sha256 && v.version===t.version
  && Number.isSafeInteger(v.size) && v.size>0 && v.size<=65536 && v.mode===384
  && md?.metadata_platform===t.platform && md.mode===384 && md.uid===501
  && Number.isSafeInteger(md.gid) && md.gid>=0 && md.link_count===1
  && parts.length===5 && parts.every(x=>/^[0-9]+$/.test(x))
  && parts[2]===String(v.size)
  && JSON.stringify([parts[0],parts[1],"501",String(md.gid),"33152","1",String(v.size),parts[3],parts[4]])
    ===JSON.stringify(t.full9Strings),"actual_original_INFO_full_identity");
 store(GF_SLOT,{rootGoWhole:true,goRaw,goPin,digest:null,fingerprint:null,job:null,
  startCalled:false,pending:null,activeObserver:null,nativeCallInFlight:false,
  paused:false,calls:{},completedObservers:[],nextStdout:0,nextStderr:0,
  localJournalAvailable:false,gitFirstExplicitlyRequiredByThisRootGO:true,
  oracleReportBodyGO:{raw:goRaw,pin:goPin,whole:true},
  onlyOracleReportBody:true,oracleReportBodyStarted:false,oracleReportBody:null});
 return {initialized:true,originalJob:null,maximumBinaryReadOperations:1,
  oldStageInfoStateUnchanged:true,completedRetrievalStateUnchanged:true};
}

function gfValidateRequest(s,kind,q,raw) {
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null,"single_call_boundary");
 gfNeed(s.oracleReportBodyGO?.whole===true && s.onlyOracleReportBody===true && s.job===null,
        "standalone_report_BODY_GO_before_any_new_call");
 if(kind==="process_start") {
  throw new Error("report_BODY_has_no_process_start_authorization");
 } else if(kind==="operation_start") {
  if(q.operation?.tool==="binary_read") {
   const a=q.operation.arguments,t=GF_ORACLE_REPORT_BODY_TARGET;
   gfNeed(s.oracleReportBodyGO?.whole===true && s.onlyOracleReportBody===true
    && s.activeObserver===null && s.oracleReportBodyStarted===false && s.oracleReportBody===null
    && gfMetaEquals(raw,GF_ORACLE_REPORT_BODY_REQUEST)
    && Object.keys(q).sort().join(",")==="idempotency_key,operation"
    && Object.keys(q.operation).sort().join(",")==="arguments,tool"
    && Object.keys(a).sort().join(",")==="expected_version,host,limit,offset,path"
    && a.host==="mac" && a.path===t.path && a.offset===0 && a.limit===t.bytes
    && a.limit>0 && a.limit<=65536 && a.expected_version===t.version,"only_one_exact_report_body");
   return;
  }
  throw new Error("BODY_scope_rejects_file_info_and_all_other_tools");
 } else if(kind==="operation_status") {
  gfNeed(Object.values(s.calls).filter(c=>c.kind==="operation_status" && c.called
   && JSON.parse(c.requestRaw).operation_id===s.activeObserver?.id).length<8,"original_status_budget_eight");
  gfNeed(s.activeObserver && !s.activeObserver.futureClosed
   && Object.keys(q).join(",")==="operation_id"
   && q.operation_id===s.activeObserver.id,"same_live_original_operation_status");
 } else if(kind==="operation_result") {
  gfNeed(Object.values(s.calls).filter(c=>c.kind==="operation_result" && c.called
   && JSON.parse(c.requestRaw).operation_id===s.activeObserver?.id).length<128,"original_page_budget_128");
  gfNeed(s.activeObserver?.futureClosed===true
   && Object.keys(q).sort().join(",")==="limit,offset,operation_id"
   && q.operation_id===s.activeObserver.id
   && q.limit===(s.activeObserver.tool==="binary_read"?GF_ORACLE_REPORT_BODY_PAGE_BYTES:8192)
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
 if(c.kind==="operation_start" && q.operation.tool==="binary_read")s.oracleReportBodyStarted=true;
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
   gfNeed(b.length<=(a.tool==="binary_read"?GF_ORACLE_REPORT_BODY_PAGE_BYTES:8192) && v.next_offset===q.offset+b.length
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
   const t=GF_ORACLE_REPORT_BODY_TARGET,asked=a.request.operation.arguments;
   gfNeed(s.oracleReportBodyGO?.whole===true && s.onlyOracleReportBody===true
    && s.oracleReportBodyStarted===true && s.oracleReportBody===null
    && asked.host==="mac" && asked.path===t.path && asked.offset===0 && asked.limit===t.bytes
    && asked.expected_version===t.version && v.path===t.path && v.size===t.bytes
    && v.version===t.version && v.offset===0 && v.next_offset===t.bytes && v.eof===true
    && typeof v.data_base64==="string" && v.chunk_sha256===t.sha256,
    "one_original_report_BODY_exact_extent");
   const body=unb64(v.data_base64);
   gfNeed(body.length===t.bytes && encodeBase64Bytes(body)===v.data_base64
    && sha256Latin1(byteString(body))===t.sha256,"whole_actual_report_BODY_SHA");
   const bodyRaw=utf8Text(body),bodyPin=gitBlobMeta(bodyRaw);
   gfNeed(bodyPin.bytes===t.bytes && bodyPin.sha256===t.sha256,"exact_public_UTF8_report");
   // Operation-derived archive key is unique; no inherited candidate literal.
   const bodyArchive=await archiveFlatPublicTextsOnce({key:"gfr-"+a.id,
    repository:"TrillionniumFoundation/HeptaBao",texts:{"report.original.json":bodyRaw}});
   s.oracleReportBody={path:t.path,version:t.version,bytes:t.bytes,sha256:t.sha256,
    originalOperation:a.id,bodyPin,bodyTree:bodyArchive.tree,whole:true};
   store(GF_SLOT+":report_body_original",bodyRaw);
  } else throw new Error("standalone_BODY_observer_tool_only");
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
