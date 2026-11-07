/* SOURCE ONLY: native-call archival substitute proposed for the local outage.
 * Requires pure_helpers.js plus git_archive_once.js in the same V8 evaluation.
 * No function below is invoked by loading this file. Root exact GO is separate.
 * No loop starts/retries a native call; all status/page steps are explicit.
 * Every original SDK is store'd, serialized, Git-created once and whole-read
 * before isError or native text is inspected.
 */
const GF_SLOT = "successor4a_mac_canonical_bundle_info_gitfirst_r1";
const GF_REQUEST = {"blob":"40a1a717a0f07c5e588977e7ddc941b75d92bce4","bytes":273,"sha256":"8fcced2a71700b581d7b8981c64e2e0e61944f763c954b23aa8a2a1565a6bcfb"};
const GF_EXPECTED = {"host":"rog","path":"/home/qian-qi/hb-4a49405b-src-20261106-r1/control/canonical-hb-4a49405b-from576.bundle","bytes":1253,"sha256":"0bdbb69aed82e8cb5d5536ef8b782ac761ceca73d03e45af4d3073f890f18851","full9":["66306","34603387","1000","1000","33152","1","1253","1794007675691817556","1794007675691817556"]};

/* Separate BODY GO attaches to the one closed INFO scope. No new job or INFO. */
const GF_BUNDLE_BODY_EXPECTED = {"host":"rog","path":"/home/qian-qi/hb-4a49405b-src-20261106-r1/control/canonical-hb-4a49405b-from576.bundle","bytes":1253,"sha256":"0bdbb69aed82e8cb5d5536ef8b782ac761ceca73d03e45af4d3073f890f18851","full9":["66306","34603387","1000","1000","33152","1","1253","1794007675691817556","1794007675691817556"],"version":"66306:34603387:1253:1794007675691817556:1794007675691817556","infoOperation":"652e6f755ef82208e0ea628ac6693cda7afab1244460c0f4062c0dacc6bac0e2","infoNative":{"blob":"f8629d29e51e1101386ea925bed8bcbb08750d3b","bytes":472,"sha256":"645ca6669054504d819ecfa338d2f33f81709e3a242e0164d2ebfca2f6c06073"}};
const GF_BUNDLE_BODY_RANGES = [{"offset":0,"limit":1253,"request":{"blob":"b6778404640bf6b307d7c43576ae374b76f1aabe","bytes":404,"sha256":"dd4ed331874d4ef93baa6af27aef4e44dab7211dd7f59e7976f150628fbe5d98"}}];
const GF_BUNDLE_INFO_STATE = {"blob":"27b3674947cd481b4f5c396739d5bbd1241f801a","bytes":18911,"sha256":"dd77a0938496f9bf5d3355674795615ddefa13de24bf2949d5eb9715cf8f9078"};
const GF_BUNDLE_BODY_PAGE_BYTES = 16384;

function gfAuthorizeCanonicalBundleBodyOnly({goRaw,goPin,goWholeReadback}) {
 const s=gfState(),need=GF_BUNDLE_BODY_EXPECTED;
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null
   && s.activeObserver===null && s.job===null && s.startCalled===false
   && s.bundleBodyGO===undefined && s.bundleBodyStarted===undefined
   && s.bundleBodyRanges===undefined
   && gfMetaEquals(JSON.stringify(s,null,2)+"\n",GF_BUNDLE_INFO_STATE),
   "exact_closed_INFO_context_before_body_GO");
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin)
   && goPin.blob!==s.goPin.blob,"separate_whole_bundle_body_GO");
 const g=JSON.parse(goRaw);
 gfNeed(g.authorization==="GO" && g.scope==="canonical_bundle_binary_read_ranges_only"
   && g.info_operation===need.infoOperation && g.maximum_binary_read_starts===1
   && g.immutable_body_page_bytes===GF_BUNDLE_BODY_PAGE_BYTES
   && g.fixed_bundle?.path===need.path && g.fixed_bundle?.bytes===need.bytes
   && g.fixed_bundle?.sha256===need.sha256 && g.fixed_bundle?.version===need.version
   && Array.isArray(g.exact_requests) && g.exact_requests.length===1
   && GF_BUNDLE_BODY_RANGES.every((x,j)=>g.exact_requests[j]?.blob===x.request.blob
     && g.exact_requests[j]?.bytes===x.request.bytes
     && g.exact_requests[j]?.sha256===x.request.sha256),"exact_new_root_one_range_scope");
 const prior=s.completedObservers.find(o=>o.id===need.infoOperation),info=s.bundleInfo;
 gfNeed(prior?.completedInactive===true && prior.tool==="file_info"
   && prior.nativeText.blob===need.infoNative.blob
   && gfMetaEquals(load(GF_SLOT+":closed_native:"+need.infoOperation),need.infoNative)
   && info?.path===need.path && info.bytes===need.bytes && info.sha256===need.sha256
   && info.version===need.version
   && JSON.stringify(info.derivedFull9)===JSON.stringify(need.full9),
   "whole_independent_info_exact_identity");
 s.bundleBodyGO={pin:goPin,raw:goRaw,whole:true};
 s.bundleBodyStarted=0;s.bundleBodyRanges=[];
 gfSave(s);
 return {originalJob:null,infoOperation:need.infoOperation,maximumBinaryReadStarts:1,
   exactRequests:GF_BUNDLE_BODY_RANGES,wholeBytes:need.bytes,bodyPageBytes:GF_BUNDLE_BODY_PAGE_BYTES};
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
function gfInitializeOnlyAfterRootGO({goRaw,goPin,goWholeReadback}) {
 gfNeed(load(GF_SLOT)===undefined,"existing_or_armed_context_must_be_recovered_not_reinitialized");
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin),"exact_whole_new_root_go");
 // Fresh standalone read scope: no earlier job/context is manufactured or reset.
 store(GF_SLOT,{rootGoWhole:true,goRaw,goPin,digest:null,fingerprint:null,job:null,
  startCalled:false,pending:null,activeObserver:null,nativeCallInFlight:false,
  paused:false,calls:{},completedObservers:[],nextStdout:0,nextStderr:0,
  localJournalAvailable:false,gitFirstExplicitlyRequiredByThisRootGO:true,
  onlyFixedCanonicalBundleFileInfo:true});
}
function gfValidateRequest(s,kind,q,raw) {
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null,"single_call_boundary");
 if(kind==="process_start") {
  throw new Error("metadata_scope_has_no_process_start_authorization");
 } else if(kind==="operation_start") {
  if(q.operation?.tool==="binary_read") {
   const index=s.bundleBodyRanges?.length,range=GF_BUNDLE_BODY_RANGES[index],a=q.operation.arguments;
   gfNeed(s.bundleBodyGO?.whole===true && s.job===null && s.activeObserver===null
     && range && s.bundleBodyStarted===index && gfMetaEquals(raw,range.request)
     && Object.keys(q).sort().join(",")==="idempotency_key,operation"
     && Object.keys(q.operation).sort().join(",")==="arguments,tool"
     && Object.keys(a).sort().join(",")==="expected_version,host,limit,offset,path"
     && a.host===GF_BUNDLE_BODY_EXPECTED.host && a.path===GF_BUNDLE_BODY_EXPECTED.path
     && a.offset===range.offset && a.limit===range.limit
     && a.limit>0 && a.limit<=65536 && a.expected_version===GF_BUNDLE_BODY_EXPECTED.version,
     "one_exact_next_version_bound_bundle_range");
   return;
  }
  gfNeed(s.onlyFixedCanonicalBundleFileInfo===true && s.job===null && s.activeObserver===null
    && s.completedObservers.length===0
    && !Object.values(s.calls).some(c=>c.kind==="operation_start"),
    "one_fixed_metadata_admission_only");
  gfNeed(gfMetaEquals(raw,GF_REQUEST)
    && Object.keys(q).sort().join(",")==="idempotency_key,operation",
    "one_exact_bundle_file_info_request");
  const op=q.operation,a=op?.arguments;
  gfNeed(op && Object.keys(op).sort().join(",")==="arguments,tool"
    && op.tool==="file_info" && a
    && Object.keys(a).sort().join(",")==="host,path"
    && a.host===GF_EXPECTED.host && a.path===GF_EXPECTED.path,"fixed_bundle_metadata_path_only");
 } else if(kind==="operation_status") {
  gfNeed(Object.values(s.calls).filter(c=>c.kind==="operation_status" && c.called
    && JSON.parse(c.requestRaw).operation_id===s.activeObserver?.id).length<8,
    "original_operation_status_budget_eight");
  gfNeed(s.activeObserver && !s.activeObserver.futureClosed
   && Object.keys(q).join(",")==="operation_id"
   && q.operation_id===s.activeObserver.id,"same_live_original_operation_status");
 } else if(kind==="operation_result") {
  gfNeed(Object.values(s.calls).filter(c=>c.kind==="operation_result" && c.called
    && JSON.parse(c.requestRaw).operation_id===s.activeObserver?.id).length<128,
    "original_operation_page_budget_128");
  gfNeed(s.activeObserver?.futureClosed===true
   && Object.keys(q).sort().join(",")==="limit,offset,operation_id"
   && q.operation_id===s.activeObserver.id
   && q.limit===(s.activeObserver.tool==="binary_read"?GF_BUNDLE_BODY_PAGE_BYTES:8192)
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
  callKey,kind,request:requestPin,rootGo:s.bundleBodyGO?.pin??s.goPin,originalJob:s.job,
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
 if(c.kind==="operation_start" && q.operation.tool==="binary_read")s.bundleBodyStarted++;
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
   gfNeed(b.length<=(a.tool==="binary_read"?GF_BUNDLE_BODY_PAGE_BYTES:8192) && v.next_offset===q.offset+b.length
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
   const need=GF_BUNDLE_BODY_EXPECTED,index=s.bundleBodyRanges.length,
     range=GF_BUNDLE_BODY_RANGES[index],asked=a.request.operation.arguments;
   gfNeed(range && s.bundleBodyStarted===index+1
     && asked.offset===range.offset && asked.limit===range.limit
     && v.path===need.path && v.version===need.version && v.size===need.bytes
     && v.offset===range.offset && v.next_offset===range.offset+range.limit
     && v.eof===(v.next_offset===need.bytes)
     && typeof v.data_base64==="string" && /^[a-f0-9]{64}$/.test(v.chunk_sha256),
     "exact_bundle_original_range_extent");
   const bodyBytes=unb64(v.data_base64);
   gfNeed(bodyBytes.length===range.limit
     && encodeBase64Bytes(bodyBytes)===v.data_base64
     && sha256Latin1(byteString(bodyBytes))===v.chunk_sha256,
     "bundle_actual_chunk_bytes_SHA");
   // Git bundle bytes are binary. Preserve an exact canonical base64 transport,
   // never decode the PACK as UTF-8 or claim a text blob is the binary object.
   const encodedRaw=v.data_base64+"\n",encodedPin=gitBlobMeta(encodedRaw);
   const encodedArchive=await archiveFlatPublicTextsOnce({
    key:"successor4a-mac-canonical-bundle-chunk-"+index+"-r1",
    repository:"TrillionniumFoundation/HeptaBao",
    texts:{"chunk.original.base64.txt":encodedRaw}});
   const row={offset:range.offset,limit:range.limit,next:v.next_offset,
     chunkSHA256:v.chunk_sha256,base64:v.data_base64,originalOperation:a.id,
     originalPayload:pin,originalPayloadTree:archive.tree,
     encoded:encodedPin,encodedTree:encodedArchive.tree};
   if(index+1===GF_BUNDLE_BODY_RANGES.length) {
    const ranges=s.bundleBodyRanges.concat([row]);
    let complete=[],at=0;
    for(const part of ranges) {
     gfNeed(part.offset===at,"bundle_whole_continuity");
     complete=complete.concat(unb64(part.base64));at=part.next;
    }
    gfNeed(at===need.bytes && complete.length===need.bytes
      && sha256Latin1(byteString(complete))===need.sha256,"bundle_whole_exact_SHA");
    const wholeBase64=encodeBase64Bytes(complete)+"\n",wholePin=gitBlobMeta(wholeBase64);
    const transport={schema:"heptabao.canonical-source-bundle-base64-transport.v1",
      encoding:"base64-with-one-terminal-LF",path:need.path,version:need.version,
      binary_bytes:need.bytes,binary_sha256:need.sha256,encoded_file:wholePin,
      original_operations:ranges.map(x=>x.originalOperation),info_operation:need.infoOperation,
      native_binary_body_observed:true,mac_published:false,product_executed:false};
    const wholeArchive=await archiveFlatPublicTextsOnce({
     key:"successor4a-mac-canonical-source-bundle-whole-r1",repository:"TrillionniumFoundation/HeptaBao",
     texts:{"canonical.bundle.base64.txt":wholeBase64,
       "BINARY-TRANSPORT.public.json":JSON.stringify(transport,null,2)+"\n"}});
    store(GF_SLOT+":canonical_bundle_base64_original",wholeBase64);
    s.bundleBody={path:need.path,version:need.version,binaryBytes:need.bytes,
      binarySHA256:need.sha256,encodedFile:wholePin,wholeTree:wholeArchive.tree,
      originalOperations:ranges.map(x=>x.originalOperation),
      metadataOperation:need.infoOperation,bodyObserved:true,macPublished:false};
   }
   s.bundleBodyRanges.push(row);
  } else if(a.tool==="file_info") {
   gfNeed(s.onlyFixedCanonicalBundleFileInfo===true
     && a.request.operation.arguments.host===GF_EXPECTED.host
     && a.request.operation.arguments.path===GF_EXPECTED.path && v.path===GF_EXPECTED.path
     && v.size===GF_EXPECTED.bytes && v.sha256===GF_EXPECTED.sha256
     && typeof v.version==="string" && /^[0-9]+(?::[0-9]+){4}$/.test(v.version)
     && v.mode===0o600 && v.metadata?.mode===0o600
     && v.metadata.metadata_platform==="linux"
     && v.metadata.uid===1000 && v.metadata.gid===1000 && v.metadata.link_count===1,
     "same_fixed_original_bundle_file_info_native_result");
   const fields=v.version.split(":");
   gfNeed(fields[2]===String(v.size),"actual_version_size_matches");
   // file_info mode is permissions, not a full st_mode. Full9 is explicitly derived.
   const full9=[fields[0],fields[1],String(v.metadata.uid),String(v.metadata.gid),
     String(0o100000|v.mode),String(v.metadata.link_count),String(v.size),fields[3],fields[4]];
   gfNeed(JSON.stringify(full9)===JSON.stringify(GF_EXPECTED.full9),
     "independent_info_full9_matches_exact_stage_witness");
   s.bundleInfo={path:v.path,bytes:v.size,sha256:v.sha256,version:v.version,
     derivedFull9:full9,full9ModeDerivation:"S_IFREG | permission_mode",
     nativeText:gitBlobMeta(nativeRaw),bodyObserved:false};
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
  if(action==="authorize_bundle_body")value=gfAuthorizeCanonicalBundleBodyOnly(args);
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
