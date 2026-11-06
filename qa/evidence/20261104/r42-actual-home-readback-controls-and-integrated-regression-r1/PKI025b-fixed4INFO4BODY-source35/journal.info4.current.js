/* SOURCE ONLY: native-call archival substitute proposed for the local outage.
 * Requires pure_helpers.js plus git_archive_once.js in the same V8 evaluation.
 * No function below is invoked by loading this file. Root exact GO is separate.
 * No loop starts/retries a native call; all status/page steps are explicit.
 * Every original SDK is store'd, serialized, Git-created once and whole-read
 * before isError or native text is inspected.
 */
const GF_SLOT = "jwt_pki_025b05a3_build_controls_inert_gitfirst_r2";
const GF_REQUEST = {blob:"4ef00cfaaeb93943db9aa93d7f3a864db4ec12ea",
 bytes:124154,sha256:"4730410592ed61808d13341ef5dd4f22f4317ff2947c27697f258b9fea56fb07"};


/* Four fixed public metadata observations after this exact publisher closes.
 * All original state/history is retained. This scope admits no binary_read.
 */
const GF_CONTROLS_INFO_REQUESTS = [{"blob":"78c9767df0ed826a7bab3d868787f33281960da6","bytes":284,"sha256":"b3c0790bc7e3a4df7715e3e6fc2f1c8519e4c76b89d2dcf88ca2960b8a7f61a3"},{"blob":"0f0487c4d2e64d6474f0c321a4f56fc4c800d00d","bytes":291,"sha256":"33f596d548fcab8f1c1eae1c855f04cbe38e45eb6f6ff8febbb0bee57a3b3779"},{"blob":"3cedb52ffcacd7820b98d9c80a022bfcb0e2aff5","bytes":292,"sha256":"81da20525aa4e777753bc5c4b0ad5a72f1efde628787d4cc55b3905e705c3905"},{"blob":"55b50cccf3fa7c3948a04ae310bd9107639c56b6","bytes":295,"sha256":"d494099f252df35e1daf90e03505095d9e1a2cdf7aed1fcd957b584b5faf6751"}];
const GF_CONTROLS_EXPECTED = [{"index":0,"name":"native_jwt_build.py","path":"/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r2/native_jwt_build.py","bytes":30397,"sha256":"d76b3d392c20bf4a7bbb7e8d8ea69abdfe3bb11f71a35075ba26ab948e778a50","publisherFull9":["66306","33212340","1000","1000","33152","1","30397","1793965550402189411","1793965550403278461"]},{"index":1,"name":"launch_native_jwt_build.py","path":"/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r2/launch_native_jwt_build.py","bytes":38565,"sha256":"efec176c08804a91adfd0160cdc092fad879d64ff594debe2fffe8008488d00c","publisherFull9":["66306","33212341","1000","1000","33152","1","38565","1793965550403677310","1793965550405279309"]},{"index":2,"name":"jwt-test-groups.public.json","path":"/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r2/jwt-test-groups.public.json","bytes":19789,"sha256":"35153ff5e90b582f83e4fbbb66ff5c9fb295e95153f08df152cefedecdb50869","publisherFull9":["66306","33212342","1000","1000","33152","1","19789","1793965550406347359","1793965550407346912"]},{"index":3,"name":"inert-stage.result.public.json","path":"/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r2/inert-stage.result.public.json","bytes":1854,"sha256":"30cd7315341a685f3bf0b95b3938dd12e717d880ded7161d462f14e75c0eac61","publisherFull9":null}];
const GF_CONTROLS_INFO_PREREQUISITES = [{"id":"4edb38378654d826ed10313b7defc623e5cd18154a4030de8dee724ad2c5118a","tool":"process_status","nativeText":{"blob":"15690bdf2a0078dcce3bb2d76863cf353d76b2dc","bytes":731,"sha256":"97cfc86ef059ff751ae6757738144695ae5015175d305678fa72d3c44057a277"}},{"id":"b9383d8a659cfe3ed84c7d1baf6cf9171d442c7ef812b88c2878280826d74786","tool":"process_read","nativeText":{"blob":"4142bf162a672bf0553a6a17815442ff09f1bd9c","bytes":4748,"sha256":"843b12b77805de709e2aa8704f4f9bd23b05ba9b19c43f8d673314eb21e8e97c"}}];
const GF_CONTROLS_STDOUT = {"blob":"444fb9941c8dae52784e0b0fe99b238206024b36","bytes":1444,"sha256":"f002a8cb103ad8b4080883e31980a29edfda6640cbf65985dc6ad025b8858665"};

function gfAuthorizePublishedControlsInfoOnly({goRaw,goPin,goWholeReadback}) {
 const s=gfState();
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null
   && s.activeObserver===null && s.startCalled===true
   && s.job==="1a1b0ade81d-fc05-7220" && s.controlsInfoGO===undefined
   && s.publishedInfoStarted===undefined && s.publishedInfos===undefined,
   "closed_exact_publisher_before_fixed4_info_GO");
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin)
   && goPin.blob!==s.goPin.blob,"separate_whole_fixed4_info_GO");
 const g=JSON.parse(goRaw);
 gfNeed(g.authorization==="GO" && g.scope==="build_controls_fixed_four_file_info_only"
   && g.original_job===s.job && g.maximum_file_info_starts===4
   && g.binary_read_authorized===false && Array.isArray(g.exact_requests)
   && g.exact_requests.length===4
   && g.exact_requests.every((p,i)=>p.blob===GF_CONTROLS_INFO_REQUESTS[i].blob
     && p.bytes===GF_CONTROLS_INFO_REQUESTS[i].bytes
     && p.sha256===GF_CONTROLS_INFO_REQUESTS[i].sha256),
   "exact_new_root_fixed4_metadata_scope");
 for(const need of GF_CONTROLS_INFO_PREREQUISITES) {
  const prior=s.completedObservers.find(o=>o.id===need.id);
  gfNeed(prior?.completedInactive===true && prior.tool===need.tool
    && prior.nativeText.blob===need.nativeText.blob
    && gfMetaEquals(load(GF_SLOT+":closed_native:"+need.id),need.nativeText),
    "original_publication_observer_closed_and_whole");
 }
 const authority=parseLosslessIntegers(load(GF_SLOT+":closed_native:"+GF_CONTROLS_INFO_PREREQUISITES[0].id));
 const streams=parseLosslessIntegers(load(GF_SLOT+":closed_native:"+GF_CONTROLS_INFO_PREREQUISITES[1].id));
 const publication=parseLosslessIntegers(streams.stdout.text);
 gfNeed(authority.exit_code===0 && authority.output_complete===true
   && authority.output_durable===true && authority.terminal_publication_confirmed===true
   && !authority.timed_out && !authority.cancelled
   && streams.stdout.eof===true && streams.stderr.eof===true
   && s.nextStdout===1444 && s.nextStderr===0 && streams.stderr.text===""
   && gfMetaEquals(streams.stdout.text,GF_CONTROLS_STDOUT)
   && publication.status==="prepared" && publication.python_compile_only===true
   && publication.files.length===3 && publication.files.every(x=>x.publication==="created")
   && ["source_executed","git_started","compiler_started","service_started","artifact_transfer_started"]
      .every(k=>publication[k]===false),"actual_original_zero_and_prepared_publication");
 s.controlsInfoGO={pin:goPin,raw:goRaw,whole:true};
 s.publishedInfoStarted=[false,false,false,false];s.publishedInfos=[];
 gfSave(s);
 return {originalJob:s.job,exactRequests:GF_CONTROLS_INFO_REQUESTS,
   maximumFileInfoStarts:4,binaryReadAuthorized:false};
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
    && /^heptabao-native-jwt-pki-025b05a3-controls-observe-r2-/.test(q.idempotency_key),
    "bounded_original_observer_key");
  const op=q.operation,a=op?.arguments;
  gfNeed(op && Object.keys(op).sort().join(",")==="arguments,tool"
    && a && a.host==="rog","same_original_host_only");
  if(op.tool==="file_info") {
   const i=s.publishedInfos?.length;
   gfNeed(s.controlsInfoGO?.whole===true && Number.isSafeInteger(i) && i>=0 && i<4
     && s.publishedInfoStarted[i]===false && gfMetaEquals(raw,GF_CONTROLS_INFO_REQUESTS[i])
     && Object.keys(a).sort().join(",")==="host,path"
     && a.path===GF_CONTROLS_EXPECTED[i].path,"one_fixed_current_ordered_published_file_info");
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
  rootGo:((kind==="operation_start" && q.operation.tool==="file_info")
    || s.activeObserver?.tool==="file_info") ? s.controlsInfoGO.pin : s.goPin,
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
 if(c.kind==="operation_start" && q.operation.tool==="file_info")
  s.publishedInfoStarted[s.publishedInfos.length]=true;
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
  if(a.tool==="file_info") {
   const i=s.publishedInfos.length,need=GF_CONTROLS_EXPECTED[i];
   const md=v.metadata,parts=typeof v.version==="string"?v.version.split(":"):[];
   gfNeed(i<4 && s.publishedInfoStarted[i]===true
     && a.request.operation.arguments.path===need.path && v.path===need.path
     && v.size===need.bytes && v.sha256===need.sha256 && v.mode===384
     && md?.metadata_platform==="linux" && md.mode===384
     && md.uid===1000 && md.gid===1000 && md.link_count===1
     && parts.length===5 && parts.every(x=>/^[0-9]+$/.test(x))
     && parts[2]===String(v.size),"fixed_published_content_metadata_and_version");
   const full9=[parts[0],parts[1],"1000","1000",String(32768|v.mode),
     "1",String(v.size),parts[3],parts[4]];
   gfNeed(need.publisherFull9===null || JSON.stringify(full9)===JSON.stringify(need.publisherFull9),
     "independent_metadata_matches_original_publisher_full9");
   s.publishedInfos.push({index:i,path:v.path,size:v.size,sha256:v.sha256,version:v.version,
     nativeText:gitBlobMeta(nativeRaw),originalOperation:a.id,full9Strings:full9,
     regularFileFromNativeFileInfoContract:true,binaryReadAuthorized:false});
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
  else if(action==="authorize_published_controls_info")value=gfAuthorizePublishedControlsInfoOnly(args);
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
