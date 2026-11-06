/* SOURCE ONLY: two immutable operation_result retrievals, never a native dispatch.
 * The original BUILD/body journal remains paused/pending with its error unchanged.
 * Loading this module invokes nothing. Use rrRun only after separate exact root GO.
 */
const RR={"slot":"jwt_pki_33b814c7_build149_body_tail_retrieval_r1","originalSlot":"jwt_pki_33b814c7_build149_gitfirst_r1","originalJob":"1a1b029a998-fc05-6eb2","operation":"7ef06d88b0a289f89193813a2f1e20c865818515a4842c816bd1a47eff2fe0a0","originalState":{"blob":"04567ecf3260b0cb341332f34ba0ba969cf6e3cc","bytes":120307,"sha256":"323ab85f815ecb7670f364f8f804b5f5117fd4b182ebe4727a885ab06f248ece"},"originalClosedStatus":{"blob":"fd2986505afda7e210666b3de197dd6d14e1f3ce","bytes":802,"sha256":"205ce509413641005f059b9cbc3ba5616e3dd5ef16fcd2bbb65d535785e1d8f6"},"statusCallKey":"jwt-pki-33b814c7-build149-report-body-status-r1","failedSDK":{"blob":"923d6b0480a7a2c63d80ec91ffbc84d0dc6a4011","bytes":248,"sha256":"cddbef2d67b84c98a2ab46bce54a59d2afcbd0e7d00254ba865eded8722ad173"},"payload":{"bytes":49765,"sha256":"ca4321b37d698c2078c193087b4e76e56c4cdb8f79955aff236e3033d7188b07"},"requests":[{"raw":"{\n  \"operation_id\": \"7ef06d88b0a289f89193813a2f1e20c865818515a4842c816bd1a47eff2fe0a0\",\n  \"offset\": 32768,\n  \"limit\": 16384\n}\n","pin":{"blob":"8448c7b5701f7551c847f55a66ae9c10892f2de1","bytes":126,"sha256":"10316b66ee044e51b3ed82b00be6b702335b06af50588df900417ce38a3a1b1c"},"offset":32768,"limit":16384},{"raw":"{\n  \"operation_id\": \"7ef06d88b0a289f89193813a2f1e20c865818515a4842c816bd1a47eff2fe0a0\",\n  \"offset\": 49152,\n  \"limit\": 16384\n}\n","pin":{"blob":"42d9eb94225c869f57e0fb52061456f1a8736b0e","bytes":126,"sha256":"a18c4e3504e35482d16a3b2d94e20c0ca9fb7675f615d4ddd659d3050bc4a539"},"offset":49152,"limit":16384}],"prefixCallKeys":["jwt-pki-33b814c7-build149-report-body-page0-r1","jwt-pki-33b814c7-build149-report-body-page1-r1"],"body":{"path":"/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r1/build-tests-r1/result.public.json","bytes":36998,"sha256":"aa8a8623cc955adb64ab386387d15ad2204febc0fd526392d20cd0ab6c9638a6","version":"66306:31364220:36998:1793957208077081949:1793957208077081949","infoOperation":"8e81613aa575b93e807bfe358614abb238250fc93a4180109222d00bde1430da","infoNative":{"blob":"d6e8562a91ba3ee27cfcf8a4c51e5644d9f904c1","bytes":480,"sha256":"66f341b2e43f26671e7eecdc96a4dabc0aefaa8c2634ada148001b75adc29ffb"},"full9Strings":["66306","31364220","1000","1000","33152","1","36998","1793957208077081949","1793957208077081949"]}};
function rrNeed(v,n){if(!v)throw Error(n);}
function rrSame(raw,p){const a=gitBlobMeta(raw);return a.blob===p.blob&&a.bytes===p.bytes&&a.sha256===p.sha256;}
function rrOldUnchanged(){
 const s=load(RR.originalSlot);
 rrNeed(rrSame(JSON.stringify(s,null,2)+"\n",RR.originalState),"original_paused_history_exact");
 return s;
}
function rrState(){const s=load(RR.slot);rrNeed(s&&s.rootGOWhole===true,"independent_retrieval_not_initialized");rrOldUnchanged();return s;}
function rrSave(s){store(RR.slot,s);}
function rrInitialize({goRaw,goPin,goWholeReadback}){
 rrNeed(load(RR.slot)===undefined,"new_retrieval_context_must_not_be_reinitialized");
 const old=rrOldUnchanged(),a=old.activeObserver;
 rrNeed(goWholeReadback===true&&rrSame(goRaw,goPin),"exact_whole_retrieval_GO");
 const g=JSON.parse(goRaw);
 rrNeed(g.authorization==="GO"&&g.scope==="original_build_report_immutable_tail_retrieval_only"
   &&g.original_job===RR.originalJob&&g.original_operation_id===RR.operation
   &&g.failed_sdk_blob===RR.failedSDK.blob&&g.maximum_operation_result_calls===2
   &&g.maximum_operation_start_calls===0&&g.maximum_process_start_calls===0
   &&Array.isArray(g.exact_requests)&&g.exact_requests.length===2
   &&g.exact_requests.every((p,i)=>p.blob===RR.requests[i].pin.blob&&p.bytes===RR.requests[i].pin.bytes&&p.sha256===RR.requests[i].pin.sha256),
   "two_exact_immutable_requests_no_dispatch");
 const statusRaw=load(RR.originalSlot+":native_raw:"+RR.statusCallKey);
 rrNeed(rrSame(statusRaw,RR.originalClosedStatus),"original_status_pin");
 const v=parseLosslessIntegers(statusRaw);
 rrNeed(v.operation_id===RR.operation&&v.tool_name==="binary_read"&&v.async_state==="completed"
   &&v.result_state==="stored_observed"&&v.owned_future_active===false&&v.payload_available===true,
   "original_effect_already_closed");
 rrNeed(old.paused===true&&old.pending==="jwt-pki-33b814c7-build149-report-body-page2-r1"
   &&old.nativeCallInFlight===false&&a.id===RR.operation&&a.futureClosed===true
   &&a.nextPageOffset===32768&&a.total===RR.payload.bytes&&a.digest===RR.payload.sha256
   &&a.eof===false&&a.pages.length===2,"exact_partial_prefix_and_preserved_error");
 const prefix=[];
 for(let i=0;i<2;i++){
  const k=RR.prefixCallKeys[i],c=old.calls[k],p=a.pages[i];
  const sdkRaw=load(RR.originalSlot+":original_sdk_raw:"+k),nativeRaw=load(RR.originalSlot+":native_raw:"+k);
  rrNeed(c.phase==="accepted"&&c.sdkArchive.whole===true&&rrSame(sdkRaw,c.sdkPin)&&rrSame(nativeRaw,c.nativePin),"prefix_original_sdk_native_whole");
  const q=parseLosslessIntegers(nativeRaw),bytes=unb64(q.data_base64);
  rrNeed(q.operation_id===RR.operation&&q.immutable_snapshot===true&&q.payload_kind==="native_result"
    &&q.offset===i*16384&&q.next_offset===(i+1)*16384&&bytes.length===16384
    &&q.total_bytes===RR.payload.bytes&&q.result_sha256===RR.payload.sha256
    &&p.offset===q.offset&&p.next===q.next_offset&&p.base64===q.data_base64,"prefix_exact_original_pages");
  prefix.push({...p,source:"original_before_timeout",originalCallKey:k});
 }
 const s={rootGOWhole:true,goRaw,goPin,originalState:RR.originalState,
  originalOperation:RR.operation,originalFutureCompletedInactive:true,
  nextIndex:0,pages:prefix,pending:null,calls:{},nativeCallInFlight:false,
  paused:false,complete:false,originalSlotMutation:false};
 rrSave(s);
 return {independentSlot:RR.slot,originalOperation:RR.operation,originalSlotUnchanged:true,
   originalFutureCompletedInactive:true,exactRequests:RR.requests.map(x=>x.pin),Native:0};
}
async function rrPrepare({index,callKey}){
 const s=rrState();
 rrNeed(!s.paused&&!s.nativeCallInFlight&&s.pending===null&&!s.complete
   &&index===s.nextIndex&&index>=0&&index<2
   &&/^[a-z0-9][a-z0-9-]{0,70}$/.test(callKey)&&!s.calls[callKey],"one_finite_retrieval_boundary");
 const fixed=RR.requests[index],request=JSON.parse(fixed.raw);
 rrNeed(rrSame(fixed.raw,fixed.pin)&&request.operation_id===RR.operation
   &&request.offset===fixed.offset&&request.limit===16384,"immutable_request_unchanged");
 const intent={schema:"heptabao.exact-immutable-tail-retrieval.intent.r1",
  callKey,index,tool:"operation_result",exactRequest:fixed.pin,originalOperation:RR.operation,
  originalFutureCompletedInactive:true,rootGO:s.goPin,originalState:s.originalState,
  maximumToolCalls:1,dispatchesNativeOperation:false,originalTimeoutPreserved:true};
 const armed={...intent,schema:"heptabao.exact-immutable-tail-retrieval.armed.r1",
  callMayHaveOccurredAfterCheckpoint:true,noAutomaticRetry:true};
 s.pending=callKey;s.calls[callKey]={index,requestRaw:fixed.raw,requestPin:fixed.pin,phase:"arming",called:false};rrSave(s);
 const archive=await archiveFlatPublicTextsOnce({key:"rr-arm-"+callKey,repository:"TrillionniumFoundation/HeptaBao",
  texts:{"request.original.json":fixed.raw,"intent.original.json":JSON.stringify(intent,null,2)+"\n","armed.original.json":JSON.stringify(armed,null,2)+"\n"}});
 s.calls[callKey].armed=archive;s.calls[callKey].phase="armed_whole";rrSave(s);
 return {callKey,index,armedTree:archive.tree,request:fixed.pin,Native:0};
}
async function rrInvoke({callKey}){
 const s=rrState(),c=s.calls[callKey];
 rrNeed(!s.paused&&!s.nativeCallInFlight&&s.pending===callKey&&c?.phase==="armed_whole"
   &&c.armed.whole===true&&!c.called&&c.index===s.nextIndex&&rrSame(c.requestRaw,c.requestPin),
   "external_whole_arm_separate_boundary");
 const q=JSON.parse(c.requestRaw);
 c.called=true;c.phase="tool_call_entered";s.nativeCallInFlight=true;rrSave(s);
 let sdk;
 try {sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_result(q);}
 catch(error){
  const record={name:error?.name??"Error",message:String(error?.message??error),originalOperation:RR.operation,
   request:c.requestPin,originalEffectWasAlreadyClosed:true,automaticRetry:false};
  store(RR.slot+":exception:"+callKey,record);
  s.nativeCallInFlight=false;c.phase="tool_exception_returned";s.paused=true;rrSave(s);
  try{c.exceptionArchive=await archiveFlatPublicTextsOnce({key:"rr-error-"+callKey,
    repository:"TrillionniumFoundation/HeptaBao",texts:{"exception.original.json":JSON.stringify(record,null,2)+"\n"}});rrSave(s);}
  catch(archiveError){store(RR.slot+":exception-archive-error:"+callKey,String(archiveError));}
  throw error;
 }
 store(RR.slot+":sdk:"+callKey,sdk);
 recordGitSDKImmutable(RR.slot+":native:"+callKey,"original_return",sdk);
 const raw=JSON.stringify(sdk,null,2)+"\n";store(RR.slot+":sdk_raw:"+callKey,raw);
 s.nativeCallInFlight=false;c.phase="sdk_returned_uninterpreted";c.sdkPin=gitBlobMeta(raw);rrSave(s);
 c.sdkArchive=await archiveFlatPublicTextsOnce({key:"rr-sdk-"+callKey,
  repository:"TrillionniumFoundation/HeptaBao",texts:{"sdk.original.json":raw}});
 c.phase="sdk_whole_uninterpreted";rrSave(s);
 return {callKey,sdk:c.sdkPin,tree:c.sdkArchive.tree,interpreted:false};
}
function rrAccept({callKey}){
 const s=rrState(),c=s.calls[callKey];
 rrNeed(!s.paused&&!s.nativeCallInFlight&&s.pending===callKey&&c?.phase==="sdk_whole_uninterpreted"
   &&c.sdkArchive.whole===true,"whole_SDK_before_isError");
 const raw=load(RR.slot+":sdk_raw:"+callKey);rrNeed(rrSame(raw,c.sdkPin),"same_original_SDK");
 const sdk=JSON.parse(raw);
 rrNeed(sdk.isError!==true,"retrieval_error_preserved_stop");
 rrNeed(sdk.content?.length===1&&sdk.content[0].type==="text","single_original_native_text");
 const nativeRaw=sdk.content[0].text;store(RR.slot+":native_raw:"+callKey,nativeRaw);
 const v=parseLosslessIntegers(nativeRaw),fixed=RR.requests[c.index],bytes=unb64(v.data_base64);
 rrNeed(v.operation_id===RR.operation&&v.immutable_snapshot===true&&v.payload_kind==="native_result"
   &&v.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization"
   &&v.offset===fixed.offset&&v.total_bytes===RR.payload.bytes&&v.result_sha256===RR.payload.sha256
   &&bytes.length===Math.min(16384,RR.payload.bytes-fixed.offset)
   &&v.next_offset===fixed.offset+bytes.length&&v.eof===(v.next_offset===RR.payload.bytes),
   "fixed_same_id_immutable_extent_SHA");
 c.nativePin=gitBlobMeta(nativeRaw);c.phase="accepted";
 s.pages.push({offset:v.offset,next:v.next_offset,base64:v.data_base64,originalSDK:c.sdkPin,
  nativeText:c.nativePin,source:"new_explicitly_authorized_immutable_retrieval",retrievalCallKey:callKey});
 s.nextIndex++;s.pending=null;rrSave(s);
 return {callKey,offset:v.offset,next:v.next_offset,total:v.total_bytes,eof:v.eof,originalEffectClosed:true};
}
async function rrFinish(){
 const s=rrState();
 rrNeed(!s.paused&&!s.nativeCallInFlight&&s.pending===null&&s.nextIndex===2&&!s.complete&&s.pages.length===4,
   "all_four_page_pieces_available");
 let bytes=[],offset=0;
 for(const p of s.pages){rrNeed(p.offset===offset,"contiguous_original_payload");bytes=bytes.concat(unb64(p.base64));offset=p.next;}
 const raw=utf8Text(bytes),pin=gitBlobMeta(raw);
 rrNeed(offset===RR.payload.bytes&&pin.bytes===RR.payload.bytes&&pin.sha256===RR.payload.sha256,"whole_original_payload_exact");
 const payloadArchive=await archiveFlatPublicTextsOnce({key:"rr-payload-"+RR.operation,repository:"TrillionniumFoundation/HeptaBao",
  texts:{"payload.original.json":raw}});
 const p=parseLosslessIntegers(raw);
 rrNeed(p.resultType==="complete"&&p.isError===false&&p.content?.length===1&&p.content[0].type==="text","original_body_operation_success");
 const nativeRaw=p.content[0].text,v=parseLosslessIntegers(nativeRaw),need=RR.body,bodyBytes=unb64(v.data_base64),body=utf8Text(bodyBytes),bodyPin=gitBlobMeta(body);
 rrNeed(v.path===need.path&&v.version===need.version&&v.size===need.bytes&&v.offset===0
  &&v.next_offset===need.bytes&&v.eof===true&&v.chunk_sha256===need.sha256
  &&bodyBytes.length===need.bytes&&bodyPin.bytes===need.bytes&&bodyPin.sha256===need.sha256,
  "exact_original36998_body_metadata_SHA_EOF");
 const bodyArchive=await archiveFlatPublicTextsOnce({key:"rr-body-"+RR.operation,repository:"TrillionniumFoundation/HeptaBao",
  texts:{"native.original.json":nativeRaw,"result.original.json":body}});
 s.complete=true;s.payload={...pin,tree:payloadArchive.tree};s.body={...bodyPin,tree:bodyArchive.tree};
 s.native=gitBlobMeta(nativeRaw);s.originalSlotMutation=false;rrSave(s);
 store(RR.slot+":payload_original",raw);store(RR.slot+":native_original",nativeRaw);store(RR.slot+":body_original",body);
 return {originalOperation:RR.operation,payload:s.payload,native:s.native,body:s.body,
  originalFutureCompletedInactive:true,originalTimeoutPreserved:true,originalSlotUnchanged:true,
  newDispatches:0,newImmutableRetrievalCalls:2,semanticQualification:false};
}
async function rrRun(action,args={}){
 try{
  let value;
  if(action==="initialize_retrieval")value=rrInitialize(args);
  else if(action==="prepare")value=await rrPrepare(args);
  else if(action==="invoke")value=await rrInvoke(args);
  else if(action==="accept")value=rrAccept(args);
  else if(action==="finish")value=await rrFinish();
  else throw Error("closed_retrieval_action");
  return {ok:true,action,value};
 }catch(error){
  const f={schema:"heptabao.immutable-retrieval.caught-failure.r1",action,name:error?.name??"Error",
   message:String(error?.message??error),originalOperation:RR.operation,originalEffectWasAlreadyClosed:true,
   automaticRetry:false,newAdmissionAllowed:false,originalSlotMutation:false};
  store(RR.slot+":failure:"+action,f);
  const s=load(RR.slot);if(s){s.paused=true;s.failures=(s.failures||[]).concat([f]);rrSave(s);}
  return {ok:false,action,failure:f};
 }
}
