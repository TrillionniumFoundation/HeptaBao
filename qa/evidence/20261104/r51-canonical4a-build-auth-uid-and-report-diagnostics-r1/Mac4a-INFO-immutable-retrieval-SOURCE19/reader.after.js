/* One immutable page from the original completed/inactive Mac stage INFO operation.
 * Requires original pure_helpers.js + git_archive_once.js. No old slot is written. */
const FIP_SLOT="successor4a_mac_stage_info_page0_retrieval_r1";
const FIP_OLD_INFO="successor4a_mac_source_only_stage_gitfirst_r1";
const FIP_INFO_PIN={"blob":"c430ef8d263c59dfced528e9a6b35a19004b162f","bytes":69161,"sha256":"61b9e20f71244ac11c2b304a70eee0ee6f218cacb5a7fe382483f61cb632b93b"};
const FIP_STATUS_PIN={"blob":"be8f407df5b4e27260b8bb67170e8130e73e0eda","bytes":800,"sha256":"db1881cb30ef27e3e46c5248efb9c8f75bc63555cb23eb8e3cca6724b7210f8a"};
const FIP_OP="de877b50d2ab34adac0ab37da7e2de06bb44b9b993da97c20b7bca92592bdd39";
const FIP_REQUEST={"blob":"2e67f1baabc04575aa277fcb2d270271500e68e3","bytes":121,"sha256":"177140e2743e89076257a772e458a8b784ed91e32f0bba3a96ef77083eb2dea9"};
const FIP_FAILED_PAGE="4a-mac-stage-r1-result-info-page0";
const FIP_FAILED_SDK={"blob":"923d6b0480a7a2c63d80ec91ffbc84d0dc6a4011","bytes":248,"sha256":"cddbef2d67b84c98a2ab46bce54a59d2afcbd0e7d00254ba865eded8722ad173"};
function fipNeed(v,c){if(!v)throw new Error(c);}
function fipJ(v){return JSON.stringify(v,null,2)+"\n";}
function fipEq(raw,p){const a=gitBlobMeta(raw);return a.blob===p.blob&&a.bytes===p.bytes&&a.sha256===p.sha256;}
function fipOld(){
 const old=load(FIP_OLD_INFO);
 fipNeed(fipEq(fipJ(old),FIP_INFO_PIN),"original_paused_state_exact");
 const raw=load(FIP_OLD_INFO+":native_raw:4a-mac-stage-r1-result-info-status0");
 fipNeed(fipEq(raw,FIP_STATUS_PIN),"actual_completed_status_exact");
 const s=JSON.parse(raw),a=old.activeObserver,c=old.calls[FIP_FAILED_PAGE];
 fipNeed(s.operation_id===FIP_OP&&s.tool_name==="file_info"&&s.async_state==="completed"
  &&s.owned_future_active===false&&s.result_state==="stored_observed"
  &&s.payload_available===true&&s.automatic_retry===false,"actual_completed_inactive_payload_pointer");
 fipNeed(old.paused===true&&old.pending===FIP_FAILED_PAGE&&old.nativeCallInFlight===false
  &&a.id===FIP_OP&&a.tool==="file_info"&&a.futureClosed===true
  &&a.nextPageOffset===0&&a.eof===false&&a.pages.length===0
  &&a.total===null&&a.digest===null&&c.called===true
  &&c.phase==="native_interpretation_refused"&&c.sdkArchive.whole===true
  &&fipEq(load(FIP_OLD_INFO+":original_sdk_raw:"+FIP_FAILED_PAGE),FIP_FAILED_SDK),
  "original_failed_page_and_unknown_payload_unchanged");
}
function fipDecodeOnePage(sdk){
 fipNeed(sdk.isError!==true&&sdk.content?.length===1&&sdk.content[0].type==="text","original_page_sdk_success_shape");
 const v=parseLosslessIntegers(sdk.content[0].text);
 fipNeed(v.operation_id===FIP_OP&&v.offset===0&&v.immutable_snapshot===true
  &&Number.isSafeInteger(v.total_bytes)&&v.total_bytes>=0&&v.total_bytes<=8192
  &&v.next_offset===v.total_bytes&&v.eof===true
  &&typeof v.payload_kind==="string"&&/^[a-z_]{1,64}$/.test(v.payload_kind)
  &&typeof v.format==="string"&&v.format.length>0&&v.format.length<=160
  &&typeof v.result_sha256==="string"&&/^[a-f0-9]{64}$/.test(v.result_sha256),"one_complete_bounded_immutable_payload");
 const b=unb64(v.data_base64),raw=utf8Text(b),pin=gitBlobMeta(raw);
 fipNeed(b.length===v.total_bytes&&pin.bytes===b.length&&pin.sha256===v.result_sha256
  &&byteString(utf8Bytes(raw))===byteString(b),"all_original_payload_bytes_and_sha");
 return {raw,pin,kind:v.payload_kind,format:v.format};
}
async function fipPrepare({goRaw,goPin,goWholeReadback}){
 fipOld();fipNeed(load(FIP_SLOT)===undefined,"new_page_recovery_context_once");
 fipNeed(goWholeReadback===true&&fipEq(goRaw,goPin),"exact_whole_recovery_go");
 const g=JSON.parse(goRaw);
 fipNeed(g.authorization==="GO"&&g.scope==="mac4a_stage_info_original_page0_once"
  &&g.maximumNativeCalls===1&&g.operationId===FIP_OP
  &&JSON.stringify(g.request)===JSON.stringify(FIP_REQUEST)
  &&JSON.stringify(g.originalInfoState)===JSON.stringify(FIP_INFO_PIN),"only_original_completed_info_page_go");
 const requestRaw=fipJ({operation_id:FIP_OP,offset:0,limit:8192});
 fipNeed(fipEq(requestRaw,FIP_REQUEST),"exact_page_request");
 const intent={schema:"heptabao.mac-stage-info-payload-page0-intent.r1",request:FIP_REQUEST,
  originalInfoState:FIP_INFO_PIN,originalStatus:FIP_STATUS_PIN,originalFailedPageSDK:FIP_FAILED_SDK,
  rootGo:goPin,maximumNativeCalls:1,noNewInfo:true,noStatus:true,noStart:true,
  noOldStateWrite:true,nativeNotYetCalled:true};
 const s={phase:"arming",called:false,inflight:false,paused:false,requestRaw,goPin};
 store(FIP_SLOT,s);
 s.arm=await archiveFlatPublicTextsOnce({key:"mac4a-stage-info-original-page0-arm-r1",
  repository:"TrillionniumFoundation/HeptaBao",texts:{"request.json":requestRaw,
  "intent.json":fipJ(intent),"armed.json":fipJ({...intent,mayHaveDispatchedAfterCheckpoint:true})}});
 s.phase="armed_whole";store(FIP_SLOT,s);
 return {arm:s.arm,requiresModelBoundary:true,nativeCalled:false};
}
async function fipInvoke(){
 fipOld();const s=load(FIP_SLOT);
 fipNeed(s&&!s.paused&&!s.called&&!s.inflight&&s.phase==="armed_whole"
  &&s.arm.whole===true&&fipEq(s.requestRaw,FIP_REQUEST),"whole_arm_before_unique_page_call");
 s.called=true;s.inflight=true;s.phase="native_call_entered";store(FIP_SLOT,s);
 const sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_result(JSON.parse(s.requestRaw));
 store(FIP_SLOT+":original-sdk",sdk);
 const raw=fipJ(sdk);store(FIP_SLOT+":original-sdk-raw",raw);
 s.sdk=gitBlobMeta(raw);s.inflight=false;s.phase="sdk_stored_uninterpreted";store(FIP_SLOT,s);
 s.sdkArchive=await archiveFlatPublicTextsOnce({key:"mac4a-stage-info-original-page0-sdk-r1",
  repository:"TrillionniumFoundation/HeptaBao",texts:{"original.sdk.json":raw}});
 s.phase="sdk_whole_uninterpreted";store(FIP_SLOT,s);fipOld();
 return {sdk:s.sdk,tree:s.sdkArchive.tree,interpreted:false};
}
async function fipAccept(){
 fipOld();const s=load(FIP_SLOT),raw=load(FIP_SLOT+":original-sdk-raw");
 fipNeed(s&&!s.paused&&!s.inflight&&s.phase==="sdk_whole_uninterpreted"
  &&s.sdkArchive.whole===true&&fipEq(raw,s.sdk),"whole_sdk_before_page_parse");
 const p=fipDecodeOnePage(JSON.parse(raw));
 store(FIP_SLOT+":payload-original",p.raw);
 s.payload=p.pin;s.payloadKind=p.kind;s.payloadFormat=p.format;s.phase="payload_stored_uninterpreted";store(FIP_SLOT,s);
 s.payloadArchive=await archiveFlatPublicTextsOnce({key:"mac4a-stage-info-original-page0-payload-r1",
  repository:"TrillionniumFoundation/HeptaBao",texts:{"payload.original.json":p.raw}});
 s.phase="payload_whole_diagnostic_only";s.closed=true;store(FIP_SLOT,s);fipOld();
 return {payload:p.pin,tree:s.payloadArchive.tree,kind:p.kind,format:p.format,
  originalCompletedFutureInactive:true,metadataQualified:false,
  semanticParsed:false,oldStatesUnchanged:true};
}
async function fipRun(action,args){
 try{
  let value;
  if(action==="prepare")value=await fipPrepare(args);
  else if(action==="invoke")value=await fipInvoke();
  else if(action==="accept")value=await fipAccept();
  else throw new Error("closed_mac_info_page_actions");
  return {ok:true,value};
 }catch(e){
  const error={name:String(e?.name),message:String(e?.message),stack:String(e?.stack)};
  store(FIP_SLOT+":failure",error);
  const s=load(FIP_SLOT);if(s){s.paused=true;s.failure=error;store(FIP_SLOT,s);}
  return {ok:false,stopped:true,code:"mac_info_payload_retrieval_stopped"};
 }
}
