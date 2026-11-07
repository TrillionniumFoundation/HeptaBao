/* One immutable page from one already failed/inactive operation. No dispatch on load.
 * Requires original pure_helpers.js + git_archive_once.js. No old slot is written. */
const FIP_SLOT="combined_4a49405b_failed_info_payload_page0_r1";
const FIP_OLD_INFO="combined_4a49405b_unknown_report_info_gitfirst_r1";
const FIP_OLD_BUILD="combined_4a49405b_fresh_build_gitfirst_r1";
const FIP_INFO_PIN={blob:"24f7020e488bea35ab336990345c4d767d89da66",bytes:11134,sha256:"d4105a16656aa555e755da451da41801438ab779947d3efbae66466aac82ccbb"};
const FIP_BUILD_PIN={blob:"2d512764d26256fabaaaf7deb3eae41120d92d3e",bytes:181122,sha256:"196a33b53ea752d27a5226e06f90e75383b1f621a44791e0e240ded17f0bac82"};
const FIP_STATUS_PIN={blob:"ba25cecb4430ece5aea933decbcea117c6894bd4",bytes:797,sha256:"e630828b792467fd100b876cd63834d1aa75fb4acbd0e71d6b933db21d763ad7"};
const FIP_OP="0a3d2c5c158da55c07f9db9202ada37d9670254e650c70eff7cfa08bb8d6d7d2";
const FIP_REQUEST={"blob":"46b765bdbbdaa51af1fa3891b78c478b4008b5aa","bytes":121,"sha256":"90e081d7d4fb16b6a1928ad526236e282416ee53f73ee2eec9209baf5870eace"};
function fipNeed(v,c){if(!v)throw new Error(c);}
function fipJ(v){return JSON.stringify(v,null,2)+"\n";}
function fipEq(raw,p){const a=gitBlobMeta(raw);return a.blob===p.blob&&a.bytes===p.bytes&&a.sha256===p.sha256;}
function fipOld(){
 fipNeed(fipEq(fipJ(load(FIP_OLD_INFO)),FIP_INFO_PIN)
  &&fipEq(fipJ(load(FIP_OLD_BUILD)),FIP_BUILD_PIN),"both_old_states_exact");
 const raw=load(FIP_OLD_INFO+":native_raw:c4a-unknown-build-report-info-r1-s0");
 fipNeed(fipEq(raw,FIP_STATUS_PIN),"actual_failed_status_exact");
 const s=JSON.parse(raw);
 fipNeed(s.operation_id===FIP_OP&&s.tool_name==="file_info"&&s.async_state==="failed"
  &&s.owned_future_active===false&&s.result_state==="stored_observed"
  &&s.payload_available===true&&s.automatic_retry===false,"actual_failed_inactive_payload_pointer");
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
 fipNeed(g.authorization==="GO"&&g.scope==="combined4a_failed_info_payload_page0_once"
  &&g.maximumNativeCalls===1&&g.operationId===FIP_OP
  &&JSON.stringify(g.request)===JSON.stringify(FIP_REQUEST)
  &&JSON.stringify(g.originalInfoState)===JSON.stringify(FIP_INFO_PIN)
  &&JSON.stringify(g.originalBuildState)===JSON.stringify(FIP_BUILD_PIN),"only_known_failed_info_page_go");
 const requestRaw=fipJ({operation_id:FIP_OP,offset:0,limit:8192});
 fipNeed(fipEq(requestRaw,FIP_REQUEST),"exact_page_request");
 const intent={schema:"heptabao.failed-info-payload-page0-intent.r1",request:FIP_REQUEST,
  originalInfoState:FIP_INFO_PIN,originalBuildState:FIP_BUILD_PIN,originalStatus:FIP_STATUS_PIN,
  rootGo:goPin,maximumNativeCalls:1,noNewInfo:true,noStatus:true,noStart:true,
  noOldStateWrite:true,nativeNotYetCalled:true};
 const s={phase:"arming",called:false,inflight:false,paused:false,requestRaw,goPin};
 store(FIP_SLOT,s);
 s.arm=await archiveFlatPublicTextsOnce({key:"c4a-failed-info-page0-arm-r1",
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
 s.sdkArchive=await archiveFlatPublicTextsOnce({key:"c4a-failed-info-page0-sdk-r1",
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
 s.payloadArchive=await archiveFlatPublicTextsOnce({key:"c4a-failed-info-page0-payload-r1",
  repository:"TrillionniumFoundation/HeptaBao",texts:{"payload.original.json":p.raw}});
 s.phase="payload_whole_diagnostic_only";s.closed=true;store(FIP_SLOT,s);fipOld();
 return {payload:p.pin,tree:s.payloadArchive.tree,kind:p.kind,format:p.format,
  originalFailedFutureInactive:true,metadataQualified:false,originalBuildOutcome:"UNKNOWN",
  semanticParsed:false,oldStatesUnchanged:true};
}
async function fipRun(action,args){
 try{
  let value;
  if(action==="prepare")value=await fipPrepare(args);
  else if(action==="invoke")value=await fipInvoke();
  else if(action==="accept")value=await fipAccept();
  else throw new Error("closed_failed_info_page_actions");
  return {ok:true,value};
 }catch(e){
  const error={name:String(e?.name),message:String(e?.message),stack:String(e?.stack)};
  store(FIP_SLOT+":failure",error);
  const s=load(FIP_SLOT);if(s){s.paused=true;s.failure=error;store(FIP_SLOT,s);}
  return {ok:false,stopped:true,code:"failed_info_payload_stopped"};
 }
}
