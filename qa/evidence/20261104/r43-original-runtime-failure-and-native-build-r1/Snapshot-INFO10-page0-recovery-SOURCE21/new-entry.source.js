/* Explicit root-directed retrieval of one failed delivery from a closed operation.
 * This never reissues file_info or creates a Native future. The failed call stays
 * called=true with its original SDK; a separate recovery call records the new read.
 */
async function gfPrepareClosedInfo10Page0Recovery({goRaw,goPin,goWholeReadback}) {
 const s=gfState(),oldKey="sf23-r1-f10-info-p0",callKey=oldKey+"-recovery1";
 const old=s.calls[oldKey],a=s.activeObserver;
 const requestPin={blob:"916332b53c58b018404b00324cb5aa1588975b52",bytes:121,
  sha256:"17f7fcfad72f016c11d8d7b0be379eb4f2043b20b9c33cc4698bb78d74173edd"};
 const errorPin={blob:"923d6b0480a7a2c63d80ec91ffbc84d0dc6a4011",bytes:248,
  sha256:"cddbef2d67b84c98a2ab46bce54a59d2afcbd0e7d00254ba865eded8722ad173"};
 const operationId="37a07e380c8f74019d9b6c20c86cfa339d409e3b6d01b42b3a4230cb767777dc";
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin),"whole_separate_page_recovery_GO");
 const g=JSON.parse(goRaw);
 gfNeed(g.authorization==="GO" && g.scope==="snapshot_formatted23_info10_page0_retrieval_recovery"
  && g.slot===GF_SLOT && g.original_operation===operationId
  && g.failed_call_key===oldKey && g.recovery_call_key===callKey
  && g.request?.blob===requestPin.blob && g.request?.bytes===requestPin.bytes
  && g.request?.sha256===requestPin.sha256
  && g.failed_sdk?.blob===errorPin.blob && g.failed_sdk?.bytes===errorPin.bytes
  && g.failed_sdk?.sha256===errorPin.sha256
  && g.maximum_recovery_page_calls===1 && g.page_bytes===8192
  && g.native_payload_cap===1048576 && g.operation_start_authorized===false
  && g.operation_status_authorized===false && g.failed_call_preserved===true
  && g.continue_original_table_only_after_info_closed===true
  && g.original_go==="25ea12c4406a12ba5ce263b10a2723f73276d74b",
  "exact_closed_info_page_only_scope");
 gfNeed(s.paused===true && s.pending===oldKey && !s.nativeCallInFlight
  && s.info10Page0Recovery===undefined && !s.calls[callKey]
  && s.goPin.blob===g.original_go && old?.kind==="operation_result"
  && old.called===true && old.phase==="native_interpretation_refused"
  && old.sdkArchive?.whole===true && gfMetaEquals(old.requestRaw,requestPin)
  && old.sdkPin.blob===errorPin.blob
  && gfMetaEquals(load(GF_SLOT+":original_sdk_raw:"+oldKey),errorPin),
  "unchanged_original_failed_delivery_and_once_recovery");
 const request=JSON.parse(old.requestRaw);
 gfNeed(Object.keys(request).sort().join(",")==="limit,offset,operation_id"
  && request.operation_id===operationId && request.offset===0 && request.limit===8192
  && a?.id===operationId && a.tool==="file_info" && a.futureClosed===true
  && a.nextPageOffset===0 && a.eof===false && a.pages.length===0
  && a.total===null && a.digest===null && a.statusCalled===1 && a.pageCalled===1
  && s.outputFiles.length===10 && s.completedObservers.length===26
  && s.admissionsCalled===27 && s.bodyBytes===574522
  && s.infoStarted[10]===true && s.outputInfos[10]===null
  && s.bodyStarted[10].every(x=>x===false) && s.infoStarted[11]===false,
  "actual_closed_info10_before_any_body_or_later_file");
 const statusKey="sf23-r1-f10-info-s0",statusCall=s.calls[statusKey];
 const statusPin={blob:"4e720931e08072dc1d769dcd3e5dd5fccb69e6d1",bytes:800,
  sha256:"f31c15d37576e29ccedaefa2d38e3eb9cc631b7d768a8fa7b70306d1d7c8d1e3"};
 const statusRaw=load(GF_SLOT+":native_raw:"+statusKey);
 gfNeed(statusCall?.called===true && statusCall.phase==="accepted"
  && statusCall.sdkArchive?.whole===true && gfMetaEquals(statusRaw,statusPin),
  "original_completed_status_identity");
 const status=parseLosslessIntegers(statusRaw);
 gfNeed(status.operation_id===operationId && status.async_state==="completed"
  && status.result_state==="stored_observed" && status.owned_future_active===false
  && status.payload_available===true,"original_future_already_closed");
 const failedCallRaw=JSON.stringify(old,null,2)+"\n";
 const before={pending:s.pending,paused:s.paused,failedCall:gitBlobMeta(failedCallRaw),
  admissionsCalled:s.admissionsCalled,bodyBytes:s.bodyBytes,pageCalled:a.pageCalled,
  completedObservers:s.completedObservers.length,wholeFiles:s.outputFiles.length};
 const intent={schema:"heptabao.gitfirst.closed-immutable-page-recovery-intent.r1",
  callKey,kind:"operation_result",request:requestPin,rootRecoveryGo:goPin,
  originalRootGo:s.goPin,originalOperation:operationId,originalFailedSDK:errorPin,
  originalFailedCall:before.failedCall,originalCompletedStatus:statusPin,
  maximumNativeCalls:1,nativeNotYetCalled:true,noNativeAdmission:true,
  notRecoveryOfOriginalSDK:true,originalFailureRemains:true,before};
 const armed={...intent,schema:"heptabao.gitfirst.closed-immutable-page-recovery-armed.r1",
  mayHaveDispatchedAfterThisCheckpoint:true,automaticRetry:false};
 s.info10Page0Recovery={phase:"arming",goRaw,goPin,before,oldKey,callKey,
  oldFailureUnchanged:true,request:requestPin};
 s.calls[callKey]={kind:"operation_result",requestRaw:old.requestRaw,requestPin,
  phase:"arming",called:false,recoveryOfDelivery:oldKey};
 gfSave(s);
 const archive=await archiveFlatPublicTextsOnce({
  key:"gfa-"+callKey,repository:"TrillionniumFoundation/HeptaBao",
  texts:{"request.json":old.requestRaw,"intent.json":JSON.stringify(intent,null,2)+"\n",
   "armed.json":JSON.stringify(armed,null,2)+"\n","original-failed-call.json":failedCallRaw}});
 gfNeed(archive.whole===true && s.pending===oldKey && s.paused===true
  && !s.nativeCallInFlight && JSON.stringify(s.calls[oldKey],null,2)+"\n"===failedCallRaw,
  "whole_arm_and_original_failure_preserved");
 s.calls[callKey].armed=archive;s.calls[callKey].phase="armed_whole";
 s.info10Page0Recovery.phase="armed_whole";
 s.pending=callKey;s.paused=false;gfSave(s);
 return {callKey,request:requestPin,armedTree:archive.tree,nativeCalled:false,
  originalFailedCallPreserved:true,originalFutureAlreadyClosed:true};
}

