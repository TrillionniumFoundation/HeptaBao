function recoverOneOriginalBuildResultPage({goRaw,goPin,goWholeReadback},h,loadState,saveState) {
 const slot="jwt_pki_33b814c7_build149_gitfirst_r1",failedCall="jwt-pki-33b814c7-build149-report-body-page2-r1";
 const s=loadState(slot),before=JSON.stringify(s,null,2)+"\n";
 const need={"blob":"04567ecf3260b0cb341332f34ba0ba969cf6e3cc","bytes":120307,"sha256":"323ab85f815ecb7670f364f8f804b5f5117fd4b182ebe4727a885ab06f248ece"};
 const actual=h.gitBlobMeta(before);
 function require(value,name){if(!value)throw Error(name);}
 require(actual.blob===need.blob&&actual.bytes===need.bytes&&actual.sha256===need.sha256,"exact_failed_before_state");
 const gp=h.gitBlobMeta(goRaw);
 require(goWholeReadback===true&&gp.blob===goPin.blob&&gp.bytes===goPin.bytes&&gp.sha256===goPin.sha256,"separate_exact_whole_root_GO");
 const g=JSON.parse(goRaw),c=s.calls[failedCall],a=s.activeObserver;
 require(g.authorization==="GO"&&g.scope==="original_build_report_immutable_page_recovery_only"
   &&g.original_job==="1a1b029a998-fc05-6eb2"
   &&g.original_operation_id==="7ef06d88b0a289f89193813a2f1e20c865818515a4842c816bd1a47eff2fe0a0"
   &&g.failed_sdk_blob==="923d6b0480a7a2c63d80ec91ffbc84d0dc6a4011"
   &&g.exact_request?.blob==="8448c7b5701f7551c847f55a66ae9c10892f2de1"
   &&g.exact_request?.bytes===126
   &&g.exact_request?.sha256==="10316b66ee044e51b3ed82b00be6b702335b06af50588df900417ce38a3a1b1c"
   &&g.maximum_page_reconciliations===1,"root_one_same_immutable_page_only");
 require(s.paused===true&&s.pending===failedCall&&s.nativeCallInFlight===false
   &&c.called===true&&c.phase==="native_interpretation_refused"
   &&c.sdkPin.blob===g.failed_sdk_blob&&c.sdkArchive.whole===true
   &&a.id===g.original_operation_id&&a.futureClosed===true
   &&a.nextPageOffset===32768&&a.total===49765&&a.eof===false&&a.pages.length===2,
   "same_closed_original_future_and_missing_page");
 const beforeCalls=JSON.stringify(s.calls),beforeObserver=JSON.stringify(a);
 const record={schema:"heptabao.original-immutable-page.local-recovery.r1",
   originalFailedCall:failedCall,originalFailedSDK:c.sdkPin,originalOperation:a.id,
   nextPageOffset:a.nextPageOffset,exactRequest:c.requestPin,rootGO:goPin,
   firstTimeoutPreserved:true,originalCallRecordsChanged:false,
   newNativeAdmission:false,newBinaryRead:false,newBuild:false,Native:0,
   explanation:"One new explicitly approved immutable-page observation of the same closed operation; this is not a recovered response to the earlier timed-out RPC."};
 s.pageRecoveryHistory=(s.pageRecoveryHistory||[]).concat([record]);
 s.paused=false;s.pending=null;
 require(JSON.stringify(s.calls)===beforeCalls&&JSON.stringify(s.activeObserver)===beforeObserver,"all_original_evidence_unchanged");
 saveState(slot,s);
 return {record,before:need,after:h.gitBlobMeta(JSON.stringify(s,null,2)+"\n"),
   exactRequestRaw:c.requestRaw,Native:0,nextAction:"External whole recovery record first, then separate-boundary prepare of a new page reconciliation call key; unchanged original journal only."};
}
