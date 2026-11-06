/* SOURCE ONLY. Pure exact-state derivation; no store, tools, Native, Git, or report JSON interpretation.
 * Root must separately authorize handback of the derived exact state. This file does not apply it.
 * The original failed call remains UNKNOWN delivery. Only the returned original effect is now closed.
 */
const HB = {
  "schema": "heptabao.oracle271.r2.BODY02.exact-handback-inputs.r1",
  "originalSlot": "official271_x230_acl23_oracle_gitfirst_r2",
  "recoverySlot": "official271_x230_acl23_r2_body02_status_reconcile_r1",
  "originalOperation": "6220e2762757d7afa1ba315c7beb2a985c59c147ac7cb3852aa17ba9c21c7a9e",
  "originalJob": "1a1b1b4fbfa-fc05-7a60",
  "originalFailedStatusKey": "official271-x230-acl23-r2-body02-status0",
  "before": {
    "blob": "652b0103388657f5515e30c077ce927c24b19cf2",
    "bytes": 454676,
    "sha256": "dd4a465e95e91c8aa23ddcde138d4541a52e79e7482297eb418bb89e16f83aa3"
  },
  "recoveryState": {
    "blob": "5d9085aeb711d6aab60f88b6641eb22e5222d66d",
    "bytes": 109798,
    "sha256": "96f62783eb44cf88fea10f65393392ff9de5fd5c1b27ff10682f00edebc8bcf7"
  },
  "range": {
    "blob": "f4179457f2e9809cc01112869e37b41e7f37ceaf",
    "bytes": 87889,
    "sha256": "47a1516de0574d2418f86104cbc9346f1bcdf6f30cdc79faf1dfd26e01a48e7f"
  },
  "payload": {
    "blob": "f20019334ad38cacb1e167322cf7794a95e241da",
    "bytes": 87807,
    "sha256": "ee2852333b301886098786350bddfabf531c07672915529a9af3562d96de9528"
  },
  "native": {
    "blob": "80fee5c5830ce3a427fc1a4f265be7b1ee63400c",
    "bytes": 87704,
    "sha256": "9899f711cc87f520fe247875f159c843ca107796e90d6f348680be3ce17625c6"
  },
  "status": {
    "blob": "b64fcdddb682057cf1d0f90d60a47121f3e47662",
    "bytes": 802,
    "sha256": "c8c49d86c35384b51653bdf518550284329fdfd7846514eaec73a272de1aa3c3"
  },
  "recoveryGO": {
    "blob": "7b1141c85601e434dff10db425277ca89e979aa6",
    "bytes": 2494,
    "sha256": "582a251cdce243240d5731c9bf4145be67fc954050716209b2a2d6e10d48540e"
  },
  "recoverySource": {
    "blob": "20a36582d7acf9d3675b9c31fd47e6ae72e7354a",
    "bytes": 21016,
    "sha256": "defc76fc73a4a3ab2fc8d4d8468b11d3410760268560c54c06682ae63b790cfd"
  },
  "recoveryWholeTree": "1da012307bd166ff9601bbcf92963a28f12cb80a",
  "recoveryStatusSDK": {
    "blob": "a295d73b6655906c92193aed0df4d42fe30b8c32",
    "bytes": 977,
    "sha256": "1a94d7f418d242fa4b99022f3d5a8280437d9fea80d8d978de712bea901c1c1e"
  },
  "oldFailedStatusSDK": {
    "blob": "0cede4881f37869cfd279b69b738c87eb62b4889",
    "bytes": 248,
    "sha256": "b85d625e0a8999ce34020675f0a2f8ba093e807dc725c16053a63c92fbbc9c70"
  },
  "mainJournal": {
    "blob": "8ef2f6875479aada7effd09d85fd398d23b43ca1",
    "bytes": 32147,
    "sha256": "c6989da12d4ccebd3ae22ce9f71ef99f01714f473f61fe29517a0b15d657e69d"
  },
  "nextRequest": {
    "blob": "5bb0631c792c014e14dd772f522fd5bca6198621",
    "bytes": 331,
    "sha256": "8da81d14bf4c561ce4c0560c23a46a15cadfa571dda943e3905e15d4aa05ac4c"
  },
  "totalOriginalRanges": 10,
  "bodyAdmissionsAlreadyStarted": 3,
  "bodyRangesAlreadyComplete": 2,
  "newRecoveryStatusCalls": 1,
  "oldFailedStatusCalls": 1,
  "combinedOriginalStatusCalls": 2,
  "originalStatusCap": 8,
  "recoveryPages": 6,
  "immutablePageBytes": 16384,
  "originalPerIDPageCap": 128,
  "originalPayloadCap": 1048576
};
function deriveOracleBody02Handback(inputs) {
 const need=(value,label)=>{if(!value)throw Error(label);};
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const exact=(text,pin,label)=>need(same(gitBlobMeta(text),{blob:pin.blob,bytes:pin.bytes,sha256:pin.sha256}),label);
 exact(inputs.beforeRaw,HB.before,"whole_exact_original_paused_state");
 exact(inputs.recoveryRaw,HB.recoveryState,"whole_exact_recovery_closed_state");
 exact(inputs.rangeRaw,HB.range,"whole_exact_original_recovered_range");
 exact(inputs.payloadRaw,HB.payload,"whole_exact_original_payload");
 exact(inputs.nativeRaw,HB.native,"whole_exact_original_native");
 exact(inputs.statusRaw,HB.status,"whole_exact_new_same_ID_status");
 const before=JSON.parse(inputs.beforeRaw),recovery=JSON.parse(inputs.recoveryRaw),
  range=JSON.parse(inputs.rangeRaw),payload=JSON.parse(inputs.payloadRaw),
  native=JSON.parse(inputs.nativeRaw),status=JSON.parse(inputs.statusRaw);
 need(JSON.stringify(before,null,2)+"\n"===inputs.beforeRaw,"original_serialization_exact");
 const oldCall=before.calls[HB.originalFailedStatusKey],prior=before.activeObserver;
 need(before.job===HB.originalJob&&before.paused===true&&before.pending===HB.originalFailedStatusKey
  &&before.nativeCallInFlight===false&&Object.keys(before.calls).length===28
  &&before.completedObservers.length===5&&before.oracleReportBodyStarted===3
  &&before.oracleReportBodyRanges.length===2&&before.oracleReportBody===undefined
  &&before.oracleReportBody02Recovery===undefined,"original_pending_range_two_before_handback");
 need(oldCall.called===true&&oldCall.phase==="native_interpretation_refused"
  &&same(oldCall.sdkPin,HB.oldFailedStatusSDK)&&oldCall.sdkArchive.whole===true
  &&before.outerFailure.message==="native_tool_error_preserved_stop","failed_status_and_outer_failure_retained");
 need(prior.id===HB.originalOperation&&prior.tool==="binary_read"&&prior.futureClosed===false
  &&prior.pages.length===0&&prior.nextPageOffset===0,"old_active_observer_is_exact_original_ID");
 need(recovery.job===HB.originalJob&&recovery.pending===null&&recovery.activeObserver===null
  &&recovery.paused===false&&recovery.nativeCallInFlight===false
  &&Object.keys(recovery.calls).length===7&&recovery.completedObservers.length===1
  &&recovery.reconcileStatusCalls===1&&recovery.originalStatusCalls===1
  &&same(recovery.goPin,HB.recoveryGO),"recovery_has_one_closed_original_observer");
 const observer=recovery.completedObservers[0],calls=Object.values(recovery.calls);
 need(calls.every(c=>c.called===true&&c.phase==="accepted"&&c.sdkArchive.whole===true)
  &&calls.filter(c=>c.kind==="operation_status").length===1
  &&calls.filter(c=>c.kind==="operation_result").length===6
  &&calls.every(c=>JSON.parse(c.requestRaw).operation_id===HB.originalOperation),
  "recovery_contains_only_one_same_ID_status_and_six_original_pages");
 need(status.operation_id===HB.originalOperation&&status.async_state==="completed"
  &&status.owned_future_active===false&&status.payload_available===true
  &&status.result_state==="stored_observed"&&status.tool_name==="binary_read",
  "new_status_confirms_original_effect_inactive");
 need(observer.id===HB.originalOperation&&observer.tool==="binary_read"
  &&observer.completedInactive===true&&observer.pages===6
  &&same(observer.payload,HB.payload)&&same(observer.nativeText,HB.native),
  "append_exact_closed_original_observer");
 need(payload.resultType==="complete"&&payload.isError===false&&payload.content.length===1
  &&payload.content[0].type==="text"&&payload.content[0].text===inputs.nativeRaw,
  "exact_original_payload_native_bytes");
 need(same(range,recovery.originalBodyRange)&&range.offset===131072&&range.limit===65536
  &&range.next===196608&&range.originalOperation===HB.originalOperation
  &&same(range.originalPayload,HB.payload)&&range.originalPayloadTree===observer.payloadTree
  &&native.offset===range.offset&&native.next_offset===range.next&&native.eof===false
  &&native.path===before.oracleReportInfo.path&&native.size===before.oracleReportInfo.size
  &&native.version===before.oracleReportInfo.version&&native.data_base64===range.base64
  &&native.chunk_sha256===range.chunkSHA256,"original_range_and_current_version_binding");
 const bytes=unb64(range.base64);
 need(bytes.length===65536&&sha256Latin1(byteString(bytes))===range.chunkSHA256,
  "full_original_chunk_integrity_without_report_parse");
 let at=0;
 for(const row of before.oracleReportBodyRanges){
  need(row.offset===at&&row.next===row.offset+row.limit,"prior_two_ranges_contiguous");
  at=row.next;
 }
 need(at===range.offset,"append_without_gap_or_overlap");
 const after=JSON.parse(inputs.beforeRaw);
 after.paused=false;
 after.pending=null;
 after.activeObserver=null;
 after.completedObservers.push(observer);
 after.oracleReportBodyRanges.push(range);
 after.oracleReportBody02Recovery={
  schema:"heptabao.oracle271.r2.original-body02-handback-reference.r1",
  originalPausedState:HB.before,recoveryClosedState:HB.recoveryState,
  originalOperation:HB.originalOperation,recoverySlot:HB.recoverySlot,
  originalFailedStatusKey:HB.originalFailedStatusKey,originalFailedStatusSDK:HB.oldFailedStatusSDK,
  oldStatusDeliveryUnknownPreserved:true,recoveryStatusSDK:HB.recoveryStatusSDK,
  recoveryGO:HB.recoveryGO,recoverySource:HB.recoverySource,recoveryWholeTree:HB.recoveryWholeTree,
  originalPayload:HB.payload,originalNative:HB.native,originalRange:HB.range,
  counts:{originalFailedStatusCalls:1,newStatusCalls:1,combinedStatusCallsForOriginalID:2,
   originalStatusLimit:8,recoveryResultCalls:6,originalPerIDPageLimit:128,
   recoveryOperationStartCalls:0,originalBodyAdmissionsAlreadyStarted:3,totalOriginalBodyAdmissionsLimit:10},
  originalBudgetsReset:false,mainJournalUnchanged:HB.mainJournal,
  nextOriginalRequest:HB.nextRequest,remainingOriginalBinaryRanges:7
 };
 need(same(after.calls,before.calls)&&same(after.outerFailure,before.outerFailure),
  "all_original_call_records_and_outer_failure_byte_values_preserved");
 need(after.oracleReportBodyStarted===3&&after.completedObservers.length===6
  &&after.oracleReportBodyRanges.length===3,"original_cumulative_admission_count_not_reset");
 const allowed=new Set(["paused","pending","activeObserver","completedObservers","oracleReportBodyRanges","oracleReportBody02Recovery"]);
 for(const key of Object.keys(before))if(!allowed.has(key))need(same(before[key],after[key]),"untouched_original_field_"+key);
 need(same(after.completedObservers.slice(0,5),before.completedObservers)
  &&same(after.oracleReportBodyRanges.slice(0,2),before.oracleReportBodyRanges),"old_closed_inputs_not_rewritten");
 return {afterRaw:JSON.stringify(after,null,2)+"\n",changedFields:[...allowed],
  originalContextApplied:false,nativeCalls:0,gitCalls:0};
}
