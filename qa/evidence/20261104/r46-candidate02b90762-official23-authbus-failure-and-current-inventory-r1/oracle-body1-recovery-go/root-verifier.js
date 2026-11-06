function qualifySameArmRestore(actual,source,bodyGO){
 const a=actual.raw,f=source.raw,plan=JSON.parse(f["PLAN.public.json"]),rows=[];const ck=(name,x)=>{if(x!==true)throw Error(name);rows.push({name,passed:true});};const eq=(raw,p)=>{const m=gitBlobMeta(raw);return m.blob===p.blob&&m.bytes===p.bytes&&m.sha256===p.sha256;};
 ck("actual23_and_SOURCE9_whole",actual.audit.whole===true&&actual.audit.files===23&&source.audit.whole===true&&source.audit.files===9);
 ck("same_exact_paused_state",a["STATE.paused.original.json"]===f["STATE.before.original.json"]&&eq(f["STATE.before.original.json"],plan.before));
 ck("same_actual_readonly_reconciliation",a["RECONCILIATION.actual.json"]===f["RECONCILIATION.actual.json"]&&eq(f["RECONCILIATION.actual.json"],plan.actualReadOnlyReconciliation));
 ck("restore_source_pin",eq(f["restore.source.js"],plan.source));
 const h=JSON.parse(a["HISTORY.original.json"]);ck("eight_original_Git_history_records",h.length===8&&h.every((x,i)=>eq(a["git-sdk-"+String(i+1).padStart(2,"0")+".original.json"],x.pin)));
 const create=JSON.parse(a["git-sdk-01.original.json"]),error=JSON.parse(a["git-sdk-03.original.json"]);
 ck("known_original_create_ACK",create.isError===false&&create.structuredContent.sha===plan.requiredGO.expected_tree&&h.filter(x=>x.stage==="create_tree").length===1);
 ck("original_read_UNKNOWN_retained",error.isError===true&&error.structuredContent.error_code==="UNKNOWN"&&error.structuredContent.error.includes("Server disconnected"));
 const rec=JSON.parse(f["RECONCILIATION.actual.json"]).value;
 ck("exact_original_arm_Merkle",immediateTreeSha(rec.entries.map(x=>({path:x.path,mode:"100644",type:"blob",sha:x.blob})))===plan.requiredGO.expected_tree&&rec.whole===true&&rec.recoveryReadOnly===true&&rec.nativeCalled===false&&rec.mutationRepeated===false);
 for(const name of ["armed","intent","request"]){const e=rec.entries.find(x=>x.path===name+".json");ck("whole_original_"+name,!!e&&eq(a["ARM."+name+".original.json"],e));const hr=h.find(x=>x.stage==="recovery_whole:"+name+".json"),sdk=JSON.parse(a["git-sdk-"+String(hr.ordinal).padStart(2,"0")+".original.json"]);ck("whole_recovery_SDK_"+name,sdk.isError===false&&sdk.structuredContent.content===a["ARM."+name+".original.json"]);}
 const sdk=JSON.parse(a["BODY1.status0.sdk.original.json"]),ns=JSON.parse(sdk.content[0].text);
 ck("original_binary_future_completed_inactive",sdk.isError===false&&ns.operation_id===plan.requiredGO.original_operation&&ns.async_state==="completed"&&ns.owned_future_active===false&&ns.payload_available===true&&ns.result_state==="stored_observed");
 const before=JSON.parse(f["STATE.before.original.json"]),q=JSON.parse(a["ARM.request.original.json"]),c=before.calls[before.pending];
 ck("pending_page_never_called",before.paused===true&&before.nativeCallInFlight===false&&before.pending===plan.requiredGO.pending_call&&c.called===false&&c.phase==="arming"&&c.sdkPin===undefined&&c.armed===undefined&&q.operation_id===ns.operation_id&&q.offset===0&&q.limit===16384);
 ck("same_original_BODY_GO",before.oracleReportBodyGO.raw===bodyGO.text&&before.oracleReportBodyGO.pin.blob===bodyGO.pins.blob);
 const result=restoreOnlyOriginalOracleR2Page0Arm({stateRaw:f["STATE.before.original.json"],reconciliationRaw:f["RECONCILIATION.actual.json"],goRaw:f["FAKE-GO.source-only.json"],goPin:gitBlobMeta(f["FAKE-GO.source-only.json"]),goWholeReadback:true});
 ck("pure_restoration_matches_exact_proposed_bytes",result.stateRaw===f["STATE.after.proposed.json"]&&eq(result.stateRaw,plan.expectedAfter)&&result.NativeCalls===0&&result.GitCalls===0);
 const reverse=JSON.parse(result.stateRaw);delete reverse.calls[before.pending].armed;reverse.calls[before.pending].phase="arming";reverse.paused=true;
 ck("exactly_three_fields_reverse_to_original",JSON.stringify(reverse,null,2)+"\n"===f["STATE.before.original.json"]);
 ck("failure_and_original_pending_history_preserved",JSON.stringify(result.state.outerFailure)===JSON.stringify(before.outerFailure)&&result.state.calls[before.pending].archiveFailure===c.archiveFailure&&result.state.pending===before.pending&&result.state.calls[before.pending].called===false);
 return{schema:"heptabao.root.oracle271.r2.same-arm-page0-recovery.qualification.r1",passed:true,checks:rows.length,rows,actualPacket:actual.audit,sourcePacket:source.audit,before:plan.before,after:plan.expectedAfter,source:plan.source,reconciliation:plan.actualReadOnlyReconciliation,originalOperation:ns.operation_id,originalRequest:plan.requiredGO.original_request,originalReadFailurePreserved:true,originalBinaryAdmissionRepeated:false,actualRestoreApplied:false,NativeCalls:0,fullReplacement:false,productionCutover:false,legacyCleanup:false};
}