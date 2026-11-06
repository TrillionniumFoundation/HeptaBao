function rootOracleInfoStatusReconcile(f,prior,author,rootUnknown){
 const rows=[],ck=(name,v)=>{rows.push({name,passed:v===true});if(v!==true)throw Error(name);},p=gitBlobMeta,pl=JSON.parse(f["PLAN.public.json"]),q=JSON.parse(f["REQUEST.status.exact.json"]),old=JSON.parse(f["ORIGINAL.paused-state.json"]),after=f["journal.after.js"];
 ck("author37_exact",author.exact&&author.value.pass&&author.value.check_count===37);
 ck("root13_original_UNKNOWN_retained",rootUnknown.value.passed&&rootUnknown.value.originalFutureClosed===false&&rootUnknown.value.laneReserved==="C1");
 ck("exact_original_paused_state",f["ORIGINAL.paused-state.json"]===prior["STATE.paused.original.json"]&&p(f["ORIGINAL.paused-state.json"]).blob===pl.original_state.blob);
 ck("exact_original_error_SDK",f["ORIGINAL.failed-status.sdk.json"]===prior["STATUS.original.sdk.json"]&&p(f["ORIGINAL.failed-status.sdk.json"]).blob===pl.original_failed_status_SDK.blob);
 ck("before_is_exact_executed_INFO_journal",f["journal.before.js"]===prior["journal.original.js"]&&p(f["journal.before.js"]).blob==="ecd8f1dad7bf090ee8749c139bb0cfc2c972dfef");
 const fw=strictApply(f["journal.before.js"],f["journal.strict.diff"]),rv=strictApply(after,f["journal.strict.diff"],true);
 ck("strict7_hunk_roundtrip",fw.text===after&&fw.hunks===7&&rv.text===f["journal.before.js"]);
 ck("only_original89_byte_status_request",f["REQUEST.status.exact.json"]===prior["STATUS.request.json"]&&Object.keys(q).join(",")==="operation_id"&&q.operation_id===rootUnknown.value.originalOperation);
 ck("new_context_preserves_original_every_entry",pl.original_slot!==pl.new_slot&&after.includes('original_paused_status_error_context_byte_identical')&&after.includes('const prior=JSON.parse(originalStateRaw),oldCall=')&&after.includes('activeObserver:observer,reconcileStatusCalls:0,originalStatusCalls:1'));
 ck("Native_tools_only_status_result",!after.includes("tools.mcp__codex_apps__heptaruntime_mac_controller_operation_start(")&&!after.includes("tools.mcp__codex_apps__heptaruntime_mac_controller_process_start("));
 ck("once_status_then_original_bounded_pages",pl.maximum_new_operation_status_calls===1&&pl.original_operation_status_calls===1&&pl.maximum_combined_operation_status_calls===8&&pl.maximum_operation_result_calls===128&&pl.immutable_page_bytes===8192&&pl.maximum_payload_bytes===1048576&&pl.maximum_operation_start_calls===0&&pl.maximum_process_start_calls===0);
 ck("new_arms_use_new_GO",after.includes("rootGo:s.goPin,originalJob:s.job")&&!after.includes("rootGo:s.oracleReportInfoGO?.pin"));
 ck("old_failure_not_reclassified",old.calls[pl.original_failed_status_key].called===true&&old.calls[pl.original_failed_status_key].phase==="native_interpretation_refused"&&!old.activeObserver.futureClosed&&old.activeObserver.pages.length===0&&Object.keys(old.calls).length===9);
 ck("metadata_only_no_body",pl.BODY_authorized===false&&pl.report_target.bytes===36658&&pl.report_target.sha256==="4b72f600f6b794c5cf7198ebe76696179cd2477da587113a5ee7bfe81be3eece");
 return{schema:"heptabao.root-official271-INFO-same-ID-status-reconcile-source.r1",passed:true,checks:rows.length,rows,sourceTree:"3606a8a328fae0c3d093dbdac298325de87da4a5",author37Exact:true,sourceOnly:true,originalFutureClosed:false,originalUNKNOWNUnchanged:true,newNativeCalls:0};
}