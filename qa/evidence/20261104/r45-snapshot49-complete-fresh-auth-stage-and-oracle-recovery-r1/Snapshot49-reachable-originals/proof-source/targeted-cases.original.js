function runFormatted23FinalR3HistoryCases(fixture) {
 const before=gitBlobMeta(JSON.stringify(fixture)),rows=[];
 const positive=verifyFormatted23KnownHistory(fixture);
 if(positive.passed!==true)throw Error("R3_positive_history");
 rows.push({name:"all_three_exact_original_failures_and_recoveries",passed:true,checks:positive.checks});
 function negative(name,mutate,expected) {
  const x=JSON.parse(JSON.stringify(fixture));mutate(x);
  let error=null;try{verifyFormatted23KnownHistory(x);}catch(e){error=String(e.message);}
  rows.push({name,passed:error===expected,error,expected});
  if(error!==expected)throw Error("R3_negative:"+name+":"+error);
 }
 negative("INFO10_failed_row_still_required",x=>delete x.state.calls["sf23-r1-f10-info-p0"],"known_failed_row_required");
 negative("BODY16_failed_row_deleted_rejected",x=>delete x.state.calls["sf23-r1-f16-b00-p0"],"only_three_exact_nonaccepted_historical_calls");
 negative("BODY16_failed_row_accepted_rejected",x=>x.state.calls["sf23-r1-f16-b00-p0"].phase="accepted","only_three_exact_nonaccepted_historical_calls");
 negative("BODY16_failed_called_reset_rejected",x=>x.state.calls["sf23-r1-f16-b00-p0"].called=false,"body16_original_failed_row_required");
 negative("BODY16_failed_row_rewritten_rejected",x=>x.state.calls["sf23-r1-f16-b00-p0"].discarded=true,"body16_failed_row_exact_snapshot");
 negative("shared_timeout_SDK_omitted_rejected",x=>delete x.blobs["923d6b0480a7a2c63d80ec91ffbc84d0dc6a4011"],"original_timeout_SDK:text_present");
 negative("BODY16_recovery_wrong_request_rejected",x=>x.state.calls["sf23-r1-f16-b00-p0-recovery1"].requestRaw=x.state.calls["sf23-r1-f10-info-p0"].requestRaw,"body16_separate_recovery_exact_request");
 negative("BODY16_fourth_arm_leaf_missing_rejected",x=>{const a=x.state.calls["sf23-r1-f16-b00-p0-recovery1"].armed;a.entries=a.entries.filter(e=>e.path!=="original-failed-call.json");a.count=a.entries.length;a.bytes=a.entries.reduce((n,e)=>n+e.bytes,0);},"body16_exact_four_leaf_arm:exact_paths");
 negative("fourth_recovery_call_rejected",x=>x.state.calls["sf23-r1-f16-b00-p0-recovery2"]=x.state.calls["sf23-r1-f16-b00-p0-recovery1"],"no_unapproved_recovery_keys");
 negative("fourth_nonaccepted_call_rejected",x=>x.state.calls["sf23-r1-f16-b00-s0"].phase="native_interpretation_refused","only_three_exact_nonaccepted_historical_calls");
 negative("BODY16_recovery_SDK_changed_rejected",x=>x.state.calls["sf23-r1-f16-b00-p0-recovery1"].sdkPin=x.state.calls["sf23-r1-f16-b00-p0"].sdkPin,"body16_recovery_actual_SDK_pin");
 negative("BODY16_old_failure_flag_cleared_rejected",x=>x.state.body16Page0Recovery.oldFailureUnchanged=false,"body16_recovery_state_no_history_rewrite");
 negative("INFO10_old_failure_flag_cleared_rejected",x=>x.state.info10Page0Recovery.oldFailureUnchanged=false,"recovery_state_does_not_clear_old");
 negative("file7_archive_error_erased_rejected",x=>delete x.state.calls["sf23-r1-f07-b01-p0"].archiveFailure,"file7_final_original_call_preserved");
 negative("BODY16_recovery_origin_rewritten_rejected",x=>x.state.calls["sf23-r1-f16-b00-p0-recovery1"].recoveryOfDelivery="sf23-r1-f10-info-p0","body16_separate_recovery_exact_request");
 negative("BODY16_recovery_called_reset_rejected",x=>x.state.calls["sf23-r1-f16-b00-p0-recovery1"].called=false,"body16_separate_recovery_exact_request");
 negative("BODY16_recovery_error_is_not_allowed",x=>x.state.calls["sf23-r1-f16-b00-p0-recovery1"].phase="native_interpretation_refused","only_three_exact_nonaccepted_historical_calls");
 negative("BODY16_next_counter_not_reset_to_p1",x=>{const row=x.state.calls["sf23-r1-f16-b00-p2"];if(!row)throw Error("exact_actual_p2_fixture_required");delete x.state.calls["sf23-r1-f16-b00-p2"];x.state.calls["sf23-r1-f16-b00-p1"]=row;},"sf23-r1-f16-b00-p1:intent_exact_bytes");
 negative("BODY20_failed_row_deleted_rejected",x=>delete x.state.calls["sf23-r1-f20-b00-p3"],"only_three_exact_nonaccepted_historical_calls");
 negative("BODY20_original_called_reset_rejected",x=>x.state.calls["sf23-r1-f20-b00-p3"].called=false,"body20_original_failed_row_required");
 negative("BODY20_failed_row_rewritten_rejected",x=>x.state.calls["sf23-r1-f20-b00-p3"].discarded=true,"body20_failed_row_exact_snapshot");
 negative("BODY20_wrong_recovery_origin_rejected",x=>x.state.calls["sf23-r1-f20-b00-p3-recovery1"].recoveryOfDelivery="sf23-r1-f16-b00-p0","body20_separate_recovery_exact_request");
 negative("BODY20_fourth_arm_leaf_required",x=>{const a=x.state.calls["sf23-r1-f20-b00-p3-recovery1"].armed;a.entries=a.entries.filter(e=>e.path!=="original-failed-call.json");a.count=a.entries.length;a.bytes=a.entries.reduce((n,e)=>n+e.bytes,0);},"body20_exact_four_leaf_arm:exact_paths");
 negative("BODY20_original_prefix_page_required",x=>delete x.state.calls["sf23-r1-f20-b00-p1"],"body20_prior_page_1_row_required");
 negative("BODY20_history_preservation_flag_required",x=>x.state.body20Page3Recovery.oldFailureUnchanged=false,"body20_recovery_state_no_history_rewrite");
 negative("BODY20_recovery_cannot_be_error",x=>x.state.calls["sf23-r1-f20-b00-p3-recovery1"].phase="native_interpretation_refused","only_three_exact_nonaccepted_historical_calls");
 const partial=JSON.parse(JSON.stringify(fixture));partial.state.outputFiles=partial.state.outputFiles.slice(0,17);
 let error=null;try{verifyFormatted23FinalActual(partial);}catch(e){error=String(e.message);}
 rows.push({name:"not_all23_rejected",passed:error==="final23_requires_all_files",error,expected:"final23_requires_all_files"});
 if(rows.at(-1).passed!==true)throw Error("R3_final23_incomplete_refusal");
 if(gitBlobMeta(JSON.stringify(fixture)).sha256!==before.sha256)throw Error("R3_fixture_changed");
 return {schema:"heptabao.formatted23-final-verifier-R3-targeted-tests.v1",passed:true,cases:rows.length,positiveCases:1,historicalNegativeCases:26,incompleteFinalCase:1,rows,fixtureUnchanged:true,newNativeCalls:0,productCasesRun:0,final23Qualified:false};
}
