function runFormatted23VerifierHistoryCases(fixture) {
 const rows=[],before=gitBlobMeta(JSON.stringify(fixture)).sha256;
 const positive=verifyFormatted23KnownHistory(fixture);
 rows.push({name:"exact_original_seven_call_history",passed:positive.passed===true,checks:positive.checks,scope:positive.scope});
 function negative(name,mutate,expected) {
  const x=JSON.parse(JSON.stringify(fixture));mutate(x);let error=null;
  try{verifyFormatted23KnownHistory(x);}catch(e){error=String(e.message);}
  const r={name,passed:error===expected,error,expected};rows.push(r);
  if(!r.passed)throw Error("negative_case:"+name+":"+error);
 }
 negative("deleted_failed_row_rejected",x=>delete x.state.calls["sf23-r1-f10-info-p0"],"known_failed_row_required");
 negative("failed_row_marked_accepted_rejected",x=>x.state.calls["sf23-r1-f10-info-p0"].phase="accepted","known_failed_row_required");
 negative("failed_call_flag_reset_rejected",x=>x.state.calls["sf23-r1-f10-info-p0"].called=false,"known_failed_row_required");
 negative("failed_SDK_changed_to_success_rejected",x=>x.state.calls["sf23-r1-f10-info-p0"].sdkPin=x.state.calls["sf23-r1-f10-info-admit"].sdkPin,"known_failed_sdk_exact");
 negative("failed_original_SDK_omitted_rejected",x=>delete x.blobs["923d6b0480a7a2c63d80ec91ffbc84d0dc6a4011"],"original_timeout_SDK:text_present");
 negative("failed_record_extra_rewrite_rejected",x=>x.state.calls["sf23-r1-f10-info-p0"].discarded=true,"failed_call_snapshot_unchanged");
 negative("recovery_same_id_request_changed_rejected",x=>x.state.calls["sf23-r1-f10-info-p0-recovery1"].requestRaw=x.state.calls["sf23-r1-f07-b01-p0"].requestRaw,"recovery_original_same_request");
 negative("fourth_arm_leaf_dropped_rejected",x=>{const a=x.state.calls["sf23-r1-f10-info-p0-recovery1"].armed;a.entries=a.entries.filter(e=>e.path!=="original-failed-call.json");a.count=a.entries.length;a.bytes=a.entries.reduce((n,e)=>n+e.bytes,0);},"recovery_exact_four_leaf_arm:exact_paths");
 negative("second_recovery_call_rejected",x=>x.state.calls["sf23-r1-f10-info-p0-recovery2"]=x.state.calls["sf23-r1-f10-info-p0-recovery1"],"no_unapproved_recovery_keys");
 negative("second_native_error_rejected",x=>x.state.calls["sf23-r1-f10-info-s0"].phase="native_interpretation_refused","only_one_nonaccepted_historical_call");
 negative("recovery_old_failure_flag_cleared_rejected",x=>x.state.info10Page0Recovery.oldFailureUnchanged=false,"recovery_state_does_not_clear_old");
 negative("file7_archive_error_erased_rejected",x=>delete x.state.calls["sf23-r1-f07-b01-p0"].archiveFailure,"file7_final_original_call_preserved");
 negative("file7_original_called_reset_rejected",x=>x.state.calls["sf23-r1-f07-b01-p0"].called=false,"file7_final_original_call_preserved");
 negative("file7_original_Git_error_omitted_rejected",x=>delete x.blobs["ddc8b45cb9056b09ca3a6bc0e94ea3aff95211f2"],"file7_original_Git_error:text_present");
 negative("new_unapproved_Git_failure_exception_rejected",x=>x.state.calls["sf23-r1-f10-info-admit"].archiveFailure="another Git error","no_extra_Git_failure_exceptions");
 negative("ordinary_success_row_with_error_SDK_rejected",x=>{const c=x.state.calls["sf23-r1-f10-info-admit"],f=x.state.calls["sf23-r1-f10-info-p0"];c.sdkPin=f.sdkPin;c.sdkArchive=f.sdkArchive;},"sf23-r1-f10-info-admit:success_original_SDK");
 let finalError=null;try{verifyFormatted23FinalActual(fixture);}catch(e){finalError=String(e.message);}
 rows.push({name:"current12_cannot_qualify_final23",passed:finalError==="final23_requires_all_files",error:finalError,expected:"final23_requires_all_files"});
 if(rows.at(-1).passed!==true)throw Error("final23_incomplete_gate");
 const unchanged=gitBlobMeta(JSON.stringify(fixture)).sha256===before;
 if(!unchanged)throw Error("fixture_mutated");
 return {schema:"heptabao.formatted23-final-verifier-targeted-tests.v1",passed:rows.every(r=>r.passed),cases:rows.length,rows,fixtureWholePreserved:true,newRuntimeCalls:0,productCasesRun:0,final23Qualified:false};
}
