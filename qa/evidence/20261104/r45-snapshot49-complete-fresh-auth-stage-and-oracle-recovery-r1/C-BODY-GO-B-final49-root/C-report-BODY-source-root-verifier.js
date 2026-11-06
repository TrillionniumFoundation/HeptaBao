function rootOracleReportBodySource(p,actual,author) {
 const rows=[],ck=(name,v)=>{rows.push({name,passed:v===true});if(v!==true)throw Error(name);},f=p.raw,plan=JSON.parse(f["PLAN.public.json"]),q=JSON.parse(f["REQUEST.exact.json"]),a=q.operation.arguments,before=f["journal.before.js"],after=f["journal.after.js"],d=f["journal.strict.diff"];
 ck("whole_SOURCE17",p.audit.whole&&p.audit.files===17&&p.audit.bytes===381965);
 ck("actual_INFO_independently_closed",actual.value.passed&&actual.value.newCalls===2&&actual.value.bodyBytesObserved===0);
 ck("author44_exact",author.exact&&author.value.passed&&author.value.check_count===44);
 ck("exact_prior_reconciliation_source",gitBlobMeta(before).blob==="2ac1f78dd4076b31c8eaaaba4c1e344f70c807e0");
 ck("eight_hunk_forward_reverse",strictApply(before,d).text===after&&strictApply(after,d,true).text===before&&strictApply(before,d).hunks===8);
 ck("closed_state_same_as_actual",f["STATE.info-closed.original.json"]===actual.rawState&&gitBlobMeta(f["STATE.info-closed.original.json"]).blob==="a4b8f2cbee6e575453b936db6e4d9cc833bf96b7");
 ck("original_paused_state_same",gitBlobMeta(f["ORIGINAL.paused-state.json"]).blob==="6c825b1f09d8584aafef83e153a7470679cae7cb");
 ck("actual_INFO_same",gitBlobMeta(f["INFO.native.original.json"]).blob==="ae824e96ceecb3ab93738c3f00fdc029203ec199");
 ck("one_exact_versioned_binary_read",q.operation.tool==="binary_read"&&a.host==="x230"&&a.path===plan.target.path&&a.offset===0&&a.limit===36658&&a.expected_version==="2053:3318893:36658:1793979309530036044:1793979309530036044"&&gitBlobMeta(f["REQUEST.exact.json"]).blob==="1420c634a44df2e1002eaeb58b8fb9be1ea7954a");
 ck("bounded_read_no_new_process_or_INFO",plan.maximumBinaryReads===1&&plan.maximumMetadataReads===0&&plan.maximumProcessStarts===0&&plan.maximumBodyBytes===36658&&plan.maximumStatusPerReturnedID===8&&plan.maximumPagesPerReturnedID===128&&plan.newBodyPageBytes===16384&&plan.maximumPayloadBytes===1048576);
 ck("new_arms_bind_separate_BODY_GO",after.includes("rootGo:s.oracleReportBodyGO?.pin??s.goPin")&&after.includes("original_paused_status_error_context_byte_identical"));
 ck("source_only_no_owner_closure_claim",plan.sourceOnly===true&&plan.bodyGo===null&&plan.noRuntimeCalls===true&&plan.previousPreTimeoutDeriverNotApplicable===true);
 return{schema:"heptabao.root-version-bound-original-report-body-source.r1",passed:true,checks:rows.length,rows,sourcePacket:p.audit.tree,readOnly:true,maximumBinaryReads:1,maximumBodyBytes:36658,NativeCalls:0,ownerChildClosureQualified:false};
}