function qualifyFreshR2InfoSource(p,author,min,original,fixture) {
 const rows=[],ck=(name,v)=>{rows.push({name,passed:v===true});if(v!==true)throw Error(name);},f=p.raw,plan=JSON.parse(f["PLAN.public.json"]),q=JSON.parse(f["REQUEST.exact.json"]),o=JSON.parse(f["STDOUT.original.txt"]),same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 ck("whole_SOURCE16",p.audit.whole&&p.audit.files===16&&p.audit.bytes===325190);
 ck("author36_exact",author.exact&&author.value.pass===true&&author.value.check_count===36);
 ck("root11_closed_outer",min.value.passed&&min.value.checks===11&&min.value.currentCalls===0&&min.value.currentFutures===0);
 ck("exact_actual_state_and_stdout",f["PRIOR-STATE.original.json"]===original.raw["STATE.original.closed.json"]&&f["STDOUT.original.txt"]===original.raw["stdout.original.txt"]);
 ck("current_fixture_journal_exact",f["journal.before.js"]===fixture.raw["journal.after.js"]);
 ck("strict_journal_roundtrip",strictApply(f["journal.before.js"],f["journal.strict.diff"]).text===f["journal.after.js"]&&strictApply(f["journal.after.js"],f["journal.strict.diff"],true).text===f["journal.before.js"]);
 ck("strict_original_INFO_rebinding_roundtrip",gitBlobMeta(f["reference.original-info.js"]).blob==="ecd8f1dad7bf090ee8749c139bb0cfc2c972dfef"&&strictApply(f["reference.original-info.js"],f["binding.strict.diff"]).text===f["journal.after.js"]&&strictApply(f["journal.after.js"],f["binding.strict.diff"],true).text===f["reference.original-info.js"]);
 ck("one_exact_readonly_report_request",q.operation.tool==="file_info"&&q.operation.arguments.host==="x230"&&q.operation.arguments.path==="/home/qian/heptabao-official271-acl23-oracle-20261106-r2/result.public.json"&&same(gitBlobMeta(f["REQUEST.exact.json"]),plan.exact_request));
 ck("actual_report_size_SHA_full9",plan.target.bytes===651803&&plan.target.sha256===o.report.sha256&&same(plan.target.full9Strings,o.report.full9_decimal)&&o.report.bytes===651803&&o.capture_complete===true&&o.failure===null);
 ck("separate_INFO_GO_no_new_context_reset",plan.action==="authorize_oracle_report_info"&&plan.slot==="official271_x230_acl23_oracle_gitfirst_r2"&&f["journal.after.js"].includes("rootGo:s.oracleReportInfoGO?.pin??s.goPin"));
 ck("bounded_metadata_only",plan.maximum_file_info_operations===1&&plan.maximum_binary_read_operations===0&&plan.maximum_process_start_calls===0&&plan.maximumStatusQueries===8&&plan.maximumPages===128&&plan.immutablePageBytes===8192&&plan.maximumPayloadBytes===1048576);
 ck("no_body_version_or_case_claim",plan.actualReportVersion===null&&plan.actualReportBody===null&&plan.actualWholeACL23Qualification===null&&plan.sourceOnly===true&&plan.NativeCalls===0);
 return{schema:"heptabao.root-official271-r2-report-INFO-source.r1",passed:true,checks:rows.length,rows,packet:p.audit.tree,rootClosedOuter:min.pins,maximumFileInfo:1,bodyAuthorized:false,NativeCalls:0,fullReplacement:false};
}