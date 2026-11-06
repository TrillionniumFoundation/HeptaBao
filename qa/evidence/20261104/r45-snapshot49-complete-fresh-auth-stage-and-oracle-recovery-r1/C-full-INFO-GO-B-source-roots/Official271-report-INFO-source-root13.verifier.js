function rootOracleInfoSource(f,original,minimum,author){
 const rows=[],ck=(name,v)=>{rows.push({name,passed:v===true});if(v!==true)throw Error(name);},p=gitBlobMeta,pl=JSON.parse(f["PLAN.public.json"]),q=JSON.parse(f["REQUEST.exact.json"]),s=JSON.parse(f["PRIOR-STATE.original.json"]),out=JSON.parse(f["STDOUT.original.txt"]);
 ck("author36_exact",author.exact&&author.value.pass&&author.value.check_count===36);
 ck("root_original13_closed",minimum.value.passed&&minimum.value.transportLaneReleased&&minimum.value.originalJob===pl.original_job);
 ck("before_actual_journal_exact",f["journal.before.js"]===original["journal.original.js"]&&p(f["journal.before.js"]).blob===pl.before.blob);
 ck("actual_prior_state_unchanged",f["PRIOR-STATE.original.json"]===original["STATE.original.json"]&&p(f["PRIOR-STATE.original.json"]).blob===pl.originalState.blob);
 ck("original_failed_stdout_unchanged",f["STDOUT.original.txt"]===original["STDOUT.original.txt"]&&p(f["STDOUT.original.txt"]).blob===pl.originalStdout.blob);
 const fw=strictApply(f["journal.before.js"],f["journal.strict.diff"]),rv=strictApply(f["journal.after.js"],f["journal.strict.diff"],true);
 ck("strict_six_hunk_roundtrip",fw.text===f["journal.after.js"]&&fw.hunks===6&&rv.text===f["journal.before.js"]);
 ck("exact_fixed_request_pin",p(f["REQUEST.exact.json"]).blob===pl.exact_request.blob&&pl.exact_request.blob==="3d4b0ac9b5e642da091ae07c6e446c2c4947b817");
 ck("one_exact_public_report_INFO",q.operation.tool==="file_info"&&q.operation.arguments.host==="x230"&&q.operation.arguments.path==="/home/qian/heptabao-official271-acl23-oracle-20261106-r1/result.public.json");
 ck("reported_file_identity_bound",pl.target.bytes===36658&&pl.target.sha256===out.report.sha256&&JSON.stringify(pl.target.full9Strings)===JSON.stringify(out.report.full9_decimal));
 ck("original7_2_closed_no_reinitialize",Object.keys(s.calls).length===7&&s.completedObservers.length===2&&s.pending===null&&s.activeObserver===null&&!s.nativeCallInFlight&&pl.noReinitialize);
 ck("new_arm_separate_INFO_GO",f["journal.after.js"].includes("rootGo:s.oracleReportInfoGO?.pin??s.goPin"));
 ck("original_budget_and_single_file",pl.maximum_file_info_operations===1&&pl.maximum_process_start_calls===0&&pl.maximum_binary_read_operations===0&&pl.maximumOperationStatusCalls===8&&pl.maximumImmutablePages===128&&pl.immutablePageBytes===8192&&pl.maximumPayloadBytes===1048576);
 ck("no_child_or_body_qualification",pl.ownerChildClosureNotYetObserved&&pl.bodyRequiresSeparateVersionBoundSourceAndGO&&pl.actualVersionBeforeInfo===null);
 return {schema:"heptabao.root-official271-original-report-INFO-source.r1",passed:true,checks:rows.length,rows,sourceTree:"244182a0e6e5d07dc47effcf3b0cd6160a76fecc",author36Exact:true,sourceOnly:true,newNativeCalls:0};
}