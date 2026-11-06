function rootTest2LogInfoSource(f,author,body){
 const rows=[],ck=(name,v)=>{rows.push({name,passed:v===true});if(v!==true)throw Error(name);},plan=JSON.parse(f["PLAN.public.json"]),i=JSON.parse(f["checker.input.public.json"]),before=f["journal.before.original.js"],after=f["journal.after.source.js"];
 ck("author37_exact",author.exact&&author.value.passed===37&&author.value.failed===0);
 ck("report_full35_qualified",body.value.passed&&body.value.checks===35&&body.value.report.blob==="5bf4476672f08c251826efc1dc9833af30bdd5b4");
 ck("old_two_log_mechanism_exact",gitBlobMeta(before).blob==="850d83d091d21699713f26dba9489e0789c9bc12");
 ck("after_exact_candidate",gitBlobMeta(after).blob==="ae8aebd99035e038de6fe65d963878e72a4bb245");
 const d=strictApply(before,f["journal.strict.diff"]),r=strictApply(after,f["journal.strict.diff"],true);ck("three_strict_hunks_both",d.text===after&&r.text===before&&d.hunks===3&&r.hunks===3);
 ck("source_inputs_whole",i.before===before&&i.after===after&&i.reportRaw===f["report.original.json"]&&i.runnerRaw===f["runner.executed.original.py"]);
 ck("prior_state_exact_current_closed",f["STATE.prior.closed.original.json"]===load("r34_packet_PKI025b-report-BODY-actual-full51").raw["STATE.after.original.json"]);
 ck("same_actual_report",f["report.original.json"]===load("r34_packet_PKI025b-report-BODY-actual-full51").raw["report.original.json"]);
 ck("original_runner_pin",gitBlobMeta(f["runner.executed.original.py"]).blob==="f8b36c8adccb493dfc6aa507856150ce8a6a764d");
 ck("same_context_readonly_aliases",i.priorSlot==="jwt_pki_025b05a3_build149_gitfirst_r2"&&plan.original_context.read_only&&plan.original_context.two_legacy_internal_aliases_refer_to_this_same_actual_closed_context);
 const qs=[f["request.00.stderr.REVIEW-ONLY.json"],f["request.01.stdout.REVIEW-ONLY.json"]];
 qs.forEach((raw,n)=>{const q=JSON.parse(raw);ck("INFO_only_fixed_actual_path_"+n,q.operation.tool==="file_info"&&q.operation.arguments.host==="rog"&&q.operation.arguments.path===plan.targets[n].path&&gitBlobMeta(raw).blob===plan.exact_requests[n].blob&&Object.keys(q.operation.arguments).sort().join(",")==="host,path");});
 ck("fresh_metadata_not_assumed",plan.targets.every(t=>t.size===null&&t.version===null&&t.full9===null&&!t.metadata_observed&&!t.body_observed));
 ck("no_body_or_process_scope",plan.limits.file_info_operations===2&&plan.limits.process_start===0&&plan.limits.binary_read===0&&plan.limits.Cargo===0);
 ck("original_caps",plan.limits.operation_status_per_id===8&&plan.limits.immutable_pages_per_id===128&&plan.limits.immutable_page_bytes===8192&&plan.limits.immutable_payload_bytes===1048576);
 return {schema:"heptabao.root-original-test2-logs-INFO-source.r1",passed:true,checks:rows.length,rows,sourcePacket:"ad311f110c2f5f4b74266e6a0cbb56de62539adb",source:plan.source,requests:plan.exact_requests,sourceOnly:true,actualAssertionTextKnown:false,NativeCalls:0};
 }