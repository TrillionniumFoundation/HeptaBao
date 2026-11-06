function verifyLogsInfoSource(files,h,d){
 const {gitBlobMeta,parseLosslessIntegers}=h,checks=[];
 function ck(n,v){checks.push({name:n,pass:!!v});if(!v)throw Error(n);}
 function pin(n,raw,p){const a=gitBlobMeta(raw);ck(n,a.blob===p.blob&&a.bytes===p.bytes&&a.sha256===p.sha256);}
 const p=JSON.parse(files["PLAN.public.json"]),before=files["journal.before.js"],after=files["journal.after.js"],diff=files["journal.strict.diff"];
 pin("reference_whole",before,p.reference);pin("candidate_whole",after,p.source);pin("diff_whole",diff,p.diff);
 const f=d.applyStrictUnified(before,diff),r=d.applyStrictUnified(after,diff,true);
 ck("strict_forward_whole",f.text===after&&f.hunks===5);ck("strict_reverse_whole",r.text===before&&r.hunks===5);
 function defs(s){const rows=[...s.matchAll(/^(?:async )?function (\w+)\(/gm)];return Object.fromEntries(rows.map((v,i)=>[v[1],s.slice(v.index,rows[i+1]?.index??s.length)]));}
 const a=defs(before),b=defs(after);
 ck("same_13_definitions",Object.keys(a).length===13&&JSON.stringify(Object.keys(a))===JSON.stringify(Object.keys(b)));
 for(const n of p.whole_unchanged_definitions)ck("whole_unchanged_"+n,a[n]===b[n]);
 const report=parseLosslessIntegers(files["actual-build-result.original.json"]);
 pin("actual_failed_report_whole",files["actual-build-result.original.json"],p.actual_report);
 ck("actual_failed_no_runtime",report.status==="failed"&&report.failure==="normal production binary compilation failed"&&report.normal_release_build.exit_code===101&&report.runtime_tests_started===false);
 for(let i=0;i<2;i++){
  const raw=files[i===0?"requests-0-stderr-info.json":"requests-1-stdout-info.json"],q=JSON.parse(raw),t=p.targets[i];
  pin("exact_request_"+i,raw,p.requests[i]);
  ck("closed_typed_request_"+i,Object.keys(q).sort().join(",")==="idempotency_key,operation"&&q.operation.tool==="file_info"&&Object.keys(q.operation.arguments).sort().join(",")==="host,path"&&q.operation.arguments.host==="rog"&&q.operation.arguments.path===t.path);
  ck("actual_log_hash_"+i,t.sha256===report.normal_release_build[i===0?"stderr_sha256":"stdout_sha256"]);
  ck("unknown_metadata_not_invented_"+i,t.size===null&&t.version===null&&t.full9===null&&t.metadata_observed===false&&t.body_observed===false);
 }
 pin("previous_retrieval_state",files["prior-retrieval.STATE.original.json"],p.previous_contexts.complete_retrieval);
 pin("old_paused_state",files["prior-BUILD.STATE.original.json"],p.previous_contexts.old_paused_BUILD);
 const prior=JSON.parse(files["prior-retrieval.STATE.original.json"]),old=JSON.parse(files["prior-BUILD.STATE.original.json"]);
 ck("prior_retrieval_full_closed",prior.complete&&prior.pending===null&&prior.nativeCallInFlight===false&&prior.nextIndex===2);
 ck("original_pause_error_preserved",old.paused===true&&old.pending==="jwt-pki-33b814c7-build149-report-body-page2-r1"&&old.activeObserver.futureClosed===true);
 pin("executed_runner_whole",files["runner.original.py"],p.original_executed_runner);
 pin("executed_launcher_whole",files["launcher.original.py"],p.original_executed_launcher);
 ck("original_runner_fixed_paths",files["runner.original.py"].includes("(output / (label + '.stdout')).open('xb')")&&files["runner.original.py"].includes("(output / (label + '.stderr')).open('xb')"));
 ck("closed_process_start_guard",after.includes('throw new Error("metadata_scope_has_no_process_start_authorization")'));
 ck("only_file_info_new_admission",after.includes('op.tool==="file_info"')&&!after.includes('op.tool==="binary_read"'));
 ck("two_once_markers",after.includes("i<2")&&after.includes("s.logInfoStarted[i]===false")&&after.indexOf('s.logInfoStarted[s.logInfos.length]=true')<after.indexOf('sdk=await tools.'));
 ck("exact_info_full9",after.includes('md.uid===1000 && md.gid===1000 && md.link_count===1')&&after.includes('String(32768|v.mode)')&&after.includes('parts[2]===String(v.size)'));
 ck("fixed_payload8k_1m",after.includes('q.limit===8192')&&after.includes('v.total_bytes<=1048576'));
 ck("no_prior_context_store",!after.includes('store(GF_PRIOR_SLOT')&&!after.includes('store(GF_ORIGINAL_SLOT'));
 new Function("tools","store","load",files["pure.original.js"]+"\n"+files["archive.original.js"]+"\n"+after+"\nreturn gfRun;");
 ck("construct_only_no_invocation",true);
 return {schema:"heptabao.compiler-logs-info.source-checks.r1",status:"PASS",checks:checks.length,results:checks,Native:0,candidate_invoked:false};
}
