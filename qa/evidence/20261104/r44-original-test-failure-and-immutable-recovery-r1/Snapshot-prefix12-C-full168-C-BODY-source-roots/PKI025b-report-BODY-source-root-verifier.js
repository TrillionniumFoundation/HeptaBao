
function qualifyReportBodySource(p,info,author){
 const checks=[],ck=(name,ok)=>checks.push({name,pass:ok===true}),pin=(raw,expected)=>{const m=gitBlobMeta(raw);return m.blob===expected.blob&&m.bytes===expected.bytes&&m.sha256===expected.sha256;};
 const plan=JSON.parse(p.raw["PLAN.public.json"]),a=p.raw["journal.after.BODY.source.js"],b=p.raw["journal.before.INFO.executed.js"],q=JSON.parse(p.raw["request.REVIEW-ONLY.public.json"]),i=JSON.parse(p.raw["checker.input.public.json"]),md=info.value.metadata;
 ck("whole_SOURCE18",p.audit.tree==="03c5150b1f6438a84a026bf1ee2d84f354580280"&&p.pins.length===18&&p.pins.reduce((n,x)=>n+x.bytes,0)===487577);
 ck("exact_source_request_diff_pins",pin(a,plan.source)&&pin(b,plan.base_info_source)&&pin(p.raw["journal.strict.diff"],plan.strict_diff)&&pin(p.raw["request.REVIEW-ONLY.public.json"],plan.exact_request));
 const f=strictApply(b,p.raw["journal.strict.diff"]),r=strictApply(a,p.raw["journal.strict.diff"],true);
 ck("eight_hunks_exact_forward_reverse",f.hunks===8&&r.hunks===8&&f.text===a&&r.text===b);
 ck("root_INFO_actual_qualified",info.value.passed&&info.pins.blob==="493332cfade7a38dfc4cdc4167fdd4a4a77663f5"&&info.value.nativeLaneReleased);
 ck("actual_INFO_binding_whole",pin(p.raw["INFO.native.original.json"],md.nativeText)&&plan.expected_report.infoOperation===md.originalOperation&&plan.expected_report.path===md.path&&plan.expected_report.bytes===md.size&&plan.expected_report.sha256===md.sha256&&plan.expected_report.version===md.version&&JSON.stringify(plan.expected_report.full9Strings)===JSON.stringify(md.full9Strings));
 ck("exact_single_range_49775",q.operation.tool==="binary_read"&&q.operation.arguments.host==="rog"&&q.operation.arguments.path===md.path&&q.operation.arguments.expected_version===md.version&&q.operation.arguments.offset===0&&q.operation.arguments.limit===md.size&&md.size===49775&&md.size<=65536);
 ck("exact_request_argument_set",Object.keys(q).sort().join(",")==="idempotency_key,operation"&&Object.keys(q.operation.arguments).sort().join(",")==="expected_version,host,limit,offset,path");
 ck("same_original_slot",plan.slot==="jwt_pki_025b05a3_build149_gitfirst_r2"&&a.includes('s.job==="1a1b10cad9b-fc05-7560"'));
 ck("author29_exact_reproduction",author.passed===29&&author.failed===0&&JSON.stringify(author)===JSON.stringify(JSON.parse(p.raw["checker.actual.public.json"])));
 ck("checker_inputs_whole_members",i.before===b&&i.after===a&&i.diff===p.raw["journal.strict.diff"]&&i.requestRaw===p.raw["request.REVIEW-ONLY.public.json"]&&i.infoNativeRaw===p.raw["INFO.native.original.json"]&&i.pure===p.raw["pure.original.js"]&&i.archive===p.raw["archive.original.js"]);
 ck("frozen_34_call_closed_frontier",Object.keys(i.state.calls).length===34&&i.state.completedObservers.length===11&&i.state.pending===null&&i.state.activeObserver===null&&!i.state.nativeCallInFlight&&!i.state.paused);
 ck("body_GO_only_attaches_to_existing_state",a.includes("s.stageResultBodyGO={pin:goPin,raw:goRaw,whole:true};")&&plan.original_context_reinitialize===false);
 ck("once_marker_before_dispatch",a.indexOf("s.stageResultBodyStarted=true")<a.indexOf("sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_process_start")&&a.includes("s.stageResultBodyStarted!==true"));
 ck("original_8K_new_binary_16K",a.includes('q.limit===(s.activeObserver.tool==="binary_read"?16384:8192)')&&a.includes('b.length<=(a.tool==="binary_read"?16384:8192)'));
 ck("whole_payload_cap_and_SHA_EOF",a.includes("v.total_bytes<=1048576")&&a.includes("v.next_offset===need.bytes && v.eof===true")&&a.includes("v.chunk_sha256===need.sha256")&&a.includes("bodyPin.sha256===need.sha256"));
 ck("no_new_process_INFO_or_target_reuse",plan.new_process_authorized===false&&plan.new_info_authorized===false&&plan.target_reuse_authorized===false&&plan.build_replay_authorized===false);
 ck("one_body_finite_original_observer",plan.limits.binary_starts===1&&plan.limits.operation_status_calls===8&&plan.limits.immutable_pages===128&&plan.limits.serialized_original_payload_cap===1048576&&plan.limits.concurrent_native_calls_or_future===1);
 ck("review_is_not_actual_body_or_test",plan.runtime_body_submitted===false&&plan.actual_tests_qualified===false);
 return {schema:"heptabao.root.PKI025b-report-BODY-SOURCE18-review.r44",passed:checks.every(x=>x.pass),checkCount:checks.length,checks,sourcePacket:p.audit.tree,journal:plan.source,exactRequest:plan.exact_request,expectedReport:plan.expected_report,author29Reproduced:true,actualReportBodyRead:false,newNativeCalls:0};
}
