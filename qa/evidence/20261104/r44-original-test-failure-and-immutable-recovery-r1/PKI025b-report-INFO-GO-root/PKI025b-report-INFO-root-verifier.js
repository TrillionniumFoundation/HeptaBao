
function qualifyBuildReportInfoSource(p,terminalQ,author){
 const checks=[],ck=(name,ok)=>checks.push({name,pass:ok===true}),pin=(raw,pin)=>{const m=gitBlobMeta(raw);return m.blob===pin.blob&&m.bytes===pin.bytes&&m.sha256===pin.sha256;};
 const plan=JSON.parse(p.raw["PLAN.public.json"]),input=JSON.parse(p.raw["checker.inputs.public.json"]),before=p.raw["journal.before.original.js"],after=p.raw["journal.after.source.js"],q=JSON.parse(p.raw["request.REVIEW-ONLY.public.json"]);
 ck("whole_SOURCE20",p.audit.tree==="167e48e740541344a9b719bfda9c5285078d7c8d"&&p.pins.length===20&&p.pins.reduce((n,x)=>n+x.bytes,0)===458849);
 ck("source_pins_exact",pin(before,plan.before)&&pin(after,plan.journal)&&pin(p.raw["request.REVIEW-ONLY.public.json"],plan.exact_request)&&pin(p.raw["journal.strict.diff"],plan.diff));
 const d=strictApply(before,p.raw["journal.strict.diff"]),r=strictApply(after,p.raw["journal.strict.diff"],true);
 ck("three_hunks_strict_forward_reverse",d.hunks===3&&r.hunks===3&&d.text===after&&r.text===before);
 ck("author39_exact_reproduction",author.passed===39&&author.failed===0&&JSON.stringify(author)===JSON.stringify(JSON.parse(p.raw["checker.actual.public.json"])));
 ck("checker_inputs_whole_files",input.before===before&&input.after===after&&input.diff===p.raw["journal.strict.diff"]&&input.requestRaw===p.raw["request.REVIEW-ONLY.public.json"]&&input.startRequestRaw===p.raw["START.request.original.json"]&&input.pure===p.raw["pure.original.js"]&&input.archive===p.raw["archive.original.js"]&&input.beforeCurrentJournal===p.raw["current-build-journal.original.js"]);
 ck("root_terminal_qualification_available",terminalQ.value.passed&&terminalQ.value.nativeLaneReleased&&terminalQ.pins.blob==="7e13974f8a7cf9bf4cf35333432b7a72194ff689");
 ck("exact_same_report_from_actual_terminal",q.operation.arguments.path===terminalQ.value.finalReport.path&&plan.expected.whole_sha256===terminalQ.value.finalReport.sha256);
 ck("only_fixed_metadata_request",Object.keys(q).sort().join(",")==="idempotency_key,operation"&&q.operation.tool==="file_info"&&Object.keys(q.operation.arguments).sort().join(",")==="host,path"&&q.operation.arguments.host==="rog"&&q.idempotency_key==="heptabao-native-jwt-pki-025b05a3-build149-observe-r2-result-info");
 ck("metadata_no_speculative_size_or_version",plan.expected.size===null&&plan.expected.version===null&&plan.expected.maximum_size===1048576);
 ck("metadata_mode_identity_preserved",plan.expected.permission_mode===384&&plan.expected.full_mode===33152&&plan.expected.uid===1000&&plan.expected.gid===1000&&plan.expected.link_count===1);
 ck("original_slot_no_reinitialization",plan.slot==="jwt_pki_025b05a3_build149_gitfirst_r2"&&after.includes('s.job==="1a1b10cad9b-fc05-7560"')&&after.includes("s.stageResultInfoGO===undefined")&&after.includes("s.stageResultInfoStarted!==true"));
 ck("new_GO_exact_request_pin_once",after.includes("g.maximum_file_info_starts===1")&&after.includes("g.binary_read_authorized===false")&&after.includes("gfMetaEquals(raw,GF_STAGE_INFO_REQUEST)"));
 ck("3_fixed_native_prerequisites_match_original",plan.prerequisites.length===3&&plan.prerequisites.every((x,i)=>pin(p.raw[["authority7.native.original.json","streams0.native.original.json","streams1.native.original.json"][i]],x.nativeText)));
 ck("actual_31_call_10_observer_boundary",Object.keys(input.state.calls).length===31&&input.state.completedObservers.length===10&&input.state.pending===null&&input.state.activeObserver===null&&!input.state.nativeCallInFlight&&!input.state.paused);
 ck("whole_report_hash_fixed_in_source",after.includes('const GF_STAGE_RESULT_EXPECTED_SHA256 = "'+terminalQ.value.finalReport.sha256+'";'));
 ck("source_count_limits",plan.limits.file_info_starts===1&&plan.limits.operation_status_per_observer===8&&plan.limits.immutable_page_bytes===8192&&plan.limits.immutable_pages_per_observer===128&&plan.limits.payload_bytes===1048576);
 ck("scope_does_not_start_build_or_read_body",plan.new_process_authorized===false&&plan.binary_read_authorized===false&&plan.target_reuse_authorized===false&&!after.includes('op.tool==="binary_read"'));
 ck("failure_and_test_results_still_unknown",plan.unknowns.failure_cause===null&&plan.unknowns.actual_test_results===null&&plan.product_test_qualification===false);
 return {schema:"heptabao.root.PKI025b-report-INFO-SOURCE20-qualification.r44",passed:checks.every(x=>x.pass),checkCount:checks.length,checks,sourcePacket:p.audit.tree,journal:plan.journal,exactRequest:plan.exact_request,author39Reproduced:true,scope:"one fixed report metadata observation source; no dispatch in this review",actualReportBodyRead:false,actualMetadataObserved:false,newNativeCalls:0};
}
