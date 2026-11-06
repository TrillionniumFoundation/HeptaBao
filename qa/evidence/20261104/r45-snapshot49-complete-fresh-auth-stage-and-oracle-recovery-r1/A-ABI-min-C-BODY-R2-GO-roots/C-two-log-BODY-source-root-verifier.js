function rootTwoLogBodiesR2(f,old,actual,author){
 const rows=[],ck=(name,v)=>{rows.push({name,passed:v===true});if(v!==true)throw Error(name);},eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b),plan=JSON.parse(f["PLAN.public.json"]),i=JSON.parse(f["checker.input.public.json"]),before=f["journal.before.original.js"],r1=f["journal.R1.original.js"],after=f["journal.after.source.js"];
 ck("source31_and_prepare26_exact",author.sourceExact&&author.source.pass&&author.source.check_count===31&&author.prepareExact&&author.prepare.pass&&author.prepare.check_count===26);
 ck("actual_INFO_root36",actual.value.passed&&actual.value.checks===36&&actual.value.observationLaneReleased);
 ck("R1_preserved_exact",r1===old["journal.after.source.js"]&&gitBlobMeta(r1).blob==="7e4332a15642b9bed13804656996c2637bddecfe");
 ck("only_one_line_GO_pin_fix",after===r1.replace("rootGo:s.goPin,originalJob:s.job","rootGo:s.failedTestLogBodiesGO?.pin??s.goPin,originalJob:s.job"));
 const d=strictApply(r1,f["journal.R1-to-R2.strict.diff"]),r=strictApply(after,f["journal.R1-to-R2.strict.diff"],true);ck("one_exact_hunk_forward_reverse",d.text===after&&r.text===r1&&d.hunks===1&&r.hunks===1);
 ck("all_new_source_strict_from_original_INFO",strictApply(before,f["journal.strict.diff"]).text===after&&strictApply(after,f["journal.strict.diff"],true).text===before);
 ck("exact_source_pin",gitBlobMeta(after).blob==="d2000cdc23f6a71d6c076dd1da2db42370a6a10d"&&gitBlobMeta(after).blob===plan.source.blob);
 ck("INFO_state_actual_whole",f["STATE.INFO.closed.original.json"]===load("r34_packet_PKI025b-test2-logs-INFO-actual-full47").raw["state.original.json"]&&i.stateRaw===f["STATE.INFO.closed.original.json"]);
 ck("BUILD_state_actual_whole",f["STATE.prior-BUILD.original.json"]===load("r34_packet_PKI025b-report-BODY-actual-full51").raw["STATE.after.original.json"]);
 ck("exact_actual_versions_and_hashes",plan.expected.length===2&&plan.expected.every((x,n)=>x.version===actual.value.actual[n].version&&x.sha256===actual.value.actual[n].sha256&&x.bytes===actual.value.actual[n].size&&x.infoOperation===actual.value.actual[n].originalOperation&&eq(x.full9Strings,actual.value.actual[n].full9Strings)));
 for(let n=0;n<2;n++){const name=n===0?"request.00.stderr.REVIEW-ONLY.json":"request.01.stdout.REVIEW-ONLY.json",q=JSON.parse(f[name]),e=plan.expected[n];
 ck("request_original_unchanged_"+n,f[name]===old[name]&&gitBlobMeta(f[name]).blob===plan.exact_requests[n].blob&&q.operation.tool==="binary_read"&&q.operation.arguments.host==="rog"&&q.operation.arguments.path===e.path&&q.operation.arguments.expected_version===e.version&&q.operation.arguments.offset===0&&q.operation.arguments.limit===e.bytes);
 }
 ck("566_total_only",plan.expected.reduce((a,x)=>a+x.bytes,0)===566&&plan.limits.binary_read_starts===2&&plan.limits.file_info_starts===0&&plan.limits.process_start_calls===0);
 ck("old_slot_attached_not_initialized",plan.initialize===false&&plan.entry_action==="authorize_failed_test_log_bodies"&&plan.slot==="jwt_pki_025b05a3_build149_failed_test2_logs_info_gitfirst_r1");
 ck("whole_validated_GO_before_pin_selection",after.includes('s.failedTestLogBodiesGO={pin:goPin,raw:goRaw,whole:true};')&&after.includes('goWholeReadback===true && gfMetaEquals(goRaw,goPin)'));
 ck("prior_donor_already_had_same_pattern",f["reference.compiler-stderr-body.original.js"].includes("rootGo:s.compilerStderrBodyGO?.pin??s.goPin"));
 ck("page_and_payload_caps",plan.limits.new_binary_page_bytes===16384&&plan.limits.old_metadata_page_bytes===8192&&plan.limits.retained_payload_bytes===1048576);
 return {schema:"heptabao.root-test2-two-log-bodies-source.r2",passed:true,checks:rows.length,rows,sourcePacket:"943b982b8e1ea3b8f37343e59206500b32ad9822",source:plan.source,requests:plan.exact_requests,authorSource31Exact:true,actualPrepareFake26Exact:true,R1FindingResolvedInSourceOnly:true,NativeCalls:0,actualLogBodiesRead:false};
 }