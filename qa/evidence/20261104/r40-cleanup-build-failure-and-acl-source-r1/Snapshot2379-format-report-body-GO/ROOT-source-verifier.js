
function reviewSnapshot2379FormatBody22(){
 const p=load("r34_packet_Snapshot2379-formatter49-report-body-source22"),r=p.raw,plan=JSON.parse(r["PLAN.public.json"]),ig=load("r40_snapshot2379_formatter49_report_info_GO"),iq=load("r40_snapshot2379_formatter49_report_info_actual_qualification"),info=iq.value.actual_file_info,actual=load("r34_packet_Snapshot2379-formatter49-report-info-full-actual22"),checks=[];
 const ck=(name,v)=>{checks.push({name,passed:v===true});if(v!==true)throw Error(name)},eq=(raw,pin)=>{const m=gitBlobMeta(raw);return m.blob===pin.blob&&m.bytes===pin.bytes&&m.sha256===pin.sha256},same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 ck("whole22_165783",p.audit.whole===true&&p.audit.files===22&&p.audit.bytes===165783);
 ck("exact_executed_INFO_source",eq(r["journal.before.js"],ig.value.source)&&same(plan.baseline,ig.value.source));
 ck("exact_current_INFO21_root_and_original_metadata",eq(r["root-info-qualification.original.json"],iq)&&same(plan.rootActualInfoQualification,{blob:iq.blob,bytes:iq.bytes,sha256:iq.sha256})&&plan.rootActualInfoPacket===actual.audit.tree&&r["actual-file-info.original.json"]===actual.raw["file-info.original.json"]&&r["actual-info-binding.public.json"]===actual.raw["actual-metadata-binding.public.json"]&&r["actual-info-payload.original.json"]===actual.raw["payload.original.json"]&&r["actual-info-release.public.json"]===actual.raw["RELEASE.public.json"]);
 ck("candidate_and_reviewed_finite_range_basis_pins",eq(r["journal.after.js"],plan.candidate)&&eq(r["reference-cli13-original.js"],plan.sourceChanges.reviewedFiniteRangeBasis)&&plan.sourceChanges.reviewedFiniteRangeBasis.blob==="bfb93119d9e3bd6840f73023f605fa14e9f26790");
 const f=strictApply(r["journal.before.js"],r["journal.forward.diff"]),v=strictApply(r["journal.after.js"],r["journal.forward.diff"],true),reverse=strictApply(r["journal.after.js"],r["journal.reverse.diff"]);
 ck("eight_strict_hunks_both_directions",f.text===r["journal.after.js"]&&v.text===r["journal.before.js"]&&reverse.text===r["journal.before.js"]&&f.hunks===8&&v.hunks===8&&reverse.hunks===8);
 const ed=JSON.parse(r["declared-eight-edits.public.json"]),requests=plan.requests.map((x,i)=>({offset:x.offset,limit:x.limit,pin:x.request,raw:r["body"+i+".exact-request.json"]}));
 const c={before:r["journal.before.js"],after:r["journal.after.js"],pin:plan.candidate,edits:ed,diff:r["journal.forward.diff"],reverse:r["journal.reverse.diff"],authorization:ed[0].after,validation:ed[1].after,closeBlock:ed[6].after,expected:plan.actualExpected,requests};
 const author=verifyFormatterBodySource({candidate:c,infoCandidate:{after:c.before},actualInfo:r["actual-file-info.original.json"],capability:JSON.parse(r["operation-result-capability.original.json"])},gitBlobMeta,(raw,d)=>strictApply(raw,d).text,parseLosslessIntegers);
 ck("68_author_source_checks_reproduced",author.count===68&&same(author,JSON.parse(r["source-checks.public.json"])));
 const e=plan.actualExpected;
 ck("whole_actual_path_size_SHA_version_observer_bound",e.path===info.path&&e.bytes===info.size&&e.sha256===info.sha256&&e.version===info.version&&e.infoOperation===info.originalOperation&&same(e.infoNative,info.nativeText));
 ck("only_two_exact_actual_ranges",requests.length===2&&requests.every((x,i)=>eq(x.raw,x.pin))&&same(requests.map(x=>[x.offset,x.limit]),[[0,65536],[65536,53389]])&&requests.reduce((sum,x)=>sum+x.limit,0)===118925);
 ck("only_new_binary16K_old8K_and_caps",plan.limits.binaryReadStarts===2&&plan.limits.perBinaryReadBytes===65536&&plan.limits.fileAcceptanceBytes===131072&&plan.limits.actualFileBytes===118925&&plan.limits.newBodyImmutablePageBytes===16384&&plan.limits.oldObserversPageBytes===8192&&plan.limits.originalPayloadMaxBytes===1048576&&plan.limits.oneFuture===true&&plan.limits.eachObserverMustCloseBeforeNext===true);
 const validate=new Function("gitBlobMeta",c.after+"\nreturn gfValidateRequest;")(gitBlobMeta);
 const st={paused:false,nativeCallInFlight:false,pending:null,job:plan.originalJob,activeObserver:null,startCalled:true,formatResultBodyGO:{whole:true},formatResultBodyRanges:[],formatResultBodyStarted:0};
 validate(st,"operation_start",JSON.parse(requests[0].raw),requests[0].raw);ck("fake_guard_exact_first_accepted",true);
 const second={...st,formatResultBodyRanges:[{}],formatResultBodyStarted:1};
 validate(second,"operation_start",JSON.parse(requests[1].raw),requests[1].raw);ck("fake_guard_exact_next_after_first_closed",true);
 const reject=(name,state,raw)=>{let denied=false;try{validate(state,"operation_start",JSON.parse(raw),raw)}catch(_){denied=true;}ck(name,denied);};
 reject("fake_guard_out_of_order_second_denied",st,requests[1].raw);
 reject("fake_guard_repeat_first_denied",second,requests[0].raw);
 reject("fake_guard_third_range_denied",{...second,formatResultBodyRanges:[{},{}],formatResultBodyStarted:2},requests[1].raw);
 reject("fake_guard_no_GO_denied",{...st,formatResultBodyGO:null},requests[0].raw);
 reject("fake_guard_prior_active_future_denied",{...st,activeObserver:{id:"x"}},requests[0].raw);
 const wrong=JSON.parse(requests[0].raw);wrong.operation.arguments.expected_version+="0";reject("fake_guard_changed_version_denied",st,JSON.stringify(wrong,null,2)+"\n");
 ck("unchanged_content_reuse_not_yet_authorized",plan.futureOutputEvidenceProposal.changedCount===23&&plan.futureOutputEvidenceProposal.sameCount===26&&plan.futureOutputEvidenceProposal.changedBytes===1346637&&plan.futureOutputEvidenceProposal.sameBytes===686814&&plan.nativeCallsInPacket===0&&plan.candidateFunctionsInvoked===0);
 const correction=JSON.parse(r["history-verifier-field-correction.public.json"]);
 ck("author_checker_field_correction_preserved_only",eq(r["history-verifier-r1.original.js"],correction.oldVerifier)&&correction.literalBefore==="info.metadata.nlink===1"&&correction.literalAfter==="info.metadata.link_count===1"&&correction.nativeCalls===0);
 return {schema:"heptabao.root-source-review.snapshot2379-format49-report-two-ranges.v1",status:"PASS_SOURCE_AND_PURE_PROTOCOL_GUARDS_ONLY",checks,check_count:checks.length,source_packet:p.audit.tree,source:plan.candidate,exact_requests:requests.map(x=>x.pin),fixed_report:plan.actualExpected,original_job:plan.originalJob,original_slot:plan.existingSlot,entry_action:plan.sourceChanges.newAuthorization,scope:plan.exactScope,info_qualification:plan.rootActualInfoQualification,strict_hunks:8,author_pure_source_checks_reproduced:68,new_body_page_bytes:16384,old_page_bytes:8192,payload_cap:1048576,output_reads_authorized:false,content_reuse_authorized:false,Cargo_authorized:false,full_replacement:false,production_cutover:false,legacy_cleanup:false,root_Runtime_calls:0};
}
