function verifyCombinedReportInfoSource(t){
 const checks=[];function ck(name,pass){checks.push({name,pass:pass===true});if(pass!==true)throw new Error(name);}
 const plan=JSON.parse(t["PLAN.public.json"]),refs=JSON.parse(t["REFERENCES.public.json"]),q=JSON.parse(t["request.exact.json"]);
 const before=t["journal.before.js"],after=t["journal.after.js"],donor=t["donor.info-journal.js"],swaps=JSON.parse(t["LITERAL-BINDINGS.public.json"]);
 const eq=(raw,pin)=>{const m=gitBlobMeta(raw);return m.blob===pin.blob&&m.bytes===pin.bytes&&m.sha256===pin.sha256;};
 ck("current_before_pin",eq(before,refs.currentStageJournal));
 ck("donor_source_pin",eq(donor,refs.donorInfoJournal));
 ck("donor_GO_pin",eq(t["donor.info-GO.public.json"],refs.donorInfoGO));
 ck("exact_new_source_pin",eq(after,plan.journal));
 ck("exact_new_request_pin",eq(t["request.exact.json"],plan.exact_request));
 ck("current_forward_exact",snapshotApply(before,t["journal.forward.diff"])===after);
 ck("current_reverse_exact",snapshotApply(after,t["journal.forward.diff"],true)===before);
 ck("reverse_file_exact",snapshotApply(after,t["journal.reverse.diff"])===before&&snapshotApply(before,t["journal.reverse.diff"],true)===after);
 ck("current_six_hunks",(t["journal.forward.diff"].match(/^@@ /gm)||[]).length===6);
 ck("donor_strict_both_directions",snapshotApply(donor,t["donor.literal-only.diff"])===after&&snapshotApply(after,t["donor.literal-only.diff"],true)===donor);
 let rebuilt=donor;ck("seven_binding_groups",swaps.length===7);
 for(const item of swaps){ck("literal_once_"+item.name,rebuilt.split(item.before).length===2);rebuilt=rebuilt.replace(item.before,item.after);}
 ck("donor_logic_byte_unchanged",rebuilt===after);
 const names=src=>[...src.matchAll(/^(?:async )?function ([a-zA-Z0-9_]+)/gm)].map(x=>x[1]);
 ck("only_one_new_function",JSON.stringify(names(after))===JSON.stringify(["gfAuthorizeStageResultInfoOnly",...names(before)]));
 const fn=(src,n)=>{const all=[...src.matchAll(/^(?:async )?function ([a-zA-Z0-9_]+)/gm)],i=all.findIndex(x=>x[1]===n);return src.slice(all[i].index,i+1<all.length?all[i+1].index:src.length);};
 for(const n of ["gfNeed","gfMetaEquals","gfState","gfSave","gfIntegerText","gfInitializeOnlyAfterRootGO","gfAcceptArchivedSDK","gfReconcileSameGitArchiveReadOnly"])ck("unchanged_"+n,fn(before,n)===fn(after,n));
 ck("one_metadata_scope",plan.scope==="stage_result_file_info_only"&&plan.maximum_file_info_starts===1&&plan.binary_read_authorized===false&&plan.process_start_authorized===false&&plan.initialize_allowed===false);
 ck("fixed_request_shape",Object.keys(q).sort().join(",")==="idempotency_key,operation"&&q.operation.tool==="file_info"&&Object.keys(q.operation.arguments).sort().join(",")==="host,path");
 ck("fixed_host_path_key",q.operation.arguments.host==="rog"&&q.operation.arguments.path===plan.metadata_gate.path&&q.idempotency_key==="heptabao-combined-5767739c-rog-source-observe-r1-report-info");
 ck("no_metadata_yet",plan.actual_metadata===null&&plan.actual_body===null&&plan.root_detail_report_qualification===false);
 ck("metadata_caps",plan.metadata_gate.size_min===1&&plan.metadata_gate.size_max===65536&&plan.metadata_gate.mode===384&&plan.metadata_gate.uid===1000&&plan.metadata_gate.gid===1000&&plan.metadata_gate.nlink===1);
 ck("original_payload_caps",plan.immutable_page_bytes===8192&&plan.maximum_original_payload_bytes===1048576&&after.includes("q.limit===8192")&&after.includes("b.length<=8192")&&after.includes("v.total_bytes<=1048576"));
 ck("only_literal_metadata_branch",after.includes('s.stageResultInfoStarted!==true')&&after.includes('gfMetaEquals(raw,GF_STAGE_INFO_REQUEST)')&&after.includes('s.stageResultInfoStarted=true;'));
 ck("full9_decimal_tokens",after.includes('parts[0],parts[1],"1000","1000",String(32768|v.mode)')&&after.includes('"1",String(v.size),parts[3],parts[4]')&&after.includes('parts.every(x=>/^[0-9]+$/.test(x))'));
 const state=JSON.parse(t["actual.STATE.original.json"]),a=parseLosslessIntegers(t["actual.authority.native.json"]),r=parseLosslessIntegers(t["actual.streams.native.json"]),summary=JSON.parse(r.stdout.text);
 ck("existing_context_closed",state.job===plan.original_job&&state.pending===null&&state.activeObserver===null&&state.nativeCallInFlight===false&&state.paused===false&&state.startCalled===true&&state.nextStdout===350&&state.nextStderr===0);
 ck("same_job_native_results",a.job_id===plan.original_job&&r.job_id===plan.original_job&&plan.original_job==="1a1b2c397c4-fc05-7fa4");
 ck("terminal_durable_zero",a.exit_code===0&&a.state==="succeeded"&&a.output_complete===true&&a.output_durable===true&&a.terminal_publication_confirmed===true&&!a.timed_out&&!a.cancelled);
 ck("summary_source_binding",summary.source_commit===refs.sourceCandidateCommit&&summary.source_tree===refs.sourceCandidateTree&&summary.result_path===plan.metadata_gate.path&&summary.status==="prepared"&&summary.all_owned_stopped===true&&summary.compiler_started===false&&summary.server_started===false);
 ck("full_stream_sizes",r.stdout.eof===true&&r.stderr.eof===true&&r.stdout.next_offset===350&&r.stderr.next_offset===0&&gitBlobMeta(r.stdout.text).bytes===350);
 for(let i=0;i<2;i++){
  const need=plan.original_prerequisites[i],raw=t[i?"actual.streams.native.json":"actual.authority.native.json"],sdk=JSON.parse(t[i?"actual.streams.status.sdk.json":"actual.authority.status.sdk.json"]);
  ck("prerequisite_pin_"+i,eq(raw,need.nativeText));
  const v=parseLosslessIntegers(sdk.content[0].text);
  ck("original_status_closed_"+i,sdk.isError!==true&&v.operation_id===need.id&&v.tool_name===need.tool&&v.async_state==="completed"&&v.result_state==="stored_observed"&&v.owned_future_active===false&&v.payload_available===true);
  ck("recorded_original_observer_"+i,state.completedObservers.some(x=>x.id===need.id&&x.completedInactive===true&&x.nativeText.blob===need.nativeText.blob));
 }
 ck("same_SDK_before_parse_body",fn(before,"gfAcceptArchivedSDK")===fn(after,"gfAcceptArchivedSDK"));
 ck("separate_GO_required",after.includes('goPin.blob!==s.goPin.blob')&&after.includes('g.scope==="stage_result_file_info_only"')&&after.includes('g.binary_read_authorized===false'));
 ck("no_new_execution_and_no_formatter",refs.all_native_calls_in_this_source_task===0&&plan.source_formatted===false&&plan.product_qualification===false);
 return {schema:"heptabao.combined5767739.stage-report-info-source-verification.r1",ok:true,checks:checks.length,results:checks,scope:"pure V8 exact source/diff/prerequisite verification; candidate functions not invoked; no Native or Python",stageDetailedReportQualified:false};
}
