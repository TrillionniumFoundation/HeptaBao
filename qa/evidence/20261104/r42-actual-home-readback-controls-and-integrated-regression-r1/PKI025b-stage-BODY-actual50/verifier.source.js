function verifyStageBodyActual(files){
 const checks=[];function ck(ok,code){checks.push({code,pass:!!ok});if(!ok)throw Error(code);}
 const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b),rows=JSON.parse(files["CALL-INDEX.public.json"]),s=JSON.parse(files["STATE.public.json"]),info=JSON.parse(files["ACTUAL-INFO.public.json"]),expected=JSON.parse(files["EXPECTED-SOURCE.public.json"]),go=JSON.parse(files["GO.original.json"]),o=s.bodyObserver;
 ck(rows.length===7&&rows.map(x=>x.kind).join(",")==="operation_start,operation_status,operation_result,operation_result,operation_result,operation_result,operation_result","seven_original_BODY_calls");
 const v=[];
 for(const row of rows){const prefix=row.key+"--",sdkRaw=files[prefix+"sdk.original.json"],sdk=JSON.parse(sdkRaw);
  ck(eq(gitBlobMeta(files[prefix+"request.json"]),row.request),row.key+":request_pin");
  ck(eq(gitBlobMeta(sdkRaw),row.sdk)&&row.sdkWhole===true,row.key+":sdk_whole_before_parse");
  ck(sdk.isError!==true&&sdk.content.length===1&&sdk.content[0].type==="text",row.key+":original_sdk_success");
  ck(sdk.content[0].text===files[prefix+"native.original.json"]&&eq(gitBlobMeta(sdk.content[0].text),row.native),row.key+":native_byteexact");
  ck(row.phase==="accepted"&&row.called===true&&row.armWhole===true,row.key+":once_whole_arm");
  const intent=JSON.parse(files[prefix+"intent.json"]),armed=JSON.parse(files[prefix+"armed.json"]);
  ck(intent.maximumNativeCalls===1&&intent.nativeNotYetCalled===true&&eq(intent.request,row.request)&&eq(armed.request,row.request)&&armed.mayHaveDispatchedAfterThisCheckpoint===true&&intent.originalJob===s.job,row.key+":pre_dispatch_records");
  ck(eq(intent.rootGo,gitBlobMeta(files["GO.original.json"])),row.key+":exact_BODY_GO");
  v.push({q:JSON.parse(files[prefix+"request.json"]),n:parseLosslessIntegers(sdk.content[0].text)});
 }
 const a=v[0].q.operation.arguments;
 ck(eq(rows[0].request,go.exact_request)&&go.scope==="stage_result_binary_read_only"&&go.maximum_binary_read_starts===1,"exact_separate_body_GO");
 ck(v[0].q.operation.tool==="binary_read"&&a.host==="rog"&&a.path===info.path&&a.offset===0&&a.limit===28125&&a.expected_version===info.version,"one_actual_version_body_range");
 ck(v[0].n.operation_id===o.id&&v[0].n.tool_name==="binary_read"&&v[0].n.reused===false&&v[0].n.automatic_retry===false,"original_binary_ACK_no_replay");
 ck(v[1].q.operation_id===o.id&&v[1].n.operation_id===o.id&&v[1].n.async_state==="completed"&&!v[1].n.owned_future_active&&v[1].n.result_state==="stored_observed"&&v[1].n.payload_available,"same_original_closed_future");
 let bytes=[],next=0;
 for(let i=2;i<v.length;i++){const {q,n}=v[i],b=unb64(n.data_base64);
  ck(q.operation_id===o.id&&q.offset===next&&q.limit===8192&&n.operation_id===o.id&&n.offset===next&&n.immutable_snapshot===true,"page"+(i-2)+":original_contiguous_query");
  ck(n.payload_kind==="native_result"&&n.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization"&&n.total_bytes===o.payload.bytes&&n.result_sha256===o.payload.sha256,"page"+(i-2)+":same_payload_identity");
  ck(b.length>0&&b.length<=8192&&n.next_offset===next+b.length&&n.eof===(n.next_offset===n.total_bytes),"page"+(i-2)+":extent_EOF");
  bytes=bytes.concat(b);next=n.next_offset;
 }
 const payloadRaw=utf8Text(bytes);
 ck(next===37939&&payloadRaw===files["observer.payload.original.json"]&&eq(gitBlobMeta(payloadRaw),o.payload),"complete_payload_bytes_SHA");
 const payload=parseLosslessIntegers(payloadRaw);
 ck(payload.resultType==="complete"&&payload.isError===false&&payload.content.length===1&&payload.content[0].type==="text"&&payload.content[0].text===files["observer.native.original.json"],"original_complete_native_success");
 ck(eq(gitBlobMeta(payload.content[0].text),o.nativeText),"original_native_pin");
 const native=parseLosslessIntegers(payload.content[0].text),body=utf8Text(unb64(native.data_base64)),pin=gitBlobMeta(body);
 ck(native.path===info.path&&native.version===info.version&&native.size===28125&&native.offset===0&&native.next_offset===28125&&native.eof===true,"whole_fixed_body_version_extent");
 ck(pin.bytes===28125&&pin.sha256===info.sha256&&native.chunk_sha256===info.sha256&&body===files["stage-result.public.json"],"whole_decoded_body_SHA");
 ck(o.completedInactive===true&&o.pages===5&&s.totalCalls===17&&s.oldCalls===10&&s.newBodyCalls===7&&s.allCompletedObservers.length===4,"all_original_observers_closed_counts");
 ck(s.pending===null&&s.activeObserver===null&&!s.nativeCallInFlight&&!s.paused&&!s.buildSubmitted,"released_lane_no_Cargo");
 const r=parseLosslessIntegers(body);
 ck(r.schema==="heptabao.native-jwt-independent-source-stage.v1"&&r.status==="prepared"&&r.host==="rog","actual_prepared_source_report");
 ck(r.source_commit===expected.commit&&r.source_tree===expected.tree&&r.sole_parent===expected.soleParent&&r.source_fetch_argument===expected.commit&&r.source_ref===null,"exact_candidate_parent_fetch");
 ck(r.root===expected.root&&r.source===expected.source&&r.stager_sha256===expected.stager.sha256&&r.carrier_sha256===expected.carrier.sha256,"exact_owned_paths_and_source_carrier");
 ck(r.full_worktree.tracked_leaf_count===3916&&r.full_worktree.tracked_bytes===62297399&&r.full_worktree.full_leaf_index_sha256===expected.indexSha256&&r.full_worktree.all_tracked_worktree_blobs_and_modes_match&&r.full_worktree.index_matches_tree,"whole_3916_candidate_worktree_index");
 ck(r.source_clean&&r.independent_git_directory&&r.no_alternates&&r.no_shared_object_links&&r.full_strict_fsck_passed,"independent_clean_full_fsck_source");
 ck(r.canonical_history_count===3767&&r.new_commits_since_actual_495.length===expected.newCommitsFrom495&&r.new_commits_since_actual_495[0]===expected.commit&&r.new_commits_since_actual_495[1]===expected.soleParent&&new Set(r.new_commits_since_actual_495).size===15,"canonical_full_history_and_15_descendants");
 ck(r.cleanup.length===60&&new Set(r.cleanup.map(x=>x.pid)).size===60&&new Set(r.cleanup.map(x=>x.label)).size===60&&r.cleanup.every(x=>x.direct_child_reaped===true&&x.exit_code===0&&Array.isArray(x.remaining)&&x.remaining.length===0),"60_original_direct_children_reaped_empty_remaining");
 ck(r.new_stage_total_seconds===300&&r.new_supervisor_seconds===360&&r.original_clone_cap_seconds===180&&r.original_git_leaf_cap_seconds===90&&r.within_new_stage_deadline===true&&r.elapsed_seconds_after_cleanup>=0&&r.elapsed_seconds_after_cleanup<300,"unchanged_deadlines_actual_completion");
 const ns=x=>BigInt(x.$exactInteger??String(x));
 ck(ns(r.terminal_ns)>ns(r.started_ns),"lossless_epoch_order");
 ck(eq(r.old_source_before,r.old_source_after)&&r.old_source_unchanged===true&&r.old_source_before.commit==="49503322c7f446e5eb41e7744f1fdbd7f1192ecc"&&r.old_source_before.status==="","original_495_source_unchanged");
 ck(eq(r.failed_observer_before,r.failed_observer_after)&&Object.keys(r.failed_observer_before.files).length===12&&r.failed_observer_before.prior_failed_build_replayed===false,"historical_12_failure_artifacts_unchanged");
 const cb=r.canonical_bundle;
 ck(cb.bytes===70271&&cb.header.version===2&&eq(cb.header.heads,[[expected.commit,"HEAD"]])&&eq(cb.header.prerequisites,["49503322c7f446e5eb41e7744f1fdbd7f1192ecc"])&&cb.path===expected.root+"/control/canonical-native-jwt-pki-025b05a3-from495.bundle","actual_canonical_incremental_bundle");
 ck(cb.identity.length===9&&cb.identity[2]===1000&&cb.identity[3]===1000&&cb.identity[4]===33152&&cb.identity[5]===1&&cb.identity[6]===cb.bytes&&/^[a-f0-9]{64}$/.test(cb.sha256),"bundle_reported_full9");
 ck(r.exact_test_count===44&&r.original_60_test_count===60&&r.exact_groups.reduce((n,x)=>n+x[1],0)===44&&r.additional_existing_tests===7&&r.additional_cold_h2_tests===9&&r.additional_same_root_publication_tests===1,"historical_stager_control_counts_not_build_denominators");
 ck(r.compiler_started===false&&r.formatter_executed===false&&r.rust_tests_executed===false&&r.server_started===false&&r.historical_controls_executed===false&&r.production_changed===false&&r.actual_build_qualification===false&&r.candidate_build_qualification===false,"stage_only_no_build_or_runtime_test_qualification");
 return {schema:"heptabao.025b-stage-result-BODY-actual-verification.r1",status:"PASS",checks:checks.length,results:checks,Native_calls:0,product_tests:0,scope:"7 original calls/5 pages and existing original stage report; not fresh runtime execution",actualBody:pin,children:60,sourceCommit:r.source_commit,sourceTree:r.source_tree,buildQualified:false};
}
