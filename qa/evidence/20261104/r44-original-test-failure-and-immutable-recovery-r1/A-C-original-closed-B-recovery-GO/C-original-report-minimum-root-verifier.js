function verifyRootReportMinimum(f,go){
  const rows=[],ck=(name,v)=>{rows.push({name,passed:v===true});if(v!==true)throw Error(name);};
  const rel=JSON.parse(f["RELEASE.public.json"]),sdk=JSON.parse(f["status.original.sdk.json"]),st=JSON.parse(sdk.content[0].text),pay=JSON.parse(f["payload.original.json"]),n=JSON.parse(pay.content[0].text),r=JSON.parse(f["report.original.json"]),ex=go.value.expectedReport;
  ck("original_report_body_operation",st.operation_id==="8a6ff767b74a82cc46818dd50f52f2599317f267cdf384ca5523e7f7f80798c7"&&rel.original.id===st.operation_id);
  ck("original_future_closed",sdk.isError===false&&st.async_state==="completed"&&st.owned_future_active===false&&st.payload_available===true&&st.result_state==="stored_observed");
  ck("payload_complete",pay.resultType==="complete"&&pay.isError===false&&pay.content.length===1);
  ck("whole_report_hash",gitBlobMeta(f["report.original.json"]).sha256===ex.sha256&&gitBlobMeta(f["report.original.json"]).bytes===49775);
  ck("original_payload_matches_report",utf8Text(unb64(n.data_base64))===f["report.original.json"]);
  ck("exact_range_eof",n.offset===0&&n.next_offset===49775&&n.size===49775&&n.eof===true&&n.chunk_sha256===ex.sha256);
  ck("same_version_path",n.version===ex.version&&n.path===ex.path);
  ck("release_closed",rel.call_in_flight===false&&rel.pending===null&&rel.active_observer===null&&rel.lane_released===true);
  ck("known_original_source",r.source_commit==="025b05a340de841b8161c1120344e86eae30eb97"&&r.source_tree==="1d8160c9385f8053b9a683cc1834da0f912e2d37");
  ck("failure_with_runtime_started",r.status==="failed"&&r.runtime_tests_started===true&&r.failure_type==="AssertionError"&&r.failure==="");
  ck("normal_release_and_shared_compile_passed",r.normal_release_build.exit_code===0&&r.compile_shared.commands.length===3&&r.compile_shared.commands.every(x=>x.exit_code===0));
  ck("shared_compile_within_original3600",r.compile_shared.cap_seconds===3600&&r.compile_shared.elapsed_seconds<3600&&r.compile_shared.deadline_reset===false);
  ck("two_test_processes_only",r.group_results.length===1&&r.group_results[0].tests.length===2&&r.group_results[0].tests[0].tests.exit_code===0&&r.group_results[0].tests[1].tests.exit_code===101);
  ck("eight_owned_children_reaped",r.cleanup.length===8&&r.cleanup.every(x=>x.direct_child_reaped===true&&x.remaining.length===0));
  ck("retained_prior_artifacts_unchanged",JSON.stringify(r.retained_df026_before)===JSON.stringify(r.retained_df026_after));
  ck("no_invented_final_source_binary_checks",!Object.hasOwn(r,"source_unchanged")&&!Object.hasOwn(r,"binary_unchanged"));
  ck("production_and_full_regressions_not_done",r.production_changed===false&&r.old_normal61_full34_LAN98plus12_comparison69_rerun===false&&r.distributed_native_jwt_ha_qualified===false);
  return {schema:"heptabao.root-original-report-minimum.r1",passed:true,checks:rows.length,rows,report:gitBlobMeta(f["report.original.json"]),runtimeTestProcesses:2,successfulTestProcesses:1,failedTestProcesses:1,fullSuiteQualified:false,observationLaneReleased:true,targetReuseQualified:false,fullReplacement:false};
 }