function qualifyCurrent576FailedReport(files,oldFiles,goRaw,bodyRequestRaw){
 const s=JSON.parse(files["STATE.original.json"]),old=JSON.parse(oldFiles["STATE.original.json"]),idx=JSON.parse(files["INDEX.public.json"]),rel=JSON.parse(files["RELEASE.public.json"]),b=parseLosslessIntegers(files["REPORT.original.json"]);
 const n=parseLosslessIntegers(files["BODY.native.original.json"]),e=parseLosslessIntegers(files["BODY.payload.original.json"]),sdk=JSON.parse(files["BODY.status.SDK.original.json"]),st=parseLosslessIntegers(sdk.content[0].text),ch=[];
 const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);function ok(n,v){if(!v)throw Error(n);ch.push(n);}
 ok("original_body_GO_exact",files["BODY.GO.original.json"]===goRaw);
 ok("old46_calls_unchanged",Object.keys(old.calls).length===46&&Object.keys(s.calls).length===56&&Object.entries(old.calls).every(([k,v])=>eq(v,s.calls[k])));
 ok("old15_observers_unchanged",old.completedObservers.length===15&&s.completedObservers.length===16&&eq(old.completedObservers,s.completedObservers.slice(0,15)));
 ok("same_original_job",s.job==="1a1b2d90976-fc05-7fff"&&s.job===old.job);
 ok("same_original_metadata",eq(s.stageResultInfo,old.stageResultInfo));
 ok("closed_lane",s.pending===null&&s.activeObserver===null&&!s.paused&&!s.nativeCallInFlight);
 ok("new10_calls_accepted",idx.calls.length===10&&idx.calls.every(c=>eq(Object.fromEntries(Object.entries(c).filter(([k])=>k!=="key")),s.calls[c.key])&&c.called&&c.phase==="accepted"&&c.armed.whole&&c.sdkArchive.whole));
 ok("body_shape",eq(idx.calls.map(c=>c.kind),["operation_start","operation_status",...Array(8).fill("operation_result")]));
 ok("GO_request_exact",idx.calls[0].requestRaw===bodyRequestRaw);
 const id=idx.bodyOriginal.id;
 ok("original_body_status_inactive",sdk.isError===false&&st.operation_id===id&&st.async_state==="completed"&&!st.owned_future_active&&st.payload_available===true&&st.result_state==="stored_observed");
 ok("status_request_same_ID",JSON.parse(idx.calls[1].requestRaw).operation_id===id);
 ok("whole_payload_envelope",e.resultType==="complete"&&e.isError===false&&e.content.length===1&&e.content[0].text===files["BODY.native.original.json"]&&eq(gitBlobMeta(files["BODY.payload.original.json"]),idx.bodyOriginal.payload));
 ok("actual_metadata_exact",n.path===old.stageResultInfo.path&&n.size===46828&&n.version===old.stageResultInfo.version&&n.offset===0&&n.next_offset===46828&&n.eof===true&&n.chunk_sha256===old.stageResultInfo.sha256);
 const bytes=unb64(n.data_base64);
 ok("decoded_body_exact",bytes.length===46828&&utf8Text(bytes)===files["REPORT.original.json"]&&encodeBase64Bytes(bytes)===n.data_base64&&gitBlobMeta(files["REPORT.original.json"]).sha256===old.stageResultInfo.sha256);
 ok("observer_completed",eq(idx.bodyOriginal,s.completedObservers[15])&&idx.bodyOriginal.completedInactive&&idx.bodyOriginal.pages===8);
 ok("prior_unknown_history_preserved",eq(s.outerFailure,old.outerFailure)&&eq(s.exactOriginalStatusSDKArchiveRecovery,old.exactOriginalStatusSDKArchiveRecovery));
 ok("report_candidate",b.source_commit==="5767739cd25e458ac052dc8d384019bab8688ae0"&&b.source_tree==="42477d622dcf96e1e2b0929fe9ecc6b7ba484740");
 ok("failure_is_test_compilation",b.status==="failed"&&b.failure_type==="AssertionError"&&b.failure==="reviewed libtest profile compilation failed");
 ok("release_success",b.normal_release_build.exit_code===0&&!b.normal_release_build.timed_out&&b.normal_release_build.direct_child_reaped&&b.normal_release_build.remaining.length===0);
 const cs=b.compile_shared.commands;
 ok("three_compile_outcomes",cs.length===3&&eq(cs.map(x=>[x.label,x.exit_code]),[["ordinary-no-default-check",0],["file-libtest-build",0],["default-libtest-build",101]]));
 ok("runtime_not_started",b.runtime_tests_started===false&&b.group_results.length===0&&b.selected_unique_test_total===252&&b.selected_profile_instance_total===280);
 ok("all_direct_children_closed",b.cleanup.length===4&&b.cleanup.every(x=>x.direct_child_reaped&&x.remaining.length===0)&&cs.every(x=>!x.timed_out));
 ok("deadlines_not_reset",b.compile_shared.deadline_reset===false&&b.compile_shared.cap_seconds===3600&&b.original_outer_seconds===12000&&b.within_original_outer_before_receipt===true);
 ok("release_state",rel.ownerRelease===true&&rel.NativeCall===0&&rel.NativeFuture===0&&rel.originalCallCount===56&&rel.originalObserverCount===16&&rel.originalPageCount===23);
 return {schema:"heptabao.root.current576-failed-build-report-qualification.r1",pass:true,check_count:ch.length,checks:ch,report:gitBlobMeta(files["REPORT.original.json"]),actual:{commit:b.source_commit,tree:b.source_tree,status:b.status,normalReleaseCompiled:true,ordinaryNoDefaultCheck:true,fileLibtestCompiled:true,defaultLibtestCompiled:false,defaultLibtestExit:101,runtimeTestsStarted:false,runtimeTestsExecuted:0,HACompileReached:false},rustErrorCauseQualified:false,laneReleased:true,NativeCallsPerformed:0,firstPureCheckerCorrection:"Index rows have an additional key property; compare only the original state fields. No source or Native change."};
}