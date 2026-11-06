function rootCheckCBuildRunning(f){
 const p=f.packet,raw=p.raw,s=JSON.parse(raw["current.state.running.public.json"]),v=JSON.parse(raw["STATE.public.json"]),index=JSON.parse(raw["CALL-INDEX.public.json"]),go=JSON.parse(raw["ROOT-GO.public.json"]),eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b),checks=[],ck=(name,pass)=>checks.push({name,pass:!!pass});
 ck("whole_running65",p.audit.whole&&p.audit.files===65);
 ck("exact_previous_start_ACK",raw["call01.sdk.original.json"]===f.ack.raw["START.sdk.original.json"]&&raw["call01.native.original.json"]===f.ack.raw["START.native.original.json"]&&raw["call01.request.json"]===f.ack.raw["START.EXACT.request.json"]);
 ck("exact_original_GO_and_journal",eq(gitBlobMeta(raw["ROOT-GO.public.json"]),f.goPins)&&eq(gitBlobMeta(raw["journal.exact.js"]),go.journal.source));
 const byBlob=new Map(Object.values(raw).map(t=>[gitBlobMeta(t).blob,t]));
 const calls=index.map(row=>({key:row.key,kind:row.kind,phase:s.calls[row.key].phase,requestPin:row.request,sdkPin:row.sdk,nativePin:row.native,requestText:raw[row.files.request],intentText:raw[row.files.intent],armedText:raw[row.files.armed],sdkText:raw[row.files.sdk],nativeText:raw[row.files.native],armedTree:row.armTree}));
 const cs=verifyOriginalJournal({label:"original_BUILD_running",calls,observers:s.completedObservers,blob:sha=>byBlob.get(sha),goPins:[f.goPins],pageLimit:()=>8192,ck});
 ck("exact_10calls_3closed_observers",calls.length===10&&s.completedObservers.length===3&&cs.filter(x=>x.c.kind==="process_start").length===1);
 for(const row of index)ck(row.key+":SDK_one_leaf_Merkle",immediateTreeSha([{path:"original.sdk.json",type:"blob",mode:"100644",sha:row.sdk.blob}])===row.sdkTree);
 for(let i=0;i<3;i++){
  const close=JSON.parse(raw["authority"+i+".closure.public.json"]),n=JSON.parse(raw["authority"+i+".native.original.json"]);
  ck("authority"+i+":original_job_running_only",n.job_id==="1a1b10cad9b-fc05-7560"&&n.state==="running"&&n.backend==="systemd"&&n.systemd.ActiveState==="active"&&n.systemd.SubState==="running"&&n.systemd.ExecMainPID==="1061091"&&close.completedInactive===true&&close.pages===1&&eq(gitBlobMeta(raw["authority"+i+".native.original.json"]),close.nativeText));
  ck("authority"+i+":original_payload_Merkle",immediateTreeSha([{path:"payload.original.json",type:"blob",mode:"100644",sha:gitBlobMeta(raw["authority"+i+".payload.original.json"]).blob}])===close.payloadTree);
 }
 ck("all_queries_exact_original_job",cs.filter(x=>x.c.kind==="operation_start").every(x=>x.q.operation.tool==="process_status"&&x.q.operation.arguments.host==="rog"&&x.q.operation.arguments.job_id===s.job));
 ck("no_observation_future_at_snapshot",s.pending===null&&s.activeObserver===null&&s.nativeCallInFlight===false&&s.paused===false&&v.observationalCallsInFlight===0&&v.observationalFuturesActive===0);
 ck("build_and_target_still_active",v.originalBuildMayBeRunning===true&&v.targetReleased===false&&v.terminal===null&&v.normalReleaseResult===null&&v.actualTestsStarted===null&&v.actualTestsPassed===null);
 ck("declared_denominators_not_results",v.declaredUnique===149&&v.declaredProfileInstances===166&&v.processStartCount===1&&v.originalCalls===10&&v.observations===3&&v.observerPages===3);
 return {schema:"heptabao.root.PKI025b-original-BUILD-running-qualification.r43",pass:checks.every(x=>x.pass),checks:checks.length,results:checks,packet:p.audit.tree,original_job:"rog/1a1b10cad9b-fc05-7560",original_calls:10,original_observers:3,original_pages:3,last_authority:v.lastOriginalAuthority,caller_snapshot:v.callerWallSnapshot,actual_state:"running",actual_tests_started:null,actual_tests_passed:null,normal_release:null,target_window_held:true,product_pass:false,full_replacement:false,production_cutover:false,legacy_cleanup:false,root_Runtime_calls:0};
}
function rootCheckBFile11Lane(f){
 const p=f.packet,r=JSON.parse(p.raw["RELEASE.public.json"]),eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b),checks=[],ck=(name,pass)=>checks.push({name,pass:!!pass}),body=f.body.raw["formatted-output.rs"];
 ck("whole_release24_and_service_body",p.audit.whole&&p.audit.files===24&&f.body.audit.whole&&f.body.audit.files===1);
 ck("whole_service519619_exact",eq(gitBlobMeta(body),r.just_completed.body)&&gitBlobMeta(body).blob==="6574a4d522a62feb328fea61d19df575ce7f2550"&&gitBlobMeta(body).bytes===519619&&f.body.audit.tree===r.just_completed.bodyTree);
 ck("only_original_file11_scope",r.root_table_go==="25ea12c4406a12ba5ce263b10a2723f73276d74b"&&r.slot==="snapshot_2379_formatted23_readonly_gitfirst_r1"&&r.just_completed.index===11&&r.just_completed.ranges.length===8&&r.new_file_observers.length===9&&r.new_file_original_pages===48&&r.new_file_call_records===66);
 ck("12whole_37closed_total",r.completed_files===12&&r.completed_observers===37&&r.native_call_records===194&&r.whole_body_bytes===1132623&&JSON.parse(p.raw["all-closed-observers.public.json"]).length===37&&JSON.parse(p.raw["whole-output-index.public.json"]).length===12);
 ck("B0_explicit_boundary_hold",r.native_calls_in_flight===0&&r.native_futures_active===0&&r.pending===null&&r.activeObserver===null&&r.paused===false&&r.lane_hold===true&&r.next_file_index===12&&r.info12_started===false&&Array.isArray(r.body12_started)&&r.body12_started.every(x=>x===false));
 for(let i=0;i<9;i++){
  const id=String(i).padStart(2,"0"),t=p.raw["status-"+id+".original.native.json"],st=JSON.parse(t),sdkText=p.raw["status-"+id+".original.sdk.json"],sdk=JSON.parse(sdkText),row=r.closed_statuses[i];
  ck("original_status"+id+":SDK_and_native_whole",eq(gitBlobMeta(t),row.native)&&eq(gitBlobMeta(sdkText),row.sdk)&&sdk.isError===false&&sdk.content.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===t);
  ck("original_status"+id+":completed_inactive",st.operation_id===row.operationId&&st.tool_name===row.tool&&st.async_state==="completed"&&st.owned_future_active===false&&st.result_state==="stored_observed"&&st.payload_available===true&&st.automatic_retry===false&&r.new_file_observers.some(o=>o.id===st.operation_id&&o.completedInactive===true));
 }
 ck("historical_errors_and_scope_preserved",r.historical_errors_preserved.length>=4&&r.build_authorized===false&&r.new_admission_authorized_by_this_release===false&&r.semantic_qualification===false);
 return {schema:"heptabao.root.snapshot-file11-boundary-lane-qualification.r43",pass:checks.every(x=>x.pass),checks:checks.length,results:checks,packet:p.audit.tree,body:gitBlobMeta(body),release:gitBlobMeta(p.raw["RELEASE.public.json"]),B_lane_released:true,allocation_after_release:{A:0,B:0,C:1,root:0},reserved_next_lane:"A only after separate exact original-instance diagnostic SOURCE/GO",remaining_formatted_files:11,whole_194_call_chain_independently_qualified:false,combined_candidate_frozen:false,product_tests_passed:false,full_replacement:false,production_cutover:false,legacy_cleanup:false,root_Runtime_calls:0};
}