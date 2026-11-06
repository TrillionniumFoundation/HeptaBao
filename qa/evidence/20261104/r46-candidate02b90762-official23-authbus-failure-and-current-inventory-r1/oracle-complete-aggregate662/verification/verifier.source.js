/* Offline evidence verification. No subprocess, HTTP, SDK invocation, or Native dispatch.
 * Prior outer10-call chain and BODY2 recovery root qualification are carried, not rerun.
 * New checks rebuild the nine ordinary body observers and all ten chunk bytes, then inspect the original report.
 */
function verifyOfficialAcl23R2Final(input) {
 const checks=[],ok=(v,label)=>{checks.push({label,pass:!!v});if(!v)throw Error(label);};
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),J=raw=>parseLosslessIntegers(raw);
 const pin=(text,p)=>{const a=gitBlobMeta(text);return a.blob===p.blob&&a.bytes===p.bytes&&a.sha256===p.sha256;};
 const state=J(input.actual["STATE.final.original.json"]),release=J(input.actual["RELEASE.public.json"]),go=J(input.actual["BODY-GO.original.json"]);
 const reportRaw=input.actual["result.public.json"],info=J(input.actual["INFO.native.original.json"]),terminal=J(input.actual["stdout.original.txt"]);
 ok(pin(reportRaw,{blob:"0605fa44d81ccb93e1d1f00a0f8f7a37f4bea897",bytes:651803,sha256:"9048f3b5c854a190dadde86f5d7eec180c497313065bd70bd23a87124789a62d"}),"whole exact original report before interpretation");
 ok(state.pending===null&&state.activeObserver===null&&state.nativeCallInFlight===false&&state.paused===false,"no remaining call or active future");
 ok(Object.keys(state.calls).length===84&&Object.values(state.calls).every(c=>c.called===true),"84 retained original main calls");
 ok(state.completedObservers.length===13&&state.completedObservers.every(o=>o.completedInactive===true),"13 original observers known closed");
 ok(state.oracleReportBodyStarted===10&&state.oracleReportBodyRanges.length===10,"exact ten original body admissions and ranges");
 const recovery=J(input.recovery["STATE.recovery.closed.json"]);
 ok(Object.keys(recovery.calls).length===7&&release.combined_native_call_records===91,"84 main plus seven independent recovery calls");
 ok(state.calls["official271-x230-acl23-r2-body02-status0"].phase==="native_interpretation_refused"&&state.outerFailure.message==="native_tool_error_preserved_stop","original status delivery failure retained");
 ok(state.oracleReportBody02Recovery.counts.combinedStatusCallsForOriginalID===2&&state.oracleReportBody02Recovery.counts.originalStatusLimit===8,"recovery status charged to original eight limit");
 ok(same(J(input.handback["STATE.after.exact.json"]).calls,J(input.handback["STATE.before.original.paused.json"]).calls),"handback preserves all original 28 call records");
 let ordinaryCalls=0,ordinaryPages=0,ordinaryStatuses=0,ordinaryAdmissions=0;
 for(const [indexText,files]of Object.entries(input.units)){
  const index=Number(indexText),rows=J(files["CALL-INDEX.public.json"]),calls=J(files["CALLS.original.json"]),o=J(files["OBSERVER.original.json"]),range=J(files["RANGE.original.json"]);
  ok(rows.length===8&&Object.keys(calls).length===8,"eight original calls for range "+index);
  ok(o.id===range.originalOperation&&o.completedInactive===true&&o.pages===6,"closed original range observer "+index);
  ok(same(state.oracleReportBodyRanges[index],range),"range appended without rewriting "+index);
  let joined=[],next=0;
  for(let n=0;n<rows.length;n++){
   const r=rows[n],key=r.callKey??r.key,c=calls[key],base=r.prefix,qraw=files[base+".request.original.json"],q=JSON.parse(qraw),intent=J(files[base+".intent.original.json"]),armed=J(files[base+".armed.original.json"]),sdkraw=files[base+".sdk.original.json"],sdk=J(sdkraw),natraw=files[base+".native.original.json"],v=J(natraw);
   ordinaryCalls++;
   ok(same(c,state.calls[key])&&c.called===true&&c.phase==="accepted","original call record "+index+"/"+n);
   ok(qraw===c.requestRaw&&pin(qraw,c.requestPin),"exact original request "+index+"/"+n);
   ok(intent.callKey===key&&intent.kind===c.kind&&same(intent.request,c.requestPin)&&pin(files["ROOT-GO.original.json"],intent.rootGo)&&intent.originalJob===state.job,"root GO and intent "+index+"/"+n);
   ok(armed.callKey===key&&same(armed.request,c.requestPin)&&same(armed.rootGo,intent.rootGo)&&armed.nativeNotYetCalled===true,"original arm "+index+"/"+n);
   const armTree=gitTreeAudit({sha:c.armed.tree,truncated:false,tree:["request","intent","armed"].map(k=>({path:k+".json",mode:"100644",type:"blob",sha:gitBlobMeta(files[base+"."+k+".original.json"]).blob}))});
   ok(armTree.leaf_count===3&&c.armed.whole===true&&r.armedTree===c.armed.tree,"three-leaf armed Merkle "+index+"/"+n);
   ok(pin(sdkraw,c.sdkPin)&&pin(natraw,c.nativePin)&&sdk.isError===false&&sdk.content.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===natraw,"whole SDK native exact "+index+"/"+n);
   ok(gitTreeAudit({sha:c.sdkArchive.tree,truncated:false,tree:[{path:"original.sdk.json",mode:"100644",type:"blob",sha:c.sdkPin.blob}]}).leaf_count===1&&c.sdkArchive.whole===true,"SDK Merkle "+index+"/"+n);
   if(n===0){
    ordinaryAdmissions++;ok(c.kind==="operation_start"&&q.operation.tool==="binary_read"&&q.operation.arguments.path===info.path&&q.operation.arguments.expected_version===info.version&&q.operation.arguments.offset===range.offset&&q.operation.arguments.limit===range.limit&&v.operation_id===o.id,"one exact original binary admission "+index);
   }else if(n===1){
    ordinaryStatuses++;ok(c.kind==="operation_status"&&q.operation_id===o.id&&v.operation_id===o.id&&v.async_state==="completed"&&v.owned_future_active===false&&v.payload_available===true,"original completed status "+index);
   }else{
    ordinaryPages++;ok(c.kind==="operation_result"&&q.operation_id===o.id&&q.offset===next&&q.limit===16384&&v.operation_id===o.id&&v.immutable_snapshot===true,"original immutable next page "+index+"/"+n);
    const b=unb64(v.data_base64);ok(v.offset===next&&v.next_offset===next+b.length&&b.length<=16384&&v.total_bytes===o.payload.bytes&&v.result_sha256===o.payload.sha256&&v.eof===(v.next_offset===v.total_bytes),"page bounds hash EOF "+index+"/"+n);
    joined=joined.concat(b);next=v.next_offset;
   }
  }
  const payload=utf8Text(joined),env=J(payload);
  ok(payload===files["payload.original.json"]&&pin(payload,o.payload)&&next===o.payload.bytes,"full original immutable payload "+index);
  ok(gitTreeAudit({sha:o.payloadTree,truncated:false,tree:[{path:"payload.original.json",mode:"100644",type:"blob",sha:o.payload.blob}]}).leaf_count===1,"whole payload Merkle "+index);
  ok(env.resultType==="complete"&&env.isError===false&&env.content.length===1&&env.content[0].text===files["native.original.json"]&&pin(env.content[0].text,o.nativeText),"original binary native envelope "+index);
  const body=J(files["native.original.json"]);
  ok(body.path===info.path&&body.version===info.version&&body.size===info.size&&body.offset===range.offset&&body.next_offset===range.next&&body.eof===(range.next===info.size)&&body.data_base64===range.base64&&body.chunk_sha256===range.chunkSHA256,"range version and data binding "+index);
 }
 ok(ordinaryCalls===72&&ordinaryPages===54&&ordinaryStatuses===9&&ordinaryAdmissions===9,"nine normal observer original counts");
 ok(same(state.oracleReportBodyRanges[2],J(input.recovery["RANGE.original.json"]))&&pin(input.recovery["payload.original.json"],recovery.completedObservers[0].payload),"separately qualified recovered third range carried");
 let complete=[],at=0;
 for(const [index,r] of state.oracleReportBodyRanges.entries()){
  const b=unb64(r.base64);
  ok(r.offset===at&&r.next===at+b.length&&r.limit===b.length&&b.length===(index===9?61979:65536)&&sha256Latin1(byteString(b))===r.chunkSHA256,"exact contiguous actual chunk "+index);
  complete=complete.concat(b);at=r.next;
 }
 ok(at===651803&&utf8Text(complete)===reportRaw&&sha256Latin1(byteString(complete))===info.sha256,"all ten source chunks reproduce exact whole report");
 const report=J(reportRaw),matrix=J(input.matrixRaw),payload=JSON.parse(input.payloadRaw);
 ok(matrix.case_count===23&&matrix.matrix.length===23&&report.acl.cases.length===23&&report.acl.actual_case_records===23&&report.matrix_case_denominator===23,"fixed 23 denominator and records");
 ok(report.capture_complete===true&&report.failure===null&&terminal.capture_complete===true&&terminal.failure===null,"original capture completed");
 ok(report.candidate_started===false&&report.parity_qualified===false&&report.status_normalization===false&&report.acl.raw_status_normalization===false,"official side only, no normalization or parity promotion");
 ok(report.live_identity.version==="2.7.1"&&report.live_identity.product==="OpenBao"&&report.live_identity.tls_verified===true&&report.live_identity.server_mode==="server_not_dev"&&report.live_identity.archive_member_matches_executable===true,"fresh original official identity");
 ok(report.live_identity.binary_sha256==="535cf827b13753046757f5ec8b97ae0ef21f10a40ffe673f0d5e75616170f5ea"&&report.live_identity.artifact_sha256==="0e2f1ce10d124e03112b50dd2fbec6b78003783253bc3a91587938f39d1e2243","fixed official artifact identity");
 ok(same(report.artifact_metadata_before,report.artifact_metadata_after)&&report.artifact_metadata_after.length===2,"two actual artifact metadata snapshots stable");
 ok(report.artifact_metadata_after.every(a=>a.whole_hash_checked_by_original_launcher===false),"artifact snapshot hash flag preserved");
 ok(report.source_inputs.length===11&&Object.keys(payload.files).length===11&&report.source_fd_rows_before_publication.length===11,"eleven exact input files");
 for(const row of report.source_inputs){
  const text=payload.files[row.relative],m=gitBlobMeta(text),fd=report.source_fd_rows_before_publication.find(f=>f.relative===row.relative);
  ok(m.bytes===row.bytes&&m.sha256===row.sha256&&row.closed===true&&row.full9_decimal[6]===String(row.bytes),"exact source pin "+row.relative);
  ok(fd&&fd.opened===true&&fd.closed===true&&fd.close_attempts===1&&same(fd.full9_decimal,row.full9_decimal),"input FD exactly closed "+row.relative);
 }
 ok(terminal.entry_fd_count===12&&terminal.all_entry_file_descriptors_closed===true&&terminal.pending_signal===null&&terminal.report.closed===true,"post-publication all twelve entry FDs closed");
 ok(terminal.report.bytes===info.size&&terminal.report.sha256===info.sha256&&same(terminal.report.full9_decimal,state.oracleReportInfo.full9Strings),"terminal report identity equals independent metadata");
 const baseline={bound_issuer:"heptabao-acl23-official271-acl23-r2",jwt_validation_pubkeys:[input.pemRaw.slice(0,-1)],jwt_supported_algs:["RS256"]};
 const objectSame=(a,b)=>{const canon=x=>Array.isArray(x)?x.map(canon):x&&typeof x==="object"?Object.fromEntries(Object.keys(x).sort().map(k=>[k,canon(x[k])])):x;return same(canon(a),canon(b));};
 ok(utf8Bytes(input.pemRaw).length===451&&input.pemRaw.endsWith("\n")&&utf8Bytes(input.pemRaw.slice(0,-1)).length===450&&objectSame(report.acl.setup_config_projection,baseline),"strict actual 450-byte public PEM projection from 451-byte source");
 const rows=report.acl.cases,records=report.admin_and_case_wire_records,observedCounts={},policyVariants=new Set(),oldDifferences=[];
 ok(records.length===838&&report.acl_requests_observed===records.length&&records.length<=report.acl_request_cap&&report.acl_request_cap===853,"actual HTTP request accounting");
 for(let i=0;i<23;i++){
  const c=rows[i],m=matrix.matrix[i],wire=records.filter(r=>r.case_id===c.case_id);
  ok(c.case_id===m.id&&c.method===m.method&&c.path===m.path&&same(c.capabilities,m.capabilities)&&same(c.official_source_prediction,m.official_source_prediction)&&same(c.R2_source_prediction,m.R2_source_prediction),"frozen matrix identity "+i);
  ok(wire.length===1&&same(wire[0],c.wire)&&c.actual_raw_status===c.wire.status&&c.wire.complete===true&&c.wire.context_closed===true&&c.wire.retried===false&&c.wire.open_calls===1&&c.wire.body_within_cap===true&&c.wire.normalized_status===false&&c.normalize_status===false,"actual raw HTTP status and complete one request "+i);
  ok(c.actor.independent_lookup===true&&c.actor.real_issued_service===true&&c.actor.no_root_policy===true&&c.actor.no_default_policy===true&&c.actor.no_entity_binding===true&&c.actor.only_exact_case_policy===true,"real case actor proof "+i);
  const b=c.before,a=c.after,names=Object.keys(b.roles).sort();
  ok(names.length===12&&same(names,Object.keys(a.roles).sort()),"complete twelve-role snapshot "+i);
  for(const snap of [b,a]){
   ok(same(snap.listed,Object.keys(snap.roles).filter(k=>snap.roles[k]!==null).sort()),"snapshot inventory equality "+i);
   for(const role of Object.values(snap.roles).filter(Boolean))policyVariants.add(JSON.stringify({token_policies_present:role.token_policies_present,token_policies:role.token_policies}));
  }
  if(c.path==="auth/jwt-acl/config"){
   ok(same(a.roles,b.roles)&&same(a.listed,b.listed),"config operation retains all roles "+i);
   const target=c.actual_raw_status===204?{...baseline,bound_issuer:baseline.bound_issuer+"-"+c.case_id}:b.config;
   ok(objectSame(a.config,target),"exact config transition "+i);
  }else{
   ok(same(a.config,b.config),"role operation retains configuration "+i);
   if(c.actual_raw_status!==204||c.method==="GET"||c.method==="LIST")ok(same(a,b),"read or rejected operation unchanged "+i);
   else{
    const name=c.path.split("/").pop();
    ok(names.filter(k=>k!==name).every(k=>same(a.roles[k],b.roles[k])),"other eleven roles unchanged "+i);
    if(c.method==="DELETE")ok(b.roles[name]!==null&&a.roles[name]===null&&!a.listed.includes(name),"exact successful delete "+i);
    else ok(a.roles[name]!==null&&objectSame(a.roles[name].common,{role_type:"jwt",user_claim:"sub",bound_audiences:[baseline.bound_issuer+"-"+c.case_id]})&&a.listed.includes(name),"exact successful role write "+i);
   }
  }
  ok(c.transition_checked===true,"original transition check recorded "+i);
  observedCounts[c.actual_raw_status]=(observedCounts[c.actual_raw_status]||0)+1;
  if(c.actual_raw_status!==c.R2_source_prediction)oldDifferences.push(c.case_id);
 }
 const owner=report.original_owner;
 ok(owner.same_originals_closed===true&&owner.passed_process_method===true&&owner.children.length===4&&owner.controls.length===0,"original four-child owner closure");
 ok(owner.external_original_deadline===true&&owner.profile_seconds===360&&report.deadline_reset===false&&owner.original_deadline_ns===report.original_deadline_ns&&owner.started_ns<owner.business_finished_ns&&owner.business_finished_ns<=owner.finished_ns&&owner.finished_ns<owner.original_deadline_ns,"original absolute 360 deadline honored");
 ok(new Set(owner.children.map(c=>c.original_PID)).size===4&&owner.children.filter(c=>c.kind==="server").length===1,"four distinct originals and one server");
 for(const c of owner.children){
  ok(c.exit_code===0&&c.completed_original_wait_count===1&&c.same_original_Popen_wait===true&&c.original_wait_attempts.length===1&&c.original_wait_attempts[0].returncode===0,"same original child waited once "+c.original_PID);
  ok(c.original_SID_retired_observed===true&&c.SID_survivors.length===0&&c.SID_observation_gaps.length===0&&c.gaps.length===0&&c.fallback===false&&c.exec_input_guard_acknowledged===true,"exact original child custody closure "+c.original_PID);
  if(c.kind==="server")ok(c.signals.length===1&&c.signals[0].signal===15&&c.signals[0].authority==="original_kernel_pidfd"&&c.signals[0].sent===true,"original server pidfd TERM");
 }
 ok(report.components.classes===4&&report.components.variants===8&&report.components.results.length===8&&report.components.results.every(c=>c.passed===true&&c.suite_call_restored===true)&&report.components.HTTP_requests===0&&report.component_product_cases===0&&report.http12_product_cases_executed===0,"eight actual component variants excluded from product denominator");
 ok(report.extra_live_health_requests.maximum===1&&report.extra_live_health_requests.attempted===1&&report.extra_live_health_requests.completed===1&&report.startup_requests_actual_count===null,"actual extra health and unknown startup count retained");
 return {schema:"heptabao.official271.ACL23.r2.offline-final-verification.r1",pass:true,check_count:checks.length,checks,
 counts:{main_original_calls:84,independent_recovery_calls:7,total_original_native_calls:91,original_observers:13,body_original_admissions:10,body_original_pages:60,whole_report_bytes:651803,official_ACL_cases:23,component_variants:8,component_product_cases:0,actual_HTTP_requests:838},
 actual_status_counts:observedCounts,official_source_prediction_matches:rows.filter(c=>c.actual_raw_status===c.official_source_prediction).length,old_R2_source_prediction_differences:oldDifferences,
 observed_role_policy_projections:[...policyVariants].map(JSON.parse),candidate_actual_cases:0,parity_qualified:false,new_Native_calls_by_verifier:0,carried_predecessors:{outer_and_INFO_root:"57ca985572a5efecc20b89ab5dc633a3409f44ea",recovery_handback_root:"a60b1ccebab5398ee2bd05a6be1a06839d65540e"}};
}
