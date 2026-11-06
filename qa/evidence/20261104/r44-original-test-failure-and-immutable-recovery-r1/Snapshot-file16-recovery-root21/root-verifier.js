function rootBody16Recovery(f,go,old){
 const rows=[],ck=(name,v)=>{rows.push({name,passed:v===true});if(v!==true)throw Error(name);},p=gitBlobMeta,eq=(x,y)=>JSON.stringify(x)===JSON.stringify(y),b=JSON.parse(f["BOUNDARY.public.json"]),binding=JSON.parse(f["actual-recovery-binding.json"]);
 ck("exact_root_recovery_GO",f["GO.original.json"]===go.text&&eq(binding.go,go.pins));
 ck("original_failed_call_fourth_leaf_exact",p(f["call0-original-failed-call.json"]).blob===go.value.failed_call.blob&&f["call0-original-failed-call.json"]===JSON.stringify(b.originalFailedCallPreserved,null,2)+"\n");
 ck("original_failed_called_not_accepted",b.originalFailedCallPreserved.called===true&&b.originalFailedCallPreserved.phase==="native_interpretation_refused"&&old.value.passed);
 const recoveryLeaves=binding.armEntries.map(x=>({path:x.path,mode:"100644",type:"blob",sha:p(f["call0-"+x.path]).blob}));
 ck("four_leaf_recovery_arm",recoveryLeaves.length===4&&immediateTreeSha(recoveryLeaves)===binding.armTree&&binding.armTree==="c370ed05be5ee262616c26daeee0beca0f4f5a13");
 const oldStatus=JSON.parse(f["original-body-status.native.json"]);
 ck("same_original_closed_future",oldStatus.operation_id===go.value.original_operation&&oldStatus.async_state==="completed"&&oldStatus.owned_future_active===false&&p(f["original-body-status.native.json"]).blob==="237b2709d1ca13c6b56fdd4be8012920bac38b7a");
 const buffer=[];let offset=0;
 for(let i=0;i<2;i++){
  const stem="call"+i+"-",q=JSON.parse(f[stem+"request.json"]),s=JSON.parse(f[stem+"original.sdk.json"]),n=JSON.parse(f[stem+"native.json"]),r=JSON.parse(f[stem+"record.json"]),a=JSON.parse(f[stem+"armed.json"]),it=JSON.parse(f[stem+"intent.json"]);
  ck("original_SDK_native_"+i,s.isError===false&&s.content.length===1&&s.content[0].text===f[stem+"native.json"]&&p(f[stem+"original.sdk.json"]).blob===r.sdkPin.blob&&p(f[stem+"native.json"]).blob===r.nativePin.blob);
  ck("called_accepted_"+i,r.called===true&&r.phase==="accepted"&&r.kind==="operation_result"&&r.sdkArchive.whole===true);
  ck("exact_request_and_key_"+i,q.operation_id===go.value.original_operation&&q.offset===offset&&q.limit===16384&&a.callKey===(i===0?go.value.recovery_call_key:"sf23-r1-f16-b00-p2")&&it.callKey===a.callKey);
  const bytes=unb64(n.data_base64);ck("contiguous_immutable_page_"+i,n.operation_id===q.operation_id&&n.offset===offset&&n.next_offset===offset+bytes.length&&n.total_bytes===22426&&n.immutable_snapshot===true&&n.payload_kind==="native_result"&&n.result_sha256===b.closedObserver.payload.sha256&&n.eof===(i===1));buffer.push(...bytes);offset+=bytes.length;
  if(i===0)ck("recovery_explicit_separate_GO_and_old_failure",eq(a.rootRecoveryGo,go.pins)&&eq(it.rootRecoveryGo,go.pins)&&a.originalFailedCall.blob===go.value.failed_call.blob&&a.originalOperation===go.value.original_operation);
  else ck("ordinary_p2_original_GO_and_three_leaf_arm",a.rootGo.blob===go.value.original_go&&immediateTreeSha(["armed.json","intent.json","request.json"].map(x=>({path:x,mode:"100644",type:"blob",sha:p(f[stem+x]).blob})))===r.armed.tree);
 }
 const payload=utf8Text(buffer);ck("whole_original_payload",payload===f["closed-payload.original.json"]&&p(payload).bytes===22426&&p(payload).sha256===b.closedObserver.payload.sha256);
 const env=JSON.parse(payload),n=JSON.parse(env.content[0].text);
 ck("whole_original_body",env.resultType==="complete"&&env.isError===false&&utf8Text(unb64(n.data_base64))===f["body.original.rs"]&&p(f["body.original.rs"]).blob==="a06777634573628646661f75d2d3d060d16e06f8"&&n.chunk_sha256===b.wholeFile.body.sha256);
 ck("original_version_path_range",n.path===b.wholeFile.path&&n.version==="66306:31236012:16474:1793956738925595332:1793956738925595332"&&n.offset===0&&n.size===16474&&n.next_offset===16474&&n.eof===true);
 ck("no_extra_admission_or_status",b.nativeCallsDuringRecovery===2&&b.additionalAdmissionCalls===0&&b.additionalStatusCalls===0);
 ck("closed_file_boundary",b.pending===null&&b.activeObserver===null&&!b.nativeCallInFlight&&!b.paused&&b.completedFiles===17&&b.bodyBytes===1200639&&b.completedObservers===47);
 ck("historical_failures_still_explicit",b.oldInfo10FailurePreserved==="native_interpretation_refused"&&b.oldInfo10RecoveryPreserved==="accepted"&&b.oldGitFailurePreserved==="Error: git_tree_read_error_preserved");
 return {schema:"heptabao.root-original-body16-page-recovery.r1",passed:true,checks:rows.length,rows,sourcePacket:"5aea752641f3c23c9cf708e3e82796d42b1b3609",file:b.wholeFile,successfulPayloadPages:2,originalFailedPageStillCalled:true,priorINFO10FailurePreserved:true,originalOperationClosed:true,wholeFilesAtBoundary:17,wholeBytesAtBoundary:1200639,final23Qualified:false,newProductTests:0};
 }