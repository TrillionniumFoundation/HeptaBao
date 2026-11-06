function rootBody20Recovery(f,go,old,failedPacket){
 const rows=[],ck=(name,v)=>{rows.push({name,passed:v===true});if(v!==true)throw Error(name);},p=gitBlobMeta,eq=(x,y)=>JSON.stringify(x)===JSON.stringify(y),b=JSON.parse(f["BOUNDARY.public.json"]),binding=JSON.parse(f["actual-recovery-binding.json"]);
 ck("exact_root_recovery_GO",f["GO.original.json"]===go.text&&eq(binding.go,go.pins));
 ck("original_failed_call_exact",p(f["recovery-original-failed-call.json"]).blob===go.value.failed_call.blob&&f["recovery-original-failed-call.json"]===JSON.stringify(b.originalFailurePreserved,null,2)+"\n");
 ck("original_failed_called_not_accepted",b.originalFailurePreserved.called===true&&b.originalFailurePreserved.phase==="native_interpretation_refused"&&old.value.passed);
 const leaves=binding.armEntries.map(x=>({path:x.path,mode:"100644",type:"blob",sha:p(f["recovery-"+x.path]).blob}));
 ck("four_leaf_recovery_arm",leaves.length===4&&immediateTreeSha(leaves)===binding.armTree&&binding.armTree==="104a0888d861282ca32cd3589635099b7d6632fb");
 const status=JSON.parse(f["original-completed-status.native.json"]);
 ck("same_original_closed_future",status.operation_id===go.value.original_operation&&status.async_state==="completed"&&status.owned_future_active===false&&p(f["original-completed-status.native.json"]).blob==="7dab61f4aeded51aff5f7db244935bb4082e092b");
 const prefix=JSON.parse(f["original-three-pages.exact.json"]),buffer=[];let offset=0;
 ck("three_original_page_rows_exact",p(f["original-three-pages.exact.json"]).blob===go.value.original_pages.blob&&prefix.length===3);
 for(let i=0;i<3;i++){const x=prefix[i],bytes=unb64(x.base64);ck("prior_contiguous_page_"+i,x.offset===offset&&x.next===offset+bytes.length&&bytes.length===16384);buffer.push(...bytes);offset=x.next;}
 const q=JSON.parse(f["recovery-request.json"]),sdk=JSON.parse(f["recovery-original.sdk.json"]),n=JSON.parse(f["recovery-native.json"]),r=JSON.parse(f["recovery-call-record.json"]),a=JSON.parse(f["recovery-armed.json"]),it=JSON.parse(f["recovery-intent.json"]);
 ck("original_SDK_native",sdk.isError===false&&sdk.content.length===1&&sdk.content[0].text===f["recovery-native.json"]&&p(f["recovery-original.sdk.json"]).blob===r.sdkPin.blob&&p(f["recovery-native.json"]).blob===r.nativePin.blob&&eq(r.sdkPin,binding.sdk)&&eq(r.nativePin,binding.native));
 ck("called_accepted_once",r.called===true&&r.phase==="accepted"&&r.kind==="operation_result"&&r.sdkArchive.whole===true&&r.recoveryOfDelivery===go.value.failed_call_key);
 ck("exact_request_and_key",q.operation_id===go.value.original_operation&&q.offset===49152&&q.limit===16384&&a.callKey===go.value.recovery_call_key&&it.callKey===a.callKey);
 const bytes=unb64(n.data_base64);
 ck("single_last_immutable_page",n.operation_id===q.operation_id&&n.offset===offset&&n.next_offset===offset+bytes.length&&n.total_bytes===63251&&n.immutable_snapshot===true&&n.payload_kind==="native_result"&&n.result_sha256===b.payload.sha256&&n.eof&&n.next_offset===63251);buffer.push(...bytes);offset+=bytes.length;
 ck("recovery_separate_GO_old_failure",eq(a.rootRecoveryGo,go.pins)&&eq(it.rootRecoveryGo,go.pins)&&a.originalFailedCall.blob===go.value.failed_call.blob&&a.originalOperation===go.value.original_operation&&it.before.pageCalled===4&&it.before.successfulPages===3);
 const payload=utf8Text(buffer);ck("whole_original_payload",payload===f["closed-payload.original.json"]&&p(payload).bytes===63251&&p(payload).sha256===b.payload.sha256);
 const env=JSON.parse(payload),body=JSON.parse(env.content[0].text);
 ck("whole_original_body",env.resultType==="complete"&&env.isError===false&&env.content[0].text===f["closed-native.original.json"]&&utf8Text(unb64(body.data_base64))===f["body.original.rs"]&&p(f["body.original.rs"]).blob==="9c5ccafbb9ae7d1f3ec1de8c05d97411630f3e98"&&body.chunk_sha256===b.wholeOutput.body.sha256);
 ck("original_version_path_range",body.path===b.wholeOutput.path&&body.version==="66306:31236028:47093:1793956738999594862:1793956738999594862"&&body.offset===0&&body.size===47093&&body.next_offset===47093&&body.eof===true);
 ck("closed_file_boundary",b.pending===null&&b.activeObserver===null&&!b.nativeCallInFlight&&!b.paused&&b.totals.wholeFiles===21&&b.totals.wholeBytes===1325067&&b.totals.closedObservers===55&&b.totals.originalAdmissions===55&&b.totals.callRecords===261);
 ck("historical_failures_still_explicit",b.info10HistoryPreserved&&b.body16HistoryPreserved&&b.file7GitFailurePreserved&&!b.nextInfo21Submitted);
 return {schema:"heptabao.root-original-body20-page-recovery.r1",passed:true,checks:rows.length,rows,sourcePacket:"a10e3d28536ea89fe8d3faf40ca27a18bba0f716",file:b.wholeOutput,successfulPayloadPages:4,newRecoveryPageCalls:1,additionalOriginalFileAdmissions:0,additionalStatusCalls:0,originalFailedPageStillCalled:true,originalThreePagesPreserved:true,originalOperationClosed:true,wholeFilesAtBoundary:21,wholeBytesAtBoundary:1325067,final23Qualified:false,newProductTests:0};
}