
function qualifySnapshot16FailedPage(p,goPin){
 const checks=[],ck=(name,ok)=>checks.push({name,pass:ok===true}),pin=(raw,x)=>{const m=gitBlobMeta(raw);return m.blob===x.blob&&m.bytes===x.bytes&&m.sha256===x.sha256;};
 const rel=JSON.parse(p.raw["RELEASE.public.json"]),rows=JSON.parse(p.raw["three-calls.index.public.json"]),active=JSON.parse(p.raw["active-observer.original.json"]),byBlob={};
 for(const raw of Object.values(p.raw))byBlob[gitBlobMeta(raw).blob]=raw;
 ck("whole_minimal23",p.audit.tree==="d4d3b0541dbb06cf809c987d19bfe8702938009d"&&p.pins.length===23&&p.pins.reduce((n,x)=>n+x.bytes,0)===27713);
 ck("same_original_slot_GO",rel.originalGO===goPin.blob&&rel.originalSlot==="snapshot_2379_formatted23_readonly_gitfirst_r1"&&rel.rootResume==="9b378d9160ec4ab96a59046efafa949e4de50984");
 const decoded=[];
 for(let i=0;i<3;i++){
 const row=rows[i],stem=["f16-b00-admit","f16-b00-s0","f16-b00-p0"][i],rawQ=p.raw[stem+".request.json"],sdkRaw=p.raw[stem+".original.sdk.json"],intentRaw=p.raw[stem+".intent.json"],armRaw=p.raw[stem+".armed.json"],sdk=JSON.parse(sdkRaw),intent=JSON.parse(intentRaw),arm=JSON.parse(armRaw);
 ck(stem+"_whole_original_request_and_SDK",pin(rawQ,row.requestPin)&&rawQ===row.requestRaw&&pin(sdkRaw,row.sdkPin)&&row.called===true&&JSON.stringify(Object.fromEntries(Object.entries(row).filter(([k])=>k!=="key")))===JSON.stringify(JSON.parse(p.raw[stem+".call.original.json"])));
 ck(stem+"_whole_arm_Merkle",row.armed.whole===true&&row.armed.entries.length===3&&row.armed.entries.every(x=>pin(byBlob[x.blob],x))&&immediateTreeSha(row.armed.entries.map(x=>({path:x.path,mode:"100644",type:"blob",sha:x.blob})))===row.armed.tree);
 ck(stem+"_once_exact_GO",intent.callKey===row.key&&arm.callKey===row.key&&intent.kind===row.kind&&arm.kind===row.kind&&JSON.stringify(intent.rootGo)===JSON.stringify(goPin)&&JSON.stringify(arm.rootGo)===JSON.stringify(goPin)&&intent.maximumNativeCalls===1&&intent.nativeNotYetCalled===true&&arm.mayHaveDispatchedAfterThisCheckpoint===true&&pin(rawQ,intent.request)&&pin(rawQ,arm.request));
 ck(stem+"_SDK_archive_Merkle",row.sdkArchive.whole===true&&immediateTreeSha([{path:"original.sdk.json",mode:"100644",type:"blob",sha:row.sdkPin.blob}])===row.sdkArchive.tree);
 if(i<2){const nr=p.raw[stem+".native.original.json"];ck(stem+"_successful_original_native",sdk.isError===false&&sdk.content.length===1&&sdk.content[0].text===nr&&pin(nr,row.nativePin)&&row.phase==="accepted");decoded.push({q:JSON.parse(rawQ),n:JSON.parse(nr)});}
 else ck("original_failed_page_preserved",row.key==="sf23-r1-f16-b00-p0"&&row.kind==="operation_result"&&row.phase==="native_interpretation_refused"&&row.interpretationFailure==="Error: native_tool_error_preserved_stop"&&!row.nativePin&&sdk.isError===true&&row.sdkPin.blob==="923d6b0480a7a2c63d80ec91ffbc84d0dc6a4011"&&sdk.content[0].text.endsWith("Mcp error: -32603: MCP request timed out"));
 }
 const admit=decoded[0],status=decoded[1],id="9037480fbf014345c1d2bbe1894020e30602a9adb2d8c1a864f6eff35368f1b0",fq=JSON.parse(rows[2].requestRaw);
 ck("original_binary_admission_only_once",admit.q.operation.tool==="binary_read"&&admit.q.operation.arguments.host==="rog"&&admit.n.operation_id===id&&admit.n.reused===false&&admit.n.automatic_retry===false);
 ck("known_future_completed_inactive",status.q.operation_id===id&&status.n.operation_id===id&&status.n.tool_name==="binary_read"&&status.n.async_state==="completed"&&status.n.result_state==="stored_observed"&&status.n.owned_future_active===false&&status.n.payload_available===true);
 ck("failed_delivery_exact_original_immutable_page",fq.operation_id===id&&fq.offset===0&&fq.limit===16384&&rows[2].requestPin.blob==="bfd96536330ccc3704a2ba596203edf3680a0702"&&rows[2].armed.tree==="e8b011038b5afae7a1df8bb9d78bacfe3d118074");
 ck("active_cursor_still_zero_with_known_closed_future",active.id===id&&active.tool==="binary_read"&&active.futureClosed===true&&active.nextPageOffset===0&&active.pages.length===0);
 const inf=parseLosslessIntegers(p.raw["file16-info.native.original.json"]),args=admit.q.operation.arguments;
 ck("body_bound_to_actual_INFO",args.path===inf.path&&args.expected_version===inf.version&&args.offset===0&&args.limit===inf.size&&inf.size===16474);
 ck("paused_pending_history_preserved",rel.state.paused===true&&rel.state.pending==="sf23-r1-f16-b00-p0"&&rel.state.pendingCalled===true&&!rel.state.nextInfoSubmitted&&rel.current.immutablePageDeliveryUnknown===true&&rel.current.originalPagesReceived===0&&rel.originalPriorFailuresPreserved===true);
 ck("no_native_call_or_owned_future",rel.lane.nativeCallsInFlight===0&&rel.lane.ownedNativeFuturesActive===0&&rel.lane.released===true&&Object.values(rel.actionsAfterError).every(x=>x===0));
 ck("no_product_failure_or_completion_inferred",rel.productFailureInferred===false&&rel.final23Qualified===false&&rel.sameErrorContentIsNotSameCall.separateCallRowsPreserved===true);
 return {schema:"heptabao.root.formatted23-file16-closed-future-page-delivery-failure-qualification.r44",passed:checks.every(x=>x.pass),checkCount:checks.length,checks,packet:p.audit.tree,originalOperation:id,failedCall:"sf23-r1-f16-b00-p0",failedRequest:rows[2].requestPin,failedSDK:rows[2].sdkPin,originalStatus:rows[1].nativePin,originalFailedCall:gitBlobMeta(p.raw["f16-b00-p0.call.original.json"]),knownNativeFutureClosed:true,nativeLaneReleased:true,immutablePageDelivery:"UNKNOWN",originalPausedAndCalledStatePreserved:true,wholeFileCountReported:16,nextINFO17Submitted:false,newNativeCalls:0,recoveryAuthorized:false,final23Qualified:false};
}
