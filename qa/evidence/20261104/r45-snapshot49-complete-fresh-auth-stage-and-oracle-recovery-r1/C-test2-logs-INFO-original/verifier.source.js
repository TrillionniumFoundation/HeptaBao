function verifyFailedTestLogInfo(files) {
 const checks=[]; function c(name,ok){checks.push({name,pass:!!ok});if(!ok)throw Error(name);}
 const j=(path)=>parseLosslessIntegers(files[path]);
 const samePin=(raw,pin)=>{const m=gitBlobMeta(raw);return m.blob===pin.blob&&m.bytes===pin.bytes&&m.sha256===pin.sha256;};
 const st=j("state.original.json"),prior=j("prior-context.original.json"),g=j("GO.original.json");
 c("new-info-GO",g.scope==="build_failed_test_logs_file_info_only"&&g.maximum_file_info_operations===2&&g.maximum_binary_read_operations===0&&g.maximum_process_start_calls===0);
 c("original-context-binding",samePin(files["prior-context.original.json"],st.priorClosedContext.state)&&st.priorClosedContext.slot===st.originalPausedContext.slot);
 c("prior-closed",prior.job==="1a1b10cad9b-fc05-7560"&&Object.keys(prior.calls).length===41&&prior.completedObservers.length===12&&prior.paused===false&&prior.pending===null&&prior.activeObserver===null&&prior.nativeCallInFlight===false);
 c("new-context-closed",st.paused===false&&st.pending===null&&st.activeObserver===null&&st.nativeCallInFlight===false&&st.startCalled===false);
 c("six-calls-two-observers",Object.keys(st.calls).length===6&&st.completedObservers.length===2&&st.logInfos.length===2);
 for(const [name,row] of Object.entries(st.calls)){
  const q=files[name+".request.json"],sdkRaw=files[name+".sdk.original.json"],nativeRaw=files[name+".native.original.json"];
  const sdk=parseLosslessIntegers(sdkRaw),intent=j(name+".intent.json"),arm=j(name+".armed.json");
  c(name+":request-pin",q===row.requestRaw&&samePin(q,row.requestPin));
  c(name+":SDK-pin-and-success",samePin(sdkRaw,row.sdkPin)&&sdk.isError!==true);
  c(name+":native-original-text",samePin(nativeRaw,row.nativePin)&&sdk.content.some(x=>x.type==="text"&&x.text===nativeRaw));
  c(name+":whole-before-accepted",row.called===true&&row.phase==="accepted"&&row.armed.whole===true&&row.sdkArchive.whole===true);
  c(name+":intent",intent.callKey===name&&intent.kind===row.kind&&intent.maximumNativeCalls===1&&intent.nativeNotYetCalled===true&&intent.rootGo.blob===st.goPin.blob);
  c(name+":armed",arm.callKey===name&&arm.mayHaveDispatchedAfterThisCheckpoint===true&&arm.request.blob===row.requestPin.blob);
  const members=row.armed.entries.map(x=>({path:x.path,mode:"100644",type:"blob",sha:x.blob}));
  const audit=gitTreeAudit({sha:row.armed.tree,truncated:false,tree:members});
  c(name+":arm-Merkle",audit.root_sha===row.armed.tree&&audit.leaf_count===3);
  c(name+":arm-whole-bytes",row.armed.entries.every(x=>samePin(files[name+"."+x.path],x)));
 }
 for(let i=0;i<2;i++){
  const k=i===0?"stderr":"stdout",base="jwt-pki-025b-test2-"+k+"-info-",o=st.completedObservers[i],info=st.logInfos[i];
  const req=j(base+"admit.request.json"),ack=j(base+"admit.native.original.json"),status=j(base+"status0.native.original.json"),page=j(base+"page0.native.original.json");
  const payloadRaw=files[k+".payload.original.json"],payload=parseLosslessIntegers(payloadRaw),nativeRaw=files[k+"-info.native.original.json"],v=parseLosslessIntegers(nativeRaw);
  c(k+":exact-request",samePin(files[base+"admit.request.json"],g.exact_requests[i])&&req.operation.tool==="file_info"&&req.operation.arguments.host==="rog"&&req.operation.arguments.path===g.targets[i].path);
  c(k+":ACK",ack.operation_id===o.id&&ack.reused===false&&ack.tool_name==="file_info");
  c(k+":status",status.operation_id===o.id&&status.async_state==="completed"&&status.owned_future_active===false&&status.result_state==="stored_observed"&&status.payload_available===true);
  c(k+":same-ID-requests",j(base+"status0.request.json").operation_id===o.id&&j(base+"page0.request.json").operation_id===o.id);
  c(k+":page-request",j(base+"page0.request.json").offset===0&&j(base+"page0.request.json").limit===8192);
  c(k+":page-identity",page.operation_id===o.id&&page.immutable_snapshot===true&&page.offset===0&&page.eof===true);
  c(k+":page-whole",utf8Text(unb64(page.data_base64))===payloadRaw&&page.next_offset===page.total_bytes&&samePin(payloadRaw,o.payload)&&page.result_sha256===o.payload.sha256&&page.total_bytes===o.payload.bytes);
  c(k+":envelope",payload.resultType==="complete"&&payload.isError===false&&payload.content.length===1&&payload.content[0].text===nativeRaw&&samePin(nativeRaw,o.nativeText));
  c(k+":metadata-shape",v.path===g.targets[i].path&&v.sha256===g.targets[i].sha256&&v.mode===384&&v.metadata.mode===384&&v.metadata.metadata_platform==="linux"&&v.metadata.uid===1000&&v.metadata.gid===1000&&v.metadata.link_count===1);
  const z=v.version.split(":");
  c(k+":version",z.length===5&&z.every(x=>/^[0-9]+$/.test(x))&&z[2]===String(v.size));
  c(k+":full9",JSON.stringify(info.full9Strings)===JSON.stringify([z[0],z[1],"1000","1000","33152","1",String(v.size),z[3],z[4]]));
  c(k+":actual-table",info.originalOperation===o.id&&info.size===v.size&&info.version===v.version&&info.sha256===v.sha256&&info.bodyReadAuthorized===false&&o.completedInactive===true&&o.pages===1);
 }
 c("actual191-and375",st.logInfos[0].size===191&&st.logInfos[1].size===375);
 return {schema:"heptabao.failed-test2-log-info-original-chain-checks.r1",pass:true,check_count:checks.length,checks,calls:6,observers:2,pages:2,body_observed:false,new_BUILD:false,product_cases:0};
}
