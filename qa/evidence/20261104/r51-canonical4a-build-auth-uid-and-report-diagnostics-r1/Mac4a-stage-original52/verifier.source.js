function verifyMac4aOuterOriginalChain(files){
 const checks=[];function need(n,v){checks.push({name:n,pass:!!v});if(!v)throw Error(n);}
 const same=(x,y)=>JSON.stringify(x)===JSON.stringify(y),pin=gitBlobMeta;
 const state=JSON.parse(files["closed-state.original.json"]),calls=JSON.parse(files["CALL-INDEX.public.json"]),go=JSON.parse(files["GO.original.json"]);
 need("root_GO_exact",pin(files["GO.original.json"]).blob==="38e5b91ff8873eb94ba434b581d3543deee0b3a6");
 need("seven_original_calls",calls.length===7&&Object.keys(state.calls).length===7);
 need("two_original_closed_observers",state.completedObservers.length===2&&state.completedObservers.every(o=>o.completedInactive===true));
 need("actual_closed_no_future",!state.paused&&!state.nativeCallInFlight&&state.pending===null&&state.activeObserver===null);
 let merkle=0;const natives=[];
 for(let i=0;i<calls.length;i++){
  const c=calls[i],p="call-"+String(i).padStart(2,"0"),raw=files[p+".request.json"],sdkRaw=files[p+".original.sdk.json"],nativeRaw=files[p+".native.original.json"];
  need("call"+i+"_exact_original_record",same(c,{callKey:c.callKey,...state.calls[c.callKey]})&&c.called&&c.phase==="accepted");
  need("call"+i+"_request_whole",same(pin(raw),c.requestPin)&&raw===c.requestRaw);
  need("call"+i+"_SDK_whole",same(pin(sdkRaw),c.sdkPin)&&c.sdkArchive.whole===true);
  const sdk=JSON.parse(sdkRaw);need("call"+i+"_native_original",sdk.isError!==true&&sdk.content.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===nativeRaw&&same(pin(nativeRaw),c.nativePin));
  const intent=JSON.parse(files[p+".intent.json"]),armed=JSON.parse(files[p+".armed.json"]);
  need("call"+i+"_arm_GO_and_request",same(intent.rootGo,pin(files["GO.original.json"]))&&same(armed.rootGo,intent.rootGo)&&same(intent.request,c.requestPin)&&same(armed.request,c.requestPin)&&intent.nativeNotYetCalled===true);
  for(const e of c.armed.entries)need("call"+i+"_arm_leaf_"+e.path,e.whole===true&&same(pin(files[p+"."+e.path]),{blob:e.blob,bytes:e.bytes,sha256:e.sha256}));
  gitTreeAudit({sha:c.armed.tree,truncated:false,tree:c.armed.entries.map(e=>({path:e.path,mode:"100644",type:"blob",sha:e.blob}))});merkle++;
  gitTreeAudit({sha:c.sdkArchive.tree,truncated:false,tree:[{path:"original.sdk.json",mode:"100644",type:"blob",sha:c.sdkPin.blob}]});merkle++;
  natives.push(parseLosslessIntegers(nativeRaw));
 }
 const q=JSON.parse(calls[0].requestRaw),binding=processStartBinding(q),ack=natives[0];
 need("exact_typed_start_binding",binding.sha256===go.native_binding.sha256&&binding.native_fingerprint===go.native_binding.native_fingerprint&&same(pin(calls[0].requestRaw),go.exact_request));
 const fp=Number.isSafeInteger(ack.job.request_fingerprint)?String(ack.job.request_fingerprint):ack.job.request_fingerprint.$exactInteger;
 need("actual_START_ack",ack.reused===false&&ack.launch.ok===true&&ack.audit_recorded===true&&ack.local_record_pending===false&&ack.job.id===state.job&&ack.job.host==="mac"&&ack.job.execution_mode==="operator"&&ack.job.request_digest===binding.sha256&&fp===binding.native_fingerprint);
 need("actual_START_argv",ack.job.idempotency_key===q.idempotency_key&&ack.job.executable===q.executable&&ack.job.cwd===q.cwd&&same(ack.job.args,q.args));
 for(let i=0;i<2;i++){
  const o=state.completedObservers[i],base=1+i*3,admit=natives[base],status=natives[base+1],page=natives[base+2],payload=files["observer-"+i+".payload.original.json"],bytes=unb64(page.data_base64);
  need("observer"+i+"_same_ID",admit.operation_id===o.id&&admit.reused===false&&status.operation_id===o.id&&page.operation_id===o.id&&admit.tool_name===o.tool&&status.tool_name===o.tool);
  need("observer"+i+"_inactive_stored",status.async_state==="completed"&&status.owned_future_active===false&&status.payload_available===true&&status.result_state==="stored_observed");
  need("observer"+i+"_whole_one_page",page.offset===0&&page.next_offset===bytes.length&&page.eof===true&&page.total_bytes===bytes.length&&bytes.length<=8192&&page.immutable_snapshot===true&&utf8Text(bytes)===payload&&pin(payload).sha256===page.result_sha256&&same(pin(payload),o.payload));
  gitTreeAudit({sha:o.payloadTree,truncated:false,tree:[{path:"payload.original.json",mode:"100644",type:"blob",sha:o.payload.blob}]});merkle++;
  const inner=JSON.parse(payload);need("observer"+i+"_original_inner_native",inner.isError!==true&&inner.content.length===1&&same(pin(inner.content[0].text),o.nativeText));
 }
 const authority=JSON.parse(files["authority.native.original.json"]),streams=JSON.parse(files["streams.native.original.json"]),summary=JSON.parse(files["stdout.original.txt"]);
 need("terminal_exit0_full_durable",authority.job_id===state.job&&authority.exit_code===0&&!authority.timed_out&&!authority.cancelled&&authority.output_complete&&authority.output_durable&&authority.terminal_publication_confirmed);
 for(const n of ["stdout","stderr"]){
  const x=streams[n],b=x.bytes_hex.match(/../g)?.map(h=>parseInt(h,16))||[];
  need(n+"_continuous_whole_text",x.offset===0&&x.eof===true&&x.next_offset===x.size&&x.size===b.length&&utf8Text(b)===x.text&&x.text===files[n+".original.txt"]&&authority.log_bytes[n].seen===x.size&&authority.log_bytes[n].stored===x.size&&authority.log_synced[n]===true&&authority.log_truncated[n]===false);
 }
 need("exact378_summary_no_Cargo",state.nextStdout===378&&state.nextStderr===0&&pin(files["stdout.original.txt"]).bytes===378&&summary.source_commit===go.candidate.commit&&summary.source_tree===go.candidate.tree&&summary.result_path===go.newReport&&summary.status==="prepared"&&summary.all_owned_stopped===true&&summary.within_new_stage_deadline===true&&summary.compiler_started===false&&summary.server_started===false);
 return{schema:"heptabao.mac4a-stage-original-transport-verification.r1",pass:true,checkCount:checks.length,checks,merkleTrees:merkle,actualOriginalCalls:7,actualOriginalObservers:2,actualPages:2,actualExitCode:0,NativeCallsByVerifier:0,detailedStageReportQualified:false,MacNormal117Qualified:false,formal34Qualified:false};
}
