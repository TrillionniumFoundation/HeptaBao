function verifyMac4aInertOriginalChain(files){
 const checks=[];function need(v,n){if(!v)throw Error(n);checks.push(n);}const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const ix=JSON.parse(files["CALL-INDEX.public.json"]),state=JSON.parse(files["state.closed.original.json"]),go=JSON.parse(files["ROOT-GO.original.json"]);
 need(eq(gitBlobMeta(files["ROOT-GO.original.json"]),ix.GO)&&go.exact_request.blob==="e159810aa46391f2934bfe48517c4da7bd0f0635","exact original INERT GO");
 need(eq(gitBlobMeta(files["state.closed.original.json"]),ix.closedState)&&state.job===ix.job&&!state.paused&&state.pending===null&&state.activeObserver===null&&!state.nativeCallInFlight,"actual closed state");
 need(ix.calls.length===8&&Object.keys(state.calls).length===8&&ix.observers.length===2,"eight calls and two observers");
 const decoded=[];
 for(const c of ix.calls){
   const requestRaw=files[c.armFiles["request.json"]],sdkRaw=files[c.sdkFile],nativeRaw=files[c.nativeFile];
   need(c.called===true&&c.phase==="accepted"&&eq(gitBlobMeta(requestRaw),c.requestPin)&&eq(gitBlobMeta(sdkRaw),c.sdkPin)&&eq(gitBlobMeta(nativeRaw),c.nativePin),"once accepted original call pins "+c.key);
   const intent=JSON.parse(files[c.armFiles["intent.json"]]),arm=JSON.parse(files[c.armFiles["armed.json"]]);
   need(intent.callKey===c.key&&arm.callKey===c.key&&intent.kind===c.kind&&arm.kind===c.kind&&eq(intent.request,c.requestPin)&&eq(arm.request,c.requestPin)&&eq(intent.rootGo,ix.GO)&&eq(arm.rootGo,ix.GO)&&intent.nativeNotYetCalled===true&&arm.mayHaveDispatchedAfterThisCheckpoint===true,"original intent and arm binding "+c.key);
   gitTreeAudit({sha:c.armTree,truncated:false,tree:Object.entries(c.armFiles).map(([path,file])=>({path,mode:"100644",type:"blob",sha:gitBlobMeta(files[file]).blob}))});
   need(true,"three-leaf arm Merkle "+c.key);
   gitTreeAudit({sha:c.sdkTree,truncated:false,tree:[{path:"original.sdk.json",mode:"100644",type:"blob",sha:c.sdkPin.blob}]});
   need(true,"whole original SDK Merkle "+c.key);
   const sdk=JSON.parse(sdkRaw);
   need(sdk.isError!==true&&sdk.content?.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===nativeRaw,"SDK exact native extraction "+c.key);
   decoded.push({...c,q:JSON.parse(requestRaw),v:parseLosslessIntegers(nativeRaw)});
 }
 const starts=decoded.filter(x=>x.kind==="process_start");need(starts.length===1,"one START");
 const st=starts[0],typed=processStartBinding(st.q),fp=st.v.job.request_fingerprint;
 need(st.requestPin.blob===go.exact_request.blob&&typed.sha256===go.typed_binding.sha256&&typed.native_fingerprint===go.typed_binding.native_fingerprint&&st.v.job.request_digest===typed.sha256&&(typeof fp==="number"?String(fp):fp.$exactInteger)===typed.native_fingerprint&&st.v.job.id===ix.job&&st.v.reused===false&&st.v.launch.ok===true,"original typed START and ACK");
 const admits=decoded.filter(x=>x.kind==="operation_start");
 need(admits.length===2&&admits[0].q.operation.tool==="process_status"&&admits[1].q.operation.tool==="process_read"&&admits.every(x=>x.q.operation.arguments.host==="mac"&&x.q.operation.arguments.job_id===ix.job&&x.v.reused===false&&x.v.automatic_retry===false),"only original job authority and streams");
 need(admits[1].q.operation.arguments.limit===16384&&admits[1].q.operation.arguments.stdout_offset===0&&admits[1].q.operation.arguments.stderr_offset===0,"original streams zero cursors and fixed cap");
 for(let n=0;n<ix.observers.length;n++){
  const o=ix.observers[n],ad=admits[n],statuses=decoded.filter(x=>x.kind==="operation_status"&&x.q.operation_id===o.id),pages=decoded.filter(x=>x.kind==="operation_result"&&x.q.operation_id===o.id);
  need(ad.v.operation_id===o.id&&o.tool===ad.q.operation.tool&&statuses.length===1&&statuses[0].v.operation_id===o.id&&statuses[0].v.async_state==="completed"&&statuses[0].v.owned_future_active===false&&statuses[0].v.payload_available===true&&statuses[0].v.result_state==="stored_observed","confirmed original future inactive "+n);
  let bytes=[],cursor=0;
  for(const p of pages){
   const v=p.v,b=unb64(v.data_base64);
   need(p.q.offset===cursor&&p.q.limit===8192&&v.operation_id===o.id&&v.offset===cursor&&v.immutable_snapshot===true&&v.payload_kind==="native_result"&&v.total_bytes===o.payload.bytes&&v.result_sha256===o.payload.sha256&&b.length<=8192&&v.next_offset===cursor+b.length&&v.eof===(v.next_offset===v.total_bytes),"original immutable continuous page "+p.key);
   cursor=v.next_offset;bytes=bytes.concat(b);
  }
  const raw=utf8Text(bytes);need(raw===files[o.payloadFile]&&eq(gitBlobMeta(raw),o.payload)&&cursor===o.payload.bytes&&pages.length===o.pages&&pages.at(-1).v.eof===true,"whole payload exact "+n);
  gitTreeAudit({sha:o.payloadTree,truncated:false,tree:[{path:"payload.original.json",mode:"100644",type:"blob",sha:o.payload.blob}]});need(true,"whole original payload Merkle "+n);
  const envelope=parseLosslessIntegers(raw);
  need(envelope.resultType==="complete"&&envelope.isError===false&&envelope.content.length===1&&envelope.content[0].text===files[o.nativeFile]&&eq(gitBlobMeta(files[o.nativeFile]),o.nativeText),"whole payload exact original result "+n);
 }
 const a=parseLosslessIntegers(files["authority.original.json"]),s=parseLosslessIntegers(files["streams.original.json"]);
 need(a.job_id===ix.job&&a.exit_code===0&&a.output_complete===true&&a.output_durable===true&&a.terminal_publication_confirmed===true&&!a.timed_out&&!a.cancelled,"actual successful durable publisher terminal");
 need(s.job_id===ix.job&&s.stdout.offset===0&&s.stdout.eof===true&&s.stdout.next_offset===2988&&s.stdout.size===2988&&s.stdout.text===files["stdout.original.json"]&&s.stderr.offset===0&&s.stderr.next_offset===0&&s.stderr.size===0&&s.stderr.eof===true&&s.stderr.text==="","whole 2988-byte stdout and empty stderr");
 need(utf8Bytes(s.stdout.text).map(x=>x.toString(16).padStart(2,"0")).join("")===s.stdout.bytes_hex,"stdout lossless bytes");
 const bi=JSON.parse(files["BUILD-INPUTS.actual.json"]);
 const result=bindFreshMacNormalBuild({...bi,authorityNativeRaw:files["authority.original.json"],streamsNativeRaw:files["streams.original.json"]});
 need(result.requestRaw===files["BUILD-request.exact.json"]&&result.actualPublisherJob===ix.job&&eq(result.actualReceipt,bi.actualReceipt),"unchanged actual build binder acceptance");
 const release=JSON.parse(files["RELEASE.public.json"]);need(release.laneReleased===true&&release.CNativeCallsInFlight===0&&release.CNativeFuturesInFlight===0&&release.normalBuildNotStarted===true&&!release.normal117Qualified&&!release.full34Qualified,"release and qualification boundary");
 return {schema:"heptabao.mac4a.inert-original-chain-check.r1",pass:true,check_count:checks.length,checks,originalJob:ix.job,originalCalls:8,originalObservers:2,originalPages:3,stdout:gitBlobMeta(s.stdout.text),actualReceipt:result.actualReceipt,normal117Qualified:false,full34Qualified:false,NativeCallsAddedByVerification:0};
}
