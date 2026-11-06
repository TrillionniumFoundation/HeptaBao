function verifyFailedTestLogBodies(files) {
 const checks=[];function c(name,v){checks.push({name,pass:!!v});if(!v)throw Error(name);}
 const j=k=>parseLosslessIntegers(files[k]),pin=(raw,x)=>{const a=gitBlobMeta(raw);return a.blob===x.blob&&a.bytes===x.bytes&&a.sha256===x.sha256;};
 const before=j("INFO.STATE.before.original.json"),after=j("STATE.after.original.json"),go=j("BODY.GO.original.json"),expected=j("expected.public.json");
 c("exact-body-GO",go.scope==="build_failed_test2_logs_binary_read_only"&&go.maximum_binary_read_starts===2&&go.maximum_file_info_starts===0&&go.maximum_process_start_calls===0);
 c("old-six-calls-preserved",Object.keys(before.calls).length===6&&Object.entries(before.calls).every(([k,v])=>JSON.stringify(v)===JSON.stringify(after.calls[k])));
 c("closed-four-observers",after.pending===null&&after.activeObserver===null&&after.nativeCallInFlight===false&&after.paused===false&&after.completedObservers.length===4&&after.completedObservers.every(x=>x.completedInactive===true));
 c("both-actual-bodies",after.failedTestLogBodies.length===2&&after.failedTestLogBodyStarted.every(x=>x===true));
 c("whole-BODY-go-pin",pin(files["BODY.GO.original.json"],after.failedTestLogBodiesGO.pin)&&after.failedTestLogBodiesGO.whole===true);
 c("prior-BUILD-immutable-pin",pin(files["prior-BUILD.original.json"],after.priorClosedContext.state)&&JSON.stringify(before.priorClosedContext)===JSON.stringify(after.priorClosedContext));
 const names=Object.keys(after.calls).filter(k=>!Object.hasOwn(before.calls,k));
 c("six-new-original-calls",names.length===6);
 for(const name of names){
  const x=after.calls[name],raw=files[name+".sdk.original.json"],sdk=parseLosslessIntegers(raw),nr=files[name+".native.original.json"];
  c(name+":request",files[name+".request.json"]===x.requestRaw&&pin(x.requestRaw,x.requestPin));
  c(name+":whole-SDK",pin(raw,x.sdkPin)&&sdk.isError!==true&&x.phase==="accepted"&&x.sdkArchive.whole===true&&x.called===true);
  c(name+":native",pin(nr,x.nativePin)&&sdk.content.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===nr);
  for(const part of ["intent.json","armed.json"]){const record=j(name+"."+part);c(name+":"+part+"-BODY-rootGo",JSON.stringify(record.rootGo)===JSON.stringify(after.failedTestLogBodiesGO.pin)&&record.maximumNativeCalls===1&&record.callKey===name);}
  c(name+":whole-arm",x.armed.whole===true&&x.armed.entries.every(q=>pin(files[name+"."+q.path],q)));
  const audit=gitTreeAudit({sha:x.armed.tree,truncated:false,tree:x.armed.entries.map(q=>({path:q.path,mode:"100644",type:"blob",sha:q.blob}))});
  c(name+":arm-Merkle",audit.root_sha===x.armed.tree&&audit.leaf_count===3);
 }
 for(let i=0;i<2;i++){
  const label=i===0?"stderr":"stdout",prefix="jwt-pki-025b-test2-"+label+"-body-",need=expected[i],o=after.completedObservers[2+i],body=after.failedTestLogBodies[i];
  const req=j(prefix+"admit.request.json"),ack=j(prefix+"admit.native.original.json"),status=j(prefix+"status0.native.original.json"),page=j(prefix+"page0.native.original.json");
  const pr=files[label+".payload.original.json"],payload=parseLosslessIntegers(pr),nr=files[label+".body.native.original.json"],v=parseLosslessIntegers(nr),raw=files[label+".original.txt"];
  c(label+":request-pin",pin(files[prefix+"admit.request.json"],go.exact_requests[i]));
  c(label+":actual-version-bound",req.operation.tool==="binary_read"&&req.operation.arguments.host==="rog"&&req.operation.arguments.path===need.path&&req.operation.arguments.offset===0&&req.operation.arguments.limit===need.bytes&&req.operation.arguments.expected_version===need.version);
  c(label+":ACK",ack.operation_id===o.id&&ack.reused===false&&ack.tool_name==="binary_read");
  c(label+":original-status",status.operation_id===o.id&&status.async_state==="completed"&&status.owned_future_active===false&&status.result_state==="stored_observed"&&status.payload_available===true);
  c(label+":same-ID-status-page",j(prefix+"status0.request.json").operation_id===o.id&&j(prefix+"page0.request.json").operation_id===o.id&&j(prefix+"page0.request.json").offset===0&&j(prefix+"page0.request.json").limit===16384);
  c(label+":immutable-page",page.operation_id===o.id&&page.offset===0&&page.immutable_snapshot===true&&page.eof===true&&page.next_offset===page.total_bytes);
  c(label+":whole-payload",utf8Text(unb64(page.data_base64))===pr&&pin(pr,o.payload)&&page.total_bytes===o.payload.bytes&&page.result_sha256===o.payload.sha256);
  c(label+":original-envelope",payload.resultType==="complete"&&payload.isError===false&&payload.content.length===1&&payload.content[0].text===nr&&pin(nr,o.nativeText));
  c(label+":binary-native",v.path===need.path&&v.size===need.bytes&&v.offset===0&&v.next_offset===need.bytes&&v.eof===true&&v.version===need.version&&v.chunk_sha256===need.sha256);
  c(label+":whole-log",utf8Text(unb64(v.data_base64))===raw&&gitBlobMeta(raw).bytes===need.bytes&&gitBlobMeta(raw).sha256===need.sha256&&pin(raw,body));
  c(label+":whole-closed-record",body.whole===true&&body.index===i&&body.originalOperation===o.id&&body.version===need.version&&o.pages===1);
 }
 c("exact-total566",after.failedTestLogBodies.reduce((a,x)=>a+x.bytes,0)===566);
 return {schema:"heptabao.actual-failed-test2-log-bodies-original-chain.r1",pass:true,check_count:checks.length,checks,newCalls:6,newObservers:2,newPages:2,totalBodyBytes:566,newProductExecutions:0};
}
