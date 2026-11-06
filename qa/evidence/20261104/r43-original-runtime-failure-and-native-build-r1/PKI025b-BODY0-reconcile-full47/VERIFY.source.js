function verifyOriginalReconciliation(files) {
 const rows=[];const check=(name,ok)=>{rows.push({name,pass:!!ok});if(!ok)throw Error(name);};
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),pin=(raw,p)=>same(gitBlobMeta(raw),p);
 const calls=JSON.parse(files["CALL-INDEX.public.json"]),state=JSON.parse(files["state.reconciliation.closed.original.json"]);
 const old=JSON.parse(files["state.old-unknown.unchanged.original.json"]),unknown=JSON.parse(files["old.UNKNOWN.original.json"]);
 const release=JSON.parse(files["RELEASE.public.json"]),go=JSON.parse(files["ROOT-GO.original.json"]);
 const id="ae1e362b109464c47c26d6ce6adff749986185dc9f480bb520a41e2c2646a1d3";
 check("5 calls and exact dispatch sequence",calls.length===5&&calls.map(x=>x.kind).join(",")==="operation_start,operation_status,operation_result,operation_result,operation_result");
 check("new context completely closed",!state.paused&&!state.nativeCallInFlight&&state.pending===null&&state.activeObserver===null&&state.completedObservers.length===1);
 check("old original state pin unchanged",pin(files["state.old-unknown.unchanged.original.json"],release.originalContextPin));
 check("old paused UNKNOWN untouched",old.paused===true&&old.pending===unknown.callKey&&old.activeObserver===null&&old.nativeCallInFlight===false&&same(old.publishedBodyStarted,[true,false,false,false])&&old.publishedBodies.length===0);
 check("old record plus original request",pin(files["old.UNKNOWN.original.json"],release.originalUnknown)&&pin(files["old.request.original.json"],release.originalRequest));
 check("old timeout retained without operation identity",JSON.parse(files["old.timeout.original.sdk.json"]).isError===true&&pin(files["old.timeout.original.sdk.json"],unknown.originalSDK));
 for(const c of calls){
  check("call "+c.index+" request pin",pin(files[c.requestLeaf],c.request));
  check("call "+c.index+" complete SDK pin",pin(files[c.sdkLeaf],c.sdk));
  check("call "+c.index+" native text pin",pin(files[c.nativeLeaf],c.native));
  const arm=JSON.parse(files[c.armedLeaf]),intent=JSON.parse(files[c.intentLeaf]),sdk=JSON.parse(files[c.sdkLeaf]);
  check("call "+c.index+" arm intent request",same(arm.request,c.request)&&same(intent.request,c.request)&&arm.callKey===c.key&&intent.callKey===c.key);
  check("call "+c.index+" external whole records",c.armedWhole===true&&c.SDKWhole===true&&c.called===true&&c.phase==="accepted");
  check("call "+c.index+" SDK original text",sdk.isError!==true&&sdk.content.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===files[c.nativeLeaf]);
 }
 check("exact same original request bytes",files[calls[0].requestLeaf]===files["old.request.original.json"]);
 const ack=parseLosslessIntegers(files[calls[0].nativeLeaf]),status=parseLosslessIntegers(files[calls[1].nativeLeaf]);
 check("actual existing-binding receipt",ack.operation_id===id&&ack.tool_name==="binary_read"&&ack.reused===true&&ack.automatic_retry===false&&ack.idempotency_binding_retained===true);
 check("same returned-ID status",JSON.parse(files[calls[1].requestLeaf]).operation_id===id&&status.operation_id===id&&status.tool_name==="binary_read");
 check("completed stored inactive available",status.async_state==="completed"&&status.result_state==="stored_observed"&&status.owned_future_active===false&&status.payload_available===true);
 let bytes=[],offset=0,total=null,digest=null;
 for(let i=2;i<calls.length;i++){
  const q=JSON.parse(files[calls[i].requestLeaf]),v=parseLosslessIntegers(files[calls[i].nativeLeaf]),b=unb64(v.data_base64);
  check("page "+(i-2)+" same exact request",q.operation_id===id&&q.offset===offset&&q.limit===16384);
  check("page "+(i-2)+" immutable original identity",v.operation_id===id&&v.immutable_snapshot===true&&v.payload_kind==="native_result"&&v.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization");
  check("page "+(i-2)+" bounds EOF",v.offset===offset&&v.next_offset===offset+b.length&&b.length<=16384&&v.eof===(v.next_offset===v.total_bytes));
  check("page "+(i-2)+" same total SHA",v.total_bytes===40951&&(total===null||total===v.total_bytes)&&(digest===null||digest===v.result_sha256));
  total=v.total_bytes;digest=v.result_sha256;offset=v.next_offset;bytes=bytes.concat(b);
 }
 const payload=utf8Text(bytes),payloadPin=gitBlobMeta(payload);
 check("complete original payload bytes SHA EOF",offset===40951&&payload===files["body0.payload.original.json"]&&payloadPin.bytes===40951&&payloadPin.sha256===digest&&pin(payload,release.payload));
 const original=parseLosslessIntegers(payload);
 check("complete success original native SDK",original.resultType==="complete"&&original.isError===false&&original.content.length===1&&original.content[0].type==="text");
 check("native exact original text",original.content[0].text===files["body0.native.original.json"]&&pin(original.content[0].text,release.native));
 const native=parseLosslessIntegers(original.content[0].text),req=JSON.parse(files["old.request.original.json"]).operation.arguments,meta=parseLosslessIntegers(files["info0.native.original.json"]);
 const body=utf8Text(unb64(native.data_base64));
 check("body metadata exact identity",native.path===req.path&&native.path===meta.path&&native.version===req.expected_version&&native.version===meta.version&&native.size===meta.size&&native.size===30397);
 check("complete file extent and EOF",native.offset===0&&native.next_offset===30397&&native.eof===true&&req.offset===0&&req.limit===30397);
 check("whole decoded body exact SHA",body===files["body0.actual.py"]&&gitBlobMeta(body).bytes===30397&&gitBlobMeta(body).sha256===meta.sha256&&native.chunk_sha256===meta.sha256&&pin(body,release.body));
 check("matches frozen runner source",gitBlobMeta(body).blob==="f8b36c8adccb493dfc6aa507856150ce8a6a764d");
 check("one observed closure full history",state.completedObservers[0].id===id&&state.completedObservers[0].completedInactive===true&&state.completedObservers[0].pages===3&&state.reconciliationAdmission.reused===true&&state.originalAttemptOutcome==="UNKNOWN");
 check("old timeout not retrospectively replaced",release.originalAttemptOutcome==="UNKNOWN"&&release.originalContextUnchanged===true&&release.originalErrorPreserved===true);
 check("scope and call caps",go.maximum_operation_start_calls===1&&go.maximumOperationStatusCalls>=1&&go.maximumOperationResultPages>=3&&go.otherThreeBodiesAuthorized===false&&go.buildAuthorized===false);
 check("zero current calls and only lane release",release.currentToolCallsInFlight===0&&release.currentOwnedFutureObservedActive===false&&release.currentPending===null&&release.currentActiveObserver===null&&release.otherBodiesSubmitted===false&&release.buildSubmitted===false);
 check("executed source exact",gitBlobMeta(files["journal.executed.original.js"]).blob==="c3c1cad15dad4e714c19e112dacdea929a1d9650");
 return {status:"PASS_ORIGINAL_RECONCILIATION_CHAIN_AND_BODY0_ONLY",checks:rows.length,rows,actualCalls:5,returnedObservers:1,immutablePages:3,NativeCallsByVerifier:0,productCases:0,otherBodiesSubmitted:false,buildSubmitted:false,oldUnknownPreserved:true};
}
