/* Pure evidence verifier. No Native, SDK invocation, network or report JSON interpretation. */
function verifyBody02Recovery(files) {
 const checks=[],need=(v,label)=>{checks.push({label,pass:!!v});if(!v)throw Error(label);};
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const meta=(raw,pin)=>same(gitBlobMeta(raw),{blob:pin.blob,bytes:pin.bytes,sha256:pin.sha256});
 const j=path=>parseLosslessIntegers(files[path]);
 const id="6220e2762757d7afa1ba315c7beb2a985c59c147ac7cb3852aa17ba9c21c7a9e";
 const go=j("ROOT-GO.original.json"),before=j("STATE.original.paused.json"),state=j("STATE.recovery.closed.json"),rows=j("CALL-INDEX.public.json"),calls=j("CALLS.original.json");
 need(meta(files["ROOT-GO.original.json"],state.goPin),"whole recovery GO");
 need(meta(files["STATE.original.paused.json"],go.original_paused_state),"exact paused predecessor");
 need(meta(files["journal.original.js"],go.source),"exact reviewed recovery source");
 need(same(state.calls,calls)&&rows.length===7&&Object.keys(calls).length===7,"seven original recovery calls");
 need(state.pending===null&&state.activeObserver===null&&state.nativeCallInFlight===false&&!state.paused,"recovery has no pending future");
 need(state.reconcileStatusCalls===1&&state.originalStatusCalls===1&&state.reconcileStatusCalls+state.originalStatusCalls<=8,"old plus new status budget");
 need(before.paused===true&&before.oracleReportBodyStarted===3&&before.oracleReportBodyRanges.length===2&&before.completedObservers.length===5,"old main read counters retained");
 const failed=before.calls["official271-x230-acl23-r2-body02-status0"];
 need(failed.called===true&&failed.phase==="native_interpretation_refused"&&meta(files["original.failed-status.sdk.json"],failed.sdkPin),"original failed status SDK retained");
 need(before.outerFailure.message==="native_tool_error_preserved_stop","original outerFailure retained");
 need(before.activeObserver.id===id&&before.activeObserver.futureClosed===false,"old knowledge is not rewritten");
 const admit=before.calls["official271-x230-acl23-r2-body02-admit"];
 need(meta(files["original.binary.request.json"],admit.requestPin)&&meta(files["original.binary.admission.sdk.json"],admit.sdkPin),"original binary admission binding");
 const admitSDK=j("original.binary.admission.sdk.json");
 need(admitSDK.isError===false&&JSON.parse(admitSDK.content[0].text).operation_id===id,"returned original operation ID");
 let assembled=[],next=0,statusCount=0,pageCount=0;
 for(const [i,row] of rows.entries()){
  const c=calls[row.callKey],base=row.prefix,qr=files[base+".request.original.json"],q=JSON.parse(qr),
   intent=j(base+".intent.original.json"),armed=j(base+".armed.original.json"),sr=files[base+".sdk.original.json"],sdk=parseLosslessIntegers(sr),
   nr=files[base+".native.original.json"],v=parseLosslessIntegers(nr);
  need(c&&c.phase==="accepted"&&c.called===true&&c.kind===row.kind,"accepted call "+i);
  need(qr===c.requestRaw&&meta(qr,c.requestPin),"request exact "+i);
  need(intent.callKey===row.callKey&&intent.kind===c.kind&&same(intent.request,c.requestPin)&&same(intent.rootGo,state.goPin)&&intent.originalOperation===id&&intent.maximumNativeCalls===1,"intent binding "+i);
  need(armed.callKey===row.callKey&&same(armed.request,c.requestPin)&&same(armed.rootGo,state.goPin)&&armed.nativeNotYetCalled===true&&armed.mayHaveDispatchedAfterThisCheckpoint===true,"armed binding "+i);
  const treeRows=["request","intent","armed"].map(n=>({path:n+".json",mode:"100644",type:"blob",sha:gitBlobMeta(files[base+"."+n+".original.json"]).blob}));
  need(gitTreeAudit({sha:c.armed.tree,truncated:false,tree:treeRows}).leaf_count===3&&c.armed.whole===true&&c.armed.tree===row.armedTree,"three-leaf armed Merkle "+i);
  need(meta(sr,c.sdkPin)&&c.sdkArchive.whole===true&&c.sdkArchive.tree===row.sdkTree,"whole original SDK "+i);
  need(gitTreeAudit({sha:c.sdkArchive.tree,truncated:false,tree:[{path:"original.sdk.json",mode:"100644",type:"blob",sha:c.sdkPin.blob}]}).leaf_count===1,"SDK archive Merkle "+i);
  need(sdk.isError===false&&sdk.content.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===nr&&meta(nr,c.nativePin),"SDK native byte exact "+i);
  need(q.operation_id===id&&v.operation_id===id,"same original ID "+i);
  if(c.kind==="operation_status"){
   statusCount++;need(i===0&&Object.keys(q).join(",")==="operation_id"&&meta(qr,go.exact_status_request),"single new exact status");
   need(v.async_state==="completed"&&v.owned_future_active===false&&v.payload_available===true&&v.result_state==="stored_observed"&&v.tool_name==="binary_read","original effect completed inactive");
  }else{
   pageCount++;need(c.kind==="operation_result"&&i>0&&q.offset===next&&q.limit===16384,"next immutable page "+i);
   need(v.offset===next&&v.immutable_snapshot===true&&v.total_bytes===87807&&v.result_sha256==="ee2852333b301886098786350bddfabf531c07672915529a9af3562d96de9528","page digest extent "+i);
   const b=unb64(v.data_base64);
   need(b.length<=q.limit&&v.next_offset===next+b.length&&v.eof===(v.next_offset===v.total_bytes),"page continuity EOF "+i);
   assembled=assembled.concat(b);next=v.next_offset;
  }
 }
 need(statusCount===1&&pageCount===6&&next===87807,"one status six pages complete");
 const payload=utf8Text(assembled),observer=state.completedObservers[0];
 need(state.completedObservers.length===1&&observer.id===id&&observer.completedInactive===true&&observer.pages===6,"one original observer closed");
 need(payload===files["payload.original.json"]&&meta(payload,observer.payload),"immutable payload byte exact");
 need(gitTreeAudit({sha:observer.payloadTree,truncated:false,tree:[{path:"payload.original.json",mode:"100644",type:"blob",sha:observer.payload.blob}]}).leaf_count===1,"payload archive Merkle");
 const env=JSON.parse(payload);need(env.resultType==="complete"&&env.isError===false&&env.content.length===1&&env.content[0].type==="text"&&env.content[0].text===files["native.original.json"],"complete native envelope byte exact");
 const n=j("native.original.json"),range=j("RANGE.original.json"),t=go.target_original_range;
 need(meta(files["native.original.json"],observer.nativeText),"native whole identity");
 need(n.path===t.path&&n.version===t.version&&n.size===t.bytes&&n.offset===131072&&n.next_offset===196608&&n.eof===false,"original BODY2 exact bounds");
 const chunk=unb64(n.data_base64);
 need(chunk.length===65536&&sha256Latin1(byteString(chunk))===n.chunk_sha256&&n.chunk_sha256==="e555738cebe004b499e9bd6cf256865322ae0a98c28a847e82ce4122496392cd","actual 65536 byte chunk SHA");
 need(same(range,state.originalBodyRange)&&range.offset===131072&&range.limit===65536&&range.next===196608&&range.base64===n.data_base64&&range.chunkSHA256===n.chunk_sha256&&range.originalOperation===id&&same(range.originalPayload,observer.payload)&&range.originalPayloadTree===observer.payloadTree,"explicit range carries original source");
 need(go.handback_authorized===false&&go.maximum_operation_start_calls===0&&go.maximum_process_start_calls===0,"scope excludes handback and new admission");
 return {schema:"heptabao.original-body02-recovery-verification.r1",pass:true,check_count:checks.length,checks,counts:{new_status:statusCount,old_failed_status:1,total_status_for_original_id:2,pages:pageCount,original_binary_admissions:1,recovery_binary_admissions:0,original_payload_bytes:87807,chunk_bytes:65536},full_report_parsed:false,handback_performed:false,old_status_delivery_unknown_preserved:true};
}
