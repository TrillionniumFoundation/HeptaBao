function verifyRemainingThreeActual(f,h) {
 const checks=[];
 function need(ok,label,detail){checks.push({label,pass:!!ok,...(detail===undefined?{}:{detail})});if(!ok)throw Error(label);}
 const j=k=>JSON.parse(f[k]),meta=k=>h.gitBlobMeta(f[k]);
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const nativeText=sdk=>{need(sdk.isError!==true,"SDK_isError_false");const xs=(sdk.content||[]).filter(x=>x.type==="text");need(xs.length===1&&typeof xs[0].text==="string","SDK_single_original_text");return xs[0].text;};
 const s=j("current.state.final.public.json"),rows=j("CALL-INDEX.public.json"),go=j("ROOT-GO.public.json"),release=j("RELEASE.public.json");
 need(go.authorization==="GO"&&go.scope==="controls_remaining_three_binary_reads_only","exact_GO_scope");
 need(meta("ROOT-GO.public.json").blob==="680a66d85ec0b8aa808ca4e484934e36df8db5f5"&&same(meta("ROOT-GO.public.json"),s.goPin),"exact_GO_whole_pin");
 need(meta("remaining3.journal.original.js").blob==="54d5a34812a42362900256bb85de60c3efac2563","exact_journal_pin");
 need(s.pending===null&&s.activeObserver===null&&s.nativeCallInFlight===false&&s.paused===false,"current_context_closed");
 need(rows.length===13&&Object.keys(s.calls).length===13,"13_original_calls");
 need(rows.filter(x=>x.kind==="operation_start").length===3&&rows.filter(x=>x.kind==="operation_status").length===3&&rows.filter(x=>x.kind==="operation_result").length===7,"3_admissions_3_status_7_pages");
 need(s.completedObservers.length===3&&s.inheritedClosedObservers.length===1&&s.publishedBodies.length===4,"3_new_1_inherited");
 for(let i=0;i<2;i++){
  const x=s.historicalContexts[i];
  need(same(meta("historical"+i+".state.original.json"),x.state),"historical_context_whole_unchanged_"+i);
 }
 const old=j("historical0.state.original.json"),prior=j("historical1.state.original.json");
 need(old.paused===true&&old.activeObserver===null&&old.publishedBodies.length===0&&old.publishedBodyStarted[0]===true,"original_lost_ACK_state_retained");
 need(prior.pending===null&&prior.activeObserver===null&&prior.nativeCallInFlight===false,"predecessor_context_closed");
 need(meta("body0.root-qualification.public.json").blob==="eb9fca7b2e01729066ddbb14e05699d901a7520c"&&j("body0.root-qualification.public.json").pass===true,"predecessor_root_qualification_exact");
 need(meta("body0.inherited.actual.py").blob==="f8b36c8adccb493dfc6aa507856150ce8a6a764d"&&s.publishedBodies[0].inherited===true,"body0_is_inherited_no_repeat");
 for(const row of rows){
  const c=s.calls[row.key],q=j(row.files.request),intent=j(row.files.intent),arm=j(row.files.armed);
  need(c?.phase==="accepted"&&c.called===true&&c.sdkArchive?.whole===true&&c.armed?.whole===true,"accepted_and_whole_"+row.ordinal);
  need(same(meta(row.files.request),c.requestPin)&&same(c.requestPin,row.request)&&c.requestRaw===f[row.files.request],"exact_typed_request_"+row.ordinal);
  need(intent.callKey===row.key&&arm.callKey===row.key&&intent.kind===c.kind&&arm.kind===c.kind&&same(intent.request,c.requestPin)&&same(arm.request,c.requestPin),"intent_arm_bind_"+row.ordinal);
  need(same(intent.rootGo,s.goPin)&&same(arm.rootGo,s.goPin)&&intent.maximumNativeCalls===1&&arm.nativeNotYetCalled===true&&arm.mayHaveDispatchedAfterThisCheckpoint===true,"one_call_original_arm_"+row.ordinal);
  need(c.armed.entries.length===3&&c.armed.entries.every(x=>{const k=x.path==="request.json"?"request":x.path==="intent.json"?"intent":x.path==="armed.json"?"armed":null;return k!==null&&same(h.gitBlobMeta(f[row.files[k]]),{blob:x.blob,bytes:x.bytes,sha256:x.sha256});}),"three_arm_files_exact_"+row.ordinal);
  need(same(meta(row.files.sdk),c.sdkPin)&&same(meta(row.files.native),c.nativePin),"SDK_native_whole_pin_"+row.ordinal);
  need(nativeText(j(row.files.sdk))===f[row.files.native],"SDK_original_native_text_"+row.ordinal);
  if(c.kind!=="operation_start")need(typeof q.operation_id==="string","observer_ID_present_"+row.ordinal);
 }
 let bodyBytes=0,payloadBytes=0,pages=0;
 for(let i=1;i<=3;i++){
  const stem="jwt-pki-025b-remaining3-r1-body"+i+"-",ad=rows.find(x=>x.key===stem+"admit"),st=rows.find(x=>x.key===stem+"status0");
  const req=j(ad.files.request),ack=j(ad.files.native),status=j(st.files.native),closed=s.completedObservers[i-1],body=s.publishedBodies[i],info=s.publishedInfos[i];
  need(req.operation.tool==="binary_read"&&req.operation.arguments.host==="rog"&&req.operation.arguments.path===info.path&&req.operation.arguments.expected_version===info.version&&req.operation.arguments.offset===0&&req.operation.arguments.limit===info.size,"body_original_request_"+i);
  need(same(meta(ad.files.request),go.exact_requests[i-1]),"GO_exact_body_request_"+i);
  need(ack.operation_id===closed.id&&ack.tool_name==="binary_read"&&ack.reused===false,"actual_admission_"+i);
  need(status.operation_id===closed.id&&status.async_state==="completed"&&status.result_state==="stored_observed"&&status.owned_future_active===false&&status.payload_available===true,"native_closed_"+i);
  const ps=rows.filter(x=>x.key.startsWith(stem+"page"));let next=0,all=[],total=null,digest=null;
  for(let n=0;n<ps.length;n++){
   const row=ps[n],rq=j(row.files.request),v=j(row.files.native),chunk=h.unb64(v.data_base64);
   need(rq.operation_id===closed.id&&rq.offset===next&&rq.limit===16384&&v.operation_id===closed.id&&v.offset===next,"contiguous_original_page_"+i+"_"+n);
   need(v.immutable_snapshot===true&&v.payload_kind==="native_result"&&v.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization","immutable_original_payload_"+i+"_"+n);
   need(chunk.length<=16384&&v.next_offset===next+chunk.length&&v.total_bytes<=1048576&&v.eof===(v.next_offset===v.total_bytes),"page_range_EOF_"+i+"_"+n);
   if(total===null){total=v.total_bytes;digest=v.result_sha256;}need(v.total_bytes===total&&v.result_sha256===digest,"page_whole_identity_"+i+"_"+n);
   all.push(...chunk);next=v.next_offset;pages++;
  }
  const payload=h.utf8Text(all),actualPayload=f["body"+i+".payload.original.json"];
  need(next===total&&payload===actualPayload&&same(h.gitBlobMeta(payload),closed.payload)&&h.gitBlobMeta(payload).sha256===digest,"whole_payload_rebuilt_"+i);
  const envelope=JSON.parse(payload);need(envelope.resultType==="complete"&&envelope.isError!==true&&nativeText(envelope)===f["body"+i+".native.original.json"],"original_payload_native_"+i);
  need(same(meta("body"+i+".native.original.json"),closed.nativeText)&&closed.completedInactive===true&&closed.pages===ps.length,"original_closure_"+i);
  const v=j("body"+i+".native.original.json"),raw=h.utf8Text(h.unb64(v.data_base64)),b=h.gitBlobMeta(raw);
  need(raw===f["body"+i+".actual.txt"]&&same(b,body.body),"actual_full_body_"+i);
  need(v.path===req.operation.arguments.path&&v.version===info.version&&v.offset===0&&v.next_offset===info.size&&v.size===info.size&&v.eof===true&&v.chunk_sha256===b.sha256,"actual_body_version_SHA_EOF_"+i);
  need(body.originalOperation===closed.id&&body.metadataOperation===info.originalOperation&&body.path===info.path&&body.version===info.version&&b.bytes===info.size&&b.sha256===info.sha256,"independent_INFO_to_body_"+i);
  bodyBytes+=b.bytes;payloadBytes+=total;
 }
 need(bodyBytes===60208&&pages===7&&payloadBytes===81560,"exact_remaining_totals");
 for(let i=0;i<4;i++){
  const info=s.publishedInfos[i],v=h.parseLosslessIntegers(f["info"+i+".native.original.json"]),a=v.version.split(":");
  need(v.path===info.path&&v.version===info.version&&v.size===info.size&&v.sha256===info.sha256,"actual_INFO_fixed_"+i);
  need(v.mode===384&&v.metadata.mode===384&&v.metadata.uid===1000&&v.metadata.gid===1000&&v.metadata.link_count===1,"actual_INFO_safe_metadata_"+i);
  need(same(info.full9Strings,[a[0],a[1],"1000","1000","33152","1",String(v.size),a[3],a[4]]),"actual_INFO_lossless_full9_"+i);
 }
 const receipt=h.parseLosslessIntegers(f["body3.actual.txt"]),groups=j("body2.actual.txt");
 need(receipt.status==="prepared"&&receipt.python_compile_only===true&&receipt.stdin_bytes===118531&&receipt.stdin_sha256==="712b5ce14c6920fa35935109be44d1ca027a8d02259fbf172b783efa8ec6c08d","actual_receipt");
 const ints=xs=>xs.map(x=>Number.isSafeInteger(x)?String(x):x.$exactInteger);
 need(receipt.files.length===3&&receipt.files.every((x,i)=>x.path===s.publishedInfos[i].path&&x.bytes===s.publishedInfos[i].size&&x.sha256===s.publishedInfos[i].sha256&&same(ints(x.identity),s.publishedInfos[i].full9Strings)),"receipt_independent_full9_lossless");
 need(new Set(groups.flatMap(x=>x.tests)).size===149&&groups.reduce((n,x)=>n+x.tests.length,0)===166,"original_149_166_not_executed");
 need(release.callCount===13&&release.returnedObservers===3&&release.pages===7&&release.newBodyBytes===60208&&release.activeNativeFutures===0&&release.toolCallsInFlight===0&&release.buildSubmitted===false,"release_consistent");
 return {schema:"heptabao.remaining-three-actual-original-chain-check.v1",pass:true,checks,count:checks.length,originalCalls:13,newObservers:3,inheritedBody0Observers:1,pages,bodyBytes,payloadBytes,originalLostACKRetained:true,historicalContextsUnchanged:true,Runtime:0,productCasesExecuted:0};
}