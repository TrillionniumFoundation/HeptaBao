function verifyCombinedStageBodyOriginalChain(texts) {
  const results=[];
  function ck(name,ok){results.push({name,pass:!!ok});if(!ok)throw Error("BODY original-chain verification: "+name);}
  function eq(a,b){return JSON.stringify(a)===JSON.stringify(b);}
  function get(path){ck("text_present_"+path,typeof texts[path]==="string");return texts[path];}
  function pin(path,want){const got=gitBlobMeta(get(path));ck("whole_"+path,got.blob===want.blob&&got.bytes===want.bytes&&got.sha256===want.sha256);return got;}
  function extract(raw,label){const sdk=JSON.parse(raw);ck("not_error_"+label,sdk.isError===false&&Array.isArray(sdk.content)&&sdk.content.length===1&&sdk.content[0].type==="text"&&typeof sdk.content[0].text==="string");return sdk.content[0].text;}
  const inputs=JSON.parse(get("INPUTS.public.json"));
  const op=inputs.operation.id;
  ck("single_fixed_original_operation",op==="d52d7e0b1bb0fe96b779284a22a9d7ed66b9507e3b232f2ec60a77b7d7b0c593");
  ck("exact_seven_original_calls",inputs.calls.length===7&&new Set(inputs.calls.map(x=>x.callKey)).size===7);
  pin("GO.original.json",inputs.GO);pin("request.exact.json",inputs.exactRequest);
  pin("body.payload.original.json",inputs.operation.payload);pin("body.native.original.json",inputs.operation.nativeText);
  pin("stage-result.public.json",inputs.bodyReport);pin("metadata.native.original.json",inputs.metadata);
  const state=JSON.parse(get("STATE.original.json")), release=JSON.parse(get("OWNER-RELEASE.public.json"));
  ck("state_no_pending",state.pending===null&&state.activeObserver===null&&state.nativeCallInFlight===false&&state.paused===false);
  ck("aggregate_17calls_4observers_8pages",Object.keys(state.calls).length===17&&state.completedObservers.length===4&&state.completedObservers.reduce((n,x)=>n+x.pages,0)===8&&state.completedObservers.every(x=>x.completedInactive===true));
  ck("release_no_active",release.nativeCallInFlight===false&&release.nativeFutureActive===false&&release.processActive===false&&release.originalFutureCompletedInactive===true);
  let offset=0,parts=[],total=null,digest=null;
  for(let i=0;i<inputs.calls.length;i++){
    const row=inputs.calls[i],k=row.callKey,c=state.calls[k];
    ck("accepted_once_"+i,c&&c.called===true&&c.phase==="accepted"&&c.armed.whole===true&&c.sdkArchive.whole===true);
    ck("archive_binding_"+i,c.armed.tree===row.armTree&&c.sdkArchive.tree===row.sdkTree);
    for(const [role,path]of Object.entries(row.paths))pin(path,row.pins[role]);
    const qRaw=get(row.paths.request),q=JSON.parse(qRaw),intent=JSON.parse(get(row.paths.intent)),arm=JSON.parse(get(row.paths.armed));
    ck("original_request_exact_"+i,qRaw===c.requestRaw&&eq(row.pins.request,c.requestPin));
    ck("intent_once_"+i,intent.callKey===k&&intent.kind===row.kind&&intent.maximumNativeCalls===1&&intent.nativeNotYetCalled===true&&intent.lossOfAcknowledgmentNeverGrantsReplay===true&&eq(intent.request,row.pins.request)&&eq(intent.rootGo,inputs.GO));
    ck("armed_same_intent_"+i,arm.callKey===k&&arm.maximumNativeCalls===1&&arm.mayHaveDispatchedAfterThisCheckpoint===true&&eq(arm.request,intent.request)&&eq(arm.rootGo,intent.rootGo));
    const nRaw=extract(get(row.paths.sdk),"sdk"+i);
    ck("sdk_exact_native_"+i,nRaw===get(row.paths.native)&&eq(row.pins.sdk,c.sdkPin)&&eq(row.pins.native,c.nativePin));
    const n=parseLosslessIntegers(nRaw);
    ck("same_id_tool_"+i,n.operation_id===op);
    if(i===0){
      ck("admission_request_whole",qRaw===get("request.exact.json")&&row.kind==="operation_start"&&q.operation.tool==="binary_read");
      ck("admission_no_replay",n.reused===false&&n.tool_name==="binary_read"&&n.idempotency_binding_retained===true);
    } else if(i===1) {
      ck("status_request_exact",row.kind==="operation_status"&&eq(q,{operation_id:op}));
      ck("original_future_closed",n.async_state==="completed"&&n.result_state==="stored_observed"&&n.owned_future_active===false&&n.payload_available===true&&n.tool_name==="binary_read");
    } else {
      ck("page_request_exact_"+i,row.kind==="operation_result"&&eq(q,{operation_id:op,offset,limit:8192}));
      const b=unb64(n.data_base64);
      if(total===null){total=n.total_bytes;digest=n.result_sha256;}
      ck("page_immutable_"+i,n.immutable_snapshot===true&&n.payload_kind==="native_result"&&n.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization");
      ck("page_geometry_"+i,n.offset===offset&&n.next_offset===offset+b.length&&b.length<=8192&&n.total_bytes===total&&n.result_sha256===digest&&n.eof===(i===6));
      parts.push(b);offset=n.next_offset;
    }
  }
  ck("final_payload_geometry",offset===38063&&total===38063&&digest===inputs.operation.payload.sha256);
  const joined=new Uint8Array(offset);let cursor=0;for(const b of parts){joined.set(b,cursor);cursor+=b.length;}
  ck("payload_reconstruct_exact",utf8Text(joined)===get("body.payload.original.json"));
  const payload=JSON.parse(get("body.payload.original.json"));
  ck("payload_complete",payload.resultType==="complete"&&payload.isError===false);
  ck("payload_exact_native",extract(get("body.payload.original.json"),"payload")===get("body.native.original.json"));
  const body=parseLosslessIntegers(get("body.native.original.json")),info=parseLosslessIntegers(get("metadata.native.original.json")),q=JSON.parse(get("request.exact.json"));
  ck("metadata_actual_closed_identity",info.path===q.operation.arguments.path&&info.version===q.operation.arguments.expected_version&&info.size===28236&&info.mode===384&&info.metadata.uid===1000&&info.metadata.gid===1000&&info.metadata.link_count===1);
  ck("binary_actual_version_and_range",body.path===info.path&&body.version===info.version&&body.offset===0&&body.next_offset===info.size&&body.size===info.size&&body.eof===true&&body.chunk_sha256===info.sha256&&q.operation.arguments.limit===info.size);
  const decoded=unb64(body.data_base64);
  ck("whole_report_from_original_body",decoded.length===28236&&utf8Text(decoded)===get("stage-result.public.json")&&gitBlobMeta(get("stage-result.public.json")).sha256===info.sha256);
  ck("separate_stage_semantic_root",inputs.rootSemanticQualification.blob==="6a64e5fec589abfeec7a05660e6edaddc780bdaf");
  ck("no_new_business_claim",inputs.noNewNativeDuringPackaging===true&&inputs.sourceStageOnly===true&&inputs.buildQualified===false&&inputs.formatterRun===false&&inputs.bundleTransported===false);
  return {schema:"heptabao.combined02b90762.original-stage-body-verification.r1",ok:true,checks:results.length,results,originalCalls:7,originalObservers:1,immutablePayloadPages:5,aggregateCalls:17,aggregateObservers:4,aggregatePages:8,report:inputs.bodyReport,pureV8:true,NativeCalls:0,buildQualified:false};
}
