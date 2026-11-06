function verifyOriginalRuntimeEvidence(input){
 const checks=[];
 const ck=(name,ok)=>checks.push({name,pass:ok===true});
 const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const meta=(raw,pin)=>{const x=gitBlobMeta(raw);return x.blob===pin.blob&&x.bytes===pin.bytes&&x.sha256===pin.sha256;};
 const s=input.state, terminal=parseLosslessIntegers(input.authorityRaw);
 ck("known_original_job",s.job==="1a1b1d28dc2-fc05-7afe");
 ck("journal_closed",s.pending===null&&s.activeObserver===null&&!s.nativeCallInFlight&&!s.paused);
 ck("88_original_calls",Object.keys(s.calls).length===88);
 ck("14_returned_observers",s.completedObservers.length===14);
 let nativeCalls={process_start:0,operation_start:0,operation_status:0,operation_result:0};
 const values={}, admissions=new Map(), pageRows=new Map(), statusRows=new Map();
 for(const [key,c] of Object.entries(s.calls)){
  const x=input.calls[key];nativeCalls[c.kind]++;
  ck(key+":accepted_once",c.called===true&&c.phase==="accepted");
  ck(key+":external_armed",c.armed?.whole===true);
  ck(key+":external_SDK",c.sdkArchive?.whole===true);
  ck(key+":request",meta(x.requestRaw,c.requestPin)&&x.requestRaw===c.requestRaw);
  ck(key+":SDK",meta(x.sdkRaw,c.sdkPin));
  ck(key+":native",meta(x.nativeRaw,c.nativePin));
  const sdk=JSON.parse(x.sdkRaw), v=parseLosslessIntegers(x.nativeRaw), q=JSON.parse(x.requestRaw);
  ck(key+":SDK_native_exact",sdk.isError!==true&&sdk.content?.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===x.nativeRaw);
  const intent=JSON.parse(x.intentRaw),armed=JSON.parse(x.armedRaw);
  ck(key+":intent_binding",intent.callKey===key&&intent.kind===c.kind&&eq(intent.request,c.requestPin)&&intent.maximumNativeCalls===1&&intent.nativeNotYetCalled===true);
  ck(key+":armed_binding",armed.callKey===key&&eq(armed.request,c.requestPin)&&armed.mayHaveDispatchedAfterThisCheckpoint===true);
  values[key]=v;
  if(c.kind==="process_start"){
   ck("original_start_binding",v.job.id===s.job&&v.reused===false&&v.launch.ok===true&&v.job.request_digest==="94425f4f50b9a0f0ea1b1fb5c2b23972fb50582f8b026f191e611ca64ea9e74e"&&v.job.request_fingerprint.$exactInteger==="10683206060337635568");
   ck("frozen_exact_request",c.requestPin.blob==="4d945e65cbee59c0df29b136abc8266be77ffa7e");
  }else if(c.kind==="operation_start"){
   ck(key+":same_job",q.operation.arguments.host==="mac"&&q.operation.arguments.job_id===s.job);
   ck(key+":original_admission",v.reused===false&&v.automatic_retry===false&&v.tool_name===q.operation.tool);
   ck(key+":unique_ID",!admissions.has(v.operation_id));
   admissions.set(v.operation_id,{key,query:q,value:v});
  }else if(c.kind==="operation_status"){
   ck(key+":same_operation",v.operation_id===q.operation_id&&v.automatic_retry===false);
   ck(key+":closed_status",v.async_state==="completed"&&v.owned_future_active===false&&v.result_state==="stored_observed"&&v.payload_available===true);
   const a=statusRows.get(q.operation_id)||[];a.push({key,query:q,value:v});statusRows.set(q.operation_id,a);
  }else{
   const b=unb64(v.data_base64);
   ck(key+":page_identity",v.operation_id===q.operation_id&&v.offset===q.offset&&v.immutable_snapshot===true&&v.payload_kind==="native_result");
   const width=s.completedObservers.find(o=>o.id===q.operation_id)?.pageLimit||8192;
   ck(key+":page_limits",[8192,16384].includes(width)&&q.limit===width&&b.length<=width&&v.total_bytes<=1048576);
   ck(key+":page_extent",v.next_offset===v.offset+b.length&&v.eof===(v.next_offset===v.total_bytes));
   const a=pageRows.get(q.operation_id)||[];a.push({key,query:q,value:v,bytes:b});pageRows.set(q.operation_id,a);
  }
 }
 ck("one_business_start",nativeCalls.process_start===1);
 ck("fourteen_observer_admissions",nativeCalls.operation_start===14);
 ck("fourteen_observer_status_calls",nativeCalls.operation_status===14);
 ck("fiftynine_immutable_pages",nativeCalls.operation_result===59);
 let stdout="",stderr="",outOffset=0,errOffset=0,statusObservers=0,readObservers=0;
 for(const o of s.completedObservers){
  const ad=admissions.get(o.id),statuses=statusRows.get(o.id)||[],pages=(pageRows.get(o.id)||[]).sort((a,b)=>a.value.offset-b.value.offset);
  ck(o.id+":admission_tool",ad?.value.tool_name===o.tool);
  ck(o.id+":status_bound",statuses.length>=1&&statuses.length<=8&&statuses.every(x=>x.value.tool_name===o.tool));
  ck(o.id+":completed",o.completedInactive===true);
  ck(o.id+":pages",pages.length===o.pages);
  let bytes=[],offset=0,total=null,digest=null;
  for(const p of pages){ck(p.key+":continuous",p.value.offset===offset);bytes.push(...p.bytes);offset=p.value.next_offset;if(total===null){total=p.value.total_bytes;digest=p.value.result_sha256;}ck(p.key+":stable_payload",p.value.total_bytes===total&&p.value.result_sha256===digest);}
  const payloadRaw=utf8Text(bytes), x=input.payloads[o.id],payload=parseLosslessIntegers(payloadRaw);
  ck(o.id+":whole_payload",offset===total&&pages.at(-1).value.eof===true&&payloadRaw===x.payloadRaw&&meta(payloadRaw,o.payload)&&gitBlobMeta(payloadRaw).sha256===digest);
  ck(o.id+":original_native_envelope",payload.resultType==="complete"&&payload.isError===false&&payload.content?.length===1&&payload.content[0].type==="text"&&payload.content[0].text===x.nativeRaw);
  ck(o.id+":native_whole",meta(x.nativeRaw,o.nativeText));
  const v=parseLosslessIntegers(x.nativeRaw);ck(o.id+":native_job",v.job_id===s.job);
  if(o.tool==="process_status"){statusObservers++;ck(o.id+":authority_exact",x.nativeRaw===input.authorityRaw);}
  else{
   readObservers++;
   for(const name of ["stdout","stderr"]){
    const row=v[name],asked=ad.query.operation.arguments[name+"_offset"],bb=[];
    for(let i=0;i<row.bytes_hex.length;i+=2)bb.push(parseInt(row.bytes_hex.slice(i,i+2),16));
    ck(o.id+":"+name+":hex_text",utf8Text(bb)===row.text&&row.bytes_hex.length===bb.length*2);
    ck(o.id+":"+name+":source_extent",row.offset===asked&&bb.length<=16384&&row.next_offset===row.offset+bb.length&&row.size===terminal.log_bytes[name].stored);
    ck(o.id+":"+name+":contiguous",row.offset===(name==="stdout"?outOffset:errOffset));
    if(name==="stdout"){stdout+=row.text;outOffset=row.next_offset;}else{stderr+=row.text;errOffset=row.next_offset;}
    ck(o.id+":"+name+":EOF",row.eof===(row.next_offset===row.size));
   }
  }
 }
 ck("observer_count_caps",statusObservers===1&&statusObservers<=64&&readObservers===13&&readObservers<=129);
 ck("full_streams_exact",stdout===input.stdoutRaw&&stderr===input.stderrRaw&&outOffset===211872&&errOffset===0);
 ck("authority_full_failed_original",terminal.state==="failed"&&terminal.exit_code===1&&terminal.output_complete===true&&terminal.output_durable===true&&terminal.terminal_publication_confirmed===true&&terminal.timed_out===false);
 ck("authority_no_log_loss",terminal.log_bytes.stdout.seen===211872&&terminal.log_bytes.stdout.stored===211872&&terminal.log_bytes.stderr.seen===0&&terminal.log_bytes.stderr.stored===0&&!terminal.log_truncated.stdout&&!terminal.log_truncated.stderr&&terminal.log_synced.stdout&&terminal.log_synced.stderr);
 const r=JSON.parse(stdout);
 ck("failure_preserved",r.ok===false&&r.outcomeUnknown===true&&r.errorType==="ObservationRefused"&&r.errorCode===null);
 ck("managed_scope_not_closed",r.manager.allRegistrationsClosed===false&&r.manager.allKnownLineagesClosed===false);
 ck("helper_unknown_preserved",r.ownedCommands.commands.length===34&&r.ownedCommands.allOwnedCommandsStopped===false&&r.ownedCommands.unknownCommandCount===2);
 ck("before_capture_only",r.captureReports.length===1&&r.captureReports[0].stage==="before"&&r.captureReports[0].report.ok===true&&r.ownedPhases.length===0);
 ck("FD_closures",r.allReturnedHomeControlDescriptorsClosed===true&&r.homeControlFinal.effectUnknown===false&&r.heldT5Final.allDescriptorsClosed===true&&r.outerDescriptorClosure.allOuterReadDescriptorsClosed===true&&r.manager.allManagerReadDescriptorsClosed===true);
 ck("original_deadline",r.originalOuterDeadlineMetAfterAllClosure===true&&r.elapsedSeconds<900);

 const prior=parseLosslessIntegers(input.deliveryPriorRaw);
 ck("delivery_prior_pin",gitBlobMeta(input.deliveryPriorRaw).blob==="f3ee8a7deed5183685c0b2c5701b242b5c795bce");
 ck("delivery_prior_closed_3_observers",prior.job===s.job&&prior.activeObserver===null&&prior.pending===null&&!prior.nativeCallInFlight&&!prior.paused&&prior.nextStdout===32768&&prior.completedObservers.length===3);
 ck("delivery_prior_calls_unmodified",Object.keys(prior.calls).length===22&&Object.entries(prior.calls).every(([k,c])=>eq(c,s.calls[k])));
 ck("delivery_prior_observers_unmodified",prior.completedObservers.every((o,i)=>eq(o,s.completedObservers[i])));
 ck("delivery_old_page_widths",s.completedObservers.slice(0,3).every(o=>o.pageLimit===undefined)&&s.completedObservers.slice(0,3).reduce((n,o)=>n+o.pages,0)===15);
 ck("delivery_new_page_widths",s.completedObservers.slice(3).length===11&&s.completedObservers.slice(3).every(o=>o.tool==="process_read"&&o.pageLimit===16384&&o.pages<=64)&&s.completedObservers.slice(3).reduce((n,o)=>n+o.pages,0)===44);
 ck("delivery_GO_exact",gitBlobMeta(input.deliveryGoRaw).blob==="c7ee949925513a39007bae15b89cf8e230bb6de6");
 ck("original_journal_preserved",gitBlobMeta(input.originalJournalRaw).blob==="356a543a19cc95ce6df4a88406cfc7950d154066");
 ck("approved_delivery_journal_exact",gitBlobMeta(input.deliveryJournalRaw).blob==="c2274b5979ecc8d73f95c27fdfb004339ca133db");
 ck("actual_failure_frames",eq(r.errorFrames,[{file:"mac_current_outer_wal_r1.py",line:1064},{file:"mac_owned_launchd_r3.py",line:787},{file:"mac_native_process_observer_r1.py",line:66},{file:"mac_native_process_observer_r1.py",line:31}]));
 ck("actual_server_exec_and_consumer_admission_only",r.manager.completedOperationCount===1&&r.manager.events.some(e=>e.kind==="actual-server-exec"&&e.generation==="server-initial")&&r.manager.events.some(e=>e.kind==="actual-wrapper-admitted"&&e.generation==="initial")&&r.ownedPhases.length===0);
 ck("no_credential_or_provider_export",r.credentialValuesPublished===false&&r.j3160Contacted===false&&r.providerRequested===false&&r.productionChangedByController===false&&r.productionServiceOperationDispatched===false);
 return {schema:"heptabao.authbus-home-r3-original-evidence-pure-verification.r1",passed:checks.every(x=>x.pass),checkCount:checks.length,checks,nativeCalls,statusObservers,readObservers,stdoutBytes:gitBlobMeta(stdout).bytes,stderrBytes:gitBlobMeta(stderr).bytes,scope:"original_evidence_chain_and_known_failure_only",productSuccess:false,managedScopeQualifiedClosed:false,newNativeCalls:0};
}