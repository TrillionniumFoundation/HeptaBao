function verifyCombinedStageOriginal7(t,h) {
 const results=[];function check(v,n){results.push({name:n,pass:!!v});if(!v)throw Error(n);}
 const index=JSON.parse(t["CHAIN-INDEX.public.json"]),state=JSON.parse(t["STATE.original.json"]),go=JSON.parse(t["GO.original.json"]);
 const parse=h.parse;
 check(index.calls.length===7&&index.observers.length===2&&new Set(index.calls.map(x=>x.callKey)).size===7,"finite_seven_calls_two_observers");
 check(state.job===index.job&&index.job==="1a1b21f5945-fc05-7c77"&&!state.paused&&state.pending===null&&state.activeObserver===null&&!state.nativeCallInFlight,"released_original_state");
 check(JSON.stringify(index.calls.map(x=>x.kind))===JSON.stringify(["process_start","operation_start","operation_status","operation_result","operation_start","operation_status","operation_result"]),"exact_call_kinds_in_order");
 const values=[];
 for(const row of index.calls){
  const raw=t[row.paths.request],sdkRaw=t[row.paths.sdk],nativeRaw=t[row.paths.native];
  check(h.meta(raw).blob===row.request.blob&&h.meta(raw).bytes===row.request.bytes&&h.meta(raw).sha256===row.request.sha256,"request_pin:"+row.callKey);
  check(h.meta(sdkRaw).blob===row.sdk.blob&&h.meta(sdkRaw).sha256===row.sdk.sha256,"SDK_pin:"+row.callKey);
  check(h.meta(nativeRaw).blob===row.native.blob&&h.meta(nativeRaw).sha256===row.native.sha256,"native_pin:"+row.callKey);
  const sdk=JSON.parse(sdkRaw),intent=JSON.parse(t[row.paths.intent]),arm=JSON.parse(t[row.paths.armed]);
  check(sdk.isError!==true&&sdk.content?.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===nativeRaw,"SDK_exact_native_parent:"+row.callKey);
  check(intent.callKey===row.callKey&&intent.kind===row.kind&&intent.request.blob===row.request.blob&&intent.maximumNativeCalls===1&&intent.nativeNotYetCalled===true&&intent.rootGo.blob===h.meta(t["GO.original.json"]).blob,"exact_once_intent:"+row.callKey);
  check(arm.callKey===row.callKey&&arm.request.blob===row.request.blob&&arm.maximumNativeCalls===1&&arm.nativeNotYetCalled===true&&arm.mayHaveDispatchedAfterThisCheckpoint===true,"original_armed_checkpoint:"+row.callKey);
  check(row.called===true&&row.phase==="accepted"&&state.calls[row.callKey].phase==="accepted"&&state.calls[row.callKey].sdkArchive.whole===true&&state.calls[row.callKey].armed.whole===true,"SDK_whole_acceptance:"+row.callKey);
  values.push({q:JSON.parse(raw),v:parse(nativeRaw)});
 }
 const start=values[0],fp=start.v.job.request_fingerprint;
 check(h.meta(t[index.calls[0].paths.request]).blob===go.exactRequest.blob&&start.v.reused===false&&start.v.launch.ok===true&&start.v.local_record_pending===false,"unique_exact_START_ACK");
 check(start.v.job.id===index.job&&start.v.job.host==="rog"&&start.v.job.request_digest===go.native_binding.sha256&&(typeof fp==="object"?fp.$exactInteger:String(fp))===go.native_binding.native_fingerprint,"typed_ACK_binding");
 check(JSON.stringify(start.v.job.args)===JSON.stringify(start.q.args)&&start.v.job.idempotency_key===start.q.idempotency_key&&start.v.job.executable===start.q.executable&&start.v.job.cwd===start.q.cwd,"ACK_exact_source_argv");
 const native=[];
 for(let i=0;i<2;i++){
  const o=index.observers[i],a=values[1+3*i],s=values[2+3*i],p=values[3+3*i],tool=i===0?"process_status":"process_read";
  check(a.q.operation.tool===tool&&a.q.operation.arguments.host==="rog"&&a.q.operation.arguments.job_id===index.job&&a.v.operation_id===o.id&&a.v.tool_name===tool&&!a.v.reused&&!a.v.automatic_retry,"observer_original_admission:"+i);
  check(s.q.operation_id===o.id&&s.v.operation_id===o.id&&s.v.tool_name===tool&&s.v.async_state==="completed"&&s.v.result_state==="stored_observed"&&s.v.owned_future_active===false&&s.v.payload_available===true,"observer_completed_inactive:"+i);
  check(p.q.operation_id===o.id&&p.q.offset===0&&p.q.limit===8192&&p.v.operation_id===o.id&&p.v.offset===0&&p.v.immutable_snapshot===true&&p.v.eof===true,"one_original_immutable_page:"+i);
  const b=h.unb64(p.v.data_base64),payload=t[o.paths.payload],pin=h.meta(payload);
  check(h.utf8Text(b)===payload&&b.length===p.v.total_bytes&&p.v.next_offset===b.length&&b.length<=8192&&pin.sha256===p.v.result_sha256&&pin.blob===o.payload.blob,"payload_full_SHA_EOF:"+i);
  const obj=parse(payload),nr=t[o.paths.native];
  check(obj.resultType==="complete"&&obj.isError===false&&obj.content.length===1&&obj.content[0].text===nr&&h.meta(nr).blob===o.nativeText.blob,"payload_exact_native_parent:"+i);
  const v=parse(nr);check(v.job_id===index.job&&o.completedInactive===true&&o.pages===1,"observer_job_closure:"+i);native.push(v);
 }
 const authority=native[0],stream=native[1];
 check(authority.state==="succeeded"&&authority.exit_code===0&&authority.output_complete===true&&authority.output_durable===true&&authority.terminal_publication_confirmed===true&&!authority.cancelled&&!authority.timed_out&&!authority.automatic_retry,"actual_terminal_zero_full_durable");
 for(const n of ["stdout","stderr"]){
  const row=stream[n],raw=t[n+".original.txt"],pin=h.meta(raw),bytes=[];for(let i=0;i<row.bytes_hex.length;i+=2)bytes.push(parseInt(row.bytes_hex.slice(i,i+2),16));
  check(row.offset===0&&row.eof===true&&row.next_offset===row.size&&row.size===pin.bytes&&row.text===raw&&h.utf8Text(bytes)===raw,"whole_original_"+n);
  check(authority.log_bytes[n].seen===pin.bytes&&authority.log_bytes[n].stored===pin.bytes&&authority.log_synced[n]===true&&!authority.log_truncated[n]&&authority.log_errors[n]===null,"authority_stream_counters_"+n);
 }
 const out=JSON.parse(t["stdout.original.txt"]);
 check(h.meta(t["stdout.original.txt"]).bytes===350&&t["stderr.original.txt"]==="","actual_350_0");
 check(out.source_commit===go.candidateCommit&&out.source_tree===go.candidateTree&&out.result_path===go.freshRoot+"/control/stage-result.public.json"&&out.status==="prepared"&&out.all_owned_stopped===true&&out.within_new_stage_deadline===true&&!out.server_started&&!out.compiler_started,"public_summary_only");
 return{schema:"heptabao.combined02b90762-original-stage-chain-verification.r1",pass:true,checks:results.length,results,calls:7,observers:2,pages:2,NativeCallsForVerification:0,detailedReportRead:false,independent61ChildAndLeafQualification:false};
}