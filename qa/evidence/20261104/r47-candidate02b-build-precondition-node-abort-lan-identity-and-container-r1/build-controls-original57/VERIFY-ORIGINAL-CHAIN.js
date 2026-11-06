function verifyControlsInertOriginalChain(texts) {
 const checks=[];function ck(n,v){checks.push({name:n,pass:!!v});if(!v)throw Error(n);}
 const inp=JSON.parse(texts["INPUTS.public.json"]),state=JSON.parse(texts["STATE.original.json"]),go=JSON.parse(texts["GO.original.json"]);
 function same(a,b){return JSON.stringify(a)===JSON.stringify(b);}
 function match(raw,p){const a=gitBlobMeta(raw);return a.blob===p.blob&&a.bytes===p.bytes&&a.sha256===p.sha256;}
 function native(raw){const v=JSON.parse(raw);ck("sdk_success_"+checks.length,v.isError===false&&v.content.length===1&&v.content[0].type==="text");return v.content[0].text;}
 ck("exact_closed_counts",inp.calls.length===7&&state.completedObservers.length===2&&state.completedObservers.every(o=>o.completedInactive===true&&o.pages===1));
 ck("no_active_call_future",state.pending===null&&state.activeObserver===null&&state.nativeCallInFlight===false&&state.paused===false);
 ck("fixed_original_job",inp.job==="1a1b247b510-fc05-7d4e"&&state.job===inp.job);
 ck("root_GO_whole",match(texts["GO.original.json"],inp.GO)&&go.authorization==="GO");
 ck("request_whole",match(texts["request.exact.json"],inp.exactRequest));
 const q=JSON.parse(texts["request.exact.json"]),binding=processStartBinding(q);
 ck("typed_identity",binding.sha256===go.digest&&binding.native_fingerprint===go.fingerprint);
 for(let i=0;i<inp.calls.length;i++){
  const row=inp.calls[i],c=state.calls[row.key],paths=row.paths;
  ck("five_original_pins_"+i,Object.entries(paths).every(([role,path])=>typeof texts[path]==="string"&&match(texts[path],row.pins[role])));
  ck("once_accepted_archived_"+i,c.called===true&&c.phase==="accepted"&&c.armed.whole===true&&c.sdkArchive.whole===true&&c.armed.tree===row.armTree&&c.sdkArchive.tree===row.sdkTree);
  const intent=JSON.parse(texts[paths.intent]),arm=JSON.parse(texts[paths.armed]),r=JSON.parse(texts[paths.request]);
  ck("exact_intent_arm_"+i,intent.callKey===row.key&&arm.callKey===row.key&&intent.maximumNativeCalls===1&&arm.maximumNativeCalls===1&&intent.nativeNotYetCalled===true&&arm.mayHaveDispatchedAfterThisCheckpoint===true&&same(intent.request,row.pins.request)&&same(intent.rootGo,inp.GO)&&same(arm.request,intent.request)&&same(arm.rootGo,intent.rootGo));
  ck("raw_sdk_to_native_"+i,native(texts[paths.sdk])===texts[paths.native]);
  ck("state_exact_raw_request_"+i,c.requestRaw===texts[paths.request]&&same(c.requestPin,row.pins.request)&&same(c.sdkPin,row.pins.sdk)&&same(c.nativePin,row.pins.native));
  const n=parseLosslessIntegers(texts[paths.native]);
  if(i===0){
   ck("single_START_exact",row.kind==="process_start"&&texts[paths.request]===texts["request.exact.json"]);
   ck("ACK_original",n.reused===false&&n.job.id===inp.job&&n.job.request_digest===binding.sha256&&n.job.request_fingerprint.$exactInteger===binding.native_fingerprint&&n.job.launch_error===null&&n.launch.ok===true);
  }else{
   const o=inp.observers[i<=3?0:1],part=(i-1)%3;
   ck("same_original_operation_"+i,n.operation_id===o.id);
   if(part===0)ck("admit_original_job_"+i,row.kind==="operation_start"&&r.operation.arguments.job_id===inp.job&&r.operation.arguments.host==="rog"&&r.operation.tool===o.tool&&n.tool_name===o.tool&&n.reused===false);
   if(part===1)ck("completed_inactive_"+i,row.kind==="operation_status"&&same(r,{operation_id:o.id})&&n.async_state==="completed"&&n.result_state==="stored_observed"&&n.owned_future_active===false&&n.payload_available===true);
   if(part===2){
    const name=i<=3?"authority":"streams",payload=texts[name+".payload.original.json"];
    ck("one_original_page_"+i,row.kind==="operation_result"&&same(r,{operation_id:o.id,offset:0,limit:8192})&&n.offset===0&&n.eof===true&&n.immutable_snapshot===true&&n.payload_kind==="native_result");
    ck("whole_original_payload_"+i,utf8Text(unb64(n.data_base64))===payload&&n.next_offset===n.total_bytes&&match(payload,o.payload)&&n.result_sha256===o.payload.sha256);
    ck("payload_native_"+i,native(payload)===texts[name+".native.original.json"]&&match(texts[name+".native.original.json"],o.nativeText));
   }
  }
 }
 const authority=parseLosslessIntegers(texts["authority.native.original.json"]),streams=parseLosslessIntegers(texts["streams.native.original.json"]);
 ck("authority_terminal_zero",authority.job_id===inp.job&&authority.state==="succeeded"&&authority.exit_code===0&&!authority.timed_out&&!authority.cancelled&&authority.output_complete&&authority.output_durable&&authority.terminal_publication_confirmed);
 for(const name of ["stdout","stderr"]){const r=streams[name],raw=texts[name+".original.txt"],b=utf8Bytes(raw);ck("whole_"+name,r.offset===0&&r.next_offset===b.length&&r.size===b.length&&r.eof===true&&r.text===raw&&r.bytes_hex===b.map(x=>x.toString(16).padStart(2,"0")).join("")&&authority.log_bytes[name].stored===b.length&&authority.log_bytes[name].seen===b.length&&authority.log_synced[name]===true&&authority.log_truncated[name]===false&&authority.log_errors[name]===null);}
 ck("stdout_whole",match(texts["stdout.original.txt"],inp.stdout)&&inp.stdout.bytes===1408&&texts["stderr.original.txt"]==="");
 const pub=parseLosslessIntegers(texts["stdout.original.txt"]);
 ck("publication_prepared_only",pub.status==="prepared"&&pub.python_compile_only===true&&["source_executed","git_started","compiler_started","service_started","artifact_transfer_started"].every(k=>pub[k]===false));
 ck("exact_three_created",pub.files.length===3&&pub.files.every(f=>{const name=f.path.slice(go.control_root.length+1),pin=go.expected_files[name];return pin&&f.path===go.control_root+"/"+name&&f.bytes===pin.bytes&&f.sha256===pin.sha256&&f.publication==="created"&&same(f.identity.slice(2,6),[1000,1000,33152,1])&&f.identity[6]===f.bytes;}));
 ck("exact_stdin",pub.stdin_bytes===go.payload.bytes&&pub.stdin_sha256===go.payload.sha256);
 ck("independent_readback_not_claimed",inp.independentNativeControlsMetadata===false&&inp.independentNativeControlsBody===false&&inp.buildQualified===false);
 return {schema:"heptabao.combined02b90762.controls-inert-original-chain-verification.r1",ok:true,checks:checks.length,results:checks,calls:7,observers:2,pages:2,pureV8:true,NativeCalls:0,buildQualified:false};
}
