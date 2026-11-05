async function completeOne(p,s){
  const k=p+"body_"+s.id+"_";
  async function record(tag,r){
    store(k+tag+"_sdk_response",r);
    const sdk=await saveRaw(JSON.stringify(r,null,2)+"\n");store(k+tag+"_sdk_snapshot",sdk);
    const parts=r.content?.filter(x=>x.type==="text")||[];
    let native;
    if(parts.length===1){native=await saveRaw(parts[0].text);store(k+tag+"_native",native);}
    if(r.isError)throw Object.assign(new Error("MCP isError before parse"),{public_stage:tag,sdk_blob:sdk.blob,native_blob:native?.blob});
    if(parts.length!==1)throw Object.assign(new Error("Unexpected SDK text envelope"),{public_stage:tag,sdk_blob:sdk.blob});
    return JSON.parse(native.raw);
  }
  try{
    if(load(p+"body_admission_stopped"))throw Error("Admissions stopped");
    if(!load(k+"intent_external_completed"))throw Error("Intent not externally complete");
    if(!load(k+"start_attempted")){
      store(k+"start_attempted",true);
      const ack=await record("start",await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_start(s.request));
      store(k+"ack_external_before_parse",true);store(k+"ack",ack);
      if(!/^[0-9a-f]{64}$/.test(ack.operation_id)||ack.tool_name!=="binary_read"||ack.idempotency_binding_retained!==true)throw Error("ACK typed binding");
      store(k+"operation_id",ack.operation_id);
    }
    const operation_id=load(k+"operation_id");
    if(!operation_id)throw Error("Original start has no known operation id; do not replay");
    const n=load(k+"status_count")||0,stag="status_"+n,streq={operation_id};
    store(k+stag+"_request",await saveRaw(JSON.stringify(streq,null,2)+"\n"));
    const status=await record(stag,await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_status(streq));
    store(k+stag,status);store(k+"latest_status",status);store(k+"status_count",n+1);
    if(status.operation_id!==operation_id||status.tool_name!=="binary_read")throw Error("Status binding");
    if(status.async_state!=="completed"||status.owned_future_active!==false)return {sequence:s.sequence,pending:true,operation_id,status};
    if(status.result_state!=="stored_observed"||status.payload_available!==true)throw Error("Stored payload unavailable");
    let off=0,all="",page=0,total=null,hash=null;
    while(true){
      if(page>=64)throw Error("Original payload page cap");
      const req={operation_id,offset:off,limit:16384},tag="result_"+page;
      store(k+tag+"_request",await saveRaw(JSON.stringify(req,null,2)+"\n"));
      const value=await record(tag,await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_result(req));
      store(k+tag,value);store(k+"result_count",page+1);
      const part=dec(value.data_base64);store(k+"result_binary_"+page,part);
      if(value.operation_id!==operation_id||value.offset!==off||value.next_offset!==off+part.length||part.length>16384||value.immutable_snapshot!==true||value.payload_kind!=="native_result"||!Number.isSafeInteger(value.total_bytes)||value.total_bytes<1||value.total_bytes>1048576)throw Error("Immutable page binding");
      if(page===0){total=value.total_bytes;hash=value.result_sha256;}
      if(value.total_bytes!==total||value.result_sha256!==hash)throw Error("Immutable page changed");
      all+=part;off=value.next_offset;page++;
      if(value.eof===true){if(off!==total)throw Error("Premature EOF");break;}
      if(!part.length||off>=total)throw Error("Non-final page boundary");
    }
    if(all.length!==total||sha(all)!==hash)throw Error("Original SDK whole hash");
    const original=await saveRaw(decodeURIComponent(escape(all)));store(k+"original_sdk_payload",original);
    const ov=JSON.parse(original.raw);store(k+"original_sdk_parsed",ov);
    const parts=ov.content?.filter(x=>x.type==="text")||[];let native;
    if(parts.length===1){native=await saveRaw(parts[0].text);store(k+"original_native",native);}
    if(ov.isError)throw Object.assign(new Error("Original SDK isError before native parse"),{public_stage:"original_sdk",sdk_blob:original.blob,native_blob:native?.blob});
    if(parts.length!==1)throw Error("Original SDK text envelope");
    const v=JSON.parse(native.raw);store(k+"binary_result",v);
    const a=s.request.operation.arguments,expected=load(p+"body_steps")[s.sequence-1],b=dec(v.data_base64);
    if(v.path!==a.path||v.version!==a.expected_version||v.size!==expected.bytes||v.offset!==a.offset||v.next_offset!==a.offset+b.length||b.length!==a.limit||v.eof!==(v.next_offset===v.size)||sha(b)!==v.chunk_sha256)throw Error("Exact binary chunk binding");
    store(k+"binary_bytes",b);
    const proof=await saveRaw(JSON.stringify({schema:"heptabao.mac-harness-sdk-body-observation.v1",sequence:s.sequence,id:s.id,request_blob:s.blob,intent_blob:load(k+"intent").blob,ack_blob:load(k+"start_native").blob,operation_id,status_blob:load(k+stag+"_native").blob,original_sdk_blob:original.blob,original_native_blob:native.blob,actual_chunk_bytes:b.length,actual_chunk_sha256:sha(b),offset:v.offset,next_offset:v.next_offset,eof:v.eof,exact_path_version_size_offset_eof:true,operation_completed:true,owned_future_active:false,original_sdk_payload_pages:page,all_original_payload_pages_verified:true,sdk_executed:false,selected_owner_conclusion:false},null,2)+"\n");
    store(k+"observation_proof",proof);store(k+"known_complete",true);store(p+"completed_body_count",s.sequence);store(p+"active_body_sequence",null);
    return {sequence:s.sequence,known_complete:true,operation_id,original_payload_pages:page,chunk:{offset:v.offset,next_offset:v.next_offset,bytes:b.length,sha256:sha(b),eof:v.eof},original_sdk:original.blob,original_native:native.blob,observation:proof.blob};
  }catch(e){
    const error={schema:"heptabao.mac-harness-sdk-body-admission-stopped.v1",sequence:s.sequence,operation_id:load(k+"operation_id")||null,error_name:String(e.name||"Error"),message:String(e.message||e),public_stage:e.public_stage||null,sdk_blob:e.sdk_blob||null,native_blob:e.native_blob||null,new_admissions_stopped:true,original_operation_replayed:false};
    store(p+"body_admission_stopped",error);
    const saved=await saveRaw(JSON.stringify(error,null,2)+"\n");store(k+"error",saved);
    return {stopped:true,...error,error_blob:saved.blob};
  }
}
