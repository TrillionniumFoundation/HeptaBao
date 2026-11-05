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
      store(k+"operation_id",ack.operation_id); notify({sequence:s.sequence,ack_saved:true,operation_id:ack.operation_id});
    }
    const operation_id=load(k+"operation_id");
    if(!operation_id)throw Error("Original start has no known operation id; do not replay");
    let status=load(k+"latest_status"),stag=load(k+"completed_status_tag")||null;
    if(!(status?.operation_id===operation_id&&status.async_state==="completed"&&status.owned_future_active===false)){
      const n=load(k+"status_count")||0;stag="status_"+n;const streq={operation_id};
      store(k+stag+"_request",await saveRaw(JSON.stringify(streq,null,2)+"\n"));
      status=await record(stag,await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_status(streq));
      store(k+stag,status);store(k+"latest_status",status);store(k+"status_count",n+1);notify({sequence:s.sequence,status_saved:true,state:status.async_state,inactive:status.owned_future_active===false});
      if(status.operation_id!==operation_id||status.tool_name!=="binary_read")throw Error("Status binding");
      if(status.async_state!=="completed"||status.owned_future_active!==false)return {sequence:s.sequence,pending:true,operation_id,status};
      store(k+"completed_status_tag",stag);
    }
    if(!stag)stag="status_"+((load(k+"status_count")||1)-1);
    if(status.operation_id!==operation_id||status.tool_name!=="binary_read"||status.result_state!=="stored_observed"||status.payload_available!==true)throw Error("Stored payload unavailable");
    let off=0,all="",page=0,total=null,hash=null;
    while(total===null||off!==total){
      if(page>=64)throw Error("Original payload page cap");
      if(load(k+"result_"+page)){
        const v=load(k+"result_"+page),b=load(k+"result_binary_"+page);
        if(typeof b!=="string"||v.operation_id!==operation_id||v.offset!==off||v.next_offset!==off+b.length||v.immutable_snapshot!==true||v.payload_kind!=="native_result")throw Error("Retained page sequence");
        if(page===0){total=v.total_bytes;hash=v.result_sha256;}
        if(v.total_bytes!==total||v.result_sha256!==hash||v.eof!==(v.next_offset===total))throw Error("Retained page invariant");
        all+=b;off=v.next_offset;page++;
        if(page===1||v.eof)notify({sequence:s.sequence,payload_bytes_observed:off,total_bytes:total,eof:v.eof});
        continue;
      }
      const jobs=[];
      const count=total===null?1:Math.min(2,Math.ceil((total-off)/16384));
      for(let j=0;j<count;j++){
        const index=page+j,offset=off+j*16384;
        if(load(k+"result_"+index))continue;
        const req={operation_id,offset,limit:16384},tag="result_"+index;
        store(k+tag+"_request",await saveRaw(JSON.stringify(req,null,2)+"\n"));
        jobs.push({index,offset,tag,req});
      }
      const outcomes=await Promise.allSettled(jobs.map(j=>tools.mcp__codex_apps__heptaruntime_mac_controller_operation_result(j.req)));
      const saved=[];
      for(let j=0;j<outcomes.length;j++){
        const o=outcomes[j],meta=jobs[j];
        if(o.status==="rejected"){
          const errRaw=await saveRaw(JSON.stringify({schema:"heptabao.original-tool-promise-rejection.v1",operation_id,request:meta.req,name:String(o.reason?.name||"Error"),message:String(o.reason?.message||o.reason)},null,2)+"\n");
          store(k+meta.tag+"_promise_rejection",errRaw);saved.push({...meta,rejection:errRaw});continue;
        }
        const r=o.value;store(k+meta.tag+"_sdk_response",r);
        const sdk=await saveRaw(JSON.stringify(r,null,2)+"\n");store(k+meta.tag+"_sdk_snapshot",sdk);
        const parts=r.content?.filter(x=>x.type==="text")||[];let native=null;
        if(parts.length===1){native=await saveRaw(parts[0].text);store(k+meta.tag+"_native",native);}
        saved.push({...meta,r,sdk,native,parts});
      }
      const errors=[];
      for(const rec of saved){
        if(rec.rejection){errors.push(Object.assign(new Error("Tool promise rejected"),{public_stage:rec.tag,sdk_blob:rec.rejection.blob}));continue;}
        if(rec.r.isError){errors.push(Object.assign(new Error("MCP isError before parse"),{public_stage:rec.tag,sdk_blob:rec.sdk.blob,native_blob:rec.native?.blob}));continue;}
        if(rec.parts.length!==1){errors.push(Object.assign(new Error("Unexpected SDK text envelope"),{public_stage:rec.tag,sdk_blob:rec.sdk.blob}));continue;}
        try{
          const v=JSON.parse(rec.native.raw),b=dec(v.data_base64);
          if(v.operation_id!==operation_id||v.offset!==rec.offset||v.next_offset!==rec.offset+b.length||b.length>16384||v.immutable_snapshot!==true||v.payload_kind!=="native_result"||!Number.isSafeInteger(v.total_bytes)||v.total_bytes<1||v.total_bytes>1048576||!(/^[0-9a-f]{64}$/.test(v.result_sha256)))throw Error("Immutable page binding");
          if(rec.index===0){total=v.total_bytes;hash=v.result_sha256;}
          if(v.total_bytes!==total||v.result_sha256!==hash||v.eof!==(v.next_offset===total)||v.next_offset>total||(!v.eof&&b.length!==16384))throw Error("Immutable page changed or boundary");
          store(k+rec.tag,v);store(k+"result_binary_"+rec.index,b);store(k+"result_count",Math.max(load(k+"result_count")||0,rec.index+1));
        }catch(e){errors.push(Object.assign(e,{public_stage:rec.tag,sdk_blob:rec.sdk.blob,native_blob:rec.native?.blob}));}
      }
      if(errors.length){store(k+"batch_errors",errors.map(e=>({stage:e.public_stage,message:e.message,sdk_blob:e.sdk_blob||null,native_blob:e.native_blob||null})));throw errors[0];}
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