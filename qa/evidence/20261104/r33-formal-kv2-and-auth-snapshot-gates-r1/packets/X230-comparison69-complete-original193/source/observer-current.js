
function c69H(){return eval(load("r32_root_helpers_source")+";({save:saveVerifiedPublicBlobJournaled,persist:persistRecoveryText,lossless:parseLosslessIntegers,unb64,utf8Text,byteString,sha256Latin1,meta:gitBlobMeta})");}
async function c69Sync(label){
 if(!/^[A-Za-z0-9._-]+$/.test(label))throw Error("unsafe_label");
 const p="/workspace/scratch/f86faac821c4/r32_recovery/"+label+".json";
 const z=await tools.exec_command({cmd:"python3 - <<'PY'\nimport os\np="+JSON.stringify(p)+"\nf=os.open(p,os.O_RDONLY)\nos.fsync(f)\nos.close(f)\nd=os.open(os.path.dirname(p),os.O_RDONLY|os.O_DIRECTORY)\nos.fsync(d)\nos.close(d)\nPY",max_output_tokens:300});
 if(z.exit_code!==0){const H=c69H();await H.persist("comparison69-local-fsync-error-"+label,JSON.stringify(z,null,2)+"\n");store("comparison69_local_fsync_unresolved",{label,result:z});throw Error("local_fsync_not_terminal_zero: "+JSON.stringify(z));}
}
async function c69State(s){
 const H=c69H(),checkpoint=JSON.parse(JSON.stringify(s));
 delete checkpoint.last_result;delete checkpoint.start_native_object;
 checkpoint.last_result_native=s.last_call?.native??null;
 for(const c of checkpoint.calls??[])delete c.request_text;
 for(const o of checkpoint.observations??[]){
  delete o.native_object;delete o.page_base64;
  for(const p of o.pages??[])if(p.call){p.call_label=p.call.label;p.native_page=p.call.native;delete p.call;}
 }
 checkpoint.original_SDKs_are_independent_immutable_files=true;
 await H.persist("comparison69-current4e808-execution-state",JSON.stringify(checkpoint,null,2)+"\n");
 await c69Sync("comparison69-current4e808-execution-state");store("x230_current_comparison69_execution_state",s);
}
async function c69Prepare(label,tool,q){
 const H=c69H(),s=load("x230_current_comparison69_execution_state");
 if(!s||s.halted||s.pending_call||s.Runtime_call_inflight||s.calls.some(c=>c.label===label))throw Error("prepare_state");
 if(tool==="operation_start"){
  if(s.active_operation_id)throw Error("unclosed_observer");
  const t=q.operation?.tool,a=q.operation?.arguments,allowed=s.full_GO.fixed_public_result_retrieval.files;
  if(a?.host!=="x230")throw Error("host");
  if(["process_status","process_read"].includes(t)){
   if(a.job_id!==s.job_id)throw Error("original_job");
   if(t==="process_read"&&(!Number.isInteger(a.limit)||a.limit<1||a.limit>16384))throw Error("stream_cap");
  }else if(t==="file_info"){
   if(!allowed.some(f=>f.path===a.path)||(s.metadata_admitted??[]).includes(a.path))throw Error("fixed_once_metadata");
  }else if(t==="binary_read"){
   const f=s.file_infos?.[a.path],rule=allowed.find(f=>f.path===a.path),body=s.file_bodies?.[a.path];
   if(!f||!rule||f.size>rule.max_body_bytes||f.size<=0||a.expected_version!==f.version||a.offset!==(body?.next_offset??0)||a.limit!==Math.min(65536,f.size-a.offset)||(s.binary_reads_admitted??0)>=9)throw Error("conditional_fixed_body");
  }else throw Error("read_allowlist");
 }else{
  if(!["operation_status","operation_result"].includes(tool)||q.operation_id!==s.active_operation_id)throw Error("same_ID_only");
  if(tool==="operation_result"&&(q.limit!==8192||q.offset!==(s.observations.at(-1).next_offset??0)))throw Error("immutable_page_geometry");
 }
 const raw=JSON.stringify(q,null,2)+"\n",rp=await H.save("comparison69-"+label+"-request",raw);
 const ip=await H.save("comparison69-"+label+"-intent",JSON.stringify({schema:"heptabao.comparison69.exact-read-intent.v1",GO:s.GO,original_business_request:s.request,original_job:s.job_id,tool,request:rp,original_operation_id:q.operation_id??null,business_replay:false,external_before_call:true},null,2)+"\n");
 s.pending_call={label,tool,request:rp,request_text:raw,intent:ip,submitted:false};await c69State(s);
 text({label,request:rp,intent:ip,Runtime_submitted:false});
}
async function c69Submit(){
 const H=c69H(),s=load("x230_current_comparison69_execution_state"),p=s?.pending_call;
 if(!p||p.submitted||s.Runtime_call_inflight||s.halted)throw Error("single_call");
 const names={operation_start:"mcp__codex_apps__heptaruntime_mac_controller_operation_start",operation_status:"mcp__codex_apps__heptaruntime_mac_controller_operation_status",operation_result:"mcp__codex_apps__heptaruntime_mac_controller_operation_result"};
 if(!names[p.tool])throw Error("readonly_allowlist");
 const q=JSON.parse(p.request_text);p.submitted=true;s.Runtime_call_inflight=true;await c69State(s);
 let sdk;try{sdk=await tools[names[p.tool]](q);}catch(e){sdk={local_transport_exception:true,name:e?.name??"Error",message:String(e)};}
 const raw=JSON.stringify(sdk,null,2)+"\n",label="comparison69-"+p.label+"-original-SDK";
 await H.persist(label,raw);await c69Sync(label);
 const sp=await H.save(label,raw),out={...p,SDK:sp,isError:sdk.isError===true,local_transport_exception:sdk.local_transport_exception===true};
 let n;
 if(!out.local_transport_exception&&Array.isArray(sdk.content)&&sdk.content.length===1&&sdk.content[0].type==="text"){
  out.native=await H.save("comparison69-"+p.label+"-original-native",sdk.content[0].text);
  if(!out.isError){try{n=H.lossless(sdk.content[0].text);}catch(e){out.parse_error=String(e);}}
 }
 s.Runtime_call_inflight=false;s.calls.push(out);s.pending_call=null;s.last_call=out;s.last_result=n??null;
 if(out.isError||out.local_transport_exception||out.parse_error)s.halted=true;
 if(p.tool==="operation_start"&&!s.halted){
  if(typeof n?.operation_id!=="string"||n.tool_name!==q.operation.tool)throw Error("admission_shape_after_preservation");
  s.active_operation_id=n.operation_id;s.observations.push({name:p.label.replace(/-admission$/,""),operation_id:n.operation_id,tool:q.operation.tool,arguments:q.operation.arguments,admission:out,pages:[],closed:false});
  if(q.operation.tool==="file_info")(s.metadata_admitted??=[]).push(q.operation.arguments.path);
  if(q.operation.tool==="binary_read")s.binary_reads_admitted=(s.binary_reads_admitted??0)+1;
 }
 await c69State(s);
 text({label:p.label,SDK:sp,native:out.native,isError:out.isError,local_transport_exception:out.local_transport_exception,result:p.tool==="operation_result"?{keys:n?Object.keys(n):null}:n});
}
async function c69AcceptStatus(){
 const s=load("x230_current_comparison69_execution_state"),n=s.last_result,o=s.observations.at(-1);
 if(s.halted||n.operation_id!==o.operation_id||n.tool_name!==o.tool)throw Error("status_binding");
 o.status=s.last_call;
 o.native_handler_closed=n.async_state==="completed"&&n.result_state==="stored_observed"&&n.owned_future_active===false&&n.payload_available===true;
 await c69State(s);
 if(!o.native_handler_closed)throw Error("native_handler_not_closed");
 return o;
}
async function c69AcceptPage(){
 const H=c69H(),s=load("x230_current_comparison69_execution_state"),n=s.last_result,o=s.observations.at(-1);
 if(s.halted||!o.native_handler_closed||s.last_call.tool!=="operation_result")throw Error("page_state");
 const b=H.unb64(n.data_base64),off=o.next_offset??0;
 if(n.operation_id!==o.operation_id||n.offset!==off||n.next_offset!==off+b.length||n.immutable_snapshot!==true||n.payload_kind!=="native_result"||b.length!==Math.min(8192,n.total_bytes-off)||n.eof!==(n.next_offset===n.total_bytes))throw Error("page_geometry");
 if(o.payload_sha256&&o.payload_sha256!==n.result_sha256||o.payload_bytes&&o.payload_bytes!==n.total_bytes)throw Error("immutable_payload_changed");
 o.payload_sha256=n.result_sha256;o.payload_bytes=n.total_bytes;o.next_offset=n.next_offset;o.pages_complete=n.eof;
 o.pages.push({call:s.last_call,offset:n.offset,next_offset:n.next_offset,total_bytes:n.total_bytes,result_sha256:n.result_sha256,eof:n.eof});
 // Original page bytes stay in their own already-persisted native page files.
 await c69State(s);text({operation:o.operation_id,pages:o.pages.length,next_offset:o.next_offset,total_bytes:o.payload_bytes,pages_complete:o.pages_complete});return o;
}
async function c69Finalize(){
 const H=c69H(),s=load("x230_current_comparison69_execution_state"),o=s.observations.at(-1);
 if(!o.pages_complete||s.halted||!o.native_handler_closed)throw Error("observation_not_ready");
 const b=[];
 for(const page of o.pages){
  const pin=page.call?.native??page.native_page;if(!pin)throw Error("missing_saved_page_pin");
  const saved=await fetchVerifiedPublicBlob(pin.blob),n=H.lossless(saved.text);
  if(n.operation_id!==o.operation_id||n.offset!==page.offset||n.result_sha256!==o.payload_sha256)throw Error("saved_page_binding");
  b.push(...H.unb64(n.data_base64));
 }
 if(b.length!==o.payload_bytes||H.sha256Latin1(H.byteString(b))!==o.payload_sha256)throw Error("whole_payload_hash");
 const raw=H.utf8Text(b),pp=await H.save("comparison69-"+o.name+"-payload-original",raw),sdk=JSON.parse(raw);
 o.payload=pp;
 if(sdk.isError===true||!Array.isArray(sdk.content)||sdk.content.length!==1||sdk.content[0].type!=="text"){
  o.native_tool_error=true;s.halted=true;await c69State(s);throw Error("original_native_tool_error");
 }
 o.native=await H.save("comparison69-"+o.name+"-native-original",sdk.content[0].text);o.native_object=H.lossless(sdk.content[0].text);o.closed=true;
 delete o.page_base64;s.active_operation_id=null;await c69State(s);
 text({observation:o.name,tool:o.tool,payload:o.payload,native:o.native,closed:true,native_keys:Object.keys(o.native_object)});
 return o;
}
