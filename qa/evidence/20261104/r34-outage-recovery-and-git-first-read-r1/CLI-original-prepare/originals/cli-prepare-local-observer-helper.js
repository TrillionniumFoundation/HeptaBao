
async function cpArchive(name,text){
 const B=eval(load("r32_root_helpers_source")+";({save:saveVerifiedPublicBlobJournaled,persist:persistRecoveryText,fb:fetchVerifiedPublicBlob,meta:gitBlobMeta})"),m=B.meta(text);
 try{return await B.save(name,text);}catch(error){
  const first=load("r32_git_write_"+m.blob+"_sdk");
  const firstRaw=JSON.stringify(first??{local_archive_exception:String(error)},null,2)+"\n",ep=B.meta(firstRaw);
  await B.persist("cli-prepare-archive-first-error-"+m.blob,firstRaw);
  const tsdk=await tools.mcp__codex_apps__github_create_tree({repository_full_name:"TrillionniumFoundation/HeptaBao",tree_elements:[{path:"exact-public-content.txt",mode:"100644",type:"blob",content:text},{path:"original-archive-error.sdk.json",mode:"100644",type:"blob",content:firstRaw}]});
  await B.persist("cli-prepare-archive-content-tree-"+m.blob,JSON.stringify(tsdk,null,2)+"\n");
  if(tsdk.isError)throw Error("Git content-tree recovery failed "+m.blob);
  const got=await B.fb(m.blob),err=await B.fb(ep.blob);
  if(got.text!==text||err.text!==firstRaw)throw Error("Git identical-content recovery mismatch");
  const incidents=load("cli_prepare_git_archive_incidents")??[];
  incidents.push({name,content:m,original_error:ep,content_tree_SDK_local:"cli-prepare-archive-content-tree-"+m.blob+".json",native_replayed:false});
  store("cli_prepare_git_archive_incidents",incidents);
  await B.persist("cli-prepare-git-archive-incidents",JSON.stringify(incidents,null,2)+"\n");
  return {name,...m};
 }
}

function cpH(){return eval(load("r32_root_helpers_source")+";({save:cpArchive,persist:persistRecoveryText,lossless:parseLosslessIntegers,unb64,utf8Text,byteString,sha256Latin1,meta:gitBlobMeta})");}
async function cpSync(label){
 if(!/^[A-Za-z0-9._-]+$/.test(label))throw Error("unsafe_label");
 const p="/workspace/scratch/f86faac821c4/r32_recovery/"+label+".json";
 const z=await tools.exec_command({cmd:"python3 - <<'PY'\nimport os\np="+JSON.stringify(p)+"\nf=os.open(p,os.O_RDONLY)\nos.fsync(f)\nos.close(f)\nd=os.open(os.path.dirname(p),os.O_RDONLY|os.O_DIRECTORY)\nos.fsync(d)\nos.close(d)\nPY",max_output_tokens:300});
 if(z.exit_code!==0){const H=cpH();await H.persist("cli-prepare-local-fsync-error-"+label,JSON.stringify(z,null,2)+"\n");store("cli-prepare_local_fsync_unresolved",{label,result:z});throw Error("local_fsync_not_terminal_zero: "+JSON.stringify(z));}
}
async function cpState(s){
 const H=cpH(),checkpoint=JSON.parse(JSON.stringify(s));
 delete checkpoint.last_result;delete checkpoint.start_native_object;
 checkpoint.last_result_native=s.last_call?.native??null;
 for(const c of checkpoint.calls??[])delete c.request_text;
 for(const o of checkpoint.observations??[]){
  delete o.native_object;delete o.page_base64;
  for(const p of o.pages??[])if(p.call){p.call_label=p.call.label;p.native_page=p.call.native;delete p.call;}
 }
 checkpoint.original_SDKs_are_independent_immutable_files=true;
 await H.persist("cli-prepare-execution-state",JSON.stringify(checkpoint,null,2)+"\n");
 await cpSync("cli-prepare-execution-state");store("cli_prepare_execution_state",s);
}
async function cpPrepare(label,tool,input){
 const H=cpH(),s=load("cli_prepare_execution_state");
 if(!s||s.halted||!s.ACK_binding_verified||s.pending_call||s.Runtime_call_inflight||s.calls.some(c=>c.label===label))throw Error("prepare_state");
 const raw=typeof input==="string"?input:JSON.stringify(input,null,2)+"\n",q=JSON.parse(raw);
 if(tool==="operation_start"){
  if(s.active_operation_id)throw Error("unclosed_observer");
  const t=q.operation?.tool,a=q.operation?.arguments;
  if(a?.host!=="desktop")throw Error("host");
  if(t==="process_status"){
   if(a.job_id!==s.job_id||Object.keys(a).sort().join(",")!=="host,job_id"||!label.startsWith("authority"))throw Error("same_prepare_job_authority");
  }else if(t==="process_read"){
   const expected={host:"desktop",job_id:s.job_id,stdout_offset:0,stderr_offset:0,limit:16384};
   if(!s.authority_terminal_passed||JSON.stringify(a)!==JSON.stringify(expected)||s.observations.some(o=>o.tool==="process_read"))throw Error("single_full_stream_observation");
  }else if(t==="file_info"){
   if(!s.original_streams_verified||s.observations.some(o=>o.tool==="file_info")||JSON.stringify(q)!==JSON.stringify(s.full_GO.conditionalResultRead.metadata))throw Error("exact_prepare_result_metadata_after_success");
  }else if(t==="binary_read"){
   if(!s.result_metadata_verified||s.observations.some(o=>o.tool==="binary_read"))throw Error("single_prepare_result_body");
   const expected=JSON.parse(JSON.stringify(s.full_GO.conditionalResultRead.bodyTemplate)),f=s.result_file_info;
   if(!f||f.size<1||f.size>s.full_GO.conditionalResultRead.maximumBodyBytes)throw Error("body_cap");
   expected.operation.arguments.limit=f.size;expected.operation.arguments.expected_version=f.version;
   if(JSON.stringify(q)!==JSON.stringify(expected))throw Error("two_null_only_actual_body");
  }else throw Error("GO_readonly_allowlist");
 }else{
  if(!["operation_status","operation_result"].includes(tool)||q.operation_id!==s.active_operation_id)throw Error("same_ID_only");
  if(tool==="operation_result"&&(q.limit!==8192||q.offset!==(s.observations.at(-1).next_offset??0)))throw Error("immutable_page_geometry");
 }
 const rp=await H.save("cli-prepare-"+label+"-request",raw);
 const ip=await H.save("cli-prepare-"+label+"-intent",JSON.stringify({schema:"heptabao.cli-prepare.exact-read-intent.v1",GO:s.GO,original_prepare_job:s.job_id,tool,request:rp,original_operation_id:q.operation_id??null,business_replay:false,external_before_call:true},null,2)+"\n");
 s.pending_call={label,tool,request:rp,request_text:raw,intent:ip,submitted:false};await cpState(s);
 text({label,request:rp,intent:ip,Runtime_submitted:false});
}
async function cpSubmit(){
 const H=cpH(),s=load("cli_prepare_execution_state"),p=s?.pending_call;
 if(!p||p.submitted||s.Runtime_call_inflight||s.halted)throw Error("single_call");
 const names={operation_start:"mcp__codex_apps__heptaruntime_mac_controller_operation_start",operation_status:"mcp__codex_apps__heptaruntime_mac_controller_operation_status",operation_result:"mcp__codex_apps__heptaruntime_mac_controller_operation_result"};
 if(!names[p.tool])throw Error("readonly_allowlist");
 const q=JSON.parse(p.request_text);p.submitted=true;s.Runtime_call_inflight=true;await cpState(s);
 let sdk;try{sdk=await tools[names[p.tool]](q);}catch(e){sdk={local_transport_exception:true,name:e?.name??"Error",message:String(e)};}
 const raw=JSON.stringify(sdk,null,2)+"\n",label="cli-prepare-"+p.label+"-original-SDK";
 await H.persist(label,raw);await cpSync(label);
 const sp=await H.save(label,raw),out={...p,SDK:sp,isError:sdk.isError===true,local_transport_exception:sdk.local_transport_exception===true};
 let n;
 if(!out.local_transport_exception&&Array.isArray(sdk.content)&&sdk.content.length===1&&sdk.content[0].type==="text"){
  out.native=await H.save("cli-prepare-"+p.label+"-original-native",sdk.content[0].text);
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
 await cpState(s);
 text({label:p.label,SDK:sp,native:out.native,isError:out.isError,local_transport_exception:out.local_transport_exception,result:p.tool==="operation_result"?{keys:n?Object.keys(n):null}:n});
}
async function cpAcceptStatus(){
 const s=load("cli_prepare_execution_state"),n=s.last_result,o=s.observations.at(-1);
 if(s.halted||n.operation_id!==o.operation_id||n.tool_name!==o.tool)throw Error("status_binding");
 o.status=s.last_call;
 o.native_handler_closed=n.async_state==="completed"&&n.result_state==="stored_observed"&&n.owned_future_active===false&&n.payload_available===true;
 await cpState(s);
 if(!o.native_handler_closed)throw Error("native_handler_not_closed");
 return o;
}
async function cpAcceptPage(){
 const H=cpH(),s=load("cli_prepare_execution_state"),n=s.last_result,o=s.observations.at(-1);
 if(s.halted||!o.native_handler_closed||s.last_call.tool!=="operation_result")throw Error("page_state");
 const b=H.unb64(n.data_base64),off=o.next_offset??0;
 if(n.operation_id!==o.operation_id||n.offset!==off||n.next_offset!==off+b.length||n.immutable_snapshot!==true||n.payload_kind!=="native_result"||b.length!==Math.min(8192,n.total_bytes-off)||n.eof!==(n.next_offset===n.total_bytes))throw Error("page_geometry");
 if(o.payload_sha256&&o.payload_sha256!==n.result_sha256||o.payload_bytes&&o.payload_bytes!==n.total_bytes)throw Error("immutable_payload_changed");
 o.payload_sha256=n.result_sha256;o.payload_bytes=n.total_bytes;o.next_offset=n.next_offset;o.pages_complete=n.eof;
 o.pages.push({call:s.last_call,offset:n.offset,next_offset:n.next_offset,total_bytes:n.total_bytes,result_sha256:n.result_sha256,eof:n.eof});
 // Original page bytes stay in their own already-persisted native page files.
 await cpState(s);text({operation:o.operation_id,pages:o.pages.length,next_offset:o.next_offset,total_bytes:o.payload_bytes,pages_complete:o.pages_complete});return o;
}
async function cpFinalize(){
 const H=cpH(),s=load("cli_prepare_execution_state"),o=s.observations.at(-1);
 if(!o.pages_complete||s.halted||!o.native_handler_closed)throw Error("observation_not_ready");
 const b=[];
 for(const page of o.pages){
  const pin=page.call?.native??page.native_page;if(!pin)throw Error("missing_saved_page_pin");
  const saved=await fetchVerifiedPublicBlob(pin.blob),n=H.lossless(saved.text);
  if(n.operation_id!==o.operation_id||n.offset!==page.offset||n.result_sha256!==o.payload_sha256)throw Error("saved_page_binding");
  b.push(...H.unb64(n.data_base64));
 }
 if(b.length!==o.payload_bytes||H.sha256Latin1(H.byteString(b))!==o.payload_sha256)throw Error("whole_payload_hash");
 const raw=H.utf8Text(b),pp=await H.save("cli-prepare-"+o.name+"-payload-original",raw),sdk=JSON.parse(raw);
 o.payload=pp;
 if(sdk.isError===true||!Array.isArray(sdk.content)||sdk.content.length!==1||sdk.content[0].type!=="text"){
  o.native_tool_error=true;s.halted=true;await cpState(s);throw Error("original_native_tool_error");
 }
 o.native=await H.save("cli-prepare-"+o.name+"-native-original",sdk.content[0].text);o.native_object=H.lossless(sdk.content[0].text);o.closed=true;
 delete o.page_base64;s.active_operation_id=null;await cpState(s);
 text({observation:o.name,tool:o.tool,payload:o.payload,native:o.native,closed:true,native_keys:Object.keys(o.native_object)});
 return o;
}
