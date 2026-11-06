
function lh(){return eval(load("r32_root_helpers_source")+";({fb:fetchVerifiedPublicBlob,f:fetchImmutablePacketCached,meta:gitBlobMeta,lossless:parseLosslessIntegers,unb64,utf8Text,byteString,sha256Latin1})");}
async function ll(name,text){const H=hlH();await H.persist(name,text);await hlSync(name);const p={name,...H.meta(text),local_json:"/workspace/scratch/f86faac821c4/r32_recovery/"+name+".json"};store("h2_live_local_text_"+p.blob,text);return p;}
function lt(p){const x=load("h2_live_local_text_"+p.blob);if(typeof x!=="string"||hlH().meta(x).blob!==p.blob)throw Error("recover_original_local_file_without_Runtime:"+p.local_json);return x;}
async function lp(label,tool,q){
 const s=load("h2_live_execution_state");
 if(s.halted||s.Runtime_call_inflight||s.pending_call||s.calls.some(x=>x.label===label))throw Error("live_call_state");
 if(!["operation_start","operation_status","operation_result"].includes(tool))throw Error("readonly_tool_only");
 if(tool==="operation_start"){
  if(!s.ACK_binding_verified||s.active_operation_id||s.observations.some(o=>!o.archived))throw Error("previous_observer_not_archived");
  const op=q.operation,a=op.arguments;if(a.host!=="desktop")throw Error("host_gate");
  if(op.tool==="process_status"){if(a.job_id!==s.job_id||Object.keys(a).sort().join(",")!=="host,job_id")throw Error("authority_job_gate");}
  else if(op.tool==="process_read"){if(!s.authority_definitive||a.job_id!==s.job_id||a.limit!==16384||a.stdout_offset!==(s.stream_stdout_next??0)||a.stderr_offset!==(s.stream_stderr_next??0))throw Error("original_stream_gate");}
  else if(op.tool==="file_info"){const f=s.full_GO.fixedPublicResultRead;if(!s.public_result_pointer_verified||s.metadata_admitted.length||a.path!==f.path||q.idempotency_key!==f.file_info.idempotency_key)throw Error("fixed_info_gate");}
  else if(op.tool==="binary_read"){const f=s.full_GO.fixedPublicResultRead,m=s.result_file_info,off=s.result_body_next_offset??0;if(!s.result_metadata_verified||a.path!==f.path||a.offset!==off||s.body_offsets_admitted.includes(off)||a.limit!==Math.min(65536,m.size-off)||a.limit<1||a.expected_version!==m.version||q.idempotency_key!==f.binary_read.idempotency_key_template.replace("{decimal_offset}",String(off)))throw Error("fixed_body_gate");}
  else throw Error("operation_tool_not_authorized");
 }else{
  const o=s.observations.at(-1);if(!o||o.operation_id!==s.active_operation_id||q.operation_id!==o.operation_id||o.closed)throw Error("same_original_operation_gate");
  if(tool==="operation_result"&&(!o.native_handler_closed||q.offset!==(o.next_offset??0)||q.limit!==(o.page_width??8192)))throw Error("original_page_gate");
 }
 const request=await ll("h2-live-"+label+"-request",JSON.stringify(q,null,2)+"\n");
 const intent=await ll("h2-live-"+label+"-intent",JSON.stringify({schema:"heptabao.h2-live.original-readonly-intent.v1",GO:s.GO,job_id:s.job_id,label,tool,request,Runtime_submitted:false,one_future:true,archive_after_observer:true},null,2)+"\n");
 s.pending_call={label,tool,request,intent,request_text:JSON.stringify(q,null,2)+"\n",submitted:false};await hlState(s);text({prepared:label,request,intent,Runtime_submitted:false});
}
async function ls(){
 const s=load("h2_live_execution_state"),p=s.pending_call;
 if(!p||p.submitted||s.Runtime_call_inflight||s.halted)throw Error("single_readonly_submit_gate");
 const names={operation_start:"mcp__codex_apps__heptaruntime_mac_controller_operation_start",operation_status:"mcp__codex_apps__heptaruntime_mac_controller_operation_status",operation_result:"mcp__codex_apps__heptaruntime_mac_controller_operation_result"};
 const q=JSON.parse(p.request_text);p.submitted=true;s.Runtime_call_inflight=true;await hlState(s);
 let sdk;try{sdk=await tools[names[p.tool]](q);}catch(e){sdk={local_transport_exception:true,name:e?.name??"Error",message:String(e)};}
 const raw=JSON.stringify(sdk,null,2)+"\n",sp=await ll("h2-live-"+p.label+"-original-SDK",raw);
 const out={...p,SDK:sp,isError:sdk.isError===true,local_transport_exception:sdk.local_transport_exception===true};let n=null;
 if(!out.local_transport_exception&&sdk.content?.length===1&&sdk.content[0].type==="text"){out.native=await ll("h2-live-"+p.label+"-original-native",sdk.content[0].text);if(!out.isError){try{n=lh().lossless(sdk.content[0].text);}catch(e){out.parse_error=String(e);}}}
 else if(!out.local_transport_exception)out.parse_error="unexpected_SDK_shape";
 s.Runtime_call_inflight=false;s.pending_call=null;s.calls.push(out);s.last_call=out;s.last_result=n;
 if(out.isError||out.local_transport_exception||out.parse_error)s.halted=true;
 if(p.tool==="operation_start"&&!s.halted){
  if(typeof n?.operation_id!=="string"||n.tool_name!==q.operation.tool){s.halted=true;await hlState(s);throw Error("preserved_admission_shape");}
  s.active_operation_id=n.operation_id;s.observations.push({name:p.label.replace(/-admission$/,""),operation_id:n.operation_id,tool:q.operation.tool,arguments:q.operation.arguments,admission:out,page_width:s.default_page_width??8192,page_width_amendment:s.page_width_amendment??null,status_calls:[],pages:[],closed:false,archived:false});
  if(q.operation.tool==="file_info")s.metadata_admitted.push(q.operation.arguments.path);
  if(q.operation.tool==="binary_read")s.body_offsets_admitted.push(q.operation.arguments.offset);
 }
 await hlState(s);
 text({label:p.label,SDK:sp,native:out.native,isError:out.isError,transport_exception:out.local_transport_exception,result:p.tool==="operation_result"?{operation_id:n?.operation_id,offset:n?.offset,next_offset:n?.next_offset,total_bytes:n?.total_bytes,eof:n?.eof}:n});
}
async function laStatus(){
 const s=load("h2_live_execution_state"),n=s.last_result,o=s.observations.at(-1);
 if(s.halted||s.last_call.tool!=="operation_status"||n.operation_id!==o.operation_id||n.tool_name!==o.tool)throw Error("original_status_binding");
 o.status_calls.push(s.last_call);o.status=s.last_call;
 o.native_handler_closed=n.async_state==="completed"&&n.result_state==="stored_observed"&&n.owned_future_active===false&&n.payload_available===true;
 await hlState(s);text({operation_id:o.operation_id,native_handler_closed:o.native_handler_closed,async_state:n.async_state,result_state:n.result_state,owned_future_active:n.owned_future_active});return o;
}
async function laPage(){
 const s=load("h2_live_execution_state"),o=s.observations.at(-1),n=s.last_result,H=lh();
 if(s.halted||!o.native_handler_closed||s.last_call.tool!=="operation_result")throw Error("page_state");
 const b=H.unb64(n.data_base64),off=o.next_offset??0;
 if(n.operation_id!==o.operation_id||n.offset!==off||n.next_offset!==off+b.length||n.immutable_snapshot!==true||n.payload_kind!=="native_result"||!Number.isSafeInteger(n.total_bytes)||n.total_bytes>1048576||b.length!==Math.min(o.page_width??8192,n.total_bytes-off)||n.eof!==(n.next_offset===n.total_bytes))throw Error("page_geometry");
 if(o.payload_sha256&&o.payload_sha256!==n.result_sha256||o.payload_bytes&&o.payload_bytes!==n.total_bytes)throw Error("immutable_payload_drift");
 o.payload_sha256=n.result_sha256;o.payload_bytes=n.total_bytes;o.next_offset=n.next_offset;o.pages_complete=n.eof;
 o.pages.push({call:s.last_call,offset:n.offset,next_offset:n.next_offset,total_bytes:n.total_bytes,result_sha256:n.result_sha256,eof:n.eof});
 await hlState(s);text({operation_id:o.operation_id,pages:o.pages.length,next_offset:o.next_offset,total_bytes:o.payload_bytes,eof:o.pages_complete});return o;
}
async function lf(){
 const s=load("h2_live_execution_state"),o=s.observations.at(-1),H=lh();
 if(!o.native_handler_closed||!o.pages_complete||s.pending_call||s.Runtime_call_inflight||s.halted)throw Error("observer_finalize_gate");
 const bytes=new Uint8Array(o.payload_bytes);let off=0;
 for(const p of o.pages){const n=H.lossless(lt(p.call.native)),b=H.unb64(n.data_base64);if(n.offset!==off)throw Error("page_reassembly_order");bytes.set(b,off);off+=b.length;}
 const raw=H.utf8Text(bytes);if(off!==o.payload_bytes||H.sha256Latin1(H.byteString(bytes))!==o.payload_sha256||H.meta(raw).sha256!==o.payload_sha256)throw Error("whole_original_payload_hash");
 o.payload=await ll("h2-live-"+o.name+"-payload-original",raw);
 const sdk=JSON.parse(raw);o.payload_isError=sdk.isError===true;
 if(sdk.content?.length!==1||sdk.content[0].type!=="text")throw Error("original_payload_shape_preserved");
 o.native=await ll("h2-live-"+o.name+"-native-original",sdk.content[0].text);
 let n=null;if(!o.payload_isError)n=H.lossless(sdk.content[0].text);
 store("h2_live_observation_native_"+o.operation_id,n);o.closed=true;s.active_operation_id=null;if(o.payload_isError)s.halted=true;
 await hlState(s);
 const entries=[],add=(path,p)=>entries.push({path,...p}),call=(prefix,c)=>{add(prefix+"/request.json",c.request);add(prefix+"/intent.json",c.intent);add(prefix+"/original.sdk.json",c.SDK);if(c.native)add(prefix+"/original.native.json",c.native);};
 call("admission",o.admission);o.status_calls.forEach((c,i)=>call("status/"+String(i).padStart(3,"0"),c));o.pages.forEach(p=>call("pages/"+String(p.offset).padStart(6,"0"),p.call));add("payload.original.sdk.json",o.payload);add("payload.original.native.json",o.native);
 const manifest={schema:"heptabao.h2-live.one-original-observer.v1",GO:s.GO,job_id:s.job_id,name:o.name,operation_id:o.operation_id,tool:o.tool,arguments:o.arguments,native_handler_closed:o.native_handler_closed,payload_isError:o.payload_isError,closed:o.closed,pages:o.pages.length,page_width:o.page_width??8192,page_width_amendment:o.page_width_amendment??null,payload_sha256:o.payload_sha256,payload_bytes:o.payload_bytes,entries:entries.map(({path,blob,bytes,sha256,local_json})=>({path,blob,bytes,sha256,local_json}))};
 const mr=JSON.stringify(manifest,null,2)+"\n",mp=await ll("h2-live-"+o.name+"-observer-manifest",mr);add("MANIFEST.public.json",mp);
 const tsdk=await tools.mcp__codex_apps__github_create_tree({repository_full_name:"TrillionniumFoundation/HeptaBao",tree_elements:entries.map(p=>({path:p.path,mode:"100644",type:"blob",content:lt(p)}))});
 const tp=await ll("h2-live-"+o.name+"-Git-batch-original-SDK",JSON.stringify(tsdk,null,2)+"\n");
 const tree=tsdk.structuredContent?.sha;if(tsdk.isError||!(/^[a-f0-9]{40}$/).test(tree))throw Error("original_observer_Git_batch_not_confirmed");
 const uniq=[...new Map(entries.map(p=>[p.blob,p])).values()];
 for(let i=0;i<uniq.length;i+=8){const got=await Promise.allSettled(uniq.slice(i,i+8).map(p=>H.fb(p.blob)));for(let j=0;j<got.length;j++){const p=uniq[i+j],z=got[j];if(z.status!=="fulfilled"||z.value.text!==lt(p)||z.value.bytes!==p.bytes||z.value.sha256!==p.sha256)throw Error("observer_Git_whole_readback:"+p.blob);}}
 const packet=await H.f(tree,"h2_live_observer_packet_"+o.name);
 if(packet.audit.files!==entries.length||packet.audit.bytes!==entries.reduce((z,p)=>z+p.bytes,0)||packet.audit.merkle.leaf_count!==entries.length)throw Error("observer_Git_Merkle_count");
 o.archive={tree,files:packet.audit.files,bytes:packet.audit.bytes,merkle:packet.audit.merkle,manifest:mp,Git_batch_SDK:tp};o.archived=true;s.last_closed_observer=o.name;
 store("h2_live_observer_entries_"+o.name,entries);await hlState(s);
 text({observer:o.name,operation_id:o.operation_id,tool:o.tool,closed:true,archived:true,pages:o.pages.length,payload:o.payload,native:o.native,archive:o.archive,native_keys:n?Object.keys(n):null});
 return o;
}
