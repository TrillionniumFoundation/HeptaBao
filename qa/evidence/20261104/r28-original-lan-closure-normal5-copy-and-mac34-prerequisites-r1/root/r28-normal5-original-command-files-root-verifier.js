function verifyNormal5RawCommands(r,c,h){
 const {parse,utf8,bs,sha,unb64}=h,checks=[],ops=[];
 const hash=t=>sha(bs(utf8(t))), canon=v=>JSON.stringify(sort(v));
 function sort(v){if(Array.isArray(v))return v.map(sort);if(v&&typeof v==="object")return Object.fromEntries(Object.keys(v).sort().map(k=>[k,sort(v[k])]));return v;}
 const eq=(a,b)=>canon(a)===canon(b), intstr=v=>v&&typeof v==="object"?v.$exactInteger:String(v), version=a=>[0,1,6,7,8].map(i=>intstr(a[i])).join(":");
 function ck(n,v){if(!v)throw Error(n);checks.push(n);}
 function sdk(t,label){const x=parse(t);ck(label+"_isError_false",x.isError===false);const c=x.content.filter(y=>y.type==="text");ck(label+"_one_native_text",c.length===1);return {text:c[0].text,value:parse(c[0].text)};}
 function observe(raw,label,start,status,pages,payloadPath,nativePath,type){
  const q=parse(raw[start+"/request.json"]),ack=sdk(raw[start+"/original-sdk.json"],label+"_ack").value,stq=parse(raw[status+"/request.json"]),st=sdk(raw[status+"/original-sdk.json"],label+"_status").value;
  ck(label+"_typed_start",q.operation.tool===type&&q.operation.arguments.host==="desktop"&&ack.tool_name===type);
  ck(label+"_closed_original_operation",ack.operation_id===stq.operation_id&&st.operation_id===ack.operation_id&&st.async_state==="completed"&&st.owned_future_active===false&&st.payload_available===true&&st.result_state==="stored_observed");
  let payload="",offset=0,total=null,whole=null;
  for(const base of pages){const pq=parse(raw[base+"/request.json"]),p=sdk(raw[base+"/original-sdk.json"],label+"_page"+offset).value,b=unb64(p.data_base64);
   if(total===null){total=p.total_bytes;whole=p.result_sha256;}
   ck(label+"_page_identity_"+offset,pq.operation_id===ack.operation_id&&p.operation_id===ack.operation_id&&pq.offset===offset&&p.offset===offset);
   ck(label+"_immutable_original_payload_"+offset,p.immutable_snapshot===true&&p.payload_kind==="native_result"&&p.total_bytes===total&&p.result_sha256===whole&&p.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization");
   ck(label+"_page_bounds_"+offset,p.next_offset===offset+b.length&&b.length<=pq.limit&&p.next_offset<=total&&p.eof===(p.next_offset===total));
   payload+=bs(b);offset=p.next_offset;
  }
  ck(label+"_complete_byte_exact_payload",offset===total&&sha(payload)===whole&&payload===raw[payloadPath]);
  const original=sdk(payload,label+"_original"),native=parse(raw[nativePath]);
  ck(label+"_native_equal",eq(original.value,native));
  ops.push({label,operation_id:ack.operation_id,tool:type,original_payload_bytes:total,original_payload_sha256:whole,closed:true});
  return {request:q.operation.arguments,native};
 }

 const b="original-command-observation",o=observe(r,"original_command_archive",b+"/sdk/original10_start",b+"/sdk/original10_status0",[0,8192,16384,24576].map(n=>b+"/sdk/original10_result"+n),b+"/original-operation-payload.json",b+"/native.json","read_multiple_files"),native=o.native,request=parse(r[b+"/plan/request.json"]),plan=parse(r[b+"/plan/read-plan.public.json"]);
 ck("exact_fixed_request",eq(request,parse(r[b+"/sdk/original10_start/request.json"]))&&eq(request,plan.request)&&o.request.max_file_bytes===65536&&o.request.max_response_bytes===131072);
 ck("ten_exact_paths",native.files.length===10&&eq(native.files.map(x=>x.path),o.request.paths)&&native.truncated===false&&native.encoding==="utf-8"&&native.atomic_snapshot===false);
 const files=[];
 for(const f of native.files){const name=f.path.slice(f.path.lastIndexOf("/")+1),raw=r["original-command-files/"+name];ck("whole_original_file_"+name,f.eof===true&&typeof raw==="string"&&raw===f.text&&utf8(raw).length===f.size&&hash(raw)===f.sha256);files.push({name,bytes:f.size,sha256:f.sha256,version:f.version});}
 ck("exact_saved_total",files.reduce((s,x)=>s+x.bytes,0)===18391);
 ck("three_actual_command_records",c.commands.length===3);
 for(const cmd of c.commands)ck("original_record_equals_core_"+cmd.label,eq(parse(r["original-command-files/"+cmd.label+".public.json"]),cmd));
 ck("sender_raw_stderr_equals_core",eq(parse(r["original-command-files/send-rog.stderr"]),c.sender));
 ck("receiver_raw_stderr_equals_core",eq(parse(r["original-command-files/receive-desktop.stderr"]),c.receiver));
 ck("preflight_equals_core",eq(parse(r["original-command-files/ssh-preflight.public.json"]),c.ssh_preflight));
 ck("config_stdout_whole_sha",hash(r["original-command-files/rog-ts-effective-config.stdout"])===c.ssh_preflight["rog-ts"].effective_config_sha256);
 ck("two_exact_empty_saved_streams",r["original-command-files/rog-ts-effective-config.stderr"]===""&&r["original-command-files/receive-desktop.stdout"]==="");
 ck("no_fabricated_sender_stdout",!Object.hasOwn(r,"original-command-files/send-rog.stdout")&&!o.request.paths.some(x=>x.endsWith("/send-rog.stdout"))&&r["core/references/relay.py"].includes("stdout=subprocess.PIPE"));
 const intent=parse(r["original-command-files/intent.public.json"]);
 for(const key of["controller","helpers","files","source_commit","source_tree","destination_root","source_alias","destination_host","overall_seconds","endpoint_seconds","ssh_child_seconds","trust_before"])ck("intent_to_terminal_"+key,eq(intent[key],c[key]));
 ck("intent_existing_controller",eq(intent.original_ha_controller,c.original_ha_controller_before));
 ck("intent_create_only",intent.destination_create_only===true&&intent.automatic_retry===false&&intent.compiler_started===false&&intent.server_started===false&&intent.git_operations===0&&intent.production_changed===false);
 return {schema:"heptabao.normal5-original-command-files-root-review.r1",status:"ORIGINAL_THREE_COMMAND_RECORDS_AND_FIVE_SAVED_STREAMS_COMPLETE",packet:"e049198ac8e32db82bedbd1ebc1a1f88eec3c71d",previous_core_destination_review:"7cfa7703c5f22a18ac668cb0c48b1786e5df7d29",checks_passed:checks.length,checks,observations:ops,files,original_file_bytes:18391,original_command_records:3,original_saved_streams:5,other_files:2,sender_stdout:"Original binary pipe, no separately saved file or invented file.",initial_intent_status:"The pre-execution intent retains its initialized status failed; actual later authority and terminal core prove success.",atomic_snapshot_claimed:false,original_command_archive_pending:false,aggregate_fd_ledger_present:false,copy_verified:true,consumer_runtime_started:false,LAN_prepare_or_live_go:false,full_replacement_qualified:false};
}
