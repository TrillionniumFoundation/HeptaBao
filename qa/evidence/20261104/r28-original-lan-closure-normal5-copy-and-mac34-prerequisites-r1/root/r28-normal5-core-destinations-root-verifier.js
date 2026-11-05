function verifyNormal5CoreAndDestinations(r,d,h){
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
 const authority=observe(r,"authority","authority/sdk/authority_start","authority/sdk/authority_status0",["authority/sdk/authority_result0"],"authority/operation.payload.json","authority/authority.public.json","process_status");
 const streams=observe(r,"streams","streams/sdk/streams_start","streams/sdk/streams_status0",["streams/sdk/streams_result0"],"streams/operation.payload.json","streams/native.public.json","process_read");
 const info=observe(r,"receipt_info","detail-observation/result_info_start","detail-observation/result_info_status0",["detail-observation/result_info_result0"],"detail-observation/result-info.payload.json","detail-observation/result-info.native.json","file_info");
 const body=observe(r,"receipt_body","detail-observation/result_body_start","recovery/sdk/result_body_status1",[0,8192,16384,24576].map(n=>"recovery/sdk/result_body_result"+n),"recovery/original-operation-payload.json","recovery/native-result-body.json","binary_read");
 ck("first_status_transport_error_preserved",parse(r["detail-observation/result_body_status0/original-sdk.json"]).isError===true);
 ck("same_id_status_reconciliation",parse(r["detail-observation/result_body_status0/request.json"]).operation_id===ops[3].operation_id&&ops[3].operation_id==="ba463b00bbd59bf90f034f0c81c9c2f58cd858cec2683e6b240047504571f544");
 const a=authority.native,s=streams.native,i=info.native,b=body.native,c=parse(r["actual/result.public.json"]),terminal=parse(r["streams/stdout.public.json"]);
 ck("original_job_and_terminal_authority",a.job_id==="1a1ac4bdf19-fc05-5366"&&s.job_id===a.job_id&&authority.request.job_id===a.job_id&&streams.request.job_id===a.job_id&&a.exit_code===0&&a.state==="succeeded"&&a.output_complete===true&&a.output_durable===true&&a.terminal_publication_confirmed===true&&!a.cancelled&&!a.timed_out);
 for(const name of["stdout","stderr"]){const x=s[name],hex=bs(Array.from({length:x.bytes_hex.length/2},(_,j)=>parseInt(x.bytes_hex.slice(2*j,2*j+2),16)));ck(name+"_whole_original_stream",x.offset===0&&x.next_offset===x.size&&x.eof===true&&hex===bs(utf8(x.text))&&x.text===r[name==="stdout"?"streams/stdout.public.json":"streams/stderr.txt"]&&a.log_bytes[name].seen===x.size&&a.log_bytes[name].stored===x.size&&a.log_synced[name]===true&&a.log_truncated[name]===false&&a.log_errors[name]===null);}
 ck("terminal_summary",s.stdout.size===365&&s.stderr.size===0&&terminal.status==="transferred"&&terminal.all_owned_stopped===true&&terminal.publication_within_original_deadline===true&&terminal.elapsed_after_publication_seconds<300&&terminal.compiler_started===false&&terminal.server_started===false&&terminal.git_operations===0);
 const coreBytes=unb64(b.data_base64);
 ck("receipt_original_whole_bytes",bs(coreBytes)===bs(utf8(r["actual/result.public.json"]))&&coreBytes.length===18565&&sha(bs(coreBytes))===i.sha256&&b.chunk_sha256===i.sha256&&i.sha256==="de4d20a2eb6551a3f0237f7f6093623f14d06fc08a8af9f75491f00a31bbcbb4");
 ck("receipt_read_version_and_eof",b.offset===0&&b.next_offset===i.size&&b.size===i.size&&b.eof===true&&b.version===i.version&&body.request.expected_version===i.version&&body.request.limit===i.size&&body.request.offset===0);
 ck("receipt_exact_paths",body.request.path===i.path&&info.request.path===i.path&&b.path===i.path&&terminal.receipt===i.path&&i.path===c.destination_root+"/control/result.public.json");
 ck("receipt_metadata",i.mode===384&&i.metadata.uid===1000&&i.metadata.gid===1000&&i.metadata.link_count===1);
 ck("product_identity",c.source_commit==="4e808d0ecb1bcded22870a7ec960dfb2491cf6ec"&&c.source_tree==="eba5e650bd080b8ad41ea52a2bc68867f541d255");
 ck("relay_success_and_original_budgets",c.status==="transferred"&&c.overall_seconds===300&&c.endpoint_seconds===90&&c.ssh_child_seconds===90&&c.elapsed_seconds<300);
 ck("all_cleanup_known",c.all_local_owned_stopped===true&&c.all_owned_stopped===true&&c.remote_endpoint_completion_verified===true&&c.remote_cleanup_unknown===false&&c.cleanup_errors.length===0);
 ck("limited_scope",c.automatic_retry===false&&c.production_changed===false&&c.compiler_started===false&&c.server_started===false&&c.git_operations===0&&c.runtime_qualification===false);
 const labels=["rog-ts-effective-config","send-rog","receive-desktop"];
 ck("three_original_unique_children",c.commands.length===3&&c.cleanup.length===3&&eq(c.commands.map(x=>x.label).sort(),labels.slice().sort())&&new Set(c.commands.map(x=>x.pid)).size===3);
 for(const cmd of c.commands){const clean=c.cleanup.find(x=>x.label===cmd.label);ck("closed_child_"+cmd.label,cmd.exit_code===0&&cmd.direct_child_reaped===true&&cmd.remaining.length===0&&cmd.timed_out===false&&cmd.limit_seconds===90&&cmd.elapsed_seconds<90&&clean.pid===cmd.pid&&clean.exit_code===0&&clean.direct_child_reaped===true&&clean.remaining.length===0);}
 ck("trust_and_existing_controller_unchanged",eq(c.trust_before,c.trust_after)&&eq(c.original_ha_controller_before,c.original_ha_controller_after));
 ck("exact_relay_source",c.controller.bytes===utf8(r["references/relay.py"]).length&&c.controller.sha256===hash(r["references/relay.py"])&&c.controller.sha256==="075193b0494e4cffc87aedebd1ac2407efef8007963aa6ff48388095d5967ad4");
 for(const name of["sender.py","receiver.py"])ck("exact_helper_"+name,c.helpers[name].sha256===hash(r["references/"+name])&&c.helpers[name].bytes===utf8(r["references/"+name]).length&&c.helpers[name].identity[5]===1);
 const literal=JSON.parse(r["references/relay.py"].match(/\nFILES=(\[[\s\S]*?\n\])\nHELPERS=/)[1]);
 ck("exact_five_frozen_files",eq(literal,c.files)&&literal.length===5&&literal.reduce((s,x)=>s+x.bytes,0)===110287359);
 for(const role of["sender","receiver"]){const e=c[role];ck(role+"_current_identity",e.source_commit===c.source_commit&&e.source_tree===c.source_tree&&e.role===role&&e.schema==="heptabao.4e808.fixed-public-normal-endpoint.v1");ck(role+"_known_complete",e.status==="complete"&&e.files.length===5&&e.all_owned_stopped===true&&e.cleanup.length===0&&e.cleanup_errors.length===0&&e.request_seconds===90&&e.elapsed_seconds<90&&e.within_original_deadline===true&&e.compiler_started===false&&e.server_started===false&&e.git_operations===0);}
 ck("receiver_create_only_and_fsync",c.receiver.destination_created_exclusive===true&&c.receiver.destination_fsynced===true&&c.receiver.destination_directory_mode===320&&c.receiver.raw_receipts_preserved===true&&c.receiver.normal_release_provenance_verified===true);
 const frozen=parse(r["destination-plan.unbound.public.json"]).files,dp=parse(d["original-fixed-plan.public.json"]);
 ck("destination_plan_exact",eq(dp,frozen));
 const destinations=[];
 for(let n=0;n<5;n++){const f=c.files[n],sent=c.sender.files[n],recv=c.receiver.files[n],plan=dp[n],base="destination/"+n+"-"+f.name,label="dest"+n;
  ck(label+"_whole_source_stream",sent.name===f.name&&sent.source===f.path&&sent.source_version===f.version&&sent.initial_file.bytes===f.bytes&&sent.initial_file.sha256===f.sha256&&eq(sent.initial_file,sent.stream));
  ck(label+"_source_full9_unchanged",eq(sent.source_identity_before,sent.source_identity_after)&&version(sent.source_identity_before)===f.version&&sent.source_identity_before[2]===1000&&sent.source_identity_before[3]===1000&&sent.source_identity_before[4]===32768+f.source_mode&&sent.source_identity_before[5]===1);
  ck(label+"_receiver_whole_file",recv.name===f.name&&recv.path===plan.path&&recv.bytes===f.bytes&&recv.sha256===f.sha256&&recv.mode===f.target_mode&&recv.same_fd_readback.bytes===f.bytes&&recv.same_fd_readback.sha256===f.sha256&&recv.create_only===true&&recv.fsynced===true);
  const q=parse(d[base+"/sdk/destination"+n+"_info_start/request.json"]);
  ck(label+"_exact_original_info_request",eq(q,plan.info_request));
  const observed=observe(d,label,base+"/sdk/destination"+n+"_info_start",base+"/sdk/destination"+n+"_info_status0",[base+"/sdk/destination"+n+"_info_result0"],base+"/operation.original-payload.json",base+"/file-info.native.json","file_info").native;
  ck(label+"_independent_bytes_sha_path",observed.path===recv.path&&observed.size===recv.bytes&&observed.sha256===recv.sha256);
  ck(label+"_independent_version_full9",observed.version===version(recv.identity)&&observed.mode===recv.mode&&observed.metadata.mode===recv.mode&&observed.metadata.uid===recv.identity[2]&&observed.metadata.gid===recv.identity[3]&&observed.metadata.link_count===recv.identity[5]&&recv.identity[4]===32768+recv.mode&&recv.identity[5]===1);
  ck(label+"_frozen_predicates",observed.size===plan.expected_bytes&&observed.sha256===plan.expected_sha256&&observed.mode===plan.expected_mode&&observed.metadata.uid===plan.expected_uid&&observed.metadata.gid===plan.expected_gid&&observed.metadata.link_count===plan.expected_nlink);
  destinations.push({name:f.name,path:observed.path,bytes:observed.size,sha256:observed.sha256,version:observed.version,mode:observed.mode,uid:observed.metadata.uid,gid:observed.metadata.gid,nlink:observed.metadata.link_count});
 }
 return {schema:"heptabao.normal5-original-core-and-destinations-root-review.r1",status:"ACTUAL_COPY_AND_FIVE_INDEPENDENT_DESTINATIONS_VERIFIED",checks_passed:checks.length,checks,job_id:a.job_id,core_packet:"24cb411cf4c6154df92b9f4913e15fecad3ff593",destination_packet:"46c580276073ea792075e06ba9fac34e89a660b0",original_status_timeout_preserved:true,original_operation_recovered_without_native_reread:true,observations:ops,files:destinations,bytes:110287359,original_commands:3,all_children_closed:true,original_command_raw_archive_pending:true,aggregate_fd_ledger_present:false,consumer_go:false,LAN_prepare_or_live_go:false,full_replacement_qualified:false};
}
