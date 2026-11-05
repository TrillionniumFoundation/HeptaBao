function verifyLanOriginalIdentity(raw, authorityRaw, originalRequestRaw, proofRaw, searchDto, helpers) {
 const {utf8,bs,sha,unb64,lossless}=helpers, checks=[];const ck=(n,v)=>{if(!v)throw Error(n);checks.push(n);};
 const hash=t=>sha(bs(utf8(t)));
 function nsdk(t){const s=JSON.parse(t);ck("sdk_not_error_"+checks.length,s.isError===false);const a=s.content.filter(x=>x.type==="text");ck("sdk_single_native_"+checks.length,a.length===1);return {text:a[0].text,data:JSON.parse(a[0].text)};}
 function opChain(r,base,status,results,wantTool,wantNative){
  const request=JSON.parse(r["sdk/"+base+"_start/request.json"]);
  ck(base+"_tool",request.operation.tool===wantTool);ck(base+"_host",request.operation.arguments.host==="desktop");
  const ack=nsdk(r["sdk/"+base+"_start/original-sdk.json"]).data;
  const stat=nsdk(r["sdk/"+base+"_"+status+"/original-sdk.json"]).data;
  ck(base+"_same_op",ack.operation_id===stat.operation_id);ck(base+"_closed",stat.async_state==="completed"&&stat.owned_future_active===false&&stat.payload_available===true);
  let payload="",cursor=0,total=null,digest=null;
  for(const name of results){const q=JSON.parse(r["sdk/"+name+"/request.json"]),p=nsdk(r["sdk/"+name+"/original-sdk.json"]).data,b=unb64(p.data_base64),piece=bs(b);ck(name+"_id_offset",q.operation_id===ack.operation_id&&p.operation_id===ack.operation_id&&q.offset===cursor&&p.offset===cursor);ck(name+"_cursor",p.next_offset===cursor+b.length&&b.length<=q.limit);ck(name+"_immutable",p.immutable_snapshot===true);if(total===null){total=p.total_bytes;digest=p.result_sha256;}ck(name+"_same_payload",total===p.total_bytes&&digest===p.result_sha256);payload+=piece;cursor+=b.length;ck(name+"_eof",p.eof===(cursor===total));}
  ck(base+"_whole_payload",cursor===total&&hash(payload)===digest);
  const native=nsdk(payload);ck(base+"_native_byte_exact",native.text===wantNative);
  return{request,ack,stat,payload,native:native.data};
 }
 const orig=JSON.parse(originalRequestRaw),actual=JSON.parse(raw["request-body.verified-public.json"]),info=JSON.parse(raw["request-info.native.json"]),stdin=JSON.parse(raw["stdin-info.native.json"]);
 function binding(q){return{args:q.args,cpu_quota_percent:q.cpu_quota_percent??null,cwd:q.cwd??null,env:Object.fromEntries(Object.entries(q.env??{}).sort()),executable:q.executable,host:q.host,memory_max_bytes:q.memory_max_bytes??null,nice:q.nice??null,stdin:q.stdin??null,timeout_seconds:q.timeout_seconds??null};}
 const pos=JSON.parse(proofRaw["positive-control/exact-request.json"]),pa=lossless(proofRaw["positive-control/ack.original.json"]),pd=hash(JSON.stringify(binding(pos))),td=hash(JSON.stringify(binding(orig)));
 ck("positive_binding_digest_exact",pd===pa.job.request_digest);ck("positive_fingerprint_exact",BigInt("0x"+pd.slice(0,16)).toString()===pa.job.request_fingerprint.$exactInteger);
 ck("target_binding_digest_exact",td==="5df3e472d540fcee1b5d2534607d051900f9abd52f979f156e822f7a752802f0");
 const job="1a1ac1641eb-fc05-521f",dir="/home/qian-qi/.local/state/hepta-runtime-mac-worker/jobs/"+job;
 ck("actual_full_digest",actual.request_digest===td&&actual.request_fingerprint===td);ck("actual_job",actual.job_id===job&&actual.job_dir===dir&&actual.stdin_path===dir+"/stdin.bin");
 for(const k of ["args","executable","cwd","timeout_seconds"])ck("actual_typed_"+k,JSON.stringify(actual[k])===JSON.stringify(orig[k]));
 ck("remote_normalized_defaults",actual.nice===0&&actual.cpu_quota_percent===null&&actual.memory_max_bytes===null&&JSON.stringify(actual.env)==="{}");
 ck("no_remote_host_key_or_inline_stdin",!Object.hasOwn(actual,"host")&&!Object.hasOwn(actual,"idempotency_key")&&!Object.hasOwn(actual,"stdin"));
 ck("original_host_key",orig.host==="desktop"&&orig.idempotency_key==="heptabao-4e808-postcold-inert-r1-57cb2b31-7ee5ee82");
 ck("platform_mode_protocol",actual.platform==="linux"&&actual.execution_mode==="operator"&&actual.terminal_publication_protocol===1);
 const i=opChain(raw,"request_info","status1",["request_info_result0"],"file_info",raw["request-info.native.json"]);
 ck("info_fixed_path",i.request.operation.arguments.path===dir+"/request.json"&&info.path===dir+"/request.json");
 const b=opChain(raw,"request_body","status0",["request_body_result0","request_body_result8192"],"binary_read",raw["native/request-body.binary-read.json"]);
 const body=bs(unb64(b.native.data_base64));
 ck("binary_fixed_path_version",b.request.operation.arguments.path===info.path&&b.request.operation.arguments.expected_version===info.version&&b.native.path===info.path&&b.native.version===info.version);
 ck("binary_whole_bounds",b.native.offset===0&&b.native.eof===true&&b.native.next_offset===8101&&b.native.size===8101&&utf8(body).length===8101);
 ck("whole_request_byte_exact",body===raw["request-body.verified-public.json"]);
 ck("whole_request_sha",hash(body)===info.sha256&&hash(body)===b.native.chunk_sha256&&info.size===8101);
 const si=opChain(raw,"stdin_info","status0",["stdin_info_result0"],"file_info",raw["stdin-info.native.json"]);
 ck("stdin_fixed_path",si.request.operation.arguments.path===dir+"/stdin.bin"&&stdin.path===dir+"/stdin.bin");
 ck("stdin_whole_original_size_hash",stdin.size===utf8(orig.stdin).length&&stdin.size===477056&&stdin.sha256===hash(orig.stdin));
 for(const [n,f] of [["request",info],["stdin",stdin]])ck(n+"_private_regular_metadata",f.mode===384&&f.metadata.mode===384&&f.metadata.uid===1000&&f.metadata.gid===1000&&f.metadata.link_count===1);
 ck("search_one_path",searchDto.snapshot.results.length===1&&searchDto.snapshot.results[0].path===job+"/request.json");
 ck("search_preview_matches_public_file_prefix",searchDto.snapshot.results[0].preview===body.slice(0,512));
 ck("first_info_timeout_preserved",JSON.parse(raw["sdk/request_info_status0/original-sdk.json"]).isError===true);
 const au=opChain(authorityRaw,"authority","status0",["authority_result0"],"process_status",authorityRaw["authority.public.json"]);
 ck("authority_exact_job_argument",au.request.operation.arguments.job_id===job);
 const a=au.native;ck("authority_original_job_nonce",a.job_id===job&&a.launch_nonce===actual.launch_nonce);
 ck("authority_succeeded_zero",a.state==="succeeded"&&a.exit_code===0&&a.timed_out===false&&a.cancelled===false);
 ck("authority_complete_durable",a.output_complete===true&&a.output_durable===true&&a.terminal_publication_confirmed===true&&a.terminal_publication_protocol===1);
 ck("authority_exact_logs",a.log_bytes.stdout.seen===5991&&a.log_bytes.stdout.stored===5991&&a.log_bytes.stderr.seen===0&&a.log_bytes.stderr.stored===0);
 ck("authority_no_log_loss",a.log_errors.stdout===null&&a.log_errors.stderr===null&&a.log_truncated.stdout===false&&a.log_truncated.stderr===false&&a.log_synced.stdout===true&&a.log_synced.stderr===true);
 return{schema:"heptabao.original-lan-request-and-authority-root-review.r1",status:"EXACT_ORIGINAL_REQUEST_STDIN_AND_TERMINAL_BOUND",checks_passed:checks.length,checks,job_id:job,host:"desktop",request_digest:td,original_ack_observed:false,original_process_start_replayed:false,original_delivery_timeout_preserved:true,original_typed_digest_positive_control:pd,identity_packet:"c99fe571b39012301c8c2273b02414b9be5ff0d7",authority_packet:"a5795dd12ccfcc81c141dede62bc79d873cb3473",original_request:"70f27390d318755075562482091b3bf27946b37d",actual_request:"11760b8f9d94126912ef592ea41943617411f0e7",authority:a,actual_stdout_body_reviewed:false,receipt_and_nine_source_readbacks_pending:true,scope:"Recovery of the original public compile-only publication identity and authoritative termination; not LAN/HA runtime qualification or full source-stage qualification."};
}
