function verifyMacInert(data,H){
 const {u,bs,s256,unb64,lossless}=H,raw=data.raw,checks=[],closed=[];
 function ok(n,v){if(!v)throw Error(n);checks.push(n);}
 function hash(t){return s256(bs(u(t)));}
 function canon(v){return JSON.stringify((function sort(x){if(Array.isArray(x))return x.map(sort);if(x&&typeof x==="object")return Object.fromEntries(Object.keys(x).sort().map(k=>[k,sort(x[k])]));return x;})(v));}
 function dec(x){return x&&typeof x==="object"&&"$exactInteger" in x?x.$exactInteger:String(x);}
 function nat(t,n){const o=lossless(t);ok(n+":sdk-not-error",o.isError!==true);const c=o.content?.filter(x=>x.type==="text");ok(n+":one-text",c?.length===1);return {text:c[0].text,value:lossless(c[0].text)};}
 const index=lossless(raw["operations/index.public.json"]),root="/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261105-official271-full34-4e808-r1",job="1a1ac8387b9-fc05-54e4",expectedTools=["process_status","process_read","file_info","file_info","read_multiple_files"];
 ok("five-original-observers",index.length===5&&new Set(index.map(x=>x.operation_id)).size===5&&canon(index.map(x=>x.name))===canon(["authority","streams","wrapper-info","receipt-info","bodies"]));
 for(let i=0;i<index.length;i++){
  const e=index[i],n=e.name,d="reads/"+n,req=e.request,intent=lossless(raw[d+"/intent.public.json"]),ack=nat(raw[d+"/admission.original.sdk.json"],n+":ack"),st=nat(raw[d+"/status.original.sdk.json"],n+":status");
  ok(n+":exact-intent",canon(intent.request)===canon(req)&&intent.submitted===false&&intent.read_only===true&&req.operation.tool===expectedTools[i]&&req.operation.arguments.host==="mac");
  ok(n+":ack-native-and-id",ack.text===raw[d+"/admission.original.native.json"]&&ack.value.operation_id===e.operation_id&&ack.value.tool_name===req.operation.tool&&ack.value.reused===false&&ack.value.idempotency_binding_retained===true);
  ok(n+":status-native-and-closure",st.text===raw[d+"/status.original.native.json"]&&st.value.operation_id===e.operation_id&&st.value.tool_name===req.operation.tool&&st.value.async_state==="completed"&&st.value.result_state==="stored_observed"&&st.value.owned_future_active===false&&st.value.payload_available===true);
  const payload=raw[d+"/immutable-payload.original.json"],bytes=u(payload);let cursor=0,parts=[];
  for(const p of e.pages){
   const pg=nat(raw[p.sdk.path],n+":page"+p.offset),v=pg.value,b=unb64(v.data_base64);
   ok(n+":page"+p.offset+"-exact-native",pg.text===raw[p.native.path]);
   ok(n+":page"+p.offset+"-bound-range",v.operation_id===e.operation_id&&v.offset===cursor&&v.offset===p.offset&&v.next_offset===cursor+b.length&&b.length===p.bytes&&b.length<=16384);
   ok(n+":page"+p.offset+"-immutable-result",v.immutable_snapshot===true&&v.payload_kind==="native_result"&&v.total_bytes===bytes.length&&v.result_sha256===hash(payload)&&v.eof===(v.next_offset===bytes.length));
   parts.push(...b);cursor=v.next_offset;
  }
  ok(n+":whole-original-sdk",cursor===bytes.length&&cursor===e.total_bytes&&hash(payload)===e.result_sha256&&bs(parts)===bs(bytes));
  const result=nat(payload,n+":whole");ok(n+":outcome-exact",result.text===raw[e.outcome.path]);
  closed.push({name:n,operation_id:e.operation_id,pages:e.pages.length,payload_bytes:cursor,payload_sha256:hash(payload),completed:true,owned_future_active:false});
 }
 const au=lossless(raw["actual/authority.original.json"]),streams=lossless(raw["actual/streams.original.json"]),wi=lossless(raw["actual/wrapper-info.original.json"]),ri=lossless(raw["actual/receipt-info.original.json"]),body=lossless(raw["actual/bodies.original.json"]),receipt=lossless(raw["actual/inert-stage.result.public.json"]),stdout=raw["actual/stdout.original.log"],stderr=raw["actual/stderr.original.log"];
 ok("same-original-terminal-job",au.job_id===job&&streams.job_id===job&&au.launch_nonce==="de389a89fa60f6cd426a08c7265d8681"&&au.state==="succeeded"&&au.exit_code===0&&!au.timed_out&&!au.cancelled);
 ok("authority-full-durable",au.output_complete===true&&au.output_durable===true&&au.terminal_publication_confirmed===true&&["stdout","stderr"].every(s=>au.log_synced[s]===true&&au.log_truncated[s]===false&&au.log_errors[s]===null));
 for(const [s,t,size] of [["stdout",stdout,854],["stderr",stderr,0]]){
  const x=streams[s],hex=u(t).map(b=>b.toString(16).padStart(2,"0")).join("");
  ok(s+":whole-authoritative-stream",x.text===t&&x.bytes_hex===hex&&u(t).length===size&&x.size===size&&x.offset===0&&x.next_offset===size&&x.eof===true&&au.log_bytes[s].seen===size&&au.log_bytes[s].stored===size);
 }
 ok("inert-request-unchanged",raw["reference/exact-inert-request.public.json"]===data.exact_inert_request);
 const ack=nat(raw["actual/start.original.sdk.json"],"process-start");
 ok("start-native-exact",ack.text===raw["actual/start.original.native.json"]);
 ok("receipt-stdout-lossless-equal",canon(receipt)===canon(lossless(stdout)));
 ok("inert-only-flags",receipt.status==="prepared"&&receipt.root_created===true&&receipt.control_created===true&&receipt.python_compile_only===true&&receipt.source_executed===false&&receipt.git_started===false&&receipt.compiler_started===false&&receipt.service_started===false&&receipt.artifact_transfer_started===false&&receipt.files.length===1);
 ok("stdin-original-pin",receipt.stdin_bytes===27485&&receipt.stdin_sha256==="39519775637edd562521696958f2bed6620e4d834618b794d307fee4cb6bcd87");
 ok("two-individual-complete-files",body.atomic_snapshot===false&&body.encoding==="utf-8"&&body.files.length===2&&body.files.every(x=>x.eof===true));
 const specs=[["wrapper",wi,root+"/control/run_current_mac_full34_r1.py","actual/run_current_mac_full34_r1.py"],["receipt",ri,root+"/control/inert-stage.result.public.json","actual/inert-stage.result.public.json"]];
 for(const [n,info,path,p] of specs){
  const f=body.files.find(x=>x.path===path),t=raw[p];
  ok(n+":independent-info-and-whole",info.path===path&&f?.text===t&&f.size===info.size&&f.sha256===info.sha256&&f.version===info.version&&u(t).length===info.size&&hash(t)===info.sha256);
  ok(n+":owned-single-link-mode",info.mode===384&&info.metadata.mode===384&&info.metadata.uid===501&&info.metadata.gid===20&&info.metadata.link_count===1);
 }
 const v=wi.version.split(":"),actual9=[v[0],v[1],"501","20","33152","1",String(wi.size),v[3],v[4]];
 ok("wrapper-publisher-full9-exact",canon(actual9)===canon(receipt.files[0].identity.map(dec))&&receipt.files[0].path===wi.path&&receipt.files[0].publication==="created"&&receipt.files[0].bytes===wi.size&&receipt.files[0].sha256===wi.sha256);
 ok("wrapper-review-bytes-exact",raw["actual/run_current_mac_full34_r1.py"]===data.reviewed_wrapper&&wi.size===20538&&wi.sha256==="29785927055d2e676c702aa79b97db9a6d274d8d8de0916073c08face41c6c9a");
 return {schema:"heptabao.root-mac-current34-inert-whole-review.r29.v1",status:"PASS_INERT_PUBLICATION_ONLY",packet_tree:"1571044456e90e23cff4443d88d92840b81439a9",packet:{files:67,bytes:718950,merkle_trees:12},check_count:checks.length,checks,original_job:"mac/"+job,previous_request_ack_authority_review:"8988752c3258150793476ef02fd5511cdae4f348",closed_observers:closed,stdout:{bytes:854,sha256:hash(stdout)},stderr:{bytes:0,sha256:hash(stderr)},wrapper:{bytes:wi.size,sha256:wi.sha256,version:wi.version,full9_decimal:actual9},receipt:{bytes:ri.size,sha256:ri.sha256,version:ri.version},conditional_prepare_go:"a03f7aa41b6c081113811fb0ab154ad534a4f65f",inert_conditions_satisfied:true,root_runtime_calls:0,live_GO:false,full34_qualified:false,full_replacement_qualified:false};
}
