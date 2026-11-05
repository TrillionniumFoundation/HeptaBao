function verifyLanInertCore(r, originalReqRaw, helpers) {
 const {utf8,bs,sha,unb64,lossless}=helpers,checks=[];function ck(n,v){if(!v)throw Error(n);checks.push(n);}
 const hash=t=>sha(bs(utf8(t)));function sdk(t){const s=JSON.parse(t);ck("sdk_success_"+checks.length,s.isError===false);const a=s.content.filter(x=>x.type==="text");ck("sdk_one_native_"+checks.length,a.length===1);return{text:a[0].text,v:JSON.parse(a[0].text)};}
 const q=JSON.parse(r["streams/sdk/streams_start/request.json"]),ack=sdk(r["streams/sdk/streams_start/original-sdk.json"]).v,st=sdk(r["streams/sdk/streams_status0/original-sdk.json"]).v;
 ck("only_original_job_read",q.operation.tool==="process_read"&&q.operation.arguments.host==="desktop"&&q.operation.arguments.job_id==="1a1ac1641eb-fc05-521f");
 ck("read_operation_closed",st.operation_id===ack.operation_id&&st.async_state==="completed"&&st.owned_future_active===false&&st.payload_available===true);
 let all="",cursor=0,total=null,h=null;
 for(const off of [0,8192,16384]){const name="streams/sdk/streams_result"+off,req=JSON.parse(r[name+"/request.json"]),p=sdk(r[name+"/original-sdk.json"]).v,b=unb64(p.data_base64);if(total===null){total=p.total_bytes;h=p.result_sha256;}ck("page_identity_"+off,req.operation_id===ack.operation_id&&p.operation_id===ack.operation_id&&p.offset===off&&cursor===off&&req.offset===off);ck("page_payload_binding_"+off,p.total_bytes===total&&p.result_sha256===h&&p.immutable_snapshot===true);ck("page_cursor_"+off,p.next_offset===off+b.length&&b.length<=req.limit);all+=bs(b);cursor+=b.length;ck("page_eof_"+off,p.eof===(cursor===total));}
 ck("whole_original_payload",all===r["streams/operation.payload.json"]&&utf8(all).length===total&&hash(all)===h);
 const n=sdk(all);ck("native_exact",n.text===r["streams/native.public.json"]);ck("native_same_job",n.v.job_id==="1a1ac1641eb-fc05-521f");
 for(const [k,size,path]of [["stdout",5991,"streams/stdout.public.json"],["stderr",0,"streams/stderr.txt"]]){const v=n.v[k];ck(k+"_full_bounds",v.offset===0&&v.next_offset===size&&v.size===size&&v.eof===true);ck(k+"_raw_text",v.text===r[path]&&utf8(v.text).length===size);ck(k+"_hex",utf8(v.text).map(x=>x.toString(16).padStart(2,"0")).join("")===v.bytes_hex);}
 const core=lossless(r["streams/stdout.public.json"]),req=JSON.parse(originalReqRaw),input=JSON.parse(req.stdin);
 ck("prepared_publication_only",core.status==="prepared"&&core.compiler_started===false&&core.git_started===false&&core.service_started===false&&core.source_executed===false);
 ck("stdin_matches_original",core.stdin_bytes===utf8(req.stdin).length&&core.stdin_sha256===hash(req.stdin));
 const names=Object.keys(input.files),base="/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-same-root-publication-pocket3-mac1-postrecovery-cold-control-r1/";
 ck("exact_nine_denominators",names.length===9&&core.files.length===9&&core.syntax.length===9);
 let sum=0;
 for(const name of names){const b=unb64(input.files[name]),f=core.files.find(x=>x.path===base+name),sy=core.syntax.find(x=>x.name===name);ck(name+"_published_pin",!!f&&f.bytes===b.length&&f.sha256===sha(bs(b))&&f.publication==="created");ck(name+"_mode_identity",f.mode==="0600"&&f.identity.length===9&&f.identity[0]===2050&&f.identity[2]===1000&&f.identity[3]===1000&&f.identity[4]===33152&&f.identity[5]===1&&f.identity[6]===b.length);ck(name+"_compile_only",!!sy&&sy.sha256===f.sha256&&sy.ast_parse===true&&sy.compile_only===true&&sy.source_executed===false);sum+=b.length;}
 ck("exact_source_total",sum===357306);
 const start=BigInt(core.started_ns.$exactInteger),end=BigInt(core.terminal_ns.$exactInteger),elapsed=end-start;
 ck("reported_time_within_original60",elapsed>0n&&elapsed<60000000000n&&req.timeout_seconds===60);
 return{schema:"heptabao.original-lan-inert-core-root-review.r1",status:"ORIGINAL_PUBLICATION_IDENTITY_TERMINAL_AND_STREAMS_CLOSED",checks_passed:checks.length,checks,packet:"e531af591121f5ea15ed92a81ea1a582f4ebd6c5",job_id:"1a1ac1641eb-fc05-521f",stdout_bytes:5991,stderr_bytes:0,source_files_created:9,source_bytes:sum,reported_wall_interval_ns:elapsed.toString(),reported_time_is_not_monotonic_deadline_proof:true,original_authority_already_bound:true,source_execution:false,independent_receipt_and_nine_source_readbacks_complete:false,original_ACK_observed:false,original_process_start_replayed:false,prepare_GO:false,LAN_live_GO:false,HA_qualified:false};
}
