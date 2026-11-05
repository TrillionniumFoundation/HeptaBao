function verifyCarrierInert(data,H){
const {u,bs,s256,unb64,lossless,binder}=H,r=data.raw,c=[],ops=[],files=[];const job="1a1aca557a2-fc05-561b",base="/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-same-root-publication-source-carrier-controls-r1";
function ok(n,v){if(!v)throw Error(n);c.push(n);}function hash(t){return s256(bs(u(t)));}function dec(x){return x&&typeof x==="object"&&"$exactInteger"in x?x.$exactInteger:String(x);}
function canon(x){return JSON.stringify((function f(v){if(Array.isArray(v))return v.map(f);if(v&&typeof v==="object")return Object.fromEntries(Object.keys(v).sort().map(k=>[k,f(v[k])]));return v;})(x));}
function nat(t,n){const s=lossless(t);ok(n+":SDK-not-error",s.isError!==true);const a=s.content?.filter(x=>x.type==="text");ok(n+":one-text",a?.length===1);return {t:a[0].text,v:lossless(a[0].text)};}
const req=lossless(r["ack/exact-request.json"]),ack=nat(r["ack/original-sdk.json"],"original-start").v,state=lossless(r["state.public.json"]),intent=lossless(r["intent/execution-intent.public.json"]);
ok("original-exact-request-and-intent",r["ack/exact-request.json"]===data.request&&r["intent/request.json"]===data.request&&u(data.request).length===intent.exact_request.bytes&&hash(data.request)===intent.exact_request.sha256);
ok("original-code-and-stdin",req.args.length===5&&req.args.slice(0,4).join(" ")==="-I -S -B -c"&&req.args[4]===data.inert&&req.stdin===data.payload&&req.timeout_seconds===60&&r["source/inert.py"]===data.inert&&r["source/payload.json"]===data.payload);
const digest=hash(binder(req));const j=ack.job;
ok("ACK-original-job-and-digest",j.id===job&&j.host==="desktop"&&j.idempotency_key===req.idempotency_key&&j.request_digest===digest&&dec(j.request_fingerprint)===BigInt("0x"+digest.slice(0,16)).toString());
ok("ACK-original-arguments",canon(j.args)===canon(req.args)&&j.executable===req.executable&&j.cwd===req.cwd&&canon(j.env_keys)===canon([]));
ok("ACK-launched-once",j.launch_state==="launched"&&j.launch_error===null&&ack.reused===false&&ack.local_record_pending===false&&ack.launch.ok===true);
const expectedNames=["authority","streams","file0_info","file1_info","file2_info","file3_info","whole_four"];
ok("seven-original-observers",canon(state.observations.map(x=>x.name))===canon(expectedNames)&&new Set(state.observations.map(x=>x.operation_id)).size===7);
for(const e of state.observations){
 const n=e.name,p="observations/"+n,req=lossless(r[p+"/intent/request.json"]),ri=lossless(r[p+"/intent/read-intent.public.json"]),a=nat(r[p+"/sdk/"+n+"_start/original-sdk.json"],n+":ACK").v;
 ok(n+":exact-read-intent",canon(req)===canon(e.exact_typed_read)&&canon(ri.exact_request)===canon(req)&&r[p+"/sdk/"+n+"_start/request.json"]===r[p+"/intent/request.json"]);
 ok(n+":original-native-ACK",a.operation_id===e.operation_id&&a.tool_name===req.operation.tool&&a.reused===false&&a.idempotency_binding_retained===true);
 const sq=lossless(r[p+"/sdk/"+n+"_status0/request.json"]),s=nat(r[p+"/sdk/"+n+"_status0/original-sdk.json"],n+":status").v;
 ok(n+":original-future-closed",sq.operation_id===a.operation_id&&s.operation_id===a.operation_id&&s.tool_name===req.operation.tool&&s.async_state==="completed"&&s.result_state==="stored_observed"&&s.owned_future_active===false&&s.payload_available===true);
 const payload=r[p+"/immutable-original-sdk.json"],bytes=u(payload),digest=hash(payload),names=Object.keys(r).filter(x=>x.startsWith(p+"/sdk/"+n+"_result")&&x.endsWith("/original-sdk.json")).sort((a,b)=>Number(a.slice((p+"/sdk/"+n+"_result").length).split("/")[0])-Number(b.slice((p+"/sdk/"+n+"_result").length).split("/")[0]));let offset=0,parts=[];
 for(const q of names){const pr=lossless(r[q.replace("/original-sdk.json","/request.json")]),pg=nat(r[q],n+":page"+offset).v,b=unb64(pg.data_base64);
 ok(q+":same-ID-fixed-page",pr.operation_id===a.operation_id&&pg.operation_id===a.operation_id&&pr.offset===offset&&pg.offset===offset&&pr.limit===8192);
 ok(q+":immutable-total-and-SHA",pg.immutable_snapshot===true&&pg.payload_kind==="native_result"&&pg.total_bytes===bytes.length&&pg.result_sha256===digest);
 ok(q+":exact-range-and-EOF",b.length<=8192&&pg.next_offset===offset+b.length&&pg.eof===(pg.next_offset===bytes.length));offset=pg.next_offset;parts.push(...b);}
 ok(n+":whole-original-payload",offset===bytes.length&&bs(parts)===bs(bytes)&&bytes.length===e.immutable_payload_bytes&&digest===e.immutable_payload_sha256&&names.length===e.pages);
 const out=nat(payload,n+":original-payload");ok(n+":native-exact",out.t===r[p+"/native.json"]);ops.push({name:n,operation_id:a.operation_id,pages:names.length,payload_bytes:bytes.length,payload_sha256:digest,completed:true,owned_future_active:false});
}
const authority=lossless(r["observations/authority/native.json"]),streams=lossless(r["observations/streams/native.json"]);
ok("terminal-authority",authority.job_id===job&&authority.state==="succeeded"&&authority.exit_code===0&&authority.timed_out===false&&authority.cancelled===false&&authority.output_complete===true&&authority.output_durable===true&&authority.terminal_publication_confirmed===true);
ok("fixed-original-stream-read",streams.job_id===job&&u(r["actual/stdout"]).length===1531&&r["actual/stderr"]==="");
for(const s of ["stdout","stderr"]){const x=streams[s],b=u(r["actual/"+s]),hex=b.map(v=>v.toString(16).padStart(2,"0")).join("");ok(s+":full-original-stream",x.offset===0&&x.eof===true&&x.next_offset===b.length&&x.size===b.length&&x.text===r["actual/"+s]&&x.bytes_hex===hex&&authority.log_bytes[s].stored===b.length&&authority.log_bytes[s].seen===b.length&&authority.log_synced[s]===true&&authority.log_truncated[s]===false&&authority.log_errors[s]===null);}
const out=lossless(r["actual/stdout"]),receipt=lossless(r["outputs/inert-stage.result.public.json"]),body=lossless(r["observations/whole_four/native.json"]);
ok("receipt-lossless-original-stdout",canon(receipt)===canon(out));ok("inert-only-flags",out.status==="prepared"&&out.python_compile_only===true&&out.source_executed===false&&out.git_started===false&&out.compiler_started===false&&out.service_started===false&&out.artifact_transfer_started===false);
ok("stdin-pin",out.stdin_bytes===u(data.payload).length&&out.stdin_sha256===hash(data.payload));
ok("fixed-four-whole-files",body.atomic_snapshot===false&&body.truncated===false&&body.encoding==="utf-8"&&body.files.length===4&&out.files.length===3);
const names=["sender.py","receiver.py","relay.py","inert-stage.result.public.json"];
for(let i=0;i<4;i++){const name=names[i],info=lossless(r["observations/file"+i+"_info/native.json"]),f=body.files[i],t=r["outputs/"+name],version=info.version.split(":"),meta=info.metadata;
 ok(name+":independent-info",info.path===base+"/"+name&&version.length===5&&version.every(x=>/^(0|[1-9][0-9]*)$/.test(x))&&version[2]===String(info.size)&&meta.uid===1000&&meta.gid===1000&&meta.mode===384&&info.mode===384&&meta.link_count===1);
 ok(name+":whole-body-info-and-candidate",f.path===info.path&&f.text===t&&f.eof===true&&f.size===info.size&&f.sha256===info.sha256&&f.version===info.version&&u(t).length===info.size&&hash(t)===info.sha256&&(i===3||t===data.sources[i]));
 const full9=[version[0],version[1],String(meta.uid),String(meta.gid),String(32768+meta.mode),String(meta.link_count),version[2],version[3],version[4]];
 if(i<3){const a=out.files[i];ok(name+":publisher-exact-full9",a.path===info.path&&a.bytes===info.size&&a.sha256===info.sha256&&a.mode==="0600"&&a.publication==="created"&&canon(a.identity.map(dec))===canon(full9));}
 files.push({path:info.path,bytes:info.size,sha256:info.sha256,version:info.version,full9_decimal:full9,publisher_full9:i<3});}
ok("positive-original-publication-duration",BigInt(dec(out.terminal_ns))-BigInt(dec(out.started_ns))===192540167n);
ok("derived-state-original-digest-corrected",state.original_job.request_digest===digest&&state.original_job.request_fingerprint===dec(j.request_fingerprint)&&state.native_future_inflight===0&&r["verification/state-derivation-correction.public.json"].includes("3a0405db3a0fabbe6dfe435436f54ba0bcfe68e6"));
return {schema:"heptabao.root-source-carrier-inert-complete-review.r29.v1",status:"PASS_INERT_CONTROLS_ONLY",checks_passed:c.length,checks:c,packet:"08fa09f554a015ca4dcd4034e1a041e70d82ea33",packet_files:109,packet_bytes:439188,merkle_trees:55,job:"desktop/"+job,request_digest:digest,request_fingerprint:dec(j.request_fingerprint),exit_code:0,stdout_bytes:1531,stderr_bytes:0,output_complete:true,output_durable:true,closed_observations:ops,files,receipt_has_independent_full9_but_no_publisher_self_identity:true,old_state_correction_preserved:true,original_source3_lost_ACK_still_UNKNOWN:true,source_or_product_executed:false,root_Runtime_calls:0,conditional_relay_prerequisites_satisfied:true,source_import_qualified:false,full_replacement_qualified:false};
}