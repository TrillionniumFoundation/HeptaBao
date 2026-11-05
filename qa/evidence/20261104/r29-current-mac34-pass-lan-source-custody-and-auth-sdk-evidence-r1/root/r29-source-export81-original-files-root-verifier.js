function verifyExport81(data,H){
const {lossless,u,bs,unb64,s256}=H,r=data.raw,c=[],ops=[],files=[];
function ok(n,v){if(!v)throw Error(n);c.push(n);}function hash(t){return s256(bs(u(t)));}function canon(v){return JSON.stringify((function f(x){if(Array.isArray(x))return x.map(f);if(x&&typeof x==="object")return Object.fromEntries(Object.keys(x).sort().map(k=>[k,f(x[k])]));return x;})(v));}
function nat(t,n){const x=lossless(t);ok(n+":SDK-not-error",x.isError!==true);const a=x.content?.filter(x=>x.type==="text");ok(n+":one-native-text",a?.length===1);return{text:a[0].text,v:lossless(a[0].text)};}
ok("frozen-plan-original-bytes",r["intent/references/fixed-plan.public.json"]===data.plan);
ok("core-original-bytes",r["intent/references/original-core.public.json"]===data.core);
const plan=lossless(data.plan),core=lossless(data.core),state=lossless(r["state.public.json"]);
ok("original-export-identity",core.canonical_commit==="4e808d0ecb1bcded22870a7ec960dfb2491cf6ec"&&core.canonical_tree==="eba5e650bd080b8ad41ea52a2bc68867f541d255"&&state.original_export_job==="rog/1a1abe371de-fc05-5122");
for(let i=0;i<6;i++){
 const label="commandlogs-"+String(i+1).padStart(2,"0"),p="observations/"+label,expected=plan.requests.find(x=>x.name===label).request,req=lossless(r[p+"_start/request.json"]),ack=nat(r[p+"_start/original-sdk.json"],label+":ack").v;
 ok(label+":exact-frozen-request",canon(req)===canon(expected)&&r["intent/requests/"+label+".json"]===data.requests[i]);
 ok(label+":returned-original-ACK",ack.tool_name==="read_multiple_files"&&ack.operation_id===state.read_operation_ids[i]&&ack.reused===false&&ack.idempotency_binding_retained===true);
 const sq=lossless(r[p+"_status0/request.json"]),status=nat(r[p+"_status0/original-sdk.json"],label+":status").v;
 ok(label+":original-future-closed",sq.operation_id===ack.operation_id&&status.operation_id===ack.operation_id&&status.tool_name==="read_multiple_files"&&status.async_state==="completed"&&status.result_state==="stored_observed"&&status.owned_future_active===false&&status.payload_available===true);
 const payload=r[p+".original-operation-payload.json"],bytes=u(payload),digest=hash(payload),pageNames=Object.keys(r).filter(x=>x.startsWith(p+"_result")&&x.endsWith("/original-sdk.json")).sort((a,b)=>Number(a.slice((p+"_result").length).split("/")[0])-Number(b.slice((p+"_result").length).split("/")[0]));let cursor=0,parts=[];
 for(const q of pageNames){
  const pr=lossless(r[q.replace("/original-sdk.json","/request.json")]),pg=nat(r[q],label+":page"+cursor).v,b=unb64(pg.data_base64);
  ok(q+":same-ID-fixed-page",pr.operation_id===ack.operation_id&&pg.operation_id===ack.operation_id&&pr.offset===cursor&&pg.offset===cursor&&pr.limit===8192);
  ok(q+":immutable-bound-result",pg.immutable_snapshot===true&&pg.payload_kind==="native_result"&&pg.total_bytes===bytes.length&&pg.result_sha256===digest);
  ok(q+":exact-range-and-EOF",b.length<=8192&&pg.next_offset===cursor+b.length&&pg.eof===(pg.next_offset===bytes.length));cursor=pg.next_offset;parts.push(...b);
 }
 ok(label+":whole-original-SDK",cursor===bytes.length&&bs(parts)===bs(bytes)&&hash(payload)===digest);
 const out=nat(payload,label+":payload");ok(label+":native-original-exact",out.text===r[p+".native.json"]);
 const body=out.v;ok(label+":independent-full-files",body.atomic_snapshot===false&&body.truncated===false&&body.encoding==="utf-8"&&body.files.length===expected.operation.arguments.paths.length);
 ok(label+":fixed-path-order",canon(body.files.map(x=>x.path))===canon(expected.operation.arguments.paths));
 for(const f of body.files){
  const row=plan.command_log_rows.find(x=>x.path===f.path),name=f.path.split("/").at(-1),text=r["original-files/"+name],version=f.version.split(":");
  ok(label+":"+name+":original-whole-exact",f.eof===true&&f.text===text&&u(text).length===row.bytes&&f.size===row.bytes&&hash(text)===row.sha256&&f.sha256===row.sha256);
  ok(label+":"+name+":independent-version",version.length===5&&version.every(x=>/^(0|[1-9][0-9]*)$/.test(x))&&version[2]===String(f.size));
  files.push({path:f.path,bytes:f.size,sha256:f.sha256,version:f.version,role:row.role});
 }
 ops.push({batch:label,operation_id:ack.operation_id,pages:pageNames.length,original_payload_bytes:bytes.length,original_payload_sha256:digest,files:body.files.length,completed:true,owned_future_active:false});
}
ok("81-unique-original-files-28080B",files.length===81&&new Set(files.map(x=>x.path)).size===81&&files.reduce((n,x)=>n+x.bytes,0)===28080);
ok("six-original-read-IDs",ops.length===6&&new Set(ops.map(x=>x.operation_id)).size===6);
ok("27-unique-command-rows",core.commands.length===27&&new Set(core.commands.map(x=>x.label)).size===27&&new Set(core.commands.map(x=>x.pid)).size===27);
for(const row of core.commands){
 const p="original-files/"+row.label,record=lossless(r[p+".public.json"]);
 ok(row.label+":record-matches-core",canon(record)===canon(row));
 for(const stream of ["stdout","stderr"]){const t=r[p+"."+stream];ok(row.label+":"+stream+"-matches-core",u(t).length===row[stream+"_bytes"]&&hash(t)===row[stream+"_sha256"]);}
 ok(row.label+":original-process-closed",row.direct_child_reaped===true&&row.remaining.length===0&&row.timed_out===false&&row.limit_seconds===90);
}
ok("25-success-plus-two-expected-query-exit1",core.commands.filter(x=>x.exit_code===0).length===25&&canon(core.commands.filter(x=>x.exit_code===1).map(x=>x.label))===canon(["006-source-before-partial-config","024-source-after-partial-config"]));
ok("no-read-or-export-replay-claim",state.original_commands_rerun===false&&state.exporter_replayed===false&&state.bundle_info_repeated===false&&state.native_calls_inflight===0&&state.source3_initial_read_lost_ACK==="UNKNOWN_PRESERVED");
return {schema:"heptabao.root-original-source-export81-completion.r29.v1",status:"PASS_COMPLETE_ORIGINAL_27_COMMAND_RECORDS_AND_54_STREAMS",packet:"f5af874eee6ec59d2afccb90898fcdb69251dffd",packet_files:162,packet_bytes:485260,merkle_trees:30,checks_passed:c.length,checks:c,original_export_job:"rog/1a1abe371de-fc05-5122",core_blob:"0109d7597b2754ee665367177ba1cd3e832d4b34",plan_blob:"9f60d88c19ab9282bfabb520ae5a2d1fe0c90602",closed_read_operations:ops,original_file_bytes:28080,original_files:files,commands:27,exit0:25,expected_config_exit1:2,no_original_command_rerun:true,bundle_info_not_repeated:true,atomic_multi_file_snapshot:false,conditional_carrier_inert_prerequisites_satisfied:true,source_import_qualified:false,product_runtime_qualified:false,root_Runtime_calls:0,full_replacement_qualified:false};
}
