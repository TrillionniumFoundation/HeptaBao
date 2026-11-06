function verifySnapshotB694StageOriginalChain(texts) {
 const checks=[];
 function check(name,value){checks.push({name,pass:!!value});if(!value)throw new Error(name);}
 function obj(raw){return parseLosslessIntegers(raw);}
 function canonical(x){if(Array.isArray(x))return x.map(canonical);if(x&&typeof x==="object")return Object.fromEntries(Object.keys(x).sort().map(k=>[k,canonical(x[k])]));return x;}
 function equal(a,b){return JSON.stringify(canonical(a))===JSON.stringify(canonical(b));}
 const index=obj(texts["calls-and-observers.public.json"]),release=obj(texts["RELEASE.public.json"]);
 check("7-original-native-calls",index.calls.length===7);
 check("one-business-start",index.calls.filter(x=>x.kind==="process_start").length===1);
 check("2-original-observers",index.observers.length===2);
 for(const c of index.calls){
  check(c.key+":accepted-once",c.phase==="accepted"&&c.called===true);
  for(const field of ["request","sdk","native"]){const raw=texts[c.prefix+"."+field+".json"],m=gitBlobMeta(raw),p=c[field];check(c.key+":"+field+"-whole",m.blob===p.blob&&m.bytes===p.bytes&&m.sha256===p.sha256);}
  const sdk=obj(texts[c.prefix+".sdk.json"]),native=obj(texts[c.prefix+".native.json"]);
  check(c.key+":sdk-nonerror",sdk.isError===false&&sdk.content?.length===1&&sdk.content[0].type==="text");
  check(c.key+":sdk-native-lossless",equal(obj(sdk.content[0].text),native));
  const intent=obj(texts[c.prefix+".intent.json"]),armed=obj(texts[c.prefix+".armed.json"]);
  check(c.key+":exact-intent",intent.callKey===c.key&&intent.kind===c.kind&&equal(intent.request,c.request)&&intent.maximumNativeCalls===1&&intent.nativeNotYetCalled===true);
  check(c.key+":exact-armed",armed.callKey===c.key&&equal(armed.request,c.request)&&armed.mayHaveDispatchedAfterThisCheckpoint===true);
 }
 const start=index.calls[0],q=obj(texts[start.prefix+".request.json"]),ack=obj(texts[start.prefix+".native.json"]);
 check("request-exact",start.request.blob==="cbd6774e2f40e2c4b1e0c2f29cbc7954eaff494d");
 check("request-source-full",q.args[4]===texts["stage-source.py"]);
 check("request-original-budget",q.host==="rog"&&q.timeout_seconds===360&&q.args.slice(0,4).join(",")==="-I,-S,-B,-c");
 check("ack-job-exact",ack.job.id===release.job_id&&ack.job.host==="rog"&&ack.reused===false);
 check("ack-native-digest",ack.job.request_digest===index.requestBinding.digest);
 const fp=ack.job.request_fingerprint;
 check("ack-lossless-fingerprint",(fp?.$exactInteger??String(fp))===index.requestBinding.fingerprint);
 for(let i=0;i<index.observers.length;i++){
  const o=index.observers[i],prefix=i===0?"snapshot-b694-authority0":"snapshot-b694-streams0";
  const rows=Object.fromEntries(index.calls.filter(c=>c.key.startsWith(prefix)).map(c=>[c.key.slice(prefix.length+1),c]));
  const admit=obj(texts[rows.admit.prefix+".native.json"]),status=obj(texts[rows.status.prefix+".native.json"]),page=obj(texts[rows.page0.prefix+".native.json"]);
  const aq=obj(texts[rows.admit.prefix+".request.json"]),sq=obj(texts[rows.status.prefix+".request.json"]),pq=obj(texts[rows.page0.prefix+".request.json"]);
  const payload=texts["observer"+i+".payload.json"],native=texts["observer"+i+".native.json"],pm=gitBlobMeta(payload),nm=gitBlobMeta(native);
  check(prefix+":same-job",aq.operation.arguments.host==="rog"&&aq.operation.arguments.job_id===release.job_id&&aq.operation.tool===o.tool);
  check(prefix+":same-operation",admit.operation_id===o.id&&status.operation_id===o.id&&page.operation_id===o.id&&sq.operation_id===o.id&&pq.operation_id===o.id);
  check(prefix+":completed-inactive",status.async_state==="completed"&&status.result_state==="stored_observed"&&status.owned_future_active===false&&status.payload_available===true&&o.completedInactive===true);
  check(prefix+":original-page-geometry",pq.offset===0&&pq.limit===8192&&page.offset===0&&page.eof===true&&page.immutable_snapshot===true&&page.next_offset===page.total_bytes&&o.pages===1);
  check(prefix+":payload-full",pm.blob===o.payload.blob&&pm.bytes===o.payload.bytes&&pm.sha256===o.payload.sha256&&pm.bytes===page.total_bytes&&pm.sha256===page.result_sha256&&utf8Text(unb64(page.data_base64))===payload);
  const envelope=obj(payload);
  check(prefix+":original-envelope",envelope.resultType==="complete"&&envelope.isError===false&&envelope.content?.length===1&&envelope.content[0].text===native);
  check(prefix+":native-full",nm.blob===o.nativeText.blob&&nm.bytes===o.nativeText.bytes&&nm.sha256===o.nativeText.sha256&&obj(native).job_id===release.job_id);
 }
 const auth=obj(texts["observer0.native.json"]),streams=obj(texts["observer1.native.json"]),out=obj(texts["stdout.original.txt"]);
 check("terminal-success",auth.state==="succeeded"&&auth.exit_code===0&&!auth.timed_out&&!auth.cancelled&&!auth.automatic_retry);
 check("terminal-full-durable",auth.output_complete===true&&auth.output_durable===true&&auth.terminal_publication_confirmed===true);
 for(const name of ["stdout","stderr"]){
  const r=streams[name],raw=texts[name+".original.txt"],bytes=utf8Bytes(raw),hex=bytes.map(x=>x.toString(16).padStart(2,"0")).join("");
  check(name+":full-stream",r.text===raw&&r.bytes_hex===hex&&r.offset===0&&r.next_offset===bytes.length&&r.size===bytes.length&&r.eof===true);
  check(name+":authority-sized",auth.log_bytes[name].seen===bytes.length&&auth.log_bytes[name].stored===bytes.length&&auth.log_errors[name]===null&&auth.log_truncated[name]===false&&auth.log_synced[name]===true);
 }
 check("383-stdout-0-stderr",gitBlobMeta(texts["stdout.original.txt"]).bytes===383&&texts["stderr.original.txt"]==="");
 check("summary-exact-source",out.source_commit==="b6949024dc5d0922ca9b27d865923d28982286c3"&&out.source_tree==="9c800e97a2527e7f01c3a4b0be594e6762f9581e");
 check("summary-prepared",out.status==="prepared"&&out.all_owned_stopped===true&&out.within_new_stage_deadline===true);
 check("summary-no-compiler-product",out.compiler_started===false&&out.server_started===false);
 check("fixed-report-pointer",out.result_path==="/home/qian-qi/heptabao-native-snapshot-forward-source-b6949024-20261106-r1/control/stage-result.public.json");
 check("owner-release",release.native_call_in_flight===false&&release.native_future_active===false&&release.pending_call===null&&release.paused===false&&release.business_process_live===false&&release.lane_released===true);
 check("scope-not-upgraded",release.detailed_report_observed===false&&release.detailed_report_file_info_submitted===false&&release.detailed_report_body_submitted===false&&release.formatter_started===false&&release.compiler_started===false&&release.product_started===false);
 return{schema:"heptabao.snapshot-b694-stage-original-chain-pure-checks.v1",pass:true,count:checks.length,checks,scope:"7 original native calls / 2 closed observers / 2 original pages; terminal and summary only, detailed report unobserved",newNativeCalls:0};
}
