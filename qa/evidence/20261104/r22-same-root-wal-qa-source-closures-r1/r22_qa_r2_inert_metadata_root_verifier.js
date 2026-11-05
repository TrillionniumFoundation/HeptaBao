function verifyQaR2InertMetadata(a,get,p,u,bs,h,unb64,request,receipt){
 const checks=[],ck=(n,v)=>{if(!v)throw Error(n);checks.push(n);},j=x=>p(get(x)),dec=x=>p(j(x).content[0].text),eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b),hash=x=>h(bs(u(x))),dig=x=>x&&typeof x==="object"&&x.$exactInteger?x.$exactInteger:String(x);
 ck("packet whole",a.files===84&&a.bytes===522767&&a.merkle.trees_verified===21);
 for(const kind of ["authority","streams","start",...Array.from({length:9},(_,i)=>"file-info-"+i)]){
  const native=kind==="start"?"actual/start-ack.original.json":"actual/"+kind+".original.json",sdk=j("sdk/"+kind+".original.json");
  ck("SDK exact native "+kind,sdk.content[0].text===get(native)&&sdk.isError!==true);
 }
 let pages=0;
 for(const kind of ["authority","streams",...Array.from({length:9},(_,i)=>"file-info-"+i)]){
  const pre="operations/"+kind+"/",ad=dec(pre+"admission.original.json"),st=dec(pre+(kind.startsWith("file-info-")?"status-1":"status")+".original.json"),rq=j(pre+"request.public.json");
  ck("read operation bound "+kind,rq.operation.arguments.host==="rog"&&ad.operation_id===st.operation_id&&ad.tool_name===rq.operation.tool&&!ad.reused);
  if(kind==="authority"||kind==="streams")ck("original job read "+kind,rq.operation.arguments.job_id==="1a1aad691c1-fc05-47e5");
  else ck("fixed file path "+kind,rq.operation.tool==="file_info"&&rq.operation.arguments.path===j("actual/"+kind+".original.json").path);
  ck("read operation closed "+kind,st.async_state==="completed"&&st.owned_future_active===false&&st.payload_available&&st.result_state==="stored_observed");
  let raw="",off=0,eof=false,sha=null,total=null;
  for(const f of a.records.filter(x=>x.path.startsWith(pre+"page-")).sort((x,y)=>x.path.localeCompare(y.path))){
   const v=dec(f.path),b=bs(unb64(v.data_base64));
   ck("immutable page "+kind+" "+off,v.operation_id===ad.operation_id&&v.immutable_snapshot&&v.payload_kind==="native_result"&&!eof&&v.offset===off&&v.next_offset===off+b.length&&(sha===null||sha===v.result_sha256)&&(total===null||total===v.total_bytes));
   sha=v.result_sha256;total=v.total_bytes;raw+=b;off=v.next_offset;eof=v.eof;pages++;
  }
  ck("complete original payload "+kind,eof&&off===total&&h(raw)===sha&&raw===bs(u(get("sdk/"+kind+".original.json")))&&j("sdk/"+kind+".original.json").resultType==="complete");
 }
 const ack=j("actual/start-ack.original.json"),auth=j("actual/authority.original.json"),streams=j("actual/streams.original.json"),core=j("actual/stdout.original");
 ck("exact unique original launch",ack.job.id==="1a1aad691c1-fc05-47e5"&&ack.job.idempotency_key===request.idempotency_key&&ack.job.host===request.host&&ack.job.executable===request.executable&&ack.job.cwd===request.cwd&&eq(ack.job.args,request.args)&&ack.reused===false&&ack.job.launch_state==="launched"&&ack.launch.ok&&ack.local_record_pending===false);
 ck("authoritative terminal zero full durable",auth.job_id===ack.job.id&&auth.state==="succeeded"&&auth.exit_code===0&&auth.output_complete&&auth.output_durable&&auth.terminal_publication_confirmed&&!auth.timed_out&&!auth.cancelled&&!auth.automatic_retry);
 for(const [name,len]of[["stdout",3168],["stderr",173]]){
  const s=streams[name];ck("complete "+name,s.text===get("actual/"+name+".original")&&s.offset===0&&s.next_offset===len&&s.size===len&&s.eof&&bs(u(s.text))===s.bytes_hex.replace(/../g,x=>String.fromCharCode(parseInt(x,16))));
  ck("durable unclipped "+name,auth.log_bytes[name].seen===len&&auth.log_bytes[name].stored===len&&auth.log_errors[name]===null&&auth.log_synced[name]&&!auth.log_truncated[name]);
 }
 ck("original compile warnings preserved",get("actual/stderr.original")==="inputs/owned_reference_phaseb_r3.py:1088: SyntaxWarning: 'return' in a 'finally' block\ninputs/official_cli_reference_r4.py:915: SyntaxWarning: 'return' in a 'finally' block\n");
 ck("prepared inert only",core.status==="prepared"&&core.python_compile_only&&!core.source_executed&&!core.git_started&&!core.compiler_started&&!core.service_started&&!core.artifact_transfer_started);
 const elapsed=BigInt(dig(core.terminal_ns))-BigInt(dig(core.started_ns));
 ck("inert elapsed below original60",elapsed>0n&&elapsed<60000000000n&&request.timeout_seconds===60);
 ck("original carrier exact",core.stdin_bytes===u(request.stdin).length&&core.stdin_sha256===hash(request.stdin));
 const carrier=p(request.stdin),expected=j("analysis/expected-input-map.public.json");ck("8 sources published",Object.keys(carrier.files).length===8&&core.files.length===8&&expected.files.length===8);
 for(let i=0;i<8;i++){
  const row=core.files[i],e=expected.files[i],info=j("actual/file-info-"+i+".original.json"),name=row.path.slice("/home/qian-qi/heptabao-native-h2-qa-controls-df026-20261105-r2/".length),raw=bs(unb64(carrier.files[name]));
  ck("exact source bytes hash "+i,row.path===e.path&&row.path===info.path&&raw.length===row.bytes&&h(raw)===row.sha256&&row.bytes===e.bytes&&row.sha256===e.sha256&&row.bytes===info.size&&row.sha256===info.sha256&&row.publication==="created");
  ck("source metadata custody "+i,info.metadata.uid===1000&&info.metadata.gid===1000&&info.metadata.link_count===1&&info.metadata.mode===384&&info.mode===384&&row.identity[2]===1000&&row.identity[3]===1000&&row.identity[4]===33152&&row.identity[5]===1&&row.identity[6]===row.bytes);
  ck("source exact lossless version "+i,info.version===[row.identity[0],row.identity[1],row.identity[6],row.identity[7],row.identity[8]].map(dig).join(":"));
 }
 const ri=j("actual/file-info-8.original.json");
 ck("receipt reconstructed under exact publisher",eq(p(receipt),core)&&u(receipt).length===4208&&hash(receipt)===ri.sha256&&ri.size===4208);
 ck("receipt observed metadata",ri.path===expected.receipt&&ri.mode===384&&ri.metadata.uid===1000&&ri.metadata.gid===1000&&ri.metadata.link_count===1);
 return{schema:"heptabao.root.qa-r2-inert-native-hash-closure.v1",status:"INERT_INPUT_BINDINGS_CLOSED",checks_passed:checks.length,checks,job:ack.job.id,original_request_key:request.idempotency_key,closed_read_operations:11,immutable_pages:pages,elapsed_ns:elapsed.toString(),fixed_source_files:8,independent_file_metadata:9,complete_stdout_bytes:3168,complete_stderr_bytes:173,new_whole_file_body_read_claimed:false,receipt_reconstructed_from_lossless_stdout_and_independent_whole_sha:true,three_body_read_unknowns_preserved:true,compiler_or_product_qualification:false};
}
