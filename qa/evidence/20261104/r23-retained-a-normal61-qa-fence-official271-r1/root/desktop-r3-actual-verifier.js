function verifyLocatorActual(raw, utf8, byteString, sha256) {
 const checks=[];function ck(n,v){if(!v)throw Error(n);checks.push(n);}
 function obj(p){return JSON.parse(raw[p]);}
 function hash(s){return sha256(byteString(utf8(s)));}
 function canon(r){return JSON.stringify({args:r.args,cpu_quota_percent:r.cpu_quota_percent??null,cwd:r.cwd??null,env:r.env??{},executable:r.executable,host:r.host,memory_max_bytes:r.memory_max_bytes??null,nice:r.nice??null,stdin:r.stdin??null,timeout_seconds:r.timeout_seconds??null});}
 const summary={};
 for(const host of ["desktop"]){
  const prefix=host+"/",req=obj(prefix+"exact-start-request.public.json"),intent=obj(prefix+"start-intent.public.json");
  const ack=obj(prefix+"start.native-original.public.json"),status=obj(prefix+"status0.native-original.public.json");
  const readings=host==="rog"?["read0","read1"]:["read0"];
  for(const name of ["start","status0",...readings]) {
   const sdk=obj(prefix+name+".mcp-snapshot.public.json");
   ck(host+" "+name+" SDK raw native bytes exact",sdk.isError===false&&sdk.content[0].text===raw[prefix+name+".native-original.public.json"]);
  }
  ck(host+" intent contains exact request",intent.exact_request_raw===raw[prefix+"exact-start-request.public.json"]);
  ck(host+" intent request whole SHA",intent.request.sha256===hash(intent.exact_request_raw)&&intent.request.bytes===utf8(intent.exact_request_raw).length);
  ck(host+" unique ACK and host binding",ack.reused===false&&ack.job.launch_state==="launched"&&ack.launch.ok===true&&ack.job.host===host&&req.host===host);
  ck(host+" exact executable argv cwd key",ack.job.executable===req.executable&&JSON.stringify(ack.job.args)===JSON.stringify(req.args)&&ack.job.cwd===req.cwd&&ack.job.idempotency_key===req.idempotency_key);
  ck(host+" canonical request digest",ack.job.request_digest===hash(canon(req)));
  ck(host+" authority full durable terminal",status.job_id===ack.job.id&&status.output_complete===true&&status.output_durable===true&&status.terminal_publication_confirmed===true&&!status.timed_out&&!status.cancelled&&!status.automatic_retry);
  for(const stream of ["stdout","stderr"]){
   let whole="",pos=0;
   for(const name of readings){
    const r=obj(prefix+name+".native-original.public.json"),arg=obj(prefix+name+".exact-request.public.json"),s=r[stream];
    ck(host+" "+name+" job binding",r.job_id===ack.job.id&&arg.host===host&&arg.job_id===ack.job.id);
    ck(host+" "+name+" "+stream+" cursor",s.offset===pos&&arg[stream+"_offset"]===pos&&s.next_offset===pos+utf8(s.text).length);
    ck(host+" "+name+" "+stream+" exact hex",s.bytes_hex===utf8(s.text).map(x=>x.toString(16).padStart(2,"0")).join(""));
    whole+=s.text;pos=s.next_offset;
   }
   const last=obj(prefix+readings.at(-1)+".native-original.public.json")[stream];
   ck(host+" "+stream+" full original EOF",last.eof===true&&last.size===pos&&whole===raw[prefix+stream+(stream==="stdout"?".original.json":".original.txt")]);
   ck(host+" "+stream+" authoritative complete byte count",status.log_bytes[stream].seen===pos&&status.log_bytes[stream].stored===pos&&status.log_synced[stream]===true&&status.log_truncated[stream]===false&&status.log_errors[stream]===null);
  }
  const out=obj(prefix+"stdout.original.json");
  ck(host+" no widened authority",out.absence_proven===false&&out.replay_authorized===false&&out.job_execution_or_termination_proven===false&&out.complete_inventory_or_stable_membership_proven===false&&out.deployed_runtime_source_identity_proven===false&&out.stdin_content_rechecked===false);
  ck(host+" source and time binding",out.source_sha256==="886d2d25836d3fe2dbaa3fdbea8ee921d6f7c4be35b6e394fa39445dc2971cbe"&&out.configured_host===host&&out.floor_unix_ms===1793864424254);
  ck(host+" closure within original15",out.all_registered_resources_closed===true&&out.within_original_deadline_after_closure===true&&out.elapsed_after_closure_ns<15000000000&&out.fds_remaining===0&&out.fd_close_failures===0&&out.cancel_signal===null&&!out.open_registration_unknown&&!out.scandir_open_unknown);
  ck(host+" complete once-close FD ledger",out.fds_opened===out.fds_closed_once&&out.fd_closure_rows.length===out.fds_opened&&out.fd_closure_rows.every((x,i)=>x.ordinal===i+1&&x.close_attempted===true&&x.closed===true&&x.close_errno===null&&x.close_error===null));
  ck(host+" iterator once closed",out.scandir_created===true&&out.scandir_close_attempted===true&&out.scandir_closed===true&&out.scandir_close_error===null);
  ck(host+" original read caps",out.request_bytes_read<=8388608&&out.request_files_read<=129&&out.matches.length<=8&&utf8(raw[prefix+"stdout.original.json"]).length<=65536);
  ck(host+" anchor typed exact",out.known_anchor.typed_fields_match===true);
  if(host==="desktop"){
   ck("desktop known bound refusal before candidate bodies",status.state==="failed"&&status.exit_code===1&&out.status==="failed"&&out.failure.code==="recent_candidates_bound"&&out.request_files_read===1&&out.request_bytes_read===out.known_anchor.request_file_bytes&&out.matches.length===0);
   ck("desktop original anchor",out.known_anchor.job_id==="1a1aaa6db3e-fc05-45a6"&&out.known_anchor.request_digest==="39297690cdf83252668d9aa1a0656dc677544816c8b6653513c15a4876a04486");
  }else{
   ck("rog actual successful bounded observation",status.state==="succeeded"&&status.exit_code===0&&out.status==="bounded_read_completed"&&out.failure===null);
   ck("rog inventory bounded",out.candidate_count===125&&out.candidate_count<=128&&out.directory_entries_observed===1903&&out.directory_entries_observed<=16384&&out.directory_name_bytes_observed===39540&&out.directory_name_bytes_observed<=1048576);
   ck("rog original anchor",out.known_anchor.job_id==="1a1aad691c1-fc05-47e5"&&out.known_anchor.request_digest==="51752897890cc752bfa1819ce557ccb6eb293586681cc46b81200a368439f3ed");
   ck("rog one exact original source target",out.matches.length===1&&out.matches[0].job_id==="1a1aae5a5c7-fc05-4882"&&out.matches[0].request_digest==="bae96736cb7abc92a03e93f7e55f5c108a152dcf5f5aeb237643b935218df42b"&&out.matches[0].request_file_sha256==="a51eb0e9adad3ca64f0e4e0e9a9e2c8bb1eb5a938c261f78567452331c1cd534");
  }
  summary[host]={observer_job:ack.job.id,observer_exit:status.exit_code,observer_status:out.status,request_files_read:out.request_files_read,request_bytes_read:out.request_bytes_read,fds_closed_once:out.fds_closed_once,elapsed_after_closure_ns:out.elapsed_after_closure_ns,matches:out.matches,absence_proven:false,replay_authorized:false};
 }
 return {schema:"heptabao.root.desktop-first-window-locator-actual-verification.v1",status:"PASS",scope:"Original desktop first-window observer; target remains unknown",checks_count:checks.length,checks,summary};
}
