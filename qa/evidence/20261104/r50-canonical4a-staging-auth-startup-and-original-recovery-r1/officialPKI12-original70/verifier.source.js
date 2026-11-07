function verifyOfficialPki12OuterActual(t){
 const checks=[];function check(name,ok){checks.push({name,pass:!!ok});if(!ok)throw Error(name);}
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),pinEq=(raw,p)=>same(gitBlobMeta(raw),p);
 const state=JSON.parse(t["STATE.closed.original.json"]),calls=JSON.parse(t["CALL-INDEX.public.json"]),go=JSON.parse(t["GO.original.json"]);
 check("exact_GO",gitBlobMeta(t["GO.original.json"]).blob==="4b3d7263860f754d52b4e76a036300418fe8e046");
 check("exact_executed_journal",gitBlobMeta(t["journal.executed.original.js"]).blob==="cde02ae68396ec97d4f0bc7a33281331377aa09e");
 check("original_unique_job",state.job==="1a1b3461a2c-fc05-81a9"&&state.startCalled===true&&state.pending===null&&state.activeObserver===null&&!state.nativeCallInFlight&&!state.paused);
 check("seven_original_calls",calls.length===7&&Object.keys(state.calls).length===7&&calls.filter(x=>x.kind==="process_start").length===1&&calls.filter(x=>x.kind==="operation_start").length===2);
 const native=[];
 for(let i=0;i<calls.length;i++){
  const c=calls[i],n="call-"+String(i).padStart(2,"0"),sdk=JSON.parse(t[n+".sdk.json"]),r=JSON.parse(t[n+".request.json"]),v=parseLosslessIntegers(t[n+".native.txt"]);
  check(n+"_original_pins",pinEq(t[n+".request.json"],c.request)&&pinEq(t[n+".sdk.json"],c.sdk)&&pinEq(t[n+".native.txt"],c.native));
  check(n+"_SDK_before_native_source",sdk.isError!==true&&sdk.content.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===t[n+".native.txt"]);
  check(n+"_accepted_original_state",state.calls[c.key].phase==="accepted"&&state.calls[c.key].called===true&&state.calls[c.key].armed.whole&&state.calls[c.key].sdkArchive.whole&&state.calls[c.key].requestRaw===t[n+".request.json"]);
  const intent=JSON.parse(t[n+".intent.json"]),arm=JSON.parse(t[n+".armed.json"]),tree=JSON.parse(t[n+".arm-tree.original.json"]),create=JSON.parse(t[n+".arm-create.original.sdk.json"]);
  check(n+"_exact_intent_and_arm",same(intent.rootGo,gitBlobMeta(t["GO.original.json"]))&&same(intent.request,c.request)&&intent.callKey===c.key&&intent.maximumNativeCalls===1&&intent.nativeNotYetCalled===true&&arm.mayHaveDispatchedAfterThisCheckpoint===true);
  check(n+"_arm_Merkle_CREATE",gitTreeAudit(tree).root_sha===c.armed_tree&&create.structuredContent.sha===c.armed_tree&&tree.tree.length===3&&tree.tree.every(e=>e.mode==="100644"&&e.sha===gitBlobMeta(t[n+"."+e.path]).blob));
  if(c.kind==="process_start"){
   check("START_exact_request",pinEq(t[n+".request.json"],go.exact_request));
   const binding=processStartBinding(r);
   check("START_typed_stdin",binding.sha256===go.native_binding.sha256&&binding.native_fingerprint===go.native_binding.native_fingerprint&&binding.sha256===v.job.request_digest&&(v.job.request_fingerprint.$exactInteger??String(v.job.request_fingerprint))===binding.native_fingerprint);
   check("START_original_ACK",v.job.id===state.job&&v.job.host==="x230"&&v.job.executable===r.executable&&same(v.job.args,r.args)&&v.job.cwd===r.cwd&&v.job.idempotency_key===r.idempotency_key&&v.reused===false&&v.launch.ok===true&&v.audit_recorded===true&&!v.local_record_pending);
  }else if(c.kind==="operation_start"){
   check(n+"_original_observer_admission",r.operation.arguments.host==="x230"&&r.operation.arguments.job_id===state.job&&v.tool_name===r.operation.tool&&v.reused===false&&v.automatic_retry===false);
  }else if(c.kind==="operation_status"){
   check(n+"_original_future_closed",v.operation_id===r.operation_id&&v.async_state==="completed"&&v.owned_future_active===false&&v.result_state==="stored_observed"&&v.payload_available===true&&v.automatic_retry===false);
  }else{
   const bytes=unb64(v.data_base64);
   check(n+"_immutable_exact_range",v.operation_id===r.operation_id&&r.offset===0&&r.limit===8192&&v.offset===0&&v.next_offset===bytes.length&&v.total_bytes===bytes.length&&bytes.length<=8192&&v.eof===true&&v.immutable_snapshot===true&&v.payload_kind==="native_result");
   check(n+"_immutable_whole_sha",sha256Latin1(byteString(bytes))===v.result_sha256);
  }
  native.push({c,r,v});
 }
 check("two_closed_original_observers",state.completedObservers.length===2&&state.completedObservers.every(o=>o.completedInactive===true&&o.pages===1));
 const products=[];
 for(let i=0;i<state.completedObservers.length;i++){
  const o=state.completedObservers[i],n="observer-"+String(i).padStart(2,"0"),raw=t[n+".payload.original.json"],env=parseLosslessIntegers(raw),v=parseLosslessIntegers(t[n+".native.original.json"]);
  check(n+"_whole_payload_and_native",pinEq(raw,o.payload)&&pinEq(t[n+".native.original.json"],o.nativeText)&&env.resultType==="complete"&&!env.isError&&env.content[0].text===t[n+".native.original.json"]);
  const page=native.find(x=>x.c.kind==="operation_result"&&x.v.operation_id===o.id);
  check(n+"_page_reconstructs_payload",page&&utf8Text(unb64(page.v.data_base64))===raw&&page.v.result_sha256===o.payload.sha256);
  check(n+"_matching_closed_admission",native.some(x=>x.c.kind==="operation_start"&&x.v.operation_id===o.id&&x.v.tool_name===o.tool)&&native.some(x=>x.c.kind==="operation_status"&&x.v.operation_id===o.id&&x.v.owned_future_active===false));
  check(n+"_original_job_identity",v.job_id===state.job);products.push(v);
 }
 const authority=products[0],streams=products[1];
 check("terminal_actual",authority.state==="succeeded"&&authority.exit_code===0&&!authority.timed_out&&!authority.cancelled&&authority.output_complete&&authority.output_durable&&authority.terminal_publication_confirmed);
 for(const name of ["stdout","stderr"]){
  const row=streams[name],raw=t[name==="stdout"?"stdout.original.json":"stderr.original.txt"],bytes=utf8Bytes(raw);
  check(name+"_lossless_full_EOF",row.offset===0&&row.next_offset===bytes.length&&row.size===bytes.length&&row.eof===true&&row.text===raw&&row.bytes_hex===bytes.map(x=>x.toString(16).padStart(2,"0")).join(""));
  check(name+"_terminal_sizes",authority.log_bytes[name].stored===bytes.length&&authority.log_bytes[name].seen===bytes.length&&authority.log_synced[name]===true&&authority.log_truncated[name]===false&&authority.log_errors[name]===null);
 }
 check("actual_676_0",state.nextStdout===676&&state.nextStderr===0&&gitBlobMeta(t["stdout.original.json"]).bytes===676&&t["stderr.original.txt"]==="");
 const summary=JSON.parse(t["stdout.original.json"]);
 check("terminal_summary_only",summary.capture_complete===true&&summary.failure===null&&summary.pki_case_denominator===12&&summary.entry_fd_count===10&&summary.all_entry_file_descriptors_closed===true&&summary.original_owner_receipt_present===true&&summary.parity_qualified===false&&summary.candidate_started===false);
 check("reported_fixed_public_file",summary.report.relative==="result.public.json"&&summary.report.bytes===41509&&summary.report.sha256==="5d28fb22f023d9a4e10e3124f45e1ce68b89d0b3e0797e8c08db59bef8ea22a0"&&summary.report.closed===true&&same(summary.report.full9_decimal,["2053","3321457","1000","1000","33152","1","41509","1794009102635552960","1794009102635552960"]));
 return {schema:"heptabao.C.official271-pki12-outer-actual-verification.r1",pass:true,check_count:checks.length,checks,scope:"Original seven-call outer transport and reported summary only",runtime_calls_added:0,report_body_observed:false,PKI12_actual_statuses:null,owner_receipt_semantics_qualified:false};
}
