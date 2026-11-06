function verifyActualStage(files){
 const rows=JSON.parse(files["CALL-INDEX.public.json"]),s=JSON.parse(files["STATE.public.json"]),checks=[];
 const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 function ck(ok,code){checks.push({code,pass:!!ok});if(!ok)throw Error(code);}
 ck(rows.length===7,"seven_original_native_calls");
 ck(rows.filter(x=>x.kind==="process_start").length===1,"one_process_start");
 ck(rows.filter(x=>x.kind==="operation_start").length===2,"two_read_admissions");
 ck(rows.filter(x=>x.kind==="operation_status").length===2,"two_original_status_calls");
 ck(rows.filter(x=>x.kind==="operation_result").length===2,"two_original_payload_pages");
 ck(s.pending===null&&s.activeObserver===null&&!s.nativeCallInFlight&&!s.paused,"local_closed_boundary");
 let start;
 const records=[];
 for(const r of rows){
  const p="calls/"+r.key+"/",raw=files[p+"sdk.original.json"],q=JSON.parse(files[p+"request.json"]);
  ck(eq(gitBlobMeta(files[p+"request.json"]),r.request),r.key+":request_pin");
  ck(eq(gitBlobMeta(raw),r.sdk)&&r.sdkWhole===true,r.key+":sdk_whole_pin");
  const sdk=JSON.parse(raw);ck(sdk.isError!==true,r.key+":sdk_success_first");
  ck(sdk.content.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===files[p+"native.original.json"],r.key+":native_exact");
  ck(eq(gitBlobMeta(files[p+"native.original.json"]),r.native),r.key+":native_pin");
  ck(r.phase==="accepted"&&r.called===true,r.key+":one_accepted_call");
  const intent=JSON.parse(files[p+"intent.json"]),armed=JSON.parse(files[p+"armed.json"]);
  ck(intent.maximumNativeCalls===1&&intent.nativeNotYetCalled===true&&eq(intent.request,r.request),r.key+":pre_dispatch_intent");
  ck(armed.mayHaveDispatchedAfterThisCheckpoint===true&&eq(armed.request,r.request),r.key+":armed_original");
  const v=parseLosslessIntegers(files[p+"native.original.json"]);records.push({r,q,v});
  if(r.kind==="process_start"){start={r,q,v};const typed=processStartBinding(q);
   ck(typed.sha256===s.digest&&typed.native_fingerprint===s.fingerprint,"typed_start_digest_fp");
   ck(v.job.id===s.job&&v.job.host==="rog"&&v.reused===false&&v.launch.ok===true,"unique_start_identity");
   ck(v.job.request_digest===s.digest&&v.job.request_fingerprint.$exactInteger===s.fingerprint,"lossless_ack_binding");
  }
 }
 ck(s.completedObservers.length===2,"two_original_closed_observers");
 for(const o of s.completedObservers){
  const adm=records.find(x=>x.r.kind==="operation_start"&&x.v.operation_id===o.id),st=records.find(x=>x.r.kind==="operation_status"&&x.q.operation_id===o.id),pg=records.find(x=>x.r.kind==="operation_result"&&x.q.operation_id===o.id);
  ck(!!adm&&adm.q.operation.tool===o.tool&&adm.q.operation.arguments.job_id===s.job&&adm.v.reused===false,o.id+":admission_binding");
  ck(st.v.async_state==="completed"&&!st.v.owned_future_active&&st.v.result_state==="stored_observed"&&st.v.payload_available,o.id+":original_inactive_status");
  ck(pg.q.offset===0&&pg.q.limit===8192&&pg.v.operation_id===o.id&&pg.v.immutable_snapshot===true&&pg.v.eof===true,o.id+":original_immutable_page");
  const data=utf8Text(unb64(pg.v.data_base64)),p="observers/"+o.id+"/";
  ck(data===files[p+"payload.original.json"]&&eq(gitBlobMeta(data),o.payload),o.id+":whole_payload_byteexact");
  ck(pg.v.total_bytes===o.payload.bytes&&pg.v.next_offset===o.payload.bytes&&pg.v.result_sha256===o.payload.sha256,o.id+":whole_payload_range_hash");
  const payload=parseLosslessIntegers(data);ck(payload.resultType==="complete"&&payload.isError===false&&payload.content.length===1,o.id+":original_payload_success");
  ck(payload.content[0].text===files[p+"native.original.json"]&&eq(gitBlobMeta(payload.content[0].text),o.nativeText),o.id+":native_payload_exact");
  ck(o.completedInactive===true&&o.pages===1,o.id+":closed_index");
 }
 const a=parseLosslessIntegers(files["observers/"+s.completedObservers[0].id+"/native.original.json"]);
 const v=parseLosslessIntegers(files["observers/"+s.completedObservers[1].id+"/native.original.json"]);
 ck(a.job_id===s.job&&a.exit_code===0&&a.state==="succeeded"&&a.output_complete&&a.output_durable&&a.terminal_publication_confirmed&&!a.timed_out,"known_success_full_durable");
 for(const name of ["stdout","stderr"]){const r=v[name],bs=[];for(let i=0;i<r.bytes_hex.length;i+=2)bs.push(parseInt(r.bytes_hex.slice(i,i+2),16));
  ck(utf8Text(bs)===r.text&&r.text===files["actual/"+name+".original.txt"],name+":hex_text_exact");
  ck(r.offset===0&&r.next_offset===bs.length&&r.size===bs.length&&r.eof&&a.log_bytes[name].stored===bs.length&&a.log_bytes[name].seen===bs.length,name+":full_eof_authority");
 }
 const summary=JSON.parse(v.stdout.text);
 ck(gitBlobMeta(v.stdout.text).bytes===374&&v.stderr.text==="","complete_374_stdout_zero_stderr");
 ck(summary.source_commit==="025b05a340de841b8161c1120344e86eae30eb97"&&summary.source_tree==="1d8160c9385f8053b9a683cc1834da0f912e2d37","exact_source_commit_tree_summary");
 ck(summary.status==="prepared"&&summary.all_owned_stopped===true&&summary.within_new_stage_deadline===true&&summary.compiler_started===false&&summary.server_started===false,"terminal_summary_no_product");
 ck(summary.result_path==="/home/qian-qi/heptabao-native-jwt-pki-source-025b05a3-20261106-r1/control/stage-result.public.json","fixed_report_path_summary");
 return {schema:"heptabao.jwt-pki-025b-stage-original-chain-verification.r1",status:"PASS",checks:checks.length,results:checks,Runtime_calls:0,product_tests:0,scope:"original 7 calls / 2 observers / 2 pages / whole summary; detailed report and build remain pending"};
}
