function verifyOriginalBuildCalls(files){
 const checks=[];const check=(name,ok)=>{checks.push({name,pass:!!ok});if(!ok)throw Error(name);};
 const meta=raw=>gitBlobMeta(raw),eq=(raw,p)=>{const q=meta(raw);return q.blob===p.blob&&q.bytes===p.bytes&&q.sha256===p.sha256;};
 const state=JSON.parse(files["STATE.final.original.json"]),index=JSON.parse(files["CALL-INDEX.public.json"]);
 check("31_original_calls",index.length===31&&Object.keys(state.calls).length===31);
 check("10_returned_observers",state.completedObservers.length===10);
 check("no_pending_or_active",state.pending===null&&state.activeObserver===null&&state.nativeCallInFlight===false&&state.paused===false);
 const native=new Map(),queries=new Map();
 for(const row of index){const stem=String(row.index).padStart(3,"0")+"."+row.key,c=state.calls[row.key];const request=files[stem+".request.json"],sdkRaw=files[stem+".original.sdk.json"],nativeRaw=files[stem+".original.native.json"];
  check(row.key+":request_pin",eq(request,row.request)&&request===c.requestRaw);
  check(row.key+":sdk_pin",eq(sdkRaw,row.sdk));check(row.key+":native_pin",eq(nativeRaw,row.native));
  const sdk=JSON.parse(sdkRaw),q=JSON.parse(request);check(row.key+":sdk_saved_before_success",sdk.isError!==true&&sdk.content?.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===nativeRaw);
  const intent=JSON.parse(files[stem+".intent.json"]),armed=JSON.parse(files[stem+".armed.json"]);
  check(row.key+":exact_armed_identity",intent.callKey===row.key&&intent.kind===row.kind&&intent.request.blob===row.request.blob&&armed.request.blob===row.request.blob&&intent.maximumNativeCalls===1&&intent.nativeNotYetCalled===true&&armed.mayHaveDispatchedAfterThisCheckpoint===true);
  for(const leaf of row.armed.entries)check(row.key+":arm_"+leaf.path,eq(files[stem+"."+leaf.path],leaf)&&leaf.whole===true);
  check(row.key+":once_accepted",c.called===true&&c.phase==="accepted"&&c.armed.whole===true&&c.sdkArchive.whole===true);
  native.set(row.key,parseLosslessIntegers(nativeRaw));queries.set(row.key,q);
 }
 const starts=index.filter(x=>x.kind==="process_start");check("exactly_one_process_start",starts.length===1);const start=native.get(starts[0].key),startQ=queries.get(starts[0].key);
 check("unique_start_binding",start.reused===false&&start.audit_recorded===true&&start.local_record_pending===false&&start.launch.ok===true&&start.job.host==="rog"&&start.job.id===state.job&&start.job.idempotency_key===startQ.idempotency_key&&start.job.request_digest===state.digest&&String(start.job.request_fingerprint.$exactInteger)===state.fingerprint);
 const observed=[];for(let n=0;n<state.completedObservers.length;n++){const o=state.completedObservers[n],stem="observer."+String(n+1).padStart(2,"0")+"."+o.tool,ad=index.filter(x=>x.kind==="operation_start"&&native.get(x.key).operation_id===o.id);
  check(o.id+":one_admission",ad.length===1);const q=queries.get(ad[0].key),ack=native.get(ad[0].key);
  check(o.id+":original_admission",ack.reused===false&&ack.automatic_retry===false&&ack.tool_name===o.tool&&q.operation.tool===o.tool&&q.operation.arguments.host==="rog"&&q.operation.arguments.job_id===state.job);
  const statuses=index.filter(x=>x.kind==="operation_status"&&queries.get(x.key).operation_id===o.id);check(o.id+":one_status",statuses.length===1);
  const status=native.get(statuses[0].key);check(o.id+":known_closed",status.operation_id===o.id&&status.async_state==="completed"&&status.owned_future_active===false&&status.result_state==="stored_observed"&&status.payload_available===true);
  const pages=index.filter(x=>x.kind==="operation_result"&&queries.get(x.key).operation_id===o.id);check(o.id+":one_original_page",pages.length===1&&o.pages===1);
  let bytes=[],at=0,total=null,sha=null;for(const pr of pages){const pq=queries.get(pr.key),page=native.get(pr.key),chunk=unb64(page.data_base64);check(o.id+":immutable_page",pq.limit===8192&&pq.offset===at&&page.operation_id===o.id&&page.offset===at&&page.immutable_snapshot===true&&page.payload_kind==="native_result"&&chunk.length<=8192&&page.next_offset===at+chunk.length&&page.eof===(page.next_offset===page.total_bytes));if(total!==null)check(o.id+":same_payload",page.total_bytes===total&&page.result_sha256===sha);bytes.push(...chunk);at=page.next_offset;total=page.total_bytes;sha=page.result_sha256;}
  const payload=utf8Text(bytes);check(o.id+":full_payload_SHA_EOF",at===total&&meta(payload).sha256===sha&&payload===files[stem+".payload.original.json"]&&eq(payload,o.payload));
  const outer=parseLosslessIntegers(payload);check(o.id+":original_native_success",outer.resultType==="complete"&&outer.isError===false&&outer.content?.length===1&&outer.content[0].type==="text");
  const raw=outer.content[0].text;check(o.id+":native_byte_exact",raw===files[stem+".native.original.json"]&&eq(raw,o.nativeText));
  const v=parseLosslessIntegers(raw);check(o.id+":same_job",v.job_id===state.job);observed.push({o,q:q.operation.arguments,v});
 }
 const statuses=observed.filter(x=>x.o.tool==="process_status"),reads=observed.filter(x=>x.o.tool==="process_read");
 check("eight_authority_two_streams",statuses.length===8&&reads.length===2);
 for(let i=0;i<7;i++)check("authority"+i+"_running",statuses[i].v.state==="running"&&statuses[i].v.backend==="systemd"&&statuses[i].v.systemd?.ActiveState==="active"&&statuses[i].v.systemd?.SubState==="running"&&!Object.prototype.hasOwnProperty.call(statuses[i].v,"exit_code"));
 const terminal=statuses[7].v;check("original_failed_terminal_complete",terminal.exit_code===1&&terminal.state==="failed"&&terminal.output_complete===true&&terminal.output_durable===true&&terminal.terminal_publication_confirmed===true&&terminal.timed_out===false&&terminal.cancelled===false);
 let stdout="",stderr="",next={stdout:0,stderr:0};for(const {v,q,o}of reads)for(const name of["stdout","stderr"]){const x=v[name],bytes=utf8Bytes(x.text),hex=bytes.map(n=>n.toString(16).padStart(2,"0")).join("");check(o.id+":"+name+"_range_hex_text",q[name+"_offset"]===next[name]&&x.offset===next[name]&&x.next_offset===next[name]+bytes.length&&x.bytes_hex===hex&&bytes.length<=16384&&x.size>=x.next_offset);next[name]=x.next_offset;if(name==="stdout")stdout+=x.text;else stderr+=x.text;}
 check("whole_2216_stdout",stdout===files["stdout.whole.original.txt"]&&meta(stdout).bytes===2216&&meta(stdout).sha256==="103dae003432cf92e24a2ed309b720869eebb3b7dae698c59c164337844be357");
 check("stderr_empty",stderr===""&&files["stderr.whole.original.txt"]==="");
 check("terminal_stream_EOF",reads[1].v.stdout.eof===true&&reads[1].v.stderr.eof===true&&next.stdout===2216&&next.stderr===0&&terminal.log_bytes.stdout.stored===2216&&terminal.log_bytes.stderr.stored===0);
 const rows=stdout.trimEnd().split("\n").map(JSON.parse);check("three_actual_rows",rows.length===3&&rows[0].status==="preflight-admitted"&&rows[1].phase==="normal-production-release-built"&&rows[2].status==="failed");
 check("planned149_166_only",rows[0].unique_test_count===149&&rows[0].profile_instance_test_count===166);
 check("final_report_identity_claim",rows[2].result_path==="/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r2/build-tests-r1/result.public.json"&&rows[2].result_sha256==="47748eadb948f08973d7de202272823cd5f031ed99ec62286868236a8cbaa318"&&rows[2].publication_within_original_outer===true&&rows[2].all_owned_stopped===true);
 return {schema:"heptabao.025b.original-build-terminal-chain-checks.v1",passed:checks.length,failed:0,checks,original_calls:31,original_observers:10,pages:10,stdout_bytes:2216,stderr_bytes:0,original_build_exit_code:1,normal_release_phase_observed:true,actual_detailed_report_observed:false,actual_test_results:null,product_test_pass_count:null,new_native_calls:0,source_execution:false};
}
