function verifyMac576StageOriginalChain(files) {
 const checks=[]; function ok(name,value){if(!value)throw Error(name);checks.push(name);}
 function eq(a,b){return JSON.stringify(a)===JSON.stringify(b);}
 function meta(raw,pin){const m=gitBlobMeta(raw);return m.blob===pin.blob&&m.bytes===pin.bytes&&m.sha256===pin.sha256;}
 function tree(sha,rows){return gitTreeAudit({sha,truncated:false,tree:rows.map(([path,pin])=>({path,mode:"100644",type:"blob",sha:pin.blob}))});}
 const s=JSON.parse(files["STATE.original.json"]),idx=JSON.parse(files["CALL-INDEX.public.json"]),g=JSON.parse(files["ROOT-GO.original.json"]),r=JSON.parse(files["RELEASE.original.json"]),actual=JSON.parse(files["ACTUAL.public.json"]);
 ok("fixed_immutable_closed_state",meta(files["STATE.original.json"],{blob:"c1ce8e3901479c1c99784569d3ea29ada9f35869",bytes:59491,sha256:"6bdb91838f2009cf45fb69a5dc2beab984b48f4ab894ef48ab0b93182d1b9bc1"}));
 ok("exact_GO",meta(files["ROOT-GO.original.json"],{blob:"1a8e8424b14962df0c3d49b67a0b549f6a1abf58",bytes:6318,sha256:"3ff1cb3b1c4c68d996ee5dd8904a8f0cccdc49ef9c09be11169aa485fc05e21f"}));
 ok("whole_GO_original_state",s.rootGoWhole===true&&s.goRaw===files["ROOT-GO.original.json"]&&meta(s.goRaw,s.goPin)&&eq(s.goPin,idx.rootGO));
 ok("original_job_and_call_order",s.job==="1a1b2f48641-fc05-8042"&&idx.originalJob===s.job&&Object.keys(s.calls).length===7&&idx.calls.length===7&&idx.calls.every((x,i)=>x.index===i&&x.key===Object.keys(s.calls)[i]));
 ok("closed_lane",s.pending===null&&s.activeObserver===null&&s.nativeCallInFlight===false&&s.paused===false&&s.startCalled===true&&s.completedObservers.length===2);
 ok("no_extra_observations",eq(idx.calls.map(x=>x.kind),["process_start","operation_start","operation_status","operation_result","operation_start","operation_status","operation_result"])&&idx.observers.length===2);
 const native=[],requests=[];let merkleTrees=0;
 for(const row of idx.calls){
  const c=s.calls[row.key],qraw=files[row.files.request],iraw=files[row.files.intent],araw=files[row.files.armed],sdkraw=files[row.files.sdk],nraw=files[row.files.native],prefix="call"+row.index+"_";
  const q=JSON.parse(qraw),i=JSON.parse(iraw),a=JSON.parse(araw),sdk=JSON.parse(sdkraw),n=parseLosslessIntegers(nraw);
  requests.push(q);native.push(n);
  ok(prefix+"original_request",qraw===c.requestRaw&&meta(qraw,c.requestPin)&&eq(row.request,c.requestPin));
  ok(prefix+"original_sdk",meta(sdkraw,c.sdkPin)&&eq(row.sdk,c.sdkPin)&&c.sdkArchive.whole===true);
  ok(prefix+"original_native",meta(nraw,c.nativePin)&&eq(row.native,c.nativePin)&&sdk.isError===false&&sdk.content.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===nraw);
  ok(prefix+"accepted_once",c.called===true&&c.phase==="accepted"&&c.kind===row.kind&&c.armed.whole===true);
  const local={"request.json":qraw,"intent.json":iraw,"armed.json":araw};
  ok(prefix+"arm_exact_three",c.armed.entries.length===3&&Object.keys(local).every(path=>{const e=c.armed.entries.find(x=>x.path===path);return e?.whole===true&&meta(local[path],e);}));
  ok(prefix+"indexed_intent_and_arm",meta(iraw,row.intent)&&meta(araw,row.armed));
  ok(prefix+"whole_arm_Merkle",tree(row.armTree,Object.entries(local).map(([path,raw])=>[path,gitBlobMeta(raw)])).leaf_count===3&&row.armTree===c.armed.tree);merkleTrees++;
  ok(prefix+"whole_sdk_Merkle",tree(row.sdkTree,[["original.sdk.json",c.sdkPin]]).leaf_count===1&&row.sdkTree===c.sdkArchive.tree);merkleTrees++;
  ok(prefix+"intent_GO_and_once",i.callKey===row.key&&i.kind===c.kind&&eq(i.request,c.requestPin)&&eq(i.rootGo,s.goPin)&&i.maximumNativeCalls===1&&i.nativeNotYetCalled===true&&i.lossOfAcknowledgmentNeverGrantsReplay===true);
  ok(prefix+"armed_GO_and_once",a.callKey===i.callKey&&a.kind===i.kind&&eq(a.request,i.request)&&eq(a.rootGo,i.rootGo)&&a.maximumNativeCalls===1&&a.nativeNotYetCalled===true&&a.mayHaveDispatchedAfterThisCheckpoint===true);
  ok(prefix+"original_job_arm",i.originalJob===(row.index===0?null:s.job)&&a.originalJob===i.originalJob&&a.originalOperation===i.originalOperation);
 }
 const q=requests[0],ack=native[0],typed=processStartBinding(q);
 ok("exact_START_request_pin",meta(files[idx.calls[0].files.request],g.exactRequest)&&g.exactRequest.blob==="3b86e61a47028c1b5d8e23369ef336490dc6382b");
 ok("correct_stdin_typed_binding",typed.sha256===s.digest&&typed.sha256==="dae9bc16adfb96104073ba4a7571815b5aa6d153f961454d671b1e3a947b7d24"&&typed.native_fingerprint===s.fingerprint&&typed.native_fingerprint==="15774345975436121616");
 ok("exact_source_and_carrier",q.args[0]==="-I"&&q.args[1]==="-S"&&q.args[2]==="-B"&&q.args[3]==="-c"&&meta(q.args[4],g.source)&&meta(q.stdin,g.carrier)&&gitBlobMeta(q.stdin).bytes===7772);
 ok("fixed_executable_host_key_budget",q.host==="mac"&&q.executable==="/opt/homebrew/bin/python3"&&q.cwd==="/Volumes/T5/hepta-vnext-recovery-20261013"&&q.idempotency_key===g.key&&q.timeout_seconds===360&&g.budgets.stage===300&&g.budgets.gitLeaf===90&&g.budgets.clone===180);
 ok("unique_ack",ack.audit_recorded===true&&ack.local_record_pending===false&&ack.reused===false&&ack.launch.ok===true&&ack.job.id===s.job&&ack.job.host==="mac"&&ack.job.execution_mode==="operator"&&ack.job.launch_state==="launched");
 ok("ACK_exact_argv_and_key",ack.job.executable===q.executable&&ack.job.cwd===q.cwd&&eq(ack.job.args,q.args)&&ack.job.idempotency_key===q.idempotency_key&&eq(ack.job.env_keys,Object.keys(q.env??{})));
 ok("ACK_lossless_FP",ack.job.request_digest===typed.sha256&&ack.job.request_fingerprint.$exactInteger===typed.native_fingerprint);
 const originals=[];
 for(const [j,o] of idx.observers.entries()){
  const prefix="observer"+j+"_",sc=s.completedObservers[j],ad=native[o.admissionCall],st=native[o.statusCall],adq=requests[o.admissionCall],stq=requests[o.statusCall];
  const raw=files[o.files.payload],nraw=files[o.files.native],pin=gitBlobMeta(raw),p=parseLosslessIntegers(raw),v=parseLosslessIntegers(nraw); originals.push(v);
  ok(prefix+"fixed_original_ID_and_tool",o.id===sc.id&&o.tool===sc.tool&&ad.operation_id===o.id&&ad.tool_name===o.tool&&ad.reused===false&&ad.automatic_retry===false&&adq.operation.tool===o.tool&&adq.operation.arguments.host==="mac"&&adq.operation.arguments.job_id===s.job);
  ok(prefix+"terminal_original_future",stq.operation_id===o.id&&st.operation_id===o.id&&st.tool_name===o.tool&&st.async_state==="completed"&&st.owned_future_active===false&&st.payload_available===true&&st.result_state==="stored_observed");
  ok(prefix+"retention_cap",st.retention_max_original_bytes===1048576);
  ok(prefix+"closed_record_matches_original",o.completedInactive===true&&sc.completedInactive===true&&o.pages===1&&sc.pages===1&&eq(o.payload,sc.payload)&&eq(o.nativeText,sc.nativeText)&&o.payloadTree===sc.payloadTree);
  ok(prefix+"whole_payload",meta(raw,o.payload)&&pin.bytes<1048576);
  ok(prefix+"whole_payload_Merkle",tree(o.payloadTree,[["payload.original.json",pin]]).leaf_count===1);merkleTrees++;
  ok(prefix+"original_native_envelope",p.resultType==="complete"&&p.isError===false&&p.content.length===1&&p.content[0].type==="text"&&p.content[0].text===nraw&&meta(nraw,o.nativeText)&&v.job_id===s.job);
  let bytes=[],cursor=0;
  for(const ci of o.pageCalls){const page=native[ci],pq=requests[ci],chunk=unb64(page.data_base64);
   ok(prefix+"page_request_and_extent",pq.operation_id===o.id&&pq.offset===cursor&&pq.limit===8192&&page.operation_id===o.id&&page.offset===cursor&&page.next_offset===cursor+chunk.length&&chunk.length<=8192);
   ok(prefix+"page_identity_immutable_EOF",page.immutable_snapshot===true&&page.payload_kind==="native_result"&&page.total_bytes===pin.bytes&&page.result_sha256===pin.sha256&&page.eof===(page.next_offset===pin.bytes)&&encodeBase64Bytes(chunk)===page.data_base64);
   bytes=bytes.concat(chunk);cursor=page.next_offset;
  }
  ok(prefix+"exact_reassembly",cursor===pin.bytes&&utf8Text(bytes)===raw&&meta(utf8Text(bytes),o.payload));
 }
 const a=originals[0],v=originals[1];
 ok("authority_success_full_durable",a.state==="succeeded"&&a.exit_code===0&&a.output_complete===true&&a.output_durable===true&&a.terminal_publication_confirmed===true&&a.terminal_publication_protocol===1&&a.timed_out===false&&a.cancelled===false);
 ok("authority_original_launch_nonce",typeof a.launch_nonce==="string"&&/^[a-f0-9]{32}$/.test(a.launch_nonce)&&a.audit_recorded===true);
 ok("original_read_zero_offsets_and_cap",requests[4].operation.arguments.stdout_offset===0&&requests[4].operation.arguments.stderr_offset===0&&requests[4].operation.arguments.limit===16384);
 for(const name of ["stdout","stderr"]){const row=v[name],raw=files[name+".original.txt"],hex=Array.from(utf8Bytes(raw),b=>b.toString(16).padStart(2,"0")).join("");
  ok(name+"_lossless_text_hex",row.text===raw&&row.bytes_hex===hex);
  ok(name+"_range_EOF",row.offset===0&&row.next_offset===gitBlobMeta(raw).bytes&&row.size===row.next_offset&&row.eof===true&&row.next_offset<=16384);
  ok(name+"_authority_match",a.log_bytes[name].stored===row.size&&a.log_bytes[name].seen===row.size&&a.log_errors[name]===null&&a.log_synced[name]===true&&a.log_truncated[name]===false);
  ok(name+"_release_pin",meta(raw,r[name])&&meta(raw,actual[name]));
 }
 ok("final_cursors",s.nextStdout===378&&s.nextStderr===0&&gitBlobMeta(files["stdout.original.txt"]).bytes===378);
 const summary=JSON.parse(files["stdout.original.txt"]);
 ok("exact_stage_summary",summary.status==="prepared"&&summary.all_owned_stopped===true&&summary.compiler_started===false&&summary.server_started===false&&summary.within_new_stage_deadline===true&&summary.source_commit===g.candidateCommit&&summary.source_tree===g.candidateTree&&summary.result_path===g.freshRoot+"/control/stage-result.public.json");
 ok("release_and_actual_boundary",r.lane_released===true&&r.native_calls_in_flight===0&&r.active_future===0&&r.source_report_whole_read===false&&r.Cargo_started===false&&actual.qualification.detailedSourceReport===false&&actual.qualification.normal117===false&&actual.qualification.full34===false&&actual.qualification.LAN===false&&eq(actual.observedSummary,summary));
 return {schema:"heptabao.mac576-stage.original-chain-verification.v1",pass:true,check_count:checks.length,checks,original_calls:7,original_observers:2,immutable_pages:2,merkle_trees_checked:merkleTrees,job:{host:"mac",id:s.job},typed:{sha256:typed.sha256,fingerprint:typed.native_fingerprint},whole_stdout:gitBlobMeta(files["stdout.original.txt"]),whole_stderr:gitBlobMeta(files["stderr.original.txt"]),summary,scope:"Original transport, terminal and complete stdout summary only; report contents and normal/full34/LAN remain unqualified.",NativeCallsPerformed:0,PythonExecuted:false,CandidateExecuted:false};
}