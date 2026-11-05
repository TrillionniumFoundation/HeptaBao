function verifyAliasActual(raw,utf8,byteString,sha256,unb64){
 const checks=[];function ck(n,v){if(!v)throw Error(n);checks.push(n);}
 function hash(s){return sha256(byteString(utf8(s)));}
 function native(p){const x=JSON.parse(raw[p]);return x.content?.[0]?.text?JSON.parse(x.content[0].text):x;}
 function decode(s){return decodeURIComponent(unb64(s).map(x=>"%"+x.toString(16).padStart(2,"0")).join(""));}
 const req=JSON.parse(raw["dispatch/request.exact.json"]),ack=JSON.parse(raw["dispatch/ack.native.original.json"]),start=JSON.parse(raw["dispatch/start.original-sdk.json"]),intent=JSON.parse(raw["dispatch/external-intent.original.json"]),go=JSON.parse(raw["dispatch/root-go.original.json"]);
 ck("original start SDK exact native",start.isError===false&&start.content[0].text===raw["dispatch/ack.native.original.json"]);
 ck("exact request source and selfhash",req.args[4]===raw["source/read_failed_qa_cargo_aliases_r2.py"]&&req.args[5]===hash(req.args[4])&&req.args[5]==="4e72160c838092ff1706fc1b14f826b500edfef2ea68f335d80df5b1148ebf12");
 ck("exact intent and GO request binding",intent.exact_request.sha256===hash(raw["dispatch/request.exact.json"])&&intent.exact_request.bytes===utf8(raw["dispatch/request.exact.json"]).length&&intent.root_go.sha256===hash(raw["dispatch/root-go.original.json"])&&go.exact_request.sha256===intent.exact_request.sha256&&intent.pre_submit===true&&intent.single_submission_required===true);
 ck("unique observed job",ack.reused===false&&ack.job.id==="1a1ab2db7e2-fc05-4b25"&&ack.job.launch_state==="launched"&&ack.launch.ok);
 for(const k of ["host","executable","args","cwd","idempotency_key"])ck("ACK exact "+k,JSON.stringify(ack.job[k])===JSON.stringify(req[k]));
 const canonical=JSON.stringify({args:req.args,cpu_quota_percent:null,cwd:req.cwd,env:{},executable:req.executable,host:req.host,memory_max_bytes:null,nice:null,stdin:null,timeout_seconds:req.timeout_seconds});
 ck("actual canonical request digest",ack.job.request_digest===hash(canonical));
 ck("original outer45 and operator scope",req.timeout_seconds===45&&req.host==="rog"&&req.executable==="/usr/bin/python3.12"&&req.cwd==="/home/qian-qi");
 for(const label of ["authority-01","streams-01"]){
  const sdkPath="sdk/"+label+".original.json",sdk=JSON.parse(raw[sdkPath]),actualPath="actual/"+label+".original.json";
  const page=native("operations/"+label+"/page-000000.original.json"),status=native("operations/"+label+"/status-1.original.json"),opreq=JSON.parse(raw["operations/"+label+"/request.public.json"]);
  ck(label+" native original SDK exact",sdk.isError===false&&sdk.content[0].text===raw[actualPath]);
  ck(label+" whole immutable SDK bytes",decode(page.data_base64)===raw[sdkPath]&&page.result_sha256===hash(raw[sdkPath])&&page.offset===0&&page.next_offset===page.total_bytes&&page.total_bytes===utf8(raw[sdkPath]).length&&page.eof&&page.immutable_snapshot);
  ck(label+" completed read operation",status.operation_id===page.operation_id&&status.async_state==="completed"&&status.result_state==="stored_observed"&&!status.owned_future_active&&status.payload_available&&!status.automatic_retry&&status.tool_name===(label==="authority-01"?"process_status":"process_read"));
 }
 const authority=JSON.parse(raw["actual/authority-01.original.json"]),streams=JSON.parse(raw["actual/streams-01.original.json"]);
 ck("authoritative full durable zero",authority.job_id===ack.job.id&&streams.job_id===ack.job.id&&authority.state==="succeeded"&&authority.exit_code===0&&authority.output_complete&&authority.output_durable&&authority.terminal_publication_confirmed&&!authority.timed_out&&!authority.cancelled&&!authority.automatic_retry);
 for(const s of ["stdout","stderr"]){
  const x=streams[s],text=raw["actual/"+s+(s==="stdout"?".original.json":".original.txt")],bytes=utf8(text);
  ck(s+" exact full original EOF",x.text===text&&x.bytes_hex===bytes.map(x=>x.toString(16).padStart(2,"0")).join("")&&x.offset===0&&x.next_offset===bytes.length&&x.size===bytes.length&&x.eof);
  ck(s+" authority byte closure",authority.log_bytes[s].seen===bytes.length&&authority.log_bytes[s].stored===bytes.length&&authority.log_synced[s]&&!authority.log_truncated[s]&&authority.log_errors[s]===null);
 }
 const core=JSON.parse(raw["actual/stdout.original.json"]);
 ck("actual fixed two-alias observation",core.status==="observed_fixed_two_aliases"&&core.source_sha256===req.args[5]&&core.error===null&&core.cancel_signal===null);
 ck("exact later full-nine identity",JSON.stringify(core.full_identity)===JSON.stringify(["66306","31633993","1000","1000","33216","2","4616576","1793869496670294192","1793869496695294129"])&&core.primary_version==="66306:31633993:4616576:1793869496670294192:1793869496695294129");
 const base="/home/qian-qi/heptabao-cold-h2-normal-20261105-r1/target-normal-r3/release/";
 ck("exact full link set",core.aliases.length===2&&core.aliases[0].path===base+"heptabao-native-h2-qa"&&core.aliases[1].path===base+"deps/heptabao_native_h2_qa-524c7b86fe50735e"&&core.expected_link_count===2&&core.same_full_identity&&core.link_count_fully_accounted_for);
 ck("both complete artifact hashes",core.aliases.every(x=>x.bytes===4616576&&x.sha256==="1f1c6eccf1ac9652a69572cb270b1d3d99a3402eaabf6d7feed6e4b2c4d55b13"));
 ck("original census limits",core.directory_entries_seen===1106&&core.directory_entries_seen<=16384&&core.directory_name_bytes===36135&&core.directory_name_bytes<=1048576&&core.qa_prefix_candidates===1&&core.qa_prefix_candidates<=32);
 ck("body and two EOF accounting",core.body_bytes_limit===9233152&&core.body_bytes_read===9233152&&core.eof_probe_calls===2&&core.eof_probe_bytes_limit===2&&core.eof_probe_bytes_read===0&&core.bytes_read===core.body_bytes_read+core.eof_probe_bytes_read&&core.total_returned_bytes_limit===9233154);
 ck("all9 FDs once closed",core.fds_opened===9&&core.fds_closed_once===9&&core.fd_closure_rows.length===9&&core.fds_remaining===0&&core.fd_close_failures===0&&core.fd_closure_rows.every((x,i)=>x.ordinal===i+1&&x.close_attempted&&x.closed&&x.close_error===null&&x.close_errno===null));
 ck("iterator once closed no unknown",core.iterator_created&&core.iterator_close_attempted&&core.iterator_closed_once&&core.iterator_close_error===null&&core.all_registered_resources_closed&&!core.resource_outcome_unknown&&!core.open_registration_unknown&&!core.iterator_open_unknown);
 ck("all cleanup within original15",core.elapsed_after_closure_ns===10994143&&core.elapsed_after_closure_ns<15000000000&&core.within_original_read_deadline_after_closure);
 ck("zero product children network writes",["binary_executions","child_starts","network_requests","file_writes"].every(k=>core[k]===0)&&core.original_qa_r2_result_remains_failed);
 const inputs=JSON.parse(raw["verification/alias-r2-actual-input.json"]);
 for(const [k,path] of [["request","dispatch/request.exact.json"],["ack","dispatch/ack.native.original.json"],["authority","actual/authority-01.original.json"],["streams","actual/streams-01.original.json"],["go","dispatch/root-go.original.json"]])ck("original50 verifier input exact "+k,inputs[k]===raw[path]);
 const ex=JSON.parse(raw["verification/verification.exec.original.json"]),result=JSON.parse(raw["verification/verification.stdout.original.json"]);
 ck("original50 author pure checks actual0 retained",ex.exit_code===0&&JSON.stringify(JSON.parse(ex.output))===JSON.stringify(result)&&result.check_count===50&&result.checks.every(x=>x.passed)&&result.host_requests===0&&!result.main_or_observer_executed);
 return {schema:"heptabao.root.fixed-cargo-alias-actual-review.v1",status:"PASS_OBSERVATION_NOT_BUILD_QUALIFICATION",checks_count:checks.length,checks,job:ack.job.id,aliases:core.aliases,full_identity:core.full_identity,elapsed_after_closure_ns:core.elapsed_after_closure_ns,source_sha256:core.source_sha256,original_r2_build_still_failed:true,new_build_executed:false,limits:"This proves the later existing fixed artifact alias set only; future compile must capture its own size, hash and identities."};
}
