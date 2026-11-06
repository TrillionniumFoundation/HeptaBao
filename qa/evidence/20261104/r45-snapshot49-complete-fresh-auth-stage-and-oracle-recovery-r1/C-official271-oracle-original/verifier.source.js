function verifyOfficialAcl23OriginalChain(files) {
 const checks=[];function check(name,value){checks.push({name,passed:!!value});if(!value)throw Error(name);}
 const parse=raw=>parseLosslessIntegers(raw),same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),integer=v=>Number.isSafeInteger(v)?String(v):v?.$exactInteger;
 const pin=(raw,want)=>{const got=gitBlobMeta(raw);return same(got,{blob:want.blob,bytes:want.bytes,sha256:want.sha256});};
 const g=parse(files["ROOT-GO.public.json"]),q=parse(files["REQUEST.original.json"]),s=parse(files["STATE.original.json"]),index=parse(files["CALL-INDEX.public.json"]),release=parse(files["RELEASE.public.json"]);
 check("whole exact GO",pin(files["ROOT-GO.public.json"],{blob:"f2ad9c134f825e4a3d01b6b26f7e389e5586f4ce",bytes:6932,sha256:"1c878e4714ad614af5b745159a9b2afab5c53c0780daf09e79c3b8b90f464fb0"}));
 check("exact original request",pin(files["REQUEST.original.json"],g.exactProcessStart));
 check("exact journal",pin(files["journal.original.js"],g.journal));
 check("fixed host/executable/outer",q.host==="x230"&&q.executable==="/usr/bin/python3"&&q.timeout_seconds===390);
 check("fixed requested argv/body identities",gitBlobMeta(q.args[4]).sha256===g.exactEntry.sha256&&gitBlobMeta(q.stdin).sha256===g.exactPublicPayload.sha256&&q.args[5]===g.exactEntry.sha256);
 const binding=processStartBinding(q);
 check("typed canonical digest",binding.sha256===g.nativeBinding.sha256&&binding.native_fingerprint===g.nativeBinding.native_fingerprint&&utf8Bytes(binding.canonical).length===g.nativeBinding.canonicalBytes);
 check("closed retained slot",s.job==="1a1b17f9eff-fc05-7932"&&s.startCalled&&!s.paused&&!s.nativeCallInFlight&&s.pending===null&&s.activeObserver===null);
 check("seven original calls two original observers",index.length===7&&Object.keys(s.calls).length===7&&s.completedObservers.length===2);
 check("exact kind order",same(index.map(c=>c.kind),["process_start","operation_start","operation_status","operation_result","operation_start","operation_status","operation_result"]));
 const values=[];
 for(const row of index) {
  const c=s.calls[row.key],b=row.prefix,reqRaw=files[b+".request.original.json"],req=parse(reqRaw),sdkRaw=files[b+".sdk.original.json"],sdk=parse(sdkRaw),nativeRaw=files[b+".native.original.json"],native=parse(nativeRaw),intent=parse(files[b+".intent.original.json"]),armed=parse(files[b+".armed.original.json"]);
  check(b+" exact request/SDK/native pins",pin(reqRaw,c.requestPin)&&pin(sdkRaw,c.sdkPin)&&pin(nativeRaw,c.nativePin));
  check(b+" accepted complete external archives",c.called===true&&c.phase==="accepted"&&c.armed.whole===true&&c.sdkArchive.whole===true);
  check(b+" original SDK text unchanged",sdk.isError!==true&&sdk.content?.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===nativeRaw);
  check(b+" original intent and scope",intent.callKey===row.key&&intent.kind===row.kind&&same(intent.request,c.requestPin)&&same(intent.rootGo,s.goPin)&&intent.maximumNativeCalls===1&&intent.nativeNotYetCalled===true);
  check(b+" original armed boundary",armed.callKey===row.key&&armed.mayHaveDispatchedAfterThisCheckpoint===true&&same(armed.rootGo,s.goPin)&&same(armed.request,c.requestPin));
  const armRows=[["request.json",reqRaw],["intent.json",files[b+".intent.original.json"]],["armed.json",files[b+".armed.original.json"]]].map(([path,raw])=>({path,type:"blob",mode:"100644",sha:gitBlobMeta(raw).blob}));
  check(b+" original 3-leaf arm Merkle",gitTreeAudit({sha:row.armedTree,tree:armRows,truncated:false}).leaf_count===3);
  check(b+" original SDK Merkle",gitTreeAudit({sha:row.sdkTree,tree:[{path:"original.sdk.json",type:"blob",mode:"100644",sha:gitBlobMeta(sdkRaw).blob}],truncated:false}).leaf_count===1);
  values.push({row,req,native});
 }
 const start=values[0].native;
 check("original unique ACK",start.reused===false&&start.audit_recorded===true&&start.local_record_pending===false&&start.launch.ok===true&&start.job.id===s.job);
 check("actual ACK typed identity",start.job.request_digest===binding.sha256&&integer(start.job.request_fingerprint)===binding.native_fingerprint&&start.job.host===q.host&&same(start.job.args,q.args)&&start.job.executable===q.executable&&start.job.cwd===q.cwd&&start.job.idempotency_key===q.idempotency_key);
 const originals=[];
 for(let i=0;i<2;i++){
  const base=1+i*3,admit=values[base],status=values[base+1],page=values[base+2],o=s.completedObservers[i],tool=i===0?"process_status":"process_read";
  check("observer"+i+" exact original job",admit.req.operation.tool===tool&&admit.req.operation.arguments.host==="x230"&&admit.req.operation.arguments.job_id===s.job);
  check("observer"+i+" unique admission",admit.native.operation_id===o.id&&admit.native.tool_name===tool&&admit.native.reused===false&&admit.native.automatic_retry===false);
  check("observer"+i+" known original future closed",status.req.operation_id===o.id&&status.native.operation_id===o.id&&status.native.async_state==="completed"&&status.native.owned_future_active===false&&status.native.result_state==="stored_observed"&&status.native.payload_available===true);
  check("observer"+i+" exact original immutable page request",page.req.operation_id===o.id&&page.req.offset===0&&page.req.limit===8192);
  const v=page.native,bytes=unb64(v.data_base64),payload=files["observer-"+i+".payload.original.json"];
  check("observer"+i+" immutable full range",v.operation_id===o.id&&v.offset===0&&v.next_offset===bytes.length&&v.total_bytes===bytes.length&&bytes.length<=8192&&v.eof===true&&v.immutable_snapshot===true);
  check("observer"+i+" payload whole original",utf8Text(bytes)===payload&&pin(payload,o.payload)&&gitBlobMeta(payload).sha256===v.result_sha256&&o.pages===1&&o.completedInactive===true);
  check("observer"+i+" original payload Merkle",gitTreeAudit({sha:o.payloadTree,tree:[{path:"payload.original.json",type:"blob",mode:"100644",sha:gitBlobMeta(payload).blob}],truncated:false}).leaf_count===1);
  const parsed=parse(payload),nativeRaw=files["observer-"+i+".native.original.json"];
  check("observer"+i+" original native success envelope",parsed.resultType==="complete"&&parsed.isError===false&&parsed.content?.length===1&&parsed.content[0].text===nativeRaw&&pin(nativeRaw,o.nativeText));
  const n=parse(nativeRaw);check("observer"+i+" returned original job",n.job_id===s.job);originals.push(n);
 }
 const [authority,streams]=originals;
 check("known failed terminal without timeout",authority.state==="failed"&&authority.exit_code===1&&authority.timed_out===false&&authority.cancelled===false);
 check("terminal publication and durable whole output",authority.output_complete&&authority.output_durable&&authority.terminal_publication_confirmed&&authority.log_synced.stdout&&authority.log_synced.stderr&&!authority.log_truncated.stdout&&!authority.log_truncated.stderr&&authority.log_errors.stdout===null&&authority.log_errors.stderr===null);
 for(const k of ["stdout","stderr"]){
  const row=streams[k],raw=files[k.toUpperCase()+".original.txt"],bytes=utf8Bytes(raw),hex=bytes.map(b=>b.toString(16).padStart(2,"0")).join("");
  check(k+" exact complete raw stream",row.text===raw&&row.bytes_hex===hex&&row.offset===0&&row.next_offset===bytes.length&&row.size===bytes.length&&row.eof&&authority.log_bytes[k].seen===bytes.length&&authority.log_bytes[k].stored===bytes.length);
 }
 check("continuous finite cursors",s.nextStdout===782&&s.nextStderr===0&&values[4].req.operation.arguments.stdout_offset===0&&values[4].req.operation.arguments.stderr_offset===0&&values[4].req.operation.arguments.limit===16384);
 const terminal=parse(files["STDOUT.original.txt"]);
 check("actual failure retained unnormalized",terminal.capture_complete===false&&terminal.failure.code==="common_config_projection_mismatch"&&terminal.failure.stage==="original_launcher_and_acl23"&&terminal.failure.class==="BaoError");
 check("actual entry FD boundary only",terminal.entry_fd_count===12&&terminal.all_entry_file_descriptors_closed===true&&terminal.pending_signal===null&&terminal.original_owner_receipt_present===true);
 check("actual report pointer only",terminal.report.bytes===36658&&terminal.report.sha256==="4b72f600f6b794c5cf7198ebe76696179cd2477da587113a5ee7bfe81be3eece"&&terminal.report.closed===true&&terminal.report.relative==="result.public.json");
 check("no parity or candidate qualification",terminal.parity_qualified===false&&terminal.candidate_started===false&&terminal.component_product_cases===0&&release.qualification.aclCaseCountObserved===null&&release.qualification.ownerChildClosureIndependentlyObserved===false);
 check("no further Native admission claim",release.laneReleased===true&&release.nativeCallsRemainingAuthorized===0);
 return {schema:"heptabao.official271.ACL23.original-chain-actual-checks.r1",pass:true,check_count:checks.length,checks,calls:7,observers:2,pages:2,stdoutBytes:782,stderrBytes:0,originalExit:1,actualAclCases:null,reportMetadataIndependentlyRead:false,ownerChildClosureIndependentlyRead:false,RuntimeCallsByVerifier:0,sourceOrTestExecutionByVerifier:0};
}
