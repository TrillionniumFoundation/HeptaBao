
function qualifyBuildTerminal(p,statuses,go,releasePhase){
 const checks=[],ck=(name,ok)=>checks.push({name,pass:ok===true}),pin=(raw,pin)=>{const m=gitBlobMeta(raw);return m.blob===pin.blob&&m.bytes===pin.bytes&&m.sha256===pin.sha256;};
 const r=JSON.parse(p.raw["RELEASE.public.json"]),a=JSON.parse(p.raw["authority7.native.original.json"]),startSDK=JSON.parse(p.raw["START.original.sdk.json"]),start=parseLosslessIntegers(startSDK.content[0].text),q=JSON.parse(p.raw["START.request.original.json"]);
 ck("whole_minimal12",p.audit.tree==="1ae0793d6f1ad35da4fc0f1a08721afa538b220e"&&p.pins.length===12&&p.pins.reduce((s,x)=>s+x.bytes,0)===46169);
 ck("same_root_GO",p.raw["ROOT-GO.original.json"]===go.text&&pin(p.raw["ROOT-GO.original.json"],go.pins));
 ck("original_start_request",gitBlobMeta(p.raw["START.request.original.json"]).blob==="dab29b2b82ae23e24c5f78865553c140e9bab5de"&&q.host==="rog"&&q.timeout_seconds===12000);
 const binding=processStartBinding(q);
 ck("original_START_ACK",startSDK.isError===false&&start.job.id==="1a1b10cad9b-fc05-7560"&&start.reused===false&&start.job.request_digest===binding.sha256&&start.job.request_fingerprint.$exactInteger===binding.native_fingerprint);
 ck("exact_terminal_authority",a.job_id===start.job.id&&a.state==="failed"&&a.exit_code===1&&a.timed_out===false&&a.cancelled===false&&a.automatic_retry===false&&a.output_complete===true&&a.output_durable===true&&a.terminal_publication_confirmed===true);
 ck("authority_payload_exact",JSON.parse(p.raw["authority7.payload.original.json"]).content[0].text===p.raw["authority7.native.original.json"]&&JSON.parse(p.raw["authority7.payload.original.json"]).isError===false);
 ck("terminal_stream_accounting",a.log_bytes.stdout.seen===2216&&a.log_bytes.stdout.stored===2216&&a.log_bytes.stderr.seen===0&&a.log_bytes.stderr.stored===0&&a.log_synced.stdout&&a.log_synced.stderr&&!a.log_truncated.stdout&&!a.log_truncated.stderr&&a.log_errors.stdout===null&&a.log_errors.stderr===null);
 ck("release_authority_same",JSON.stringify(r.terminal)===JSON.stringify(a)&&r.original_calls===31&&r.returned_observers===10&&r.payload_pages===10);
 ck("all_closed_statuses_available",statuses.length===10&&r.closed_statuses.length===10&&r.completed_observers.length===10&&new Set(r.completed_observers.map(x=>x.id)).size===10);
 for(let i=0;i<statuses.length;i++){
 const row=statuses[i],record=r.closed_statuses[i],sdk=JSON.parse(row.raw.text),raw=sdk.content[0].text,v=JSON.parse(raw),o=r.completed_observers[i];
 ck("original_status_"+i,record.key===row.key&&pin(row.raw.text,record.sdk)&&pin(raw,record.native)&&sdk.isError===false&&sdk.content.length===1&&sdk.content[0].type==="text"&&v.operation_id===o.id&&v.tool_name===o.tool&&v.async_state==="completed"&&v.owned_future_active===false&&v.payload_available===true&&v.result_state==="stored_observed"&&v.automatic_retry===false&&o.completedInactive===true);
 }
 ck("ledger_has_no_active_call_or_future",r.native_call_in_flight===false&&r.pending===null&&r.active_observer===null&&r.all_returned_observers_completed_inactive===true&&r.lane_released===true);
 let out="",err="",outOffset=0,errOffset=0;
 for(let i=0;i<2;i++){
 const raw=p.raw["streams"+i+".native.original.json"],v=JSON.parse(raw),range=r.stream_ranges[i];
 ck("stream_original_"+i,v.job_id===start.job.id&&pin(raw,range.observer.nativeText));
 for(const name of ["stdout","stderr"]){const z=v[name],bytes=[];for(let j=0;j<z.bytes_hex.length;j+=2)bytes.push(parseInt(z.bytes_hex.slice(j,j+2),16));
 ck("stream_extent_"+i+"_"+name,utf8Text(bytes)===z.text&&z.next_offset===z.offset+bytes.length&&z.offset===(name==="stdout"?outOffset:errOffset)&&z.offset===range[name][0]&&z.next_offset===range[name][1]&&z.eof===(z.next_offset===z.size));
 if(name==="stdout"){out+=z.text;outOffset=z.next_offset;}else{err+=z.text;errOffset=z.next_offset;}}
 }
 ck("whole_contiguous_streams",out===p.raw["stdout.whole.original.txt"]&&err===p.raw["stderr.whole.original.txt"]&&outOffset===2216&&errOffset===0&&pin(out,r.stdout_whole)&&pin(err,r.stderr_whole));
 const lines=out.trimEnd().split("\n").map(JSON.parse),last=lines.at(-1);
 ck("original_release_prefix_unchanged",out.slice(0,1809)===releasePhase.raw["stdout.original.txt"]||gitBlobMeta(out.slice(0,1809)).blob==="f8cdff6f7fd13dfc36dee01e1a7fad40b3111432");
 ck("three_original_lines",lines.length===3&&lines[0].status==="preflight-admitted"&&lines[1].phase==="normal-production-release-built"&&last.status==="failed");
 ck("last_exact_report_locator",last.result_path==="/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r2/build-tests-r1/result.public.json"&&last.result_sha256==="47748eadb948f08973d7de202272823cd5f031ed99ec62286868236a8cbaa318"&&last.source_commit==="025b05a340de841b8161c1120344e86eae30eb97"&&last.source_tree==="1d8160c9385f8053b9a683cc1834da0f912e2d37");
 ck("terminal_claims_not_promoted_to_detail",last.all_owned_stopped===true&&last.publication_within_original_outer===true&&r.cargo_target_reuse_qualified===false&&r.final_report_independent_metadata_and_body_observed===false&&r.actual_runtime_tests===null&&r.failure_cause===null);
 return {schema:"heptabao.root.PKI025b-original-terminal-minimal-lane-qualification.r44",passed:checks.every(x=>x.pass),checkCount:checks.length,checks,packet:p.audit.tree,originalJob:"rog/1a1b10cad9b-fc05-7560",state:"failed",exitCode:1,timedOut:false,stdoutBytes:2216,stderrBytes:0,closedObserverCount:10,originalCallCountReported:31,full31CallChainQualified:false,nativeLaneReleased:true,cargoTargetReuseQualified:false,finalReport:{path:last.result_path,sha256:last.result_sha256,bytes:null,version:null,independentlyRead:false},runtimeTestResults:null,failureCause:null,normalReleaseIsPhaseOnly:true,newNativeCalls:0,fullReplacement:false};
}
