function verify(input) {
 const checks=[];const ck=(name,ok)=>{checks.push({name,passed:ok===true});if(ok!==true)throw new Error(name);};
 ck("reviewed_before_whole",gitBlobMeta(input.before).blob==="d8d792caa494c8c2e084db5cea908d0833ce309f");
 ck("current_pki_process_journal",gitBlobMeta(input.current).blob==="3f6bb9e67890d08af99adb01c29054869fff75c3");
 let out=input.before;
 for(const r of input.replacements){ck("literal_count:"+r.from.slice(0,55),out.split(r.from).length-1===r.count);out=out.split(r.from).join(r.to);}
 ck("forward_exact",out===input.after);
 let rev=input.after;for(const r of input.replacements.slice().reverse())rev=rev.split(r.to).join(r.from);
 ck("reverse_exact",rev===input.before);
 const q=JSON.parse(input.requestRaw);
 ck("one_fixed_file_info",q.operation.tool==="file_info"&&Object.keys(q.operation.arguments).sort().join(",")==="host,path");
 ck("host_path_exact",q.operation.arguments.host==="rog"&&q.operation.arguments.path==="/home/qian-qi/heptabao-native-pki-lease400-format-20261106-r1/result.public.json");
 ck("exact_key",q.idempotency_key==="heptabao-native-pki-lease400-formatter-observe-r1-receipt-info0");
 ck("request_constant",input.after.includes("const GF_FORMATTER_RECEIPT_INFO_REQUEST = "+JSON.stringify(gitBlobMeta(input.requestRaw))+";"));
 ck("original_process_constant",input.after.includes("const GF_REQUEST = "+JSON.stringify(input.processRequestPin)+";"));
 ck("prerequisites_constant",input.after.includes("const GF_FORMATTER_RECEIPT_INFO_PREREQUISITES = "+JSON.stringify(input.prerequisites)+";"));
 ck("receipt_cap_original",input.after.includes("const GF_FORMATTER_RECEIPT_MAX_BYTES = 65536;"));
 ck("actual_job_guard",input.after.includes('s.job==="1a1af6d62a1-fc05-686a"'));
 const authority=parseLosslessIntegers(input.authority),streams=parseLosslessIntegers(input.streams),summary=JSON.parse(streams.stdout.text);
 ck("prior_authority_exact",gitBlobMeta(input.authority).blob===input.prerequisites[0].nativeText.blob&&authority.job_id==="1a1af6d62a1-fc05-686a"&&authority.exit_code===0&&authority.output_complete===true&&authority.output_durable===true&&authority.terminal_publication_confirmed===true);
 ck("prior_streams_exact",gitBlobMeta(input.streams).blob===input.prerequisites[1].nativeText.blob&&streams.job_id===authority.job_id&&streams.stdout.eof===true&&streams.stderr.eof===true&&streams.stdout.size===921&&streams.stderr.size===0);
 ck("two_file_summary",summary.files.length===2&&summary.status==="passed"&&summary.allOwnedStopped===true&&summary.withinDeadline===true&&summary.root==="/home/qian-qi/heptabao-native-pki-lease400-format-20261106-r1");
 ck("original_state_closed",input.originalState.pending===null&&input.originalState.activeObserver===null&&input.originalState.nativeCallInFlight===false&&input.originalState.completedObservers.length===2&&input.originalState.completedObservers.every(o=>o.completedInactive===true));
 return {schema:"heptabao.pki-formatter-receipt-info-source-checks.r1",passed:true,count:checks.length,checks,runtime_executed:false,journal_executed:false,formatter_replayed:false};
}
