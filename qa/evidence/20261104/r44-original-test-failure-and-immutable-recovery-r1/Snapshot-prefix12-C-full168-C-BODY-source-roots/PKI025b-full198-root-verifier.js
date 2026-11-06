
function qualifyOriginalBuildFull(p,files,go,minimal,author,infoSource){
 const checks=[],ck=(name,ok)=>checks.push({name,pass:ok===true}),pin=(raw,x)=>{const m=gitBlobMeta(raw);return m.blob===x.blob&&m.bytes===x.bytes&&m.sha256===x.sha256;};
 const manifest=JSON.parse(p.raw["MANIFEST.public.json"]),state=JSON.parse(files["STATE.final.original.json"]),index=JSON.parse(files["CALL-INDEX.public.json"]);
 ck("whole_198_three_tree_packet",p.audit.tree==="8ab6851525ce0843e95db8f5a19ea4582b084ce8"&&p.pins.length===198&&p.pins.reduce((n,x)=>n+x.bytes,0)===529267&&gitTreeAudit(p.tree).trees_verified===3);
 ck("whole_manifest_197_payloads",manifest.files.length===197&&manifest.payload_files===197&&manifest.payload_bytes===473773&&manifest.files.every(x=>x.whole&&pin(p.raw[x.path],x))&&manifest.files.reduce((n,x)=>n+x.bytes,0)===473773);
 ck("original_GO_and_minimal_unchanged",files["ROOT-GO.original.json"]===go.text&&Object.entries(minimal.raw).every(([name,raw])=>files[name]===raw));
 ck("same_state_at_later_INFO_boundary",files["STATE.final.original.json"]===infoSource.raw["STATE.before.original.json"]);
 ck("author403_exact_reproduction",author.exactOriginal&&author.value.passed===403&&author.value.failed===0);
 const byBlob={};for(const raw of Object.values(files))byBlob[gitBlobMeta(raw).blob]=raw;
 const calls=index.map(x=>{const stem=String(x.index).padStart(3,"0")+"."+x.key,c=state.calls[x.key];
 ck("call_index_"+x.index,c.kind===x.kind&&c.called===true&&c.phase==="accepted"&&pin(files[stem+".request.json"],x.request)&&pin(files[stem+".original.sdk.json"],x.sdk)&&pin(files[stem+".original.native.json"],x.native)&&JSON.stringify(c.armed)===JSON.stringify(x.armed)&&JSON.stringify(c.sdkArchive)===JSON.stringify(x.sdkArchive));
 ck("SDK_tree_"+x.index,immediateTreeSha([{path:"original.sdk.json",mode:"100644",type:"blob",sha:x.sdk.blob}])===x.sdkArchive.tree);
 return {key:x.key,kind:c.kind,phase:c.phase,requestPin:c.requestPin,sdkPin:c.sdkPin,nativePin:c.nativePin,requestText:files[stem+".request.json"],intentText:files[stem+".intent.json"],armedText:files[stem+".armed.json"],sdkText:files[stem+".original.sdk.json"],nativeText:files[stem+".original.native.json"],armedTree:c.armed.tree};});
 const cs=verifyOriginalJournal({label:"PKI025b_original_full31",calls,observers:state.completedObservers,blob:sha=>byBlob[sha],goPins:[go.pins],pageLimit:()=>8192,ck});
 const start=cs.find(x=>x.c.kind==="process_start"),binding=processStartBinding(start.q);
 ck("exact_typed_original_start",binding.sha256==="527c6f94dadb62d7f4ff1168adecc80f2b1af2feef6891e28a3bcb2b1673388d"&&binding.native_fingerprint==="5943748293339865815"&&start.n.job.request_digest===binding.sha256&&start.n.job.request_fingerprint.$exactInteger===binding.native_fingerprint&&start.n.reused===false&&start.n.job.id==="1a1b10cad9b-fc05-7560");
 ck("original_call_inventory",calls.length===31&&cs.filter(x=>x.c.kind==="process_start").length===1&&cs.filter(x=>x.c.kind==="operation_start").length===10&&cs.filter(x=>x.c.kind==="operation_status").length===10&&cs.filter(x=>x.c.kind==="operation_result").length===10);
 ck("observer_scope_and_budgets",cs.filter(x=>x.c.kind==="operation_start").every(x=>x.q.operation.arguments.host==="rog"&&x.q.operation.arguments.job_id===state.job&&["process_status","process_read"].includes(x.q.operation.tool))&&state.completedObservers.filter(x=>x.tool==="process_status").length===8&&state.completedObservers.filter(x=>x.tool==="process_read").length===2);
 ck("original_journal_and_source_identity",gitBlobMeta(files["journal.original.js"]).blob==="bcb88527395732519b1db1ddc59312b54059d93e"&&start.q.args[7]==="025b05a340de841b8161c1120344e86eae30eb97"&&start.q.args[9]==="1d8160c9385f8053b9a683cc1834da0f912e2d37"&&start.q.timeout_seconds===12000);
 ck("original_checker_failure_preserved",typeof files["verifier.r1.error.public.json"]==="string"&&typeof files["verifier.r1.original.js"]==="string"&&files["verifier.r1.original.js"]!==files["verifier.corrected.source.js"]);
 ck("detailed_report_not_promoted",author.value.actual_detailed_report_observed===false&&author.value.actual_test_results===null&&author.value.product_test_pass_count===null);
 return {schema:"heptabao.root.PKI025b-original-BUILD-full198-qualification.r44",passed:checks.every(x=>x.pass),checkCount:checks.length,checks,packet:p.audit.tree,originalJob:"rog/1a1b10cad9b-fc05-7560",author403Reproduced:true,originalCalls:31,originalObservers:10,originalPages:10,stdoutBytes:2216,stderrBytes:0,actualTerminalState:"failed",actualExitCode:1,fullOriginalObservationChainQualified:true,normalReleasePhaseObserved:true,detailedReportQualified:false,runtimeTestPassCount:null,cargoTargetReuseQualified:false,newNativeCalls:0,fullReplacement:false};
}
