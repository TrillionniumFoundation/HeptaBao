function rootFreshHomeR3(f,author,current,approved){
 const rows=[],ck=(name,v)=>{rows.push({name,passed:v===true});if(v!==true)throw Error(name);},p=gitBlobMeta,eq=(x,y)=>JSON.stringify(x)===JSON.stringify(y);
 const c=JSON.parse(f["CONTRACT.public.json"]),q=JSON.parse(f["dispatch--inert.exact-request.public.json"]),oldQ=JSON.parse(f["dispatch--before.exact-request.public.json"]),oldCarrier=JSON.parse(oldQ.stdin),carrier=JSON.parse(q.stdin);
 ck("author206_exact",author.exact&&author.value.passed&&author.value.checkCount===206);
 ck("root_current_diagnostic40_closed",current.value.passed&&current.value.checks===40&&current.value.currentObservationComplete&&current.value.historicalManagedScopeClosed===false);
 ck("exact_current_diagnostic_stdout",p(f["reference--current-independent-observation.stdout.original.json"]).blob==="2eb4a1866ccbb32d2a70d074d351939d5b2fb2f8");
 ck("same_approved_parser",f["reference--approved-parser-after.py"]===approved&&p(approved).blob==="3f259a4b085394fba0658359575aa0d74b9757e2");
 const ns=[
 ["/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-home-launch-r2","/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-home-launch-r3"],
 ["/Users/qianqi/heptabao-mac-authbus-4e808-home-launch-20261106-r2","/Users/qianqi/heptabao-mac-authbus-4e808-home-launch-20261106-r3"],
 ["mac-authbus-4e808-current-home-launch-r2","mac-authbus-4e808-current-home-launch-r3"],
 ["org.heptabao.qa.mac-authbus-4e808-home-r2.server","org.heptabao.qa.mac-authbus-4e808-home-r3.server"],
 ["org.heptabao.qa.mac-authbus-4e808-home-r2.consumer","org.heptabao.qa.mac-authbus-4e808-home-r3.consumer"]];
 const rewrite=x=>ns.reduce((s,[a,b])=>s.split(a).join(b),x),beforePins=JSON.parse(f["before--source-pins.public.json"]),afterPins=JSON.parse(f["source-pins.public.json"]);
 let changed=0,unchanged=0;
 ck("complete22_source_carriers",Object.keys(oldCarrier.files).length===22&&Object.keys(carrier.files).length===22&&Object.keys(afterPins).length===22);
 for(const[name,b64]of Object.entries(oldCarrier.files)){
 const old=utf8Text(unb64(b64)),after=f["source--"+name],inert=utf8Text(unb64(carrier.files[name]));
 ck("source_"+name,eq(p(old),beforePins[name])&&eq(p(after),afterPins[name])&&inert===after&&rewrite(name==="mac_owned_launchd_r3.py"?approved:old)===after);
 if(old===after)unchanged++;else changed++;
 }
 ck("only11_changed_11_unchanged",changed===11&&unchanged===11);
 let proofs=0;for(const[name,b64]of Object.entries(oldCarrier.documents)){if(name.startsWith("proofs/")){proofs++;ck("unchanged_"+name,b64===carrier.documents[name]);}}
 ck("seven_original_proofs_only",proofs===7&&Object.keys(carrier.documents).length===8);
 const projection=JSON.parse(JSON.stringify(oldQ));projection.args[4]=f["after--publisher.py"];projection.stdin=f["dispatch--public-stdin.original.json"];projection.idempotency_key=c.inert.idempotencyKey;
 ck("only_three_request_field_changes",JSON.stringify(projection,null,2)+"\n"===f["dispatch--inert.exact-request.public.json"]);
 ck("exact_request_source_payload_pins",eq(p(f["dispatch--inert.exact-request.public.json"]),c.inert.request)&&eq(p(q.args[4]),c.inert.publisher)&&eq(p(q.stdin),c.inert.payload));
 ck("bounded_inert_only_60_45_30",q.host==="mac"&&q.cwd==="/Users/qianqi"&&q.executable===c.inert.interpreter&&q.timeout_seconds===60&&q.args.slice(0,4).join(",")==="-I,-S,-B,-c"&&q.args.length===5&&c.inert.publisherDeadlineSeconds===45&&c.inert.diskutilSeconds===30);
 for(const [stem,n]of [["publisher.py",6],["journal.js",2],["runtime-deriver.js",1],["candidate.public.json",2]]){
 const before=f["before--"+stem],after=f["after--"+stem],fw=strictApply(before,f["diff--"+stem+".diff"]),rv=strictApply(after,f["inverse--"+stem+".diff"]);ck("strict_"+stem,fw.text===after&&rv.text===before&&fw.hunks===n&&rv.hunks===n);
 }
 ck("runtime_deriver_only_key_suffix",f["before--runtime-deriver.js"].replace("'-20261106-r2'","'-20261106-r3'")===f["after--runtime-deriver.js"]);
 ck("fresh_roots_and_labels_unobserved",c.namespaceEvidence.newRootsExistence==="NOT_OBSERVED"&&c.namespaceEvidence.newLabelAbsence==="NOT_OBSERVED"&&!c.namespaceEvidence.historicalClosureClaim);
 ck("future_runtime_unbound",c.futureRuntime.actualHomeBinding===null&&c.futureRuntime.actualRuntimeRequest===null&&c.futureRuntime.actualPort===null&&!c.futureRuntime.readyForRuntime);
 ck("old_business_budgets_not_inert_authority",c.preserved.budgets.outer===900&&c.preserved.outerRuntimeNativeTimeoutSeconds===1080&&c.preserved.fiveAgents.length===5&&c.trustedCurrentFlow.phases.length===4&&c.trustedCurrentFlow.nativeLineagesRequired===10);
 return{schema:"heptabao.root-fresh-AuthBus-HOME-r3-inert-source.r1",passed:true,checks:rows.length,rows,sourceTree:"1b9f6f07249d0757ac0efa0227827e834a750260",author206Exact:true,sourceFiles:22,changedByNamespaceAndApprovedParser:11,unchangedSourceFiles:11,proofDocumentsUnchanged:7,sourceOnly:true,newNativeCalls:0,inertSourceReady:true,businessRuntimeBound:false,productBaseline:"4e808d0ecb1bcded22870a7ec960dfb2491cf6ec",fullReplacement:false};
}