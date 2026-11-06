function verifyRootBuildReportFull(files,go,min,author){
 const checks=[],ck=(name,v)=>{checks.push({name,passed:v===true});if(v!==true)throw Error(name);},meta=gitBlobMeta;
 const index=JSON.parse(files["CALL-INDEX.public.json"]),rel=JSON.parse(files["RELEASE.public.json"]),blobs={};for(const raw of Object.values(files))blobs[meta(raw).blob]=raw;
 ck("root17_minimum",min.value.passed&&min.value.checks===17&&min.value.observationLaneReleased);
 ck("author87_exact",author.exact&&author.value.passed===87&&author.value.failed===0);
 ck("exact_original_body_GO",files["ROOT-GO.original.json"]===go.text);
 ck("exact_executed_journal",meta(files["journal.executed.original.js"]).blob===go.value.journal.blob);
 const calls=index.map(row=>{const p=String(row.index).padStart(2,"0")+"."+row.key;return {key:row.key,kind:row.kind,phase:row.phase,requestPin:row.request,sdkPin:row.sdk,nativePin:row.native,requestText:files[p+".request.json"],intentText:files[p+".intent.json"],armedText:files[p+".armed.json"],sdkText:files[p+".original.sdk.json"],nativeText:files[p+".original.native.json"],armedTree:row.armed.tree};});
 const cs=verifyOriginalJournal({label:"original_report_body",calls,observers:[rel.original],blob:k=>blobs[k],goPins:[go.pins],pageLimit:()=>16384,ck});
 ck("exact_GO_request",meta(cs[0].c.requestText).blob===go.value.exact_request.blob);
 const before=JSON.parse(files["STATE.before.original.json"]),after=JSON.parse(files["STATE.after.original.json"]);
 ck("original41_12_complete",Object.keys(before.calls).length===34&&Object.keys(after.calls).length===41&&before.completedObservers.length===11&&after.completedObservers.length===12);
 ck("original34_calls_exact",Object.entries(before.calls).every(([k,v])=>JSON.stringify(v)===JSON.stringify(after.calls[k])));
 ck("original11_observers_exact",JSON.stringify(before.completedObservers)===JSON.stringify(after.completedObservers.slice(0,11)));
 ck("new_observer_exact_release",JSON.stringify(after.completedObservers[11])===JSON.stringify(rel.original));
 const r=JSON.parse(files["report.original.json"]);
 ck("failure_log_SHA_precise",r.group_results[0].tests[1].tests.stdout_sha256==="baaffbccd60cd36f53810a4a49dc1ca9ae55883a1abb21253d29970d8dbf79ad"&&r.group_results[0].tests[1].tests.stderr_sha256==="9829d15840c80e4a69ccf1afeab7025cd42dc94c421c3421271c973c801167cf");
 ck("missing_final_fences_not_filled",!Object.hasOwn(r,"source_unchanged")&&!Object.hasOwn(r,"binaries_unchanged")&&!Object.hasOwn(r,"release_artifacts_unchanged"));
 return {schema:"heptabao.root-original-report-full-chain.r1",passed:true,checks:checks.length,rows:checks,sourcePacket:"3079e97e1f59af5642fd6b445d6e42315e050e6b",report:meta(files["report.original.json"]),originalCalls:7,originalObservers:1,originalPages:5,author87ExactlyReproduced:true,testProcessesObserved:2,testProcessExit0:1,testProcessExit101:1,compilationFailed:false,suitePassed:false,observationLaneReleased:true,targetReuseQualified:false,fullReplacement:false};
 }