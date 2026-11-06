function qualifyOfficialR2Full(p,go,author,min){
 const rows=[],ck=(name,v)=>{rows.push({name,passed:v===true});if(v!==true)throw Error(name);},f=p.raw,s=JSON.parse(f["STATE.original.json"]),blobs={};for(const raw of Object.values(f))blobs[gitBlobMeta(raw).blob]=raw;
 ck("whole55",p.audit.whole&&p.audit.files===55&&p.audit.bytes===698647);
 ck("author88_exact",author.exact&&author.value.pass===true&&author.value.check_count===88);
 ck("root11_minimum_exact_stdout",min.value.passed&&min.value.checks===11&&gitBlobMeta(f["STDOUT.original.txt"]).blob==="8ba51a89419cb8be7c215bea6f29677c9de258d8");
 ck("exact_original_GO_and_source",f["ROOT-GO.public.json"]===go.text&&s.goRaw===go.text&&gitBlobMeta(f["journal.original.js"]).blob===go.value.journal.blob);
 const index=JSON.parse(f["CALL-INDEX.public.json"]),calls=index.map(row=>{const c=s.calls[row.key],b=row.prefix;return{key:row.key,kind:c.kind,phase:c.phase,requestPin:c.requestPin,sdkPin:c.sdkPin,nativePin:c.nativePin,requestText:f[b+".request.original.json"],intentText:f[b+".intent.original.json"],armedText:f[b+".armed.original.json"],sdkText:f[b+".sdk.original.json"],nativeText:f[b+".native.original.json"],armedTree:c.armed.tree};});
 verifyOriginalJournal({label:"official271_fresh_r2_original",calls,observers:s.completedObservers,blob:k=>blobs[k],goPins:[go.pins],pageLimit:()=>8192,ck});
 ck("exact_original_START",gitBlobMeta(calls[0].requestText).blob===go.value.exactProcessStart.blob&&calls.length===7&&s.completedObservers.length===2);
 ck("all_closed_and_no_case_inference",s.pending===null&&s.activeObserver===null&&!s.nativeCallInFlight&&!s.paused&&s.nextStdout===681&&s.nextStderr===0&&min.value.actualACLCases===null&&min.value.ownerReceiptQualified===false);
 return{schema:"heptabao.root-official271-fresh-r2-original-full.r1",passed:true,checks:rows.length,rows,packet:p.audit.tree,job:s.job,exitCode:0,originalCalls:7,originalObservers:2,originalPages:2,currentNativeCalls:0,currentOwnedFutures:0,actualACLCases:null,ownerReceiptQualified:false,fullReplacement:false,productionCutover:false,legacyCleanup:false};
}