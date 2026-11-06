function rootIndependentR2Full(f,go,author,min){
 const rows=[],ck=(name,v)=>{rows.push({name,passed:v===true});if(v!==true)throw Error(name);},p=gitBlobMeta,s=JSON.parse(f["journal-final-state.original.json"]),blobs={};
 for(const raw of Object.values(f))blobs[p(raw).blob]=raw;
 ck("author161_exact",author.exact&&author.value.passed&&author.value.checkCount===161);
 ck("root15_minimum_original",min.value.passed&&min.value.checks===15&&p(f["actual--stdout.original.txt"]).blob===min.value.stdout.blob);
 ck("original_exact_GO",f["reference-GO.original.json"]===go.text&&s.goRaw===go.text);
 const paths=JSON.parse(f["original-calls.index.public.json"]),calls=Object.entries(s.calls).map(([key,c])=>({key,kind:c.kind,phase:c.phase,requestPin:c.requestPin,sdkPin:c.sdkPin,nativePin:c.nativePin,requestText:f[paths[key].requestRaw],intentText:f[paths[key].intentRaw],armedText:f[paths[key].armedRaw],sdkText:f[paths[key].sdkRaw],nativeText:f[paths[key].nativeRaw],armedTree:c.armed.tree}));
 verifyOriginalJournal({label:"A_original_R2_independent_diagnostic",calls,observers:s.completedObservers,blob:k=>blobs[k],goPins:[go.pins],pageLimit:()=>8192,ck});
 ck("original_exact_START_request",p(calls[0].requestText).blob===go.value.exactProcessStart.blob);
 ck("all_closed_and_unknown_preserved",s.pending===null&&s.activeObserver===null&&!s.nativeCallInFlight&&!s.paused&&min.value.PIDStateQualified===false&&min.value.historicalManagedScopeClosed===false);
 return {schema:"heptabao.root-A-independent-R2-original-full.r1",passed:true,checks:rows.length,rows,tree:"8a2a4c0b3dde3e7912cbf0ccd62a09c93e0d5a53",originalCalls:9,originalObservers:2,originalPages:4,author161Exact:true,sourceConstructorABIRefusalObserved:true,managedScopeClosed:false,PIDStateQualified:false,newNativeCalls:0};
 }