function rootOfficial271Full(f,go,author,min){
 const rows=[],ck=(name,v)=>{rows.push({name,passed:v===true});if(v!==true)throw Error(name);},p=gitBlobMeta,s=JSON.parse(f["STATE.original.json"]),blobs={};
 for(const raw of Object.values(f))blobs[p(raw).blob]=raw;
 ck("author88_exact",author.exact&&author.value.pass&&author.value.check_count===88);
 ck("root13_minimum_original",min.value.passed&&min.value.checks===13&&p(f["STDOUT.original.txt"]).blob==="4cadde347ce3fb4b3dd8a175dea060bb73ccb1db");
 ck("exact_original_GO_and_journal",f["ROOT-GO.public.json"]===go.text&&p(f["journal.original.js"]).blob===go.value.journal.blob);
 const index=JSON.parse(f["CALL-INDEX.public.json"]),calls=index.map(row=>{const c=s.calls[row.key],b=row.prefix;return{key:row.key,kind:c.kind,phase:c.phase,requestPin:c.requestPin,sdkPin:c.sdkPin,nativePin:c.nativePin,requestText:f[b+".request.original.json"],intentText:f[b+".intent.original.json"],armedText:f[b+".armed.original.json"],sdkText:f[b+".sdk.original.json"],nativeText:f[b+".native.original.json"],armedTree:c.armed.tree};});
 verifyOriginalJournal({label:"official271_original",calls,observers:s.completedObservers,blob:k=>blobs[k],goPins:[go.pins],pageLimit:()=>8192,ck});
 ck("exact_original_START",p(calls[0].requestText).blob===go.value.exactProcessStart.blob);
 ck("no_new_REPORT_or_child_closure_claim",s.pending===null&&s.activeObserver===null&&!s.nativeCallInFlight&&!s.paused&&min.value.ownerChildClosureQualified===false&&min.value.actualAclCaseCount===null);
 return {schema:"heptabao.root-official271-X230-original-full.r1",passed:true,checks:rows.length,rows,tree:"e5a1f1c0f0a00fb0b71720012e31e633ab4e640a",originalCalls:7,originalObservers:2,originalPages:2,author88Exact:true,transportLaneReleased:true,ownerChildClosureQualified:false,actualAclCaseCount:null,newNativeCalls:0};
}