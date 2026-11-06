function qualifyHomeR2FixedReadbackRoot(p,source,minimum,inert,go,root97,h) {
 const rows=[];const ck=(id,v)=>{rows.push({id,pass:!!v});if(!v)throw Error(id);},same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),pin=h.gitBlobMeta;
 const f=p.raw,s=JSON.parse(f["evidence/final-journal.public.json"]),plan=JSON.parse(f["evidence/PLAN.original.public.json"]),cm=JSON.parse(f["evidence/calls-path-map.public.json"]),om=JSON.parse(f["evidence/observers-path-map.public.json"]);
 ck("whole212_merkle5",p.audit.whole&&p.audit.files===212&&p.audit.bytes===1435332&&p.audit.merkle.trees_verified===5);
 ck("whole_minimum12_same",Object.entries(minimum.raw).every(([n,t])=>f["core/"+n]===t));
 ck("original_plan_source_exact",f["evidence/PLAN.original.public.json"]===source.raw["PLAN.public.json"]);
 ck("root_exact_original_GO",f["evidence/root-go.original.json"]===go.text&&s.goRaw===go.text&&same(s.goPin,pin(go.text)));
 ck("actual_35calls_7observers_closed",cm.length===35&&om.length===7&&Object.keys(s.calls).length===35&&s.completedObservers.length===7&&s.pending===null&&s.activeObserver===null&&!s.nativeCallInFlight&&!s.paused&&s.processStartsInThisScope===0);
 const callOriginals=Object.fromEntries(cm.map(x=>[x.key,{sdkRaw:f[x.files["original.sdk.json"].path],nativeRaw:f[x.files["original.native.json"].path]}]));
 const observerOriginals=Object.fromEntries(om.map(o=>[o.id,{payloadRaw:f[o.payloadPath],nativeRaw:f[o.nativePath]}]));
 const author=h.author({state:s,plan,callOriginals,observerOriginals,originalInertStateRaw:inert.raw["final-journal.public.json"]});
 ck("author88_exact_reproduction",author.passed&&author.checkCount===88&&same(author,JSON.parse(f["evidence/actual-checks.public.json"])));
 const byBlob=new Map(p.pins.map(x=>[x.blob,f[x.path]]));
 const calls=cm.map(m=>{const c=s.calls[m.key];return {key:m.key,kind:c.kind,phase:c.phase,requestPin:c.requestPin,sdkPin:c.sdkPin,nativePin:c.nativePin,requestText:f[m.files["request.json"].path],sdkText:f[m.files["original.sdk.json"].path],nativeText:f[m.files["original.native.json"].path],armedText:f[m.files["armed.json"].path],intentText:f[m.files["intent.json"].path],armedTree:c.armed.tree};});
 h.verifyOriginalJournal({label:"fixed7",calls,observers:s.completedObservers,blob:sha=>byBlob.get(sha),goPins:[pin(go.text)],pageLimit:()=>8192,ck});
 ck("all35_original_sdk_archive_trees",cm.every(m=>{const c=s.calls[m.key];return c.called===true&&c.sdkArchive.whole===true&&h.immediateTreeSha([{path:"original.sdk.json",mode:"100644",type:"blob",sha:c.sdkPin.blob}])===c.sdkArchive.tree;}));
 const infos=om.slice(0,3).map(o=>h.parseLosslessIntegers(f[o.nativePath]));ck("actual_native_infos_match_state",same(infos,s.readbackInfos));
 const d=h.deriveFixedReadbackBodies(plan,infos);ck("actual_versions_reproduce_exact_body_plan",same(d,s.derivedBodyPlan));
 ck("exact_three_metadata_requests",s.readbackRequests.slice(0,3).every((raw,i)=>pin(raw).blob===source.pins.find(x=>x.path==="metadata-"+String(i+1).padStart(2,"0")+".exact-request.public.json")?.blob));
 ck("exact_four_actual_bound_requests",same(d.requests.map(x=>x.requestRaw),s.readbackRequests.slice(3)));
 const parts=[],whole=[];for(let i=0;i<4;i++){const result=h.validateFixedReadbackBody(plan,infos,i,JSON.parse(s.readbackRequests[i+3]),h.parseLosslessIntegers(f[om[i+3].nativePath]),parts);parts.push(result.part);if(result.whole)whole.push(result.whole);ck("actual_binary_native_part_"+i,same(result.part,s.readbackParts[i]));}
 ck("actual_native_whole_files_reproduced",same(whole,s.readbackWholeFiles));
 ck("three_whole_files_minimum_equal",whole.every((w,i)=>w.raw===minimum.raw[["actual-outer.whole.original.txt","actual-candidate.whole.original.txt","actual-receipt.whole.original.txt"][i]]));
 ck("full9_exact_stage",d.metadata.every((m,i)=>same(m.full9,plan.targets[i].stageFull9)));
 const receipt=JSON.parse(whole[2].raw),pub=JSON.parse(source.raw["reference.actual-inert-stdout.original.txt"]);
 ck("receipt_is_prefinal_false_not_terminal",receipt.ok===false&&receipt.preparedCandidate===true&&pub.ok===true&&pub.candidateReceiptSha256===whole[2].pin.sha256&&same(receipt.homeControlBinding,pub.homeControlBinding));
 ck("prior_inert97_preserved",same(plan.originalState,pin(inert.raw["final-journal.public.json"]))&&same(JSON.parse(f["evidence/source-reference.public.json"]).actualInertQualification,root97.pins));
 return {schema:"heptabao.root-actual-qualification.home-r2-fixed-readback.r1",pass:true,checks:rows.length,rows,packet:p.audit,minimum:minimum.audit,source:source.audit,originalGO:pin(go.text),inertQualification:root97.pins,NativeCalls:35,originalOperations:7,originalImmutablePages:21,wholeBodyBytes:96654,wholeFiles:whole.map(w=>({target:w.target,path:w.path,version:w.version,full9:w.full9,pin:w.pin})),authorChecksReproduced:88,allOriginalOperationsClosed:true,metadataAndWholeBytesQualified:true,readThenExecAtomicityClaim:false,actualRuntimeOrCredentialsQualified:false,oldPartialAndUnknownHistoriesPreserved:true,fullReplacement:false,productionCutover:false,legacyCleanup:false};
}