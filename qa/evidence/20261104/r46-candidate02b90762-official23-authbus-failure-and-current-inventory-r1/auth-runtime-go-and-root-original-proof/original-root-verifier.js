function qualifyAuthFixed3Full(p,f,go,sourceRoot,author) {
 const rows=[];const ck=(name,v)=>{if(v!==true)throw Error(name);rows.push({name,passed:true});};
 ck("whole_full216",p.audit.whole===true&&p.audit.tree==="a3d8d11df9a065faf7c555d14e45d1fdf5d82303"&&p.audit.files===216);
 const m=JSON.parse(p.raw["MANIFEST.public.json"]);ck("all214_logical_paths_unique",m.files.length===214&&new Set(m.files.map(x=>x.logicalPath)).size===214&&m.files.every(x=>{const a=gitBlobMeta(p.raw[x.path]);return f[x.logicalPath]===p.raw[x.path]&&a.blob===x.blob&&a.bytes===x.bytes&&a.sha256===x.sha256;}));
 ck("author88_exact",author.exact===true&&author.value.passed===true&&author.value.checkCount===88);
 ck("root25_actual_bodies_and_source",sourceRoot.value.passed===true&&sourceRoot.value.checks===25);
 const ci=JSON.parse(f["original-calls.index.public.json"]),oi=JSON.parse(f["original-observers.index.public.json"]),s=JSON.parse(f["journal-final-state.original.json"]),pool=new Map(m.files.map(x=>[x.blob,p.raw[x.path]]));
 const calls=ci.map(x=>({key:x.key,kind:x.kind,phase:x.phase,requestPin:x.pins.request,sdkPin:x.pins.sdk,nativePin:x.pins.native,requestText:f[x.paths.request],intentText:f[x.paths.intent],armedText:f[x.paths.armed],sdkText:f[x.paths.sdk],nativeText:f[x.paths.native],armedTree:x.armedTree}));
 ck("same35calls7observers",ci.length===35&&oi.length===7&&Object.keys(s.calls).length===35&&s.completedObservers.length===7);
 verifyOriginalJournal({label:"auth_r3_fixed3",calls,observers:oi,blob:sha=>{if(!pool.has(sha))throw Error("missing blob "+sha);return pool.get(sha);},goPins:[go.pins],pageLimit:()=>8192,ck});
 for(const x of ci)ck("SDK_tree_"+x.ordinal,immediateTreeSha([{path:"original-sdk.json",mode:"100644",type:"blob",sha:x.pins.sdk.blob}])===x.sdkTree);
 ck("original_inert_closed_state_unchanged",gitBlobMeta(f["original-inert-closed-state.original.json"]).blob==="d087853e217e00f48e676fdd17e91a97d814cb82");
 ck("GO_original_identical",f["root-GO.original.json"]===go.text);
 ck("zero_current_calls_futures",s.nativeCallInFlight===false&&s.pending===null&&s.activeObserver===null&&s.paused===false);
 return{schema:"heptabao.root.authbus.r3.fixed3.full-original-chain.qualification.r1",passed:true,checks:rows.length,rows,packet:p.audit,sourceAndBodies:sourceRoot.pins,authorCheckCount:88,originalCalls:35,originalOperations:7,immutablePages:21,decodedBodyBytes:96654,allOriginalObserversClosed:true,NativeCallsInVerifier:0,runtimeSubmitted:false,actualBusinessTests:0,fullReplacement:false,productionCutover:false,legacyCleanup:false};
}