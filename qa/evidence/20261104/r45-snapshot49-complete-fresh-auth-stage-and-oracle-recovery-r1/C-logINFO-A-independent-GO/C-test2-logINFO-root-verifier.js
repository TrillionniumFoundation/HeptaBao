function verifyRootTest2LogInfo(files,go,author,bodyFiles){
 const rows=[],ck=(name,v)=>{rows.push({name,passed:v===true});if(v!==true)throw Error(name);},pin=gitBlobMeta,eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b),state=JSON.parse(files["state.original.json"]),rel=JSON.parse(files["RELEASE.public.json"]),infos=JSON.parse(files["actual-log-metadata.public.json"]),blobs={};
 for(const raw of Object.values(files))blobs[pin(raw).blob]=raw;
 ck("author78_exact",author.exact&&author.value.pass&&author.value.check_count===78);
 ck("GO_exact_whole",files["GO.original.json"]===go.text&&state.goRaw===go.text);
 ck("journal_exact_executed",pin(files["journal.executed.original.js"]).blob===go.value.source.blob);
 ck("original41_context_whole_unchanged",files["prior-context.original.json"]===bodyFiles["STATE.after.original.json"]);
 ck("six_once_accepted_calls",Object.keys(state.calls).length===6&&Object.values(state.calls).every(x=>x.called===true&&x.phase==="accepted"&&x.sdkArchive.whole));
 const calls=Object.entries(state.calls).map(([key,c])=>({key,kind:c.kind,phase:c.phase,requestPin:c.requestPin,sdkPin:c.sdkPin,nativePin:c.nativePin,requestText:files[key+".request.json"],intentText:files[key+".intent.json"],armedText:files[key+".armed.json"],sdkText:files[key+".sdk.original.json"],nativeText:files[key+".native.original.json"],armedTree:c.armed.tree}));
 const cs=verifyOriginalJournal({label:"original_test2_log_INFO",calls,observers:state.completedObservers,blob:k=>blobs[k],goPins:[go.pins],pageLimit:()=>8192,ck});
 ck("two_exact_INFO_requests",cs.filter(x=>x.c.kind==="operation_start").every((x,i)=>pin(x.c.requestText).blob===go.value.exact_requests[i].blob));
 ck("exact_two_metadata_rows",infos.length===2&&eq(infos,state.logInfos)&&eq(infos,rel.actual));
 for(let i=0;i<2;i++){
  const role=i===0?"stderr":"stdout",n=parseLosslessIntegers(files[role+"-info.native.original.json"]),m=infos[i],target=go.value.targets[i],o=state.completedObservers[i];
  ck("INFO_current_identity_"+role,n.path===target.path&&n.sha256===target.sha256&&n.size===(i===0?191:375)&&n.version===m.version&&m.path===n.path&&m.sha256===n.sha256&&m.originalOperation===o.id);
  ck("full9_and_mode_"+role,m.full9Strings[0]+":"+m.full9Strings[1]+":"+m.full9Strings[6]+":"+m.full9Strings[7]+":"+m.full9Strings[8]===n.version&&m.full9Strings[2]==="1000"&&m.full9Strings[3]==="1000"&&m.full9Strings[4]==="33152"&&m.full9Strings[5]==="1"&&n.mode===384&&n.metadata.uid===1000&&n.metadata.gid===1000&&n.metadata.link_count===1);
  ck("actual_native_pin_"+role,pin(files[role+"-info.native.original.json"]).blob===m.nativeText.blob&&m.bodyReadAuthorized===false);
 }
 ck("closed_state",state.pending===null&&state.activeObserver===null&&!state.paused&&!state.nativeCallInFlight&&state.completedObservers.length===2);
 ck("no_body_build_or_target_reuse",rel.body_observed===false&&rel.body_authorized===false&&rel.build_replayed===false&&rel.target_reuse_authorized===false);
 return {schema:"heptabao.root-test2-log-info-original-full.r1",passed:true,checks:rows.length,rows,sourcePacket:"b2909bcbd96212c17c97b32fd004bbb52d713141",actual:infos,originalCalls:6,originalObservers:2,originalPages:2,wholeLogBytesPending:566,observationLaneReleased:true,newBuild:false,targetReuseQualified:false,fullReplacement:false};
 }