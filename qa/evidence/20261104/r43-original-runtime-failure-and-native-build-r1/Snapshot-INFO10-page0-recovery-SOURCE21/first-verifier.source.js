async function verifyClosedInfoPageRecovery(input) {
 const checks=[],check=(name,ok)=>{checks.push({name,ok:!!ok});if(!ok)throw Error(name);};
 const clone=x=>JSON.parse(JSON.stringify(x)),slot="snapshot_2379_formatted23_readonly_gitfirst_r1";
 const before=input.before,after=input.after;
 const applied=input.applyStrict(before,input.forward),reversed=input.applyStrict(after,input.reverse);
 check("forward_3_hunks_whole",applied.hunks===3&&applied.raw===after);
 check("reverse_3_hunks_whole",reversed.hunks===3&&reversed.raw===before);
 function defs(src){const ms=[...src.matchAll(/^(?:async )?function ([A-Za-z0-9_]+)\(/gm)],m={};for(let i=0;i<ms.length;i++)m[ms[i][1]]=src.slice(ms[i].index,ms[i+1]?.index??src.length);return m;}
 const bd=defs(before),ad=defs(after);
 check("only_one_new_definition",Object.keys(ad).length===Object.keys(bd).length+1&&ad.gfPrepareClosedInfo10Page0Recovery);
 for(const name of Object.keys(bd))if(!["gfPrepareOne","gfAcceptArchivedSDK","gfRun"].includes(name))
  check("old_definition_"+name,bd[name]===ad[name]);
 // The insertion is immediately before gfPrepareOne, so previous gfValidateRequest
 // contains the new definition in naïve span parsing; compare through its exact end.
 check("prepare_original_unchanged",bd.gfPrepareOne===ad.gfPrepareOne);
 const oldMethods=[...before.matchAll(/tools\.([A-Za-z0-9_]+)\(/g)].map(x=>x[1]);
 const newMethods=[...after.matchAll(/tools\.([A-Za-z0-9_]+)\(/g)].map(x=>x[1]);
 check("native_and_git_dispatch_set_unchanged",JSON.stringify(oldMethods)===JSON.stringify(newMethods));
 check("new_entry_has_no_native_call",!ad.gfPrepareClosedInfo10Page0Recovery.includes("tools."));
 const factory=eval("(function(load,store,archiveFlatPublicTextsOnce,tools){"+input.pure+"\n"+after+"\nreturn {run:gfRun};})");
 async function runCase(change,replay=false) {
  const st=clone(input.state),go=clone(input.go);
  const raws={error:input.failedSdkRaw,status:input.statusRaw};
  change?.(st,go,raws);
  const m=new Map([[slot,st],[slot+":original_sdk_raw:sf23-r1-f10-info-p0",raws.error],
   [slot+":native_raw:sf23-r1-f10-info-s0",raws.status]]);
  const calls=[];let native=0;
  const archive=async q=>{calls.push(q);return {whole:true,tree:"0".repeat(40),entries:[]};};
  const api=factory(k=>m.get(k),(k,v)=>m.set(k,v),archive,new Proxy({}, {get(){native++;throw Error("Native forbidden in pure fixture");}}));
  const goRaw=JSON.stringify(go,null,2)+"\n",pin=input.meta(goRaw);
  const oldRaw=JSON.stringify(st.calls["sf23-r1-f10-info-p0"]);
  const result=await api.run("prepare_closed_info10_page0_recovery",{goRaw,goPin:pin,goWholeReadback:true});
  const first={result,state:clone(m.get(slot)),archives:calls.length,native,oldUnchanged:JSON.stringify(m.get(slot).calls["sf23-r1-f10-info-p0"])===oldRaw};
  if(replay)first.replay=await api.run("prepare_closed_info10_page0_recovery",{goRaw,goPin:pin,goWholeReadback:true});
  first.totalArchives=calls.length;first.native=native;
  return first;
 }
 const yes=await runCase(null,true);
 check("actual_subset_preflight_arm_only",yes.result.ok&&yes.archives===1);
 check("no_native_invoked",yes.native===0);
 check("old_failed_call_exact_preserved",yes.oldUnchanged&&yes.state.calls["sf23-r1-f10-info-p0"].called===true);
 check("only_new_pending_after_whole_arm",yes.state.pending==="sf23-r1-f10-info-p0-recovery1"&&yes.state.calls[yes.state.pending].called===false&&yes.state.calls[yes.state.pending].phase==="armed_whole");
 check("original_native_counts_not_reset",yes.state.admissionsCalled===27&&yes.state.activeObserver.pageCalled===1&&yes.state.bodyBytes===574522);
 check("replay_prepare_refused_no_second_archive",!yes.replay.ok&&yes.totalArchives===1);
 const bad=[
 ["wrong_operation",(_s,g)=>g.original_operation="0".repeat(64)],
 ["wrong_request_pin",(_s,g)=>g.request.blob="0".repeat(40)],
 ["old_called_false",s=>s.calls["sf23-r1-f10-info-p0"].called=false],
 ["future_not_closed",s=>s.activeObserver.futureClosed=false],
 ["different_next_page",s=>s.activeObserver.nextPageOffset=8192],
 ["body_already_started",s=>s.bodyStarted[10][0]=true],
 ["status_raw_drift",(_s,_g,r)=>r.status=r.status+" "],
 ["failed_sdk_drift",(_s,_g,r)=>r.error=r.error+" "]
 ];
 for(const [name,mutate] of bad){const r=await runCase(mutate);check("reject_"+name,!r.result.ok&&r.archives===0&&r.native===0&&r.oldUnchanged);}
 check("recovery_specific_complete_page_guard",ad.gfAcceptArchivedSDK.includes('if(c.recoveryOfDelivery==="sf23-r1-f10-info-p0")\n    gfNeed(v.eof===true && q.offset===0 && v.total_bytes===b.length,'));
 return {schema:"heptabao.closed-info-page-recovery.pure-source-check.r1",pass:true,checks,
  nativeCalls:0,realGitCalls:0,realArchiveExecuted:false,
  scope:"strict source and isolated fake archive only; not actual retrieval or authorization"};
}