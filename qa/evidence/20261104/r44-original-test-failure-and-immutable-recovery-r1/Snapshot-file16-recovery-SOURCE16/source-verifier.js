async function verifyBody16RecoverySource(input) {
 const rows=[];
 function check(name,value){rows.push({name,passed:value===true});if(value!==true)throw Error(name);}
 check("exact_before",gitBlobMeta(input.before).blob==="a154e8b3e4bbce818471dd10fe434e4ded570c8b");
 check("exact_after",gitBlobMeta(input.after).blob==="3397c4e1b8743273af9209c5074170e855491cc1");
 check("exact_added_function",gitBlobMeta(input.insert).blob==="4196c6e08d6bddc7d89d2ddf5dff2fc969b553b0");
 check("only_one_new_function_and_dispatch_line",input.after.replace(input.insert,"").replace(input.dispatchAfter,input.dispatchBefore)===input.before);
 check("new_function_has_no_Native_tool_call",!input.insert.includes("tools.")&&!input.insert.includes("gfInvokePreparedOnce")&&!input.insert.includes("operation_start(q)"));
 const diff=snapshotUnified(input.before,input.after,"formatted23-journal.js");
 check("exact_two_hunks",diff.split("\n").filter(x=>x.startsWith("@@")).length===2);
 check("strict_forward",snapshotApply(input.before,diff)===input.after);
 check("strict_reverse",snapshotApply(input.after,diff,true)===input.before);
 const originalFixture=JSON.stringify(input.fixture);
 async function isolate(name,mutate,expected,archiveMode="whole") {
  const state=JSON.parse(JSON.stringify(input.fixture.state)),go=JSON.parse(JSON.stringify(input.fixture.fakeGO));
  const mem=new Map([["snapshot_2379_formatted23_readonly_gitfirst_r1",state],
   ["snapshot_2379_formatted23_readonly_gitfirst_r1:original_sdk_raw:sf23-r1-f16-b00-p0",input.fixture.rawError],
   ["snapshot_2379_formatted23_readonly_gitfirst_r1:native_raw:sf23-r1-f16-b00-s0",input.fixture.statusRaw]]);
  let calls=0,archiveInput=null,originalFailed=JSON.stringify(state.calls["sf23-r1-f16-b00-p0"]),oldInfo=JSON.stringify(state.calls["sf23-r1-f10-info-p0"]),oldInfoRecovery=JSON.stringify(state.info10Page0Recovery);
  const load=k=>mem.get(k),store=(k,v)=>mem.set(k,v);
  const archiveFlatPublicTextsOnce=async x=>{
   calls++;archiveInput=x;
   if(archiveMode==="throw")throw Error("simulated_Git_unknown");
   const entries=Object.keys(x.texts).sort().map(path=>({path,...gitBlobMeta(x.texts[path]),whole:true})),bytes=[];
   for(const e of entries){bytes.push(...utf8Bytes("100644 "+e.path+"\0"));for(let i=0;i<40;i+=2)bytes.push(parseInt(e.blob.slice(i,i+2),16));}
   return {tree:sha1Bytes(utf8Bytes("tree "+bytes.length+"\0").concat(bytes)),entries,count:entries.length,bytes:entries.reduce((n,e)=>n+e.bytes,0),whole:archiveMode==="whole"};
  };
  const config={whole:true};
  if(mutate)mutate(state,go,mem,config);
  const raw=JSON.stringify(go,null,2)+"\n",pin=gitBlobMeta(raw);
  const prepare=eval(input.helpers+"\n"+input.insert+";gfPrepareClosedBody16Page0Recovery");
  let error=null,result=null;
  try{result=await prepare({goRaw:raw,goPin:pin,goWholeReadback:config.whole});}catch(e){error=String(e.message);}
  if(expected===null) {
   check(name+":accepted",error===null&&result.nativeCalled===false);
   check(name+":one_Git_arm_only",calls===1&&Object.keys(archiveInput.texts).sort().join(",")==="armed.json,intent.json,original-failed-call.json,request.json");
   check(name+":original_request_unchanged",archiveInput.texts["request.json"]===state.calls["sf23-r1-f16-b00-p0"].requestRaw);
   check(name+":old_failed_row_unchanged",JSON.stringify(state.calls["sf23-r1-f16-b00-p0"])===originalFailed);
   check(name+":prior_INFO10_unchanged",JSON.stringify(state.calls["sf23-r1-f10-info-p0"])===oldInfo&&JSON.stringify(state.info10Page0Recovery)===oldInfoRecovery);
   check(name+":new_uncalled_pending_only",state.pending==="sf23-r1-f16-b00-p0-recovery1"&&state.paused===false&&state.calls[state.pending].phase==="armed_whole"&&state.calls[state.pending].called===false&&state.body16Page0Recovery.phase==="armed_whole");
   check(name+":all_Native_counters_unchanged",state.admissionsCalled===47&&state.activeObserver.pageCalled===1&&state.activeObserver.statusCalled===1&&state.bodyBytes===1184165&&state.completedObservers.length===46);
   check(name+":future_still_closed",state.activeObserver.futureClosed===true&&state.activeObserver.pages.length===0&&state.activeObserver.nextPageOffset===0&&state.outputFiles.length===16);
  }else{
   check(name+":exact_rejection",error===expected);
   check(name+":no_Native_or_extra_Git",calls===(archiveMode==="whole"?0:1));
   if(archiveMode!=="whole")check(name+":old_failed_pending_preserved",state.paused===true&&state.pending==="sf23-r1-f16-b00-p0"&&state.calls["sf23-r1-f16-b00-p0"].called===true&&JSON.stringify(state.calls["sf23-r1-f16-b00-p0"])===originalFailed);
  }
 }
 await isolate("exact_original_known_closed_body16",null,null);
 await isolate("unwhole_GO",(_s,_g,_m,c)=>c.whole=false,"whole_separate_page_recovery_GO");
 await isolate("wrong_scope",(_s,g)=>g.scope="another","exact_closed_body16_page_only_scope");
 await isolate("operation_start_permission",(_s,g)=>g.operation_start_authorized=true,"exact_closed_body16_page_only_scope");
 await isolate("operation_status_permission",(_s,g)=>g.operation_status_authorized=true,"exact_closed_body16_page_only_scope");
 await isolate("wrong_page_width",(_s,g)=>g.page_bytes=8192,"exact_closed_body16_page_only_scope");
 await isolate("wrong_operation",(_s,g)=>g.original_operation="0".repeat(64),"exact_closed_body16_page_only_scope");
 await isolate("wrong_key",(_s,g)=>g.recovery_call_key="another","exact_closed_body16_page_only_scope");
 await isolate("wrong_failed_call_pin",(_s,g)=>g.failed_call.blob="0".repeat(40),"exact_original_failed_call_and_actual_INFO16");
 await isolate("original_called_reset",s=>s.calls["sf23-r1-f16-b00-p0"].called=false,"unchanged_original_failed_delivery_and_once_recovery");
 await isolate("original_failed_row_rewritten",s=>s.calls["sf23-r1-f16-b00-p0"].discarded=true,"exact_original_failed_call_and_actual_INFO16");
 await isolate("second_recovery",s=>s.body16Page0Recovery={},"unchanged_original_failed_delivery_and_once_recovery");
 await isolate("active_Native_call",s=>s.nativeCallInFlight=true,"unchanged_original_failed_delivery_and_once_recovery");
 await isolate("actual_version_rewritten",s=>s.outputInfos[16].version+="0","exact_original_failed_call_and_actual_INFO16");
 await isolate("body_path_rewritten",s=>s.activeObserver.request.operation.arguments.path="/tmp/other","exact_already_submitted_version_bound_body_only");
 await isolate("future_not_closed",s=>s.activeObserver.futureClosed=false,"actual_closed_body16_before_any_later_file");
 await isolate("received_page_discard",s=>s.activeObserver.pages=[{}],"actual_closed_body16_before_any_later_file");
 await isolate("original_page_counter_reset",s=>s.activeObserver.pageCalled=0,"actual_closed_body16_before_any_later_file");
 await isolate("later_INFO_started",s=>s.infoStarted[17]=true,"actual_closed_body16_before_any_later_file");
 await isolate("old_INFO10_deleted",s=>delete s.calls["sf23-r1-f10-info-p0"],"prior_INFO10_failure_and_recovery_unchanged");
 await isolate("old_INFO10_flag_cleared",s=>s.info10Page0Recovery.oldFailureUnchanged=false,"prior_INFO10_failure_and_recovery_unchanged");
 await isolate("original_status_corrupt",(_s,_g,m)=>m.set("snapshot_2379_formatted23_readonly_gitfirst_r1:native_raw:sf23-r1-f16-b00-s0","{}"),"original_completed_status_identity");
 await isolate("Git_arm_unknown",null,"simulated_Git_unknown","throw");
 await isolate("Git_arm_not_whole",null,"whole_arm_and_original_failure_preserved","not_whole");
 check("fixture_not_mutated",JSON.stringify(input.fixture)===originalFixture);
 return {schema:"heptabao.formatted23-body16-page0-recovery-source-checks.v1",passed:true,checks:rows.length,rows,testMode:"Pure V8 selected prepare function with fake Git; no gfInvoke/gfAccept/Runtime or actual Git mutation. This is not a runtime authorization.",realNativeCalls:0,realGitMutations:0,positiveFakeArmCount:1,negativeCases:23,final23Qualified:false};
}
