async function verifyOracleInfoStatusReconcileSource(files) {
 const checks=[];function check(name,v){checks.push({name,passed:!!v});if(!v)throw Error(name);}
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),meta=gitBlobMeta,plan=JSON.parse(files["PLAN.public.json"]),before=files["journal.before.js"],after=files["journal.after.js"],oldRaw=files["ORIGINAL.paused-state.json"],old=JSON.parse(oldRaw),statusRaw=files["REQUEST.status.exact.json"],status=JSON.parse(statusRaw);
 check("strict forward source",applyStrict(before,files["journal.strict.diff"],false)===after);
 check("strict reverse source",applyStrict(after,files["journal.strict.diff"],true)===before);
 check("exact after source",same(meta(after),plan.source));
 check("exact old paused state",same(meta(oldRaw),plan.original_state));
 check("exact failed status SDK retained",same(meta(files["ORIGINAL.failed-status.sdk.json"]),plan.original_failed_status_SDK));
 check("exact same request bytes not a new operation",same(meta(statusRaw),plan.exact_status_request)&&statusRaw===old.calls[plan.original_failed_status_key].requestRaw);
 check("one returned original ID",Object.keys(status).join(",")==="operation_id"&&status.operation_id===plan.original_operation_id&&old.activeObserver.id===plan.original_operation_id);
 check("original unknown future preserved",old.paused&&old.pending===plan.original_failed_status_key&&old.calls[old.pending].called&&!old.nativeCallInFlight&&!old.activeObserver.futureClosed&&old.activeObserver.pages.length===0);
 check("old 9 calls and two closed historical observers",Object.keys(old.calls).length===9&&old.completedObservers.length===2);
 check("new independent slot not reset",plan.new_slot!==plan.original_slot&&after.includes("original_paused_status_error_context_byte_identical"));
 check("no Native admission tool in candidate",!after.includes("tools.mcp__codex_apps__heptaruntime_mac_controller_operation_start(")&&!after.includes("tools.mcp__codex_apps__heptaruntime_mac_controller_process_start("));
 check("one status total remains two under eight",plan.maximum_new_operation_status_calls===1&&plan.original_operation_status_calls===1&&plan.maximum_combined_operation_status_calls===8);
 check("original 8K pages/1MiB cap",plan.immutable_page_bytes===8192&&plan.maximum_payload_bytes===1048576&&plan.maximum_operation_result_calls===128);
 function def(text,name){const starts=[...text.matchAll(/^(?:async )?function ([A-Za-z0-9_]+)\(/gm)],i=starts.findIndex(m=>m[1]===name);return text.slice(starts[i].index,i+1<starts.length?starts[i+1].index:text.length);}
 for(const name of ["gfNeed","gfMetaEquals","gfSave","gfIntegerText","gfCloseOriginalObserver","gfReconcileSameGitArchiveReadOnly"])check("unchanged "+name,def(before,name)===def(after,name));
 const go={authorization:"GO",scope:plan.scope,original_job:plan.original_job,original_operation_id:plan.original_operation_id,maximum_new_operation_status_calls:1,original_operation_status_calls:1,maximum_combined_operation_status_calls:8,maximum_operation_result_calls:128,maximum_operation_start_calls:0,maximum_process_start_calls:0,immutable_page_bytes:8192,maximum_payload_bytes:1048576,exact_status_request:plan.exact_status_request};
 const goRaw=JSON.stringify(go,null,2)+"\n",goPin=meta(goRaw);
 const success={content:[{type:"text",text:JSON.stringify({operation_id:plan.original_operation_id,tool_name:"file_info",automatic_retry:false,async_state:"completed",owned_future_active:false,result_state:"stored_observed",payload_available:true})}]};
 function fixture(returned=success){
  const data=new Map([[plan.original_slot,JSON.parse(oldRaw)],[plan.original_slot+":original_sdk_raw:"+plan.original_failed_status_key,files["ORIGINAL.failed-status.sdk.json"]]]),archives=[],calls=[];
  const helpers="async function archiveFlatPublicTextsOnce(args){__archives.push(JSON.parse(JSON.stringify(args)));return {tree:'1111111111111111111111111111111111111111',whole:true};}\nfunction recordGitSDKImmutable(){}";
  const mocked={mcp__codex_apps__heptaruntime_mac_controller_operation_status:async q=>{calls.push(q);return returned;}};
  const api=new Function("tools","store","load","__archives",files["pure.original.js"]+"\n"+helpers+"\n"+after+"\nreturn {run:gfRun,validate:gfValidateRequest};")(mocked,(k,v)=>data.set(k,v),k=>data.get(k),archives);
  return {data,archives,calls,api};
 }
 const init={goRaw,goPin,goWholeReadback:true,originalStateRaw:oldRaw},f=fixture();
 let r=await f.api.run("initialize",init);check("new context initializes only once from original pinned state",r.ok===true);
 check("old context byte-identical after initialize",JSON.stringify(f.data.get(plan.original_slot),null,2)+"\n"===oldRaw);
 r=await f.api.run("prepare",{callKey:"pure-reconcile-status0",kind:"operation_status",requestRaw:statusRaw});
 check("actual status prepare only",r.ok===true&&f.archives.length===1&&f.calls.length===0);
 check("new status arm exact GO and original operation",same(JSON.parse(f.archives[0].texts["intent.json"]).rootGo,goPin)&&JSON.parse(f.archives[0].texts["intent.json"]).originalOperation===plan.original_operation_id);
 r=await f.api.run("invoke",{callKey:"pure-reconcile-status0"});check("one virtual status dispatch same ID",r.ok===true&&f.calls.length===1&&same(f.calls[0],status));
 const intermediate=f.data.get(plan.new_slot);check("whole SDK before acceptance",intermediate.calls["pure-reconcile-status0"].phase==="sdk_whole_uninterpreted"&&intermediate.calls["pure-reconcile-status0"].sdkArchive.whole===true);
 r=await f.api.run("accept",{callKey:"pure-reconcile-status0"});check("actual accept records original future closed",r.ok===true&&f.data.get(plan.new_slot).activeObserver.futureClosed===true);
 check("combined status count exactly two",f.data.get(plan.new_slot).originalStatusCalls+f.data.get(plan.new_slot).reconcileStatusCalls===2);
 check("old failed status and SDK still exact",JSON.stringify(f.data.get(plan.original_slot),null,2)+"\n"===oldRaw&&f.data.get(plan.original_slot+":original_sdk_raw:"+plan.original_failed_status_key)===files["ORIGINAL.failed-status.sdk.json"]);
 const page={operation_id:plan.original_operation_id,offset:0,limit:8192};
 r=await f.api.run("prepare",{callKey:"pure-reconcile-page0",kind:"operation_result",requestRaw:JSON.stringify(page,null,2)+"\n"});
 check("original page allowed only after known closure",r.ok===true&&f.calls.length===1&&same(JSON.parse(f.archives.at(-1).texts["intent.json"]).rootGo,goPin));
 async function rejection(name,kind,q,edit=()=>{}){
  const x=fixture();await x.api.run("initialize",init);edit(x.data.get(plan.new_slot));
  const r=await x.api.run("prepare",{callKey:"pure-rejected-call",kind,requestRaw:typeof q==="string"?q:JSON.stringify(q,null,2)+"\n"});
  check(name,r.ok===false&&x.calls.length===0&&x.archives.length===0&&JSON.stringify(x.data.get(plan.original_slot),null,2)+"\n"===oldRaw);
 }
 await rejection("second new status rejected","operation_status",statusRaw,s=>s.reconcileStatusCalls=1);
 await rejection("different operation status rejected","operation_status",{operation_id:"b".repeat(64)});
 await rejection("new file_info admission rejected","operation_start",old.activeObserver.request);
 await rejection("new process start rejected","process_start",{host:"x230",executable:"/usr/bin/true",args:[]});
 await rejection("original page before closure rejected","operation_result",page);
 await rejection("changed page cursor rejected","operation_result",{...page,offset:8192},s=>{s.reconcileStatusCalls=1;s.activeObserver.futureClosed=true;});
 const u=fixture(JSON.parse(files["ORIGINAL.failed-status.sdk.json"]));await u.api.run("initialize",init);await u.api.run("prepare",{callKey:"pure-status-unknown",kind:"operation_status",requestRaw:statusRaw});await u.api.run("invoke",{callKey:"pure-status-unknown"});r=await u.api.run("accept",{callKey:"pure-status-unknown"});
 check("new transport unknown pauses only new context",r.ok===false&&u.data.get(plan.new_slot).paused&&u.calls.length===1&&!u.data.get(plan.new_slot).activeObserver.futureClosed);
 check("both old and new original errors preserved",JSON.stringify(u.data.get(plan.original_slot),null,2)+"\n"===oldRaw&&u.data.get(plan.new_slot+":original_sdk_raw:pure-status-unknown")===files["ORIGINAL.failed-status.sdk.json"]);
 return {schema:"heptabao.official271.same-ID-status.source-checks.r1",pass:true,check_count:checks.length,checks,NativeCalls:0,pureVirtualStatusCalls:2,oldSlotNotWritten:true,RuntimeAuthorized:false};
}
