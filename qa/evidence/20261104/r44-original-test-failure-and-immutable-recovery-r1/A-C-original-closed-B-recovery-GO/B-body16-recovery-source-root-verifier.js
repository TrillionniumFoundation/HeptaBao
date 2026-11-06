function verifyRootBody16RecoverySource(files,input,author,oldClosure) {
 const rows=[],ck=(name,v)=>{rows.push({name,passed:v===true});if(v!==true)throw Error(name);},eq=(x,y)=>JSON.stringify(x)===JSON.stringify(y);
 ck("author65_exact",author.exact&&author.result.passed&&author.result.checks===65&&author.result.negativeCases===23);
 ck("before_original_journal",gitBlobMeta(files["journal.before.js"]).blob==="a154e8b3e4bbce818471dd10fe434e4ded570c8b");
 ck("after_exact_journal",gitBlobMeta(files["journal.after.js"]).blob==="3397c4e1b8743273af9209c5074170e855491cc1");
 ck("all_existing_source_unchanged",files["journal.after.js"].replace(files["added-function.only.js"],"").replace(input.dispatchAfter,input.dispatchBefore)===files["journal.before.js"]);
 ck("exact_input_bytes",input.before===files["journal.before.js"]&&input.after===files["journal.after.js"]&&input.insert===files["added-function.only.js"]);
 const f=strictApply(input.before,files["forward.diff"]),r=strictApply(input.after,files["reverse.diff"]);ck("strict_forward_two_hunks",f.text===input.after&&f.hunks===2);ck("strict_reverse_two_hunks",r.text===input.before&&r.hunks===2);
 const g=JSON.parse(files["GO-fields.REVIEW-ONLY.json"]),q=JSON.parse(files["request.original.json"]),s=input.fixture.state,old=s.calls[g.failed_call_key];
 ck("metadata_review_only",g.authorization==="REVIEW_ONLY_NOT_A_GO");
 ck("immutable_page_exact",Object.keys(q).sort().join(",")==="limit,offset,operation_id"&&q.offset===0&&q.limit===16384&&q.operation_id==="9037480fbf014345c1d2bbe1894020e30602a9adb2d8c1a864f6eff35368f1b0");
 ck("original_failed_request_exact",old.requestRaw===files["request.original.json"]&&gitBlobMeta(old.requestRaw).blob===g.request.blob);
 ck("original_failed_called_and_pin",old.called===true&&old.phase==="native_interpretation_refused"&&gitBlobMeta(JSON.stringify(old,null,2)+"\n").blob===g.failed_call.blob);
 ck("known_closed_root25",oldClosure.value.passed===true&&oldClosure.pins.blob==="557023960b1b922cb2862745a1ccf10265ba0488");
 ck("no_new_read_or_status",g.operation_start_authorized===false&&g.operation_status_authorized===false&&g.maximum_recovery_page_calls===1);
 ck("prior_INFO10_not_deleted",s.calls["sf23-r1-f10-info-p0"].called===true&&s.calls["sf23-r1-f10-info-p0-recovery1"].phase==="accepted"&&s.info10Page0Recovery.oldFailureUnchanged);
 ck("16_whole_files_not_final23",s.outputFiles.length===16&&s.bodyBytes===1184165&&!s.infoStarted[17]);
 ck("one_closed_original_observer",s.activeObserver.futureClosed===true&&s.activeObserver.pages.length===0&&s.activeObserver.pageCalled===1&&s.activeObserver.statusCalled===1&&!s.nativeCallInFlight);
 ck("no_Native_in_prepare",!input.insert.includes("tools.")&&!input.insert.includes("gfInvokePreparedOnce"));
 const pr=JSON.parse(files["live-state-preservation.public.json"]);ck("source_work_no_live_state_change",eq(pr.before,pr.after)&&pr.unchanged&&pr.newNativeCalls===0&&!pr.newSlotInitialized);
 return {schema:"heptabao.root-formatted23-body16-recovery-source.r1",passed:true,checks:rows.length,rows,author65Exact:true,sourceTree:"f1370549e1d3ff48bd9f0fa4adcd22172078dcb5",sourceOnly:true,newNativeCalls:0,final23Qualified:false};
 }