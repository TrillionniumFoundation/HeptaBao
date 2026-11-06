function verifyRootBody20RecoverySource(files,input,author,oldClosure) {
 const rows=[],ck=(name,v)=>{rows.push({name,passed:v===true});if(v!==true)throw Error(name);},eq=(x,y)=>JSON.stringify(x)===JSON.stringify(y);
 ck("author81_exact",author.exact&&author.result.passed&&author.result.checks===81&&author.result.negativeCases===30);
 ck("before_original_journal",gitBlobMeta(files["journal.before.js"]).blob==="3397c4e1b8743273af9209c5074170e855491cc1");
 ck("after_exact_journal",gitBlobMeta(files["journal.after.js"]).blob==="d2154d558749bc51f9f1aa37d69372fedfd9392c");
 ck("all_existing_source_unchanged",files["journal.after.js"].replace(files["added-function.only.js"],"").replace(input.dispatchAfter,input.dispatchBefore)===files["journal.before.js"]);
 ck("exact_input_bytes",input.before===files["journal.before.js"]&&input.after===files["journal.after.js"]&&input.insert===files["added-function.only.js"]);
 const f=strictApply(input.before,files["forward.diff"]),r=strictApply(input.after,files["reverse.diff"]);ck("strict_forward_two_hunks",f.text===input.after&&f.hunks===2);ck("strict_reverse_two_hunks",r.text===input.before&&r.hunks===2);
 const g=JSON.parse(files["GO-fields.REVIEW-ONLY.json"]),q=JSON.parse(files["request.original.json"]),s=input.fixture.state,old=s.calls[g.failed_call_key],a=s.activeObserver;
 ck("metadata_review_only",g.authorization==="HOLD"&&g.notRuntimeAuthorization===true);
 ck("immutable_page_exact",Object.keys(q).sort().join(",")==="limit,offset,operation_id"&&q.offset===49152&&q.limit===16384&&q.operation_id==="2d748c65bb3394cc8a97b59b24027a4f3ee24a18885a04523c98435b3fefc1fe");
 ck("original_failed_request_exact",old.requestRaw===files["request.original.json"]&&gitBlobMeta(old.requestRaw).blob===g.request.blob);
 ck("original_failed_called_and_pin",old.called===true&&old.phase==="native_interpretation_refused"&&gitBlobMeta(JSON.stringify(old,null,2)+"\n").blob===g.failed_call.blob);
 ck("known_closed_root28",oldClosure.value.passed===true&&oldClosure.pins.blob==="d41bf8571fe1b67d1d621fd20b0d09f1ae4d40ee");
 ck("no_new_read_or_status",g.operation_start_authorized===false&&g.operation_status_authorized===false&&g.maximum_recovery_page_calls===1);
 ck("prior_INFO10_not_deleted",s.calls["sf23-r1-f10-info-p0"].called===true&&s.calls["sf23-r1-f10-info-p0-recovery1"].phase==="accepted"&&s.info10Page0Recovery.oldFailureUnchanged);
 ck("prior_BODY16_not_deleted",s.calls["sf23-r1-f16-b00-p0"].called===true&&s.calls["sf23-r1-f16-b00-p0-recovery1"].phase==="accepted"&&s.body16Page0Recovery.oldFailureUnchanged);
 ck("20_whole_files_not_final23",s.outputFiles.length===20&&s.bodyBytes===1277974&&!s.infoStarted[21]&&s.completedObservers.length===54&&s.admissionsCalled===55);
 ck("one_closed_original_observer",a.futureClosed===true&&a.pages.length===3&&a.pageCalled===4&&a.statusCalled===1&&!s.nativeCallInFlight);
 ck("three_original_pages_exact",JSON.stringify(a.pages)===files["original-pages.exact.json"]&&gitBlobMeta(files["original-pages.exact.json"]).blob===g.original_pages.blob);
 ck("payload_digest_and_offset",a.nextPageOffset===49152&&a.total===63251&&a.digest===g.expected_payload_sha256&&a.eof===false);
 ck("no_Native_in_prepare",!input.insert.includes("tools.")&&!input.insert.includes("gfInvokePreparedOnce"));
 const pr=JSON.parse(files["live-state-preservation.public.json"]);ck("source_work_no_live_state_change",eq(pr.before,pr.after)&&pr.unchanged&&!pr.nativeCallInFlight&&pr.originalFutureClosed&&pr.pending==="sf23-r1-f20-b00-p3");
 return {schema:"heptabao.root-formatted23-body20-recovery-source.r1",passed:true,checks:rows.length,rows,author81Exact:true,sourceTree:"a07cb54144ba6ed1bc001b84cfbfa692f5e9e177",sourceOnly:true,newNativeCalls:0,final23Qualified:false};
}