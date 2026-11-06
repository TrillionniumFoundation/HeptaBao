/* Pure SOURCE verification with the unchanged main journal's actual admission function.
 * This does not store state, call archive, invoke Native, or interpret the incomplete report.
 */
function verifyOracleBody02HandbackSource(files) {
 const checks=[],check=(v,label)=>{checks.push({label,pass:!!v});if(!v)throw Error(label);};
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const reject=(f,label)=>{let caught=false;try{f();}catch{caught=true;}check(caught,label);};
 const inputs={beforeRaw:files["STATE.before.original.paused.json"],recoveryRaw:files["STATE.recovery.closed.json"],
  rangeRaw:files["RANGE.original.json"],payloadRaw:files["payload.original.json"],nativeRaw:files["native.original.json"],statusRaw:files["status.native.original.json"]};
 const derive=new Function(files["pure_helpers.js"]+"\n"+files["handback.source.js"]+"\nreturn deriveOracleBody02Handback;")();
 const result=derive(inputs),proposal=JSON.parse(files["PROPOSAL.public.json"]),before=JSON.parse(inputs.beforeRaw),after=JSON.parse(result.afterRaw);
 check(result.afterRaw===files["STATE.after.proposed.json"],"exact proposed successor state");
 check(same(gitBlobMeta(result.afterRaw),proposal.exactAfter),"exact successor bytes and hashes");
 check(same(gitBlobMeta(inputs.beforeRaw),proposal.exactBefore),"exact paused predecessor bytes and hashes");
 check(result.originalContextApplied===false&&result.nativeCalls===0&&result.gitCalls===0,"pure derivation only");
 const strict=new Function(files["strict_diff.js"]+"\nreturn {strictDiff,applyStrict};")();
 check(strict.applyStrict(inputs.beforeRaw,files["STATE.strict.diff"],false)===result.afterRaw,"strict forward state delta");
 check(strict.applyStrict(result.afterRaw,files["STATE.strict.diff"],true)===inputs.beforeRaw,"strict reverse state delta");
 const keys=new Set([...Object.keys(before),...Object.keys(after)]),changed=[...keys].filter(k=>!same(before[k],after[k])).sort();
 check(same(changed,["activeObserver","completedObservers","oracleReportBody02Recovery","oracleReportBodyRanges","paused","pending"].sort()),"only six explicitly reviewed fields change");
 check(same(before.calls,after.calls)&&Object.keys(after.calls).length===28,"all original 28 call records preserved");
 check(same(before.outerFailure,after.outerFailure),"original outerFailure preserved");
 const old=after.calls["official271-x230-acl23-r2-body02-status0"];
 check(old.called===true&&old.phase==="native_interpretation_refused"&&old.sdkPin.blob==="0cede4881f37869cfd279b69b738c87eb62b4889","failed delivery record preserved");
 check(after.oracleReportBodyStarted===3&&before.oracleReportBodyStarted===3,"no admission-count reset");
 check(same(after.oracleReportBodyRanges.slice(0,2),before.oracleReportBodyRanges),"prior two ranges preserved");
 check(same(after.completedObservers.slice(0,5),before.completedObservers),"prior five observer records preserved");
 check(after.completedObservers[5].id===after.oracleReportBodyRanges[2].originalOperation&&after.completedObservers[5].completedInactive===true,"only recovered original closed observer added");
 check(after.oracleReportBodyRanges[2].offset===131072&&after.oracleReportBodyRanges[2].next===196608,"recovered third range contiguous");
 check(after.oracleReportBody02Recovery.counts.combinedStatusCallsForOriginalID===2&&after.oracleReportBody02Recovery.counts.originalStatusLimit===8,"old failed query still consumes original budget");
 check(after.oracleReportBody02Recovery.counts.recoveryOperationStartCalls===0&&after.oracleReportBody02Recovery.originalBudgetsReset===false,"no recovery admission or budget reset");
 check(after.oracleReportBody===undefined,"full report still incomplete and unparsed");
 check(same(gitBlobMeta(files["main.journal.original.js"]),proposal.main_journal_unchanged),"unchanged approved main journal");
 const validate=new Function(files["pure_helpers.js"]+"\n"+files["main.journal.original.js"]+"\nreturn gfValidateRequest;")();
 const qraw=files["next.original.request.json"],q=JSON.parse(qraw);
 check(same(gitBlobMeta(qraw),proposal.nextRequest)&&q.operation.arguments.offset===196608&&q.operation.arguments.limit===65536,"next is exact original BODY3");
 reject(()=>validate(before,"operation_start",q,qraw),"old paused predecessor still refuses next admission");
 validate(after,"operation_start",q,qraw);check(true,"proposed successor accepts only the exact next original request");
 const originalAdmit=before.calls["official271-x230-acl23-r2-body02-admit"];
 reject(()=>validate(after,"operation_start",JSON.parse(originalAdmit.requestRaw),originalAdmit.requestRaw),"cannot repeat original BODY2");
 const skipped=JSON.parse(qraw);skipped.operation.arguments.offset=262144;
 reject(()=>validate(after,"operation_start",skipped,JSON.stringify(skipped)+"\n"),"cannot skip to BODY4");
 reject(()=>validate(after,"process_start",{},"{}\n"),"no process admission");
 reject(()=>validate(after,"operation_status",{operation_id:proposal.original_operation_id},"{}\n"),"no further original BODY2 status after handback");
 reject(()=>validate(after,"operation_result",{operation_id:proposal.original_operation_id,offset:0,limit:16384},"{}\n"),"no BODY2 page replay");
 reject(()=>derive({...inputs,beforeRaw:result.afterRaw}),"second application rejected by exact before guard");
 reject(()=>derive({...inputs,recoveryRaw:inputs.recoveryRaw+" "}),"changed recovery state rejected");
 reject(()=>derive({...inputs,nativeRaw:inputs.nativeRaw+" "}),"changed original chunk rejected");
 check(inputs.beforeRaw===files["STATE.before.original.paused.json"],"source check does not mutate predecessor input");
 return {schema:"heptabao.oracle271.r2.BODY02.handback-source-verification.r1",pass:true,check_count:checks.length,checks,actual_main_state_mutation:false,native_calls:0,git_calls:0,report_json_interpreted:false,root_handback_GO_pending:true};
}
