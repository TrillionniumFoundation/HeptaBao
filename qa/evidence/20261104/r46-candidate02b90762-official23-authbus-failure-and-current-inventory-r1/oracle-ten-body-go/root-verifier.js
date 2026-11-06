function qualifyOracleR2BodySource(p,infoRoot,author) {
 const f=p.raw,plan=JSON.parse(f["PLAN.public.json"]),state=JSON.parse(f["PRIOR-STATE.original.closed.json"]),info=JSON.parse(f["INFO.native.original.json"]);const rows=[];
 function ck(name,value){if(value!==true)throw Error(name);rows.push({name,passed:true});}
 function pin(name,want){const got=gitBlobMeta(f[name]);return got.blob===want.blob&&got.bytes===want.bytes&&got.sha256===want.sha256;}
 ck("whole_SOURCE27_Merkle",p.audit.whole===true&&p.audit.tree==="110ad5e4707f61b076815cd33c7514eebaf39746"&&p.audit.files===27);
 ck("author75_exact_reproduction",author.exact===true&&author.value.pass===true&&author.value.check_count===75);
 ck("independently_qualified_actual_INFO",infoRoot.value.passed===true&&infoRoot.value.checks===22&&infoRoot.pins.blob==="4c43efd2187a4a592ff6558cdabd746cb524a902");
 ck("actual_closed_state_pin",pin("PRIOR-STATE.original.closed.json",plan.priorClosedState));
 ck("actual_INFO_native_pin",pin("INFO.native.original.json",plan.fixedReport.infoNative));
 ck("original_INFO_GO_pin",pin("INFO-GO.original.json",plan.infoGO));
 ck("frozen_journal_pin",pin("journal.after.js",plan.source));
 ck("all_previous_calls_closed",state.pending===null&&state.activeObserver===null&&state.nativeCallInFlight===false&&!state.paused&&Object.keys(state.calls).length===10&&state.completedObservers.length===3&&state.completedObservers.every(x=>x.completedInactive===true)&&Object.values(state.calls).every(x=>x.phase==="accepted"&&x.sdkArchive.whole===true));
 ck("actual_fixed_report_binding",state.job===plan.originalJob&&info.path===plan.fixedReport.path&&info.size===651803&&info.sha256===plan.fixedReport.sha256&&info.version===plan.fixedReport.version&&info.metadata.uid===1000&&info.metadata.gid===1000&&info.metadata.link_count===1&&info.mode===384);
 let end=0;const keys=new Set(); for(let i=0;i<10;i++){const name="request-"+String(i).padStart(2,"0")+".exact.json",r=JSON.parse(f[name]),a=r.operation.arguments;ck("exact_range_"+i,pin(name,plan.exactRequests[i])&&r.operation.tool==="binary_read"&&a.host==="x230"&&a.path===info.path&&a.expected_version===info.version&&a.offset===end&&a.limit===(i<9?65536:61979)&&!keys.has(r.idempotency_key));end+=a.limit;keys.add(r.idempotency_key);}
 ck("contiguous_whole_651803",end===info.size);
 ck("bounded_read_only_GO_contract",plan.requiredGO.maximum_binary_read_starts===10&&plan.requiredGO.maximum_file_info_operations===0&&plan.requiredGO.maximum_process_start_calls===0&&plan.requiredGO.immutable_body_page_bytes===16384&&plan.requiredGO.maximum_operation_status_calls_per_id===8&&plan.requiredGO.maximum_immutable_pages_per_id===128&&plan.budgets.maximumSimultaneousCallsOrFutures===1);
 return {schema:"heptabao.root.oracle271.r2.ten-body-source.qualification.r1",passed:true,checks:rows.length,rows,packet:p.audit,source:plan.source,priorActualINFO:infoRoot.pins,originalJob:plan.originalJob,actualReportBytes:info.size,actualReportSHA256:info.sha256,newBinaryReadStarts:0,bodyQualified:false,aclResultsQualified:false,fullReplacement:false,productionCutover:false,legacyCleanup:false};
}