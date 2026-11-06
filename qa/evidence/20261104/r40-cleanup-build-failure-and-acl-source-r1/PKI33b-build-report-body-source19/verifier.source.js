function verifySingleBuildBody(i,h,d,makeValidator) {
 const checks=[];function ok(n,v){checks.push({name:n,passed:!!v});if(!v)throw Error(n);}
 const f=d.applyStrictUnified(i.before,i.diff),r=d.applyStrictUnified(i.after,i.diff,true);
 ok("eight_strict_hunks_forward_reverse",f.hunks===8&&r.hunks===8&&f.text===i.after&&r.text===i.before);
 let rebuilt=i.referenceBody;
 for(const x of [...i.referenceInfoRebindings,...i.bodyChanges]){ok("exact_source_replacement_"+x.reason,rebuilt.split(x.before).length===2);rebuilt=rebuilt.replace(x.before,x.after);}
 ok("reference_algorithm_mechanically_rebuilt",rebuilt===i.after);
 ok("single_body_request_pin",JSON.stringify(h.gitBlobMeta(i.requestRaw))===JSON.stringify(i.requestPin));
 const q=JSON.parse(i.requestRaw),e=i.expected,m=i.metadata;
 ok("actual_metadata_binding",m.path===e.path&&m.size===e.bytes&&m.sha256===e.sha256&&m.version===e.version&&m.originalOperation===e.infoOperation&&JSON.stringify(m.full9Strings)===JSON.stringify(e.full9Strings));
 ok("one_exact_range",q.operation.tool==="binary_read"&&q.operation.arguments.offset===0&&q.operation.arguments.limit===36998&&e.bytes===36998&&e.bytes<=65536);
 ok("original_failed_job_and_scope",i.after.includes('s.job==="1a1b029a998-fc05-6eb2"')&&i.after.includes('g.scope==="build_result_binary_read_only"'));
 ok("info_chain_closed",i.infoObserver.completedInactive===true&&i.infoObserver.id===e.infoOperation&&i.infoObserver.nativeText.blob===e.infoNative.blob);
 ok("native_whole_identity",h.gitBlobMeta(i.infoNativeRaw).blob===e.infoNative.blob);
 ok("info_0600_linux_singlelink",i.infoNative.metadata.mode===384&&i.infoNative.mode===384&&i.infoNative.metadata.uid===1000&&i.infoNative.metadata.gid===1000&&i.infoNative.metadata.link_count===1&&i.infoNative.metadata.metadata_platform==="linux");
 ok("old_observers_8k_new_binary_16k",i.after.includes('q.limit===(s.activeObserver.tool==="binary_read"?16384:8192)')&&i.after.includes('b.length<=(a.tool==="binary_read"?16384:8192)'));
 ok("new_16k_scope_separate_GO",i.after.includes("g.immutable_body_page_bytes===16384"));
 ok("once_marker_pre_dispatch",i.after.indexOf('q.operation.tool==="binary_read")s.stageResultBodyStarted=true')<i.after.indexOf("let sdk;"));
 ok("original_payload_whole_before_parse",i.after.indexOf("archiveKey=\"gfc-\"")<i.after.indexOf("const p=parseLosslessIntegers(raw);"));
 ok("decoded_whole_SHA_before_save",i.after.indexOf('"whole_report_actual_bytes_SHA"')<i.after.indexOf('store(GF_SLOT+":stage_result_body_original"'));
 const v=makeValidator(),s={paused:false,nativeCallInFlight:false,pending:null,job:i.job,activeObserver:null,startCalled:true,stageResultInfoStarted:true,stageResultBodyGO:{whole:true}};
 v(s,"operation_start",q,i.requestRaw);ok("exact_body_accepted_in_fake_authorized_state",true);
 function reject(n,ss,qq,raw,kind="operation_start"){let denied=false;try{v(ss,kind,qq,raw);}catch(_){denied=true;}ok(n,denied);}
 reject("no_go_denied",{...s,stageResultBodyGO:null},q,i.requestRaw);
 reject("repeat_body_denied",{...s,stageResultBodyStarted:true},q,i.requestRaw);
 for(const [n,k,value]of [["path","path",e.path+".other"],["offset","offset",1],["limit","limit",36997],["version","expected_version",e.version+"0"],["host","host","desktop"]]){const qq=JSON.parse(i.requestRaw);qq.operation.arguments[k]=value;reject("changed_"+n+"_denied",s,qq,JSON.stringify(qq,null,2)+"\n");}
 const active={id:"a".repeat(64),tool:"binary_read",futureClosed:true,nextPageOffset:0,eof:false};
 const page={operation_id:active.id,offset:0,limit:16384};v({...s,activeObserver:active},"operation_result",page,JSON.stringify(page));ok("new_body_16k_page_accepted_in_fake_state",true);
 reject("wrong_body_8k_page_denied",{...s,activeObserver:active},{...page,limit:8192},"", "operation_result");
 const old={...active,tool:"file_info"};v({...s,activeObserver:old},"operation_result",{...page,limit:8192},"");ok("old_info_8k_page_retained",true);
 reject("old_info_16k_denied",{...s,activeObserver:old},page,"","operation_result");
 reject("noncontiguous_page_denied",{...s,activeObserver:active},{...page,offset:16384},"","operation_result");
 ok("actual_slot_not_mutated",i.actualState.pending===null&&i.actualState.activeObserver===null&&!i.actualState.nativeCallInFlight&&!i.actualState.paused&&i.actualState.stageResultBodyGO===undefined);
 return {schema:"heptabao.failed-build-report-one-body.source-checks.r1",status:"PASS_SOURCE_ONLY",checks:checks.length,details:checks,Native:0,productExecution:0,actualBodyRead:false,actualSlotMutated:false};
}
