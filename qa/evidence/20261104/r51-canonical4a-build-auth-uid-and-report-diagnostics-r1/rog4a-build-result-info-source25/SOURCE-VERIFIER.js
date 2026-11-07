function verify4aBuildInfoSource(x) {
 const checks=[];function ck(name,v){checks.push({name,passed:v===true});if(v!==true)throw new Error(name);}
 let rebuilt=x.before;for(const e of x.edits){ck("unique_edit_"+e.label,rebuilt.split(e.before).length-1===e.count);rebuilt=rebuilt.split(e.before).join(e.after);}
 ck("seven_exact_edits",x.edits.length===7&&rebuilt===x.after);
 ck("strict_forward",snapshotApply(x.before,x.fwd)===x.after);ck("strict_reverse",snapshotApply(x.after,x.rev)===x.before);
 function fn(t,n){const m=new RegExp("^(?:async )?function "+n+"\\(","m").exec(t);if(!m)throw new Error(n);const a=t.slice(m.index).split("\n");if(a[0].endsWith("}")&&!a[0].endsWith("{"))return a[0]+"\n";const e=a.findIndex((l,i)=>i>0&&l==="}");if(e<0)throw new Error(n+"_end");return a.slice(0,e+1).join("\n")+"\n";}
 for(const n of ["gfOriginalFrozen","gfNeed","gfMetaEquals","gfState","gfSave","gfIntegerText","gfInitializeOnlyAfterRootGO","gfAuthorizeActualJobObservers","gfAcceptArchivedSDK","gfReconcileSameGitArchiveReadOnly"])ck("unchanged_"+n,fn(x.before,n)===fn(x.after,n));
 const original=JSON.parse(x.stateRaw),q=JSON.parse(x.requestRaw),qp=gitBlobMeta(x.requestRaw),sp=gitBlobMeta(x.stateRaw);
 const slot="combined_4a49405b_exact_key_conditional_admission_r1";
 ck("exact_terminal_pin",sp.blob==="ffd08542730b5033fdc564c1b38a000f6515c6c8");
 ck("closed_actual_job",original.job==="1a1b3978da9-fc05-83bd"&&original.pending===null&&original.activeObserver===null&&!original.paused&&!original.nativeCallInFlight);
 ck("43_14_14",Object.keys(original.calls).length===43&&original.completedObservers.length===14&&original.completedObservers.reduce((n,o)=>n+o.pages,0)===14);
 ck("original_unknown_state",gitBlobMeta(x.oldBuildRaw).blob==="2d512764d26256fabaaaf7deb3eae41120d92d3e");
 ck("original_failed_INFO_state",gitBlobMeta(x.oldInfoRaw).blob==="24f7020e488bea35ab336990345c4d767d89da66");
 ck("8_exact_prior_native_inputs",x.prereqs.length===8&&x.prereqs.every(r=>gitBlobMeta(x.closed[r.id]).blob===r.nativeText.blob));
 ck("one_fixed_request",q.operation.tool==="file_info"&&q.operation.arguments.host==="rog"&&q.operation.arguments.path==="/home/qian-qi/hb-4a49405b-controls-20261106-r1/build-tests-r1/result.public.json");
 const mem=new Map([[slot,JSON.parse(x.stateRaw)],["combined_4a49405b_fresh_build_gitfirst_r1",JSON.parse(x.oldBuildRaw)],["combined_4a49405b_unknown_report_info_gitfirst_r1",JSON.parse(x.oldInfoRaw)]]);
 for(const[id,raw]of Object.entries(x.closed))mem.set(slot+":closed_native:"+id,raw);
 const load=k=>mem.get(k),store=(k,v)=>mem.set(k,v),tools=new Proxy({},{get(){throw Error("NO_TOOL_IN_PRIVATE_SOURCE_CHECK");}});
 const api=eval(x.after+";({authorize:gfAuthorizeStageResultInfoOnly,validate:gfValidateRequest,initialize:gfInitializeOnlyAfterRootGO})");
 const goRaw=JSON.stringify({authorization:"GO",scope:"build_result_file_info_only",original_job:original.job,maximum_file_info_starts:1,binary_read_authorized:false,actualClosedState:sp,exact_request:qp,SOURCE_PRIVATE_MODEL_ONLY:true});
 const args={goRaw,goPin:gitBlobMeta(goRaw),goWholeReadback:true};
 function bad(n,f){let rejected=false;try{f();}catch(e){rejected=true;}ck(n,rejected);}
 bad("cannot_initialize_existing_context",()=>api.initialize({}));
 api.authorize(args);const state=mem.get(slot);ck("private_positive_info_GO",state.stageResultInfoGO?.whole===true);
 const stripped={...state};delete stripped.stageResultInfoGO;ck("attach_preserves_all_original_fields",JSON.stringify(stripped)===JSON.stringify(original));
 api.validate(state,"operation_start",q,x.requestRaw);ck("exact_INFO_request_accepted",true);
 bad("repeat_GO_rejected",()=>api.authorize(args));
 bad("no_GO_rejected",()=>api.validate(stripped,"operation_start",q,x.requestRaw));
 bad("once_marker_rejected",()=>api.validate({...state,stageResultInfoStarted:true},"operation_start",q,x.requestRaw));
 for(const[n,change]of[["key",v=>v.idempotency_key+="x"],["host",v=>v.operation.arguments.host="x230"],["path",v=>v.operation.arguments.path+=".other"],["binary",v=>v.operation.tool="binary_read"],["extra_argument",v=>v.operation.arguments.limit=4194304]]){const v=JSON.parse(x.requestRaw);change(v);bad("wrong_"+n+"_rejected",()=>api.validate(state,"operation_start",v,JSON.stringify(v)+"\n"));}
 bad("process_start_rejected",()=>api.validate(state,"process_start",{},x.requestRaw));
 const ps={idempotency_key:"heptabao-combined-4a49405b-fresh-observe-r1-extra-status",operation:{tool:"process_status",arguments:{host:"rog",job_id:state.job}}};
 bad("no_new_job_observer_under_info_GO",()=>api.validate(state,"operation_start",ps,JSON.stringify(ps)+"\n"));
 const active={...state,activeObserver:{id:"a".repeat(64),futureClosed:false,statusCalls:8,pageCalls:0,nextPageOffset:0,eof:false}};
 bad("status8_cap",()=>api.validate(active,"operation_status",{operation_id:active.activeObserver.id},""));
 active.activeObserver={...active.activeObserver,futureClosed:true,pageCalls:128};
 bad("page128_cap",()=>api.validate(active,"operation_result",{operation_id:active.activeObserver.id,offset:0,limit:8192},""));
 active.activeObserver.pageCalls=0;
 bad("page16K_not_allowed",()=>api.validate(active,"operation_result",{operation_id:active.activeObserver.id,offset:0,limit:16384},""));
 ck("Linux_mode_owner_nlink",x.after.includes("v.mode===384")&&x.after.includes('md?.metadata_platform==="linux"')&&x.after.includes("md.uid===1000 && md.gid===1000 && md.link_count===1"));
 ck("actual_report_SHA",x.after.includes('v.sha256==="7be18adad000805344acf09d01b91fbd1ed99e561bfbc97c9faf0fd56a07b250"'));
 ck("4MiB_metadata_1MiB_payload",x.after.includes("GF_STAGE_RESULT_MAX_BYTES = 4194304")&&x.after.includes("v.total_bytes<=1048576"));
 ck("Native_SDK_first_unchanged",x.after.includes('store(GF_SLOT+":original_sdk:"+callKey,sdk); // First operation on the returned SDK.')&&x.after.includes('c.phase="sdk_whole_uninterpreted"'));
 ck("info_mark_before_dispatch",x.after.indexOf('if(q.operation.tool==="file_info")s.stageResultInfoStarted=true;')<x.after.indexOf("let sdk;"));
 ck("frozen_state_inputs_still_exact",gitBlobMeta(JSON.stringify(mem.get("combined_4a49405b_fresh_build_gitfirst_r1"),null,2)+"\n").blob===gitBlobMeta(x.oldBuildRaw).blob&&gitBlobMeta(JSON.stringify(mem.get("combined_4a49405b_unknown_report_info_gitfirst_r1"),null,2)+"\n").blob===gitBlobMeta(x.oldInfoRaw).blob);
 return {schema:"heptabao.4a-known-failed-build-INFO-source-checks.r1",passed:true,checks:checks.length,results:checks,NativeCalls:0,toolsCalled:0,liveContextModified:false,privateSyntheticGOOnly:true};
}
