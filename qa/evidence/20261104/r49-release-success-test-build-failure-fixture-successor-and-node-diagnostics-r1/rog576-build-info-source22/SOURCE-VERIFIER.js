function verify576BuildInfoSource(x) {
 const checks=[];function ck(n,v){checks.push({name:n,passed:v===true});if(v!==true)throw new Error(n);}
 let rebuilt=x.before;for(const e of x.edits){ck("exact_literal_"+e.label,rebuilt.split(e.before).length-1===e.count);rebuilt=rebuilt.split(e.before).join(e.after);}ck("donor_derivation",rebuilt===x.after);
 ck("donor_strict_forward",snapshotApply(x.before,x.fwd)===x.after);ck("donor_strict_reverse",snapshotApply(x.after,x.rev)===x.before);
 ck("original_journal_strict_forward",snapshotApply(x.base,x.baseFwd)===x.after);ck("original_journal_strict_reverse",snapshotApply(x.after,x.baseRev)===x.base);
 function fn(t,n){const re=new RegExp("(?:async )?function "+n+"\\("),m=re.exec(t);if(!m)throw new Error(n);const a=m.index,tail=t.slice(a+m[0].length),end=/\n(?:async )?function /.exec(tail);return end?t.slice(a,a+m[0].length+end.index):t.slice(a);}
 for(const name of ["gfNeed","gfMetaEquals","gfState","gfSave","gfIntegerText","gfInitializeOnlyAfterRootGO","gfPrepareOne","gfInvokePreparedOnce","gfAcceptArchivedSDK","gfReconcileSameGitArchiveReadOnly","gfRun"])ck("unchanged_donor_"+name,fn(x.before,name)===fn(x.after,name));
 const original=JSON.parse(x.stateRaw),q=JSON.parse(x.requestRaw),qp=gitBlobMeta(x.requestRaw);
 ck("actual_closed_boundary",original.job==="1a1b2d90976-fc05-7fff"&&original.pending===null&&original.activeObserver===null&&!original.paused&&!original.nativeCallInFlight&&original.startCalled===true);
 ck("43_14_14_actual",Object.keys(original.calls).length===43&&original.completedObservers.length===14&&original.completedObservers.reduce((n,o)=>n+o.pages,0)===14);
 ck("old_git_unknown_retained",!!original.outerFailure&&!!original.exactOriginalStatusSDKArchiveRecovery);
 ck("one_fixed_report_request",q.operation.tool==="file_info"&&q.operation.arguments.host==="rog"&&q.operation.arguments.path==="/home/qian-qi/hb-5767739c-controls-20261106-r1/build-tests-r1/result.public.json");
 const slot="combined_5767739c_fresh_build_gitfirst_r1",mem=new Map([[slot,JSON.parse(x.stateRaw)]]);
 for(const [id,raw] of Object.entries(x.closed))mem.set(slot+":closed_native:"+id,raw);
 const load=k=>mem.get(k),store=(k,v)=>mem.set(k,v),tools=new Proxy({}, {get(){throw new Error("NO_TOOL_IN_SOURCE_VERIFIER");}});
 const api=eval(x.after+";({authorize:gfAuthorizeStageResultInfoOnly,validate:gfValidateRequest})");
 const goRaw=JSON.stringify({authorization:"GO",scope:"build_result_file_info_only",original_job:original.job,maximum_file_info_starts:1,binary_read_authorized:false,exact_request:qp,SOURCE_PRIVATE_FIXTURE_ONLY:true});
 const args={goRaw,goPin:gitBlobMeta(goRaw),goWholeReadback:true};
 const authorized=api.authorize(args);ck("private_valid_scope",authorized.maximumFileInfoStarts===1&&authorized.binaryReadAuthorized===false);
 const state=mem.get(slot),without={...state};delete without.stageResultInfoGO;
 ck("attach_preserves_all_existing_state",JSON.stringify(without)===JSON.stringify(original));
 api.validate(state,"operation_start",q,x.requestRaw);ck("private_exact_info_accepted",true);
 function bad(name,f){let failed=false;try{f();}catch(e){failed=true;}ck(name,failed);}
 bad("repeat_authorization_rejected",()=>api.authorize(args));
 const noGO={...state};delete noGO.stageResultInfoGO;bad("old_scope_cannot_info",()=>api.validate(noGO,"operation_start",q,x.requestRaw));
 bad("once_marker_blocks_info",()=>api.validate({...state,stageResultInfoStarted:true},"operation_start",q,x.requestRaw));
 for(const [name,change] of [["rekey",v=>v.idempotency_key+="x"],["other_host",v=>v.operation.arguments.host="x230"],["other_path",v=>v.operation.arguments.path+=".other"],["binary_read",v=>v.operation.tool="binary_read"]]){const v=JSON.parse(x.requestRaw);change(v);bad(name+"_rejected",()=>api.validate(state,"operation_start",v,JSON.stringify(v)));}
 ck("metadata_fixed_cap_mode_owner_links",x.after.includes("GF_STAGE_RESULT_MAX_BYTES = 4194304")&&x.after.includes("v.mode===384")&&x.after.includes("md.uid===1000 && md.gid===1000 && md.link_count===1"));
 ck("old_8k_and_1MiB_preserved",x.after.includes("q.limit===8192")&&x.after.includes("v.total_bytes<=1048576"));
 ck("report_sha_pin",x.after.includes('v.sha256==="95743757382a6828e622ce3f39ec1eaddb9da1db20df70a1b1ad3f87ec78d639"'));
 ck("all_prior_native_pin_inputs",x.prerequisites.length===7&&x.prerequisites.every(r=>gitBlobMeta(x.closed[r.id]).blob===r.nativeText.blob));
 ck("no_live_context_or_tool_touched",mem.get(slot)!==original&&Object.keys(original.calls).length===43);
 return{schema:"heptabao.current576-build-info-source-checks.r1",passed:true,checks:checks.length,results:checks,toolsCalled:0,NativeCalls:0,privateSyntheticGOOnly:true,liveContextModified:false};
}
