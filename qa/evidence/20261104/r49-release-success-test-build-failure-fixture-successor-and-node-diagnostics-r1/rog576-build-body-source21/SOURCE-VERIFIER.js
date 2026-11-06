function verify576BuildBodySource(x){
 const checks=[];function ck(n,v){checks.push({name:n,passed:v===true});if(v!==true)throw new Error(n);}
 let rebuilt=x.donor;for(const e of x.edits){ck("literal_"+e.label,rebuilt.split(e.before).length-1===e.count);rebuilt=rebuilt.split(e.before).join(e.after);}ck("whole_donor_derivation",rebuilt===x.after);
 ck("strict_forward",snapshotApply(x.before,x.fwd)===x.after);ck("strict_reverse",snapshotApply(x.after,x.rev)===x.before);ck("donor_strict_forward",snapshotApply(x.donor,x.donorFwd)===x.after);ck("donor_strict_reverse",snapshotApply(x.after,x.donorRev)===x.donor);
 function fn(t,n){let a=t.indexOf("function "+n+"(");if(a<0)throw new Error(n);let b=t.indexOf("\n}\n",a);if(b<0)throw new Error(n+" end");return t.slice(a,b+3);}
 for(const k of ["gfAuthorizeStageResultInfoOnly","gfNeed","gfMetaEquals","gfState","gfSave","gfIntegerText","gfInitializeOnlyAfterRootGO","gfAcceptArchivedSDK","gfReconcileSameGitArchiveReadOnly"])ck("old_function_unchanged_"+k,fn(x.before,k)===fn(x.after,k));
 const original=JSON.parse(x.stateRaw),need=x.expected,q=JSON.parse(x.requestRaw),qp=gitBlobMeta(x.requestRaw),info=parseLosslessIntegers(x.actualInfoRaw);
 ck("actual_info_pin",gitBlobMeta(x.actualInfoRaw).blob===need.infoNative.blob&&gitBlobMeta(x.actualInfoRaw).sha256===need.infoNative.sha256);
 ck("actual_version_size_SHA",need.path===info.path&&need.bytes===info.size&&need.version===info.version&&need.sha256===info.sha256&&need.bytes===46828&&need.bytes<=65536);
 ck("actual_closed46_15",Object.keys(original.calls).length===46&&original.completedObservers.length===15&&original.activeObserver===null&&original.pending===null&&!original.nativeCallInFlight&&!original.paused);
 ck("old_git_unknown_kept",!!original.outerFailure&&!!original.exactOriginalStatusSDKArchiveRecovery);
 ck("actual_info_owner",info.mode===384&&info.metadata.uid===1000&&info.metadata.gid===1000&&info.metadata.link_count===1);
 ck("request_exact_range",q.operation.tool==="binary_read"&&q.operation.arguments.path===need.path&&q.operation.arguments.expected_version===need.version&&q.operation.arguments.offset===0&&q.operation.arguments.limit===need.bytes);
 const slot="combined_5767739c_fresh_build_gitfirst_r1",mem=new Map([[slot,JSON.parse(x.stateRaw)],[slot+":closed_native:"+need.infoOperation,x.actualInfoRaw]]);
 const load=k=>mem.get(k),store=(k,v)=>mem.set(k,v),tools=new Proxy({}, {get(){throw new Error("SOURCE_NO_TOOLS");}});
 const api=eval(x.after+";({authorize:gfAuthorizeStageResultBodyOnly,validate:gfValidateRequest})");
 const raw=JSON.stringify({authorization:"GO",scope:"build_result_binary_read_only",original_job:original.job,info_operation:need.infoOperation,maximum_binary_read_starts:1,exact_request:qp,SOURCE_PRIVATE_FIXTURE_ONLY:true});
 const args={goRaw:raw,goPin:gitBlobMeta(raw),goWholeReadback:true},a=api.authorize(args);ck("private_valid_body_GO",a.wholeBytes===46828&&a.maximumBinaryReadStarts===1);
 let state=mem.get(slot),copy={...state};delete copy.stageResultBodyGO;ck("only_body_go_added",JSON.stringify(copy)===JSON.stringify(original));
 api.validate(state,"operation_start",q,x.requestRaw);ck("exact_private_body_request",true);
 function bad(n,f){let threw=false;try{f();}catch(e){threw=true;}ck(n,threw);}
 bad("repeat_body_GO",()=>api.authorize(args));let missing={...state};delete missing.stageResultBodyGO;bad("old_info_GO_cannot_read_body",()=>api.validate(missing,"operation_start",q,x.requestRaw));
 bad("once_marker_no_replay",()=>api.validate({...state,stageResultBodyStarted:true},"operation_start",q,x.requestRaw));
 for(const [n,edit] of [["different_key",v=>v.idempotency_key+="x"],["different_version",v=>v.operation.arguments.expected_version+="0"],["different_offset",v=>v.operation.arguments.offset=1],["different_limit",v=>v.operation.arguments.limit++],["different_path",v=>v.operation.arguments.path+=".other"],["different_host",v=>v.operation.arguments.host="x230"]]){const v=JSON.parse(x.requestRaw);edit(v);bad(n,()=>api.validate(state,"operation_start",v,JSON.stringify(v)));}
 ck("single_range_whole_hash_and_eof",x.after.includes("v.offset===0 && v.next_offset===need.bytes && v.eof===true")&&x.after.includes("bodyPin.sha256===need.sha256"));
 ck("raw_bytes_retained_before_semantics",x.after.includes('store(GF_SLOT+":stage_result_body_original",bodyRaw)')&&x.after.includes("semanticQualification:false"));
 ck("original8K_1MiB_bound",x.after.includes("q.limit===8192")&&x.after.includes("v.total_bytes<=1048576"));
 return{schema:"heptabao.current576-build-report-body-source-checks.r1",passed:true,checks:checks.length,results:checks,NativeCalls:0,toolsCalled:0,liveContextModified:false,privateSyntheticGOOnly:true};
}
