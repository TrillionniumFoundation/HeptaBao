function verifyStageBodySource(x,D,meta) {
 const checks=[];function need(n,v){checks.push({name:n,pass:v===true});if(v!==true)throw new Error(n);}
 function def(raw,name){const all=[...raw.matchAll(/^(?:async )?function ([A-Za-z0-9_]+)[(]/gm)];const i=all.findIndex(m=>m[1]===name);if(i<0)throw new Error(name);return raw.slice(all[i].index,i+1<all.length?all[i+1].index:raw.length);}
 need("strict_forward",D.apply(x.before,x.diff)===x.after);need("strict_reverse",D.apply(x.after,x.diff,true)===x.before);need("six_hunks",(x.diff.match(/^@@/gm)||[]).length===6);
 for(const name of ["gfNeed","gfMetaEquals","gfState","gfSave","gfIntegerText","gfInitializeOnlyAfterRootGO","gfAcceptArchivedSDK","gfReconcileSameGitArchiveReadOnly"])need("unchanged:"+name,def(x.before,name)===def(x.after,name));
 let s=x.reference;for(const r of x.replacements){need("reference_literal_count:"+checks.length,s.split(r.old).length-1===r.count);s=s.split(r.old).join(r.new);}need("reference_bindings_exact",s===x.after);
 need("request_pin",JSON.stringify(meta(x.requestRaw))===JSON.stringify(x.requestPin));
 const q=JSON.parse(x.requestRaw),n=x.expected,m=JSON.parse(x.infoRaw);
 need("binary_only",q.operation.tool==="binary_read"&&Object.keys(q.operation.arguments).sort().join(",")==="expected_version,host,limit,offset,path");
 need("actual_range",q.operation.arguments.host==="rog"&&q.operation.arguments.path===m.path&&q.operation.arguments.offset===0&&q.operation.arguments.limit===m.size&&m.size===28015&&m.size<=65536&&q.operation.arguments.expected_version===m.version);
 need("actual_metadata_full_binding",n.path===m.path&&n.bytes===m.size&&n.sha256===m.sha256&&n.version===m.version&&JSON.stringify(n.infoNative)===JSON.stringify(meta(x.infoRaw)));
 need("actual_closed_metadata",x.current.completedObservers.some(o=>o.id===n.infoOperation&&o.tool==="file_info"&&o.completedInactive&&o.nativeText.blob===n.infoNative.blob));
 need("existing_context_not_reset",x.current.pending===null&&x.current.activeObserver===null&&!x.current.nativeCallInFlight&&!x.current.paused&&x.current.stageResultBodyGO===undefined&&x.current.stageResultBodyStarted!==true);
 need("separate_body_GO",x.after.includes('g.scope==="stage_result_binary_read_only"')&&x.after.includes('goPin.blob!==s.stageResultInfoGO.pin.blob')&&x.after.includes('g.maximum_binary_read_starts===1'));
 need("no_start_reset",x.after.includes('s.stageResultInfoGO?.whole===true && s.stageResultInfoStarted===true'));
 need("one_fixed_request",x.after.includes("gfMetaEquals(raw,GF_STAGE_BODY_REQUEST)"));
 need("once_before_call",x.after.indexOf("s.stageResultBodyStarted=true")<x.after.indexOf("let sdk;"));
 need("original_body_path_version",x.after.includes("v.path===need.path && v.version===need.version && v.size===need.bytes"));
 need("actual_full_EOF",x.after.includes("v.offset===0 && v.next_offset===need.bytes && v.eof===true"));
 need("independent_chunk_SHA",x.after.includes('v.chunk_sha256===need.sha256'));
 need("decoded_whole_SHA",x.after.includes("bodyBytes.length===need.bytes && bodyPin.bytes===need.bytes")&&x.after.includes('bodyPin.sha256===need.sha256'));
 need("old8192pages",x.after.includes("q.limit===8192")&&x.after.includes("b.length<=8192"));
 need("old1MiBpayload",x.after.includes("v.total_bytes<=1048576"));
 need("old16384stream",x.after.includes("a.limit===16384"));
 need("no_semantic_promotion",x.after.includes("semanticQualification:false"));
 return {schema:"heptabao.snapshot8c95.stage-body-source-checks.v1",checks,passed:checks.length,RuntimeCalls:0,candidateFunctionsExecuted:false};
}
