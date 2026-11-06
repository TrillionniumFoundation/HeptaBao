function verifyStageInfoSource(x,D,meta) {
 const checks=[];function need(name,value){checks.push({name,pass:value===true});if(value!==true)throw new Error(name);}
 function def(raw,name){const all=[...raw.matchAll(/^(?:async )?function ([A-Za-z0-9_]+)[(]/gm)];const i=all.findIndex(m=>m[1]===name);if(i<0)throw new Error("missing:"+name);return raw.slice(all[i].index,i+1<all.length?all[i+1].index:raw.length);}
 need("strict_forward",D.apply(x.before,x.diff)===x.after);
 need("strict_reverse",D.apply(x.after,x.diff,true)===x.before);
 need("six_hunks",(x.diff.match(/^@@/gm)||[]).length===6);
 for(const name of ["gfNeed","gfMetaEquals","gfState","gfSave","gfIntegerText","gfInitializeOnlyAfterRootGO","gfAcceptArchivedSDK","gfReconcileSameGitArchiveReadOnly"])need("unchanged:"+name,def(x.before,name)===def(x.after,name));
 let rebound=x.reference;for(const r of x.replacements){need("one_reference_literal:"+checks.length,rebound.split(r.old).length===2);rebound=rebound.replace(r.old,r.new);}need("reference_binding_only",rebound===x.after);
 need("request_whole",JSON.stringify(meta(x.requestRaw))===JSON.stringify(x.requestPin));
 const q=JSON.parse(x.requestRaw);
 need("one_file_info_request",q.operation.tool==="file_info"&&Object.keys(q.operation.arguments).sort().join(",")==="host,path"&&q.operation.arguments.host==="rog"&&q.operation.arguments.path===x.path);
 need("key_original_prefix",q.idempotency_key==="heptabao-native-snapshot-8c95fb0a-rog-source-observe-r1-report-info");
 need("existing_slot",x.after.includes('const GF_SLOT = "snapshot_8c95_rog_source_gitfirst_r1";'));
 need("fixed_64KiB_cap",x.after.includes("const GF_STAGE_RESULT_MAX_BYTES = 65536;"));
 need("separate_GO",x.after.includes('goPin.blob!==s.goPin.blob')&&x.after.includes('g.scope==="stage_result_file_info_only"')&&x.after.includes('g.binary_read_authorized===false'));
 need("actual_job",x.after.includes('s.job==="1a1afa74868-fc05-6a7e"'));
 need("actual_closed_streams",x.after.includes('s.nextStdout===383 && s.nextStderr===0'));
 need("source_stage_two_closures",x.prerequisites.length===2&&x.prerequisites.every(p=>x.after.includes(JSON.stringify(p))));
 need("once_before_original_call",x.after.indexOf('s.stageResultInfoStarted=true')<x.after.indexOf('let sdk;'));
 need("exact_request_gate",x.after.includes("gfMetaEquals(raw,GF_STAGE_INFO_REQUEST)"));
 need("native_metadata_0600",x.after.includes("v.mode===384")&&x.after.includes("md.mode===384"));
 need("native_metadata_owner_single",x.after.includes("md.uid===1000 && md.gid===1000 && md.link_count===1"));
 need("lossless_full_mode",x.after.includes('String(32768|v.mode)'));
 need("decimal_version_preserved",x.after.includes('parts[3],parts[4]')&&x.after.includes('parts[2]===String(v.size)'));
 need("no_binary_read_branch",!x.after.includes('op.tool==="binary_read"'));
 need("old_page_limit",x.after.includes('q.limit===8192')&&x.after.includes('b.length<=8192'));
 need("old_payload_limit",x.after.includes("v.total_bytes<=1048576"));
 need("old_process_read_limit",x.after.includes("a.limit===16384"));
 need("old_SDK_before_parse",x.after.indexOf('c.sdkArchive=await archiveFlatPublicTextsOnce')<x.after.indexOf('const sdk=JSON.parse(raw)'));
 need("actual_context_untouched",x.current.stageResultInfoGO===undefined&&x.current.stageResultInfoStarted!==true&&x.current.activeObserver===null&&x.current.pending===null&&x.current.nativeCallInFlight===false);
 return {schema:"heptabao.snapshot8c95.report-info-source-checks.v1",checks,passed:checks.length,RuntimeCalls:0,candidateFunctionsExecuted:false,sourceOnly:true};
}
