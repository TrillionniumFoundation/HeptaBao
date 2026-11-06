function verifyInfoOnly(data,pureSource) {
 const P=new Function(pureSource+"\nreturn {gitBlobMeta,parseLosslessIntegers};")();
 const checks=[];function ck(name,ok){checks.push({name,pass:!!ok});if(!ok)throw Error(name);}
 function clone(x){return JSON.parse(JSON.stringify(x));}
 function defs(t){const a=[...t.matchAll(/^(?:async )?function ([A-Za-z0-9_]+)\(/gm)],out={};for(let i=0;i<a.length;i++)out[a[i][1]]=t.slice(a[i].index,i+1<a.length?a[i+1].index:t.length);return out;}
 const b=defs(data.before),n=defs(data.after);
 ck("one_new_definition",Object.keys(n).length===Object.keys(b).length+1&&Object.hasOwn(n,"gfAuthorizeStageResultInfoOnly"));
 const changed=["gfValidateRequest","gfPrepareOne","gfInvokePreparedOnce","gfCloseOriginalObserver","gfRun"];
 for(const name of Object.keys(b))if(!changed.includes(name))ck("whole_definition_"+name,b[name]===n[name]);
 let out=data.before;for(const r of data.replacements){ck("replace_once_"+r.label,out.split(r.before).length===2);out=out.replace(r.before,r.after);}
 ck("forward_whole",out===data.after);for(const r of [...data.replacements].reverse()){ck("reverse_once_"+r.label,out.split(r.after).length===2);out=out.replace(r.after,r.before);}ck("reverse_whole",out===data.before);
 function apply(before,diff){const old=before.split("\n");old.pop();const lines=diff.split("\n");let cursor=0,result=[],i=2,hunks=0;while(i<lines.length&&lines[i]!==""){const m=/^@@ -([0-9]+),([0-9]+) \+([0-9]+),([0-9]+) @@$/.exec(lines[i++]);if(!m)throw Error("diff_header");hunks++;const pos=Number(m[1])-1;result.push(...old.slice(cursor,pos));cursor=pos;let removed=0,added=0;while(i<lines.length&&!lines[i].startsWith("@@")&&lines[i]!==""){const line=lines[i++],k=line[0],v=line.slice(1);if(k!=="+"&&old[cursor++]!==v)throw Error("diff_context");if(k!=="+")removed++;if(k!=="-"){result.push(v);added++;}}if(removed!==Number(m[2])||added!==Number(m[4]))throw Error("diff_count");}result.push(...old.slice(cursor));return{raw:result.join("\n")+"\n",hunks};}
 const patch=apply(data.before,data.diff);ck("strict_six_hunk_apply",patch.hunks===6&&patch.raw===data.after);
 const constants=data.after.slice(data.after.indexOf("const GF_SLOT"),data.after.indexOf("\nfunction gfAuthorizeStageResultInfoOnly"));
 const selected=constants+"\n"+n.gfAuthorizeStageResultInfoOnly+n.gfNeed+n.gfMetaEquals+n.gfValidateRequest;
 // Only authorization and pure request validation are selected. No async method,
 // archive, native tool, full module initialization or gfRun is invoked.
 let current;const fakeLoad=k=>k.startsWith("jwt_e3af_rog_source_gitfirst_r1:closed_native:")?data.closedNative[k.slice(k.lastIndexOf(":")+1)]:undefined;
 const api=new Function("gitBlobMeta","parseLosslessIntegers","gfState","gfSave","load",
   selected+"\nreturn {authorize:gfAuthorizeStageResultInfoOnly,validate:gfValidateRequest};")
   (P.gitBlobMeta,P.parseLosslessIntegers,()=>current,s=>{current=s;},fakeLoad);
 const q=JSON.parse(data.requestRaw),rPin=P.gitBlobMeta(data.requestRaw);
 const fakeGO={authorization:"GO",scope:"stage_result_file_info_only",original_job:data.baseState.job,maximum_file_info_starts:1,binary_read_authorized:false,exact_request:rPin};
 const goRaw=JSON.stringify(fakeGO,null,2)+"\n",authorization={goRaw,goPin:P.gitBlobMeta(goRaw),goWholeReadback:true};
 function reset(){current=clone(data.baseState);}
 function refuses(name,fn){let refused=false;try{fn();}catch(e){refused=true;}ck(name,refused);}
 reset();refuses("no_info_before_new_GO",()=>api.validate(current,"operation_start",q,data.requestRaw));
 reset();api.authorize(authorization);ck("separate_info_GO_accepts_and_preserves_job",current.stageResultInfoGO.whole===true&&current.job===data.baseState.job&&current.startCalled);
 api.validate(current,"operation_start",q,data.requestRaw);ck("one_exact_info_accepts",true);
 refuses("no_repeat_capability",()=>api.authorize(authorization));
 current.stageResultInfoStarted=true;refuses("no_repeat_info_admission",()=>api.validate(current,"operation_start",q,data.requestRaw));
 reset();refuses("old_start_GO_cannot_add_file_info",()=>api.authorize({goRaw:data.oldGo,goPin:P.gitBlobMeta(data.oldGo),goWholeReadback:true}));
 reset();refuses("unread_GO_refuses",()=>api.authorize({...authorization,goWholeReadback:false}));
 reset();current.activeObserver={id:"unclosed"};refuses("unclosed_future_refuses_capability",()=>api.authorize(authorization));
 reset();current.job="wrong-job";refuses("different_job_refuses_capability",()=>api.authorize(authorization));
 reset();current.completedObservers[0].completedInactive=false;refuses("unclosed_prior_authority_refuses",()=>api.authorize(authorization));
 const bad=clone(fakeGO);bad.binary_read_authorized=true;const badRaw=JSON.stringify(bad);
 reset();refuses("GO_scope_cannot_authorize_body",()=>api.authorize({goRaw:badRaw,goPin:P.gitBlobMeta(badRaw),goWholeReadback:true}));
 const variants=[
  ["wrong_path",x=>x.operation.arguments.path+="/other"],
  ["wrong_host",x=>x.operation.arguments.host="desktop"],
  ["different_key",x=>x.idempotency_key+="-again"],
  ["body_tool",x=>x.operation.tool="binary_read"],
  ["extra_argument",x=>x.operation.arguments.limit=65536],
  ["extra_top_field",x=>x.extra=true]
 ];
 for(const[name,mutate]of variants){reset();api.authorize(authorization);const v=clone(q);mutate(v);refuses(name,()=>api.validate(current,"operation_start",v,JSON.stringify(v,null,2)+"\n"));}
 reset();api.authorize(authorization);
 const oldStatus={idempotency_key:"heptabao-native-jwt-e3afc157-rog-source-observe-r1-pure-status",operation:{tool:"process_status",arguments:{host:"rog",job_id:current.job}}};
 api.validate(current,"operation_start",oldStatus,JSON.stringify(oldStatus));ck("original_status_route_preserved",true);
 oldStatus.operation.arguments.job_id="other";refuses("old_status_other_job_still_refuses",()=>api.validate(current,"operation_start",oldStatus,JSON.stringify(oldStatus)));
 const oldRead={idempotency_key:"heptabao-native-jwt-e3afc157-rog-source-observe-r1-pure-read",operation:{tool:"process_read",arguments:{host:"rog",job_id:current.job,limit:16384,stdout_offset:370,stderr_offset:0}}};
 api.validate(current,"operation_start",oldRead,JSON.stringify(oldRead));ck("original_read_route_preserved",true);
 oldRead.operation.arguments.job_id="other";refuses("old_read_other_job_still_refuses",()=>api.validate(current,"operation_start",oldRead,JSON.stringify(oldRead)));
 const close=n.gfCloseOriginalObserver,begin=close.indexOf('  if(a.tool==="file_info") {'),end=close.indexOf(' else gfNeed(v.job_id===s.job',begin);
 ck("selected_metadata_block_exact",begin>=0&&end>begin);
 const metadata=new Function("gitBlobMeta",constants+"\n"+n.gfNeed+
   "\nreturn function(v){const s={},a={tool:'file_info',id:'synthetic-info'},nativeRaw=JSON.stringify(v);"+
   close.slice(begin,end)+"\nreturn s.stageResultInfo;};")(P.gitBlobMeta);
 const sample=JSON.parse(data.sampleInfo);sample.path=q.operation.arguments.path;
 const good=metadata(sample);ck("Linux_full_mode_33152",good.full9Strings[4]==="33152");
 ck("nanoseconds_remain_literal_strings",good.full9Strings[7]===sample.version.split(":")[3]&&good.full9Strings[8]===sample.version.split(":")[4]);
 ck("metadata_does_not_grant_body",good.binaryReadAuthorized===false);
 const mutations=[
 ["metadata_wrong_path",v=>v.path+="/bad"],["metadata_wrong_mode",v=>v.mode=420],
 ["metadata_uid",v=>v.metadata.uid=0],["metadata_links",v=>v.metadata.link_count=2],
 ["metadata_platform",v=>v.metadata.metadata_platform="macos"],
 ["metadata_zero",v=>v.size=0],["metadata_cap",v=>v.size=150001],
 ["metadata_hash",v=>v.sha256="bad"],["metadata_version_size",v=>v.version=v.version.replace(":27181:",":1:")]
 ];
 for(const[name,mutate]of mutations){const v=clone(sample);mutate(v);refuses(name,()=>metadata(v));}
 ck("same_original_Native_dispatch_whole",data.after.includes(data.before.slice(data.before.indexOf(" let sdk;\n try {"),data.before.indexOf("\n store(GF_SLOT+\":original_sdk:"))));
 ck("external_SDK_accept_method_whole",b.gfAcceptArchivedSDK===n.gfAcceptArchivedSDK);
 ck("no_binary_read_dispatch",!data.after.includes('op.tool==="binary_read"')&&!data.after.includes("controller_binary_read"));
 return {schema:"heptabao.native-jwt.stage-result-info.selected-checks.v1",checks,passed:checks.length,
  executed:"Only selected pure authorization/request/metadata branches with fake state; synthetic authorization is not an actual root GO.",
  originalStateMutated:false,RuntimeCalls:0,GitMutations:0,fullModuleExecuted:false};
}