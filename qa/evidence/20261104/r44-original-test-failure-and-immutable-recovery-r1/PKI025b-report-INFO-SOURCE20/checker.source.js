function strictDiff(before,after,label){
 const a=before.split("\n"),b=after.split("\n");if(a.pop()!==""||b.pop()!=="")throw Error("LF required");
 const d=Array.from({length:a.length+1},()=>new Uint16Array(b.length+1));
 for(let i=a.length-1;i>=0;i--)for(let j=b.length-1;j>=0;j--)d[i][j]=a[i]===b[j]?1+d[i+1][j+1]:Math.max(d[i+1][j],d[i][j+1]);
 let i=0,j=0,ops=[];while(i<a.length||j<b.length){if(i<a.length&&j<b.length&&a[i]===b[j]){ops.push([" ",a[i++]]);j++;}else if(j<b.length&&(i===a.length||d[i][j+1]>d[i+1][j]))ops.push(["+",b[j++]]);else ops.push(["-",a[i++]]);}
 const changed=ops.map((x,k)=>x[0]!==" "?k:-1).filter(k=>k>=0);if(!changed.length)return "";
 const spans=[];for(const k of changed){const z=[Math.max(0,k-3),Math.min(ops.length,k+4)];if(spans.length&&z[0]<=spans.at(-1)[1])spans.at(-1)[1]=Math.max(spans.at(-1)[1],z[1]);else spans.push(z);}
 let out="--- a/"+label+"\n+++ b/"+label+"\n";
 for(const [l,r]of spans){let old=0,neu=0,oc=0,nc=0;for(let k=0;k<l;k++){if(ops[k][0]!=="+")old++;if(ops[k][0]!=="-")neu++;}for(let k=l;k<r;k++){if(ops[k][0]!=="+")oc++;if(ops[k][0]!=="-")nc++;}out+="@@ -"+(old+(oc?1:0))+","+oc+" +"+(neu+(nc?1:0))+","+nc+" @@\n"+ops.slice(l,r).map(x=>x.join("")).join("\n")+"\n";}return out;
}
function applyStrict(before,diff,reverse){
 const src=before.split("\n");if(src.pop()!=="")throw Error("LF");if(diff==="")return before;
 const ls=diff.trimEnd().split("\n");let p=2,cursor=0,out=[];
 while(p<ls.length){const m=/^@@ -(\d+),(\d+) \+(\d+),(\d+) @@$/.exec(ls[p++]);if(!m)throw Error("hunk");
 const start=Number(m[reverse?3:1]),count=Number(m[reverse?4:2]),destCount=Number(m[reverse?2:4]);const at=start-(count?1:0);if(at<cursor)throw Error("overlap");out.push(...src.slice(cursor,at));cursor=at;let used=0,made=0;
 while(p<ls.length&&!ls[p].startsWith("@@ ")){const x=ls[p++],kind=reverse?({" ":" ","+":"-","-":"+"})[x[0]]:x[0],v=x.slice(1);if(kind===" "||kind==="-"){if(src[cursor++]!==v)throw Error("whole context");used++;}if(kind===" "||kind==="+"){out.push(v);made++;}if(![" ","-","+"].includes(kind))throw Error("kind");}
 if(used!==count||made!==destCount)throw Error("hunk counts");
 }out.push(...src.slice(cursor));return out.join("\n")+"\n";
}

async function verifyBuildInfoSource(input){
 const checks=[];function check(name,ok){checks.push({name,pass:!!ok});if(!ok)throw Error(name);}
 const {before,after,requestRaw,state,closedNative,beforeCurrentJournal}=input,q=JSON.parse(requestRaw),pin=gitBlobMeta(requestRaw);
 check("strict_forward_whole",applyStrict(before,input.diff,false)===after);
 check("strict_reverse_whole",applyStrict(after,input.diff,true)===before);
 check("same_current_slot",after.includes('const GF_SLOT = "'+input.slot+'";'));
 check("existing_original_current_start_request",after.includes(JSON.stringify(input.startRequestPin)));
 check("fixed_only_report_path",q.operation.tool==="file_info"&&q.operation.arguments.host==="rog"&&Object.keys(q.operation.arguments).sort().join(",")==="host,path"&&q.operation.arguments.path===input.reportPath);
 check("actual_failed_original_job_known",state.job===input.job&&state.startCalled===true);
 check("actual_31_calls_10_closed",Object.keys(state.calls).length===31&&state.completedObservers.length===10&&state.completedObservers.every(x=>x.completedInactive));
 check("actual_frontier_no_future",state.pending===null&&state.activeObserver===null&&!state.nativeCallInFlight&&!state.paused&&state.nextStdout===2216&&state.nextStderr===0);
 const functionSlices=raw=>{const hits=[...raw.matchAll(/^(?:async )?function (\w+)\(/gm)];return Object.fromEntries(hits.map((m,i)=>[m[1],raw.slice(m.index,i+1<hits.length?hits[i+1].index:raw.length)]));};
 const oldFns=functionSlices(before),newFns=functionSlices(after);
 check("same_function_names",Object.keys(oldFns).join(",")===Object.keys(newFns).join(","));
 for(const name of Object.keys(oldFns)){if(name==="gfAuthorizeStageResultInfoOnly")continue;const x=name==="gfValidateRequest"?oldFns[name].replace("heptabao-native-jwt-pki-33b814c7-build149-observe-r1-","heptabao-native-jwt-pki-025b05a3-build149-observe-r2-"):oldFns[name];check("preserved_"+name,newFns[name]===x);}
 check("metadata_size_cap_1MiB_preserved",after.includes("const GF_STAGE_RESULT_MAX_BYTES = 1048576;"));
 check("metadata_fullmode_correct",after.includes("String(32768|v.mode)"));
 check("new_metadata_8KiB_pages_preserved",after.includes("q.limit===8192")&&after.includes("b.length<=8192"));
 check("no_binary_dispatch_added",!after.includes("controller_binary_read")&&!after.includes('op.tool==="binary_read"'));
 check("candidate_compiles_as_JS_source_only",typeof new Function("tools","store","load",input.pure+"\n"+input.archive+"\n"+after+"\nreturn gfRun;")==="function");
 let toolCalls=0;const toolsStub=new Proxy({}, {get(){return ()=>{toolCalls++;throw Error("forbidden tool");};}});
 const go={authorization:"GO",scope:"build_result_file_info_only",original_job:input.job,maximum_file_info_starts:1,binary_read_authorized:false,exact_request:pin};
 const goRaw=JSON.stringify(go,null,2)+"\n",goPin=gitBlobMeta(goRaw);
 function sandbox(mutator){const local=new Map(),copy=JSON.parse(JSON.stringify(state));local.set(input.slot,copy);for(const[k,v]of Object.entries(closedNative))local.set(k,v);if(mutator)mutator(copy,local);const api=new Function("tools","store","load",input.pure+"\n"+input.archive+"\n"+after+"\nreturn {gfRun,gfValidateRequest};")(toolsStub,(k,v)=>local.set(k,v),k=>local.get(k));return {local,api};}
 const good=sandbox(),snapshot=JSON.stringify(good.local.get(input.slot)),result=await good.api.gfRun("authorize_build_result_info",{goRaw,goPin,goWholeReadback:true});
 check("actual_closure_authorizes_metadata_only",result.ok&&result.value.maximumFileInfoStarts===1&&result.value.binaryReadAuthorized===false);
 const accepted=good.local.get(input.slot);const strip=JSON.parse(JSON.stringify(accepted));delete strip.stageResultInfoGO;check("all_old_state_byte_values_preserved",JSON.stringify(strip)===snapshot);
 good.api.gfValidateRequest(accepted,"operation_start",q,requestRaw);check("one_exact_file_info_admission_valid",true);
 function reject(name,s,kind,raw){let refused=false;try{good.api.gfValidateRequest(s,kind,JSON.parse(raw),raw);}catch(e){refused=true;}check(name,refused);}
 const clone=()=>JSON.parse(JSON.stringify(accepted));
 const wrongPath=JSON.parse(requestRaw);wrongPath.operation.arguments.path+="/extra";reject("other_path_refused",clone(),"operation_start",JSON.stringify(wrongPath,null,2)+"\n");
 const body=JSON.parse(requestRaw);body.operation.tool="binary_read";body.operation.arguments.offset=0;body.operation.arguments.limit=1;reject("body_not_authorized",clone(),"operation_start",JSON.stringify(body,null,2)+"\n");
 const twice=clone();twice.stageResultInfoStarted=true;reject("repeat_info_refused",twice,"operation_start",requestRaw);
 reject("new_process_refused",clone(),"process_start",input.startRequestRaw);
 for(const[name,mut]of[
  ["live_future_refused",s=>{s.activeObserver={id:"x"};}],
  ["wrong_frontier_refused",s=>{s.nextStdout=1809;}],
  ["missing_closed_observer_refused",s=>{s.completedObservers.pop();}],
  ["unwhole_original_pin_refused",(s,m)=>{const k=Object.keys(closedNative)[0];m.set(k,closedNative[k]+" ");}]
 ]){const x=sandbox(mut),r=await x.api.gfRun("authorize_build_result_info",{goRaw,goPin,goWholeReadback:true});check(name,r.ok===false);}
 check("zero_native_git_tools_executed",toolCalls===0);
 return {schema:"heptabao.025b-build-report-info-source-checks.v1",checks,passed:checks.length,failed:0,scope:"PURE_SOURCE_AND_SELECTED_GUARDS_ONLY",native_calls:0,product_tests:0,actual_metadata_observed:false};
}
