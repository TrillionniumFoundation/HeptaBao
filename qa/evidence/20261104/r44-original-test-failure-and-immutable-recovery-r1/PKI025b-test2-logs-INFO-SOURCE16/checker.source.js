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

async function verifyFailedTestLogInfoSource(i){
 const checks=[];const check=(name,v)=>{checks.push({name,pass:!!v});if(!v)throw Error(name);};
 check("strict_forward_whole",applyStrict(i.before,i.diff,false)===i.after);check("strict_reverse_whole",applyStrict(i.after,i.diff,true)===i.before);
 check("three_hunks",(i.diff.match(/^@@ /gm)||[]).length===3);
 const slices=s=>{const m=[...s.matchAll(/^(?:async )?function (\w+)\(/gm)];return Object.fromEntries(m.map((x,k)=>[x[1],s.slice(x.index,m[k+1]?.index??s.length)]));},a=slices(i.before),b=slices(i.after);
 check("same_function_inventory",Object.keys(a).join(",")===Object.keys(b).join(","));
 for(const name of Object.keys(a))if(name!=="gfInitializeOnlyAfterRootGO")check("old_function_unchanged_"+name,a[name]===b[name]);
 check("two_exact_public_test_paths",i.requestRaws.length===2&&i.targets[0].path.endsWith("/native-jwt-pki-file17-2.stderr")&&i.targets[1].path.endsWith("/native-jwt-pki-file17-2.stdout"));
 check("same_actual_report_root",i.targets.every(t=>t.path.startsWith("/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r2/build-tests-r1/")));
 const report=parseLosslessIntegers(i.reportRaw),test=report.group_results[0].tests[1];check("actual_failed_test_record",test.name==="service::native_auth::jwt_tests::native_jwt_rejects_remote_batch_and_bad_signature_without_candidate_delta"&&test.tests.label==="native-jwt-pki-file17-2"&&test.tests.exit_code===101&&test.tests.timed_out===false);
 check("actual_raw_log_hashes",test.tests.stderr_sha256===i.targets[0].sha256&&test.tests.stdout_sha256===i.targets[1].sha256);
 check("owned_runner_path_rule_original",i.runnerRaw.includes("with (output / (label + '.stdout')).open('xb') as out, (output / (label + '.stderr')).open('xb') as err:"));
 check("all34prior_plus7body_closed",i.priorState.completedObservers.length===12&&Object.keys(i.priorState.calls).length===41&&i.priorState.pending===null&&i.priorState.activeObserver===null&&!i.priorState.nativeCallInFlight&&!i.priorState.paused);
 let invoked=0;const toolsStub=new Proxy({}, {get(){return ()=>{invoked++;throw Error("forbidden");};}});
 const go={authorization:"GO",scope:"build_failed_test_logs_file_info_only",original_job:"1a1b10cad9b-fc05-7560",maximum_file_info_operations:2,maximum_process_start_calls:0,maximum_binary_read_operations:0,exact_requests:i.requestPins},goRaw=JSON.stringify(go,null,2)+"\n",goPin=gitBlobMeta(goRaw);
 function box(mut){const m=new Map([[i.priorSlot,JSON.parse(i.priorStateRaw)],[i.priorSlot+":stage_result_body_original",i.reportRaw]]);if(mut)mut(m);const api=new Function("tools","store","load",i.pure+"\n"+i.archive+"\n"+i.after+"\nreturn {gfRun,gfValidateRequest};")(toolsStub,(k,v)=>m.set(k,v),k=>m.get(k));return {m,api};}
 const x=box(),beforeState=JSON.stringify(x.m.get(i.priorSlot)),res=await x.api.gfRun("initialize",{goRaw,goPin,goWholeReadback:true,priorStateRaw:i.priorStateRaw});
 check("exact_new_readonly_context_initializes",res.ok&&x.m.get(i.slot)?.rootGoWhole===true);
 check("original_build_context_unchanged",JSON.stringify(x.m.get(i.priorSlot))===beforeState);
 const state=x.m.get(i.slot);x.api.gfValidateRequest(state,"operation_start",JSON.parse(i.requestRaws[0]),i.requestRaws[0]);check("first_stderr_exact_admissible",true);
 function reject(name,raw,kind="operation_start",s=state){let failed=false;try{x.api.gfValidateRequest(s,kind,JSON.parse(raw),raw);}catch(e){failed=true;}check(name,failed);}
 reject("stdout_out_of_order_refused",i.requestRaws[1]);
 reject("process_start_refused",i.requestRaws[0],"process_start");
 let q=JSON.parse(i.requestRaws[0]);q.operation.tool="binary_read";reject("binary_refused",JSON.stringify(q,null,2)+"\n");
 q=JSON.parse(i.requestRaws[0]);q.operation.arguments.path+="/extra";reject("extra_path_refused",JSON.stringify(q,null,2)+"\n");
 const once=JSON.parse(JSON.stringify(state));once.logInfoStarted[0]=true;reject("started_info_not_replayed",i.requestRaws[0],"operation_start",once);
 const next=JSON.parse(JSON.stringify(state));next.logInfos=[{index:0}];next.logInfoStarted[0]=true;next.completedObservers=[{completedInactive:true}];next.calls={first:{kind:"operation_start"}};x.api.gfValidateRequest(next,"operation_start",JSON.parse(i.requestRaws[1]),i.requestRaws[1]);check("second_only_after_completed_index",true);
 for(const[name,mut]of[["drift_old_state_refused",m=>{m.get(i.priorSlot).paused=true;}],["changed_report_refused",m=>{m.set(i.priorSlot+":stage_result_body_original",i.reportRaw+" ");}]]){
  const bad=box(mut),r=await bad.api.gfRun("initialize",{goRaw,goPin,goWholeReadback:true,priorStateRaw:i.priorStateRaw});check(name,r.ok===false);
 }
 const twice=await x.api.gfRun("initialize",{goRaw,goPin,goWholeReadback:true,priorStateRaw:i.priorStateRaw});check("context_reinitialize_refused",twice.ok===false);
 check("unchanged_metadata1MiB_and8KiB_pages",i.after.includes("const GF_LOG_METADATA_MAX_BYTES = 1048576;")&&i.after.includes("q.limit===8192")&&i.after.includes("v.total_bytes<=1048576"));
 check("metadata_does_not_authorize_body",i.after.includes("expectedVersionBeforeObservation:null,bodyReadAuthorized:false"));
 check("no_tools_executed",invoked===0);
 return {schema:"heptabao.025b.failed-test2-log-info-source-checks.v1",passed:checks.length,failed:0,checks,Native:0,actual_metadata_observed:false,product_tests:0};
}
