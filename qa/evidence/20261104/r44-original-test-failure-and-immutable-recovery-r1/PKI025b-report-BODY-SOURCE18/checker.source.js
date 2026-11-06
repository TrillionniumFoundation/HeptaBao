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

async function verifyFixedReportBodySource(input){
 const checks=[];const check=(name,ok)=>{checks.push({name,pass:!!ok});if(!ok)throw Error(name);};
 const {before,after,diff,requestRaw,expected,state,infoNativeRaw}=input,q=JSON.parse(requestRaw),requestPin=gitBlobMeta(requestRaw);
 check("strict_forward",applyStrict(before,diff,false)===after);check("strict_reverse",applyStrict(after,diff,true)===before);
 check("single_known_49775_range",q.operation.tool==="binary_read"&&q.operation.arguments.offset===0&&q.operation.arguments.limit===49775&&expected.bytes===49775&&expected.bytes<=65536);
 check("actual_path_version_SHA",q.operation.arguments.path===expected.path&&q.operation.arguments.expected_version===expected.version&&expected.sha256==="47748eadb948f08973d7de202272823cd5f031ed99ec62286868236a8cbaa318");
 check("actual_info_original_pin",gitBlobMeta(infoNativeRaw).blob===expected.infoNative.blob);
 check("old_info_authorizer_whole_unchanged",after.slice(after.indexOf("function gfAuthorizeStageResultInfoOnly"),after.indexOf("/* One exact whole-report chunk"))===before.slice(before.indexOf("function gfAuthorizeStageResultInfoOnly"),before.indexOf("function gfNeed")));
 check("closed_original_frontier",state.pending===null&&state.activeObserver===null&&!state.nativeCallInFlight&&!state.paused&&state.stageResultInfoStarted===true&&state.completedObservers.length===11&&Object.keys(state.calls).length===34);
 const apiSource=input.pure+"\n"+input.archive+"\n"+after+"\nreturn {gfRun,gfValidateRequest};";
 let toolsCalled=0;const toolsStub=new Proxy({}, {get(){return ()=>{toolsCalled++;throw Error("No tools allowed");};}});
 function box(mut){const m=new Map(),s=JSON.parse(JSON.stringify(state));m.set(input.slot,s);m.set(input.slot+":closed_native:"+expected.infoOperation,infoNativeRaw);if(mut)mut(s,m);const api=new Function("tools","store","load",apiSource)(toolsStub,(k,v)=>m.set(k,v),k=>m.get(k));return {m,api};}
 const go={authorization:"GO",scope:"build_result_binary_read_only",original_job:state.job,info_operation:expected.infoOperation,maximum_binary_read_starts:1,immutable_body_page_bytes:16384,exact_request:requestPin};
 const goRaw=JSON.stringify(go,null,2)+"\n",goPin=gitBlobMeta(goRaw),good=box(),oldState=JSON.stringify(good.m.get(input.slot));
 const result=await good.api.gfRun("authorize_build_result_body",{goRaw,goPin,goWholeReadback:true});check("valid_exact_actual_info_authorizes_body_only",result.ok&&result.value.wholeBytes===49775&&result.value.maximumBinaryReadStarts===1);
 const current=good.m.get(input.slot),copy=JSON.parse(JSON.stringify(current));delete copy.stageResultBodyGO;check("original_all_state_preserved",JSON.stringify(copy)===oldState);
 good.api.gfValidateRequest(current,"operation_start",q,requestRaw);check("one_exact_body_valid",true);
 function reject(name,changed,kind="operation_start",newState){let failed=false;try{const raw=typeof changed==="string"?changed:JSON.stringify(changed,null,2)+"\n";good.api.gfValidateRequest(newState||JSON.parse(JSON.stringify(current)),kind,JSON.parse(raw),raw);}catch(e){failed=true;}check(name,failed);}
 for(const [name,field,value]of[["wrong_version","expected_version",expected.version+"0"],["other_path","path",expected.path+"/x"],["wrong_offset","offset",1],["over_range","limit",65536]]){const bad=JSON.parse(requestRaw);bad.operation.arguments[field]=value;reject(name,bad);}
 const duplicate=JSON.parse(JSON.stringify(current));duplicate.stageResultBodyStarted=true;reject("repeat_body_refused",q,"operation_start",duplicate);
 reject("no_new_process",input.startRequestRaw,"process_start");
 reject("no_repeat_info",input.infoRequestRaw);
 for(const[name,mut]of[["unclosed_refused",s=>{s.activeObserver={id:"x"};}],["drift_version_refused",s=>{s.stageResultInfo.version+="0";}],["drift_full9_refused",s=>{s.stageResultInfo.full9Strings[8]="0";}],["missing_info_closed_refused",s=>{s.completedObservers=s.completedObservers.filter(x=>x.id!==expected.infoOperation);}],["wrong_original_info_refused",(s,m)=>{m.set(input.slot+":closed_native:"+expected.infoOperation,infoNativeRaw+" ");}]]){
  const x=box(mut),r=await x.api.gfRun("authorize_build_result_body",{goRaw,goPin,goWholeReadback:true});check(name,r.ok===false);
 }
 const observed=JSON.parse(JSON.stringify(current));observed.activeObserver={id:"a".repeat(64),tool:"binary_read",futureClosed:true,nextPageOffset:0,eof:false};
 good.api.gfValidateRequest(observed,"operation_result",{operation_id:observed.activeObserver.id,offset:0,limit:16384},JSON.stringify({operation_id:observed.activeObserver.id,offset:0,limit:16384}));check("new_binary_page16K",true);
 reject("wrong_binary_page8K",{operation_id:observed.activeObserver.id,offset:0,limit:8192},"operation_result",observed);
 observed.activeObserver.tool="file_info";good.api.gfValidateRequest(observed,"operation_result",{operation_id:observed.activeObserver.id,offset:0,limit:8192},JSON.stringify({operation_id:observed.activeObserver.id,offset:0,limit:8192}));check("old_info_page8K_preserved",true);
 check("payload1MiB_preserved",after.includes("v.total_bytes<=1048576"));
 check("whole_body_SHA_EOF_preserved",after.includes('v.next_offset===need.bytes && v.eof===true')&&after.includes('bodyPin.sha256===need.sha256'));
 check("once_marker_before_call",after.indexOf('s.stageResultBodyStarted=true')<after.indexOf('sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_process_start'));
 check("no_tools_no_actual_body",toolsCalled===0);
 return {schema:"heptabao.025b-fixed-report-body-source-checks.v1",passed:checks.length,failed:0,checks,scope:"PURE_SELECTED_GUARDS_ONLY",native_calls:0,actual_body_observed:false,product_tests:0};
}
