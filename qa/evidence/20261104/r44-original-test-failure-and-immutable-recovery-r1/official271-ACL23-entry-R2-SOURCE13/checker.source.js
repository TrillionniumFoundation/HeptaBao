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

function verifyOracleEntryR2(i){
 const out=[];const check=(name,ok)=>{out.push({name,pass:!!ok});if(!ok)throw Error(name);};
 check("four_hunks",(i.diff.match(/^@@ /gm)||[]).length===4);
 check("strict_forward",applyStrict(i.before,i.diff,false)===i.after);
 check("strict_reverse",applyStrict(i.after,i.diff,true)===i.before);
 let reconstructed=i.before;for(const[a,b]of i.replacements){check("unique_edit_"+out.length,reconstructed.split(a).length===2);reconstructed=reconstructed.replace(a,b);}check("only_four_declared_sites",reconstructed===i.after);
 const beforeQ=i.oldRequest,q=i.request;check("unchanged_stdin_all11_inputs",q.stdin===beforeQ.stdin&&q.stdin===i.payloadRaw);
 check("unchanged_host_exe_cwd_outer",q.host===beforeQ.host&&q.executable===beforeQ.executable&&q.cwd===beforeQ.cwd&&q.timeout_seconds===beforeQ.timeout_seconds&&q.timeout_seconds===390);
 check("only_request_source_selfhash_key",JSON.stringify({...q,args:beforeQ.args,idempotency_key:beforeQ.idempotency_key})===JSON.stringify(beforeQ));
 check("exact_inline_source_selfhash",q.args[4]===i.after&&q.args[5]===gitBlobMeta(i.after).sha256);
 check("exact_request_raw",JSON.stringify(q,null,2)+"\n"===i.requestRaw);
 check("absolute360_and_all_original_budgets",JSON.stringify(i.plan.budgets)===JSON.stringify(i.oldPlan.budgets)&&i.plan.budgets.originalOwnerSeconds===360&&i.plan.budgets.aclHTTPMaximum===853);
 check("root_ports_runid_unchanged",["fixedRoot","loopbackHttpsPort","clusterPort","run_id"].every(k=>i.plan[k]===i.oldPlan[k]));
 check("fixed_helper_pins_unchanged",JSON.stringify(i.plan.immutableInputs)===JSON.stringify(i.oldPlan.immutableInputs));
 check("write_chunk_64KiB",i.after.includes("written = os.write(fd, view[:65536])")&&!i.after.includes("written = os.write(fd, view)"));
 const init=i.after.indexOf("extra_live_health_attempted, extra_live_health_completed = 0, 0"),attempt=i.after.indexOf("extra_live_health_attempted = 1"),call=i.after.indexOf("health = client.health()"),done=i.after.indexOf("extra_live_health_completed = 1"),identity=i.after.indexOf("identity = launcher.verify_selected_oracle(");
 check("per_entry_counter_initialization",init>=0&&init<attempt&&i.after.slice(0,init).lastIndexOf("def main():")>=0);
 check("attempt_before_call_completed_after_return",attempt<call&&call<done&&done<identity);
 check("exactly_one_attempt_and_return_site",(i.after.match(/extra_live_health_attempted = 1/g)||[]).length===1&&(i.after.match(/extra_live_health_completed = 1/g)||[]).length===1);
 check("reported_maximum_not_claimed_attempt",i.after.includes('"extra_live_health_requests": {"maximum": 1,')&&!i.after.includes('"extra_live_health_requests": 1,'));
 check("startup_actual_stays_unknown",i.after.includes('"startup_requests_actual_count": None'));
 const t=processStartBinding(q);check("typed_native_binding",t.sha256===i.typed.sha256&&t.native_fingerprint===i.typed.native_fingerprint);
 check("not_Runtime_or_Python_execution",true);
 return {schema:"heptabao.oracle-entry-r2.source-checks.v1",checks:out,passed:out.length,failed:0,scope:"V8 source/diff/request only; no Python, OpenSSL, OpenBao, HTTP or native call",Native:0,product_cases_executed:0,component_variants_executed:0};
}
