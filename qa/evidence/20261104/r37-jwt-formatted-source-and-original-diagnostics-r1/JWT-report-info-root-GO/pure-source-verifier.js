function verifyCollectorReportInfoSource(I) {
 const {gitBlobMeta}=new Function(I.pure+"\nreturn {gitBlobMeta};")();
 const out=[];const need=(v,n)=>{out.push({name:n,pass:!!v});if(!v)throw Error(n);};
 let f=I.before;for(const [i,r]of I.replacements.entries()){need(f.split(r.before).length===2,"replacement_unique_"+i);f=f.replace(r.before,r.after);}
 need(f===I.after,"whole_forward_reconstruction");
 let back=I.after;for(const [i,r]of [...I.replacements].reverse().entries()){need(back.split(r.after).length===2,"inverse_unique_"+i);back=back.replace(r.after,r.before);}
 need(back===I.before,"whole_inverse_reconstruction");
 const names=Array.from(I.before.matchAll(/^(?:async )?function ([A-Za-z0-9_]+)\(/gm),m=>m[1]);
 function definition(s,n){const match=new RegExp("^(?:async )?function "+n+"\\(","m").exec(s);if(!match)throw Error("missing_"+n);const start=match.index;const next=/\n(?:async )?function [A-Za-z0-9_]+\(/g;next.lastIndex=start+1;const end=next.exec(s);return s.slice(start,end?end.index:s.length);}
 const changed=new Set(["gfValidateRequest","gfPrepareOne","gfInvokePreparedOnce","gfCloseOriginalObserver","gfRun"]);
 for(const n of names)if(!changed.has(n))need(definition(I.before,n)===definition(I.after,n),"unchanged_definition_"+n);
 const slot="jwt_e3af_rog_format38_collector_gitfirst_r1";
 const fakeGo={authorization:"GO",scope:"collector_report_file_info_only",original_job:I.actual_state.job,maximum_file_info_starts:1,binary_read_authorized:false,exact_request:I.request_pin};
 function env(mutator){const m=new Map(Object.entries(I.closed_native));m.set(slot,JSON.parse(JSON.stringify(I.actual_state)));if(mutator)mutator(m.get(slot),m);const api=new Function("store","load",I.pure+"\n"+I.after+"\nreturn {gfAuthorizeCollectorReportInfoOnly,gfValidateRequest};")((k,v)=>m.set(k,v),k=>m.get(k));return {m,api};}
 function auth(E,g=fakeGo){const raw=JSON.stringify(g)+"\n";return E.api.gfAuthorizeCollectorReportInfoOnly({goRaw:raw,goPin:gitBlobMeta(raw),goWholeReadback:true});}
 function refuses(fn,n){let rejected=false;try{fn();}catch(e){rejected=true;}need(rejected,n);}
 const E=env();const r=auth(E);need(r.maximumFileInfoStarts===1&&r.binaryReadAuthorized===false,"actual_closed_state_accepts_only_info");
 const q=JSON.parse(I.request_raw);E.api.gfValidateRequest(E.m.get(slot),"operation_start",q,I.request_raw);need(true,"one_exact_info_request_allowed");
 refuses(()=>auth(E),"second_authorization_refused");
 refuses(()=>auth(env(s=>s.activeObserver={id:"active"})),"unclosed_observer_refused");
 refuses(()=>auth(env(s=>s.paused=true)),"paused_history_refused");
 refuses(()=>auth(env(),{...fakeGo,binary_read_authorized:true}),"body_permission_in_info_GO_refused");
 refuses(()=>{const X=env();X.api.gfValidateRequest(X.m.get(slot),"operation_start",q,I.request_raw);},"unapproved_info_refused");
 refuses(()=>{const q2=JSON.parse(I.request_raw);q2.operation.arguments.path+="/x";E.api.gfValidateRequest(E.m.get(slot),"operation_start",q2,JSON.stringify(q2)+"\n");},"different_path_refused");
 refuses(()=>{const q2=JSON.parse(I.request_raw);q2.operation={tool:"binary_read",arguments:{host:"rog",path:q.operation.arguments.path,offset:0,limit:65536,expected_version:"x"}};E.api.gfValidateRequest(E.m.get(slot),"operation_start",q2,JSON.stringify(q2)+"\n");},"binary_read_refused");
 refuses(()=>{const X=env(s=>s.collectorReportInfoStarted=true);auth(X);},"already_started_info_refused");
 need(I.after.includes("q.limit===8192")&&I.after.includes("b.length<=8192"),"old_8192_pages_unchanged");
 need(!I.after.includes('op.tool==="binary_read"'),"no_body_dispatch_branch");
 need(I.after.includes('String(32768|v.mode)')&&I.after.includes('md.uid===1000 && md.gid===1000 && md.link_count===1'),"linux_full_mode_and_single_link_guard");
 return {schema:"heptabao.collector-report-info-source-verification.v1",status:"passed",checks:out,checks_count:out.length,native_calls:0,github_calls:0,candidate_python_executed:false,exact_request:gitBlobMeta(I.request_raw),source:gitBlobMeta(I.after),synthetic_go_not_authorization:true};
}