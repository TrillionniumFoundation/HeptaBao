function verifyCollectorReportBodySource(I) {
 const {gitBlobMeta}=new Function(I.pure+"\nreturn {gitBlobMeta};")();const checks=[];
 const need=(v,n)=>{checks.push({name:n,pass:!!v});if(!v)throw Error(n);};
 let f=I.before;for(const [i,r]of I.replacements.entries()){need(f.split(r.before).length===2,"body_delta_unique_"+i);f=f.replace(r.before,r.after);}need(f===I.unbound,"unbound_whole");
 for(const [i,r]of I.bindings.entries()){need(f.split(r.before).length===2,"actual_binding_unique_"+i);f=f.replace(r.before,r.after);}need(f===I.after,"bound_whole");
 for(const r of [...I.bindings].reverse())f=f.replace(r.after,r.before);for(const r of [...I.replacements].reverse())f=f.replace(r.after,r.before);need(f===I.before,"full_inverse_whole");
 function def(s,n){const m=new RegExp("^(?:async )?function "+n+"\\(","m").exec(s);if(!m)throw Error("definition_"+n);const re=/\n(?:async )?function [A-Za-z0-9_]+\(/g;re.lastIndex=m.index+1;const next=re.exec(s);return s.slice(m.index,next?next.index:s.length);}
 const changed=new Set(["gfValidateRequest","gfPrepareOne","gfInvokePreparedOnce","gfAcceptArchivedSDK","gfCloseOriginalObserver","gfRun"]);
 for(const m of I.before.matchAll(/^(?:async )?function ([A-Za-z0-9_]+)\(/gm))if(!changed.has(m[1])) {
  const a=def(I.before,m[1]),b=def(I.after,m[1]);
  if(m[1]==="gfAuthorizeCollectorReportInfoOnly")need(b.startsWith(a.trimEnd()),"old_info_authorizer_body_preserved");else need(a===b,"unchanged_definition_"+m[1]);
 }
 const slot="jwt_e3af_rog_format38_collector_gitfirst_r1",info=I.state.collectorReportInfo;
 const go={authorization:"GO",scope:"collector_report_binary_read_ranges_only",original_job:I.state.job,info_operation:info.originalOperation,maximum_binary_read_starts:3,immutable_body_page_bytes:16384,fixed_report:I.expected,exact_requests:I.requests.map(gitBlobMeta)};
 function env(mutate,source=I.after){const m=new Map(Object.entries(I.closed_native));m.set(slot,JSON.parse(JSON.stringify(I.state)));if(mutate)mutate(m.get(slot),m);const api=new Function("store","load",I.pure+"\n"+source+"\nreturn {gfAuthorizeCollectorReportBodyOnly,gfValidateRequest};")((k,v)=>m.set(k,v),k=>m.get(k));return {m,api};}
 function auth(E,g=go){const raw=JSON.stringify(g)+"\n";return E.api.gfAuthorizeCollectorReportBodyOnly({goRaw:raw,goPin:gitBlobMeta(raw),goWholeReadback:true});}
 function refuses(fn,n){let x=false;try{fn();}catch(e){x=true;}need(x,n);}
 const E=env(),out=auth(E);need(out.maximumBinaryReadStarts===3&&out.bodyPageBytes===16384&&out.wholeBytes===167436,"closed_actual_info_allows_exact_three_range_GO");
 E.api.gfValidateRequest(E.m.get(slot),"operation_start",JSON.parse(I.requests[0]),I.requests[0]);need(true,"first_exact_body_range_allowed");
 refuses(()=>auth(env(null,I.unbound)),"unbound_source_never_authorizes");
 refuses(()=>auth(E),"second_body_authorization_refused");
 refuses(()=>auth(env(s=>s.activeObserver={id:"still-active"})),"active_future_refused");
 refuses(()=>auth(env(s=>s.collectorReportInfo.version+="0")),"changed_metadata_version_refused");
 refuses(()=>auth(env(),{...go,maximum_binary_read_starts:4}),"fourth_range_GO_refused");
 refuses(()=>{const X=env();X.api.gfValidateRequest(X.m.get(slot),"operation_start",JSON.parse(I.requests[0]),I.requests[0]);},"body_without_GO_refused");
 refuses(()=>E.api.gfValidateRequest(E.m.get(slot),"operation_start",JSON.parse(I.requests[1]),I.requests[1]),"out_of_order_body_refused");
 const running=env(s=>{s.activeObserver={id:"x",tool:"binary_read",futureClosed:true,nextPageOffset:0,eof:false};});running.api.gfValidateRequest(running.m.get(slot),"operation_result",{operation_id:"x",offset:0,limit:16384},"");need(true,"new_binary_page16384_allowed");
 refuses(()=>running.api.gfValidateRequest(running.m.get(slot),"operation_result",{operation_id:"x",offset:0,limit:32768},""),"oversize_binary_page_refused");
 const old=env(s=>{s.activeObserver={id:"old",tool:"file_info",futureClosed:true,nextPageOffset:0,eof:false};});old.api.gfValidateRequest(old.m.get(slot),"operation_result",{operation_id:"old",offset:0,limit:8192},"");need(true,"old_info_page8192_retained");
 refuses(()=>old.api.gfValidateRequest(old.m.get(slot),"operation_result",{operation_id:"old",offset:0,limit:16384},""),"old_info_page_not_widened");
 let at=0;for(const [i,raw]of I.requests.entries()){const q=JSON.parse(raw),a=q.operation.arguments;need(q.operation.tool==="binary_read"&&a.host==="rog"&&a.path===I.expected.path&&a.expected_version===I.expected.version&&a.offset===at&&a.limit>0&&a.limit<=65536,"exact_fixed_range_"+i);at+=a.limit;}need(at===167436,"exact_total_no_gap_no_overlap");
 return {schema:"heptabao.collector-report-three-ranges-source-verification.v1",status:"passed",checks,checks_count:checks.length,Native:0,Git:0,Python:0,synthetic_go_not_authorization:true};
}