function verifyControlsBody4Source(input,h,d) {
 const rows=[];function ck(name,pass){rows.push({name,pass:!!pass});if(!pass)throw Error(name);}
 const before=input.before,after=input.source,fw=d.applyStrictUnified(before,input.diff),rv=d.applyStrictUnified(after,input.diff,true);
 ck("strict8_hunks_both_whole",fw.text===after&&rv.text===before&&fw.hunks===8);
 let x=before;for(const[a,b]of input.replacements){ck("unique_declared_delta:"+rows.length,x.split(a).length===2);x=x.replace(a,b);}ck("only_declared_delta",x===after);
 function fn(s,name){const m=new RegExp("^(?:async )?function "+name+"\\(","m").exec(s);if(!m)throw Error("missing:"+name);const t=s.slice(m.index),n=/\n(?:async )?function \w+\(/.exec(t.slice(1));const first=t.split("\n",1)[0];if(first.endsWith("}"))return first;const block=n?t.slice(0,n.index+1):t,end=block.lastIndexOf("\n}");if(end<0)throw Error("function_end:"+name);return block.slice(0,end+2);}
 for(const name of["gfAuthorizePublishedControlsInfoOnly","gfNeed","gfMetaEquals","gfState","gfSave","gfIntegerText","gfInitializeOnlyAfterRootGO","gfReconcileSameGitArchiveReadOnly"])ck("unchanged_function:"+name,fn(before,name)===fn(after,name));
 ck("exact_four_actual_version_requests",input.requests.length===4&&input.requests.every((raw,i)=>{const q=JSON.parse(raw),e=input.expected[i];return h.gitBlobMeta(raw).blob===input.requestPins[i].blob&&q.operation.tool==="binary_read"&&q.operation.arguments.host==="rog"&&q.operation.arguments.path===e.path&&q.operation.arguments.expected_version===e.version&&q.operation.arguments.offset===0&&q.operation.arguments.limit===e.bytes;}));
 ck("exact_total90605_all_le64K",input.expected.reduce((n,x)=>n+x.bytes,0)===90605&&input.expected.every(x=>x.bytes>0&&x.bytes<=65536));
 ck("four_info_whole_bindings",input.expected.every(e=>input.closedState.publishedInfos[e.index].version===e.version&&h.gitBlobMeta(input.fixtureStore[input.slot+":closed_native:"+e.infoOperation]).blob===e.infoNative.blob));
 ck("old8K_newbody16K_only",after.includes('q.limit===(s.activeObserver.tool==="binary_read"?16384:8192)')&&after.includes('b.length<=(a.tool==="binary_read"?16384:8192)')&&after.includes("v.total_bytes<=1048576"));
 ck("body_once_mark_before_native",after.indexOf("s.publishedBodyStarted[s.publishedBodies.length]=true;")<after.indexOf("sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_start(q)"));
 ck("whole_body_version_eof_sha",after.includes("v.path===need.path && v.version===need.version && v.size===need.bytes")&&after.includes("v.offset===0 && v.next_offset===need.bytes && v.eof===true")&&after.includes("bodyPin.sha256===need.sha256"));
 const mem=new Map(Object.entries(input.fixtureStore)),copy=x=>JSON.parse(JSON.stringify(x)),slot=input.slot;
 const api=new Function("load","store","tools",input.pure+"\n"+input.archive+"\n"+after+"\nreturn {authorize:gfAuthorizePublishedControlsBodiesOnly,validate:gfValidateRequest};")(k=>mem.get(k),(k,v)=>mem.set(k,v),{});
 const go={authorization:"GO",scope:"build_controls_fixed_four_binary_reads_only",original_job:input.closedState.job,maximum_binary_read_starts:4,immutable_page_bytes:16384,maximum_total_body_bytes:90605,exact_requests:input.requestPins};
 const goRaw=JSON.stringify(go,null,2)+"\n",goArgs={goRaw,goPin:h.gitBlobMeta(goRaw),goWholeReadback:true};
 mem.set(slot,copy(input.closedState));api.authorize(goArgs);const a=copy(mem.get(slot));
 ck("selected_attach_preserves_all_prior",a.job===input.closedState.job&&a.goRaw===input.closedState.goRaw&&JSON.stringify(a.calls)===JSON.stringify(input.closedState.calls)&&JSON.stringify(a.completedObservers)===JSON.stringify(input.closedState.completedObservers)&&JSON.stringify(a.publishedInfos)===JSON.stringify(input.closedState.publishedInfos)&&a.publishedBodies.length===0);
 for(let i=0;i<4;i++){const s=copy(a);s.publishedBodies=Array(i).fill({synthetic:true});api.validate(s,"operation_start",JSON.parse(input.requests[i]),input.requests[i]);ck("selected_ordered_body:"+i,true);}
 function reject(name,edit,raw=input.requests[0],kind="operation_start"){let caught=false;try{const s=copy(a);edit(s);api.validate(s,kind,JSON.parse(raw),raw);}catch(_){caught=true;}ck(name,caught);}
 reject("reject_no_body_GO",s=>{delete s.controlsBodyGO;});
 reject("reject_repeated_body",s=>{s.publishedBodyStarted[0]=true;});
 reject("reject_out_of_order",s=>{},input.requests[1]);
 reject("reject_active_future",s=>{s.activeObserver={id:"a".repeat(64)};});
 reject("reject_pending",s=>{s.pending="synthetic";});
 reject("reject_paused",s=>{s.paused=true;});
 const drift=JSON.parse(input.requests[0]);drift.operation.arguments.expected_version+="-drift";reject("reject_version_drift",s=>{},JSON.stringify(drift,null,2)+"\n");
 const extra=JSON.parse(input.requests[0]);extra.operation.arguments.limit++;reject("reject_range_extension",s=>{},JSON.stringify(extra,null,2)+"\n");
 const st=copy(a);st.activeObserver={id:"a".repeat(64),tool:"binary_read",futureClosed:true,nextPageOffset:0,eof:false};
 const page={operation_id:st.activeObserver.id,offset:0,limit:16384};api.validate(st,"operation_result",page,JSON.stringify(page));ck("new_binary16K_page_allowed",true);
 let wrongPage=false;try{api.validate(st,"operation_result",{...page,limit:8192},"{}");}catch(_){wrongPage=true;}ck("new_binary_other_page_refused",wrongPage);
 st.activeObserver.tool="file_info";api.validate(st,"operation_result",{...page,limit:8192},"{}");ck("old_info8K_page_preserved",true);
 wrongPage=false;try{api.validate(st,"operation_result",page,"{}");}catch(_){wrongPage=true;}ck("old_info16K_page_refused",wrongPage);
 let missing=false;try{const z=copy(input.closedState);z.publishedInfos.pop();mem.set(slot,z);api.authorize(goArgs);}catch(_){missing=true;}ck("all_four_infos_required",missing);
 let repeat=false;try{mem.set(slot,copy(a));api.authorize(goArgs);}catch(_){repeat=true;}ck("duplicate_body_authorization_refused",repeat);
 return {schema:"heptabao.jwt-pki33b-controls-body4-source-checks.v1",pass:true,checks:rows.length,rows,privateFakeStoreOnly:true,NativeCalls:0,realSlotUnchanged:true,PythonExecuted:false};
}
