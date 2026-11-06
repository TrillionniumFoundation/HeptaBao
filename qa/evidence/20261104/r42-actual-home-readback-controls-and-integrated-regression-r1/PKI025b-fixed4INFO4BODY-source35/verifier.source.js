function verifyFixed4ConditionalSource(input,h,d) {
 const rows=[];function ck(name,pass){rows.push({name,pass:!!pass});if(!pass)throw Error(name);}
 const copy=x=>JSON.parse(JSON.stringify(x)),same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 function fn(s,name){const m=new RegExp("^(?:async )?function "+name+"\\(","m").exec(s);if(!m)throw Error("missing:"+name);const t=s.slice(m.index),n=/\n(?:async )?function \w+\(/.exec(t.slice(1));const first=t.split("\n",1)[0];if(first.endsWith("}"))return first;const block=n?t.slice(0,n.index+1):t,end=block.lastIndexOf("\n}");if(end<0)throw Error("end:"+name);return block.slice(0,end+2);}
 for(const[name,before,after,diff,hunks]of[
  ["info",input.infoBefore,input.info.source,input.infoDiff,2],
  ["body",input.bodyBefore,input.bodyTemplate,input.bodyDiff,4]]) {
   const a=d.applyStrictUnified(before,diff),b=d.applyStrictUnified(after,diff,true);
   ck(name+"_strict_whole_both_directions",a.text===after&&b.text===before&&a.hunks===hunks);
 }
 let normalized=input.bodyBefore;
 for(const r of input.bodyReplacements){ck("declared_body_replacement:"+r.label,normalized.split(r.before).length-1===r.count);normalized=normalized.split(r.before).join(r.after);}
 ck("body_only_declared_changes",normalized===input.bodyTemplate);
 let shared=input.bodyBefore;
 for(const[a,b]of input.info.changes)if(a!==b)shared=shared.split(a).join(b);
 const oldNames=[...shared.matchAll(/^(?:async )?function (\w+)\(/gm)].map(m=>m[1]);
 for(const name of oldNames.filter(x=>x!=="gfAuthorizePublishedControlsBodiesOnly"))
  ck("whole_old_body_function:"+name,fn(shared,name)===fn(input.bodyTemplate,name));
 ck("current_info_authorizer_exact_in_body_template",fn(input.info.source,"gfAuthorizePublishedControlsInfoOnly")===fn(input.bodyTemplate,"gfAuthorizePublishedControlsInfoOnly"));
 ck("unknown_body_tables_are_null",input.bodyTemplate.includes("const GF_CONTROLS_BODY_REQUESTS = null;")&&input.bodyTemplate.includes("const GF_CONTROLS_BODY_EXPECTED = null;"));
 ck("four_body_templates_version_null",input.templates.length===4&&input.templates.every((raw,i)=>{const q=JSON.parse(raw),a=q.operation.arguments,e=input.info.expected[i];return q.operation.tool==="binary_read"&&a.host==="rog"&&a.path===e.path&&a.expected_version===null&&a.offset===0&&a.limit===e.bytes&&a.limit<=65536;}));
 ck("bounded_total_90605",input.info.expected.reduce((n,x)=>n+x.bytes,0)===90605);
 ck("receipt_derived_not_observed",input.info.expected[3].publisherFull9===null&&h.gitBlobMeta(input.info.expectedReceipt).sha256===input.info.expected[3].sha256);
 const mem=new Map(),fakeLoad=k=>mem.get(k),fakeStore=(k,v)=>mem.set(k,v),slot=input.slot;
 for(const o of input.closedState.completedObservers)mem.set(slot+":closed_native:"+o.id,input.originalNativeTexts[o.id]);
 mem.set(slot,copy(input.closedState));
 const conditional={authorization:"GO",scope:"build_controls_fixed_four_binary_reads_only",maximum_binary_read_starts:4,
  immutable_page_bytes:16384,maximum_total_body_bytes:90605,deriver:h.gitBlobMeta(input.deriver),
  journal_template:h.gitBlobMeta(input.bodyTemplate),exact_templates:input.templates.map(h.gitBlobMeta)};
 const g={authorization:"GO",scope:"build_controls_fixed_four_file_info_only",original_job:input.closedState.job,
  maximum_file_info_starts:4,binary_read_authorized:false,exact_requests:input.info.requestPins,
  conditional_body_authorization:conditional};
 const goRaw=JSON.stringify(g,null,2)+"\n",goArgs={goRaw,goPin:h.gitBlobMeta(goRaw),goWholeReadback:true};
 const infoApi=new Function("load","store","tools",input.pure+"\n"+input.archive+"\n"+input.info.source+"\nreturn {authorize:gfAuthorizePublishedControlsInfoOnly,validate:gfValidateRequest};")(fakeLoad,fakeStore,{});
 infoApi.authorize(goArgs);const infoState=copy(mem.get(slot));
 ck("info_attach_preserves_original_job_calls_and_observers",infoState.job===input.closedState.job&&same(infoState.calls,input.closedState.calls)&&same(infoState.completedObservers,input.closedState.completedObservers));
 for(let i=0;i<4;i++){const s=copy(infoState);s.publishedInfos=Array(i).fill({synthetic:true});infoApi.validate(s,"operation_start",JSON.parse(input.info.requests[i]),input.info.requests[i]);ck("ordered_info_request:"+i,true);}
 function catches(name,f){let failed=false;try{f();}catch(_){failed=true;}ck(name,failed);}
 catches("info_does_not_admit_unbound_body",()=>infoApi.validate(copy(infoState),"operation_start",JSON.parse(input.templates[0]),input.templates[0]));
 // Entirely synthetic metadata for guard tests. These are NOT current host observations.
 const syntheticState=copy(infoState),nativeTexts={};
 syntheticState.publishedInfoStarted=[true,true,true,true];syntheticState.publishedInfos=[];
 for(let i=0;i<4;i++){
  const e=input.info.expected[i],id=String(i+1).repeat(64),f=e.publisherFull9||["66306","90000001","1000","1000","33152","1",String(e.bytes),"1700000000000000000","1700000000000000000"];
  const version=[f[0],f[1],f[6],f[7],f[8]].join(":"),v={path:e.path,size:e.bytes,sha256:e.sha256,mode:384,version,metadata:{metadata_platform:"linux",mode:384,uid:1000,gid:1000,link_count:1}};
  const raw=JSON.stringify(v,null,2)+"\n",pin=h.gitBlobMeta(raw);nativeTexts[id]=raw;
  syntheticState.completedObservers.push({id,tool:"file_info",nativeText:pin,completedInactive:true});
  syntheticState.publishedInfos.push({index:i,path:e.path,size:e.bytes,sha256:e.sha256,version,full9Strings:f,originalOperation:id,nativeText:pin});
  mem.set(slot+":closed_native:"+id,raw);
 }
 const derive=new Function(input.deriver+"\nreturn derive025bPublishedBodies;")();
 const args={templateSource:input.bodyTemplate,deriverSource:input.deriver,...goArgs,closedState:copy(syntheticState),nativeTexts:copy(nativeTexts),requestTemplates:input.templates};
 const derived=derive(args,h);
 ck("pure_deriver_only_two_literal_tables",derived.sourceChangesOnly.join(",")==="GF_CONTROLS_BODY_REQUESTS,GF_CONTROLS_BODY_EXPECTED"&&derived.source===input.bodyTemplate.replace("const GF_CONTROLS_BODY_REQUESTS = null;","const GF_CONTROLS_BODY_REQUESTS = "+JSON.stringify(derived.requestPins)+";").replace("const GF_CONTROLS_BODY_EXPECTED = null;","const GF_CONTROLS_BODY_EXPECTED = "+JSON.stringify(derived.expected)+";"));
 ck("deriver_preserves_exact_request_shape",derived.requests.every((raw,i)=>{const a=JSON.parse(input.templates[i]),b=JSON.parse(raw);a.operation.arguments.expected_version=syntheticState.publishedInfos[i].version;return same(a,b);}));
 const cases=[
  ["missing_info",x=>x.closedState.publishedInfos.pop()],
  ["pending",x=>x.closedState.pending="synthetic"],
  ["active_future",x=>x.closedState.activeObserver={id:"a".repeat(64)}],
  ["paused",x=>x.closedState.paused=true],
  ["info_not_closed",x=>x.closedState.completedObservers.at(-1).completedInactive=false],
  ["repeated_derivation_after_body_attach",x=>x.closedState.controlsBodyGO={whole:true}],
  ["wrong_template_bytes",x=>x.templateSource+="\n"],
  ["wrong_deriver_bytes",x=>x.deriverSource+="\n"],
  ["wrong_request_template",x=>x.requestTemplates[0]+="\n"],
  ["wrong_native_metadata",x=>x.nativeTexts["1".repeat(64)]+="\n"],
  ["wrong_projection_version",x=>x.closedState.publishedInfos[0].version+="0"],
  ["wrong_projection_full9",x=>x.closedState.publishedInfos[0].full9Strings[5]="2"],
  ["wrong_body_authority",x=>{const q=JSON.parse(x.goRaw);q.conditional_body_authorization.authorization="NO_GO";x.goRaw=JSON.stringify(q,null,2)+"\n";x.goPin=h.gitBlobMeta(x.goRaw);x.closedState.controlsInfoGO={raw:x.goRaw,pin:x.goPin,whole:true};}]
 ];
 for(const[name,edit]of cases)catches("deriver_rejects_"+name,()=>{const x=copy(args);edit(x);derive(x,h);});
 mem.set(slot,copy(syntheticState));
 const unbound=new Function("load","store","tools",input.pure+"\n"+input.archive+"\n"+input.bodyTemplate+"\nreturn gfAuthorizePublishedControlsBodiesOnly;")(fakeLoad,fakeStore,{});
 catches("unbound_template_cannot_authorize_bodies",()=>unbound(goArgs));
 const bodyApi=new Function("load","store","tools",input.pure+"\n"+input.archive+"\n"+derived.source+"\nreturn {authorize:gfAuthorizePublishedControlsBodiesOnly,validate:gfValidateRequest};")(fakeLoad,fakeStore,{});
 mem.set(slot,copy(syntheticState));bodyApi.authorize(goArgs);const bs=copy(mem.get(slot));
 ck("body_same_root_GO_no_new_root_or_controller",bs.controlsBodyGO.pin.blob===infoState.controlsInfoGO.pin.blob&&bs.controlsBodyGO.conditional===true);
 ck("body_attach_preserves_all_original_calls_infos",same(bs.calls,syntheticState.calls)&&same(bs.completedObservers,syntheticState.completedObservers)&&same(bs.publishedInfos,syntheticState.publishedInfos));
 for(let i=0;i<4;i++){const s=copy(bs);s.publishedBodies=Array(i).fill({synthetic:true});bodyApi.validate(s,"operation_start",JSON.parse(derived.requests[i]),derived.requests[i]);ck("ordered_body_request:"+i,true);}
 for(const[name,edit]of[["repeat",s=>s.publishedBodyStarted[0]=true],["pending",s=>s.pending="x"],["active",s=>s.activeObserver={id:"a".repeat(64)}],["pause",s=>s.paused=true],["noGO",s=>delete s.controlsBodyGO]])
  catches("body_refuses_"+name,()=>{const s=copy(bs);edit(s);bodyApi.validate(s,"operation_start",JSON.parse(derived.requests[0]),derived.requests[0]);});
 catches("body_refuses_out_of_order",()=>bodyApi.validate(copy(bs),"operation_start",JSON.parse(derived.requests[1]),derived.requests[1]));
 const drift=JSON.parse(derived.requests[0]);drift.operation.arguments.expected_version+="0";
 catches("body_refuses_version_drift",()=>bodyApi.validate(copy(bs),"operation_start",drift,JSON.stringify(drift,null,2)+"\n"));
 const pageState=copy(bs);pageState.activeObserver={id:"a".repeat(64),tool:"binary_read",futureClosed:true,nextPageOffset:0,eof:false};
 bodyApi.validate(pageState,"operation_result",{operation_id:"a".repeat(64),offset:0,limit:16384},"{}");ck("new_body_16K_pages_preserved",true);
 pageState.activeObserver.tool="file_info";bodyApi.validate(pageState,"operation_result",{operation_id:"a".repeat(64),offset:0,limit:8192},"{}");ck("old_info_8K_pages_preserved",true);
 catches("old_info_refuses_16K",()=>bodyApi.validate(pageState,"operation_result",{operation_id:"a".repeat(64),offset:0,limit:16384},"{}"));
 mem.set(slot,copy(bs));catches("body_attach_once",()=>bodyApi.authorize(goArgs));
 return {schema:"heptabao.025b-fixed4-conditional-source-verification.v1",pass:true,checks:rows.length,rows,
  fakeMetadataOnly:true,currentIndependentMetadataObserved:false,actualBodiesObserved:false,NativeCalls:0,PythonExecuted:false,realSlotUntouched:true};
}
