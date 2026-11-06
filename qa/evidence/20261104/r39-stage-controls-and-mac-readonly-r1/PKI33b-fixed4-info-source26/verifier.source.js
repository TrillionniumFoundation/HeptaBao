function verifyControlsInfo4Source(input,h,d) {
 const rows=[];function ck(name,pass){rows.push({name,pass:!!pass});if(!pass)throw Error(name);}
 const before=input.before,after=input.source;
 const fw=d.applyStrictUnified(before,input.diff),rv=d.applyStrictUnified(after,input.diff,true);
 ck("strict6_hunks_both_whole",fw.text===after&&rv.text===before&&fw.hunks===6);
 let forward=before;for(const[a,b]of input.replacements){ck("unique_declared_replacement:"+rows.length,forward.split(a).length===2);forward=forward.replace(a,b);}
 ck("only_declared_changes",forward===after);
 function fn(s,name){const re=new RegExp("^(?:async )?function "+name+"\\(","m"),m=re.exec(s);if(!m)throw Error("function_missing:"+name);const rest=s.slice(m.index),next=/\n(?:async )?function \w+\(/.exec(rest.slice(1));return next?rest.slice(0,next.index+1):rest;}
 for(const name of ["gfNeed","gfMetaEquals","gfState","gfSave","gfIntegerText","gfInitializeOnlyAfterRootGO","gfAcceptArchivedSDK","gfReconcileSameGitArchiveReadOnly"])
   ck("unchanged_function:"+name,fn(before,name)===fn(after,name));
 ck("four_fixed_requests",input.requests.length===4&&input.requests.every((raw,i)=>h.gitBlobMeta(raw).blob===input.requestPins[i].blob));
 ck("exact_roles_and_content",input.expected.length===4&&input.expected.slice(0,3).every(x=>Array.isArray(x.publisherFull9)&&x.publisherFull9.length===9)&&input.expected[3].publisherFull9===null&&input.expected[3].bytes===1854);
 ck("no_binary_branch",!after.includes('op.tool==="binary_read"'));
 ck("original_8K_16K_1MiB_caps",after.includes("q.limit===8192")&&after.includes("a.limit===16384")&&after.includes("v.total_bytes<=1048576"));
 ck("metadata_once_marker_before_native",after.indexOf("s.publishedInfoStarted[s.publishedInfos.length]=true;")<after.indexOf("sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_start(q)"));
 ck("lossless_metadata_and_no_permission_widening",after.includes('String(32768|v.mode)')&&after.includes("md.uid===1000 && md.gid===1000 && md.link_count===1")&&after.includes('parts.every(x=>/^[0-9]+$/.test(x))')&&after.includes("JSON.stringify(full9)===JSON.stringify(need.publisherFull9)"));
 const mem=new Map(Object.entries(input.fixtureStore)),fakeLoad=k=>mem.get(k),fakeStore=(k,v)=>mem.set(k,v);
 const api=new Function("load","store","tools",input.pure+"\n"+input.archive+"\n"+after+"\nreturn {authorize:gfAuthorizePublishedControlsInfoOnly,validate:gfValidateRequest};")(fakeLoad,fakeStore,{});
 const copy=x=>JSON.parse(JSON.stringify(x)),slot=input.slot;
 const go={authorization:"GO",scope:"build_controls_fixed_four_file_info_only",original_job:input.originalJob,maximum_file_info_starts:4,binary_read_authorized:false,exact_requests:input.requestPins};
 const goRaw=JSON.stringify(go,null,2)+"\n";
 mem.set(slot,copy(input.closedState));
 api.authorize({goRaw,goPin:h.gitBlobMeta(goRaw),goWholeReadback:true});
 const authorized=copy(mem.get(slot));
 ck("selected_authorize_preserves_original_context",authorized.job===input.closedState.job&&authorized.startCalled===true&&authorized.goRaw===input.closedState.goRaw&&JSON.stringify(authorized.calls)===JSON.stringify(input.closedState.calls)&&JSON.stringify(authorized.completedObservers)===JSON.stringify(input.closedState.completedObservers)&&authorized.publishedInfos.length===0);
 for(let i=0;i<4;i++){const s=copy(authorized);s.publishedInfos=Array(i).fill({synthetic:true});api.validate(s,"operation_start",JSON.parse(input.requests[i]),input.requests[i]);ck("selected_fixed_index:"+i,true);}
 function rejects(name,edit,raw=input.requests[0],kind="operation_start"){let caught=false;try{const s=copy(authorized);edit(s);api.validate(s,kind,JSON.parse(raw),raw);}catch(_){caught=true;}ck(name,caught);}
 rejects("reject_no_new_GO",s=>{delete s.controlsInfoGO;});
 rejects("reject_repeat_index0",s=>{s.publishedInfoStarted[0]=true;});
 rejects("reject_out_of_order",s=>{},input.requests[1]);
 rejects("reject_existing_future",s=>{s.activeObserver={id:"f".repeat(64)};});
 rejects("reject_pending_call",s=>{s.pending="synthetic";});
 rejects("reject_paused",s=>{s.paused=true;});
 const wrong=JSON.parse(input.requests[0]);wrong.operation.arguments.path+="-not-allowed";rejects("reject_unlisted_path",s=>{},JSON.stringify(wrong,null,2)+"\n");
 const binary=JSON.parse(input.requests[0]);binary.operation.tool="binary_read";rejects("reject_binary",s=>{},JSON.stringify(binary,null,2)+"\n");
 rejects("reject_second_process_start",s=>{},input.initialRequest,"process_start");
 let duplicate=false;try{mem.set(slot,copy(authorized));api.authorize({goRaw,goPin:h.gitBlobMeta(goRaw),goWholeReadback:true});}catch(_){duplicate=true;}
 ck("reject_second_attach",duplicate);
 const dump=new Function(input.receiptDeriver+"\nreturn dumpPublisherJSON;")(),parsed=h.parseLosslessIntegers(input.stdout);
 ck("lossless_compact_actual_stdout",dump(parsed,null)+"\n"===input.stdout);
 ck("exact_derived_receipt1854",dump(parsed,2)+"\n"===input.expectedReceipt&&h.gitBlobMeta(input.expectedReceipt).sha256===input.expected[3].sha256);
 return {schema:"heptabao.jwt-pki33b-fixed4-info-source-checks.v1",pass:true,checks:rows.length,rows,selectedChecksUsedFakeStore:true,actualSlotUnchanged:true,NativeCalls:0,PythonExecuted:false,bodyAuthorized:false};
}
