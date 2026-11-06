function verifyFinalStageInfoSource(files,h,diffapi) {
 const checks=[];function need(v,n){checks.push({check:n,pass:!!v});if(!v)throw Error(n);}
 const before=files["journal.before.js"],after=files["journal.after.js"],diff=files["journal.strict.diff"];
 const cfg=JSON.parse(files["BINDINGS.public.json"]);
 need(h.gitBlobMeta(before).blob==="5251b35f820ade2765d2266616b13d1ef1effc48","exact_successful_info_baseline");
 need(h.gitBlobMeta(after).blob===cfg.candidate.blob,"exact_after_source_pin");
 need(cfg.replacements.length===10,"ten_explicit_literal_bindings");
 let forward=before;for(const[a,b]of cfg.replacements){need(forward.split(a).length===2,"once_literal:"+a.slice(0,48));forward=forward.replace(a,b);}
 need(forward===after,"all_other_bytes_identical");
 let reverse=after;for(const[a,b]of cfg.replacements.slice().reverse()){if(reverse.split(b).length!==2)throw Error("reverse_once");reverse=reverse.replace(b,a);}
 need(reverse===before,"inverse_whole_original");
 const f=diffapi.applyStrictUnified(before,diff),r=diffapi.applyStrictUnified(after,diff,true);
 need(f.text===after&&r.text===before&&f.hunks===3&&r.hunks===3,"strict_three_hunk_bidirectional");
 function defs(src){const a=[...src.matchAll(/^(?:async )?function ([A-Za-z0-9_]+)\(/gm)];return a.map((x,i)=>({name:x[1],text:src.slice(x.index,a[i+1]?.index??src.length)}));}
 const bd=defs(before),ad=defs(after);
 need(bd.length===ad.length&&bd.every((x,i)=>x.name===ad[i].name),"complete_same_order_function_inventory");
 const changed=bd.filter((x,i)=>x.text!==ad[i].text).map(x=>x.name);
 need(JSON.stringify(changed)===JSON.stringify(["gfAuthorizeStageResultInfoOnly","gfValidateRequest"]),"only_existing_literal_guard_functions_changed");
 for(let i=0;i<bd.length;i++)if(!changed.includes(bd[i].name))need(bd[i].text===ad[i].text,"whole_function:"+bd[i].name);
 const qb=JSON.parse(files["request.before.json"]),q=JSON.parse(files["request.exact.json"]);
 need(h.gitBlobMeta(files["request.before.json"]).blob==="dbd4063ee0bcadab95c7649ef189e91a99c2402c","exact_old_request_pin");
 const expected=JSON.parse(JSON.stringify(qb));expected.idempotency_key=cfg.requestKey;expected.operation.arguments.path=cfg.resultPath;
 need(JSON.stringify(q)===JSON.stringify(expected),"request_only_path_and_key");
 need(Object.keys(q).sort().join(",")==="idempotency_key,operation"&&q.operation.tool==="file_info"&&q.operation.arguments.host==="rog"&&Object.keys(q.operation.arguments).sort().join(",")==="host,path","single_public_file_info_no_other_arguments");
 need(h.gitBlobMeta(files["request.exact.json"]).blob===cfg.exactRequest.blob&&cfg.exactRequest.bytes===309,"whole_exact_request_pin");
 need(q.idempotency_key.length<=128&&q.operation.arguments.path===cfg.resultPath,"bounded_key_and_owned_path");
 const authority=h.parseLosslessIntegers(files["authority.original.json"]),streams=h.parseLosslessIntegers(files["streams.original.json"]);
 for(let i=0;i<2;i++){const status=JSON.parse(files[i===0?"authority-observer-status.original.json":"streams-observer-status.original.json"]);const native=files[i===0?"authority.original.json":"streams.original.json"];need(status.operation_id===cfg.prerequisites[i].id&&status.tool_name===cfg.prerequisites[i].tool&&status.async_state==="completed"&&status.result_state==="stored_observed"&&status.owned_future_active===false&&status.payload_available===true,"actual_original_closed_status:"+i);need(h.gitBlobMeta(native).blob===cfg.prerequisites[i].nativeText.blob,"exact_original_native:"+i);}
 need(authority.job_id===cfg.originalJob&&authority.exit_code===0&&authority.output_complete===true&&authority.output_durable===true&&authority.terminal_publication_confirmed===true&&!authority.timed_out&&!authority.cancelled,"known_original_zero_full_durable_authority");
 need(streams.job_id===cfg.originalJob&&streams.stdout.eof===true&&streams.stderr.eof===true&&streams.stdout.next_offset===374&&streams.stderr.next_offset===0,"original_complete_stream_extents");
 const summary=JSON.parse(files["stdout.original.txt"]);
 need(streams.stdout.text===files["stdout.original.txt"]&&h.gitBlobMeta(files["stdout.original.txt"]).bytes===374&&streams.stderr.text==="","original_whole_stdout_stderr");
 need(summary.result_path===cfg.resultPath&&summary.source_commit===cfg.commit&&summary.source_tree===cfg.tree&&summary.status==="prepared"&&summary.all_owned_stopped===true&&summary.within_new_stage_deadline===true&&summary.compiler_started===false&&summary.server_started===false,"source_summary_without_compilation");
 need(after.includes('const GF_STAGE_RESULT_MAX_BYTES = 150000;')&&after.includes('q.limit===8192')&&after.includes('v.mode===384')&&after.includes('md.uid===1000 && md.gid===1000 && md.link_count===1')&&after.includes('String(32768|v.mode)')&&after.includes('parts.every(x=>/^[0-9]+$/.test(x))'),"original_metadata_budget_and_lossless_full9");
 need(after.includes('g.scope==="stage_result_file_info_only"')&&after.includes('g.maximum_file_info_starts===1')&&after.includes('g.binary_read_authorized===false')&&after.includes('goPin.blob!==s.goPin.blob')&&after.includes('s.stageResultInfoGO===undefined')&&after.includes('s.stageResultInfoStarted!==true'),"separate_once_info_GO_and_no_body_admission");
 need(ad.find(x=>x.name==="gfInvokePreparedOnce").text===bd.find(x=>x.name==="gfInvokePreparedOnce").text&&ad.find(x=>x.name==="gfCloseOriginalObserver").text===bd.find(x=>x.name==="gfCloseOriginalObserver").text,"original_SDK_and_whole_payload_before_parse_paths_exact");
 need(cfg.bodyAuthorized===false&&cfg.Runtime===false&&cfg.attachOnly===true&&cfg.contextResetAllowed===false,"SOURCE_only_attach_existing_context");
 return {schema:"heptabao.jwt-pki-finalstage-info-source-checks.v1",pass:true,checks:checks.length,rows:checks,hunks:3,literalBindings:10,functions:bd.length,unchangedFunctions:bd.length-changed.length,changedFunctions:changed,NativeCalls:0,candidateExecuted:false};
}
