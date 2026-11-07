function verifyPrivateListAdapter(input){
 const h=eval(input.pure+"\n"+input.source+";({pack:b4pPack,decode:b4pDecode,project:b4pProject,meta:gitBlobMeta,j:b4pJ,title:B4P_TITLE,key:B4P_KEY,digest:B4P_DIGEST,fp:B4P_FP})");
 const request=JSON.parse(input.originalRequestRaw);
 const target={id:"original-job-fixture-only",host:"rog",execution_mode:"operator",idempotency_key:h.key,request_digest:h.digest,request_fingerprint:h.fp,executable:request.executable,cwd:request.cwd,args:request.args,created_unix_ms:Date.parse("2026-11-06T23:58:00Z"),ssh_target:"DO_NOT_EXPORT_TARGET",env:{SECRET:"DO_NOT_EXPORT_TARGET_ENV"}};
 const other={id:"unrelated-job",host:"rog",idempotency_key:"UNRELATED_KEY",args:["UNRELATED_ARG_SECRET"],env:{PASSWORD:"UNRELATED_ENV_SECRET"},ssh_target:"UNRELATED_SSH",padding:"保密原始资料🧪".repeat(2000)};
 const raw=h.j({content:[{type:"text",text:JSON.stringify({jobs:[other,target],inventory_complete:false,next_cursor:"PRIVATE_CURSOR"})}],isError:false});
 const packed=h.pack(raw),pageId="page_fixture_only_not_created";
 const sharing={structuredContent:{scope:"page_owner",sharing_available:false,owner_only:true}};
 function page(){return {structuredContent:{metadata:{page_id:pageId,drive_scope:"personal"},content:{page_id:pageId,title:h.title,blocks:packed.request.initial_blocks.map(markdown=>({kind:"markdown",markdown}))}}};}
 const checks=[];function ok(name,v){checks.push({name,pass:!!v});if(!v)throw Error(name);}
 function reject(name,f){let caught=false;try{f();}catch{caught=true;}ok(name,caught);}
 ok("codec_multiblock_unicode_whole",h.decode(page(),sharing,pageId,raw,packed).raw===raw&&packed.parts.length>1);
 ok("page_create_omits_parent_space",Object.keys(packed.request).sort().join(",")==="idempotency_key,initial_blocks,title");
 for(const [name,change]of [["owner_false_stops",{owner_only:false}],["owner_unknown_stops",{owner_only:null}],["unknown_sharing_scope_stops",{scope:"unknown"}],["partial_sharing_stops",{complete:false}]]){
  reject(name,()=>h.decode(page(),{structuredContent:{...sharing.structuredContent,...change}},pageId,raw,packed));
 }
 const removed=page();removed.structuredContent.content.blocks.pop();reject("missing_chunk_stops",()=>h.decode(removed,sharing,pageId,raw,packed));
 const dup=page();dup.structuredContent.content.blocks.push(dup.structuredContent.content.blocks.at(-1));reject("duplicate_chunk_stops",()=>h.decode(dup,sharing,pageId,raw,packed));
 const altered=page();const last=altered.structuredContent.content.blocks.at(-1);
 const marker=last.markdown.indexOf("\n",last.markdown.indexOf("HEPTABAO_SDK_PART"))+1;
 last.markdown=last.markdown.slice(0,marker)+(last.markdown[marker]==="A"?"B":"A")+last.markdown.slice(marker+1);
 reject("altered_chunk_stops",()=>h.decode(altered,sharing,pageId,raw,packed));
 reject("wrong_original_bytes_stops",()=>h.decode(page(),sharing,pageId,raw+" ",packed));
 const out=h.project(rawWith([target]),request),outText=JSON.stringify(out);
 ok("safe_target_only_projection",out.match?.id===target.id&&!/UNRELATED_|DO_NOT_EXPORT_|PRIVATE_CURSOR|"args"|"env"|"ssh_target"/.test(outText));
 function rawWith(rows){return h.j({content:[{type:"text",text:JSON.stringify({jobs:rows,inventory_complete:true,next_cursor:null})}],isError:false});}
 reject("typed_digest_mismatch_stops",()=>h.project(rawWith([{...target,request_digest:"0".repeat(64)}]),request));
 reject("duplicate_target_stops",()=>h.project(rawWith([target,target]),request));
 reject("wrong_args_stops",()=>h.project(rawWith([{...target,args:["different"]}]),request));
 ok("no_match_is_not_absence_or_binding",h.project(rawWith([other]),request).match===null);
 reject("pre_go_created_time_stops",()=>h.project(rawWith([{...target,created_unix_ms:0}]),request));
 ok("one_native_tool_only",(input.source.match(/tools\.mcp__codex_apps__heptaruntime/g)||[]).length===1);
 ok("old_context_never_written",!input.source.includes("store(B4P_OLD_SLOT"));
 ok("raw_sdk_private_store_before_page",input.source.indexOf('store(B4P_SLOT+":private-original-native-raw",raw)')<input.source.indexOf("tools.mcp__codex_apps__chatgpt_space_create_page"));
 ok("native_parse_only_separate_post_whole_accept",input.source.includes('s.phase==="private_sdk_whole_uninterpreted"')&&input.source.includes("const projection=b4pProject(raw,request)"));
 ok("original_unknown_input_exact",h.meta(input.originalStateRaw).blob==="2d512764d26256fabaaaf7deb3eae41120d92d3e");
 return {schema:"heptabao.private-list-pure-boundary-checks.r1",cases:checks,passed:checks.length,NativeCalls:0,PagesCalls:0,fixtureOnly:true,actualProviderSchemaNotClaimed:true};
}
