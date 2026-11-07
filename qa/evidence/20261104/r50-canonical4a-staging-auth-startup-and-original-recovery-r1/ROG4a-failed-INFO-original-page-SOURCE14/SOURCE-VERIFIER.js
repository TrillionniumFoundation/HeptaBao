function verifyFailedInfoPageSource(input){
 const cases=[],check=(v,n)=>{if(!v)throw new Error(n);cases.push({name:n,pass:true});};
 const rejected=(name,f)=>{let yes=false;try{f();}catch{yes=true;}check(yes,name);};
 const m=new Map([
  ["combined_4a49405b_unknown_report_info_gitfirst_r1",JSON.parse(input.infoStateRaw)],
  ["combined_4a49405b_fresh_build_gitfirst_r1",JSON.parse(input.buildStateRaw)],
  ["combined_4a49405b_unknown_report_info_gitfirst_r1:native_raw:c4a-unknown-build-report-info-r1-s0",input.statusRaw]]);
 let writes=0,toolsUsed=0;
 const a=new Function("load","store","tools",input.pure+"\n"+input.source+
  "\nreturn {old:fipOld,decode:fipDecodeOnePage};")(
  k=>m.get(k),()=>{writes++;},new Proxy({}, {get(){toolsUsed++;throw new Error("no_tools");}}));
 a.old();check(true,"exact_two_original_states_and_actual_failed_pointer");
 const request=JSON.parse(input.requestRaw);
 check(request.operation_id==="0a3d2c5c158da55c07f9db9202ada37d9670254e650c70eff7cfa08bb8d6d7d2"
  &&request.offset===0&&request.limit===8192&&Object.keys(request).length===3,"exact_original_page0_request");
 const payload='{"resultType":"error","error":{"code":-32603,"message":"fixture only"}}';
 const bytes=utf8Bytes(payload),pin=gitBlobMeta(payload);
 const v={operation_id:request.operation_id,offset:0,total_bytes:bytes.length,next_offset:bytes.length,eof:true,
  immutable_snapshot:true,payload_kind:"native_error",format:"opaque_original_error_data",
  result_sha256:pin.sha256,data_base64:encodeBase64Bytes(bytes)};
 const sdk=x=>({content:[{type:"text",text:JSON.stringify(x)}],isError:false});
 check(a.decode(sdk(v)).raw===payload,"opaque_error_payload_whole_not_success_inference");
 const v2={...v,payload_kind:"native_result"};
 check(a.decode(sdk(v2)).raw===payload,"opaque_native_result_kind_also_byte_only");
 for(const [field,value] of [["operation_id","b".repeat(64)],["offset",1],["total_bytes",8193],["next_offset",0],["eof",false],["immutable_snapshot",false],["result_sha256","0".repeat(64)],["payload_kind","bad value"],["format",""]]){
  rejected("reject_"+field,()=>a.decode(sdk({...v,[field]:value})));
 }
 rejected("tool_error_rejected_after_archive",()=>a.decode({...sdk(v),isError:true}));
 rejected("missing_native_text_rejected",()=>a.decode({isError:false,content:[]}));
 const old=m.get("combined_4a49405b_unknown_report_info_gitfirst_r1");old.paused=false;
 rejected("changed_old_info_state_rejected",()=>a.old());
 const methods=[...input.source.matchAll(/tools\.(mcp__codex_apps__heptaruntime_[A-Za-z0-9_]+)/g)].map(x=>x[1]);
 check(methods.length===1&&methods[0].endsWith("_operation_result"),"only_one_fixed_page_native_method");
 check(writes===0&&toolsUsed===0,"pure_checks_no_state_write_no_tool");
 return {schema:"heptabao.failed-info-page0-pure-checks.r1",cases,passed:cases.length,NativeCalls:0,PagesCalls:0,fixtureOnly:true};
}
