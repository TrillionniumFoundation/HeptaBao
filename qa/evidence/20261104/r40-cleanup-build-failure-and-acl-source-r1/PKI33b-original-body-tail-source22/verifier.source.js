function verifyTailSource(files,helper){
 const {gitBlobMeta,parseLosslessIntegers,unb64}=helper,checks=[];
 function ck(n,v){checks.push({name:n,pass:!!v});if(!v)throw Error(n);}
 function pin(n,raw,p){const a=gitBlobMeta(raw);ck(n,a.blob===p.blob&&a.bytes===p.bytes&&a.sha256===p.sha256);}
 const plan=JSON.parse(files["PLAN.public.json"]),src=files["retrieval.source.js"];
 const old=JSON.parse(files["original-slot.STATE.json"]);
 pin("candidate_whole",src,plan.source);
 pin("original_state_whole",files["original-slot.STATE.json"],plan.helpers.old_slot_state);
 ck("old_paused_pending_and_no_inflight",old.paused===true&&old.pending==="jwt-pki-33b814c7-build149-report-body-page2-r1"&&old.nativeCallInFlight===false);
 const obs=old.activeObserver,expected=plan.original_effect.operation_id;
 ck("old_effect_closed_and_two_original_prefixes",obs.id===expected&&obs.futureClosed===true&&obs.pages.length===2&&obs.nextPageOffset===32768&&obs.eof===false);
 pin("original_closed_status_whole",files["original-status.native.json"],plan.original_effect.status);
 const st=parseLosslessIntegers(files["original-status.native.json"]);
 ck("native_completed_stored_inactive",st.operation_id===expected&&st.tool_name==="binary_read"&&st.async_state==="completed"&&st.result_state==="stored_observed"&&st.owned_future_active===false&&st.payload_available===true);
 pin("old_timeout_whole",files["original-timeout.sdk.json"],plan.old_error.sdk);
 ck("old_timeout_remains_error",JSON.parse(files["original-timeout.sdk.json"]).isError===true);
 for(let i=0;i<2;i++){
  const qraw=files["request-0"+i+".original.json"],q=JSON.parse(qraw);
  pin("exact_request_"+i,qraw,plan.new_retrieval.exact_requests[i]);
  ck("exact_request_fields_"+i,JSON.stringify(Object.keys(q).sort())===JSON.stringify(["limit","offset","operation_id"])&&q.operation_id===expected&&q.offset===[32768,49152][i]&&q.limit===16384);
  const sdkRaw=files["original-prefix-"+i+".sdk.json"],nativeRaw=files["original-prefix-"+i+".native.json"],c=old.calls["jwt-pki-33b814c7-build149-report-body-page"+i+"-r1"];
  pin("prefix_sdk_pin_"+i,sdkRaw,c.sdkPin);pin("prefix_native_pin_"+i,nativeRaw,c.nativePin);
  const sdk=JSON.parse(sdkRaw),v=parseLosslessIntegers(nativeRaw);
  ck("prefix_SDK_native_exact_"+i,sdk.isError!==true&&sdk.content.length===1&&sdk.content[0].text===nativeRaw);
  ck("prefix_offsets_SHA_"+i,v.operation_id===expected&&v.offset===i*16384&&v.next_offset===(i+1)*16384&&v.eof===false&&v.total_bytes===49765&&v.result_sha256===plan.whole_payload.sha256&&unb64(v.data_base64).length===16384);
 }
 ck("two_tool_extents_cover_missing_tail",32768+16384===49152&&49152+613===49765);
 const methods=[...src.matchAll(/tools\.(mcp__[A-Za-z0-9_]+)/g)].map(x=>x[1]);
 ck("single_Native_method_is_result_only",methods.length===1&&methods[0]==="mcp__codex_apps__heptaruntime_mac_controller_operation_result");
 ck("no_oldslot_store",!src.includes("store(RR.originalSlot")&&!src.includes("gfRun("));
 ck("only_two_sequential_indices",src.includes("index===s.nextIndex&&index>=0&&index<2")&&src.includes("s.nextIndex++"));
 ck("SDK_external_before_isError",src.indexOf('c.sdkArchive=await archiveFlatPublicTextsOnce')<src.indexOf('sdk.isError!==true')&&src.includes('c.sdkArchive.whole===true'));
 ck("payload_external_before_parse",src.indexOf('const payloadArchive=await archiveFlatPublicTextsOnce')<src.indexOf('const p=parseLosslessIntegers(raw)'));
 ck("no_report_semantics_parsing",!src.includes("JSON.parse(body)")&&!src.includes("parseLosslessIntegers(body)")&&src.includes("semanticQualification:false"));
 ck("failure_pauses_only_newcontext",src.includes('const s=load(RR.slot);if(s){s.paused=true')&&src.includes('automaticRetry:false,newAdmissionAllowed:false'));
 new Function("tools","store","load",files["pure.original.js"]+"\n"+files["archive.original.js"]+"\n"+src+"\nreturn rrRun;");
 ck("JavaScript_function_constructs_without_invoking",true);
 ck("original_effect_is_not_reissued",plan.new_retrieval.operation_start===0&&plan.new_retrieval.process_start===0&&plan.new_retrieval.operation_status===0);
 ck("public_tool_contract_never_dispatches",files["operation-result.public-contract.txt"].includes("This API never dispatches")&&files["operation-result.public-contract.txt"].includes("independent byte offset"));
 return {schema:"heptabao.immutable-tail-source.offline-checks.r1",status:"PASS",checks:checks.length,results:checks,Native:0,module_invoked:false,original_slot_mutated:false};
}
