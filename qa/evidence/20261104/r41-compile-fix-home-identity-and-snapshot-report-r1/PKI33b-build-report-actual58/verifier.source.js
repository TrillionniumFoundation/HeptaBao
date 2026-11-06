function verifyCompleteBody(files,h){
 const {gitBlobMeta,parseLosslessIntegers,unb64,utf8Text}=h,checks=[];
 function ck(n,v){checks.push({name:n,pass:!!v});if(!v)throw Error(n);}
 function pin(n,raw,p){const a=gitBlobMeta(raw);ck(n,a.blob===p.blob&&a.bytes===p.bytes&&a.sha256===p.sha256);}
 const p=JSON.parse(files["PLAN.public.json"]),old=JSON.parse(files["history-STATE.original.public.json"]),fresh=JSON.parse(files["retrieval.STATE.public.json"]),idx=JSON.parse(files["retrieval.CALL-INDEX.public.json"]);
 pin("old_state_exact",files["history-STATE.original.public.json"],p.old_original_slot_state_unchanged);
 ck("old_paused_pending_preserved",old.paused===true&&old.pending==="jwt-pki-33b814c7-build149-report-body-page2-r1"&&old.activeObserver.futureClosed===true&&old.activeObserver.nextPageOffset===32768);
 ck("independent_context_complete",fresh.complete===true&&fresh.pending===null&&fresh.nativeCallInFlight===false&&fresh.originalSlotMutation===false);
 ck("exact_two_retrievals",idx.length===2&&idx.every(x=>x.kind==="operation_result"&&x.original_effect===p.original_operation&&x.called&&x.phase==="accepted"));
 const err=JSON.parse(files["history-call-04-sdk.original.json"]);
 ck("old_timeout_isError_preserved",err.isError===true&&err.content[0].text.includes("MCP request timed out"));
 let bytes=[],offset=0;
 const pairs=[["history-call-02-sdk.original.json","history-call-02-native.original.json"],["history-call-03-sdk.original.json","history-call-03-native.original.json"],["retrieval-0-sdk.original.json","retrieval-0-native.original.json"],["retrieval-1-sdk.original.json","retrieval-1-native.original.json"]];
 for(let i=0;i<pairs.length;i++){
  const [sp,np]=pairs[i],sdk=JSON.parse(files[sp]),v=parseLosslessIntegers(files[np]);
  ck("page_"+i+"_SDK_native",sdk.isError!==true&&sdk.content.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===files[np]);
  ck("page_"+i+"_sameID_immutable",v.operation_id===p.original_operation&&v.immutable_snapshot===true&&v.payload_kind==="native_result");
  const b=unb64(v.data_base64);
  ck("page_"+i+"_contiguous",v.offset===offset&&v.next_offset===offset+b.length&&b.length===Math.min(16384,49765-offset));
  ck("page_"+i+"_total_digest_EOF",v.total_bytes===49765&&v.result_sha256===p.full_original_payload.sha256&&v.eof===(v.next_offset===49765));
  bytes=bytes.concat(b);offset=v.next_offset;
 }
 const raw=utf8Text(bytes);
 ck("four_pages_exact_original_payload",raw===files["payload.original.json"]&&offset===49765);
 pin("whole_payload",raw,p.full_original_payload);
 const payload=parseLosslessIntegers(raw);
 ck("payload_native_success",payload.resultType==="complete"&&payload.isError===false&&payload.content.length===1&&payload.content[0].text===files["native.original.json"]);
 const n=parseLosslessIntegers(files["native.original.json"]),body=utf8Text(unb64(n.data_base64));
 ck("body_exact_native",body===files["result.original.json"]&&n.offset===0&&n.next_offset===36998&&n.size===36998&&n.eof===true);
 pin("whole_body",body,p.decoded_original_body);
 ck("native_version_SHA",n.version==="66306:31364220:36998:1793957208077081949:1793957208077081949"&&n.chunk_sha256===p.decoded_original_body.sha256);
 const r=parseLosslessIntegers(body);
 ck("source_identity",r.source_commit===p.source_commit&&r.source_tree==="b7f276f70e0da1a33306564f385ab7bc12fd44f6");
 ck("known_compilation_failure",r.status==="failed"&&r.failure_type==="AssertionError"&&r.failure==="normal production binary compilation failed"&&r.normal_release_build.exit_code===101&&r.normal_release_build.timed_out===false);
 ck("runtime_tests_not_started",r.runtime_tests_started===false&&r.group_results.length===0&&r.selected_unique_test_total===149&&r.selected_profile_instance_total===166);
 ck("single_direct_compile_child_reaped",r.cleanup.length===1&&r.cleanup[0].label==="normal-release-build"&&r.cleanup[0].direct_child_reaped===true&&r.cleanup[0].exit_code===101&&r.cleanup[0].remaining.length===0&&r.cleanup[0].pid===r.normal_release_build.owned_pgid);
 ck("retained_before_after_unchanged",r.retained_df026_before.status==="unchanged"&&r.retained_df026_after.status==="unchanged");
 ck("finite_archived_calls",p.counts.total_archived_body_chain_calls===7&&p.counts.original_native_admissions===1&&p.counts.original_page_errors===1);
 return {schema:"heptabao.native-jwt-pki-build149.body-whole-verification.r1",status:"PASS",checks:checks.length,results:checks,scope:"immutable original chain and failure summary",new_Runtime_calls:0,product_tests_executed_by_verifier:0,compiler_success:false,flock_observed:false};
}
