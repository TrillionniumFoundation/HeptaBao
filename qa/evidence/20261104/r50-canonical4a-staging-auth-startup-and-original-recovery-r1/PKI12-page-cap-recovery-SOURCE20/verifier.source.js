function verifyPkiPageCapR2(files){
 const checks=[];function need(name,v){checks.push({name,pass:!!v});if(!v)throw Error(name);}
 const before=files["journal.before.js"],after=files["journal.after.js"],old=files["paused-state.original.json"],sdkRaw=files["page0.original.sdk.json"];
 const state=JSON.parse(old),key="off271-pki12-r1-report-body-page0",slot="official271_x230_pki12_oracle_gitfirst_r1";
 const expr='gfNeed(b.length<=(a.tool==="binary_read"?GF_ORACLE_REPORT_BODY_PAGE_BYTES:8192) && v.next_offset===q.offset+b.length';
 need("only_one_expression",before.replace("gfNeed(b.length<=8192 && v.next_offset===q.offset+b.length",expr)===after);
 need("one_strict_hunk",(files["journal.forward.diff"].match(/^@@ /gm)||[]).length===1);
 need("forward_whole",applyStrict(before,files["journal.forward.diff"])===after);
 need("reverse_whole",applyStrict(after,files["journal.reverse.diff"])===before);
 need("original_request_unchanged",gitBlobMeta(files["BODY-request.original.json"]).blob==="d358686f2a39455eda39a972043f71d8a3282f5d");
 need("binary_constant_16384",after.includes("const GF_ORACLE_REPORT_BODY_PAGE_BYTES = 16384;"));
 need("prepare_already_selects_same_cap",before.includes('q.limit===(s.activeObserver.tool==="binary_read"?GF_ORACLE_REPORT_BODY_PAGE_BYTES:8192)'));
 need("old_8192_branch_retained",after.includes(expr));
 need("real_paused_original",state.paused===true&&state.pending===key&&state.activeObserver.futureClosed===true);
 need("real_failed_call_retained",state.calls[key].phase==="native_interpretation_refused"&&state.calls[key].interpretationFailure==="Error: exact_original_page_extent");
 const sdk=JSON.parse(sdkRaw),v=JSON.parse(sdk.content[0].text),bytes=unb64(v.data_base64);
 need("actual_original_sdk_whole",gitBlobMeta(sdkRaw).blob==="5ceec5345171ff27f8bd0265c94f0f8e6a0cef7c");
 need("actual_original_page_16384",bytes.length===16384&&v.offset===0&&v.next_offset===16384&&v.total_bytes===55762&&v.eof===false);
 function run(j,tool,n,useActual){
  const clone=JSON.parse(old);clone.paused=false;clone.activeObserver.tool=tool;clone.calls[key].phase="sdk_whole_uninterpreted";
  let raw=sdkRaw;
  if(!useActual){const data=new Array(n).fill(65),nv={...v,data_base64:encodeBase64Bytes(data),next_offset:n};
   raw=JSON.stringify({content:[{type:"text",text:JSON.stringify(nv)}]})+"\n";
   clone.calls[key].sdkPin=gitBlobMeta(raw);
  }
  const m=new Map([[slot,clone],[slot+":original_sdk_raw:"+key,raw]]);
  const accept=new Function("store","load",files["pure_helpers.original.js"]+"\n"+j+"\nreturn gfAcceptArchivedSDK;")((k,x)=>m.set(k,x),k=>m.get(k));
  try{accept(key);return {pass:true,state:m.get(slot)};}catch(e){return {pass:false,error:String(e),state:m.get(slot)};}
 }
 const rejected=run(before,"binary_read",16384,true),accepted=run(after,"binary_read",16384,true);
 need("real_page_old_source_rejects",!rejected.pass&&rejected.error==="Error: exact_original_page_extent");
 need("real_page_new_source_accepts",accepted.pass&&accepted.state.activeObserver.nextPageOffset===16384);
 need("new_binary_16385_still_rejected",!run(after,"binary_read",16385,false).pass);
 need("old_INFO_8192_accepted",run(after,"file_info",8192,false).pass);
 need("old_INFO_8193_rejected",!run(after,"file_info",8193,false).pass);
 need("old_process_8193_rejected",!run(after,"process_read",8193,false).pass);
 const derive=new Function(files["pure_helpers.original.js"]+"\n"+files["cached-recovery.source.js"]+"\nreturn derivePkiCachedPageRecovery;")();
 const d=derive({beforeStateRaw:old,pageSDKRaw:sdkRaw,errorHistoryRaw:files["error-history.original.json"],journalAfter:after,pureHelpers:files["pure_helpers.original.js"]});
 need("exact_proposed_after",d.afterStateRaw===files["after-state.proposed.json"]);
 const next=JSON.parse(d.afterStateRaw),inverse=JSON.parse(d.afterStateRaw);
 for(const k of ["paused","pending","activeObserver"])inverse[k]=state[k];
 need("only_three_state_fields",JSON.stringify(inverse)===JSON.stringify(state));
 need("all13_original_calls_exact",Object.keys(next.calls).length===13&&JSON.stringify(next.calls)===JSON.stringify(state.calls));
 need("original_failed_record_still_refused",next.calls[key].phase==="native_interpretation_refused"&&next.calls[key].interpretationFailure===state.calls[key].interpretationFailure);
 need("outerFailure_exact",JSON.stringify(next.outerFailure)===JSON.stringify(state.outerFailure));
 need("old_completed_observers_exact",JSON.stringify(next.completedObservers)===JSON.stringify(state.completedObservers));
 need("original_SDK_page_reference",next.activeObserver.pages[0].originalSDK.blob===gitBlobMeta(sdkRaw).blob);
 need("known_future_closed_kept",next.activeObserver.futureClosed===true);
 need("cursor_and_digest_no_body_parse",next.activeObserver.nextPageOffset===16384&&next.activeObserver.total===55762&&next.activeObserver.digest===v.result_sha256&&next.oracleReportBody===null);
 need("proposal_is_not_applied",JSON.parse(files["RECOVERY-PROPOSAL.public.json"]).applied===false);
 need("no_native_or_Git_in_recovery",!/\btools\.|archiveFlatPublicTextsOnce\s*\(/.test(files["cached-recovery.source.js"]));
 need("all_five_archive_call_sites_unchanged",after.split("\n").filter(l=>l.includes("archiveFlatPublicTextsOnce(")).join("\n")===before.split("\n").filter(l=>l.includes("archiveFlatPublicTextsOnce(")).join("\n"));
 const proposalRaw=files["RECOVERY-PROPOSAL.public.json"],proposal=JSON.parse(proposalRaw);
 const fakeGO={authorization:"GO",scope:"official271_pki12_cached_page0_acceptance_recovery_only",original_operation:d.originalOperation,original_state:d.beforeState,corrected_journal:gitBlobMeta(after),proposed_after_state:d.afterState};
 const fakeGORaw=JSON.stringify(fakeGO,null,2)+"\n",local=new Map([[slot,JSON.parse(old)],[slot+":outer_failures",JSON.parse(files["error-history.original.json"])]]);
 const writes=[];const apply=new Function("store","load",files["pure_helpers.original.js"]+"\n"+files["cached-recovery.source.js"]+"\nreturn applyPkiCachedPageRecovery;")((k,x)=>{writes.push(k);local.set(k,x);},k=>local.get(k));
 const fakeArgs={goRaw:fakeGORaw,goPin:gitBlobMeta(fakeGORaw),goWholeReadback:true,proofRaw:proposalRaw,proofPin:gitBlobMeta(proposalRaw),proofWholeReadback:true,afterStateRaw:d.afterStateRaw};
 const receipt=apply(fakeArgs);
 need("fake_apply_is_exact_proposed_state",JSON.stringify(local.get(slot),null,2)+"\n"===d.afterStateRaw);
 need("fake_apply_only_slot_and_new_receipt",writes.length===2&&writes[0]===slot&&writes[1]===slot+":cached-page0-cap-recovery-r2");
 need("fake_apply_old_error_history_unchanged",JSON.stringify(local.get(slot+":outer_failures"),null,2)+"\n"===files["error-history.original.json"]);
 need("fake_apply_records_pure_once",receipt.applied===true&&receipt.nativeCalls===0&&receipt.gitCalls===0);
 let twice=false;try{apply(fakeArgs);}catch(e){twice=String(e).includes("original_slot_and_proof_exact_once");}
 need("fake_second_apply_refused",twice&&writes.length===2);
 return {schema:"heptabao.official-pki12.page-cap-pure-checks.r2",pass:true,checkCount:checks.length,checks,actualNativeCalls:0,actualRealStateApply:false,onlyPrivateClones:true};
}
