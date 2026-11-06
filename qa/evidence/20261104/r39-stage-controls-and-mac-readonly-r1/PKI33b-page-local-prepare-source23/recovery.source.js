function resumeFinalStageBodyPageAfterLocalPrepareRefusal({goRaw,goPin,goWholeReadback},h,store,load) {
 const SLOT="jwt_pki_33b814c7_rog_source_gitfirst_r1";
 const OP="2a6b394a4c3e5df4436b6fd4627d8fe6065390668129f0d71755efd15a9a4a5e";
 const KEY="jwt-pki-33b814c7-source-result-body0-page1-r1";
 const FAILURE="29702a6bdaa45a33b23389cef0d89b6cce7edb8e";
 function need(x,c){if(!x)throw Error(c);}
 const s=load(SLOT),o=s?.activeObserver,actual=h.gitBlobMeta(goRaw);
 need(goWholeReadback===true&&actual.blob===goPin.blob&&actual.bytes===goPin.bytes&&actual.sha256===goPin.sha256,"separate_whole_root_recovery_GO");
 const g=JSON.parse(goRaw);
 need(g.authorization==="GO"&&g.scope==="original_page_prepare_local_pause_recovery_only"&&g.original_slot===SLOT&&g.operation_id===OP&&g.offset===8192&&g.limit===8192&&g.original_failure_blob===FAILURE,"exact_root_single_recovery_scope");
 need(s?.rootGoWhole===true&&s.job==="1a1afcbafab-fc05-6bb0"&&s.startCalled===true&&s.paused===true&&s.pending===null&&s.nativeCallInFlight===false,"same_original_paused_context_no_call");
 need(s.stageResultBodyGO?.pin?.blob==="2890d06182b076c0198807350e632f06f121e697"&&s.stageResultBodyStarted===true&&goPin.blob!==s.stageResultBodyGO.pin.blob,"body_already_started_new_recovery_GO");
 need(o?.id===OP&&o.tool==="binary_read"&&o.futureClosed===true&&o.eof===false&&o.nextPageOffset===8192&&o.total===37683&&o.pages.length===1&&o.pages[0].offset===0&&o.pages[0].next===8192,"same_original_closed_native_and_exact_next_page");
 need(!Object.prototype.hasOwnProperty.call(s.calls,KEY)&&load("pure_git_once:gfa-"+KEY)===undefined,"failed_prepare_never_armed_or_called");
 need(s.calls["jwt-pki-33b814c7-source-result-body0-page0-r1"]?.phase==="accepted"&&s.calls["jwt-pki-33b814c7-source-result-body0-status0-r1"]?.phase==="accepted","original_status_page_accepted");
 const originalFailure=load("gitfirst-failure-by-blob:"+FAILURE);
 need(typeof originalFailure==="string"&&h.gitBlobMeta(originalFailure).blob===FAILURE&&s.outerFailure?.action==="prepare"&&s.outerFailure?.message==="same_closed_original_operation_next_page","preserve_exact_original_refusal");
 need(s.localBodyPagePrepareRecovery===undefined&&load(SLOT+":local_body_page_prepare_recovery")===undefined,"once_only_local_unpause");
 const priorFailures=JSON.stringify(load(SLOT+":outer_failures")??null),priorOuter=JSON.stringify(s.outerFailure);
 const record={schema:"heptabao.finalstage.body-page-local-prepare-recovery.v1",rootGO:goPin,originalFailure:FAILURE,originalOperation:OP,nextOffset:8192,limit:8192,noNativeCalled:true,noGitMutation:true,noContextInitialization:true,oldFailurePreserved:true};
 s.localBodyPagePrepareRecovery=record;s.paused=false;
 need(JSON.stringify(s.outerFailure)===priorOuter&&JSON.stringify(load(SLOT+":outer_failures")??null)===priorFailures,"failure_not_overwritten");
 store(SLOT+":local_body_page_prepare_recovery",record);store(SLOT,s);
 return record;
}
