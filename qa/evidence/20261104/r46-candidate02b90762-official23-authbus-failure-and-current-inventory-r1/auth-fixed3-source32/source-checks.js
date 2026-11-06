/* Pure R3 rebind check. No journal, SDK, metadata or body function is invoked. */
function verifyR3ReadbackSource(files,pin,apply){
 const checks=[];const ck=(n,v)=>{checks.push({name:n,passed:v===true});if(v!==true)throw Error(n);};
 const j=n=>JSON.parse(files[n]),same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const p=j('PLAN.public.json'),oldp=j('PLAN.before.original.json'),c=j('CONTRACT.public.json');
 const before=files['journal.before.original.js'],after=files['readback-journal.js'],d=files['fixed-readback-deriver.js'];
 ck('reviewed_journal_before_whole',pin(before).blob==='f6c9314e003ee344cebb811d84c30966e664b73c');
 ck('reviewed_pure_deriver_whole_unchanged',pin(d).blob==='07c54395de82130247a0a40b9d32c18ad4c431c6'&&after.includes(d));
 ck('strict_forward_complete',apply(before,files['journal.forward.diff']).raw===after);
 ck('strict_inverse_complete',apply(after,files['journal.reverse.diff']).raw===before);
 const stateRaw=files['reference.original-inert-state.json'],s=JSON.parse(stateRaw),oldRequest=JSON.parse(Object.values(s.calls).find(x=>x.kind==='process_start').requestRaw);
 const newRequestPin=pin(Object.values(s.calls).find(x=>x.kind==='process_start').requestRaw);
 const originalRequestLiteral='const GF_REQUEST = {blob:"2cbe610fa2f2264d1eb137d46421069db38655a5",\n bytes:875394,sha256:"cbb10074d91b254d2205f037e976f4dbbb377c0c4e37a36dd930432bd8a65314"};';
 const newRequestLiteral='const GF_REQUEST = {blob:"'+newRequestPin.blob+'",\n bytes:'+newRequestPin.bytes+',sha256:"'+newRequestPin.sha256+'"};';
 let normalized=after.replace('const GF_SLOT = "'+p.newSlot+'";','const GF_SLOT = "'+oldp.newSlot+'";');
 normalized=normalized.replace('const GF_READBACK_PLAN = '+JSON.stringify(p,null,2)+';','const GF_READBACK_PLAN = '+JSON.stringify(oldp,null,2)+';');
 normalized=normalized.replace(newRequestLiteral,originalRequestLiteral);
 ck('all_functions_whole_unchanged_after_three_binding_blocks',normalized===before);
 ck('new_slot_and_old_context_exact',p.oldSlot==='owner_authbus_current_home_inert_gitfirst_r3'&&p.newSlot==='owner_authbus_home_r3_fixed_readback_gitfirst_r1'&&p.oldSlot!==p.newSlot);
 ck('original_state_pin',same(pin(stateRaw),p.originalState));
 ck('original_stage_closed',s.job===p.originalJob&&s.startCalled===true&&s.pending===null&&s.activeObserver===null&&s.nativeCallInFlight===false&&!s.paused&&s.completedObservers.length===3&&s.completedObservers.every(x=>x.completedInactive===true));
 const a=j('reference.actual-inert-authority.original.json'),r=j('reference.actual-inert-stdout.original.txt'),release=j('reference.actual-inert-release.public.json');
 ck('actual_authority_bound',same(pin(files['reference.actual-inert-authority.original.json']),p.authority)&&a.job_id===p.originalJob&&a.exit_code===0&&a.output_complete===true&&a.output_durable===true&&a.terminal_publication_confirmed===true);
 ck('actual_final_stdout_bound',same(pin(files['reference.actual-inert-stdout.original.txt']),p.finalStdout)&&r.ok===true&&!r.outcomeUnknown&&r.allOwnedCommandsStopped&&r.allOwnedDescriptorsClosed);
 ck('actual_release_bound',same(pin(files['reference.actual-inert-release.public.json']),p.release)&&release.laneReleased===true&&release.activeCallCount===0&&release.activeFutureCount===0);
 const expectedNames=['qa/mac_current_outer_wal_r1.py','candidate-current-manager-wal-r1.public.json','inert-registry-wal-4e808-result.public.json'];
 ck('exact_three_targets',p.targets.length===3&&p.metadataRequests.length===3);
 p.targets.forEach((t,i)=>{
  const row=i===2?r.candidateReceipt:r.files.find(x=>x.name===expectedNames[i]);
  ck('target_'+i+'_actual_full9_size_sha',t.ordinal===i+1&&t.path===r.createdRoot+'/'+expectedNames[i]&&t.bytes===row.bytes&&t.sha256===row.sha256&&same(t.stageFull9,row.identity));
  const raw=files['metadata-'+String(i+1).padStart(2,'0')+'.exact-request.public.json'],q=JSON.parse(raw);
  ck('metadata_'+i+'_one_exact_request',raw===p.metadataRequests[i]&&q.idempotency_key===p.keyPrefix+'info-'+String(i+1).padStart(2,'0')&&same(q.operation,{tool:'file_info',arguments:{host:'mac',path:t.path}})&&same(pin(raw),c.metadataExactRequests[i]));
 });
 ck('outer_expected_whole_source',same(pin(files['reference.outer.frozen.py']),p.targets[0].sourcePin));
 ck('candidate_expected_whole_source',same(pin(files['reference.candidate.frozen.public.json']),p.targets[1].sourcePin));
 ck('receipt_actual_not_source_or_fabricated_version',p.targets[2].sourcePin===null&&p.targets[2].bytes===15237&&p.targets[2].sha256===r.candidateReceiptSha256&&c.receiptBoundary.independentExternalBodyObserved===false&&p.targets.every(x=>!Object.hasOwn(x,'version')&&!Object.hasOwn(x,'expected_version')));
 ck('exact_4_chunks_96654',same(p.targets.map(x=>x.bodyChunks),[[65536,8382],[7499],[15237]])&&p.targets.flatMap(x=>x.bodyChunks).reduce((n,x)=>n+x,0)===96654&&p.bodyTotalBytes===96654);
 ck('original_read_and_observer_caps',p.metadataOperations===3&&p.conditionalBodyOperations===4&&p.bodyChunkMaximum===65536&&p.immutablePageMaximum===8192&&p.immutablePayloadMaximum===1048576&&p.maxStatusesPerOperation===8);
 ck('old_and_new_body_accounting_separate',p.oldReadbackBodyBytesRemainConsumed===96654&&p.newAdditionalBodyBytes===96654&&p.twoReadbackScopesCumulativeBodyBytes===193308&&p.metadataHashCostIsSeparate===true);
 ck('no_new_submission_or_actual_metadata',p.metadataSubmitted===0&&p.bodySubmitted===0&&p.runtimeSubmitted===0&&c.validation.actualNewMetadataObserved===false&&c.validation.actualNewBodyObserved===false);
 ck('pre_finally_receipt_and_final_stdout_distinct',c.receiptBoundary.preFinallyOkFalseMustRemain===true&&c.receiptBoundary.postFinallyStdoutOkTrueIsSeparate===true);
 ck('future_runtime_deriver_frozen_r3',pin(files['reference.runtime-deriver.unchanged.js']).blob==='6c36bdd55a2ea4442c5eec1fbf9b62d990226080'&&c.futureRuntime.processStartRequest===null&&c.futureRuntime.requiresSeparateExactRuntimeGO===true);
 ck('original_runtime_1080_preserved',JSON.parse(j('reference.runtime-binding-input.public.json').originalRuntimeRequestRaw).timeout_seconds===1080&&c.scope.existing900_1080RuntimeBudgetsUnchanged===true);
 ck('root_qualification_pending_not_invented',p.actualRootQualification===null&&p.actualRootQualificationPacket===null&&p.actualRootQualificationPendingThisScopeGO===true&&c.actualInertQualificationRequiredInExactGO===true);
 ck('unreachable_start_guard_retained',after.includes('throw new Error("readback_scope_never_process_start");'));
 ck('no_journal_or_deriver_execution_claim',c.validation.syntheticMetadataFunctionsNotRerun===true&&c.validation.oldComponentsNotRerun===true);
 return {schema:'heptabao.r3-fixed-readback-pure-binding-checks.v1',passed:true,checkCount:checks.length,checks,NativeCalls:0,metadataCalls:0,binaryCalls:0,sourceOnly:true};
}
