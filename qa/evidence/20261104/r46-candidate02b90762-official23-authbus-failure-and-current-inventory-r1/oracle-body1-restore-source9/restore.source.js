function restoreOnlyOriginalOracleR2Page0Arm({stateRaw,reconciliationRaw,goRaw,goPin,goWholeReadback}) {
 const fail=code=>{throw new Error(code);};
 const exact=(raw,pin)=>{const q=gitBlobMeta(raw);return q.blob===pin.blob&&q.bytes===pin.bytes&&q.sha256===pin.sha256;};
 if(!goWholeReadback||!exact(goRaw,goPin))fail("exact_new_root_recovery_GO");
 const g=JSON.parse(goRaw),callKey="official271-x230-acl23-r2-body01-page000000",id="5433a8b98b3015f338e147954b4d9910b5657f85730a4bc09de3a79129a88155";
 if(g.authorization!=="GO"||g.scope!=="official271_r2_body1_page0_git_arm_restore_only"
   ||g.original_operation!==id||g.pending_call!==callKey
   ||g.expected_tree!=="2e7e1a66eec4e42a14ea0c350328f4f263842c20"
   ||g.original_request!=="c466e0e87676208da9a08ad7630283696ec42cc8")fail("one_original_page_arm_scope");
 if(!exact(stateRaw,{blob:"551c671b614f169d938ea734a963c0a996258dbf",bytes:346725,sha256:"fc5eddffa1ec12f067afbf5016d66924e23ed188b780618309fc554130e0a9fa"}))fail("exact_original_paused_state");
 if(!exact(reconciliationRaw,{blob:"e58b4ef7bed4b32ed196726e19fdcff0801d2e53",bytes:1007,sha256:"46a0ce5d5df69a0ae9d5e0b08607050b0f9f9ae1aeaa68bb87f10d82778a8475"}))fail("exact_completed_same_Git_readback");
 const s=JSON.parse(stateRaw),r=JSON.parse(reconciliationRaw),c=s.calls[callKey],o=s.activeObserver;
 if(!r.ok||r.action!=="git_readonly_reconcile"||r.value.whole!==true
   ||r.value.recoveryReadOnly!==true||r.value.mutationRepeated!==false||r.value.nativeCalled!==false
   ||r.value.tree!==g.expected_tree||r.value.count!==3)fail("known_original_three_leaf_archive");
 if(s.job!=="1a1b1b4fbfa-fc05-7a60"||s.paused!==true||s.pending!==callKey
   ||s.nativeCallInFlight!==false||c?.phase!=="arming"||c.called!==false
   ||c.kind!=="operation_result"||c.armed!==undefined||c.sdkPin!==undefined
   ||c.requestPin.blob!==g.original_request||o?.id!==id||o.futureClosed!==true
   ||o.nextPageOffset!==0||o.pages.length!==0||o.eof!==false
   ||s.outerFailure?.message!=="whole_read_incomplete_no_mutation_retry"
   ||c.archiveFailure!=="Error: whole_read_incomplete_no_mutation_retry")fail("Native_page_never_entered_exact_boundary");
 const q=JSON.parse(c.requestRaw);
 if(q.operation_id!==id||q.offset!==0||q.limit!==16384)fail("original_page_request_unchanged");
 const audit=gitTreeAudit({sha:g.expected_tree,truncated:false,tree:r.value.entries.map(e=>({path:e.path,type:"blob",mode:"100644",sha:e.blob}))});
 if(audit.leaf_count!==3||r.value.entries.some(e=>e.whole!==true))fail("same_original_3_leaf_Merkle");
 c.armed=r.value;
 c.phase="armed_whole";
 s.paused=false;
 return {state:s,stateRaw:JSON.stringify(s,null,2)+"\n",changedFields:["calls."+callKey+".armed","calls."+callKey+".phase","paused"],NativeCalls:0,GitCalls:0,pendingStillOriginal:true,errorHistoryPreserved:true};
}
