const PKI_PAGE_RECOVERY_BINDING = {
  "slot": "official271_x230_pki12_oracle_gitfirst_r1",
  "callKey": "off271-pki12-r1-report-body-page0",
  "operation": "decec225ffa9d077603bcf55dea04d12f8f80273cf1d5547d5582fb54c217706",
  "recoveryKey": "official271_x230_pki12_oracle_gitfirst_r1:cached-page0-cap-recovery-r2",
  "beforeState": {
    "blob": "e48bb16c1d18b72506546378eac09aad7996cd63",
    "bytes": 246355,
    "sha256": "c5bc674d2f31e94aa018f97a0896db3e7382fb1cd19a50be06d29fa767ded5b4"
  },
  "pageSDK": {
    "blob": "5ceec5345171ff27f8bd0265c94f0f8e6a0cef7c",
    "bytes": 22705,
    "sha256": "d613452f7e603c59f49e059bbb987b53bc1aab73549cf7df464974f59912c309"
  },
  "errorHistory": {
    "blob": "aa0fce14552b552107d94619a154ee4fb229e66e",
    "bytes": 304,
    "sha256": "22d97a34eed7cbd16ce7e58fcadc05d0fc0e1aa4cc608b11efa81a122071fc50"
  },
  "beforeJournal": {
    "blob": "f83797d03a41092340ba39074b155594464d8bf2",
    "bytes": 28846,
    "sha256": "0b4f9cc8c62104d96cbc4c021c4e500074b45b8fad24609874f851bd19b7297c"
  },
  "afterJournal": {
    "blob": "86edcf2a0d2d5206025a6a702883e6b645e2cc87",
    "bytes": 28904,
    "sha256": "0940f9d7b0c206864962e77cf40106e7b4d3faf2ec0ad225b472840e214fc107"
  }
};
function pkiRecoveryNeed(v,c){if(!v)throw Error(c);}
function pkiRecoverySame(raw,pin){return JSON.stringify(gitBlobMeta(raw))===JSON.stringify(pin);}
function derivePkiCachedPageRecovery({beforeStateRaw,pageSDKRaw,errorHistoryRaw,journalAfter,pureHelpers}) {
 const b=PKI_PAGE_RECOVERY_BINDING;
 pkiRecoveryNeed(pkiRecoverySame(beforeStateRaw,b.beforeState)&&pkiRecoverySame(pageSDKRaw,b.pageSDK)
  &&pkiRecoverySame(errorHistoryRaw,b.errorHistory)&&pkiRecoverySame(journalAfter,b.afterJournal),"exact_recovery_inputs");
 const before=JSON.parse(beforeStateRaw),clone=JSON.parse(beforeStateRaw),c=before.calls[b.callKey];
 pkiRecoveryNeed(before.paused===true&&before.pending===b.callKey&&!before.nativeCallInFlight
  &&before.activeObserver.id===b.operation&&before.activeObserver.futureClosed===true
  &&before.activeObserver.nextPageOffset===0&&before.activeObserver.pages.length===0
  &&c.called===true&&c.phase==="native_interpretation_refused"
  &&c.interpretationFailure==="Error: exact_original_page_extent"
  &&c.sdkArchive.whole===true&&JSON.stringify(c.sdkPin)===JSON.stringify(b.pageSDK)
  &&Object.keys(before.calls).length===13,"only_this_cached_page_failure");
 const local=new Map([[b.slot,clone],[b.slot+":original_sdk_raw:"+b.callKey,pageSDKRaw]]);
 clone.paused=false;clone.calls[b.callKey].phase="sdk_whole_uninterpreted";
 const localStore=(k,v)=>{pkiRecoveryNeed(k===b.slot||k===b.slot+":native_raw:"+b.callKey,"private_clone_writes_only");local.set(k,v);};
 const localLoad=k=>{pkiRecoveryNeed(local.has(k),"private_clone_known_read_only");return local.get(k);};
 const accept=new Function("store","load",pureHelpers+"\n"+journalAfter+"\nreturn gfAcceptArchivedSDK;")(localStore,localLoad);
 const accepted=accept(b.callKey),next=local.get(b.slot);
 pkiRecoveryNeed(accepted.operation===b.operation&&next.activeObserver.nextPageOffset===16384
  &&next.activeObserver.pages.length===1&&next.activeObserver.total===55762
  &&next.activeObserver.digest==="dfad7e61e08ada43dc512c7a5014db31584d41babd5839b6271ab59516f06502"
  &&next.activeObserver.eof===false&&!next.paused&&next.pending===null,"actual_original_page0_admitted");
 // Original failed call, failure string, budgets and provenance remain byte-value identical.
 next.calls=before.calls;
 const inverse=JSON.parse(JSON.stringify(next));
 for(const k of ["paused","pending","activeObserver"])inverse[k]=before[k];
 pkiRecoveryNeed(JSON.stringify(inverse)===JSON.stringify(before),"only_three_state_fields_change");
 const afterStateRaw=JSON.stringify(next,null,2)+"\n";
 return {afterStateRaw,afterState:gitBlobMeta(afterStateRaw),beforeState:b.beforeState,
  pageSDK:b.pageSDK,journalAfter:b.afterJournal,errorHistory:b.errorHistory,
  originalOperation:b.operation,acceptedCursor:16384,failedCallRetained:true,
  changedFields:["paused","pending","activeObserver"],nativeCalls:0,gitCalls:0};
}
function applyPkiCachedPageRecovery({goRaw,goPin,goWholeReadback,proofRaw,proofPin,proofWholeReadback,afterStateRaw}) {
 const b=PKI_PAGE_RECOVERY_BINDING;
 pkiRecoveryNeed(goWholeReadback===true&&pkiRecoverySame(goRaw,goPin)
  &&proofWholeReadback===true&&pkiRecoverySame(proofRaw,proofPin),"whole_GO_and_proof_before_pure_apply");
 const g=JSON.parse(goRaw),proof=JSON.parse(proofRaw),now=load(b.slot);
 pkiRecoveryNeed(g.authorization==="GO"&&g.scope==="official271_pki12_cached_page0_acceptance_recovery_only"
  &&g.original_operation===b.operation&&JSON.stringify(g.original_state)===JSON.stringify(b.beforeState)
  &&JSON.stringify(g.corrected_journal)===JSON.stringify(b.afterJournal)
  &&JSON.stringify(g.proposed_after_state)===JSON.stringify(proof.afterState),"exact_new_recovery_GO");
 pkiRecoveryNeed(load(b.recoveryKey)===undefined&&pkiRecoverySame(JSON.stringify(now,null,2)+"\n",b.beforeState)
  &&pkiRecoverySame(JSON.stringify(load(b.slot+":outer_failures"),null,2)+"\n",b.errorHistory)
  &&pkiRecoverySame(afterStateRaw,proof.afterState)
  &&JSON.stringify(proof.beforeState)===JSON.stringify(b.beforeState)
  &&JSON.stringify(proof.pageSDK)===JSON.stringify(b.pageSDK)
  &&proof.nativeCalls===0&&proof.gitCalls===0,"original_slot_and_proof_exact_once");
 const next=JSON.parse(afterStateRaw),inverse=JSON.parse(afterStateRaw);
 for(const k of ["paused","pending","activeObserver"])inverse[k]=now[k];
 pkiRecoveryNeed(JSON.stringify(inverse)===JSON.stringify(now)&&!next.paused&&next.pending===null
  &&next.activeObserver.id===b.operation&&next.activeObserver.futureClosed===true
  &&next.activeObserver.nextPageOffset===16384&&next.activeObserver.pages.length===1,
  "bounded_three_field_apply");
 store(b.slot,next);
 const receipt={schema:"heptabao.official-pki12.cached-page0-recovery.applied.r2",
  applied:true,phase:"applied_once",rootGo:goPin,proof:proofPin,beforeState:b.beforeState,
  afterState:proof.afterState,originalOperation:b.operation,failedCallRetained:true,
  errorHistory:b.errorHistory,changedFields:["paused","pending","activeObserver"],nativeCalls:0,gitCalls:0};
 store(b.recoveryKey,receipt);return receipt;
}
