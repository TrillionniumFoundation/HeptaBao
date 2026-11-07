/* SOURCE ONLY. Pure cached receipt adoption; no Git or Native tool call.
 * Exact separate root GO is required. Does not interpret the Native SDK.
 * Requires public pure helper gitBlobMeta and gitTreeAudit.
 * Invocation must be in a normal-return outer catch; this function itself
 * catches all failures before they can discard retained V8 evidence. */
function applyFixedPsLexicalR2RetainedPageSDK({goRaw,goPin,goWholeReadback,archiveReceipt}) {
 const prefix="authbus_ps_lexical_probe_r2_";
 const slot="owner_authbus_fixed_setuid_ps_lexical_gitfirst_r2";
 const callKey="fixed-ps-lexical-r2-authority-page-0";
 const originalTree="4665892c2127b6a7665571e4690363098818e914";
 const beforePin={blob:"db7b1ebc3c4c76b039f6cefb2dbe4a7071167438",bytes:82671,sha256:"37772b46962bbe0758fe0d960f7fa19ad441ecaf8b377a539d8495dd52365a97"};
 const sdkPin={blob:"5c67fb5e3a2f72a47e84ae80ee0ab2e8a1a9e4e7",bytes:2064,sha256:"996dd982476eeb22b4aa7377a207b8ede9bac6f67bbc9ded62f73e99bb3cfc1a"};
 const need=(x,k)=>{if(!x)throw new Error(k);};
 const match=(raw,pin)=>{const x=gitBlobMeta(raw);return x.blob===pin.blob&&x.bytes===pin.bytes&&x.sha256===pin.sha256;};
 try {
  need(goWholeReadback===true&&match(goRaw,goPin),"whole_exact_root_adopt_GO");
  const go=JSON.parse(goRaw);
  need(go.authorization==="GO"&&go.scope==="cached_adopt_one_retained_original_page_SDK_no_Native"
    &&go.originalCallKey===callKey&&go.originalExpectedTree===originalTree
    &&go.NativeCalls===0,"exact_cached_adopt_scope");
  need(JSON.stringify(go.beforeState)===JSON.stringify(beforePin)
    &&JSON.stringify(go.originalSDK)===JSON.stringify(sdkPin),"exact_original_state_SDK_GO_binding");
  const beforeRaw=JSON.stringify(load(slot),null,2)+"\n";
  need(match(beforeRaw,beforePin)&&beforeRaw===load(prefix+"archive_failure_state_raw"),
       "live_paused_state_exact_before");
  const s=JSON.parse(beforeRaw),c=s.calls[callKey],a=s.activeObserver;
  need(s.paused===true&&s.nativeCallInFlight===false&&s.startCalled===true
    &&s.pending===callKey&&s.job==="1a1b3af5466-fc05-844c","same_original_paused_context");
  need(c?.called===true&&c.kind==="operation_result"&&c.phase==="sdk_git_archive_unresolved"
    &&c.archiveFailure==="Error: git_create_returned_error_preserved"&&c.sdkArchive===undefined
    &&JSON.stringify(c.sdkPin)===JSON.stringify(sdkPin),"one_already_called_uninterpreted_page");
  need(a?.id==="935c018fc993a7d076532e6a9aab2818da3a18516d24507feb404867f30480df"
    &&a.tool==="process_status"&&a.futureClosed===true&&a.nextPageOffset===0
    &&a.eof===false&&a.pages.length===0&&a.total===null&&a.digest===null,
    "same_completed_inactive_unaccepted_original_page");
  const oldArchive=load("pure_git_once:gfs-"+callKey);
  need(oldArchive?.expectedTree===originalTree&&oldArchive.phase==="create_tree_admitted_once",
    "old_Git_UNKNOWN_record_preserved");
  const sdkRaw=load(slot+":original_sdk_raw:"+callKey);
  need(match(sdkRaw,sdkPin)&&sdkRaw===oldArchive.texts["original.sdk.json"],
    "original_SDK_bytes_still_identical_unparsed");
  need(archiveReceipt?.whole===true&&archiveReceipt.tree!==originalTree
    &&archiveReceipt.tree===go.recoveryEvidenceTree
    &&archiveReceipt.entries.every(x=>x.whole===true),"new_distinct_whole_evidence_packet");
  const entry=archiveReceipt.entries.find(x=>x.path==="Native-page0.original.sdk.json");
  const savedState=archiveReceipt.entries.find(x=>x.path==="paused-state.original.json");
  need(entry&&match(sdkRaw,entry)&&savedState&&match(beforeRaw,savedState),
    "whole_packet_original_SDK_and_state");
  const audit=gitTreeAudit({sha:archiveReceipt.tree,truncated:false,
    tree:archiveReceipt.entries.map(x=>({path:x.path,mode:"100644",type:"blob",sha:x.blob}))});
  need(audit.root_sha===archiveReceipt.tree&&audit.leaf_count===archiveReceipt.entries.length
    &&audit.trees_verified===1,"whole_evidence_flat_Merkle");
  need(!Object.hasOwn(s,"retainedPageSDKArchiveRecovery"),"one_cached_adopt_only");
  // Clone was made from exact immutable original state. No other original field changes.
  c.sdkArchive=JSON.parse(JSON.stringify(archiveReceipt));
  c.phase="sdk_whole_uninterpreted";
  s.paused=false;
  s.retainedPageSDKArchiveRecovery={callKey,beforeState:beforePin,rootGO:goPin,
    recoveryEvidenceTree:archiveReceipt.tree,originalSDK:sdkPin,
    oldExpectedTree:originalTree,oldGitCreateOutcome:"UNKNOWN",
    oldArchiveFailureRetained:true,oldOuterFailureRetained:true,
    originalNativeSDKInterpreted:false,NativeCalls:0};
  const afterRaw=JSON.stringify(s,null,2)+"\n";
  // Single state replacement; old immutable snapshot and Git archive context stay unchanged.
  store(slot,s);
  store(prefix+"cached_adopt_after_raw",afterRaw);
  return {ok:true,action:"cached_receipt_adopt_only",before:beforePin,after:gitBlobMeta(afterRaw),
    originalCallKey:callKey,originalSDKStillUninterpreted:true,NativeCalls:0,
    nextAllowedActionNotExecuted:"separate root-authorized unchanged gfRun accept of original page"};
 } catch(error) {
  const failure={ok:false,action:"cached_receipt_adopt_only",name:error?.name??"Error",
    message:String(error?.message??error),NativeCalls:0,noAutomaticRetry:true};
  store(prefix+"cached_adopt_failure",failure);
  return failure;
 }
}
