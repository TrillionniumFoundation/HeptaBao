const R_SLOT="jwt_pki_025b05a3_build_controls_inert_gitfirst_r2";
const R_CALL="jwt-pki-025b05a3-controls-r2-published-info3-status0";
const R_STATE={"blob":"bf02278326d0499eed9acc0ccf43aae7689348ff","bytes":192323,"sha256":"d9546451d179601caa63cabf69dbf17795002ec2d894a2a66713c853426fa735"};
const R_REQUEST={"blob":"7d1b35b0d9380bcc334c25e523088fb9da053233","bytes":89,"sha256":"e20f22d9d70ed5029cc45084dcbf5f6815f08ee8b9cdfe8c680cfa4dcbfa763d"};
const R_TREE="0cba6dbd80682e8418edad3f685e02dd0f3aacb6";
const R_OPERATION="9f565be95050449328b40b589e82270d644f88dc95a192de202c8de1f7e57a5a";

function restore025bReceiptInfoStatusArm({goRaw,goPin,goWholeReadback},h) {
 const need=(v,k)=>{if(!v)throw Error(k);},same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 need(goWholeReadback===true&&same(h.gitBlobMeta(goRaw),goPin),"separate_whole_recovery_GO");
 const g=JSON.parse(goRaw),s=load(R_SLOT),c=s?.calls?.[R_CALL],prefix="pure_git_once:gfa-"+R_CALL;
 need(g.authorization==="GO"&&g.scope==="025b_receipt_info3_status_git_arm_recovery_only"
   &&g.slot===R_SLOT&&g.callKey===R_CALL&&g.originalOperation===R_OPERATION
   &&g.expectedTree===R_TREE&&same(g.originalRequest,R_REQUEST),
   "one_exact_pending_status_recovery_GO");
 need(s&&same(h.gitBlobMeta(JSON.stringify(s,null,2)+"\n"),R_STATE)
   &&s.paused===true&&s.nativeCallInFlight===false&&s.pending===R_CALL
   &&s.activeObserver?.id===R_OPERATION&&s.activeObserver.tool==="file_info"
   &&s.activeObserver.futureClosed===false&&s.activeObserver.nextPageOffset===0
   &&s.activeObserver.pages.length===0&&s.receiptInfoStatusGitArmRecovery===undefined
   &&c?.kind==="operation_status"&&c.phase==="arming"&&c.called===false&&c.armed===undefined
   &&c.archiveFailure==="Error: whole_read_incomplete_no_mutation_retry"
   &&same(h.gitBlobMeta(c.requestRaw),R_REQUEST)
   &&c.requestRaw===JSON.stringify({operation_id:R_OPERATION},null,2)+"\n",
   "unchanged_original_uninvoked_pending_status");
 need(load(R_SLOT+":original_sdk_raw:"+R_CALL)===undefined
   &&load(R_SLOT+":native_raw:"+R_CALL)===undefined,
   "no_original_status_dispatch_or_SDK_exists");
 const original=load(prefix),r=load(prefix+":recovery_complete");
 need(original?.expectedTree===R_TREE&&r?.tree===R_TREE&&r.whole===true
   &&r.recoveryReadOnly===true&&r.mutationRepeated===false&&r.nativeCalled===false
   &&r.count===3&&r.entries.length===3
   &&r.entries.every(e=>e.whole===true&&same(h.gitBlobMeta(original.texts[e.path]),
     {blob:e.blob,bytes:e.bytes,sha256:e.sha256})),"exact_three_original_Git_files_whole");
 const oldFailure=s.outerFailure,oldArchiveFailure=c.archiveFailure;
 c.armed=r;c.phase="armed_whole";
 s.receiptInfoStatusGitArmRecovery={rootGO:goPin,originalState:R_STATE,originalFailure:oldFailure,
   originalArchiveFailure:oldArchiveFailure,recoveredOriginalTree:R_TREE,
   originalCall:R_CALL,originalOperation:R_OPERATION,mutationRepeated:false,NativeCalls:0};
 s.paused=false;store(R_SLOT,s);
 return {restored:true,pending:s.pending,called:c.called,phase:c.phase,originalFailurePreserved:true,
   originalState:R_STATE,originalOperation:R_OPERATION,NativeCalls:0,nextAction:"invoke_same_original_status_once"};
}
