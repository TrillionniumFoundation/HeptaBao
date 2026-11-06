function restoreC576OriginalStatusSDKArchive({goRaw,goPin,goWhole,newArchive}) {
 const slot="combined_5767739c_fresh_build_gitfirst_r1",callKey="c576-fresh-build-r1-streams0-status0";
 const need=(v,m)=>{if(!v)throw new Error(m)};
 need(goWhole===true && JSON.stringify(gitBlobMeta(goRaw))===JSON.stringify(goPin),"whole_exact_recovery_GO");
 const g=JSON.parse(goRaw);
 need(g.authorization==="GO" && g.scope==="c576_status0_original_sdk_archive_recovery" && g.slot===slot && g.callKey===callKey && g.originalSDK?.blob==="b2459cf511bae4559b0941fb079048009c308d68" && g.newArchiveTree===newArchive?.tree,"GO_exact_original_call_and_new_archive");
 const s=load(slot),before=JSON.stringify(s,null,2)+"\n";
 need(gitBlobMeta(before).blob==="6f71ba0559184bf8f0e2e70d620ef8cd039d1e7c","exact_frozen_before_state");
 const c=s.calls[callKey];
 need(s.paused===true && s.nativeCallInFlight===false && s.pending===callKey && c.called===true && c.phase==="sdk_git_archive_unresolved","exact_original_returned_boundary");
 const raw=load(slot+":original_sdk_raw:"+callKey);
 need(gitBlobMeta(raw).blob==="b2459cf511bae4559b0941fb079048009c308d68","exact_returned_original_SDK");
 need(newArchive?.whole===true && newArchive.entries.some(x=>x.path==="ORIGINAL-NATIVE-STATUS-SDK.json" && x.blob==="b2459cf511bae4559b0941fb079048009c308d68" && x.whole===true),"original_SDK_whole_in_new_evidence_archive");
 c.sdkArchive=newArchive;c.phase="sdk_whole_uninterpreted";s.paused=false;
 s.exactOriginalStatusSDKArchiveRecovery={go:goPin,newArchive:newArchive.tree,before:{"blob":"6f71ba0559184bf8f0e2e70d620ef8cd039d1e7c","bytes":179536,"sha256":"f4b55506a075d40ef0ed67fd3f03520a2c34c6f8757c2de5e3d1820914ac34a1"},oldCreateExpectedTree:"5ecb3221ebad396fb9b7af067e7549d3294b2225",oldPhase:"sdk_git_archive_unresolved",oldArchiveFailure:c.archiveFailure,oldOuterFailure:s.outerFailure,oldUnknownRetained:true,originalNativeCallNotRepeated:true};
 store(slot,s);
 return {before:{"blob":"6f71ba0559184bf8f0e2e70d620ef8cd039d1e7c","bytes":179536,"sha256":"f4b55506a075d40ef0ed67fd3f03520a2c34c6f8757c2de5e3d1820914ac34a1"},after:gitBlobMeta(JSON.stringify(s,null,2)+"\n"),originalSDK:c.sdkPin,readyForOriginalAcceptOnly:true,NativeCalls:0};
}
