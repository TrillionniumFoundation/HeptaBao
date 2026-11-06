
function verifyTwoNoneMinimalFix(packet,baseTree,referenceFiles){
 const checks=[];const ck=(n,v)=>{checks.push({name:n,passed:v===true});if(v!==true)throw Error(n)};
 const p=JSON.parse(packet.raw["PROPOSAL.public.json"]),sites=JSON.parse(packet.raw["CALL-SITES.public.json"]);
 const audit=gitTreeAudit(baseTree),leaves=baseTree.tree.filter(x=>x.type!=="tree"),byPath=new Map(leaves.map(x=>[x.path,x]));
 ck("whole_two_file_source_packet",packet.audit.tree==="a9a83d6af101b2042543904b839f83e01805d55b"&&packet.audit.files===10&&packet.audit.bytes===110065&&packet.audit.whole===true);
 ck("original_33b_complete_tree",baseTree.sha===p.baseTree&&baseTree.truncated===false&&audit.root_sha==="b7f276f70e0da1a33306564f385ab7bc12fd44f6"&&audit.leaf_count===3916);
 ck("exact_two_changed_paths",p.baseCommit==="33b814c7034ec853151b1ff13e7529c83f65ea70"&&p.edits.map(x=>x.path).join(",")==="crates/heptabao-server/src/service_native_pki.rs,crates/heptabao-server/src/service_native_ssh.rs");
 const eq=(s,x)=>{const m=gitBlobMeta(s);return ["blob","bytes","sha256"].every(k=>m[k]===x[k])};
 const next=leaves.map(x=>({...x}));
 for(const x of p.edits){
  const name=x.path.split("/").at(-1),before=packet.raw[name+".before"],after=packet.raw[name+".after"],diff=packet.raw[name+".diff"];
  ck(name+"_whole_before_after_and_diff",eq(before,x.before)&&eq(after,x.after)&&eq(diff,x.diff)&&byPath.get(x.path).sha===x.before.blob&&byPath.get(x.path).mode==="100644");
  const marker="                    &mut consumption,\n                )",replacement="                    &mut consumption,\n                    None,\n                )";
  ck(name+"_single_explicit_None_addition",before.split(marker).length===2&&before.replace(marker,replacement)===after&&x.after.bytes===x.before.bytes+26);
  const f=strictApply(before,diff),r=strictApply(after,diff,true);
  ck(name+"_strict_forward_reverse_one_hunk",f.text===after&&r.text===before&&f.hunks===1&&r.hunks===1);
  ck(name+"_exact_non_JWT_method_path_bound",after.includes("Service::dispatch_native_authorized_subrequest(")&&after.includes("&self.method,\n                    &self.path,\n                    &self.body,")&&after.includes("request.origin_peer,\n"+replacement));
  const row=next.find(e=>e.path===x.path);row.sha=x.after.blob;row.size=x.after.bytes;
 }
 const definition=referenceFiles["crates/heptabao-server/src/service.rs"],jwt=referenceFiles["crates/heptabao-server/src/service_native_auth.rs"];
 for(const [path,v]of Object.entries(referenceFiles))ck("unchanged_reference_"+path,byPath.get(path).sha===v.blob&&eq(v.text,v)&&sites.files.some(r=>r.path===path&&r.source.blob===v.blob));
 ck("original_optional_request_local_JWT_slot",definition.text.includes("native_jwt_lifetime: Option<&mut Option<crate::federated_auth::NativeJwtLifetime>>")&&definition.text.includes("if native_jwt_lifetime.as_deref().is_some_and(Option::is_some)"));
 ck("JWT_login_caller_retains_real_slot",jwt.text.includes("Self::dispatch_native_authorized_subrequest(")&&jwt.text.includes(".is_some_and(|owner| owner.is_login())\n                    .then_some(&mut jwt_lifetime),"));
 const rebuilt=rebuildTreeFromLeaves(next),changed=next.filter((x,i)=>x.sha!==leaves[i].sha);
 ck("exact_two_leaf_delta_no_other_changes",changed.length===2&&leaves.length===next.length&&next.length===3916&&next.filter((x,i)=>x.sha===leaves[i].sha).length===3914);
 ck("expected_new_tree_and_byte_sum",rebuilt.root_sha==="1d8160c9385f8053b9a683cc1834da0f912e2d37"&&next.reduce((n,e)=>n+(e.size||0),0)===62297399);
 ck("no_behavior_test_or_compile_claim",p.compile===false&&p.fmt===false&&p.testsRun===0&&p.Native===0&&p.knownCallSites.fullRepositorySearch===false&&p.preserved.includes("ACL/policy behavior"));
 return {report:{schema:"heptabao.root.two-non-JWT-None-compile-fix.source-review.r1",passed:true,checkCount:checks.length,checks,sourcePacket:packet.audit,baseCommit:p.baseCommit,baseTree:p.baseTree,expectedTree:rebuilt.root_sha,trackedFiles:3916,trackedBytes:62297399,changedFiles:2,unchangedFiles:3914,edits:p.edits,sourceScope:"Only two explicit None operands for existing PKI/SSH non-JWT calls; exact prior 13 arguments and all other bytes retained.",priorCompilerFailure:p.evidence,compiled:false,runtimeTestsExecuted:0,requiredUnchangedUniqueTests:149,requiredSelectedInvocations:166,fullReplacement:false,productionCutover:false,legacyCleanup:false},expectedTree:rebuilt,leaves:next};
}