function rootFirst5Components(c,peer,original){
 const checks=[];const ck=(name,v)=>{checks.push({name,passed:v===true});if(v!==true)throw Error(name)},r=c.raw;
 ck("whole16_component_packet",c.audit.whole&&c.audit.tree==="7592e1176e1634cf4b8259f53860ec0bc35786e3"&&c.audit.files===16&&c.audit.bytes===254786);
 ck("peer64_independently_reproduced",peer.passed&&peer.checks===64&&peer.NativeCalls===0&&peer.PythonCalls===0);
 for(const [name,beforeBlob]of [["home-control","617a5dff5118482095792e368e128016fe817435"],["manager","72432815fd3f7cd77ba70e8d6461cd4f739fcbc8"],["publisher","fc40ff27b6657aee025162e0db547d501f327c8a"]]){
 const before=r[name+".before.py"],after=r[name+".after.py"],forward=r[name+".forward.diff"],reverse=r[name+".reverse.diff"];
 ck(name+"_whole_exact_predecessor",gitBlobMeta(before).blob===beforeBlob&&before===load("r32_recovered_blob_"+beforeBlob).text);
 ck(name+"_strict3_forward_and_reverse",strictApply(before,forward).text===after&&strictApply(after,forward,true).text===before&&strictApply(after,reverse).text===before&&strictApply(before,forward).hunks===3&&strictApply(after,reverse).hunks===3);
 }
 for(const n of ["manager","publisher"])ck(n+"_same_HomeControl_only",r[n+".before.py"].replace(r["home-control.before.py"],r["home-control.after.py"])===r[n+".after.py"]);
 const a=r["home-control.after.py"],b=r["home-control.before.py"];
 ck("object_first5_with_current_named_full9",a.includes("need(current==named_root and current[:5]==before_root[:5],")&&b.includes("need(current==named_root and current[:6]==self.root_identity[:6],"));
 ck("diagnostic_three_full9_before_guard",a.indexOf("self.last_own_create_root_observation={")<a.indexOf("need(current==named_root")&&["'beforeFull9':list(before_root)","'currentFull9':list(current)","'namedFull9':list(named_root)"].every(x=>a.includes(x)));
 ck("original_preop_and_leaf_guards_retained",a.includes("file_identity(info)==file_identity(named)==self.root_identity")&&a.includes("identity==file_identity(named) and identity[:6]==file_identity(before)[:6]")&&a.includes("before.st_nlink==1"));
 ck("original_failed_bytes_retained",gitBlobMeta(r["original-failure.stdout.public.json"]).blob==="905b50d39c980b7c9c4041825dd815131490f344"&&original.passed);
 ck("not_a_dispatch_bound_candidate",JSON.parse(r["PLAN.public.json"]).status==="COMPONENT_SOURCE_ONLY_NOT_DISPATCHABLE");
 return {schema:"heptabao.root.AuthBus-HOME-own-create-first5-component-qualification.r1",passed:true,checkCount:checks.length,checks,packet:c.audit,helper:gitBlobMeta(a),manager:gitBlobMeta(r["manager.after.py"]),publisher:gitBlobMeta(r["publisher.after.py"]),onlyBehaviorChange:"Own-created directory continuity uses dev/ino/uid/gid/mode; current held-vs-named comparison remains full9. Record before/current/named full9 before the guard.",originalFailurePointValuesRecovered:false,originalEffectUnknownPreserved:true,componentOnly:true,requestBound:false,NativeCalls:0};
}