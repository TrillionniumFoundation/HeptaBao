function verify025bControlsPreboundRoot(p,input,author){
 const checks=[];const ck=(name,v)=>{checks.push({name,passed:v===true});if(v!==true)throw Error(name)},r=p.raw,plan=JSON.parse(r["PLAN.public.json"]);
 ck("whole20_prebound_packet",p.audit.whole&&p.audit.files===20&&p.audit.bytes===429198&&p.audit.tree==="f16eb025529a6e78d5ff5fd2d24201aa242ef3ba");
 ck("51_author_checks_previously_independently_reproduced",author.pass&&author.total===51&&author.unchangedDefinitions===25&&author.Runtime===0);
 ck("entire_input_matches_packet",input.carrier===r["payload.prebound.public.json"]&&input.runner===r["runner.prebound.py"]&&input.launcher===r["launcher.prebound.py"]&&input.publisher===r["publisher.prebound.py"]&&input.groups===r["groups.unchanged.public.json"]&&JSON.stringify(input.proposal)===JSON.stringify(plan));
 for(const e of input.edits){
 ck(e.name+"_before_after_exact",e.before===r[e.name+".before.py"]&&e.after===r[e.name+".prebound.py"]&&e.diff===r[e.name+".strict.diff"]);
 let x=e.before;for(const [a,b]of e.replacements){ck(e.name+"_unique_literal_"+a.slice(0,28),x.split(a).length===2);x=x.replace(a,b);}
 ck(e.name+"_only_exact_bound_literals",x===e.after);
 const f=strictApply(e.before,e.diff),b=strictApply(e.after,e.diff,true);ck(e.name+"_strict_forward_reverse",f.text===e.after&&b.text===e.before&&f.hunks===(e.name==="publisher"?1:2)&&b.hunks===f.hunks);
 ck(e.name+"_still_not_ready",e.after.includes("BINDING_READY = False\nassert BINDING_READY,"));
 }
 const groups=JSON.parse(input.groups);
 ck("exact_original149_166_groups",gitBlobMeta(input.groups).blob==="5d563b1c7a1b7070395f6d8a03b512ddb019fae0"&&groups.reduce((n,g)=>n+g.tests.length,0)===166&&new Set(groups.flatMap(g=>g.tests)).size===149&&groups.length===4&&groups.every(g=>g.runtime_seconds===600)&&input.groups.includes("native_jwt_role_operations_keep_the_existing_legacy_acl_contract"));
 ck("fixed_new_commit_roots_old_target_preserved",plan.commit==="025b05a340de841b8161c1120344e86eae30eb97"&&plan.tree==="1d8160c9385f8053b9a683cc1834da0f912e2d37"&&plan.newRoot==="/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r2"&&plan.target==="/home/qian-qi/heptabao-cold-h2-normal-20261105-r1/target-normal-r3"&&plan.oldAttemptAllPathsUntouched);
 ck("original_caps_retained",plan.budgets.outer===12000&&plan.budgets.release===1800&&plan.budgets.sharedCompile===3600&&plan.budgets.listing===30&&plan.budgets.term===5&&plan.budgets.kill===5&&plan.budgets.publisherSeconds===60&&plan.budgets.publisherStdinMax===262144);
 ck("fresh_NB_probe_not_lifetime_lease",plan.freshProbeFromUnchangedLauncher&&plan.probeClosedBeforeRunner&&plan.probeNotHeldForWholeCargo&&plan.rootMustCoordinateCargo&&input.launcher.indexOf("        os.close(lock_fd)")<input.launcher.indexOf("os.execv(argv[0], argv)"));
 ck("no_actual_values_in_prebind",plan.actualStage===null&&plan.actualPublication===null&&plan.actualBuild===null&&!plan.threeReadyFlags&&!input.buildTemplate.dispatchAllowed&&input.buildTemplate.requestTemplate.idempotency_key===null);
 return {schema:"heptabao.root.025b-controls-prebound-source-qualification.r1",passed:true,checkCount:checks.length,checks,packet:p.audit,commit:plan.commit,tree:plan.tree,selectedUniqueTests:149,selectedProfileInstances:166,ready:false,actualBinding:false,NativeCalls:0,normalBuildQualified:false};
}