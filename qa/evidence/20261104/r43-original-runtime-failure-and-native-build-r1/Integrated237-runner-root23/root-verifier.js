
function verifyIntegrated237RunnerRoot(p,inventory,base,reproduced){
 const i=JSON.parse(p.raw["verifier-input.public.json"]),plan=JSON.parse(p.raw["PLAN.public.json"]);
 const rows=[],ck=(name,ok)=>{rows.push({name,ok});if(!ok)throw Error(name);};
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),pins=raw=>gitBlobMeta(raw);
 ck("whole_original_runner_exact",p.raw["runner.before.py"]===base.raw["runner.ready.py"]&&same(pins(p.raw["runner.before.py"]),plan.original_controls.runner));
 ck("whole_original_launcher_exact",p.raw["launcher.before.py"]===base.raw["launcher.ready.py"]&&same(pins(p.raw["launcher.before.py"]),plan.original_controls.launcher));
 ck("input_objects_are_actual_packet_sources",i.runner.before===p.raw["runner.before.py"]&&i.runner.after===p.raw["runner.after.UNBOUND.py"]&&i.launcher.before===p.raw["launcher.before.py"]&&i.launcher.after===p.raw["launcher.after.UNBOUND.py"]&&i.groupsRaw===p.raw["combined-test-groups.public.json"]);
 const full=JSON.parse(inventory.raw["PROFILE-ENTRIES254.public.json"]);
 ck("root_inventory_ordinals_contiguous",full.length===254&&full.every((x,n)=>x.ordinal===n+1));
 const expectedRows=full.map(({ordinal,...entry})=>{
  if(ordinal>=186&&ordinal<=193)return {...entry,family:ordinal<=189?"completion":"real-service-audit",sourceEvidence:"frozen2379-unformatted-whole-pending-actual-output"};
  return entry;
 });
 ck("input_original254_identity_profile_and_order",same(i.originalInventory.map(x=>({crate:x.crate,libtest_profile:x.libtest_profile,name:x.name})),full.map(x=>({crate:x.crate,libtest_profile:x.libtest_profile,name:x.name}))));
 ck("only_eight_explicit_auxiliary_metadata_differences",same(i.originalInventory,expectedRows));
 ck("full_execution_table_is_exact_input",p.raw["execution-entries254.public.json"]===JSON.stringify(i.originalInventory,null,2)+"\n");
 ck("input_original_C_groups_exact",i.oldGroupsRaw===inventory.raw["original-Cgroups.json"]&&p.raw["original-C-groups.public.json"]===i.oldGroupsRaw);
 ck("canonical_HA_features_whole",i.haCargo===p.raw["canonical-ha-Cargo.toml"]&&i.haCargo===inventory.raw["original-haCargo.toml"]);
 ck("canonical_server_features_whole",p.raw["canonical-server-Cargo.toml"]===inventory.raw["original-serverCargo.toml"]);
 for(const label of ["runner","launcher"]){
  const x=i[label];ck(label+"_strict_forward_reverse",strictApply(x.before,x.forward).text===x.after&&strictApply(x.after,x.reverse).text===x.before);
  ck(label+"_artifact_pin",same(pins(x.after),plan.proposal[label]));
 }
 const spans=[
 ["runner_release",i.runner,"    release = owned('normal-release-build'","    # One original"],
 ["runner_ordinary_compile",i.runner,"    ordinary = owned(","    binaries = {}"],
 ["runner_exact_list_test_loop",i.runner,"        for index, name in enumerate(group['tests']):","    result['binaries_unchanged']"],
 ["launcher_shared_target_fences",i.launcher,"lock_fd = None\ntry:","    argv = [PYTHON"],
 ["launcher_same_PID_argv",i.launcher,"    argv = [PYTHON","    assert time.monotonic() < OUTER_UNTIL, 'original outer deadline expired before exec admission'"]
 ];
 for(const [label,x,a,b]of spans){
  const get=s=>{const start=s.indexOf(a),end=s.indexOf(b,start+a.length);if(start<0||end<=start)throw Error(label+"_nonempty");return s.slice(start,end);};
  ck(label+"_nonempty_original_whole",get(x.before)===get(x.after));
 }
 ck("three_crate_profiles_not_mislabeled",reproduced.profiles["heptabao-server/default"]===220&&reproduced.profiles["heptabao-server/file"]===17&&reproduced.profiles["heptabao-ha-service/ha-native-v6-peer-ingress"]===17);
 ck("no_unqualified_combined_inputs_bound",plan.combined_commit===null&&plan.combined_tree===null&&plan.source_stage_root===null&&plan.runtime_request===null&&plan.native_authorized===false&&plan.ready===false);
 ck("all_time_limits_retained",plan.budgets.outer_seconds===12000&&plan.budgets.normal_release_build_seconds===1800&&plan.budgets.all_compile_checks_shared_seconds===3600&&plan.budgets.each_runtime_family_shared_seconds===600&&plan.budgets.each_exact_listing_max_seconds===30&&plan.budgets.cleanup_term_seconds===5&&plan.budgets.cleanup_kill_seconds===5&&plan.budgets.compile_deadline_reset===false);
 ck("groups_bound_only_to_exact_fixed_content",plan.fixed_input_limit_change.new_bytes_cap===32163&&same(pins(i.groupsRaw),plan.proposal.groups)&&plan.fixed_input_limit_change.generic_read_bound_changed===false);
 return {schema:"heptabao.root.combined237-254-unbound-runner-source-review.v1",pass:true,packet:p.audit.tree,proposal:plan.proposal,authorChecks:85,rootChecks:rows,counts:plan.denominator,profiles:reproduced.profiles,budgets:plan.budgets,readiness:false,combinedCommit:null,combinedTree:null,NativeCalls:0,PythonCompilation:false,RustCompilation:false,actualTests:0,actualLibtestListingObserved:false,requiredNext:["All23 actual formatted file bodies and independently bound49-overlay candidate.","Fresh exact source stage, controls publication and actual receipt binding.","Remeasure final bound launcher/runner under40000 and full carrier under262144.","Exclusive shared-target window and separate exact BUILD GO."],rootReviewHistory:"Two pure root comparisons detected inventory schema differences. The final check verifies contiguous root ordinals, exact254 crate/profile/name order and all source pins, with only the explicitly reviewed eight auxiliary family/sourceEvidence labels mapped. The eight still refer to frozen unformatted test sources awaiting actual formatted output. No candidate or Native state changed."};
}
