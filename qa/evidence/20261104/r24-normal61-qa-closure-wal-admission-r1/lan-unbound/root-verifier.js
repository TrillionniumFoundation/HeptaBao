function verifyRetainedALanUnbound(input,utf8,latin1,sha256,apply){
 const raw=input.raw,a=input.audit,vi=JSON.parse(input.staticRaw),checks=[],ck=(n,v)=>{if(!v)throw Error(n);checks.push(n);},hash=s=>sha256(latin1(utf8(s))),obj=p=>JSON.parse(raw[p]),same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),old="1c66541993662f92cf717154e33717abedb2ea74",now="4e808d0ecb1bcded22870a7ec960dfb2491cf6ec",ot="94ced21a63ff9aaca4538c0d4796efea2150e632",nt="eba5e650bd080b8ad41ea52a2bc68867f541d255";
 const map=new Map(a.records.map(r=>[r.path,r])),prior=new Map(input.prior.records.map(r=>[r.path,r]));
 ck("exact9_before_and_after",Object.keys(vi.before).length===9&&Object.keys(vi.after).length===9&&same(vi.renames,{"native_v6_pocket_source_postrecovery_cold_1c665_r1.py":"native_v6_pocket_source_postrecovery_cold_4e808_r1.py"}));
 const renames=vi.renames;let changed=0,unchanged=0,hunks=0;
 for(const [name,before]of Object.entries(vi.before)){
  const afterName=renames[name]??name,after=vi.after[afterName],br=map.get("before/"+name),ar=map.get("candidate/"+afterName);
  ck(name+".original_prior_member",br.blob===prior.get("candidate/"+name)?.blob);
  ck(name+".actual_static_input_bytes",raw["before/"+name]===before&&raw["candidate/"+afterName]===after&&hash(before)===br.sha256&&hash(after)===ar.sha256);
  if(before===after){unchanged++;ck(name+".whole_unchanged",br.blob===ar.blob);continue;}
  changed++;
  const patch=raw["diffs/"+afterName+".diff"],out=apply(before,patch);
  ck(afterName+".strict_patch_exact",out.text===after);
  hunks+=out.hunks;
  let expected=before.replaceAll(old,now).replaceAll(ot,nt);
  if(afterName==="read_stopped_recovered_cipher_same_root_publication_r1.py"){ck(afterName+".exact1_hunk",out.hunks===1);}
  else if(afterName==="native_v6_pocket_source_postrecovery_cold_4e808_r1.py"){
   expected=expected.replace("0469ffd127f60c60ded67129a0f23868b81e28b6253a6b41584dc28a8afaab27","62be0f577ace2ce3a7754b10d310dfc3f7cc6aa667f566b883c8575d320366b5");
   ck(afterName+".exact2_hunks",out.hunks===2);
  }else if(afterName==="launch_normal_same_root_publication_pocket_postrecovery_cold_r1.py"){
   for(const [x,y]of[
    ["exact 1c665 product","exact 4e808 product"],
    ["continuation-20261105-same-root-publication-normal-r1","continuation-20261105-same-root-publication-normal-r2"],
    ["heptabao-same-root-publication-normal-20261105-r1","heptabao-same-root-publication-normal-20261105-r2"],
    ["native_v6_pocket_source_postrecovery_cold_1c665_r1.py","native_v6_pocket_source_postrecovery_cold_4e808_r1.py"],
    ["6438d429371e7a7e96d56c4c490d07b05df566efd454000452b316beff9195cd","7ee5ee8218b50b7edc3cc010bdd1306f6d03b3301f00811034425b591ad76754"],
    ["0469ffd127f60c60ded67129a0f23868b81e28b6253a6b41584dc28a8afaab27","62be0f577ace2ce3a7754b10d310dfc3f7cc6aa667f566b883c8575d320366b5"],
    ["8b02c5f8f3f0d80286aff0bffcf8a249bb86696b4c25370447e31a953604d33a","93dd6190c7f081305defdbc1c49600974bfa581d943736c77798d51a1c8f54be"],
    ["61ee0154712b2ee6f764e1bf077fe2c107b7f8e05ed3fb0c8651393bdc232c02","3e013354f125cc4c282905beb6347d19f84448a14c304efd576b4d8705e0c2d8"]]){ck(afterName+".original_literal."+x.slice(0,35),expected.includes(x));expected=expected.replaceAll(x,y);}
   ck(afterName+".exact4_hunks",out.hunks===4);
  }else throw Error("unapproved changed file");
  ck(afterName+".only_approved_literal_replacements",expected===after);
 }
 ck("exact3_changed6_unchanged7_hunks",changed===3&&unchanged===6&&hunks===7);
 const b=obj("binding.unbound.public.json"),r=obj("verification/source-checks.stdout.json"),ex=obj("verification/source-checks.executor.json"),strict=obj("verification/strict-exact.public.json");
 ck("actual31_ast_checks_unmodified_inputs",same(b,vi.binding)&&ex.exit_code===0&&ex.output===raw["verification/source-checks.stdout.json"]&&r.all_passed===true&&r.checks.length===31&&r.checks.every(x=>x.passed===true)&&r.unchanged_function_class_count===227&&r.source_modules_executed===0&&r.remote_calls===0&&r.host_or_runtime_qualification===false);
 for(const [name,diff]of Object.entries(r.diffs))ck(name+".actual_python_diff_equals_archived",diff===raw["diffs/"+name+".diff"]);
 ck("all_actual_artifact_pins_none",Object.keys(b.all10_actual_artifact_pins).length===2&&Object.values(b.all10_actual_artifact_pins).reduce((n,v)=>n+Object.keys(v.files).length,0)===10&&Object.values(b.all10_actual_artifact_pins).every(v=>Object.values(v.files).every(x=>x===null)));
 ck("no_inherited_normal61_or_desktop_import",Object.values(b.independent_normal61_required).every(v=>v.normal_result_sha256===null&&v.normal_result_blob===null&&v.authoritative_terminal_blob===null&&v.root_review_blob===null)&&b.desktop_source.actual_complete_import_sha256===null&&b.desktop_source.exists_claimed===false&&b.qualified_normal61_both_platforms===false);
 ck("current_exact_candidate_independent_counts",b.source_commit===now&&b.source_tree===nt&&b.each_platform_original60===60&&b.each_platform_additional_same_root_regression===1&&b.normal_test_denominators_remain_independent===true&&b.prior_candidate_failure.qualification_transferred===false);
 ck("unbound_source_scope_only",b.ready===false&&b.dispatch_authorized===false&&b.actual_stage_or_runtime_submitted===false&&b.normal_qualification_is_external_root_gate===true&&b.artifact_hash_shape_component_is_not_qualification===true);
 ck("original_budgets_and_denominators",same(strict.original_budgets_seconds,{controller:2400,postcold:300,direction_preparation:60,sealed_election:60,http:15,admission:8,supervisor:3000})&&strict.original98_and_additional12_denominators_unchanged===true&&strict.all36_old_fences_unchanged===true&&strict.prepared===false&&strict.live_authorized===false);
 const canonical=obj("canonical/unchanged-qa-members.public.json"),cmap=new Map(input.canonical.tree.map(r=>[r.path,r]));
 ck("five_exact_QA_pin_members",canonical.length===5&&same(canonical.map(r=>r.path),["ha_multihost_live.py","native_v6_ha_multihost_live.py","native_v6_ha_direct_lan_live.py","native_v6_ha_official_history_live.py","native_fixture_recovery.py"].map(x=>"qa/openbao-acceptance/"+x)));
 const launcher=vi.after["launch_normal_same_root_publication_pocket_postrecovery_cold_r1.py"],pinRegion=launcher.split("QA_PINS = {").at(-1).split("\n}")[0];
 for(const p of canonical){
  const leaf=cmap.get(p.path),pr=input.priorLeafMap[p.path],text=input.canonicalBodies[p.blob];
  ck(p.path+".actual_whole_canonical_member",leaf.sha===p.blob&&pr.sha===p.blob&&leaf.size===p.bytes&&leaf.mode===p.mode&&utf8(text).length===p.bytes&&hash(text)===p.declared_sha256&&p.canonical_commit===now);
  ck(p.path+".exact_launcher_pin",pinRegion.includes(p.path.split("/").at(-1))&&pinRegion.includes(p.declared_sha256));
 }
 const initial=new Map(input.initial.records.map(r=>[r.path,r])),modified=a.records.filter(r=>initial.get(r.path)?.blob!==r.blob).map(r=>r.path).sort();
 ck("table_correction_only_three_evidence_files",same(modified,["canonical/unchanged-qa-members.public.json","corrections/qa-member-table.public.json","manifest.public.json"])&&input.initial.records.every(r=>map.has(r.path))&&input.initial.records.filter(r=>r.path.startsWith("candidate/")).every(r=>map.get(r.path)?.blob===r.blob));
 return{schema:"heptabao.root.retained-a-lan-unbound-source.v1",status:"PASS_UNBOUND_SOURCE_ONLY",packet:a.tree,files:a.files,bytes:a.bytes,merkle_trees:a.merkle.trees_verified,check_count:checks.length,checks,source_commit:now,source_tree:nt,source_files:9,changed_sources:3,whole_unchanged_sources:6,exact_hunks:7,unchanged_function_class_bodies:227,actual_source_ast_checks:31,current_canonical_QA_members:5,original_budgets_seconds:strict.original_budgets_seconds,artifact_values_unbound:10,normal61_core_bindings_unbound:2,host_actions:0,actual_LAN_qualified:false,stage_go:false,runtime_go:false,full_replacement:false};
}