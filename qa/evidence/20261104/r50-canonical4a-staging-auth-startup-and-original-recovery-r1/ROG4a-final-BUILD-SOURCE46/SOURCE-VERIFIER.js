function verifyNext4aFreshBuildSource(t) {
 const checks=[];function ck(name,pass){checks.push({name,pass:pass===true});if(pass!==true)throw new Error(name);}
 const plan=JSON.parse(t["PLAN.public.json"]),q=JSON.parse(t["request.exact.json"]);
 const meta=(raw,pin)=>{const x=gitBlobMeta(raw);return x.blob===pin.blob&&x.bytes===pin.bytes&&x.sha256===pin.sha256;};
 function defs(src){const lines=src.split("\n"),out={};for(let i=0;i<lines.length;i++){const m=/^def ([A-Za-z_][A-Za-z0-9_]*)\(/.exec(lines[i]);if(!m)continue;let j=i+1;while(j<lines.length&&(/^\s/.test(lines[j])||lines[j]===""))j++;out[m[1]]=lines.slice(i,j).join("\n").replace(/\n+$/,"")+"\n";}return out;}
 for(const name of ["runner","launcher","publisher","journal"]){
  const ext=name==="journal"?"js":"py",before=t[name+".before."+ext],after=t[name+".after."+ext],edits=JSON.parse(t[name+".edits.public.json"]);
  ck(name+"_before_pin",meta(before,plan.before[name]));ck(name+"_after_pin",meta(after,plan[name]));
  ck(name+"_forward_strict",snapshotApply(before,t[name+".forward.diff"])===after);
  ck(name+"_reverse_strict",snapshotApply(after,t[name+".forward.diff"],true)===before);
  ck(name+"_reverse_file_strict",snapshotApply(after,t[name+".reverse.diff"])===before);
  let reconstructed=before;
  for(const e of edits){ck(name+"_declared_count_"+e.name,reconstructed.split(e.before).length-1===(e.count??1));reconstructed=reconstructed.split(e.before).join(e.after);}
  ck(name+"_only_declared_edits",reconstructed===after);
  if(name!=="journal"){const a=defs(before),b=defs(after);ck(name+"_same_functions",JSON.stringify(Object.keys(a))===JSON.stringify(Object.keys(b)));for(const n of Object.keys(a)){if(name==="runner"&&n==="fresh_target_pin"){ck(name+"_function_"+n,a[n].replace("/home/qian-qi/hb-5767739c-controls-20261106-r1/cargo-target-r1","/home/qian-qi/hb-4a49405b-controls-20261106-r1/cargo-target-r1")===b[n]);}else ck(name+"_function_"+n,a[n]===b[n]);}}
 }
 const l=t["launcher.after.py"],r=t["runner.after.py"],pu=t["publisher.after.py"],j=t["journal.after.js"];
 ck("control_caps_unchanged",gitBlobMeta(l).bytes<=40000&&gitBlobMeta(r).bytes<=40000&&plan.budgets.launcherBytes===40000&&plan.budgets.runnerBytes===40000);
 ck("groups_specific_bound",l.includes("args.groups_sha256, 35287)")&&l.includes("_, runner_pin = read_bound(runner, args.runner_sha256, 40000)"));
 const groups=JSON.parse(t["jwt-test-groups.public.json"]),old=JSON.parse(t["groups.before.json"]),profile={file:0,default:0,"ha-native-v6-peer-ingress":0},names=new Set();
 ck("groups_whole",meta(t["jwt-test-groups.public.json"],plan.groups)&&plan.groups.blob==="0a3d746de42bfc31d3072cee1073f3908fc5811c"&&plan.groups.bytes===35287);
 for(const g of groups){ck("family_"+g.label,g.runtime_seconds===600&&Object.keys(g).sort().join(",")==="label,libtest_profile,runtime_seconds,tests"&&g.tests.length===new Set(g.tests).size);profile[g.libtest_profile]+=g.tests.length;for(const name of g.tests)names.add((g.libtest_profile==="ha-native-v6-peer-ingress"?"heptabao-ha-service":"heptabao-server")+"::"+name);}
 ck("exact_counts",groups.length===18&&names.size===252&&profile.file===28&&profile.default===235&&profile["ha-native-v6-peer-ingress"]===17&&groups.reduce((n,g)=>n+g.tests.length,0)===280);
 ck("two_profiles_same_names",JSON.stringify(groups[0].tests)===JSON.stringify(groups[1].tests));
 ck("rest16groups_byte_values_same",JSON.stringify(groups.slice(2))===JSON.stringify(old.slice(2)));
 ck("all_normal61",groups.slice(9).reduce((n,g)=>n+g.tests.length,0)===61&&JSON.stringify(groups.slice(9))===JSON.stringify(old.slice(9)));
 ck("snapshot27_unchanged",groups.slice(4,9).reduce((n,g)=>n+g.tests.length,0)===27&&JSON.stringify(groups.slice(4,9))===JSON.stringify(old.slice(4,9)));
 ck("first4_164_192",groups.slice(0,4).reduce((n,g)=>n+g.tests.length,0)===192&&new Set(groups.slice(0,4).flatMap(g=>g.tests)).size===164);
 ck("all_groups_whole_unchanged",t["jwt-test-groups.public.json"]===t["groups.before.json"]);
 const six=plan.newLocalBatchCases;
 ck("six_local_batch_cases_retained",six.length===6&&new Set(six).size===6&&groups[0].tests.filter(n=>six.includes(n)).length===6&&groups[1].tests.filter(n=>six.includes(n)).length===6);
 ck("request_whole",meta(t["request.exact.json"],plan.exactRequest));
 ck("request_shape",q.host==="rog"&&q.executable==="/usr/bin/python3"&&q.cwd==="/home/qian-qi"&&q.timeout_seconds===12000&&JSON.stringify(q.args.slice(0,4))===JSON.stringify(["-I","-S","-B","-c"])&&q.args.length===5&&q.args[4]===pu);
 ck("request_fresh_key",q.idempotency_key===plan.key&&q.idempotency_key.startsWith("heptabao-combined-4a49405b-fresh-build-")&&q.idempotency_key.length<=128);
 ck("stdin_exact",q.stdin===t["stdin.exact.json"]&&meta(q.stdin,plan.stdin)&&plan.stdin.bytes<=262144);
 const payload=JSON.parse(q.stdin),entries={"native_jwt_build.py":r,"launch_native_jwt_build.py":l,"jwt-test-groups.public.json":t["jwt-test-groups.public.json"]};
 ck("payload_closed_names",payload.schema==="heptabao.native-jwt-pki-build-control-inputs.v1"&&JSON.stringify(Object.keys(payload.files).sort())===JSON.stringify(Object.keys(entries).sort()));
 for(const [name,raw]of Object.entries(entries)){ck("payload_"+name,utf8Text(unb64(payload.files[name]))===raw);const pin=gitBlobMeta(raw);ck("publisher_pin_"+name,pu.includes(JSON.stringify(name)+": [\n        "+pin.bytes+",\n        "+JSON.stringify(pin.sha256)));}
 const typed=processStartBinding(q);ck("typed_digest",typed.sha256===plan.typed.sha256&&String(typed.native_fingerprint)===plan.typed.native_fingerprint);
 ck("candidate_exact",plan.candidate.commit==="4a49405b93c45ab1c25ecba11cde63a7ede20dce"&&plan.candidate.tree==="f02dd113d208d79f5275005dc65a5e8aecd0e9d3"&&l.includes(plan.candidate.commit)&&l.includes(plan.candidate.tree)&&r.includes(plan.candidate.commit)&&r.includes(plan.candidate.tree));
 const stage=parseLosslessIntegers(t["stage-result.actual.original.json"]);
 ck("stage_whole_actual",meta(t["stage-result.actual.original.json"],plan.actualStageReport));
 ck("stage_source_prepared",stage.status==="prepared"&&stage.source_commit===plan.candidate.commit&&stage.source_tree===plan.candidate.tree&&stage.source===plan.candidate.source&&stage.root==="/home/qian-qi/hb-4a49405b-src-20261106-r1"&&stage.source_clean===true&&stage.independent_git_directory===true&&stage.old_source_unchanged===true);
 ck("stage_full_tree",stage.full_worktree.full_leaf_index_sha256==="7e7acf5b5f4c0b2f9c410e6ead923258cb8b8750389d516b8998f6a45f5e8d7d"&&stage.full_worktree.tracked_leaf_count===3932&&stage.full_worktree.tracked_bytes===62553956&&stage.full_worktree.index_matches_tree===true&&stage.full_worktree.all_tracked_worktree_blobs_and_modes_match===true);
 ck("stage_clean_and_closed",stage.full_strict_fsck_passed===true&&stage.no_alternates===true&&stage.no_shared_object_links===true&&stage.within_new_stage_deadline===true&&stage.cleanup.every(x=>x.direct_child_reaped&&!x.remaining.length));
 ck("no_prior_compile_or_format_qualification",stage.compiler_started===false&&stage.rust_tests_executed===false&&stage.formatter_executed===false&&stage.historical_controls_executed===false&&plan.candidate.sourceFormatted===false&&plan.runtimeQualificationInherited===false);
 ck("publisher_stage_sha",pu.includes("'--stage-sha256', '"+plan.actualStageReport.sha256+"'"));
 const rootStage=JSON.parse(t["stage-root-qualification.public.json"]);
 ck("actual_stage_root_whole",meta(t["stage-root-qualification.public.json"],plan.originalStageQualification));
 ck("actual_stage_root_binding",rootStage.candidateCommit===plan.candidate.commit&&rootStage.candidateTree===plan.candidate.tree&&rootStage.stageReport.blob===plan.actualStageReport.blob&&rootStage.stageReport.sha256===plan.actualStageReport.sha256);
 ck("stage_only_qualification",rootStage.sourceStageQualified===true&&rootStage.buildQualified===false&&rootStage.currentControlsQualified===false&&rootStage.productTestsPassed===0&&plan.rootStageQualificationPendingAtSourceCutoff===false);
 ck("fresh_fixed_roots",plan.controlRoot==="/home/qian-qi/hb-4a49405b-controls-20261106-r1"&&plan.target===plan.controlRoot+"/cargo-target-r1"&&pu.includes("BASE = PARENT / 'hb-4a49405b-controls-20261106-r1'")&&l.includes("ROOT = Path('"+plan.controlRoot+"')")&&r.includes("Path('"+plan.target+"')"));
 ck("current_receipt_validation_preserved",l.includes("identity(os.fstat(target_fd))[:5] == identity(TARGET.lstat())[:5]")&&l.includes("assert not os.path.lexists(TARGET)")&&pu.includes("assert not os.path.lexists(BASE)"));
 ck("clock_budgets_unchanged",pu.includes("PUBLICATION_UNTIL = JOINT_STARTED + 60")&&pu.includes("JOINT_UNTIL = JOINT_STARTED + 12000")&&l.includes("ORIGINAL_OUTER_SECONDS = 12000")&&r.includes("ORIGINAL_OUTER_SECONDS = 12000")&&plan.budgets.releaseSeconds===1800&&plan.budgets.allCompileGatesSharedSeconds===3600&&plan.budgets.perFamilySeconds===600&&plan.budgets.listSeconds===30&&plan.budgets.cleanupTermSeconds===5&&plan.budgets.cleanupKillSeconds===5);
 ck("no_redundant_independent_controls_reads",plan.independentNativeControlsMetadataPlanned===false&&plan.independentNativeControlBodiesPlanned===false);
 ck("exact_precheck_qualified_source",gitBlobMeta(r).blob==="b3901c3ef34b4384c54e130637ea4ab8df0c6839"&&plan.precheckSourceTree==="d47fd022860b95f1b9c63eb6c5ba35afa0e45f25");
 ck("release_single_absolute_deadline",r.includes("release_until = min(release_started + 1800.0, OUTER_UNTIL)")&&r.includes("min(300.0, bounded_remaining(release_until)), deadline=release_until)")&&r.includes("bounded_remaining(release_until), deadline=release_until)")&&plan.budgets.precheckMaxWithinReleaseSeconds===300);
 ck("actual_json_gate_not_runtime_qualification",r.includes("precheck_artifact['target']['kind'] == ['lib']")&&r.includes("e.get('profile', {}).get('test') is True")&&r.includes("'linked_test_executable_qualified': False")&&plan.fastGateReplacesRelease===false&&plan.fastGateReplacesNoRun===false&&plan.fastGateReplacesTestRun===false);
 ck("separate_fresh_GO_required",plan.authorization==="NOT_GO"&&plan.NativeCalls===0&&plan.initializeCalled===false&&plan.buildQualified===false&&plan.fullReplacement===false);
 return {schema:"heptabao.combined4a49405b.fast-gated-fresh-joint-source-verification.r1",ok:true,checks:checks.length,results:checks,scope:"pure V8 strict source/data verification only; no Python, Native, compiler or candidate function invocation"};
}
