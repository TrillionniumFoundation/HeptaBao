function verifyMacNormalNative28Source(i) {
 const checks=[];const ok=(name,v)=>{checks.push({name,pass:v===true});if(v!==true)throw Error(name);};
 const defs=s=>Array.from(s.matchAll(/^def ([A-Za-z_][A-Za-z0-9_]*)[^\n]*\n(?:(?:[ \t].*|[ \t]*)\n)*/gm),m=>({name:m[1],raw:m[0]}));
 for(const [kind,n]of [["runner",10],["launcher",7],["publisher",5]]){
  const b=i[kind+"Before"],a=i[kind+"After"],d=i[kind+"Diff"];
  ok(kind+"_strict_forward",applyStrict(b,d,false)===a);
  ok(kind+"_strict_reverse",applyStrict(a,d,true)===b);
  ok(kind+"_all_original_helpers_identical",defs(b).length===n&&JSON.stringify(defs(b))===JSON.stringify(defs(a)));
 }
 const rb=i.runnerBefore,ra=i.runnerAfter;
 const begin="    release = owned('normal-release-build'";
 const exception="except BaseException as error:\n    result['failure_type']";
 const extension="\n    if result['status'] == 'passed':\n        bounded_remaining(OUTER_UNTIL)\n        result['original_61_status']";
 const oldBlock=rb.slice(rb.indexOf(begin),rb.indexOf(exception));
 const newBlock=ra.slice(ra.indexOf(begin),ra.indexOf(extension));
 ok("original_release_default_compile_and_all61_block_exact",newBlock+"\n"===oldBlock);
 ok("original_failure_cleanup_and_deadline_tail_exact",rb.slice(rb.indexOf(exception))===ra.slice(ra.indexOf(exception)));
 const oldGroups=JSON.parse(i.oldGroupsRaw),g=JSON.parse(i.groupsRaw),root=JSON.parse(i.rootGroupsRaw);
 ok("exact_original_six_groups_retained",JSON.stringify(oldGroups)===JSON.stringify(g.normal61_groups));
 const selected=root.filter(x=>["native-jwt-pki-file28","native-jwt-pki-default28"].includes(x.label));
 ok("two_native_groups_verbatim_root_selection",JSON.stringify(selected)===JSON.stringify(g.native_jwt_pki_groups));
 function tuple(name){const start=rb.indexOf(name+" = (\n"),end=rb.indexOf("\n)",start);if(start<0||end<0)throw Error(name);return Array.from(rb.slice(start,end).matchAll(/"([^"]+)"/g),m=>m[1]);}
 const oldNames=oldGroups.flatMap(x=>x.tests).concat(tuple("INGRESS_OBSERVER_TESTS"),tuple("COLD_H2_TESTS"),tuple("SAME_ROOT_PUBLICATION_TESTS"));
 ok("original61_distinct",oldNames.length===61&&new Set(oldNames).size===61);
 ok("native28_same_names_both_profiles",selected.length===2&&selected.every(x=>x.tests.length===28&&new Set(x.tests).size===28)&&JSON.stringify(selected[0].tests)===JSON.stringify(selected[1].tests));
 ok("89unique117profile_no_overlap",oldNames.every(n=>!selected[0].tests.includes(n))&&new Set(oldNames.concat(selected[0].tests)).size===89&&oldNames.length+selected.reduce((s,g)=>s+g.tests.length,0)===117);
 ok("six_new_batch_functions_twelve_executions",selected[0].tests.filter(x=>/::native_jwt_batch_/.test(x)).length===6);
 ok("default_feature_proof",gitBlobMeta(i.cargoRaw).blob==="666dc6d056a8f653bb86ca5ba7ed89b229dfe228"&&i.cargoRaw.includes('default = ["native-v6-storage", "native-v6-ha"]'));
 ok("same_run_default_binary_reuse_and_file_profile",ra.includes("'default': result['binary']")&&ra.includes("'--lib', '--no-run', '--no-default-features', '--features',\n                           'native-v6-storage'")&&ra.includes("assert sorted(file_event['features']) == ['native-v6-storage']")&&ra.includes("assert file_event['profile'] == artifact['profile']"));
 ok("new_file_build_finished_required",ra.includes("assert file_build_finished and len(file_events) == 1"));
 ok("original8280_not_reset",ra.includes("ORIGINAL_OUTER_SECONDS = 8280")&&ra.includes("OUTER_UNTIL = args.outer_started_monotonic + ORIGINAL_OUTER_SECONDS")&&ra.split("OUTER_UNTIL =").length===2&&i.launcherAfter.includes("ORIGINAL_OUTER_SECONDS = 8280"));
 ok("new_compile_and_groups_clamped_to_original_deadline",ra.includes("min(1800.0, bounded_remaining(OUTER_UNTIL)), deadline=OUTER_UNTIL)")&&ra.includes("group_until = min(group_started + 600.0, OUTER_UNTIL)")&&ra.includes("min(30.0, bounded_remaining(group_until)), deadline=group_until)"));
 ok("new_exact_actual_execution_checks",ra.includes("assert selected == [name], 'exact native JWT/PKI testcase missing'")&&ra.includes("[str(actual_binary), name, '--exact', '--nocapture', '--test-threads=1']")&&ra.includes("assert 'test result: ok. 1 passed; 0 failed; 0 ignored;' in summary"));
 ok("runner_read_cap_explicit_and_sufficient",gitBlobMeta(ra).bytes===42977&&i.launcherAfter.includes("read_bound(runner, args.runner_sha256, 49152)")&&gitBlobMeta(i.launcherAfter).bytes<40000&&gitBlobMeta(i.groupsRaw).bytes<20000);
 const pins=JSON.parse(i.publisherAfter.split("\n").find(l=>l.startsWith("PINS = ")).slice(7));
 ok("publisher_pins_match_three_exact_templates",JSON.stringify(pins)===JSON.stringify({
  "mac_normal_same_root_publication_build.py":[gitBlobMeta(ra).bytes,gitBlobMeta(ra).sha256],
  "launch_normal_same_root_publication.py":[gitBlobMeta(i.launcherAfter).bytes,gitBlobMeta(i.launcherAfter).sha256],
  "normal-test-groups.public.json":[gitBlobMeta(i.groupsRaw).bytes,gitBlobMeta(i.groupsRaw).sha256]}));
 ok("publication_unbound_until_real_stage",i.publisherAfter.includes("BINDING_READY = False\nSTAGE_REPORT =")&&i.publisherAfter.includes("\nSTAGE_EXPECTED = None\n")&&i.launcherAfter.includes("\nSTAGE_EXPECTED_FULL9 = None\n")&&i.binding.ready===false&&i.binding.actual_stage_report===null&&i.binding.publisher_exact_request===null&&i.binding.build_exact_request===null);
 ok("new_receipt_and_launcher_counts_agree",i.publisherAfter.includes("result['selected_unique_test_count'] = 89")&&i.publisherAfter.includes("result['selected_profile_execution_count'] = 117")&&i.launcherAfter.includes("controls['selected_unique_test_count'] == 89 and controls['selected_profile_execution_count'] == 117"));
 ok("future_binder_strict_roundtrip",applyStrict(i.binderBefore,i.binderDiff,false)===i.binderAfter&&applyStrict(i.binderAfter,i.binderDiff,true)===i.binderBefore);
 ok("future_binder_keeps8280_and_actual_receipt_scope",i.binderAfter.includes("timeout_seconds:8280")&&i.binderAfter.includes("result.selected_unique_test_count===89&&result.selected_profile_execution_count===117")&&i.binderAfter.includes("rootBuildGORequired:true,NativeExecuted:false"));
 return {schema:"heptabao.mac.normal61-native28.source-verification.v1",pass:true,check_count:checks.length,checks,source_only:true,Python_runs:0,Rust_runs:0,Native_calls:0,product_cases_passed:0};
}
