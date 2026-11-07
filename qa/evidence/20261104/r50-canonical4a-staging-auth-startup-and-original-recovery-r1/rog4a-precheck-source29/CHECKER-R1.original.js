function verifyPrecheck4a(I) {
 const rows=[];function ok(id,v){rows.push({id,ok:!!v});if(!v)throw Error(id);}
 let built=I.before;for(const e of I.edits){ok("unique-edit:"+e.label,built.split(e.oldText).length===2);built=built.replace(e.oldText,e.newText);}
 ok("mechanism-exact",built===I.mechanismAfter);
 for(const e of I.bindingEdits){ok("unique-binding:"+e.label,built.split(e.oldText).length===2);built=built.replace(e.oldText,e.newText);}
 ok("only-five-edits",I.edits.length===2&&I.bindingEdits.length===3&&built===I.after);
 ok("forward-whole",snapshotApply(I.before,I.diff)===I.after);
 ok("reverse-whole",snapshotApply(I.after,I.diff,true)===I.before);
 ok("one-mechanism-hunk",(snapshotUnified(I.before,I.mechanismAfter,"runner.py").match(/^@@/gm)||[]).length===1);
 ok("four-total-hunks",(I.diff.match(/^@@/gm)||[]).length===4);
 ok("under-original40000",gitBlobMeta(I.after).bytes<=40000);
 const c=JSON.parse(I.candidateRaw);
 ok("actual-candidate-commit",I.after.includes("DIAGNOSTIC_COMMIT = '"+c.commit+"'"));
 ok("actual-candidate-tree",I.after.includes("DIAGNOSTIC_TREE = '"+c.tree+"'"));
 ok("fresh-target",I.after.includes("/home/qian-qi/hb-4a49405b-controls-20261106-r1/cargo-target-r1"));
 ok("old-target-no-execution-introduced",I.after.slice(I.after.indexOf("PRESERVED_FILES ="),I.after.indexOf("def git("))===I.before.slice(I.before.indexOf("PRESERVED_FILES ="),I.before.indexOf("def git(")));
 function section(raw,start,end){const a=raw.indexOf(start),b=raw.indexOf(end,a);if(a<0||b<a)throw Error("section");return raw.slice(a,b);}
 ok("owned-lifecycle-byte-identical",section(I.after,"def owned(","assert os.uname()")===section(I.before,"def owned(","assert os.uname()"));
 ok("signals-termination-byte-identical",section(I.after,"def group_members(","profile = {")===section(I.before,"def group_members(","profile = {"));
 ok("environment-RUSTFLAGS-byte-identical",section(I.after,"profile = {","def bounded_remaining(")===section(I.before,"profile = {","def bounded_remaining("));
 ok("tool-whole-byte-identical",section(I.after,"PUBLIC_TOOL_IDENTITIES =","def fresh_target_pin")===section(I.before,"PUBLIC_TOOL_IDENTITIES =","def fresh_target_pin"));
 ok("single-release-clock",(I.after.match(/release_until = /g)||[]).length===1&&I.after.includes("release_until = min(release_started + 1800.0, OUTER_UNTIL)"));
 ok("precheck300-shared-clock",I.after.includes("min(300.0, bounded_remaining(release_until)), deadline=release_until)"));
 ok("release-only-remaining",I.after.includes("'--message-format=json-render-diagnostics'], bounded_remaining(release_until), deadline=release_until)"));
 ok("no-release-reset-after-precheck",I.after.indexOf("release_until =")<I.after.indexOf("precheck = owned")&&I.after.indexOf("precheck = owned")<I.after.indexOf("release = owned"));
 ok("original-total12000",I.after.includes("ORIGINAL_OUTER_SECONDS = 12000")&&I.after.includes("OUTER_UNTIL = args.outer_started_monotonic + ORIGINAL_OUTER_SECONDS"));
 ok("subsequent-compile3600-and-all-runtime-exact",I.after.slice(I.after.indexOf("    # One original 3600-second compilation budget"))===I.before.slice(I.before.indexOf("    # One original 3600-second compilation budget")));
 ok("original-release-after-call-exact",section(I.after,"    result['normal_release_build'] = release","    # One original 3600-second compilation budget")===section(I.before,"    result['normal_release_build'] = release","    # One original 3600-second compilation budget"));
 ok("all-test-groups-exact",section(I.after,"PROFILE_CRATES =","assert not output.exists()")===section(I.before,"PROFILE_CRATES =","assert not output.exists()"));
 ok("original-finally-byte-identical",I.after.slice(I.after.lastIndexOf("\nfinally:\n"))===I.before.slice(I.before.lastIndexOf("\nfinally:\n")));
 ok("only-one-new-owned-child",(I.after.match(/= owned\(/g)||[]).length===(I.before.match(/= owned\(/g)||[]).length+1);
 ok("exact-lib-check-command",I.after.includes("'--locked', '--offline', '-p', 'heptabao-server', '--lib', '--profile', 'test',"));
 ok("no-new-RUSTFLAGS-or-tests-switch",!section(I.after,"    precheck = owned","    release = owned").includes("--tests")&&!section(I.after,"    precheck = owned","    release = owned").includes("RUSTFLAGS"));
 ok("actual-test-mode",I.after.includes("and e.get('profile', {}).get('test') is True"));
 ok("actual-target-name-kind",I.after.includes("e.get('target', {}).get('name') == 'heptabao_server'")&&I.after.includes("precheck_artifact['target']['kind'] == ['lib']"));
 ok("actual-source-and-manifest",I.after.includes("precheck_artifact['target']['src_path'] == str(source / 'crates/heptabao-server/src/lib.rs')")&&I.after.includes("precheck_artifact['manifest_path'] == str(source / 'crates/heptabao-server/Cargo.toml')"));
 ok("exact-default-features",I.after.includes("sorted(precheck_artifact['features']) == ['default', 'native-v6-ha', 'native-v6-storage']"));
 ok("one-finished-success",I.after.includes("len(precheck_finished) == 1 and precheck_finished[0].get('success') is True"));
 ok("one-matching-test-artifact",I.after.includes("assert len(precheck_artifacts) == 1"));
 ok("no-link-executable-required",!section(I.after,"    precheck_artifacts =","    result['default_libtest_precheck_mode']").includes("executable"));
 ok("explicit-no-runtime-replacement",I.after.includes("'linked_test_executable_qualified': False")&&I.after.includes("'runtime_tests_qualified': False")&&I.after.includes("'replaces_release_or_no_run': False"));
 const p=JSON.parse(I.primaryReportRaw);
 ok("primary-pinned-Cargo-source",p.rust_gitlink.commit==="797e8a9bca276c1c9f9f738d2a20f484fa4eea9d");
 ok("no-binary-version-overclaim",p.boundary.deployed_cargo_binary_to_gitlink_proven===false&&p.boundary.actual_cargo_version===null);
 ok("profile-checktest-primary",I.checkRaw.includes("UserIntent::Check { test }")&&I.checkRaw.includes('Some("test")'));
 ok("JSON-is-any-test-primary",I.compilerRaw.includes("test: unit_mode.is_any_test(),"));
 ok("whole-primary-code-pins",gitBlobMeta(I.checkRaw).blob==="6bcc83b48f96e61fd48b9d31456957614231ffc2"&&gitBlobMeta(I.compilerRaw).blob==="6153b2f1e4e8009ce2b8f5624f11b2ced651eee1");
 return {schema:"heptabao.b.fast-default-libtest-precheck-source.r1",checks:rows,checksPassed:rows.length,before:gitBlobMeta(I.before),after:gitBlobMeta(I.after),sameReleaseBudget1800:true,precheckMax300:true,compileBudget3600:true,total12000:true,selectedUnique:252,selectedProfileInstances:280,NativeCalls:0,PythonExecuted:false,CargoExecuted:false,actualNewPrecheck:null};
}
