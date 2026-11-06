function verifyMac576AdmissionFragment(files){
 const checks=[],check=(name,ok)=>{checks.push({name,pass:!!ok});if(!ok)throw Error(name);};
 const before=files["admission.before.py"],after=files["admission.after.py"],d=files["admission.strict.diff"];
 check("strict_forward",applyStrict(before,d)===after);
 check("strict_reverse",applyStrict(after,d,true)===before);
 const schema=JSON.parse(files["INTERFACE.public.json"]),g=JSON.parse(files["groups.original.json"]);
 const oldSection=x=>x.slice(x.indexOf(" for key,names in ("),x.indexOf(" need(n.get('groups_sha256')")>=0?x.indexOf(" need(n.get('groups_sha256')"):x.indexOf(" cleanup=n.get('cleanup')"));
 check("original_7_9_ABA_assertions_exact",oldSection(before)===oldSection(after));
 check("original_cleanup_and_return_exact",before.slice(before.indexOf(" cleanup=n.get('cleanup')"))===after.slice(after.indexOf(" cleanup=n.get('cleanup')")));
 const line=after.split("\n").find(x=>x.startsWith(" expected_groups=json.loads("));
 const names=JSON.parse(JSON.parse(line.slice(" expected_groups=json.loads(".length,-1)));
 check("actual_source28_names_both_profiles",JSON.stringify(names)===JSON.stringify(g.native_jwt_pki_groups));
 check("same28_twice",names.length===2&&names.every(x=>x.tests.length===28)&&JSON.stringify(names[0].tests)===JSON.stringify(names[1].tests));
 check("both_actual_profile_groups",names[0].libtest_profile==="file"&&names[1].libtest_profile==="default");
 check("same_current_schema_and_runner",after.includes("'heptabao.mac-normal61-native-jwt-pki28-exact-tests.v1'")&&after.includes("'9ad6026ea175fbbeb52ad7ac68ec2f150d9a1bf4da08db7a36dc0d820df31913'"));
 check("current_117_and_89",after.includes("n.get('selected_test_total')==117")&&after.includes("n.get('selected_unique_test_total')==89"));
 check("actual_tests_listing_status_not_merely_plan",after.includes("len(rows)==28")&&after.includes("listing.get('exit_code')==0")&&after.includes("test.get('exit_code')==0")&&after.includes("group.get('actual_test_names')==expected['tests']"));
 check("distinct_file_default_and_same_run_binary",after.includes("binaries['default']==n.get('binary')")&&after.includes("['default','native-v6-ha','native-v6-storage']")&&after.includes("['native-v6-storage']"));
 check("unchanged_full34_denominator_budget",schema.preserved_full34.required_checks.length===31&&schema.preserved_full34.logical_bytes===35651584&&schema.preserved_full34.http_seconds===15&&schema.preserved_full34.migration_seconds===360&&schema.preserved_full34.native_outer_seconds===1800);
 check("actual_unknown_no_request",schema.current_normal.actual_result===null&&schema.current_normal.actual_retained_binary===null&&schema.execution.full_wrapper===null&&schema.execution.live_request===null&&schema.execution.Native_calls===0);
 return {schema:"heptabao.mac576.admission-fragment-source-verification.v1",pass:true,check_count:checks.length,checks,Python_runs:0,HTTP_runs:0};
}

