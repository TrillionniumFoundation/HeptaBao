function verifyBuildCorrection18(){
 const p=load("r34_packet_JWT-PKI-build-unbound-source18-r2"),b=load("r34_packet_JWT-PKI-build-unbound-source22"),old=load("r34_packet_JWT-build-unbound-source26"),plan=JSON.parse(p.raw["PLAN.public.json"]),groupsRaw=p.raw["groups.JWT-PKI.unchanged.json"],groups=JSON.parse(groupsRaw),oldGroups=JSON.parse(old.raw["groups.public.json"]),checks=[];
 const ck=(name,ok)=>{checks.push({name,passed:!!ok});if(!ok)throw Error(name);},eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b),match=(t,p)=>{const m=gitBlobMeta(t);return m.blob===p.blob&&m.bytes===p.bytes&&m.sha256===p.sha256;};
 ck("whole_successor18_708279_and_original22_851121",p.audit.whole&&p.audit.files===18&&p.audit.bytes===708279&&b.audit.whole&&b.audit.files===22&&b.audit.bytes===851121);
 ck("old26_review_retained",load("r37_jwt_build26_source_review_value").status==="SOURCE_ONLY_STILL_UNBOUND"&&old.audit.whole&&old.audit.files===26);
 const definitions=raw=>{const lines=raw.split("\n"),out={};for(let i=0;i<lines.length;i++){const m=/^def ([A-Za-z_][A-Za-z_0-9]*)\(/.exec(lines[i]);if(!m)continue;let j=i+1;for(;j<lines.length;j++)if(lines[j]!==""&&!/^\s/.test(lines[j]))break;out[m[1]]=lines.slice(i,j).join("\n");}return out;};
 const after={},definitionsCount={};let hunks=0;
 for(const kind of ["runner","launcher","publisher"]){
  const f=plan.components[kind],before=p.raw[kind+".BUILD22.before.py"],a=p.raw[kind+".BUILD22-r2.after.py"],d=p.raw[kind+".strict.diff"],prev=b.raw[kind+".JWT-PKI.after.py"];
  ck(kind+"_pins_base22",before===prev&&match(before,f.before)&&match(a,f.after)&&match(d,f.diff));
  const fw=strictApply(before,d),rev=strictApply(a,d,true);ck(kind+"_successor_exact_forward_reverse",fw.text===a&&rev.text===before&&fw.hunks===f.hunks&&rev.hunks===f.hunks);hunks+=fw.hunks;
  const orig=b.raw[kind+".BUILD26.before.py"],d1=b.raw[kind+".strict.diff"];
  ck(kind+"_original26_exact_forward_reverse",orig===old.raw[kind+".candidate.py"]&&strictApply(orig,d1).text===before&&strictApply(before,d1,true).text===orig);
  const defs=definitions(a);definitionsCount[kind]=Object.keys(defs).length;ck(kind+"_all_definitions_preserved_from26",eq(defs,definitions(orig)));
  ck(kind+"_BINDING_READY_false",a.includes("BINDING_READY = False")&&a.includes("assert BINDING_READY"));
  after[kind]=a;
 }
 ck("exact4_new_hunks25_definitions",hunks===4&&eq(definitionsCount,{runner:10,launcher:10,publisher:5}));
 const gp=gitBlobMeta(groupsRaw),carrier=p.raw["control-inputs.unbound.public.json"],payload=JSON.parse(carrier),publisherPins=JSON.parse(after.publisher.match(/^PINS = (\{[\s\S]*?^\})/m)[1]);
 ck("groups_exact_unchanged22_and_pins",groupsRaw===b.raw["groups.JWT-PKI.public.json"]&&match(groupsRaw,plan.groups)&&gp.sha256==="35153ff5e90b582f83e4fbbb66ff5c9fb295e95153f08df152cefedecdb50869");
 ck("runner_and_launcher_digest_bind_same_table",after.runner.match(/assert args.groups_sha256 == '([a-f0-9]{64})'/)?.[1]===gp.sha256&&after.launcher.match(/GROUPS_SHA256 = '([a-f0-9]{64})'/)?.[1]===gp.sha256);
 const files={"native_jwt_build.py":after.runner,"launch_native_jwt_build.py":after.launcher,"jwt-test-groups.public.json":groupsRaw};
 ck("payload_three_exact_keys_schema_cap",eq(Object.keys(payload.files).sort(),Object.keys(files).sort())&&payload.schema==="heptabao.native-jwt-pki-build-control-inputs.v1"&&match(carrier,plan.carrier)&&plan.carrier.bytes<=262144);
 for(const[name,t]of Object.entries(files)){const pin=gitBlobMeta(t);ck("payload_and_publisher_pin_"+name,utf8Text(unb64(payload.files[name]))===t&&eq(publisherPins[name],[pin.bytes,pin.sha256]));}
 ck("new_original_names_preserved",eq(groups[0].tests.slice(0,15),oldGroups[0].tests)&&eq(groups[1].tests.slice(0,15),oldGroups[1].tests)&&eq(groups[2],oldGroups[2])&&eq(groups[3],oldGroups[3]));
 const expectedPki=["service::native_auth::pki_tests::native_pki_formal_expired_lease_lookup_matches_openbao_271_400_and_cold","service::native_auth::pki_tests::native_pki_formal_revoked_lease_lookup_matches_openbao_271_400_and_cold"];
 ck("only_two_exact_new_PKI_names_both_profiles",eq(groups[0].tests.slice(15),expectedPki)&&eq(groups[0].tests,groups[1].tests)&&expectedPki.every(n=>b.raw["pki-tests.candidate.unformatted.rs"].includes("fn "+n.split("::").at(-1)+"(")));
 const names=groups.flatMap(g=>g.tests),existing=new Set(groups[2].tests.concat(groups[3].tests)),newNames=new Set(groups[0].tests);
 ck("four_family_shapes_same600_caps",eq(groups.map(g=>[g.libtest_profile,g.tests.length,g.runtime_seconds]),[["file",17,600],["default",17,600],["default",63,600],["default",69,600]]));
 ck("149_unique166_instances17new132existing_disjoint",names.length===166&&new Set(names).size===149&&existing.size===132&&newNames.size===17&&[...newNames].every(n=>!existing.has(n))&&existing.size+2*newNames.size===166);
 ck("generic17_and_explicit_JWT15_30_PKI2_4",after.runner.includes("'new_unique_test_total': 17, 'existing_unique_test_total': 132,")&&after.launcher.includes("new_jwt_test_names=15, new_jwt_profile_instances=30,")&&after.launcher.includes("new_pki_test_names=2, new_pki_profile_instances=4,"));
 ck("final_identity_still_unbound",Object.values(plan.final_binding).every(x=>x===null)&&after.launcher.includes("FINAL_COMMIT = None")&&after.launcher.includes("FINAL_TREE = None")&&plan.runtime_authorized===false);
 ck("budgets_not_raised",plan.budgets.release===1800&&plan.budgets.compileShared===3600&&plan.budgets.compileCommands===3&&plan.budgets.familyShared===600&&plan.budgets.families===4&&plan.budgets.outer===12000&&plan.budgets.cleanupTerm===5&&plan.budgets.cleanupKill===5&&plan.budgets.deadlineReset===false&&plan.budgets.publisherOuter===60);
 const value={schema:"heptabao.root-source-review.JWT-PKI-build149-166-correction.v1",status:"SOURCE_CORRECTED_STILL_UNBOUND",packet:p.audit,prior22:b.audit,prior26:old.audit,checks,check_count:checks.length,definition_counts:definitionsCount,correction_hunks:hunks,controls:plan.components,groups:plan.groups,payload:plan.carrier,denominators:plan.denominators,original22_findings_preserved:plan.root_findings,old_147_162_plan_preserved:true,binding_ready:false,final_source_commit:null,final_source_tree:null,independent_stage:null,actual_control_publication:null,Python_compiled:false,Rust_compiled:false,component_tests_executed:false,PKI_HTTP12_separate:true,distributed_HA_qualification:false,full_replacement:false,production_cutover:false,legacy_cleanup:false,root_Runtime_calls:0};
 store("r38_build18_root_source_review_value",value);return{status:value.status,checks:checks.length,definitions:definitionsCount,hunks,unique:149,profile_instances:166};
}