
function verifyJwtPolicyRunnerAdapter(texts,H){
 const checks=[],ok=(c,n)=>{checks.push({name:n,pass:!!c});if(!c)throw Error(n);},eq=(a,b,n)=>ok(JSON.stringify(a)===JSON.stringify(b),n);
 const input=JSON.parse(texts["INPUTS.public.json"]);
 for(const role of ["runner","launcher"]){
  const r=input[role],b=texts[role+".before.UNBOUND.py"],a=texts[role+".after.UNBOUND.py"];
  eq(H.meta(b),r.before,"whole before "+role);eq(H.meta(a),r.after,"whole after "+role);
  let replay=b;for(const x of r.replacements){ok(replay.split(x.before).length===2,"unique exact "+role+" "+x.label);replay=replay.replace(x.before,x.after);}
  ok(replay===a,"exact replacement reconstruction "+role);
  let rev=a;for(const x of [...r.replacements].reverse()){ok(rev.split(x.after).length===2,"reverse unique "+role+" "+x.label);rev=rev.replace(x.after,x.before);}
  ok(rev===b,"exact reverse reconstruction "+role);
  ok(H.apply(b,texts[role+".forward.diff"])===a,"strict forward "+role);
  ok(H.apply(a,texts[role+".forward.diff"],true)===b,"strict inverse "+role);
  ok(H.apply(a,texts[role+".reverse.diff"])===b,"strict reverse "+role);
  ok(a.includes("BINDING_READY = False"),"unbound admission "+role);
  ok(a.includes("ORIGINAL_OUTER_SECONDS = 12000"),"original12000 "+role);
  ok(!a.includes("BINDING_READY = True"),"no ready bypass "+role);
 }
 const rb=texts["runner.before.UNBOUND.py"],ra=texts["runner.after.UNBOUND.py"],lb=texts["launcher.before.UNBOUND.py"],la=texts["launcher.after.UNBOUND.py"];
 const slice=(s,start,end)=>{const i=s.indexOf(start),j=s.indexOf(end,i+start.length);if(i<0||j<0)throw Error("slice");return s.slice(i,j);};
 eq(slice(ra,"    for group in groups:\n        family_started","    result['binaries_unchanged']"),slice(rb,"    for group in groups:\n        family_started","    result['binaries_unchanged']"),"entire runtime family/list/exact execution loop unchanged");
 ok(ra.split("\nexcept BaseException as error:\n").length===2&&rb.split("\nexcept BaseException as error:\n").length===2,"unique outer exception header");
 eq(ra.slice(ra.indexOf("\nexcept BaseException as error:\n")),rb.slice(rb.indexOf("\nexcept BaseException as error:\n")),"runner final error/cleanup entire tail unchanged");
 eq(slice(la,"def read_bound(","def "),slice(lb,"def read_bound(","def "),"generic read_bound function unchanged");
 eq(slice(la,"    argv = [PYTHON","    assert time.monotonic()"),slice(lb,"    argv = [PYTHON","    assert time.monotonic()"),"same-PID runner argv unchanged");
 ok(la.includes("SOURCE_STAGE_SCHEMA = 'heptabao.native-jwt-independent-source-stage.v1'"),"frozen stage schema unchanged");
 for(const name of ["FINAL_COMMIT","FINAL_TREE","SOURCE_STAGE_ROOT"])ok(la.includes(name+" = None"),"unbound "+name);
 for(const name of ["DIAGNOSTIC_COMMIT","DIAGNOSTIC_TREE"])ok(ra.includes(name+" = None"),"unbound "+name);
 eq(slice(ra,"try:\n    result['retained_df026_before']","    for group in groups:\n        family_started"),slice(rb,"try:\n    result['retained_df026_before']","    for group in groups:\n        family_started"),"all existing fences and normal/compile pipelines unchanged");
 eq(la.slice(la.indexOf("finally:\n    result['terminal_ns']"),la.indexOf("print(json.dumps({'status': 'preflight-admitted'")),lb.slice(lb.indexOf("finally:\n    result['terminal_ns']"),lb.indexOf("print(json.dumps({'status': 'preflight-admitted'")),"launcher lock-close/refusal tail unchanged");
 ok(H.meta(la).bytes===39648&&H.meta(la).bytes<40000,"launcher known byte cap39648/40000");
 ok(H.meta(ra).bytes===31984&&H.meta(ra).bytes<40000,"runner known byte cap31984/40000");
 const groups=JSON.parse(texts["groups.after.json"]),oldGroups=JSON.parse(texts["groups.before.json"]),es=JSON.parse(texts["entries268.after.json"]),oldEs=JSON.parse(texts["entries254.before.json"]),ps=JSON.parse(texts["profiles.after.json"]),oldPs=JSON.parse(texts["profiles.before.json"]);
 const uniq=xs=>new Set(xs.map(x=>x.crate+"\0"+x.name)).size;
 eq([oldEs.length,uniq(oldEs)],[254,237],"old exact inventory254/237");
 eq([es.length,uniq(es)],[268,246],"new exact inventory268/246");
 eq(groups.slice(4),oldGroups.slice(4),"fourteen unchanged groups27+61");
 eq(es.slice(180),oldEs.slice(166),"eighty-eight unchanged rows incl full source provenance");
 const pc=Object.fromEntries(oldPs.map(x=>[x.profile,x.package]));
 eq(es.map(x=>[x.crate,x.libtest_profile,x.name]),groups.flatMap(g=>g.tests.map(n=>[pc[g.libtest_profile],g.libtest_profile,n])),"entire ordered group/profile/fullname join");
 eq(ps,oldPs.map(x=>({...x,entries:es.filter(e=>e.libtest_profile===x.profile).length})),"profile definitions unchanged except counts");
 eq(ps.map(x=>x.entries),[22,229,17],"profile22/229/17 exact");
 ok(groups.length===18&&groups.every(g=>g.runtime_seconds===600),"eighteen families with600 deadline");
 ok(groups[0].tests.join("\n")===groups[1].tests.join("\n")&&groups[0].tests.length===22,"same22 file/default source names");
 ok(H.meta(texts["groups.after.json"]).bytes===33825,"exact input groups33825");
 ok(la.includes("args.groups_sha256, 33825)")&&!la.includes("args.groups_sha256, 32163)"),"only finite groups read bound33825");
 const hash=H.meta(texts["groups.after.json"]).sha256;
 ok(ra.includes("assert args.groups_sha256 == '"+hash+"'")&&la.includes("GROUPS_SHA256 = '"+hash+"'"),"exact new groups hash bound in both controls");
 ok(ra.includes("'baseline_c_unique_test_total': 149, 'baseline_c_profile_instance_total': 166")&&la.includes("baseline_c_unique=149, baseline_c_profile_instances=166"),"original C149/166 provenance retained");
 ok(ra.includes("'jwt_policy_delta_unique_test_total': 9, 'jwt_policy_delta_profile_instance_total': 14")&&la.includes("selected_jwt_pki_unique=158, selected_jwt_pki_instances=180"),"explicit scoped new test delta");
 ok(la.includes("new_jwt_test_names=20, new_jwt_profile_instances=40, jwt_policy_legacy_additions=4"),"actual local selected20 Native plus4 legacy");
 ok(ra.includes("snapshot_low_level_component_total': 23")&&ra.includes("snapshot_service_regression_total': 4")&&ra.includes("normal61_selected_test_total': 61"),"snapshot23+Service4+normal61 retained separately");
 return{schema:"heptabao.jwt-policy.runner-adapter.source-verification.r1",pass:true,checkCount:checks.length,checks,files:2,exactReplacements:25,hunks:12,unique:246,profileEntries:268,profiles:{file:22,default:229,HA:17},groups:18,groupBytes:33825,launcherBytes:39648,launcherMarginBeforeBinding:352,runnerBytes:31984,pythonCompiled:false,rustCompiled:false,RuntimeCalls:0,finalBindingReady:false};
}
