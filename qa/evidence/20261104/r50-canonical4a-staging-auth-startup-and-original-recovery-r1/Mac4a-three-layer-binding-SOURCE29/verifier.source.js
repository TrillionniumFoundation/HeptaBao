function verifyMac4aCandidateBinding(files) {
 const plan=JSON.parse(files["PLAN.public.json"]),candidate=JSON.parse(files["CANDIDATE.original.json"]),checks=[];
 const need=(name,v,detail)=>{if(!v)throw Error(name);checks.push({name,pass:true,detail});};
 need("actual candidate manifest",gitBlobMeta(files["CANDIDATE.original.json"]).blob==="c38e8861e72700088d2c3dd797fce885d117d903",null);
 need("exact current candidate",candidate.commit==="4a49405b93c45ab1c25ecba11cde63a7ede20dce"&&candidate.tree==="f02dd113d208d79f5275005dc65a5e8aecd0e9d3"&&candidate.parent==="5767739cd25e458ac052dc8d384019bab8688ae0"&&candidate.leafCount===3932&&candidate.trackedBytes===62553956&&candidate.fullLeafIndexSha256==="7e7acf5b5f4c0b2f9c410e6ead923258cb8b8750389d516b8998f6a45f5e8d7d",null);
 const rows=[
  ["stage.candidate.py","stage.before.unbound.py","stage.candidate.template.py","stage.candidate.diff"],
  ["runner.candidate.py","runner.before.py","runner.candidate.py","runner.candidate.diff"],
  ["launcher.candidate.py","launcher.before.py","launcher.candidate.template.py","launcher.candidate.diff"],
  ["publisher.candidate.template.py","publisher.before.py","publisher.candidate.template.py","publisher.candidate.diff"],
  ["build-binder.candidate.js","build-binder.before.js","build-binder.candidate.js","build-binder.candidate.diff"],
  ["full34-admission.candidate.py","full34-admission.before.py","full34-admission.candidate.py","full34-admission.candidate.diff"]
 ];
 for(const [name,b,a,d]of rows){
  const p=plan.changes[name];
  need(name+" whole pins",JSON.stringify(gitBlobMeta(files[b]))===JSON.stringify(p.before)&&JSON.stringify(gitBlobMeta(files[a]))===JSON.stringify(p.after)&&JSON.stringify(gitBlobMeta(files[d]))===JSON.stringify(p.diff),null);
  need(name+" strict forward",applyStrict(files[b],files[d],false)===files[a],null);
  need(name+" strict reverse",applyStrict(files[a],files[d],true)===files[b],null);
  let reconstructed=files[b];for(const r of p.applied){if(reconstructed.split(r.from).length-1!==r.count)throw Error(name+" unique literal");reconstructed=reconstructed.split(r.from).join(r.to);}
  need(name+" only listed literal replacements",reconstructed===files[a]&&(files[d].match(/^@@ /gm)||[]).length===p.hunks,{hunks:p.hunks});
 }
 const defs=s=>Array.from(s.matchAll(/^def ([A-Za-z_][A-Za-z0-9_]*)[^\n]*\n(?:(?:[ \t].*|[ \t]*)\n)*/gm),m=>({name:m[1],raw:m[0]}));
 for(const [,b,a]of rows.slice(0,4))need(a+" complete original definitions",JSON.stringify(defs(files[b]))===JSON.stringify(defs(files[a])),{count:defs(files[b]).length});
 need("groups original exact",gitBlobMeta(files["groups.original.json"]).blob==="c1cd3341b57860b199302b1adf86e336957700c1",null);
 const pins=JSON.parse(files["publisher.candidate.template.py"].split("\n").find(l=>l.startsWith("PINS = ")).slice(7));
 for(const [name,file]of [["mac_normal_same_root_publication_build.py","runner.candidate.py"],["launch_normal_same_root_publication.py","launcher.candidate.template.py"],["normal-test-groups.public.json","groups.original.json"]]){
  const p=gitBlobMeta(files[file]);need("publisher pin "+name,JSON.stringify(pins[name])===JSON.stringify([p.bytes,p.sha256]),null);
 }
 need("bundle remains unbound",files["stage.candidate.template.py"].includes("CANONICAL_BUNDLE_BYTES = None\nCANONICAL_BUNDLE_SHA256 = None\n"),null);
 need("controls remain unbound",files["launcher.candidate.template.py"].includes("STAGE_EXPECTED_FULL9 = None")&&files["publisher.candidate.template.py"].includes("BINDING_READY = False")&&files["publisher.candidate.template.py"].includes("STAGE_EXPECTED = None"),null);
 need("admission sole runner SHA replacement",files["full34-admission.before.py"].replace(gitBlobMeta(files["runner.before.py"]).sha256,gitBlobMeta(files["runner.candidate.py"]).sha256)===files["full34-admission.candidate.py"],null);
 const s=JSON.parse(files["STAGE-BINDINGS.public.json"]),n=JSON.parse(files["NORMAL-BINDINGS.unobserved.public.json"]),f=JSON.parse(files["FULL34-INTERFACE.public.json"]);
 need("stage current candidate/base relation",s.candidate.commit===candidate.commit&&s.candidate.tree===candidate.tree&&s.readonlyBase.commit===candidate.parent&&s.requiredBundle.prerequisites.length===1&&s.requiredBundle.prerequisites[0]===candidate.parent&&s.requiredBundle.heads[0][0]===candidate.commit,null);
 need("stage original budgets",JSON.stringify(s.budget)===JSON.stringify({stage:300,clone:180,git:90,outer:360,stdinCarrierBytes:262144,trackedWorktreeBytes:134217728}),null);
 need("bundle and runtime actual slots absent",Object.values(s.actualBundle).every(v=>v===null)&&s.actual.exactRequest===null&&s.actual.runtimeSlot===null&&s.actual.GO===null&&s.actual.report===null,null);
 need("normal actual inputs absent",n.ready===false&&n.commit===candidate.commit&&n.tree===candidate.tree&&["actual_stage_report","actual_stage_report_full9","root_stage_qualification","actual_controls_receipt","actual_publisher_job","build_exact_request","build_runtime_slot","actual_server","actual_seed","actual_default_libtest","actual_file_libtest","actual_normal61","actual_native_file28","actual_native_default28","actual_combined_result","root_build_qualification"].every(k=>n[k]===null),null);
 need("normal exact89/117 binding",f.current_normal.selected_unique_tests===89&&f.current_normal.selected_profile_executions===117&&f.current_normal.runner.blob===gitBlobMeta(files["runner.candidate.py"]).blob,null);
 need("full34 fragment current before/diff",f.fragment.before.blob===gitBlobMeta(files["full34-admission.before.py"]).blob&&f.fragment.after.blob===gitBlobMeta(files["full34-admission.candidate.py"]).blob&&f.fragment.strict_diff.blob===gitBlobMeta(files["full34-admission.candidate.diff"]).blob,null);
 need("full34 original scope and unobserved",f.preserved_full34.required_check_count===31&&f.preserved_full34.logical_bytes===35651584&&f.preserved_full34.native_outer_seconds===1800&&f.preserved_full34.http_seconds===15&&f.preserved_full34.migration_seconds===360&&f.full34_baseline.driver.blob==="87db25eab1258c8a2d7f9047e2009b62404b6259"&&f.execution.full_wrapper===null&&f.execution.prepare_request===null&&f.execution.live_request===null,null);
 return {schema:"heptabao.mac4a49405b.candidate-binding-pure-checks.r1",pass:true,count:checks.length,checks,Native_calls:0,Python_runs:0,Cargo_runs:0};
}
