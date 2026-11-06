function verifyMacSuccessorStageTemplate(input) {
 const {before,after,diff,candidateRaw,indexRaw,groupsRaw,plan,interface:iface}=input;
 const checks=[];function check(name,value){checks.push({name,pass:value===true});if(value!==true)throw Error(name);}
 check("exact_existing_stage_source",gitBlobMeta(before).blob==="b6a9190bc5856e42be2d8e750875675521ecf22d");
 check("exact_new_unbound_template",gitBlobMeta(after).blob==="79c2bae6e400b385a5efa8c57a23c6e5f0ea72ed");
 check("strict_diff_forward",applyStrict(before,diff,false)===after);
 check("strict_diff_reverse",applyStrict(after,diff,true)===before);
 check("four_strict_hunks",(diff.match(/^@@ /gm)||[]).length===4);
 const defs=s=>Array.from(s.matchAll(/^def ([A-Za-z_][A-Za-z0-9_]*)[^\n]*\n(?:(?:[ \t].*|[ \t]*)\n)*/gm),m=>({name:m[1],raw:m[0]}));
 const a=defs(after),b=defs(before);
 check("all20_definitions_unchanged",a.length===20&&JSON.stringify(a)===JSON.stringify(b));
 const tail=s=>s.slice(s.indexOf("except BaseException as error:\n    result['error_type']"));
 check("failure_finally_terminal_tail_identical",tail(before).length>1000&&tail(before)===tail(after));
 check("actual_candidate_manifest_whole",gitBlobMeta(candidateRaw).blob==="d9d3fa89aecbdf276f8e22651559caa94b0ea518");
 const c=JSON.parse(candidateRaw);
 check("actual_successor_parent_bound",c.commit==="5767739cd25e458ac052dc8d384019bab8688ae0"&&c.tree==="42477d622dcf96e1e2b0929fe9ecc6b7ba484740"&&c.parent==="02b90762b3d6cc8699cc88bffb6f76cb1f07e270");
 check("full_index_whole",gitBlobMeta(indexRaw).sha256===c.fullLeafIndexSha256);
 const rows=indexRaw.trimEnd().split("\n").map(line=>{const x=line.split("\0");if(x.length!==4)throw Error("index_schema");return{path:x[0],mode:x[1],blob:x[2],bytes:Number(x[3]),line};});
 check("3932_rows_62553540_bytes",rows.length===3932&&new Set(rows.map(x=>x.path)).size===3932&&rows.reduce((s,x)=>s+x.bytes,0)===62553540);
 let reverse=indexRaw;
 check("five_known_modifications",c.changedFiles.length===5&&new Set(c.changedFiles.map(x=>x.path)).size===5);
 for(const f of c.changedFiles){
  const r=rows.find(x=>x.path===f.path);
  check("after_leaf:"+f.path,!!r&&r.blob===f.after.blob&&r.bytes===f.after.bytes);
  reverse=reverse.replace(r.line+"\n",f.path+"\0"+r.mode+"\0"+f.before.blob+"\0"+f.before.bytes+"\n");
 }
 check("five_before_substitutions_restore_exact02b_index",gitBlobMeta(reverse).sha256==="c6cef770842a1b0006b4c86a58e325802d00dd5779dede468262f2693c3246cc");
 check("runtime_hardpin_unchanged",rows.some(x=>x.path==="crates/heptabao-server/src/ha_native_v6_runtime.rs"&&x.blob==="3289da21ebb25a1efd04ae0d0fd1013ac7ac8fb3"&&x.bytes===61623));
 check("unbound_bundle_fails_before_main_writes",after.includes("CANONICAL_BUNDLE_BYTES = None\nCANONICAL_BUNDLE_SHA256 = None\n")&&after.indexOf("assert isinstance(CANONICAL_BUNDLE_BYTES")<after.indexOf("    canonical_path = ROOT.parent"));
 check("canonical_transport_and_dispatch_unobserved",iface.canonical_bundle.actual_bytes===null&&iface.canonical_bundle.actual_sha256===null&&iface.canonical_bundle.actual_version===null&&iface.canonical_bundle.complete_carrier_pin===null&&iface.source_stage.exact_request===null&&iface.source_stage.runtime_slot===null);
 check("staged_and_product_actual_slots_unobserved",iface.source_stage.actual_result===null&&iface.controls.actual_publication_receipt===null&&iface.normal.actual_server===null&&iface.normal.actual_normal61_report===null&&iface.full34.actual_live_result===null&&iface.controls.runtime_slot===null&&iface.normal.runtime_slot===null&&iface.full34.live_slot===null);
 check("source_budgets_unchanged",JSON.stringify(plan.unchanged_budgets.source_stage)===JSON.stringify({internal_seconds:300,git_leaf_seconds:90,clone_seconds:180,outer_seconds:360,carrier_bytes:262144,tracked_worktree_bytes:134217728}));
 check("exact_normal_groups_original",gitBlobMeta(groupsRaw).blob==="302e5d5a5bfe501dcaf75f8c4cfc166acd58ea5f"&&JSON.parse(groupsRaw).flatMap(g=>g.tests).length===44);
 check("normal61_and_original_budget",iface.normal.selected_tests===61&&JSON.stringify(iface.normal.selection)===JSON.stringify({six_groups:44,ingress:7,cold_h2:9,same_root_ABA:1})&&JSON.stringify(plan.unchanged_budgets.normal)===JSON.stringify({absolute_outer_seconds:8280,release_seconds:1800,libtest_compile_seconds:1800,listing_seconds:30,family_seconds:600,TERM_seconds:5,KILL_seconds:5}));
 check("canonical_full34_driver_unchanged",rows.some(x=>x.path==="qa/openbao-acceptance/kv2_271_lossless_native_live.py"&&x.blob===iface.full34.driver.blob)&&rows.some(x=>x.path==="qa/openbao-acceptance/official_openbao_launcher.py"&&x.blob===iface.full34.official_launcher.blob));
 check("full34_scope_original",iface.full34.keys===17&&iface.full34.value_bytes===2097152&&iface.full34.logical_bytes===35651584&&iface.full34.required_checks===31&&iface.full34.including_storage_checks===3&&plan.unchanged_budgets.full34.outer_seconds===1800&&plan.unchanged_budgets.full34.internal_wrapper_subprocess_timeout===null);
 return {schema:"heptabao.mac.successor576.pure-source-verification.v1",pass:true,check_count:checks.length,checks,definitions:a.map(x=>x.name),Native_calls:0,Python_runs:0,Cargo_runs:0,product_cases:0};
}
