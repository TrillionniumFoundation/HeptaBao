function verifyCliCurrentSource(r, canonical, records, applyUnified) {
 const checks=[]; function ck(n,v){if(!v)throw Error(n);checks.push(n);}
 const pairs=[["reference/phaseb_binding_df026.py","candidate/phaseb_binding_r3.py","review/binding.review.diff",8],["reference/partial-binding.df026.private.json","binding/partial-binding.private.json","review/binding-template.review.diff",4],["reference/requests.df026.template.json","dispatch/requests.template.json","review/dispatch-template.review.diff",4]];
 for(const [b,a,d,n]of pairs){const q=applyUnified(r[b],r[d]);ck("strict_forward_"+d,q.text===r[a]);ck("hunks_"+d,q.hunks===n);}
 const binding=JSON.parse(r["binding/partial-binding.private.json"]),old=JSON.parse(r["reference/partial-binding.df026.private.json"]),dispatch=JSON.parse(r["dispatch/requests.template.json"]);
 ck("current_commit",binding.candidate_commit==="4e808d0ecb1bcded22870a7ec960dfb2491cf6ec"&&dispatch.candidate_commit===binding.candidate_commit);
 ck("current_tree",binding.candidate_tree==="eba5e650bd080b8ad41ea52a2bc68867f541d255"&&dispatch.candidate_tree===binding.candidate_tree);
 ck("dispatch_unready_unauthorized",dispatch.ready===false&&dispatch.requests_authorized===false);
 ck("prepare_unready",binding.ready_for_readonly_prepare===false);
 for(const k of ["server","native_receipt","release_receipt","combined_tests"])ck("unbound_"+k,binding.artifacts[k].bytes===null&&binding.artifacts[k].sha256===null);
 ck("normal_groups_unchanged",binding.artifacts.test_groups.bytes===6249&&binding.artifacts.test_groups.sha256==="0566f7f98ea16a4c1df43ebaf992172646ad91623c18f68fcc59f7c08b53d1f1");
 ck("fresh_control_r4",binding.layout.control.endsWith("/official271-native-cli-phaseb-r3-control-r4"));
 ck("fresh_live_r4",binding.layout.work.endsWith("/official271-native-cli-phaseb-r3-live-r4"));
 ck("source_current_namespace",binding.layout.source.endsWith("/normal-same-root-publication-validation-source-r1"));
 const ct=Array.isArray(canonical)?canonical:canonical.tree;
 for(const rec of records.filter(x=>x.path.startsWith("reference/canonical/"))){const path=rec.path.slice("reference/canonical/".length),e=ct.find(x=>x.path===path);ck("canonical_"+path,!!e&&e.sha===rec.blob);}
 for(const p of ["candidate/phaseb_controller_r3.py","candidate/native_fixture_reference_r8.py","candidate/official_cli_reference_r4.py","candidate/phaseb_evidence_r3.py"]){const name=p.slice("candidate/".length),rec=records.find(x=>x.path===p),spec=binding.qa_files[name],before=old.qa_files[name];ck("actual_qa_binding_"+name,rec.bytes===spec.bytes&&rec.sha256===spec.sha256);ck("original_qa_identity_"+name,spec.bytes===before.bytes&&spec.sha256===before.sha256);}
 for(const k of ["budgets","old_fences","official_cli","host","utilities"])ck("unchanged_"+k,JSON.stringify(binding[k])===JSON.stringify(old[k]));
 ck("original_unknowns_unreplayed",dispatch.old_unknown_attempts_replayed===false);
 return {status:"passed_source_only",checks,checks_passed:checks.length,diff_hunks:[8,4,4],packet_tree:"ce236663c9969af8d7e00cf598a6594666c5d0fc",independent_peer:"3af3b767f0d9c1d2a7712ac4d60fe8b57bf8631f",scope:"Root whole-blob/Merkle verification, strict diffs, canonical product-source bindings and preserved original constraints. No module import, fixture, controller or CLI execution.",author_static_checks:143,author_selected_predicate_cases:14,root_claims_rerun_of_author_tests:false,prepare_go:false,live_go:false,product_runtime_qualification:false};
}
