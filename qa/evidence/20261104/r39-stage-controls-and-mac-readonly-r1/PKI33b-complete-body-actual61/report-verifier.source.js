function verifyFinalStageReport(raw,expect,h){
 const rows=[];function ck(k,v){rows.push({check:k,pass:!!v});if(!v)throw Error(k);}
 const p=h.gitBlobMeta(raw),r=h.parseLosslessIntegers(raw);
 ck("whole_exact_report",p.bytes===expect.metadata.size&&p.sha256===expect.metadata.sha256);
 ck("current_source_schema_status",r.schema==="heptabao.native-jwt-independent-source-stage.v1"&&r.status==="prepared");
 ck("exact_commit_tree_parent",r.source_commit===expect.commit&&r.source_tree===expect.tree&&r.sole_parent===expect.parent);
 ck("exact_owned_source_paths",r.root===expect.root&&r.source===expect.root+"/source"&&r.host==="rog");
 ck("exact_stager_carrier",r.stager_sha256===expect.stagerSHA&&r.carrier_sha256===expect.carrierSHA);
 ck("exact_commit_fetch_no_branch_guess",r.source_ref===null&&r.source_fetch_argument===expect.commit&&r.public_network_fetch_used===true);
 ck("original_stage_caps",r.original_git_leaf_cap_seconds===90&&r.original_clone_cap_seconds===180&&r.new_stage_total_seconds===300&&r.new_supervisor_seconds===360);
 ck("no_product_or_formatter_or_compiler",r.compiler_started===false&&r.server_started===false&&r.production_changed===false&&r.formatter_executed===false&&r.rust_tests_executed===false&&r.historical_controls_executed===false&&r.actual_build_qualification===false&&r.candidate_build_qualification===false);
 ck("source_clean_independent_checked",r.source_clean===true&&r.independent_git_directory===true&&r.no_alternates===true&&r.no_shared_object_links===true&&r.full_strict_fsck_passed===true&&Number.isSafeInteger(r.object_files_checked)&&r.object_files_checked>0);
 ck("full_canonical_inventory",r.full_worktree?.tracked_leaf_count===3916&&r.full_worktree.tracked_bytes===62297347&&r.full_worktree.full_leaf_index_sha256==="7a2ab1d97a5140120034276c0d21547ffa935867055a0c5af95f7f061f8f3df0"&&r.full_worktree.all_tracked_worktree_blobs_and_modes_match===true&&r.full_worktree.index_matches_tree===true);
 ck("old495_before_after",JSON.stringify(r.old_source_before)===JSON.stringify(r.old_source_after)&&r.old_source_before.commit==="49503322c7f446e5eb41e7744f1fdbd7f1192ecc"&&r.old_source_before.tree==="1d4211f91e1b34a2ed087a3bbef2e2884bac88e9"&&r.old_source_before.status===""&&r.old_source_unchanged===true);
 ck("failed_fixture_before_after_exact",JSON.stringify(r.failed_observer_before)===JSON.stringify(r.failed_observer_after)&&r.failed_observer_before.prior_failed_build_replayed===false);
 ck("all12_failed_files_same_content",Object.keys(r.failed_observer_before.files).length===12&&Object.entries(expect.failedFiles).every(([name,q])=>r.failed_observer_before.files[name]?.bytes===q.bytes&&r.failed_observer_before.files[name]?.sha256===q.sha256));
 const fa=r.failed_observer_before.authority;ck("failed_authority_exact_at_new_control",fa.path===expect.root+"/control/prior-observer-build-authority.public.json"&&fa.bytes===726&&fa.sha256==="820a3243ba5be87f4d8fdf3d47d68361a2f2d6a95043d38c0086afab1cf559b6");
 ck("four_historical_controls_compile_only",JSON.stringify(r.controls)===JSON.stringify(expect.controls)&&r.historical_controls_executed===false);
 ck("ancestry_history3766",r.canonical_history_count===3766&&r.new_commits_since_actual_495.length===14&&new Set(r.new_commits_since_actual_495).size===14&&expect.ancestry.every(x=>r.new_commits_since_actual_495.includes(x)));
 const cb=r.canonical_bundle;ck("current_bundle_shape_identity",cb.path===expect.root+"/control/canonical-native-jwt-pki-33b814c7-from495.bundle"&&Number.isSafeInteger(cb.bytes)&&cb.bytes>0&&cb.bytes<=4194304&&/^[0-9a-f]{64}$/.test(cb.sha256)&&cb.identity.length===9&&cb.identity[2]===1000&&cb.identity[3]===1000&&cb.identity[4]===33152&&cb.identity[5]===1&&cb.identity[6]===cb.bytes);
 ck("bundle_current_HEAD_and495_prerequisite",cb.header.version===2&&JSON.stringify(cb.header.heads)===JSON.stringify([[expect.commit,"HEAD"]])&&JSON.stringify(cb.header.prerequisites)===JSON.stringify(["49503322c7f446e5eb41e7744f1fdbd7f1192ecc"]));
 ck("all59_owned_direct_children_closed",r.cleanup.length===59&&new Set(r.cleanup.map(x=>x.label)).size===59&&r.cleanup.every(x=>x.exit_code===0&&x.direct_child_reaped===true&&Array.isArray(x.remaining)&&x.remaining.length===0&&!x.cleanup_error_type));
 ck("original_cleanup_deadline",typeof r.elapsed_seconds_after_cleanup==="number"&&r.elapsed_seconds_after_cleanup>=0&&r.elapsed_seconds_after_cleanup<300&&r.within_new_stage_deadline===true);
 const int=x=>BigInt(typeof x==="object"?x.$exactInteger:x);ck("original_epoch_order_lossless",int(r.started_ns)>0n&&int(r.terminal_ns)>int(r.started_ns));
 ck("legacy_counters_not_new_tests",r.exact_test_count===44&&r.additional_existing_tests===7&&r.additional_cold_h2_tests===9&&r.additional_same_root_publication_tests===1&&r.original_60_test_count===60&&r.rust_tests_executed===false);
 return {schema:"heptabao.jwt-pki33b-source-stage-report-content-review.v1",pass:true,checks:rows.length,rows,report:p,cleanupCount:r.cleanup.length,canonicalLeafCount:r.full_worktree.tracked_leaf_count,trackedBytes:r.full_worktree.tracked_bytes,elapsed:r.elapsed_seconds_after_cleanup,Cargo:0,productTests:0,qualificationScope:"actual source report consistency; no build or runtime regression qualification",canonicalBundle:cb};
}
