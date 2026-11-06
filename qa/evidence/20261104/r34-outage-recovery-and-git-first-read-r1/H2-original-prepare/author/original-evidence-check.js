function auditH2Prepared(r,b,t,H) {
 const checks=[];const C=(name,condition)=>checks.push({name,passed:condition===true});
 const canon=x=>{if(x&&typeof x==="object"&&Object.keys(x).length===1&&typeof x.$exactInteger==="string")return["exact-integer",x.$exactInteger];if(Array.isArray(x))return x.map(canon);if(x&&typeof x==="object")return Object.fromEntries(Object.keys(x).sort().map(k=>[k,canon(x[k])]));return x;};
 const eq=(a,b)=>JSON.stringify(canon(a))===JSON.stringify(canon(b));
 const integer=x=>BigInt(typeof x==="object"?x.$exactInteger:String(x));
 const idFields=["device","inode","uid","gid","mode","links","bytes","mtime_ns","ctime_ns","sha256","path"];
 C("schema",r.schema==="heptabao.normal-native-h2-gate.prepare.v2");
 C("passed-no-failure",r.status==="passed"&&r.failure_code===null);
 C("prepare-only",r.runtime_started===false&&r.server_processes===0&&r.cli_snapshot_commands===0&&r.production_changed===false&&r.readiness_is_not_runtime_qualification===true);
 C("binding",r.binding_sha256==="b241c6fc78bbe77ea69fc3b8a707b1747324a81f1da1ade3d9bb15c5cea5b7d8"&&r.inputs.binding_sha256===r.binding_sha256&&t.binding.sha256===r.binding_sha256);
 C("source",r.inputs.source.commit===b.candidate_commit&&r.inputs.source.tree===b.candidate_tree&&r.inputs.source.status==="");
 C("host",eq(r.inputs.host,b.host));C("budgets",eq(r.inputs.budgets,b.budgets));
 C("distinct-identities",b.candidate_commit==="4e808d0ecb1bcded22870a7ec960dfb2491cf6ec"&&b.candidate_tree==="eba5e650bd080b8ad41ea52a2bc68867f541d255"&&b.instrument_build_commit==="df026fe323dd7cf0f0ec57d7d2d9c5a79897053c"&&b.instrument_build_tree==="424463ccd2310ddc1e7b2bbcd7b7af29ae58c825");
 const stage=new Map();
 for(const x of t.captured_readonly_inputs)stage.set(x.path,x);
 for(const x of t.copied)stage.set(x.target.path,x.target);
 for(const x of Object.values(t.h2_copied))stage.set(x.target.path,x.target);
 for(const x of t.qa_files)stage.set(b.layout.control+"/qa/"+x.name,{...x,path:b.layout.control+"/qa/"+x.name});
 for(const x of t.extra_artifacts)stage.set(b.layout.control+"/artifacts/"+x.name,{...x,path:b.layout.control+"/artifacts/"+x.name});
 const mappings=[["artifacts",b.artifacts],["h2_client",b.h2_client],["qa",b.qa_files],["utilities",b.utilities]];
 let count=0;const identities=[];
 for(const [group,expected] of mappings){
  const actual=r.inputs.files[group];C(group+"-exact-roles",eq(Object.keys(actual).sort(),Object.keys(expected).sort()));
  for(const [role,e] of Object.entries(expected)){
   const a=actual[role];count++;C(group+"/"+role+"-binding",Object.entries(e).every(([k,v])=>eq(a[k],v))&&a.links===1);
   const prior=stage.get(a.path);C(group+"/"+role+"-stage-full9",!!prior&&idFields.every(k=>eq(a[k],prior[k])));
   identities.push({group,role,path:a.path,bytes:a.bytes,sha256:a.sha256});
  }
 }
 C("six-fences",r.inputs.files.old_fences.length===6&&b.old_fences.length===6);
 for(let i=0;i<b.old_fences.length;i++){
  const a=r.inputs.files.old_fences[i],e=b.old_fences[i],prior=stage.get(a.path);count++;
  C("old-fence-"+i+"-binding",Object.entries(e).every(([k,v])=>eq(a[k],v))&&a.links===1);
  C("old-fence-"+i+"-stage-full9",!!prior&&idFields.every(k=>eq(a[k],prior[k])));
  identities.push({group:"old_fences",role:i,path:a.path,bytes:a.bytes,sha256:a.sha256});
 }
 C("31-input-files",count===31&&new Set(identities.map(x=>x.path)).size===31);
 const sourceRows=Object.entries(r.inputs.archive_and_audit_product_sources);
 C("8-product-source-rows",sourceRows.length===8);
 for(const [path,x] of sourceRows){const prior=stage.get(b.layout.source+"/"+path);C("product-source/"+path,!!prior&&x.bytes===prior.bytes&&x.sha256===prior.sha256&&/^[a-f0-9]{40}$/.test(x.git_blob));}
 const q=r.inputs.product_test_qualification,i=r.inputs.independent_h2_qa;
 C("product-normal61",q.product_commit===b.candidate_commit&&q.product_tree===b.candidate_tree&&q.original_tests===44&&q.ingress_tests===7&&q.cold_h2_tests===9&&q.same_root_publication_tests===1&&q.total_tests===61&&q.normal_result_sha256===b.artifacts.combined_tests.sha256&&q.normal_runner_sha256==="93dd6190c7f081305defdbc1c49600974bfa581d943736c77798d51a1c8f54be");
 C("instrument-historical-df026",i.instrument_build_commit===b.instrument_build_commit&&i.instrument_build_tree===b.instrument_build_tree&&i.instrument_build_normal_result_sha256==="84d763e6ff948df27964f373e834f869d7b22eeb0d7efb929fbd5c299c528f1b");
 C("instrument-receipt-executable",i.actual_build_receipt_sha256===b.h2_client.build_receipt.sha256&&i.executable_sha256===b.h2_client.executable.sha256);
 C("instrument-six-original-components",i.component_count===6&&i.component_status==="passed"&&i.component_names.length===6&&new Set(i.component_names).size===6&&i.new_qa_components_not_added_to_product_44_7_9_1===true);
 C("instrument-locked-sources",i.lock_subset.canonical_sha256===b.h2_client.canonical_lock.sha256&&i.lock_subset.qa_lock_sha256===b.h2_client.cargo_lock.sha256&&i.lock_subset.exact_version_source_checksum_subset===true&&i.lock_subset.registry_package_count===76&&i.lock_subset.packages.length===76&&i.lock_subset.owned_qa_package_count===1);
 C("qualification-boundaries",i.http_or_product_qualification===false&&r.inputs.official_cli_qualification===false&&r.inputs.whole_replacement_qualification===false);
 const base=[b.utilities.git.path,"-c","core.fsmonitor=false","-c","core.hooksPath=/dev/null","-C",b.layout.source];
 const argv=[["source-commit",base.concat(["rev-parse","HEAD"])],["source-tree",base.concat(["rev-parse","HEAD^{tree}"])],["source-status",base.concat(["status","--porcelain","--untracked-files=all"])]];
 C("three-original-guards",r.child_provenance.length===3);
 C("three-original-cleanups",r.owned_cleanup.length===3);
 C("no-extra-exec-visibility",r.child_exec_visibility.length===0);
 const commandProof=[];
 for(let j=0;j<argv.length;j++){
  const [label,args]=argv[j],p=r.child_provenance[j],c=r.owned_cleanup.find(x=>x.pid===p.pid);
  const cmd=args.join("\0")+"\0",hash=H.meta(cmd).sha256,bytes=H.meta(cmd).bytes;
  C(label+"-argv",p.stage==="exact_executable_and_argv"&&p.guard_accepted===true&&p.captured_only_by_original_child_guard===true&&p.actual_argc===args.length&&p.expected_argc===args.length&&p.extra_args_omitted===0&&p.args.length===args.length&&p.actual_cmdline_bytes===bytes&&p.actual_cmdline_sha256===hash&&p.args.every((a,k)=>a.index===k&&a.equal===true&&a.bytes===H.meta(args[k]).bytes&&a.expected_bytes===a.bytes&&a.sha256===H.meta(args[k]).sha256&&a.expected_sha256===a.sha256));
  C(label+"-identity",p.identity.pid===p.pid&&p.identity.pgid===p.pid&&p.identity.exe===b.utilities.git.path&&Number.isSafeInteger(p.identity.start_ticks)&&p.identity.start_ticks>0);
  C(label+"-cleanup",!!c&&c.start_ticks===p.identity.start_ticks&&c.direct_child_reaped===true&&c.owned_stopped===true&&c.stop_terminal_captured===true&&c.wait_returncode===0&&Array.isArray(c.remaining)&&c.remaining.length===0);
  commandProof.push({label,argv:args,pid:p.pid,start_ticks:String(p.identity.start_ticks),cmdline_sha256:hash,guard_accepted:p.guard_accepted,cleanup:c});
 }
 C("unique-owned-pids",new Set(r.child_provenance.map(x=>x.pid)).size===3&&new Set(r.owned_cleanup.map(x=>x.pid)).size===3);
 C("all-owned-stopped",r.all_owned_stopped===true);
 const done=integer(r.completed_after_cleanup_monotonic_ns),deadline=integer(r.deadline_monotonic_ns);
 C("original-absolute-deadline",done<deadline&&b.budgets.action_seconds===300);
 return {schema:"heptabao.h2-prepare-author-original-evidence-check.v1",checks,passed:checks.every(x=>x.passed),check_count:checks.length,input_files:identities,original_owned_command_proof:commandProof,completed_after_cleanup_monotonic_ns:done.toString(),deadline_monotonic_ns:deadline.toString(),remaining_after_cleanup_ns:(deadline-done).toString(),historical_components_not_rerun:true,Runtime_calls:0,product_H2_qualification:false};
}
