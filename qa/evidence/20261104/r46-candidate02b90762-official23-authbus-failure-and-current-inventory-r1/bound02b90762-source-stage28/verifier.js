function verifyBoundCombinedStage(t,h) {
  const out=[];function need(v,n){out.push({name:n,pass:!!v});if(!v)throw Error(n);}
  const plan=JSON.parse(t["PLAN.public.json"]), input=JSON.parse(t["INPUTS.public.json"]);
  for(const [path,pin]of Object.entries(input.files)){const actual=h.meta(t[path]);need(actual.blob===pin.blob&&actual.bytes===pin.bytes&&actual.sha256===pin.sha256,"whole:"+path);}
  const before=t["stage.before.py"],after=t["stage.after.py"],jb=t["journal.before.js"],ja=t["journal.after.js"];
  const changes=JSON.parse(t["LITERAL-CHANGES.public.json"]);
  function applyChanges(raw,rows){for(const [a,b]of rows){need(a!==b&&raw.split(a).length===2,"unique_literal:"+out.length);raw=raw.replace(a,b);}return raw;}
  need(changes.stage.length===12&&changes.journal.length===3,"finite_literal_counts");
  need(applyChanges(before,changes.stage)===after,"only_stage_literals");
  need(applyChanges(jb,changes.journal)===ja,"only_journal_literals");
  need(h.apply(before,t["stage.forward.diff"])===after&&h.apply(after,t["stage.forward.diff"],true)===before&&h.apply(after,t["stage.reverse.diff"])===before,"stage_strict_both_directions");
  need(h.apply(jb,t["journal.forward.diff"])===ja&&h.apply(ja,t["journal.forward.diff"],true)===jb&&h.apply(ja,t["journal.reverse.diff"])===jb,"journal_strict_both_directions");
  need((t["stage.forward.diff"].match(/^@@/gm)||[]).length===6&&(t["journal.forward.diff"].match(/^@@/gm)||[]).length===2,"strict_hunk_counts");
  function defs(raw){const a=raw.split("\n"),r=[];for(let i=0;i<a.length;i++)if(/^def /.test(a[i])){let j=i+1;while(j<a.length&&(a[j]===""||/^[ \t]/.test(a[j])))j++;r.push({name:a[i].match(/^def ([A-Za-z_]\w*)/)[1],raw:a.slice(i,j).join("\n")});}return r;}
  const bd=defs(before),ad=defs(after);
  need(bd.length===20&&ad.length===20&&bd.every((x,i)=>x.name===ad[i].name),"all_original_function_order");
  need(bd.filter(x=>x.name!=="verify_full_worktree").every(x=>ad.some(y=>y.name===x.name&&y.raw===x.raw)),"nineteen_original_function_bodies");
  const oldVerify=bd.find(x=>x.name==="verify_full_worktree").raw,newVerify=ad.find(x=>x.name==="verify_full_worktree").raw;
  need(oldVerify.replace("assert len(entries) == 3930 and len({x[0] for x in entries}) == 3930","assert len(entries) == 3932 and len({x[0] for x in entries}) == 3932")===newVerify,"sole_function_actual_leafcount_only");
  need(after.slice(after.indexOf("\nexcept BaseException as error:\n"))===before.slice(before.indexOf("\nexcept BaseException as error:\n")),"original_exception_finally_terminal_tail");
  const pub=JSON.parse(t["root-publication-proof.original.json"]),commit=JSON.parse(t["actual-commit.original.json"]),ancestry=JSON.parse(t["base-ancestry.original.json"]);
  need(pub.commit===plan.canonical.commit&&pub.tree===plan.canonical.tree&&pub.soleParent===plan.canonical.parent&&pub.branchReadbackCommit===pub.commit,"root_actual_publication");
  need(commit.sha===pub.commit&&commit.tree.sha===pub.tree&&commit.parents.length===1&&commit.parents[0].sha===pub.soleParent,"actual_commit_parent_tree");
  const links=pub.actualAncestryTo495;
  need(links.length===16&&links[0].sha===pub.commit&&links.every((x,i)=>x.parent===(links[i+1]?.sha||"49503322c7f446e5eb41e7744f1fdbd7f1192ecc")),"exact_16link_continuity");
  need(JSON.stringify(links.slice(1))===JSON.stringify(ancestry.links)&&pub.expectedCandidateHistoryCount===3752+links.length&&pub.expectedCandidateHistoryCount===3768,"actual_base_chain_and_history");
  need(after.includes("ANCESTRY = (\n"+links.map(x=>"    ('"+x.sha+"', '"+x.parent+"'),").join("\n")+"\n)"),"source_actual_ancestry_literal");
  const rows=t["git-order-leaf-index.original.txt"].split("\n");need(rows.pop()==="","index_exact_trailing_newline");
  const entries=rows.map(x=>x.split("\0"));
  need(entries.every(x=>x.length===4&&/^(100644|100755)$/.test(x[1])&&/^[a-f0-9]{40}$/.test(x[2])&&/^(0|[1-9][0-9]*)$/.test(x[3])),"original_nul_index_shape");
  need(entries.length===3932&&new Set(entries.map(x=>x[0])).size===3932&&entries.reduce((a,x)=>a+Number(x[3]),0)===62537554,"actual_leaf_count_and_tracked_bytes");
  need(h.meta(t["git-order-leaf-index.original.txt"]).sha256===pub.gitOrderLeafIndex.sha256&&after.includes(pub.gitOrderLeafIndex.sha256),"actual_index_digest_bound");
  need(entries.some(x=>x[0]==="crates/heptabao-server/src/ha_native_v6_runtime.rs"&&x[2]==="3289da21ebb25a1efd04ae0d0fd1013ac7ac8fb3"&&x[3]==="61623"),"unchanged_canonical_runtime_guard");
  need(after.includes("ROOT = Path('"+plan.paths.root+"')")&&plan.paths.root==="/home/qian-qi/hb-02b90762-src-20261106-r1"&&after.includes("'canonical-hb-02b90762-from495.bundle'"),"root_selected_fresh_paths");
  need(after.includes("'schema': 'heptabao.native-jwt-independent-source-stage.v1'")&&after.includes("'stage_purpose': 'combined_source_for_separate_build_admission'"),"reviewed_schema_and_unformatted_purpose");
  need(pub.sourceFormatted===false&&plan.qualification.sourceFormatted===false&&plan.qualification.compilationExecuted===false&&plan.qualification.testsExecuted===0,"no_formatter_or_execution_qualification");
  const oldQ=JSON.parse(t["request.before.json"]),q=JSON.parse(t["request.after.json"]),oldGO=JSON.parse(t["baseline-stage-GO.original.json"]);
  const expectedQ=JSON.parse(t["request.before.json"]);expectedQ.args[4]=after;expectedQ.args[6]=h.meta(after).sha256;expectedQ.idempotency_key=plan.key;
  need(JSON.stringify(q)===JSON.stringify(expectedQ),"request_only_source_selfhash_key");
  need(q.stdin===t["historical-carrier.original.json"]&&q.stdin===oldQ.stdin&&h.meta(q.stdin).bytes===79951,"unchanged_whole_carrier");
  need(q.host==="rog"&&q.executable==="/usr/bin/python3"&&q.cwd==="/home/qian-qi"&&q.timeout_seconds===360&&q.args.length===9&&q.args[7]==="--carrier-sha256"&&q.args[8]===h.meta(q.stdin).sha256,"exact_original_request_geometry");
  need(q.idempotency_key.length<=128&&q.idempotency_key==="heptabao-combined-02b90762-rog-source-20261106-r1-"+h.meta(after).sha256.slice(0,8),"unique_scope_key_literal");
  const ob=h.binding(oldQ),nb=h.binding(q);
  need(ob.sha256===oldGO.native_binding.sha256&&ob.native_fingerprint===oldGO.native_binding.native_fingerprint,"typed_stdin_original_positive_control");
  need(nb.sha256===plan.nativeBinding.sha256&&nb.native_fingerprint===plan.nativeBinding.native_fingerprint,"new_correct_typed_binding");
  need(ja.includes('const GF_SLOT = "'+plan.slot+'";')&&ja.includes(h.meta(t["request.after.json"]).blob)&&ja.includes(h.meta(t["request.after.json"]).sha256),"new_journal_slot_request_pins");
  need(ja.includes("/^heptabao-combined-02b90762-rog-source-observe-r1-/")&&ja.includes('a.host==="rog"')&&ja.includes("q.limit===8192")&&ja.includes("a.limit===16384"),"original_observer_host_caps");
  need(plan.budgets.stage===300&&plan.budgets.gitLeaf===90&&plan.budgets.clone===180&&plan.budgets.outer===360&&plan.budgets.term===5&&plan.budgets.kill===5&&plan.budgets.stdin===262144&&plan.budgets.payload===1048576,"original_budget_table");
  need(plan.NativeAuthorized===false&&plan.processStartSubmitted===false&&plan.actualStage===null&&plan.actualBundle===null&&plan.actualStageReadAuthority===false,"source_review_only");
  return {schema:"heptabao.combined02b90762-bound-stage-source-verification.r1",pass:true,checks:out.length,results:out,stage:h.meta(after),request:h.meta(t["request.after.json"]),journal:h.meta(ja),functionBodiesUnchanged:19,stageLiteralChanges:12,journalLiteralChanges:3,stageHunks:6,journalHunks:2,pythonExecuted:false,NativeCalls:0,RustExecuted:false};
}
