function verifyStage4a(I,O) {
 const checks=[];function ok(id,v){checks.push({id,ok:!!v});if(!v)throw Error(id);}
 const c=JSON.parse(I.candidateRaw), q=JSON.parse(O.requestRaw), oldq=JSON.parse(I.beforeRequestRaw);
 const rebuilt=buildStage4a(I);
 ok("deterministic_exact_after",rebuilt.after===O.after);
 ok("deterministic_exact_request",rebuilt.requestRaw===O.requestRaw);
 ok("deterministic_exact_journal",rebuilt.journal===O.journal);
 ok("thirteen_named_source_edits",O.edits.length===13);
 ok("strict_source_forward",snapshotApply(I.before,O.sourceDiff)===O.after);
 ok("strict_source_reverse",snapshotApply(O.after,O.sourceDiff,true)===I.before);
 ok("strict_journal_forward",snapshotApply(I.beforeJournal,O.journalDiff)===O.journal);
 ok("strict_journal_reverse",snapshotApply(O.journal,O.journalDiff,true)===I.beforeJournal);
 ok("six_source_two_journal_hunks",(O.sourceDiff.match(/^@@/gm)||[]).length===6&&(O.journalDiff.match(/^@@/gm)||[]).length===2);
 ok("candidate_identity",c.commit==="4a49405b93c45ab1c25ecba11cde63a7ede20dce"&&c.tree==="f02dd113d208d79f5275005dc65a5e8aecd0e9d3"&&c.parent==="5767739cd25e458ac052dc8d384019bab8688ae0");
 ok("candidate_only_three_test_leaves",c.changedFiles.length===3&&c.changedFiles.every(x=>x.path.includes("test"))&&c.productionCodeUnchangedFromParent===true);
 ok("candidate_unqualified",c.RustCompiled===false&&c.runtimeTestsExecuted===0&&c.formatted===false&&c.fullReplacement===false);
 const rows=I.indexRaw.trimEnd().split("\n").map(l=>l.split("\0"));
 ok("whole_index_hash",gitBlobMeta(I.indexRaw).sha256===c.fullLeafIndexSha256);
 ok("whole_index_count",rows.length===3932&&new Set(rows.map(x=>x[0])).size===3932);
 ok("whole_index_bytes",rows.reduce((n,x)=>n+Number(x[3]),0)===62553956);
 for(const d of c.changedFiles){const r=rows.find(x=>x[0]===d.path);ok("index:"+d.path,r&&r[2]===d.after.blob&&Number(r[3])===d.after.bytes);}
 ok("history3770",c.expectedHistoryCount===3770&&O.after.includes("'canonical_history_count': 3770")&&O.after.includes("== '3770'"));
 const ancestry=O.after.slice(O.after.indexOf("ANCESTRY = ("),O.after.indexOf("\nROOT_COMMIT ="));
 const links=[...ancestry.matchAll(/\('([0-9a-f]{40})', '([0-9a-f]{40})'\)/g)].map(m=>[m[1],m[2]]);
 ok("eighteen_actual_parent_links",links.length===18&&links[0][0]===c.commit&&links[0][1]===c.parent&&links.at(-1)[1]==="49503322c7f446e5eb41e7744f1fdbd7f1192ecc");
 ok("chain_connected",links.slice(0,-1).every((r,i)=>r[1]===links[i+1][0]));
 function defs(raw){const lines=raw.split("\n"),out=[];for(let i=0;i<lines.length;i++){if(!/^def \w+\(/.test(lines[i]))continue;let end=i+1;while(end<lines.length&&(lines[end]===""||/^\s/.test(lines[end])))end++;out.push({name:/^def (\w+)/.exec(lines[i])[1],raw:lines.slice(i,end).join("\n")});i=end-1;}return out;}
 const beforeDefs=defs(I.before),afterDefs=defs(O.after);ok("same_definition_count",beforeDefs.length===afterDefs.length);
 for(let i=0;i<beforeDefs.length;i++){ok("definition-name-"+i,beforeDefs[i].name===afterDefs[i].name);if(beforeDefs[i].name!=="canonical_bundle_header")ok("unchanged-definition-"+i,beforeDefs[i].raw===afterDefs[i].raw);}
 ok("base02b_literal_retained",O.after.includes("BASE = Path('/home/qian-qi/hb-02b90762-src-20261106-r1/source')")&&O.after.includes("BASE_COMMIT = '02b90762b3d6cc8699cc88bffb6f76cb1f07e270'"));
 ok("old495_failed_fence_unchanged",O.after.slice(O.after.indexOf("EXPECTED_CONTROLS ="),O.after.indexOf("children = []"))===I.before.slice(I.before.indexOf("EXPECTED_CONTROLS ="),I.before.indexOf("children = []")));
 ok("original_finally_exact",O.after.slice(O.after.indexOf("except BaseException as error:\n    result['error_type']"))===I.before.slice(I.before.indexOf("except BaseException as error:\n    result['error_type']")));
 ok("stage300_unchanged",O.after.includes("STAGE_SECONDS = 300.0")&&O.after.includes("return original_owned(label, argv, min(limit, stage_remaining()), cwd)"));
 ok("leaf90_clone180",O.after.includes("def owned(label, argv, limit=90, cwd=None):")&&O.after.includes("str(BASE), str(SOURCE)], 180)"));
 ok("shared_bundle_fourMiB",O.after.includes("bundle_remaining = 4 * 1024 * 1024 - canonical_total_bytes")&&O.after.includes("canonical_total_bytes += len(canonical_raw)")&&(O.after.match(/stable_read\(canonical_path, bundle_remaining\)/g)||[]).length===2);
 ok("two_fixed_bundle_specs",O.after.includes("('canonical-hb-4a49405b-from576.bundle', PARENT, 'canonical_bundle')")&&O.after.includes("('canonical-hb-4a49405b-from02b.bundle', BASE_COMMIT, 'canonical_x230_bundle')"));
 ok("one_prerequisite_bound_header",O.after.includes("assert prerequisites == [prerequisite]")&&O.after.includes("assert heads == [[COMMIT, 'HEAD']]"));
 ok("fresh_create_no_overwrite",O.after.includes("assert not os.path.lexists(ROOT)")&&O.after.includes("assert not os.path.lexists(canonical_path)"));
 ok("request_shape_same",Object.keys(q).sort().join()===Object.keys(oldq).sort().join());
 for(const k of ["host","executable","cwd","timeout_seconds","stdin"])ok("request-unchanged-"+k,q[k]===oldq[k]);
 ok("original_outer360",q.timeout_seconds===360);
 ok("original_stdin79951",gitBlobMeta(q.stdin).bytes===79951&&gitBlobMeta(q.stdin).sha256==="85fd6e473ce1e231f1bcfbd2bcf2bef760e6a4e551040c55ee3274606acebb77");
 ok("source_exact_args",q.args[4]===O.after&&q.args[6]===gitBlobMeta(O.after).sha256);
 ok("remaining_arguments_exact",q.args.length===oldq.args.length&&q.args.every((x,i)=>i===4||i===6||x===oldq.args[i]));
 ok("key_specific",q.idempotency_key==="heptabao-combined-4a49405b-rog-source-20261106-r1-"+gitBlobMeta(O.after).sha256.slice(0,8));
 const binding=processStartBinding(q);ok("typed_correct_stdin_binding",binding.sha256===O.binding.sha256&&binding.native_fingerprint===O.binding.native_fingerprint);
 ok("same_journal_except_five_literals",rebuilt.journal===O.journal);
 const validate=eval(O.journal+";gfValidateRequest"),base={paused:false,nativeCallInFlight:false,pending:null,startCalled:false,job:null,activeObserver:null};
 validate(base,"process_start",q,O.requestRaw);ok("exact_start_allowed",true);
 for(const [name,mutate] of [
  ["host",x=>x.host="mac"],["key",x=>x.idempotency_key+="-changed"],["timeout",x=>x.timeout_seconds=361],["source",x=>x.args[4]+="\n"],["stdin",x=>x.stdin+="\n"]
 ]){const bad=JSON.parse(O.requestRaw);mutate(bad);let denied=false;try{validate(base,"process_start",bad,JSON.stringify(bad,null,2)+"\n");}catch{denied=true;}ok("reject-start-"+name,denied);}
 let denied=false;try{validate({...base,startCalled:true},"process_start",q,O.requestRaw);}catch{denied=true;}ok("reject_second_start",denied);
 const prior=JSON.parse(I.baseQualificationRaw);ok("actual576_stage_reference",prior.candidateCommit===c.parent);
 return {schema:"heptabao.b.4a-stage-source-verification.r1",checks,checksPassed:checks.length,source:gitBlobMeta(O.after),request:gitBlobMeta(O.requestRaw),journal:gitBlobMeta(O.journal),definitions:beforeDefs.length,unchangedDefinitions:beforeDefs.length-1,NativeCalls:0,PythonExecuted:false,RustExecuted:false,bundleActual:null,stageActual:null};
}
