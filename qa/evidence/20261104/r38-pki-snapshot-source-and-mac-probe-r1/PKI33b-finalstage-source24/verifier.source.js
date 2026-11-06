function verifyFinalStage(input,h,d,bind) {
 const out=[];function ck(name,ok,detail=null){out.push({name,pass:!!ok,detail});if(!ok)throw Error(name);}function eq(a,b){return JSON.stringify(a)===JSON.stringify(b);}
 function defs(s){const l=s.split("\n"),r=[];for(let i=0;i<l.length;i++){if(!/^def \w+\(/.test(l[i]))continue;let j=i+1;while(j<l.length&&(!l[j]||/^\s|^#/.test(l[j])))j++;r.push({name:l[i].match(/^def (\w+)/)[1],body:l.slice(i,j).join("\n")});i=j-1;}return r;}
 const {base,after,journalBefore,journalAfter,replacements,journalReplacements,sourceDiff,journalDiff,requestRaw,baseRequestRaw,freezeRaw,commitRaw,expected}=input;
 const fr=JSON.parse(freezeRaw),commit=JSON.parse(commitRaw),q=JSON.parse(requestRaw),old=JSON.parse(baseRequestRaw);
 ck("actual_commit",commit.sha===expected.commit&&fr.commit===expected.commit);
 ck("sole_parent",commit.parents.length===1&&commit.parents[0].sha===expected.parent&&fr.sole_parent===expected.parent);
 ck("actual_tree",commit.tree.sha===expected.tree&&fr.tree===expected.tree);
 ck("canonical_size_index_count",fr.leaves===3916&&fr.tracked_bytes===62297347&&fr.index.bytes===452026&&fr.index.sha256===expected.indexSha256);
 let rebuilt=base;for(const[a,b]of replacements){ck("one_source_literal",rebuilt.split(a).length===2);rebuilt=rebuilt.replace(a,b);}ck("all_source_changes_accounted",rebuilt===after&&replacements.length===13);
 for(const[a,b]of [...replacements].reverse()){ck("inverse_single_source_literal",rebuilt.split(b).length===2);rebuilt=rebuilt.replace(b,a);}ck("inverse_source_whole",rebuilt===base);
 ck("all20defs_whole",defs(base).length===20&&eq(defs(base),defs(after)));
 ck("source_strict_forward",d.applyStrictUnified(base,sourceDiff).text===after&&d.applyStrictUnified(base,sourceDiff).hunks===4);
 ck("source_strict_reverse",d.applyStrictUnified(after,sourceDiff,true).text===base);
 let j=journalBefore;for(const[a,b]of journalReplacements){ck("one_journal_literal",j.split(a).length===2);j=j.replace(a,b);}ck("journal_all_changes_accounted",j===journalAfter&&journalReplacements.length===5);
 ck("journal_strict_forward",d.applyStrictUnified(journalBefore,journalDiff).text===journalAfter&&d.applyStrictUnified(journalBefore,journalDiff).hunks===2);
 ck("journal_strict_reverse",d.applyStrictUnified(journalAfter,journalDiff,true).text===journalBefore);
 ck("old_runtime_host_preserved",q.host==="rog"&&q.host===old.host&&q.executable===old.executable&&q.cwd===old.cwd&&q.timeout_seconds===old.timeout_seconds&&q.timeout_seconds===360);
 ck("all_other_request_fields",eq(Object.keys(q),Object.keys(old))&&eq(q.args.slice(0,4),old.args.slice(0,4))&&eq(q.args.slice(7),old.args.slice(7))&&q.args[5]===old.args[5]);
 ck("source_self_SHA",q.args[4]===after&&q.args[6]===h.gitBlobMeta(after).sha256);
 ck("carrier_whole_unchanged",q.stdin===old.stdin&&q.args[8]===h.gitBlobMeta(q.stdin).sha256&&h.gitBlobMeta(q.stdin).bytes===79951);
 ck("request_pin_exact",eq(h.gitBlobMeta(requestRaw),expected.request));
 ck("fresh_key_bound_to_source",q.idempotency_key==="heptabao-native-jwt-pki-33b814c7-rog-source-20261106-r1-"+h.gitBlobMeta(after).sha256.slice(0,8)&&q.idempotency_key!==old.idempotency_key);
 ck("original_schema_for_existing_launcher",after.includes("'schema': 'heptabao.native-jwt-independent-source-stage.v1'"));
 ck("new_root_create_only",after.includes("ROOT = Path('"+expected.root+"')")&&after.includes("assert not os.path.lexists(ROOT)")&&after.includes("ROOT.mkdir(mode=0o700)"));
 ck("history_count3766",after.includes("'canonical_history_count': 3766")&&after.includes("assert len(added) == 14")&&after.includes("COMMIT).decode().strip() == '3766'"));
 const ancestry=after.slice(after.indexOf("ANCESTRY = ("),after.indexOf("\n)\n",after.indexOf("ANCESTRY = ("))+3);
 const pairs=[...ancestry.matchAll(/\('([0-9a-f]{40})', '([0-9a-f]{40})'\)/g)].map(m=>[m[1],m[2]]);
 ck("ancestry14",pairs.length===14&&pairs[0][0]===expected.commit&&pairs[0][1]===expected.parent&&pairs[1][0]===expected.parent&&pairs[1][1]==="e3afc157447d35c861f275a761b29da3e42aff8e");
 ck("chain_contiguous",pairs.every((x,i)=>i===pairs.length-1||x[1]===pairs[i+1][0]));
 ck("old495_anchor_same",pairs.at(-1)[1]==="49503322c7f446e5eb41e7744f1fdbd7f1192ecc");
 for(const token of ["STAGE_SECONDS = 300.0","str(OLD), str(SOURCE)], 180)","def owned(label, argv, limit=90, cwd=None):","assert len(carrier) <= 262144","process.wait(timeout=5)"]){ck("budget_literal:"+token,after.includes(token)&&base.includes(token));}
 ck("historical_controls_never_executed",after.includes("'historical_controls_executed': False")&&after.includes("'compiler_started': False")&&after.includes("'rust_tests_executed': False"));
 const oldBinding=bind(old),newBinding=bind(q);
 ck("positive_base_binding",oldBinding.sha256==="cf25a0596615538ba565454b443a661e50cb1daa6b80181e85c580d33e0b3f6b"&&oldBinding.native_fingerprint==="14926512845814584203");
 ck("new_typed_binding",newBinding.sha256===expected.binding.sha256&&newBinding.native_fingerprint===expected.binding.native_fingerprint);
 ck("journal_request_binding",journalAfter.includes(expected.request.blob)&&journalAfter.includes(expected.request.sha256)&&journalAfter.includes("bytes:"+expected.request.bytes));
 ck("journal_host_ROG_both",journalAfter.includes('a.host==="rog"')&&journalAfter.includes('v.job?.host==="rog"'));
 ck("journal_no_new_kinds",journalAfter.includes('q.limit===8192')&&journalAfter.includes('a.limit===16384')&&!journalAfter.includes('file_info')&&!journalAfter.includes('binary_read'));
 return {schema:"heptabao.native-jwt-pki.finalstage-source-checks.r1",status:"PASS_SOURCE_ONLY",checks:out.length,results:out,all_original_20_source_functions_byte_identical:true,source_hunks:4,journal_hunks:2,commit:expected.commit,tree:expected.tree,sole_parent:expected.parent,binding:expected.binding,Native:0,Cargo:0,productTests:0,stage_actual_qualification:false};
}