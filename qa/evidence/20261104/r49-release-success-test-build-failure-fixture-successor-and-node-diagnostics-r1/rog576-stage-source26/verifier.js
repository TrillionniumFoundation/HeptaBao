function verifyNext576StageSource(I,F) {
 const checks=[];const c=(name,ok)=>{checks.push({name,pass:!!ok});if(!ok)throw Error(name);};
 for(const [name,pin] of Object.entries(I.pins)){const m=gitBlobMeta(F[name]);c("whole "+name,m.blob===pin.blob&&m.bytes===pin.bytes&&m.sha256===pin.sha256);}
 const old=F["stager.before.py"],now=F["stager.after.py"],jo=F["journal.before.js"],jn=F["journal.after.js"];
 let derived=old;for(const e of I.stagerEdits){c("unique stage edit "+e.name,derived.split(e.before).length===2);derived=derived.replace(e.before,e.after);}c("exact full stage derivation",derived===now);
 let jderived=jo;for(const e of I.journalEdits){c("unique journal edit "+e.name,jderived.split(e.before).length===2);jderived=jderived.replace(e.before,e.after);}c("exact journal derivation",jderived===jn);
 for(const [tag,b,a] of [["stager",old,now],["journal",jo,jn]]){c(tag+" forward",snapshotApply(b,F[tag+".forward.diff"])===a);c(tag+" reverse",snapshotApply(a,F[tag+".forward.diff"],true)===b);c(tag+" reverse file",snapshotApply(a,F[tag+".reverse.diff"])===b);}
 function defs(raw){const ls=raw.split("\n"),out=[];for(let i=0;i<ls.length;i++){const m=/^def (\w+)\(/.exec(ls[i]);if(!m)continue;let e=i+1;while(e<ls.length&&(ls[e].trim()===""||/^\s/.test(ls[e])||/^#/.test(ls[e])))e++;out.push({name:m[1],text:ls.slice(i,e).join("\n")});}return out;}
 const od=defs(old),nd=defs(now);c("twenty original defs",od.length===20&&nd.length===20);
 for(let i=0;i<od.length;i++){c("def "+i+" "+od[i].name,od[i].name===nd[i].name&&nd[i].text===(od[i].name==="canonical_bundle_header"?od[i].text.replace("[OLD_COMMIT]","[BASE_COMMIT]"):od[i].text));}
 const q0=JSON.parse(F["request.before.json"]),q=JSON.parse(F["request.after.json"]),plan=JSON.parse(F["PLAN.public.json"]),cand=JSON.parse(F["candidate.root.public.json"]);
 c("fresh candidate actual root",cand.commit==="5767739cd25e458ac052dc8d384019bab8688ae0"&&cand.tree==="42477d622dcf96e1e2b0929fe9ecc6b7ba484740"&&cand.parent==="02b90762b3d6cc8699cc88bffb6f76cb1f07e270");
 c("3932 current leaves bytes index",now.includes("== 3932")&&now.includes("== 62553540")&&now.includes("'"+cand.fullLeafIndexSha256+"'"));
 c("17 links",(/ANCESTRY = \(\n([^]*?)\n\)/.exec(now)[1].match(/^    \('/gm)||[]).length===17);
 c("history3769",now.includes("'canonical_history_count': 3769")&&now.includes("COMMIT).decode().strip() == '3769'"));
 c("old495 binding retained",now.includes("OLD_COMMIT = '49503322c7f446e5eb41e7744f1fdbd7f1192ecc'")&&now.includes("result['old_source_after'] == before"));
 c("fresh clone base exact",now.includes("BASE = Path('/home/qian-qi/hb-02b90762-src-20261106-r1/source')")&&now.includes("str(BASE), str(SOURCE)], 180)"));
 c("base before exact",now.includes("assert result['clone_base_before'] == {'commit': BASE_COMMIT, 'tree': BASE_TREE, 'status': ''}"));
 c("base after exact",now.includes("assert result['clone_base_after'] == result['clone_base_before']"));
 c("one exact BASE bundle prerequisite",now.includes("assert prerequisites == [BASE_COMMIT]")&&now.includes("'HEAD', '^' + BASE_COMMIT)"));
 c("fresh path create-only retained",now.includes("assert not os.path.lexists(ROOT)")&&now.includes("ROOT.mkdir(mode=0o700)"));
 c("retained stage absolute budget",now.includes("STAGE_SECONDS = 300.0")&&now.includes("min(limit, stage_remaining())"));
 c("old payload exact whole",q.stdin===q0.stdin&&q.stdin===F["carrier.stdin.original.json"]&&gitBlobMeta(q.stdin).blob==="f9166bc801c5b10e12b77274f485d27d61cd499a");
 c("only request source/hash/key changes",JSON.stringify({...q,args:q0.args,idempotency_key:q0.idempotency_key})===JSON.stringify(q0));
 c("real inline argv and SHA",q.args.length===9&&q.args[4]===now&&q.args[6]===gitBlobMeta(now).sha256&&q.args[8]===gitBlobMeta(q.stdin).sha256&&q.args.slice(0,4).join(",")==="-I,-S,-B,-c");
 c("outer360 unchanged",q.timeout_seconds===360&&q.host==="rog"&&q.executable==="/usr/bin/python3"&&q.cwd==="/home/qian-qi");
 const binding=processStartBinding(q),bound=JSON.parse(F["typed-binding.public.json"]);
 c("typed native binding",binding.sha256===bound.sha256&&binding.native_fingerprint===bound.native_fingerprint);
 c("journal exact request identity",jn.includes(gitBlobMeta(F["request.after.json"]).blob)&&jn.includes(gitBlobMeta(F["request.after.json"]).sha256));
 c("fresh slot namespace",jn.includes('const GF_SLOT = "combined_5767739c_rog_source_gitfirst_r1";')&&jn.includes("/^heptabao-combined-5767739c-rog-source-observe-r1-/"));
 c("no implicit current test qualification",now.includes("'historical_controls_executed': False")&&now.includes("'candidate_build_qualification': False"));
 c("no actual bundle metadata invented",plan.bundle.actualBytes===null&&plan.bundle.actualSHA256===null&&plan.bundle.actualFull9===null);
 c("all original observer budgets unchanged",JSON.stringify(plan.budgets)===JSON.stringify(JSON.parse(F["base-stage.GO.public.json"]).budgets));
 return {schema:"next576-source-stage-verifier-r1",ok:true,total:checks.length,checks,sourceOnly:true,nativeCalls:0,PythonExecuted:false,actualStagePassed:false,actualBuildPassed:false,scope:"19 named source edits/7 hunks; 3 journal bindings/2 hunks; 19 defs byte-identical and one prerequisite literal"};
}
