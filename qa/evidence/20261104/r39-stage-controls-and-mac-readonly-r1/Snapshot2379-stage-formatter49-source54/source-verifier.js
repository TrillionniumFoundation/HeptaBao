function verifySnapshotStageFormat49(input) {
 const {candidate:c,base:b,canonical,parent,currentCommit,parentCommit,serviceChanges,serviceNew,readPlan,meta,apply,audit,binding}=input;
 const checks=[];function check(name,value){checks.push({name,pass:!!value});if(!value)throw Error(name);}
 function defs(s){const ls=s.split("\n"),out=[];for(let i=0;i<ls.length;i++)if(/^def [A-Za-z_]\w*\(/.test(ls[i])){let j=i+1;while(j<ls.length&&(!ls[j].trim()||/^[ \t]/.test(ls[j])))j++;out.push({name:ls[i].match(/^def ([A-Za-z_]\w*)/)[1],text:ls.slice(i,j).join("\n")});i=j-1;}return out;}
 function literal(before,edits,label){let s=before;for(const [i,e] of edits.entries()){check(label+" literal "+i+" unique",s.split(e.before).length-1===(e.occurrences??1));s=s.split(e.before).join(e.after);}return s;}
 const ca=audit(canonical),pa=audit(parent);
 check("canonical root 358 Merkle",ca.root_sha==="fc933c18a0415730e3658c17ff021db9b2df2caa"&&ca.trees_verified===358);
 check("parent b694 root",pa.root_sha==="9c800e97a2527e7f01c3a4b0be594e6762f9581e");
 const leaves=canonical.tree.filter(x=>x.type==="blob"),old=parent.tree.filter(x=>x.type==="blob"),cm=new Map(leaves.map(x=>[x.path,x])),om=new Map(old.map(x=>[x.path,x]));
 check("3930 versus3928 leaves",leaves.length===3930&&old.length===3928);
 const modified=leaves.filter(x=>om.has(x.path)&&(om.get(x.path).sha!==x.sha||om.get(x.path).mode!==x.mode)),added=leaves.filter(x=>!om.has(x.path));
 check("exact6modified2new no delete",modified.length===6&&added.length===2&&old.every(x=>cm.has(x.path)));
 check("3922 unchanged",leaves.length-modified.length-added.length===3922);
 for(const x of serviceChanges){check("service change "+x.name,om.get(x.path)?.sha===x.before.blob&&cm.get(x.path)?.sha===x.after.blob&&cm.get(x.path).size===x.after.bytes);}
 for(const x of serviceNew){check("service new "+x.path,!om.has(x.path)&&cm.get(x.path)?.sha===x.after.blob&&cm.get(x.path).size===x.after.bytes);}
 check("tracked62486000",leaves.reduce((n,x)=>n+x.size,0)===62486000);
 const index=leaves.map(x=>x.path+"\0"+x.mode+"\0"+x.sha+"\0"+x.size+"\n").join("");
 check("index453627 exact",meta(index).bytes===453627&&meta(index).sha256==="0e35cb5c3192efd2b9ddecfdbbe78581dd65c8ceb1aee8577709f7d7f504b811"&&index===input.index);
 check("current exact commit soleparent",currentCommit.sha==="2379d02ba1ee3e88989815d5a978f998822bac4f"&&currentCommit.tree.sha===ca.root_sha&&currentCommit.parents.length===1&&currentCommit.parents[0].sha==="b6949024dc5d0922ca9b27d865923d28982286c3");
 check("b694 exact parent unaffected",parentCommit.sha==="b6949024dc5d0922ca9b27d865923d28982286c3"&&parentCommit.tree.sha===pa.root_sha&&parentCommit.parents.length===1&&parentCommit.parents[0].sha==="8c95fb0a8b2f61933a09b04986df2bafc9e7095c");
 const paths=new Set([...b.files.map(x=>x.path),...serviceChanges.map(x=>x.path),...serviceNew.map(x=>x.path)]);
 check("49 union",paths.size===49&&c.files.length===49&&new Set(c.files.map(x=>x.path)).size===49&&c.files.every(x=>paths.has(x.path)));
 check("49 unique basename",new Set(c.files.map(x=>x.name)).size===49);
 check("46 original order preserved",c.files.slice(0,46).every((x,i)=>x.path===b.files[i].path));
 check("5 intersection3 added",serviceChanges.filter(x=>b.files.some(y=>y.path===x.path)).length===5&&c.files.filter(x=>!b.files.some(y=>y.path===x.path)).length===3);
 check("49 exact total2023746",c.files.reduce((n,x)=>n+x.unformattedSource.bytes,0)===2023746);
 for(const x of c.files){
  const e=cm.get(x.path);
  check("canonical49 "+x.name,e?.sha===x.unformattedSource.blob&&e.size===x.unformattedSource.bytes&&e.mode==="100644");
 }
 for(const k of ["stage","formatter","stageJournal","formatterJournal"]){
  const x=c[k];check(k+" literal whole",literal(x.before,x.edits,k)===x.after);
  check(k+" exact predecessor",x.before===b[k].after);
  check(k+" strict forward",apply(x.before,x.diff)===x.after);
  check(k+" strict reverse",apply(x.after,x.diff,true)===x.before);
  const m=meta(x.after);check(k+" whole source pin",m.blob===x.pin.blob&&m.bytes===x.pin.bytes&&m.sha256===x.pin.sha256);
 }
 check("4-3-2-2 hunks",c.stage.hunks===4&&c.formatter.hunks===3&&c.stageJournal.hunks===2&&c.formatterJournal.hunks===2);
 check("12-10-3-3 literals",c.stage.edits.length===12&&c.formatter.edits.length===10&&c.stageJournal.edits.length===3&&c.formatterJournal.edits.length===3);
 const bs=defs(b.stage.after),as=defs(c.stage.after),bf=defs(b.formatter.after),af=defs(c.formatter.after);
 check("stage20 defs",bs.length===20&&as.length===20);
 for(let i=0;i<bs.length;i++){
  const a=bs[i],z=as[i];
  check("stage def "+i+" "+a.name,a.name===z.name&&(a.name==="verify_full_worktree"?a.text.replace("assert len(entries) == 3928 and len({x[0] for x in entries}) == 3928","assert len(entries) == 3930 and len({x[0] for x in entries}) == 3930")===z.text:a.text===z.text));
 }
 check("formatter5 defs",bf.length===5&&af.length===5);
 for(let i=0;i<bf.length;i++)check("formatter def "+i,bf[i].name===af[i].name&&bf[i].text===af[i].text);
 const sq=JSON.parse(c.stage.request),oldSq=JSON.parse(b.stage.request),fq=JSON.parse(c.formatter.request),oldFq=JSON.parse(b.formatter.request);
 check("stage exact request meta",meta(c.stage.request).blob===c.stage.requestPin.blob&&meta(c.stage.request).sha256===c.stage.requestPin.sha256);
 check("stage code argv",sq.args[4]===c.stage.after&&sq.args[sq.args.indexOf("--self-sha256")+1]===c.stage.pin.sha256&&sq.args[sq.args.indexOf("--carrier-sha256")+1]===meta(sq.stdin).sha256);
 check("stage original79951 stdin",sq.stdin===oldSq.stdin&&meta(sq.stdin).bytes===79951&&meta(sq.stdin).sha256==="85fd6e473ce1e231f1bcfbd2bcf2bef760e6a4e551040c55ee3274606acebb77");
 check("stage360 unchanged host/tool/cwd",sq.timeout_seconds===360&&sq.host===oldSq.host&&sq.executable===oldSq.executable&&sq.cwd===oldSq.cwd);
 const normalized={...sq,args:[...sq.args],idempotency_key:oldSq.idempotency_key};normalized.args[4]=oldSq.args[4];normalized.args[normalized.args.indexOf("--self-sha256")+1]=oldSq.args[oldSq.args.indexOf("--self-sha256")+1];
 check("stage only binding fields",JSON.stringify(normalized)===JSON.stringify(oldSq));
 check("stage source key",sq.idempotency_key==="heptabao-native-snapshot-forward-2379d02b-rog-source-20261106-r1-"+c.stage.pin.sha256.slice(0,8));
 check("stage 300/90/180 unchanged",c.stage.after.includes("STAGE_SECONDS = 300.0")&&c.stage.after.includes("def owned(label, argv, limit=90, cwd=None)")&&c.stage.after.includes("'original_clone_cap_seconds': 180")&&c.stage.after.includes("str(OLD), str(SOURCE)], 180)"));
 check("stage history3768/16",c.stage.after.includes("'canonical_history_count': 3768")&&c.stage.after.includes("assert len(added) == 16"));
 const ancestry=c.stage.after.match(/ANCESTRY = \(([\s\S]*?)\n\)/)[1].match(/^\s+\('[a-f0-9]{40}', '[a-f0-9]{40}'\),$/gm);
 check("16 exact ancestry",ancestry?.length===16);
 check("new source root",c.stage.after.includes("ROOT = Path('/home/qian-qi/heptabao-native-snapshot-forward-source-2379d02b-20261106-r1')"));
 const dict=name=>JSON.parse(c.formatter.after.match(new RegExp("^"+name+"=(.+)$","m"))[1].replace(/\bNone\b/g,"null"));
 const exp=dict("EXPECTED"),sizes=dict("SOURCE_SIZES"),caps=dict("FORMAT_OUTPUT_CAPS"),rel=dict("SOURCE_RELATIVE"),carrier=JSON.parse(fq.stdin);
 check("formatter exact request meta",meta(c.formatter.request).blob===c.formatter.requestPin.blob&&meta(c.formatter.request).sha256===c.formatter.requestPin.sha256);
 check("formatter code argv",fq.args.length===5&&fq.args.slice(0,4).join(",")==="-I,-S,-B,-c"&&fq.args[4]===c.formatter.after);
 check("formatter original60 host/tool/cwd",fq.timeout_seconds===60&&fq.host===oldFq.host&&fq.executable===oldFq.executable&&fq.cwd===oldFq.cwd);
 const fnormal={...fq,args:oldFq.args,stdin:oldFq.stdin,idempotency_key:oldFq.idempotency_key};check("formatter only bindings",JSON.stringify(fnormal)===JSON.stringify(oldFq));
 check("formatter manifest7155 within262144",meta(fq.stdin).bytes===7155&&meta(fq.stdin).bytes<=262144&&JSON.stringify(carrier)===JSON.stringify(c.formatter.manifest));
 check("formatter49 dictionary geometry",[exp,sizes,caps,rel,carrier].every(x=>Object.keys(x).length===49&&Object.keys(x).every(k=>c.files.some(f=>f.name===k))));
 for(const f of c.files)check("formatter49 pin "+f.name,exp[f.name][0]===(f.baseReference?.sha256??null)&&exp[f.name][1]===f.unformattedSource.sha256&&sizes[f.name]===f.unformattedSource.bytes&&caps[f.name]===(f.name==="service.rs"?655360:262144)&&rel[f.name]===f.path&&carrier[f.name].sha256===f.unformattedSource.sha256&&carrier[f.name].bytes===f.unformattedSource.bytes);
 check("formatter key",fq.idempotency_key==="heptabao-native-snapshot-forward-2379d02b-format-20261106-r1-"+c.formatter.pin.sha256.slice(0,8));
 check("formatter50 shared/10 child",c.formatter.after.includes("LIMIT=50.0")&&c.formatter.after.includes("min(10.0,remain())"));
 check("formatter exact source metadata",c.formatter.after.includes("'sourceCommit':'2379d02ba1ee3e88989815d5a978f998822bac4f'")&&c.formatter.after.includes("'sourceTree':'fc933c18a0415730e3658c17ff021db9b2df2caa'")&&c.formatter.after.includes("'sourceInputTotalBytes':2023746"));
 for(const kind of ["stage","formatter"]){const z=binding(JSON.parse(c[kind].request));check(kind+" typed digest/FP",z.sha256===c[kind].binding.sha256&&z.native_fingerprint===c[kind].binding.native_fingerprint);}
 check("stage journal exact request",c.stageJournal.after.includes(c.stage.requestPin.blob)&&c.stageJournal.after.includes(c.stage.requestPin.sha256));
 check("formatter journal exact request",c.formatterJournal.after.includes(c.formatter.requestPin.blob)&&c.formatterJournal.after.includes(c.formatter.requestPin.sha256));
 check("new slots independent",c.stageJournal.after.includes('const GF_SLOT = "snapshot_2379_rog_source_gitfirst_r1";')&&c.formatterJournal.after.includes('const GF_SLOT = "snapshot_2379_rog_formatter_gitfirst_r1";'));
 check("old observer caps unchanged",[c.stageJournal.after,c.formatterJournal.after].every(s=>s.includes("q.limit===8192")&&s.includes("a.limit===16384")&&s.includes("1048576")));
 check("198 future fixed output files",readPlan.files.length===196&&readPlan.authorized===false&&readPlan.allActualVersions===null&&readPlan.allReadsNeedSeparateExactGO===true);
 check("not runtime tested",input.newNativeCalls===0&&input.candidateFunctionCalls===0);
 return{schema:"heptabao.snapshot2379-stage-format49-source-checks.v1",pass:true,count:checks.length,checks,newNativeCalls:0,candidateFunctionCalls:0,RustFormatting:false,RustCompilation:false,testsExecuted:0};
}