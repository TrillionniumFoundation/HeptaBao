function verifySnapshotStageFormat23(input) {
 const {texts,tables,canonical,parent,commits,pins,meta,apply,audit,binding}=input;
 const checks=[];function check(n,v){checks.push({name:n,pass:!!v});if(!v)throw Error(n);}
 function defs(s){const ls=s.split("\n"),out=[];for(let i=0;i<ls.length;i++)if(/^def [A-Za-z_]\w*\(/.test(ls[i])){
  let j=i+1;while(j<ls.length&&(!ls[j].trim()||/^[ \t]/.test(ls[j])))j++;
  out.push({name:ls[i].match(/^def ([A-Za-z_]\w*)/)[1],text:ls.slice(i,j).join("\n")});i=j-1;
 }return out;}
 function literalEdits(before,edits){let s=before;for(const e of edits){check("literal unique "+e.before.slice(0,70),s.split(e.before).length-1===(e.occurrences??1));s=s.split(e.before).join(e.after);}return s;}
 check("canonical root/Merkle",audit(canonical).root_sha==="f412f1524e08a56e23374897d329bfcf6295f4fe");
 check("parent root/Merkle",audit(parent).root_sha==="0506d30b02f5a2a2dc7d6364299365ae8d1d7cc7");
 const leaves=canonical.tree.filter(x=>x.type==="blob"),old=parent.tree.filter(x=>x.type==="blob"),om=new Map(old.map(x=>[x.path,x]));
 check("3928 current and3916 parent leaves",leaves.length===3928&&old.length===3916);
 const delta=leaves.filter(e=>!om.has(e.path)||om.get(e.path).sha!==e.sha||om.get(e.path).mode!==e.mode);
 check("exact23 delta/12 new/11 modified",delta.length===23&&delta.filter(x=>!om.has(x.path)).length===12&&delta.filter(x=>om.has(x.path)).length===11);
 check("3905 unchanged/no deletions",leaves.length-delta.length===3905&&old.every(e=>leaves.some(x=>x.path===e.path)));
 check("total tracked bytes",leaves.reduce((n,e)=>n+e.size,0)===62460068);
 const index=leaves.map(e=>e.path+"\0"+e.mode+"\0"+e.sha+"\0"+e.size+"\n").join("");
 check("exact full index",meta(index).sha256==="6baa9290fa3ee8f67bc22a77697d38a7ad1c4c776fc769f5f04ee645de204574"&&index===texts.index);
 check("candidate commit soleparent",commits.current.sha==="8c95fb0a8b2f61933a09b04986df2bafc9e7095c"&&commits.current.parents.length===1&&commits.current.parents[0].sha==="808e45d690f177ecb922e13d1ed19f7877156094"&&commits.current.tree.sha===canonical.sha);
 check("formatted JWT parent retains e3af ancestry",commits.parent.parents.length===1&&commits.parent.parents[0].sha==="e3afc157447d35c861f275a761b29da3e42aff8e"&&commits.parent.tree.sha===parent.sha);
 check("23 unique output basenames",pins.length===23&&new Set(pins.map(x=>x.name)).size===23);
 check("23 source total",pins.reduce((n,x)=>n+x.after.bytes,0)===1350582);
 for(const p of pins){const e=delta.find(x=>x.path===p.path);check("canonical source pin "+p.path,!!e&&e.sha===p.after.blob&&e.size===p.after.bytes);check("parent source pin "+p.path,p.before?om.get(p.path)?.sha===p.before.blob&&!p.path.includes(".."):!om.has(p.path));}
 for(const [label,b,a,d,n] of [
 ["stager",texts.stageBefore,texts.stageAfter,texts.stageDiff,7],
 ["formatter",texts.formatBefore,texts.formatAfter,texts.formatDiff,5],
 ["stage journal",texts.stageJournalBefore,texts.stageJournalAfter,texts.stageJournalDiff,2],
 ["format journal",texts.formatJournalBefore,texts.formatJournalAfter,texts.formatJournalDiff,2]]){
  check(label+" strict forward",apply(b,d)===a);check(label+" strict reverse",apply(a,d,true)===b);check(label+" exact hunks",(d.match(/^@@ /gm)||[]).length===n);
 }
 check("stager exact16 replacements",tables.stageEdits.length===16&&literalEdits(texts.stageBefore,tables.stageEdits)===texts.stageAfter);
 check("formatter exact12 replacements",tables.formatEdits.length===12&&literalEdits(texts.formatBefore,tables.formatEdits)===texts.formatAfter);
 const sd0=defs(texts.stageBefore),sd1=defs(texts.stageAfter);
 check("same20 source definitions",sd0.length===20&&sd1.length===20);
 for(let i=0;i<sd0.length;i++)check("source definition "+i+" "+sd0[i].name,sd0[i].name===sd1[i].name&&(sd0[i].name==="verify_full_worktree"?sd0[i].text.replaceAll("== 3916","== 3928")===sd1[i].text:sd0[i].text===sd1[i].text));
 const fd0=defs(texts.formatBefore),fd1=defs(texts.formatAfter);
 check("same5 formatter definitions",fd0.length===5&&fd1.length===5);
 for(let i=0;i<fd0.length;i++)check("formatter definition "+fd0[i].name,fd0[i].name===fd1[i].name&&fd0[i].text===fd1[i].text);
 const childStart=" for name in EXPECTED:\n  text=data[name]",childEnd=" sync_dir(ROOT/'candidate')";
 check("original formatter Popen/communicate/cleanup block unchanged",texts.formatBefore.slice(texts.formatBefore.indexOf(childStart),texts.formatBefore.indexOf(childEnd))===texts.formatAfter.slice(texts.formatAfter.indexOf(childStart),texts.formatAfter.indexOf(childEnd)));
 const sq0=JSON.parse(texts.stageRequestBefore),sq=JSON.parse(texts.stageRequest),fq0=JSON.parse(texts.formatRequestBefore),fq=JSON.parse(texts.formatRequest);
 check("stager exact carrier unchanged",sq.stdin===sq0.stdin&&meta(sq.stdin).blob==="f9166bc801c5b10e12b77274f485d27d61cd499a"&&meta(sq.stdin).bytes===79951);
 check("stager inline argv contract",sq.args.length===9&&JSON.stringify(sq.args.slice(0,4))==='["-I","-S","-B","-c"]'&&sq.args[4]===texts.stageAfter&&sq.args[5]==="--self-sha256"&&sq.args[6]===meta(texts.stageAfter).sha256&&sq.args[7]==="--carrier-sha256"&&sq.args[8]===meta(sq.stdin).sha256);
 check("stager exact host/cwd/executable/outer",sq.host===sq0.host&&sq.host==="rog"&&sq.cwd===sq0.cwd&&sq.executable===sq0.executable&&sq.timeout_seconds===360&&sq0.timeout_seconds===360);
 for(const x of ["STAGE_SECONDS = 300.0","def owned(label, argv, limit=90, cwd=None):","process.wait(timeout=5)","str(SOURCE)], 180)","sys.stdin.buffer.read(262145)","len(carrier) <= 262144","compile(raw, name, 'exec')","assert not os.path.lexists(ROOT)"])check("stager original guard "+x,texts.stageBefore.includes(x)&&texts.stageAfter.includes(x));
 check("stager no added execution primitive",(texts.stageAfter.match(/subprocess\.Popen/g)||[]).length===(texts.stageBefore.match(/subprocess\.Popen/g)||[]).length&&!/\bexec\(/.test(texts.stageAfter));
 check("formatter argv shape",fq.args.length===5&&fq.args[4]===texts.formatAfter&&JSON.stringify(fq.args.slice(0,4))==='["-I","-S","-B","-c"]');
 check("formatter original host/cwd/executable/outer",fq.host===fq0.host&&fq.host==="rog"&&fq.cwd===fq0.cwd&&fq.executable===fq0.executable&&fq.timeout_seconds===60&&fq0.timeout_seconds===60);
 const manifest=JSON.parse(fq.stdin);
 check("formatter carrier exact23",Object.keys(manifest).length===23&&fq.stdin===texts.formatManifest&&meta(fq.stdin).bytes<262144);
 function table(name){const l=texts.formatAfter.match(new RegExp("^"+name+"=(.*)$","m"));check("table "+name,!!l);return JSON.parse(l[1].replaceAll("None","null"));}
 const ex=table("EXPECTED"),sz=table("SOURCE_SIZES"),rel=table("SOURCE_RELATIVE"),caps=table("FORMAT_OUTPUT_CAPS");
 for(const p of pins){check("formatter exact mapping "+p.name,rel[p.name]===p.path&&sz[p.name]===p.after.bytes&&ex[p.name][0]===(p.before?.sha256??null)&&ex[p.name][1]===p.after.sha256&&manifest[p.name].bytes===p.after.bytes&&manifest[p.name].sha256===p.after.sha256);check("output cap "+p.name,caps[p.name]===(p.name==="service.rs"?655360:262144)&&caps[p.name]>p.after.bytes);}
 check("two source lookups only",(texts.formatAfter.match(/path=SOURCE\/SOURCE_RELATIVE\[name\]/g)||[]).length===2&&!texts.formatAfter.includes("path=SOURCE/name"));
 check("formatter original deadlines and config",texts.formatAfter.includes("START=time.monotonic(); LIMIT=50.0")&&texts.formatAfter.includes("timeout=min(10.0,remain())")&&texts.formatAfter.includes("'newRemoteSupervisorSeconds':60")&&texts.formatAfter.includes("FMT_SHA='5005cdcd39ded526dca8fa6ccd716d42fc7da54469034e055dbf54649bec7877'")&&texts.formatAfter.includes("FORMAT_CONFIG=b'edition = \"2024\"\\n'"));
 check("formatter original directchild group facts only",texts.formatAfter.includes("start_new_session=False")&&texts.formatAfter.includes("if child['pgid']!=child['supervisorGroup']"));
 check("formatter no Cargo/rustc/product call",!/\bcargo\b|\brustc\b/.test(texts.formatAfter)&&texts.formatAfter.includes("'compileExecuted':False"));
 for(const [kind,oldJ,newJ,edits,q] of [["stage",texts.stageJournalBefore,texts.stageJournalAfter,tables.stageJournalEdits,sq],["format",texts.formatJournalBefore,texts.formatJournalAfter,tables.formatJournalEdits,fq]]){
  check(kind+" journal exactly3 replacements",edits.length===3&&literalEdits(oldJ,edits)===newJ);
  check(kind+" journal exact new request pin",newJ.includes(meta(kind==="stage"?texts.stageRequest:texts.formatRequest).blob));
  check(kind+" original observer pages/cap",newJ.includes("q.limit===8192")&&newJ.includes("a.limit===16384")&&newJ.includes('a.host==="rog"'));
 }
 check("correct stdin helper positive stage",binding(sq0).sha256==="cf25a0596615538ba565454b443a661e50cb1daa6b80181e85c580d33e0b3f6b");
 check("correct stdin helper positive formatter",binding(fq0).sha256==="97b92b61a47d93f1a7a871d7ae2ce3bb08e3c26a67c2302947a464704a654839");
 return {schema:"heptabao.snapshot-source23-stage-format.SOURCE-checks.v1",checks,checkCount:checks.length,allPassed:checks.every(x=>x.pass),sourceCommit:commits.current.sha,stagerBinding:binding(sq),formatterBinding:binding(fq),pythonExecuted:false,rustfmtExecuted:false,cargoExecuted:false,runtimeCalls:0,stageActualQualified:false,formatterActualQualified:false};
}