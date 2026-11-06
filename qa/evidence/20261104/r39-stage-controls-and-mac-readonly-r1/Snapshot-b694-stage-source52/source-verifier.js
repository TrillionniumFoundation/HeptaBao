function verifySnapshotStageFormat46(input) {
 const {texts,tables,canonical,parent,commits,pins,original23,fix24,meta,apply,audit,binding}=input;
 const checks=[];function check(name,value){checks.push({name,pass:!!value});if(!value)throw Error(name);}
 function defs(s){const lines=s.split("\n"),out=[];for(let i=0;i<lines.length;i++)if(/^def [A-Za-z_]\w*\(/.test(lines[i])){let j=i+1;while(j<lines.length&&(!lines[j].trim()||/^[ \t]/.test(lines[j])))j++;out.push({name:lines[i].match(/^def ([A-Za-z_]\w*)/)[1],text:lines.slice(i,j).join("\n")});i=j-1;}return out;}
 function literal(before,edits,label){let s=before;for(let i=0;i<edits.length;i++){const e=edits[i];check(label+" literal "+i+" unique",s.split(e.before).length-1===(e.occurrences??1));s=s.split(e.before).join(e.after);}return s;}
 const currentAudit=audit(canonical),parentAudit=audit(parent);
 check("canonical b694 root/Merkle",currentAudit.root_sha==="9c800e97a2527e7f01c3a4b0be594e6762f9581e");
 check("parent 8c95 root/Merkle",parentAudit.root_sha==="f412f1524e08a56e23374897d329bfcf6295f4fe");
 const leaves=canonical.tree.filter(e=>e.type==="blob"),old=parent.tree.filter(e=>e.type==="blob"),om=new Map(old.map(e=>[e.path,e])),cm=new Map(leaves.map(e=>[e.path,e]));
 check("both canonical trees3928",leaves.length===3928&&old.length===3928);
 const delta=leaves.filter(e=>!om.has(e.path)||om.get(e.path).sha!==e.sha||om.get(e.path).mode!==e.mode);
 check("exact24 modifications no add/delete",delta.length===24&&delta.every(e=>om.has(e.path))&&old.every(e=>cm.has(e.path)));
 check("3904 unchanged",leaves.length-delta.length===3904);
 check("tracked bytes62463643",leaves.reduce((n,e)=>n+e.size,0)===62463643);
 const index=leaves.map(e=>e.path+"\0"+e.mode+"\0"+e.sha+"\0"+e.size+"\n").join("");
 check("canonical index whole",index===texts.index&&meta(index).bytes===453379&&meta(index).sha256==="80a220f0a5d03d5b9cbe5cdb6a69b2e1c29d794f0abe367a98b5be096996e727");
 check("b694 exact commit soleparent",commits.current.sha==="b6949024dc5d0922ca9b27d865923d28982286c3"&&commits.current.parents.length===1&&commits.current.parents[0].sha==="8c95fb0a8b2f61933a09b04986df2bafc9e7095c"&&commits.current.tree.sha===canonical.sha);
 check("8c95 parent still808",commits.parent.sha==="8c95fb0a8b2f61933a09b04986df2bafc9e7095c"&&commits.parent.parents.length===1&&commits.parent.parents[0].sha==="808e45d690f177ecb922e13d1ed19f7877156094"&&commits.parent.tree.sha===parent.sha);
 const union=new Set([...original23.map(p=>p.path),...fix24.map(p=>p.path)]);
 check("46 fixed union23+24-1",original23.length===23&&fix24.length===24&&union.size===46&&pins.length===46&&pins.every(p=>union.has(p.path))&&new Set(pins.map(p=>p.path)).size===46);
 check("only overlap service_snapshot_transfer",original23.filter(p=>fix24.some(x=>x.path===p.path)).map(p=>p.name).join(",")==="service_snapshot_transfer.rs");
 check("46 unique basenames/two crates",new Set(pins.map(p=>p.name)).size===46&&pins.every(p=>p.name===p.path.split("/").at(-1)&&/^crates\/heptabao-(server|ha-service)\/src\/[^/]+\.rs$/.test(p.path)));
 check("46 exact total1931523",pins.reduce((n,p)=>n+p.unformattedSource.bytes,0)===1931523);
 for(const p of pins){
  const e=cm.get(p.path),a=original23.find(x=>x.path===p.path),f=fix24.find(x=>x.path===p.path);
  check("current canonical pin "+p.name,!!e&&e.sha===p.unformattedSource.blob&&e.size===p.unformattedSource.bytes);
  check("lineage and base reference "+p.name,p.original23===!!a&&p.exhaustive24===!!f&&(a?JSON.stringify(p.baseReference)===JSON.stringify(a.before):p.baseReference.blob===om.get(p.path).sha));
  check("current after selection "+p.name,f?p.unformattedSource.blob===f.after.blob&&p.unformattedSource.sha256===f.after.sha256:p.unformattedSource.blob===a.after.blob&&p.unformattedSource.sha256===a.after.sha256);
 }
 check("canonical delta is exact24",delta.every(e=>fix24.some(f=>f.path===e.path&&f.after.blob===e.sha)));
 for(const [label,b,a,d,rd,n,edits] of [
 ["stage",texts.stageBefore,texts.stageAfter,texts.stageDiff,texts.stageReverse,3,tables.stageEdits],
 ["formatter",texts.formatBefore,texts.formatAfter,texts.formatDiff,texts.formatReverse,3,tables.formatEdits],
 ["stage journal",texts.stageJournalBefore,texts.stageJournalAfter,texts.stageJournalDiff,texts.stageJournalReverse,2,tables.stageJournalEdits],
 ["format journal",texts.formatJournalBefore,texts.formatJournalAfter,texts.formatJournalDiff,texts.formatJournalReverse,2,tables.formatJournalEdits]]){
  check(label+" strict forward",apply(b,d)===a);check(label+" strict reverse",apply(a,d,true)===b&&apply(a,rd)===b);
  check(label+" exact hunks",(d.match(/^@@ /gm)||[]).length===n);
  check(label+" complete literal delta",literal(b,edits,label)===a);
 }
 check("stage11/format10/journals3+3",tables.stageEdits.length===11&&tables.formatEdits.length===10&&tables.stageJournalEdits.length===3&&tables.formatJournalEdits.length===3);
 const ds0=defs(texts.stageBefore),ds1=defs(texts.stageAfter);check("20 stage definitions whole",ds0.length===20&&ds1.length===20);
 for(let i=0;i<ds0.length;i++)check("stage definition "+i+" "+ds0[i].name,ds0[i].name===ds1[i].name&&ds0[i].text===ds1[i].text);
 const df0=defs(texts.formatBefore),df1=defs(texts.formatAfter);check("5 formatter definitions whole",df0.length===5&&df1.length===5);
 for(let i=0;i<df0.length;i++)check("formatter definition "+i+" "+df0[i].name,df0[i].name===df1[i].name&&df0[i].text===df1[i].text);
 const childStart=" for name in EXPECTED:\n  text=data[name]",childEnd=" sync_dir(ROOT/'candidate')";
 check("formatter original Popen/communicate/cleanup whole",texts.formatBefore.slice(texts.formatBefore.indexOf(childStart),texts.formatBefore.indexOf(childEnd))===texts.formatAfter.slice(texts.formatAfter.indexOf(childStart),texts.formatAfter.indexOf(childEnd)));
 const sq0=JSON.parse(texts.stageRequestBefore),sq=JSON.parse(texts.stageRequest),fq0=JSON.parse(texts.formatRequestBefore),fq=JSON.parse(texts.formatRequest);
 check("same historical79951 carrier",sq.stdin===sq0.stdin&&meta(sq.stdin).blob==="f9166bc801c5b10e12b77274f485d27d61cd499a"&&meta(sq.stdin).bytes===79951&&sq.stdin===texts.carrier);
 check("stage argv exact main contract",sq.args.length===9&&JSON.stringify(sq.args.slice(0,4))==='["-I","-S","-B","-c"]'&&sq.args[4]===texts.stageAfter&&sq.args[5]==="--self-sha256"&&sq.args[6]===meta(texts.stageAfter).sha256&&sq.args[7]==="--carrier-sha256"&&sq.args[8]===meta(sq.stdin).sha256);
 check("stage exact unchanged host/cwd/tool/outer360",sq.host===sq0.host&&sq.host==="rog"&&sq.cwd===sq0.cwd&&sq.executable===sq0.executable&&sq.timeout_seconds===360&&sq0.timeout_seconds===360);
 for(const x of ["STAGE_SECONDS = 300.0","def owned(label, argv, limit=90, cwd=None):","process.wait(timeout=5)","str(SOURCE)], 180)","sys.stdin.buffer.read(262145)","len(carrier) <= 262144","compile(raw, name, 'exec')","assert not os.path.lexists(ROOT)","canonical_raw = stable_read(canonical_path, 4 * 1024 * 1024)"])check("stage original guard "+x,texts.stageBefore.includes(x)&&texts.stageAfter.includes(x));
 check("stage ancestry exactly prepend one",texts.stageAfter.includes("assert len(added) == 15")&&texts.stageAfter.includes("'canonical_history_count': 3767")&&texts.stageAfter.includes("'rev-list', '--count', COMMIT).decode().strip() == '3767'"));
 check("no new stage subprocess or exec",(texts.stageAfter.match(/subprocess\.Popen/g)||[]).length===(texts.stageBefore.match(/subprocess\.Popen/g)||[]).length&&!/\bexec\(/.test(texts.stageAfter));
 check("formatter argv exact unchanged shape",fq.args.length===5&&fq.args[4]===texts.formatAfter&&JSON.stringify(fq.args.slice(0,4))==='["-I","-S","-B","-c"]');
 check("formatter host/cwd/tool/outer60",fq.host===fq0.host&&fq.host==="rog"&&fq.cwd===fq0.cwd&&fq.executable===fq0.executable&&fq.timeout_seconds===60&&fq0.timeout_seconds===60);
 const manifest=JSON.parse(fq.stdin);
 check("formatter carrier46 exact",Object.keys(manifest).length===46&&fq.stdin===texts.formatManifest&&meta(fq.stdin).bytes<262144);
 function table(name){const row=texts.formatAfter.match(new RegExp("^"+name+"=(.*)$","m"));check("formatter table "+name,!!row);return JSON.parse(row[1].replaceAll("None","null"));}
 const ex=table("EXPECTED"),sizes=table("SOURCE_SIZES"),rel=table("SOURCE_RELATIVE"),caps=table("FORMAT_OUTPUT_CAPS");
 for(const p of pins){
  check("format46 current input and reference "+p.name,rel[p.name]===p.path&&sizes[p.name]===p.unformattedSource.bytes&&ex[p.name][0]===(p.baseReference?.sha256??null)&&ex[p.name][1]===p.unformattedSource.sha256&&manifest[p.name].bytes===p.unformattedSource.bytes&&manifest[p.name].sha256===p.unformattedSource.sha256);
  check("format original output cap "+p.name,caps[p.name]===(p.name==="service.rs"?655360:262144)&&caps[p.name]>p.unformattedSource.bytes);
 }
 check("two readonly source lookups",(texts.formatAfter.match(/path=SOURCE\/SOURCE_RELATIVE\[name\]/g)||[]).length===2&&!texts.formatAfter.includes("path=SOURCE/name"));
 for(const v of ["START=time.monotonic(); LIMIT=50.0","timeout=min(10.0,remain())","'newRemoteSupervisorSeconds':60","FMT_SHA='5005cdcd39ded526dca8fa6ccd716d42fc7da54469034e055dbf54649bec7877'","FORMAT_CONFIG=b'edition = \"2024\"\\n'","start_new_session=False","if child['pgid']!=child['supervisorGroup']"])check("formatter inherited guard "+v,texts.formatBefore.includes(v)&&texts.formatAfter.includes(v));
 check("formatter no cargo/rustc execution",!/\bcargo\b|\brustc\b/.test(texts.formatAfter)&&texts.formatAfter.includes("'compileExecuted':False"));
 for(const [label,j,q] of [["stage",texts.stageJournalAfter,texts.stageRequest],["format",texts.formatJournalAfter,texts.formatRequest]]){
  check(label+" journal request exact pin",j.includes(meta(q).blob)&&j.includes(meta(q).sha256));
  check(label+" journal unchanged bounds",j.includes("q.limit===8192")&&j.includes("a.limit===16384")&&j.includes('a.host==="rog"'));
 }
 check("binding helper actual8c95 stage positive",binding(sq0).sha256==="041f9b79429e5825a1f8f5efae84a1bb0534316e76ffb344f0fbdb001cedc6b5");
 check("binding helper frozen8c95 formatter positive",binding(fq0).sha256==="7f12aee66e08455143565fba83e18f2c9339707e5f2f5acbb39d98ce1810a2a8");
 const sb=binding(sq),fb=binding(fq);
 return {schema:"heptabao.snapshot-source46-stage-format.SOURCE-checks.v1",checks,checkCount:checks.length,allPassed:checks.every(c=>c.pass),sourceCommit:commits.current.sha,stagerBinding:{sha256:sb.sha256,native_fingerprint:sb.native_fingerprint},formatterBinding:{sha256:fb.sha256,native_fingerprint:fb.native_fingerprint},stageActualQualified:false,formatterActualQualified:false,pythonExecuted:false,rustfmtExecuted:false,cargoExecuted:false,runtimeCalls:0};
}
