function verifyFormatterSource(d,meta) {
 const checks=[]; const ok=(name,condition,details)=>{checks.push({name,passed:!!condition,...(details===undefined?{}:{details})});if(!condition)throw Error("check failed: "+name);};
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const one=(s,a,b)=>{if(s.split(a).length!==2)throw Error("replacement cardinality");return s.replace(a,b);};
 let rebuilt=d.before;
 for(const [i,p] of d.replacements.entries()){ok("replacement before unique "+i,rebuilt.split(p[0]).length===2);rebuilt=one(rebuilt,p[0],p[1]);}
 ok("ordered exact replacement reconstructs candidate",rebuilt===d.after);
 let reverse=d.after;for(const p of [...d.replacements].reverse())reverse=one(reverse,p[1],p[0]);
 ok("ordered inverse reconstructs original whole",reverse===d.before);
 function applyDiff(base,patch,inverse){
  const b=base.split("\n");if(b.pop()!=="")throw Error("base lacks final LF");
  const p=patch.split("\n");let out=[],pos=0,hunks=0;
  for(let i=2;i<p.length;){
   if(p[i]===""){i++;continue;}const m=/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(p[i++]);if(!m)throw Error("bad hunk");
   let start=Number(m[inverse?3:1])-1,count=Number(m[inverse?4:2]??1),used=0;
   if(start<pos)throw Error("overlap");out.push(...b.slice(pos,start));pos=start;
   while(i<p.length&&!p[i].startsWith("@@ ")){
    const x=p[i++];if(x==="")continue;let sign=x[0],line=x.slice(1);
    if(inverse)sign=sign==="+"?"-":sign==="-"?"+":sign;
    if(sign===" "||sign==="-"){if(b[pos++]!==line)throw Error("context mismatch");used++;}
    if(sign===" "||sign==="+")out.push(line);
    if(!" +-".includes(sign))throw Error("bad patch sign");
   }
   if(used!==count)throw Error("hunk count");hunks++;
  }
  out.push(...b.slice(pos));return {text:out.join("\n")+"\n",hunks};
 }
 const a=applyDiff(d.before,d.diff,false),b=applyDiff(d.after,d.diff,true);
 ok("strict diff forward whole",a.text===d.after);ok("strict diff reverse whole",b.text===d.before);
 ok("exact five hunks",a.hunks===5&&b.hunks===5);
 const defs=s=>{let m=[...s.matchAll(/^def ([a-z_]+)\([^\n]*\):\n/gm)];return m.map((x,i)=>({name:x[1],text:s.slice(x.index,(m[i+1]?.index??s.indexOf("report={",x.index)))}));};
 const beforeDefs=defs(d.before),afterDefs=defs(d.after);
 ok("ordered five original definitions",same(beforeDefs.map(x=>x.name),["remain","sha","read_pin","write_new","sync_dir"])&&same(beforeDefs.map(x=>x.name),afterDefs.map(x=>x.name)));
 for(let i=0;i<beforeDefs.length;i++)if(beforeDefs[i].name!=="read_pin")ok("whole function unchanged "+beforeDefs[i].name,beforeDefs[i].text===afterDefs[i].text);
 let rp=afterDefs[2].text.replace("def read_pin(p,expected_bytes=None):","def read_pin(p):").replace("  if expected_bytes is not None and a.st_size!=expected_bytes: raise RuntimeError('source_size_pin')\n","");
 ok("read_pin only expected size admission",rp===beforeDefs[2].text);
 const slice=(s,a,b)=>s.slice(s.indexOf(a),s.indexOf(b,s.indexOf(a)));
 ok("actual Popen/communicate/kill/reap block whole unchanged",slice(d.before,"  argv=[str(FMT)","  write_new(ROOT/(name+'.rustfmt.stderr')")===slice(d.after,"  argv=[str(FMT)","  if len(err)>65536:"));
 ok("original tool/config/children/deadline/stdio final tail whole unchanged",d.before.slice(d.before.indexOf(" if tool_before is not None:"))===d.after.slice(d.after.indexOf(" if tool_before is not None:")));
 const req=JSON.parse(d.request),oldReq=JSON.parse(d.originalRequest),m=JSON.parse(d.stdin),names=Object.keys(d.pins);
 ok("request exact source",req.args[4]===d.after);
 ok("request isolated Python argv original shape",same(req.args.slice(0,4),oldReq.args.slice(0,4))&&req.args.length===oldReq.args.length&&req.args.length===5);
 for(const k of ["host","executable","cwd","timeout_seconds"])ok("request unchanged "+k,req[k]===oldReq[k]);
 ok("request only original top fields",same(Object.keys(req),Object.keys(oldReq)));
 ok("request original supervisor sixty",req.timeout_seconds===60);
 ok("manifest exact stdin",req.stdin===d.stdin);
 ok("stdin within original 262144 and Native 1MiB",meta(d.stdin).bytes<=262144&&meta(d.stdin).bytes<=1048576);
 ok("ordered exact nine manifest names",same(Object.keys(m),names)&&names.length===9);
 const parseLiteral=(name)=>JSON.parse(d.after.match(new RegExp("^"+name+"=(.*)$","m"))[1].replaceAll("None","null"));
 const exp=parseLiteral("EXPECTED"),sizes=parseLiteral("SOURCE_SIZES"),caps=parseLiteral("FORMAT_OUTPUT_CAPS");
 ok("only nine fixed input/output names",same(Object.keys(exp),names)&&same(Object.keys(sizes),names)&&same(Object.keys(caps),names));
 let total=0,capsTotal=0;
 for(const n of names){
  const pin=d.pins[n];total+=pin.bytes;capsTotal+=caps[n];
  ok("source literal pin "+n,sizes[n]===pin.bytes&&exp[n][1]===pin.sha256);
  ok("stdin source literal pin "+n,same(m[n],{bytes:pin.bytes,sha256:pin.sha256}));
  ok("canonical exact source leaf "+n,d.canonicalLeaves.find(x=>x.path==="crates/heptabao-server/src/"+n)?.sha===pin.blob);
  ok("source first line compatible with existing output guard "+n,d.firstLines[n].length>0&&!d.firstLines[n].includes("\n"));
  ok("fixed output cap "+n,caps[n]===(n==="auth.rs"?524288:n==="service.rs"?655360:262144));
 }
 ok("source sum 1221466",total===1221466);ok("output cap sum 3014656",capsTotal===3014656);
 ok("three readonly source admission checks precede fresh root creation",d.after.indexOf("SOURCE.resolve(strict=True)")<d.after.indexOf("ROOT.mkdir")&&d.after.indexOf("original,pin=read_pin(path,SOURCE_SIZES[name])")<d.after.indexOf("ROOT.mkdir")&&d.after.indexOf("sha(original)!=EXPECTED[name][1]")<d.after.indexOf("ROOT.mkdir"));
 ok("finally source all full pin equality",d.after.includes("if sha(original)!=EXPECTED[name][1] or after_pin!=before_pin: raise RuntimeError('source_changed')")&&d.after.includes("report['sourceInputsAfter']==source_before"));
 ok("same absolute fifty-second clock",d.after.includes("START=time.monotonic(); LIMIT=50.0")&&d.after.match(/START=time\.monotonic\(\)/g)?.length===1);
 ok("original per child clipped ten",d.after.includes("timeout=min(10.0,remain())"));
 ok("original cleanup clipped five",d.after.includes("p.wait(timeout=min(5.0,remain()))"));
 ok("tool pinned original exact binary",d.after.includes("FMT_SHA='5005cdcd39ded526dca8fa6ccd716d42fc7da54469034e055dbf54649bec7877'"));
 ok("owned explicit config pinned",d.after.includes("FORMAT_CONFIG=b'edition = \"2024\"\\n'")&&d.after.includes("FORMAT_CONFIG_SHA='f32d2f03b3f4b1e295c79ed49d543f1205c7dac7c3dc74f05a5a27af4fea0584'"));
 ok("full canonical inventory no ambient rustfmt config",!d.canonicalLeaves.some(x=>/(^|\/)\.?rustfmt\.toml$/.test(x.path)));
 ok("fresh root no exist_ok",d.after.includes("ROOT.mkdir(mode=0o700);created=True")&&!d.after.includes("exist_ok"));
 ok("fixed source path",d.after.includes("SOURCE=Path('/home/qian-qi/heptabao-native-jwt-source-e3afc157-20261106-r1/source/crates/heptabao-server/src')"));
 ok("no source write target",!d.after.includes("write_new(SOURCE")&&!d.after.includes("cwd=str(SOURCE)"));
 ok("original no detached group",d.after.includes("start_new_session=False")&&d.after.includes("if child['pgid']!=child['supervisorGroup']:"));
 ok("original all Owned stopped and deadline exit",d.after.includes("if not report['withinDeadline'] or not report['allOwnedStopped']: report['status']='failed'")&&d.after.endsWith("sys.exit(0 if report['status']=='passed' and time.monotonic()-START<LIMIT else 1)\n"));
 ok("no Cargo or product subprocess",d.after.match(/subprocess\.Popen\(/g)?.length===1&&d.after.includes("argv=[str(FMT)")&&!d.after.includes("cargo"));
 ok("original once close remains for all original FD helpers",d.after.match(/finally: os\.close\(fd\)/g)?.length===3);
 const plan=d.outputPlan;ok("exact 38 outputs",plan.outputs.length===38);
 ok("all output paths fresh root",plan.outputs.every(x=>x.path.startsWith(d.scope.root+"/")));
 ok("all actual output identities unknown",plan.outputs.every(x=>x.actual_version===null));
 ok("success observation arithmetic explicit",total+2*capsTotal+9*65536+17+65536===7906155&&plan.success_observation_admission_budget_bytes===7906155);
 ok("source no actual stage or formatter",d.scope.stage_actual_closed===false&&d.scope.formatter_started===false&&d.scope.Runtime_GO===false);
 return {schema:"heptabao.native-jwt.format-nine.source-checks.v1",passed:true,checks:checks.length,results:checks,execution:"pure V8 only; lexical/whole-byte/diff/metadata checks, not Python AST or formatter",Runtime:0,Python:0,Rust:0};
}