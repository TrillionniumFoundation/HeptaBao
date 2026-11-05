function checkCLIStage(raws,tree,cli44,u,h,h1){
 const checks=[];function ck(ok,label){checks.push({label,ok:!!ok});if(!ok)throw Error(label);}
 const before=raws["before/stage.original.py"],after=raws["candidate/stage_current4e808_r4.py"],diff=raws["review/stage.review.diff"];
 function apply(original,patch,reverse=false){
  ck(original.endsWith("\n")&&patch.endsWith("\n"),"strict-newlines-"+reverse);
  const lines=original.slice(0,-1).split("\n"),d=patch.slice(0,-1).split("\n");let p=2,pos=0,out=[],hunks=0;
  ck(d[0].startsWith("--- ")&&d[1].startsWith("+++ "),"strict-header-"+reverse);
  while(p<d.length){const m=/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(d[p++]);ck(!!m,"strict-hunk-header-"+reverse+"-"+hunks);const start=Number(m[reverse?3:1])-1,oldCount=Number(m[reverse?4:2]??1),newCount=Number(m[reverse?2:4]??1);ck(start>=pos,"strict-hunk-order-"+reverse+"-"+hunks);out.push(...lines.slice(pos,start));pos=start;let oldN=0,newN=0;
   while(p<d.length&&!d[p].startsWith("@@ ")){const line=d[p++],kind=line[0],text=line.slice(1);ck([" ","+","-"].includes(kind),"strict-diff-line-"+reverse+"-"+p);const take=kind===" "||kind===(reverse?"+":"-"),put=kind===" "||kind===(reverse?"-":"+");if(take){ck(lines[pos]===text,"strict-context-"+reverse+"-"+pos);pos++;oldN++;}if(put){out.push(text);newN++;}}
   ck(oldN===oldCount&&newN===newCount,"strict-counts-"+reverse+"-"+hunks);hunks++;
  }out.push(...lines.slice(pos));return{raw:out.join("\n")+"\n",hunks};
 }
 const f=apply(before,diff),r=apply(after,diff,true);
 ck(f.raw===after&&r.raw===before&&f.hunks===3&&r.hunks===3,"three-hunks-forward-reverse-whole");
 const tail="UNTIL = 0\n";ck(before.split(tail).length===2&&after.split(tail).length===2&&before.slice(before.indexOf(tail))===after.slice(after.indexOf(tail)),"UNTIL-through-EOF-byte-identical");
 const defs=[...after.matchAll(/^[ \t]*def ([a-zA-Z0-9_]+)\(/gm)].map(m=>m[1]);ck(defs.length===18,"eighteen-original-definitions-in-unchanged-tail");
 function blocks(s){const head=s.slice(0,s.indexOf(tail)),matches=[...head.matchAll(/^([A-Z][A-Z0-9_]*) = /gm)],o={};for(let i=0;i<matches.length;i++)o[matches[i][1]]=head.slice(matches[i].index,i+1<matches.length?matches[i+1].index:head.length);return o;}
 const b=blocks(before),a=blocks(after),changed=Object.keys(b).filter(k=>b[k]!==a[k]),expected=["CONTROL","WORK","SOURCE","INCOMING","HEAD","TREE","PAYLOAD_SHA","PAYLOAD_BYTES","FILES","COPY","SOURCE_PINS","OLD_FENCES"];
 ck(JSON.stringify(changed)===JSON.stringify(expected)&&JSON.stringify(Object.keys(b))===JSON.stringify(Object.keys(a)),"only-twelve-top-bindings");
 const stagePin={bytes:u(after).length,sha256:h(u(after)),blob:h1([...u("blob "+u(after).length+"\0"),...u(after)])};
 ck(stagePin.bytes===23638&&stagePin.sha256==="87a9c2a7d1b9b4e789a4fda79fc9a89ba21657493707403f36cb891546e4a34f"&&stagePin.blob==="45ceb135688a2002e845f31e010ca5c010551517","exact-candidate-whole");
 const template=JSON.parse(raws["candidate/binding.partially-resolved.json"]),carrier=JSON.parse(raws["candidate/source-carrier.public.json"]),normal=JSON.parse(raws["references/normal5-actual-table.original.json"]);
 const base="/home/qian-qi/heptabao-ha-closure-20261103-r1",control=base+"/official271-native-cli-phaseb-r3-control-r4";
 ck(template.ready_for_readonly_prepare===false&&template.layout.control===control&&template.layout.work===base+"/official271-native-cli-phaseb-r3-live-r4"&&template.layout.source===base+"/normal-same-root-publication-validation-source-r1"&&template.layout.prepare===control+"/prepare-r1","template-exact-layout-not-ready");
 const fences=[...a.OLD_FENCES.matchAll(/"([^"]+)": "([0-9a-f]{64})",/g)].map(m=>({path:base+"/"+m[1],sha256:m[2]}));
 ck(fences.length===6&&JSON.stringify(fences)===JSON.stringify(template.old_fences.map(x=>({path:x.path,sha256:x.sha256}))),"six-old-fences-exact-order-and-SHA");
 const oldFences=[...b.OLD_FENCES.matchAll(/"([^"]+)": "([0-9a-f]{64})",/g)].map(m=>({path:base+"/"+m[1],sha256:m[2]}));
 ck(oldFences.length===4&&oldFences.every(x=>fences.some(y=>JSON.stringify(x)===JSON.stringify(y))),"original-four-old-fences-retained");
 const filePins=JSON.parse(/json.loads\(r'''([\s\S]+)'''\)/.exec(a.FILES)[1]);
 ck(Object.keys(carrier).sort().join("|")==="files|schema"&&carrier.schema==="heptabao.official271-native-cli-phaseb-r3.local-source-carrier.v1","carrier-shape");
 ck(Object.keys(filePins).length===8&&JSON.stringify(Object.keys(carrier.files).sort())===JSON.stringify(Object.keys(filePins).sort()),"eight-carrier-files");
 ck(u(raws["candidate/source-carrier.public.json"]).length===302459&&302459<1048576&&h(u(raws["candidate/source-carrier.public.json"]))==="a2f1d6b11c206b8b10ec896fd857207e38f72efac24bffd556fa94349bc34915","carrier-whole-and-original-cap");
 for(const [name,p]of Object.entries(filePins)){
  const actual=name==="binding.partially-resolved.json"?raws["candidate/binding.partially-resolved.json"]:raws["payload/"+name];
  ck(carrier.files[name]===actual&&u(actual).length===p.bytes&&h(u(actual))===p.sha256,"carried-whole:"+name);
 }
 const qaNames=[...a.QA_NAMES.matchAll(/"([^"]+\.py)"/g)].map(m=>m[1]);
 ck(qaNames.length===5&&a.QA_NAMES===b.QA_NAMES,"five-QA-original-order");
 for(const name of qaNames){const leaf=cli44.tree.find(x=>x.path==="candidate/"+name),raw=raws["payload/"+name],bytes=u(raw);ck(leaf?.type==="blob"&&leaf.mode==="100644"&&leaf.size===bytes.length&&leaf.sha===h1([...u("blob "+bytes.length+"\0"),...bytes]),"current-CLI44-QA-leaf:"+name);ck(template.qa_files[name].sha256===h(bytes)&&template.qa_files[name].bytes===bytes.length&&template.qa_files[name].path===control+"/qa/"+name,"QA-template-pin:"+name);}
 const copy=[...a.COPY.matchAll(/\("([^"]+)", (\d+), "([0-9a-f]{64})", (0o[0-7]+), (0o[0-7]+)\),/g)].map(m=>({name:m[1],bytes:Number(m[2]),sha256:m[3],source_mode:parseInt(m[4].slice(2),8),target_mode:parseInt(m[5].slice(2),8)}));
 ck(copy.length===3,"three-copy-roles");
 for(const [i,c]of copy.entries()){
  const n=normal.files.find(x=>x.name===c.name),target=Object.values(template.artifacts).find(x=>x.path===control+"/artifacts/"+c.name);
  ck(n?.path===base+"/normal-same-root-publication-shared-artifacts-r1/incoming/"+c.name&&n.bytes===c.bytes&&n.sha256===c.sha256&&n.mode===c.source_mode&&n.uid===1000&&n.nlink===1,"copy-actual-input:"+c.name);
  ck(target?.mode===c.target_mode&&target.bytes===c.bytes&&target.sha256===c.sha256&&c.source_mode===(i===0?320:256)&&c.target_mode===(i===0?320:384),"copy-source-target-modes:"+c.name);
 }
 for(const name of ["normal-release-tests-result.public.json","groups.json"]){const n=normal.files.find(x=>x.name===name),raw=raws["payload/"+name];ck(n.bytes===u(raw).length&&n.sha256===h(u(raw))&&n.mode===256,"payload-normal5-original:"+name);}
 function sourcePins(block){return [...block.matchAll(/"([^"]+)": \((\d+), "([0-9a-f]{64})"\),/g)].map(m=>({path:m[1],bytes:Number(m[2]),sha256:m[3]}));}
 const oldPins=sourcePins(b.SOURCE_PINS),newPins=sourcePins(a.SOURCE_PINS),srcTree=JSON.parse(raws["references/canonical-trees/src.json"]);
 ck(oldPins.length===5&&newPins.length===8&&oldPins.every(x=>newPins.some(y=>x.path===y.path)),"five-old-source-members-plus-three");
 for(const p of newPins){
  const path="references/canonical/"+p.path,leaf=tree.tree.find(x=>x.path===path),baseLeaf=srcTree.tree.find(x=>x.path===p.path.split("/").at(-1));
  ck(leaf?.sha===baseLeaf?.sha&&leaf.size===p.bytes&&baseLeaf.mode==="100644","canonical-member:"+p.path);
  if(raws[path]!==undefined)ck(h(u(raws[path]))===p.sha256,"whole-changed-source-pin:"+p.path);
 }
 ck(oldPins.filter(x=>x.path!=="crates/heptabao-server/src/service_no_forwarding_ha_tests.rs").every(x=>newPins.some(y=>JSON.stringify(x)===JSON.stringify(y))),"four-old-source-content-pins-unchanged");
 const req=JSON.parse(raws["requests/STAGE.REVIEW-ONLY.public.json"]);
 ck(req.host==="desktop"&&req.executable==="/usr/bin/python3.12"&&req.cwd===base&&req.timeout_seconds===330,"request-host-python-cwd-original-outer");
 ck(JSON.stringify(req.args)===JSON.stringify(["-I","-S","-B","-c",after,"--external-controller-sha256",stagePin.sha256]),"request-exact-main-interface");
 ck(req.stdin===raws["candidate/source-carrier.public.json"],"request-exact-stdin");
 ck(after.includes('parser.add_argument("--external-controller-sha256", required=True)')&&after.includes("UNTIL = started + 300_000_000_000"),"original-required-arg-and-300");
 ck(req.idempotency_key==="heptabao-official271-phaseb-4e808-local-stage-87a9c2a7-20261105-r4","review-only-fixed-key");
 return{schema:"heptabao.compatibility-peer-current-CLI-stage.v1",status:"PASS_NARROW_SOURCE_ONLY",checks_passed:checks.length,checks,changed_bindings:changed,unchanged_defs:defs,strict_hunks:3,original_runtime_tail_identical:true,source_modules_executed:0,author_AST_executed:false,Runtime_calls:0,new_stage_go:false,prepare_or_live_qualification:false};
}
