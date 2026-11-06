function verify(files, hash) {
 const checks=[];
 function check(name,passed){checks.push({name,passed:!!passed});if(!passed)throw Error(name);}
 function metaEq(a,b){return a.blob===b.blob&&a.bytes===b.bytes&&a.sha256===b.sha256;}
 function lines(s){return s.match(/[^\n]*\n|[^\n]+$/g)||[];}
 function treeHash(rows) {
  const sorted=rows.slice().sort((a,b)=>{
   const x=hash.utf8(a.path+(a.type==="tree"?"/":"")),y=hash.utf8(b.path+(b.type==="tree"?"/":""));
   for(let i=0;i<Math.min(x.length,y.length);i++)if(x[i]!==y[i])return x[i]-y[i];
   return x.length-y.length;
  });
  const bytes=[];
  for(const r of sorted){bytes.push(...hash.utf8((r.type==="tree"?"40000":r.mode)+" "+r.path+"\0"));for(let i=0;i<40;i+=2)bytes.push(parseInt(r.sha.slice(i,i+2),16));}
  return hash.sha1(hash.utf8("tree "+bytes.length+"\0").concat(bytes));
 }
 const table=JSON.parse(files["FILES.public.json"]);
 const splices=JSON.parse(files["SOURCE.splice-inputs.json"]);
 const proof=JSON.parse(files["SOURCE-TREE.offline-proof.public.json"]);
 check("nine-files",table.files.length===9);
 check("seven-modified-two-new",table.files.filter(x=>x.before).length===7&&table.files.filter(x=>!x.before).length===2);
 for(const r of table.files){
  const n=r.path.split("/").pop(),text=files[r.after_packet_path];
  check("current-whole:"+n,typeof text==="string"&&metaEq(hash.meta(text),r.after));
  if(r.before)check("original-whole:"+n,metaEq(hash.meta(files[r.before_packet_path]),r.before));
 }
 for(const [label,v] of Object.entries(splices)){
  const slash=label.indexOf("/"),scope=label.slice(0,slash),n=label.slice(slash+1);
  const bp="historical-r1/"+(scope==="from-r1"?"candidate":"before")+"/"+n;
  const before=files[bp]??"",after=files["candidate/"+n];
  check("splice-before-pin:"+label,v.before?metaEq(hash.meta(before),v.before):before==="");
  check("splice-after-pin:"+label,metaEq(hash.meta(after),v.after));
  check("delta-archived-exact:"+label,files["diffs/"+label+".diff"]===v.delta);
  let a=lines(before);
  for(const e of v.edits.slice().reverse()){
   check("splice-exact-range:"+label+":"+e.start_line,a.slice(e.start_line,e.end_line).join("")===e.before);
   a.splice(e.start_line,e.end_line-e.start_line,...lines(e.after));
  }
  check("splice-whole-reconstruction:"+label,a.join("")===after);
 }
 const old=files["historical-r1/candidate/service_native_jwt_tests.rs"];
 const now=files["candidate/service_native_jwt_tests.rs"];
 const names=s=>[...s.matchAll(/#\[test\]\s*fn\s+(\w+)/g)].map(x=>x[1]);
 const oldNames=names(old),newNames=names(now);
 check("R1-whole23058-identical-prefix",hash.meta(old).bytes===23058&&now.startsWith(old));
 check("ten-original-fifteen-total",oldNames.length===10&&newNames.length===15&&new Set(newNames).size===15);
 check("old-test-names-order",JSON.stringify(newNames.slice(0,10))===JSON.stringify(oldNames));
 const regressions=JSON.parse(files["REGRESSIONS.public.json"]);
 check("all-fifteen-mapped",JSON.stringify(regressions.tests.map(x=>x.name))===JSON.stringify(newNames));
 check("all-test-execution-unobserved",regressions.Rust_tests_executed===0&&regressions.tests.every(x=>x.execution==="NOT_RUN"));
 const snOld=files["historical-r1/candidate/service_native_auth.rs"],snNew=files["candidate/service_native_auth.rs"];
 const before='|| matches!(&owner, NativeLocalOwner::Userpass(owner) if !owner.is_login()))';
 const after='|| matches!(&owner, NativeLocalOwner::Userpass(owner) if !owner.is_login())\n                || matches!(&owner, NativeLocalOwner::Jwt(owner) if !owner.is_login()))';
 check("only-native-service-selector-replacement",snOld.split(before).length===2&&snNew.split(after).length===2&&snNew.replace(after,before)===snOld);
 const oldTrees={};
 for(const n of ["root","crates","heptabao-server","src"]){
  const t=JSON.parse(files["historical-r1/canonical-trees/"+n+".json"]);
  check("canonical-tree-merkle:"+n,!t.truncated&&treeHash(t.tree)===t.sha);
  oldTrees[n]=t;
 }
 const next=JSON.parse(JSON.stringify(oldTrees));
 for(const row of table.files){
  const n=row.path.split("/").pop(),found=next.src.tree.filter(x=>x.path===n);
  check("canonical-leaf-membership:"+n,row.before?found.length===1&&found[0].sha===row.before.blob&&found[0].size===row.before.bytes:found.length===0);
  if(found.length){found[0].sha=row.after.blob;found[0].size=row.after.bytes;}
  else next.src.tree.push({path:n,mode:"100644",type:"blob",sha:row.after.blob,size:row.after.bytes});
 }
 next.src.sha=treeHash(next.src.tree);
 for(const [parent,name,child] of [["heptabao-server","src","src"],["crates","heptabao-server","heptabao-server"],["root","crates","crates"]]){
  const r=next[parent].tree.find(x=>x.path===name);check("canonical-tree-link:"+parent,r.sha===oldTrees[child].sha);
  r.sha=next[child].sha;next[parent].sha=treeHash(next[parent].tree);
 }
 const rows=t=>t.tree.map(x=>[x.path,x.mode,x.type,x.sha,x.size??null]).sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0);
 for(const n of ["root","crates","heptabao-server","src"]){
  const observed=JSON.parse(files["source-tree/derived-readback-"+n+".json"]);
  check("actual-source-tree-merkle:"+n,!observed.truncated&&treeHash(observed.tree)===observed.sha);
  check("independent-vs-actual-tree:"+n,observed.sha===next[n].sha&&JSON.stringify(rows(observed))===JSON.stringify(rows(next[n])));
 }
 check("expected-root-tree",next.root.sha===proof.expected_tree&&next.root.sha===table.source_tree);
 const commit=JSON.parse(files["commit/readback.original.json"]),intent=JSON.parse(files["commit/intent.original.json"]);
 check("commit-identity",commit.sha===table.source_commit);
 check("commit-one-parent",commit.parents.length===1&&commit.parents[0].sha===table.sole_parent);
 check("commit-tree",commit.tree.sha===table.source_tree);
 check("commit-message-exact",commit.message===intent.request.message);
 const exec=JSON.parse(files["verification/r2-source-executor.original.json"]);
 const originalResult=JSON.parse(exec.completion.output);
 check("original-local-237-actual-exit0",exec.completion.exit_code===0&&originalResult.check_count===237&&originalResult.status==="PASS_OFFLINE_SOURCE_DELTA_ONLY");
 check("original-zero-Rust-and-Runtime",originalResult.Runtime_calls===0&&originalResult.Rust_tests_executed===0&&originalResult.compiled===false);
 const recovery=JSON.parse(files["RECOVERY.public.json"]);
 check("no-ref-or-Runtime",recovery.ref_updates===0&&recovery.zero_Runtime===true);
 check("one-commit-submission",recovery.source_commit_submissions===1);
 return {status:"PASS_PURE_V8_SOURCE_FREEZE_ONLY",checks,check_count:checks.length,source_commit:commit.sha,source_tree:commit.tree.sha,sole_parent:commit.parents[0].sha,R1_tests_unchanged:10,new_test_source_count:15,compile:false,formatter:false,Runtime_calls:0,product_test_executions:0};
}
