function verifyCurrentWalSource(a,get,apply,u,bs,h,s1,unb64){
 const checks=[];const ck=(n,v)=>{if(!v)throw Error(n);checks.push(n);};
 const pin=(raw,p)=>{const b=u(raw);return b.length===p.bytes&&h(bs(b))===p.sha256&&s1(u("blob "+b.length+"\0").concat(b))===(p.git_blob||p.blob);};
 const byBlob=blob=>{const r=a.records.find(x=>x.blob===blob);if(!r)throw Error("missingblob "+blob);return get(r.path);};
 const inv=JSON.parse(get("verification/strict-source-diffs.public.json"));let changed=0,same=0,added=0,hunks=0;
 ck("22 source inventory",inv.sources.length===22);
 for(const row of inv.sources){const after=byBlob(row.after.git_blob);ck("after."+row.name,pin(after,row.after));
  if(row.before){const before=byBlob(row.before.git_blob);ck("before."+row.name,pin(before,row.before));
   if(row.diff){const d=byBlob(row.diff.git_blob),r=apply(before,d);ck("diff."+row.name,pin(d,row.diff)&&r.text===after&&r.hunks===row.hunks);changed++;hunks+=r.hunks;}
   else{ck("unchanged."+row.name,before===after&&row.change==="byte_exact");same++;}
  }else{ck("qualified exact added library",row.after.git_blob==="c97d95b735bb4d76bf90d4c2b78d7b1bbcaa0920");added++;}
 }
 const ir=inv.inert,ir0=byBlob(ir.before.git_blob),ir1=byBlob(ir.after.git_blob),ird=byBlob(ir.diff.git_blob),iar=apply(ir0,ird);
 ck("inert 12-hunk whole reconstruction",pin(ir0,ir.before)&&pin(ir1,ir.after)&&pin(ird,ir.diff)&&iar.text===ir1&&iar.hunks===12);
 const reconstructed=[];
 for(const row of a.records.filter(x=>x.path.endsWith(".reconstruction.public.json"))){
  const m=JSON.parse(get(row.path));let raw="",offset=0;
  for(const p of m.orderedParts){const part=get(p.path);ck("part."+p.path,p.byteOffset===offset&&pin(part,p));raw+=part;offset+=u(part).length;}
  ck("whole reconstruction."+row.path,pin(raw,m.whole));reconstructed.push({path:row.path,whole:m.whole,parts:m.orderedParts.length});
  if(row.path==="verification/complete-static.input.public.json.reconstruction.public.json"){
   var input=JSON.parse(raw);
  }
 }
 ck("complete static input exists",!!input);
 ck("22 exact source inputs",Object.keys(input.sources).length===22);
 for(const [name,raw]of Object.entries(input.sources))ck("static source."+name,raw===get("sources/"+name));
 for(const [name,raw]of Object.entries(input.base))ck("static base."+name,raw===get("references/base-current/"+name));
 ck("base count21",Object.keys(input.base).length===21);
 for(const [name,raw]of Object.entries(input.documents))ck("static document."+name,raw===get("documents/"+name));
 ck("doc count8",Object.keys(input.documents).length===8);
 const carrier=input.inert;ck("inert source equals frozen source",carrier.args[4]===ir1);
 const payload=JSON.parse(carrier.stdin);
 ck("inert payload file count22",Object.keys(payload.files).length===22);
 for(const [name,b64]of Object.entries(payload.files))ck("carrier source."+name,bs(unb64(b64))===bs(u(input.sources[name])));
 for(const [name,b64]of Object.entries(payload.documents))ck("carrier document."+name,bs(unb64(b64))===bs(u(input.documents[name])));
 ck("inert payload doc count8",Object.keys(payload.documents).length===8);
 const rawCandidate=input.documents["candidate-current-manager-wal-r1.public.json"];
 const candidate=JSON.parse(rawCandidate);
 ck("candidate input exact",JSON.stringify(input.candidate)===JSON.stringify(candidate));
 const pins=JSON.parse(get("bindings/public-source-pins.public.json"));
 ck("sourcepin count22",Object.keys(pins).length===22);
 for(const [name,raw]of Object.entries(input.sources))ck("sourcepin."+name,pins[name]===h(bs(u(raw)))&&candidate.sourcePins[name]===pins[name]);
 ck("exact public WAL proof",h(bs(u(input.documents["proofs/registry-wal-r1.stdout.public.json"])))==="7d08a18c21a5d754ea9fbe7711e6315daf8fbd80c7b5a6937756fea7ba4d1c82");
 ck("exact public WAL authority",h(bs(u(input.documents["proofs/registry-wal-r1.authority.public.json"])))==="b564093e2300cdc44b2ae4724e869d5b24bfe3d94d269f8ebfa977e08b07505f");
 const selected=JSON.parse(get("verification/selected-admission-input.public.json"));
 ck("selected input exact entry and proof",selected.entry===input.sources["mac_current_capture_entry_wal_r1.py"]&&selected.proof===input.documents["proofs/registry-wal-r1.stdout.public.json"]&&selected.authority===input.documents["proofs/registry-wal-r1.authority.public.json"]);
 for(const [stem,count]of[["complete-static",82],["selected-admission",8]]){
  const raw=get("verification/"+stem+".stdout.public.json"),out=JSON.parse(raw),ex=JSON.parse(get("verification/"+stem+".executor.public.json"));
  ck(stem+" exact executor output",ex.exit_code===0&&ex.output===raw);
  ck(stem+" complete reported checks",out.passed===count&&out.checks.length===count&&out.checks.every(x=>x.passed===true));
 }
 const rt=input.runtime,arg=f=>rt.args[rt.args.indexOf(f)+1];
 ck("runtime original outer1080",rt.host==="mac"&&rt.executable==="/opt/homebrew/bin/python3"&&rt.timeout_seconds===1080&&rt.cwd==="/Users/qianqi");
 ck("runtime candidate exact",arg("--candidate-sha256")===h(bs(u(rawCandidate))));
 ck("runtime public source pins exact",bs(unb64(arg("--public-source-pins-base64")))===bs(u(get("bindings/public-source-pins.public.json"))));
 ck("runtime anchor exact",arg("--public-volume-anchor-base64")===payload.anchorBase64&&bs(unb64(payload.anchorBase64))===bs(u(get("bindings/public-t5-anchor.public.json"))));
 return{schema:"heptabao.root.mac-current-wal-source-review.v1",status:"SOURCE_BINDINGS_AND_TRANSCRIPTS_VERIFIED_NOT_HOST_GO",checks_passed:checks.length,checks,packet:{tree:a.tree,files:a.files,bytes:a.bytes,merkle_trees:a.merkle.trees_verified},strict:{changed,same,added,source_hunks:hunks,inert_hunks:12},reconstructed,author_static_checks:82,author_selected_components:8,root_reexecuted_components:false,current_private_capture_executed:false,successor_qualification_transferred:false};
}
