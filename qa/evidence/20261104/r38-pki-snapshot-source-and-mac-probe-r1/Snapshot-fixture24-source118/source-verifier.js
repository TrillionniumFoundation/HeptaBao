function verifyNativeSnapshotForwardCompileSurface(f, H, D) {
 const checks=[]; function ck(name,yes){checks.push({name,passed:!!yes});if(!yes)throw new Error(name);}
 const canonical=f.canonical.tree.filter(x=>x.type==="blob"&&x.path.startsWith("crates/heptabao-server/src/")&&x.path.endsWith(".rs")).map(x=>({path:x.path,blob:x.sha,bytes:x.size})).sort((a,b)=>a.path.localeCompare(b.path));
 ck("canonical exact tree, untruncated",f.canonical.sha==="f412f1524e08a56e23374897d329bfcf6295f4fe"&&f.canonical.truncated===false);
 ck("finite inventory equals all canonical server Rust leaves",JSON.stringify(canonical)===JSON.stringify(f.inventory.map(({path,blob,bytes})=>({path,blob,bytes})).sort((a,b)=>a.path.localeCompare(b.path))));
 ck("906 leaves and exact 20918237 UTF8 bytes",f.inventory.length===906&&f.inventory.reduce((n,r)=>n+r.bytes,0)===20918237);
 const observed=[];
 for(const r of f.inventory){
   const t=f.cache[r.blob].text,m=H.meta(t);
   if(m.blob!==r.blob||m.bytes!==r.bytes)throw new Error("whole canonical blob mismatch "+r.path);
   const lines=t.split("\n"), hits=lines.flatMap((text,i)=>/NativeSnapshotAdmission|begin_native_snapshot_before/.test(text)?[{line:i+1,text}]:[]);
   if(hits.length)observed.push({...r,sha256:m.sha256,hits});
 }
 ck("all 906 whole Git objects verified",observed.length===33);
 ck("all 151 lexical references recorded exactly",observed.reduce((n,r)=>n+r.hits.length,0)===151&&JSON.stringify(observed)===JSON.stringify(f.hits));
 ck("exact 24 unique affected leaves",f.rows.length===24&&new Set(f.rows.map(r=>r.path)).size===24);
 for(const r of f.rows){
   const before=f.cache[r.before.blob].text,after=f.texts["after-"+r.name];
   const fd=f.texts["forward-"+r.name+".diff"],rd=f.texts["reverse-"+r.name+".diff"];
   ck(r.name+": before canonical member",canonical.some(x=>x.path===r.path&&x.blob===r.before.blob&&x.bytes===r.before.bytes));
   ck(r.name+": all four whole pins",JSON.stringify(H.meta(before))===JSON.stringify(r.before)&&JSON.stringify(H.meta(after))===JSON.stringify(r.after)&&JSON.stringify(H.meta(fd))===JSON.stringify(r.forward)&&JSON.stringify(H.meta(rd))===JSON.stringify(r.reverse));
   ck(r.name+": exact one unique insertion",before.split(r.anchor).length===2&&after===before.replace(r.anchor,r.anchor+r.insertion)&&after.split(r.insertion).length===2&&after.replace(r.insertion,"")===before);
   ck(r.name+": forward strict whole",D.apply(before,fd)===after);
   ck(r.name+": reverse strict whole",D.apply(after,rd)===before);
   ck(r.name+": exactly one hunk",r.hunks===1&&(fd.match(/^@@ /gm)||[]).length===1&&(rd.match(/^@@ /gm)||[]).length===1);
   ck(r.name+": native feature gated and explicit refusal",r.insertion.includes('#[cfg(feature = "native-v6-ha")]')&&r.insertion.includes("NativeSnapshotAdmission::Forward(_)")&&r.insertion.includes("Err(")&&!/\b(?:execute|forward_request|unwrap|expect|panic|sleep|spawn|retry)\s*\(/.test(r.insertion));
   ck(r.name+": test declarations unchanged",JSON.stringify(before.match(/#\[test\]/g)||[])===JSON.stringify(after.match(/#\[test\]/g)||[]));
 }
 ck("24 hunks / 65 inserted lines",f.rows.reduce((n,r)=>n+r.hunks,0)===24&&f.rows.reduce((n,r)=>n+r.insertion.split("\n").length-1,0)===65);
 ck("all nonmodified lexical files classified",f.classifications.filter(r=>r.disposition.kind!=="insert_explicit_forward_rejection").length===9&&f.classifications.every(r=>r.disposition.kind));
 const tr=f.rows.find(r=>r.name==="service_snapshot_transfer.rs");
 ck("only non-test filename insertion remains within original cfg-test Linux impl",f.cache[tr.before.blob].text.indexOf('#[cfg(all(test, target_os = "linux"))]')<f.cache[tr.before.blob].text.indexOf(tr.anchor)&&f.rows.every(r=>r.name.endsWith("_tests.rs")||r.name==="service_snapshot_transfer.rs"));
 ck("actual old HTTP forward handler whole unchanged",!f.rows.some(r=>r.name==="http_snapshot.rs")&&f.cache["c3740f0a2e55281b72a05f1b6c8e527618f3d65a"].text.includes("NativeSnapshotAdmission::Forward(plan)"));
 ck("source only, original frozen tree and budgets not modified",f.runtimeCalls===0&&f.rustCompile===false&&f.newCommit===null&&f.oldFrozenTreeModified===false);
 return {schema:"heptabao.native-snapshot-forward-exhaustive-source-checks.v1",passed:true,checks,checksPassed:checks.length,inventoryLeaves:906,inventoryBytes:20918237,hitFiles:33,hitLines:151,changedLeaves:24,hunks:24,addedLines:65,rustCompile:false,runtimeCalls:0,testExecutions:0,completeCompilerQualification:false};
}