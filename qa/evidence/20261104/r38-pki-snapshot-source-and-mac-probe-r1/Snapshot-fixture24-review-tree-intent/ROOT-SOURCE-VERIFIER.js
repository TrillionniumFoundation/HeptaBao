function reviewSnapshot24Arms(){
 const p=load("r34_packet_Snapshot24-forward-match-source118"),r=p.raw,plan=JSON.parse(r["PLAN.public.json"]),map=JSON.parse(r["24-leaf-patch-map.public.json"]),classes=JSON.parse(r["33-hit-classifications.public.json"]),idx=JSON.parse(r["906-canonical-source-index.public.json"]),ct=JSON.parse(r["canonical-tree.original.json"]),rootLeaves=load("r38_snapshot_freeze_expected_leaves"),checks=[];
 const ck=(name,v)=>{checks.push({name,passed:v===true});if(v!==true)throw Error(name);},eq=(s,p)=>{const m=gitBlobMeta(s);return m.blob===p.blob&&m.bytes===p.bytes&&m.sha256===p.sha256;},same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 ck("whole118_3734641",p.audit.whole&&p.audit.files===118&&p.audit.bytes===3734641);
 const leaves=ct.tree.filter(e=>e.type==="blob"),byPath=Object.fromEntries(leaves.map(e=>[e.path,e]));
 ck("original_full_tree_matches_root_frozen3928",ct.sha==="f412f1524e08a56e23374897d329bfcf6295f4fe"&&ct.truncated===false&&leaves.length===3928&&rootLeaves.length===3928&&rootLeaves.every(e=>byPath[e.path]?.sha===e.sha&&byPath[e.path]?.mode===e.mode));
 ck("exact8c95_parent_and_source_only",plan.parentCommit==="8c95fb0a8b2f61933a09b04986df2bafc9e7095c"&&plan.parentTree===ct.sha&&plan.parentCommitModified===false&&plan.newCommit===null&&plan.execution.runtimeCalls===0);
 const scoped=leaves.filter(e=>e.path.startsWith("crates/heptabao-server/src/")&&e.path.endsWith(".rs"));ck("canonical906_inventory_and_reported_whole",scoped.length===906&&idx.length===906&&new Set(idx.map(x=>x.path)).size===906&&idx.every(x=>byPath[x.path]?.sha===x.blob&&byPath[x.path]?.size===x.bytes&&x.wholeGitVerified===true)&&idx.reduce((n,x)=>n+x.bytes,0)===20918237);
 ck("exact33hit151reported_inventory",classes.length===33&&new Set(classes.map(x=>x.path)).size===33&&classes.reduce((n,x)=>n+x.hits.length,0)===151&&idx.filter(x=>x.lexicalHits>0).length===33&&idx.reduce((n,x)=>n+x.lexicalHits,0)===151);
 const names=new Set(map.map(x=>x.path));ck("24_unique_existing_leaves",map.length===24&&names.size===24&&map.every(x=>byPath[x.path]&&x.path==="crates/heptabao-server/src/"+x.name));
 let addedLines=0,addedBytes=0;const candidates={};
 for(const x of map){
  const a=r["before-"+x.name],b=r["after-"+x.name],d=r["forward-"+x.name+".diff"],rev=r["reverse-"+x.name+".diff"];
  ck("pins_"+x.name,eq(a,x.before)&&eq(b,x.after)&&eq(d,x.forward)&&eq(rev,x.reverse)&&byPath[x.path].sha===x.before.blob&&byPath[x.path].size===x.before.bytes);
  const fw=strictApply(a,d),bw=strictApply(b,d,true);ck("strict_one_hunk_"+x.name,fw.hunks===1&&fw.text===b&&bw.text===a&&strictApply(b,rev).text===a);
  ck("only_one_guarded_rejection_insert_"+x.name,a.split(x.anchor).length===2&&a.replace(x.anchor,x.anchor+x.insertion)===b&&x.insertion.startsWith(x.anchor.match(/^([ ]*)/)[1]+'#[cfg(feature = "native-v6-ha")]\n'));
  const diffLines=d.split("\n").slice(2);ck("no_removal_or_test_change_"+x.name,!diffLines.some(z=>z.startsWith("-"))&&x.insertion.includes("NativeSnapshotAdmission::Forward(_) =>")&&x.insertion.includes("Err(")&&!x.insertion.includes(".execute")&&!x.insertion.includes("Ok(")&&!x.insertion.includes("#[test]"));
  addedLines+=diffLines.filter(z=>z.startsWith("+")).length;addedBytes+=x.after.bytes-x.before.bytes;
  candidates[x.path]={path:x.path,text:b,blob:x.after.blob,bytes:x.after.bytes,sha256:x.after.sha256};
 }
 ck("24hunks65addedlines_zero_newtests",addedLines===65&&plan.change.newTests===0&&plan.change.leaves===24&&plan.change.removedLines===0);
 ck("23test_files_one_cfg_fixture",map.filter(x=>x.name.endsWith("_tests.rs")).length===23&&map.filter(x=>!x.name.endsWith("_tests.rs")).map(x=>x.name).join()==="service_snapshot_transfer.rs");
 const fixture=r["before-service_snapshot_transfer.rs"],fpos=fixture.indexOf("fn fixture_begin_native_snapshot_upload(");ck("fixture_was_test_linux_only",fpos>=0&&fixture.slice(fpos-120,fpos).includes('#[cfg(all(test, target_os = "linux"))]'));
 ck("enum_crate_private_forward_same_cfg",fixture.includes('pub(crate) enum NativeSnapshotAdmission {\n    Execute(RequestExecution),\n    Redirect(TrustedSnapshotOrigin),\n    #[cfg(feature = "native-v6-ha")]\n    Forward(Box<forward::SnapshotForwardPlan>),\n}'));
 for(const cl of classes){
  const name=cl.path.split("/").pop(),raw=r[(names.has(cl.path)?"before-":"reference-")+name],rows=raw.split("\n").flatMap((line,i)=>/NativeSnapshotAdmission|begin_native_snapshot_before/.test(line)?[{line:i+1,text:line}]:[]);
  ck("whole_actual_hit_lines_"+name,eq(raw,cl)&&same(rows,cl.hits)&&idx.find(x=>x.path===cl.path).lexicalHits===rows.length);
  ck("exact_disposition_membership_"+name,(cl.disposition.kind==="insert_explicit_forward_rejection")===names.has(cl.path));
 }
 const afterLeaves=rootLeaves.map(e=>candidates[e.path]?{...e,sha:candidates[e.path].blob}:e),merkle=rebuildTreeFromLeaves(afterLeaves),tracked=leaves.reduce((n,e)=>n+e.size,0)+addedBytes;
 const oldIndex=leaves.map(e=>e.path+"\0"+e.mode+"\0"+e.sha+"\0"+e.size+"\n").join("");
 ck("canonical_order_matches_prior_index",gitBlobMeta(oldIndex).sha256==="6baa9290fa3ee8f67bc22a77697d38a7ad1c4c776fc769f5f04ee645de204574");
 const indexText=leaves.map(e=>{const c=candidates[e.path];return e.path+"\0"+e.mode+"\0"+(c?c.blob:e.sha)+"\0"+(c?c.bytes:e.size)+"\n";}).join("");
 store("r38_snapshot24_reviewed_candidates",candidates);store("r38_snapshot24_expected_leaves",afterLeaves);store("r38_snapshot24_expected_tree",merkle);store("r38_snapshot24_expected_index",{text:indexText,...gitBlobMeta(indexText)});
 return {schema:"heptabao.root-source-review.snapshot24-exhaustive-refusal-arms.v1",status:"PASS_24_MINIMAL_TEST_FIXTURE_ARMS",checks,check_count:checks.length,source_packet:p.audit.tree,parent_commit:plan.parentCommit,parent_tree:ct.sha,changed_leaves:24,added_lines:addedLines,removed_lines:0,added_bytes:addedBytes,new_tests:0,product_HTTP_callback_changed:false,expected_tree:merkle.root_sha,leaves:3928,tracked_bytes:tracked,index:gitBlobMeta(indexText),root_independently_recomputed:{canonical906_inventory_metadata:true,whole33_hit_sources_and151_lines:true,all24_strict_forward_reverse_and_exact_insertion:true},author_finite_scan:{rust_leaves:906,bytes:20918237,unread_by_root_nonhit_source_bodies:873,scope:"Defining crate server/src only; not global Rust semantics."},limits:{formatted:false,compiled:false,component_tests_executed:false,real_Service_audit_failure_gates_executed:false,old_CLI_B04_B05_failure_unchanged:true,PKI33b_not_included:true,full_replacement:false,production_cutover:false,legacy_cleanup:false},root_Runtime_calls:0};
}