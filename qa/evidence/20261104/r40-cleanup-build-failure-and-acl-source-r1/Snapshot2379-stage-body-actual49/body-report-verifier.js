function verifySnapshot2379OriginalBody(texts){
 const rows=[];const ck=(name,value)=>{rows.push({name,pass:!!value});if(!value)throw new Error(name);};
 const obj=parseLosslessIntegers;
 const canonical=x=>Array.isArray(x)?x.map(canonical):x&&typeof x==="object"?Object.fromEntries(Object.keys(x).sort().map(k=>[k,canonical(x[k])])):x;
 const eq=(a,b)=>JSON.stringify(canonical(a))===JSON.stringify(canonical(b));
 const index=obj(texts["INDEX.public.json"]),o=index.observer,info=obj(texts["info.original.json"]);
 ck("7-original-body-calls",index.calls.length===7);
 ck("one-binary-read-admission",index.calls.filter(c=>c.kind==="operation_start").length===1);
 ck("no-business-start",index.calls.every(c=>c.kind!=="process_start"));
 for(const c of index.calls){
  ck(c.key+":accepted-once",c.phase==="accepted"&&c.called===true);
  for(const k of ["request","sdk","native"]){const m=gitBlobMeta(texts[c.key+"."+k+".json"]);ck(c.key+":"+k+"-whole",eq(m,c[k]));}
  const sdk=obj(texts[c.key+".sdk.json"]),native=texts[c.key+".native.json"];
  ck(c.key+":SDK-native",sdk.isError===false&&sdk.content?.length===1&&sdk.content[0].type==="text"&&eq(obj(sdk.content[0].text),obj(native)));
  const intent=obj(texts[c.key+".intent.json"]),armed=obj(texts[c.key+".armed.json"]);
  ck(c.key+":intent",intent.callKey===c.key&&intent.kind===c.kind&&eq(intent.request,c.request)&&intent.maximumNativeCalls===1&&intent.nativeNotYetCalled===true);
  ck(c.key+":armed",armed.callKey===c.key&&eq(armed.request,c.request)&&armed.mayHaveDispatchedAfterThisCheckpoint===true);
  ck(c.key+":original-archives-whole",c.armed.whole===true&&c.sdkArchive.whole===true);
 }
 const prefix="snapshot-2379-report-body-";
 const q=obj(texts[prefix+"admit.request.json"]),a=obj(texts[prefix+"admit.native.json"]),st=obj(texts[prefix+"status.native.json"]),sq=obj(texts[prefix+"status.request.json"]);
 ck("exact-original-admission",gitBlobMeta(texts[prefix+"admit.request.json"]).blob==="df08f53171c4476a25e5813a4ec22fca3a716bdf");
 ck("fixed-binary-read",q.operation.tool==="binary_read"&&q.operation.arguments.host==="rog"&&q.operation.arguments.path===info.path&&q.operation.arguments.offset===0&&q.operation.arguments.limit===28399&&q.operation.arguments.expected_version===info.version);
 ck("original-operation-id",a.operation_id===o.id&&st.operation_id===o.id&&sq.operation_id===o.id&&a.reused===false);
 ck("completed-inactive",st.async_state==="completed"&&st.result_state==="stored_observed"&&st.owned_future_active===false&&st.payload_available===true&&o.completedInactive===true);
 let bytes=[],offset=0;
 for(let i=0;i<5;i++){
  const key=prefix+"page"+i,p=obj(texts[key+".native.json"]),r=obj(texts[key+".request.json"]),decoded=unb64(p.data_base64);
  ck(key+":request-geometry",r.operation_id===o.id&&r.offset===offset&&r.limit===8192);
  ck(key+":original-page",p.operation_id===o.id&&p.offset===offset&&p.next_offset===offset+decoded.length&&p.total_bytes===38316&&p.immutable_snapshot===true&&p.eof===(i===4)&&p.result_sha256===o.payload.sha256);
  bytes=bytes.concat(decoded);offset=p.next_offset;
 }
 const payload=texts["observer.payload.json"],envelope=obj(payload),native=texts["observer.native.json"];
 ck("five-pages-whole",offset===38316&&utf8Text(bytes)===payload&&eq(gitBlobMeta(payload),o.payload)&&o.pages===5);
 ck("original-payload-native",envelope.resultType==="complete"&&envelope.isError===false&&envelope.content?.length===1&&envelope.content[0].text===native&&eq(gitBlobMeta(native),o.nativeText));
 const b=obj(native),body=texts["stage.report.original.json"],bp=gitBlobMeta(body);
 ck("single-real-body-EOF",b.offset===0&&b.next_offset===28399&&b.size===28399&&b.eof===true&&b.path===info.path&&b.version===info.version);
 ck("decoded-full-original",utf8Text(unb64(b.data_base64))===body&&bp.bytes===28399&&bp.sha256===b.chunk_sha256&&bp.sha256===info.sha256&&info.size===28399);
 ck("whole-raw-original-pin",bp.blob==="630883993c821cd1bb33cab2ee31667064fa9bbf"&&bp.sha256==="733f77ea123b842e424f0b315d9ec910881b99e5844a4fd9ee51b651d5fb1955");
 const r=obj(body);
 ck("stage-schema-status",r.schema==="heptabao.native-snapshot-forward-independent-source-stage.v1"&&r.status==="prepared"&&r.host==="rog");
 ck("b694-canonical",r.source_commit==="2379d02ba1ee3e88989815d5a978f998822bac4f"&&r.source_tree==="fc933c18a0415730e3658c17ff021db9b2df2caa"&&r.sole_parent==="b6949024dc5d0922ca9b27d865923d28982286c3");
 ck("fixed-fresh-root",r.root==="/home/qian-qi/heptabao-native-snapshot-forward-source-2379d02b-20261106-r1"&&r.source===r.root+"/source");
 ck("actual-full-tree",r.full_worktree.tracked_leaf_count===3930&&r.full_worktree.tracked_bytes===62486000&&r.full_worktree.full_leaf_index_sha256==="0e35cb5c3192efd2b9ddecfdbbe78581dd65c8ceb1aee8577709f7d7f504b811"&&r.full_worktree.index_matches_tree===true&&r.full_worktree.all_tracked_worktree_blobs_and_modes_match===true);
 for(const k of ["full_strict_fsck_passed","independent_git_directory","no_alternates","no_shared_object_links","source_clean","old_source_unchanged","within_new_stage_deadline"])ck(k,r[k]===true);
 ck("actual-history-and-ancestry",r.canonical_history_count===3768&&r.new_commits_since_actual_495.length===16&&r.new_commits_since_actual_495[0]===r.source_commit&&r.new_commits_since_actual_495[1]===r.sole_parent);
 ck("old495-source-unchanged",eq(r.old_source_before,r.old_source_after)&&r.old_source_before.commit==="49503322c7f446e5eb41e7744f1fdbd7f1192ecc"&&r.old_source_before.tree==="1d4211f91e1b34a2ed087a3bbef2e2884bac88e9"&&r.old_source_before.status==="");
 ck("failed-observer-fences-unchanged",eq(r.failed_observer_before,r.failed_observer_after)&&Object.keys(r.failed_observer_before.files).length===12&&r.failed_observer_before.prior_failed_build_replayed===false);
 ck("original-budgets",r.new_stage_total_seconds===300&&r.new_supervisor_seconds===360&&r.original_git_leaf_cap_seconds===90&&r.original_clone_cap_seconds===180&&r.elapsed_seconds_after_cleanup>=0&&r.elapsed_seconds_after_cleanup<300);
 ck("actual-61-direct-cleanup",r.cleanup.length===61&&new Set(r.cleanup.map(x=>x.label)).size===61&&new Set(r.cleanup.map(x=>x.pid)).size===61);
 r.cleanup.forEach((row,i)=>ck("cleanup-"+row.label,row.label.startsWith(String(60-i).padStart(3,"0")+"-")&&row.direct_child_reaped===true&&row.exit_code===0&&row.remaining.length===0));
 const bundle=r.canonical_bundle;
 ck("actual-incremental-bundle-witness",bundle.path===r.root+"/control/canonical-native-snapshot-forward-2379d02b-from495.bundle"&&bundle.bytes===136231&&bundle.sha256==="04830729f13f635b6e91fa71fbdb14a343714ebc400ee968afed739906e0d92a"&&bundle.bytes<=4194304);
 ck("bundle-identity-reported",bundle.identity[4]===33152&&bundle.identity[5]===1&&bundle.identity[6]===bundle.bytes);
 ck("bundle-header-not-standalone",bundle.header.version===2&&eq(bundle.header.prerequisites,["49503322c7f446e5eb41e7744f1fdbd7f1192ecc"])&&eq(bundle.header.heads,[[r.source_commit,"HEAD"]]));
 ck("four-controls-inert",Object.keys(r.controls).length===4&&r.carrier_sha256==="85fd6e473ce1e231f1bcfbd2bcf2bef760e6a4e551040c55ee3274606acebb77"&&r.historical_controls_executed===false);
 for(const key of ["actual_build_qualification","candidate_build_qualification","compiler_started","server_started","formatter_executed","rust_tests_executed","production_changed"])ck("not-qualified-"+key,r[key]===false);
 ck("cumulative-slot-closure",index.originalSlotCallCount===17&&index.originalSlotObserverCount===4&&index.originalSlotPageCount===8&&index.ownerReleased===true);
 return {schema:"heptabao.snapshot-2379-original-report-finite-checks.v1",pass:true,count:rows.length,checks:rows,newNativeCalls:0,scope:"one original version-bound report read plus its finite report assertions; no independent bundle-body or raw 61 command-file reads; no Rust qualification"};
}