function verifyMac576StageBodyOriginalChain(files){
 const checks=[];function ok(n,x){if(!x)throw Error(n);checks.push(n);}
 function eq(a,b){return JSON.stringify(a)===JSON.stringify(b);}
 function pin(raw,p){const x=gitBlobMeta(raw);return x.blob===p.blob&&x.bytes===p.bytes&&x.sha256===p.sha256;}
 function mt(root,rows){return gitTreeAudit({sha:root,truncated:false,tree:rows.map(([path,raw])=>({path,mode:"100644",type:"blob",sha:gitBlobMeta(raw).blob}))});}
 const before=JSON.parse(files["STATE.before.original.json"]),s=JSON.parse(files["STATE.closed.original.json"]),idx=JSON.parse(files["CALL-INDEX.public.json"]),g=JSON.parse(files["ROOT-GO.original.json"]),a=JSON.parse(files["ACTUAL.public.json"]),r=JSON.parse(files["RELEASE.public.json"]);
 ok("before_INFO_state_exact",pin(files["STATE.before.original.json"],{blob:"6cacd6b522bd9e068fdd83f850c7efeafe342f3f",bytes:71983,sha256:"204c5a55372cdae4a93af785bf87c5ab45534177b90f23579e856ad232c8d22e"}));
 ok("after_body_state_exact",pin(files["STATE.closed.original.json"],{blob:"8d95f80103482864ae69b78f5faeb6345f053a1a",bytes:87192,sha256:"5eb87fffb99b08d12eebd5be12817d6578711196e7960674f523584b7219a14c"}));
 ok("separate_exact_BODY_GO",pin(files["ROOT-GO.original.json"],{blob:"69da452a806d8ac630058128fd3c663de5db7aaa",bytes:3150,sha256:"b3f57a8f85ac28cc7fa4f836dfcbedd36c2c2a8e3a331cb809c520649f58ce36"})&&g.scope==="stage_result_binary_read_only"&&g.maximum_binary_read_starts===1&&g.immutable_page_bytes===8192&&eq(s.stageResultBodyGO.pin,idx.rootGO)&&s.stageResultBodyGO.raw===files["ROOT-GO.original.json"]);
 ok("ten_original_calls_unchanged",Object.keys(before.calls).length===10&&Object.keys(s.calls).length===14&&Object.keys(before.calls).every(k=>eq(before.calls[k],s.calls[k])));
 ok("three_original_observers_unchanged",before.completedObservers.length===3&&s.completedObservers.length===4&&eq(before.completedObservers,s.completedObservers.slice(0,3)));
 ok("original_metadata_and_stage_preserved",s.job===before.job&&s.job==="1a1b2f48641-fc05-8042"&&eq(before.stageResultInfo,s.stageResultInfo)&&eq(before.stageResultInfoGO,s.stageResultInfoGO)&&s.goRaw===before.goRaw&&s.nextStdout===378&&s.nextStderr===0);
 ok("closed_once_body_lane",s.pending===null&&s.activeObserver===null&&s.paused===false&&s.nativeCallInFlight===false&&s.stageResultBodyStarted===true&&s.stageResultBody.whole===true);
 ok("four_call_shape",idx.calls.length===4&&eq(idx.calls.map(x=>x.kind),["operation_start","operation_status","operation_result","operation_result"]));
 const requests=[],native=[];let merkleTrees=0;
 for(const [i,cx] of idx.calls.entries()){
  const c=s.calls[cx.key],qraw=files[cx.files.request],iraw=files[cx.files.intent],araw=files[cx.files.armed],sdkraw=files[cx.files.sdk],nraw=files[cx.files.native];
  const sdk=JSON.parse(sdkraw),intent=JSON.parse(iraw),armed=JSON.parse(araw);requests.push(JSON.parse(qraw));native.push(parseLosslessIntegers(nraw));
  ok("call"+i+"_original_request",qraw===c.requestRaw&&pin(qraw,c.requestPin)&&eq(cx.request,c.requestPin));
  ok("call"+i+"_original_SDK_native",pin(sdkraw,c.sdkPin)&&pin(nraw,c.nativePin)&&sdk.isError===false&&sdk.content.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===nraw);
  ok("call"+i+"_accepted_once",c.called===true&&c.phase==="accepted"&&c.armed.whole===true&&c.sdkArchive.whole===true);
  const local={"request.json":qraw,"intent.json":iraw,"armed.json":araw};
  ok("call"+i+"_arm_whole",c.armed.entries.length===3&&Object.entries(local).every(([path,raw])=>{const z=c.armed.entries.find(x=>x.path===path);return z?.whole===true&&pin(raw,z);}));
  ok("call"+i+"_new_BODY_GO",eq(intent.rootGo,idx.rootGO)&&eq(armed.rootGo,idx.rootGO)&&intent.callKey===cx.key&&armed.callKey===cx.key&&intent.originalJob===s.job&&armed.originalJob===s.job&&intent.maximumNativeCalls===1&&armed.maximumNativeCalls===1&&intent.nativeNotYetCalled===true&&armed.nativeNotYetCalled===true);
  ok("call"+i+"_arm_Merkle",cx.armTree===c.armed.tree&&mt(cx.armTree,Object.entries(local)).leaf_count===3);merkleTrees++;
  ok("call"+i+"_SDK_Merkle",cx.sdkTree===c.sdkArchive.tree&&mt(cx.sdkTree,[["original.sdk.json",sdkraw]]).leaf_count===1);merkleTrees++;
 }
 const q=requests[0],o=idx.observer,ad=native[0],st=native[1],need=a.metadata;
 ok("exact_request_and_version",pin(files[idx.calls[0].files.request],g.exact_request)&&q.operation.tool==="binary_read"&&eq(Object.keys(q.operation.arguments).sort(),["expected_version","host","limit","offset","path"])&&q.operation.arguments.host==="mac"&&q.operation.arguments.path===need.path&&q.operation.arguments.offset===0&&q.operation.arguments.limit===7665&&q.operation.arguments.expected_version===need.version);
 ok("unique_original_admission",ad.reused===false&&ad.automatic_retry===false&&ad.tool_name==="binary_read"&&ad.operation_id===o.id&&o.id==="3bd47e557d29824b0b7f5b9cf4a272b98cefdb16ed650c06da7d9881572808fa");
 ok("same_ID_status_inactive",requests[1].operation_id===o.id&&st.operation_id===o.id&&st.async_state==="completed"&&st.owned_future_active===false&&st.payload_available===true&&st.result_state==="stored_observed"&&st.tool_name==="binary_read");
 const payload=files["payload.original.json"],pp=gitBlobMeta(payload);let bytes=[],cursor=0;
 for(const i of [2,3]){const pg=native[i],rq=requests[i],chunk=unb64(pg.data_base64);
  ok("page"+(i-2)+"_same_ID_contiguous",rq.operation_id===o.id&&rq.offset===cursor&&rq.limit===8192&&pg.operation_id===o.id&&pg.offset===cursor&&pg.next_offset===cursor+chunk.length&&chunk.length<=8192);
  ok("page"+(i-2)+"_immutable_identity",pg.immutable_snapshot===true&&pg.total_bytes===10663&&pg.result_sha256===pp.sha256&&pg.eof===(pg.next_offset===10663)&&encodeBase64Bytes(chunk)===pg.data_base64);
  bytes=bytes.concat(chunk);cursor=pg.next_offset;
 }
 ok("whole_original_payload",cursor===10663&&utf8Text(bytes)===payload&&pin(payload,o.payload)&&pp.bytes<=1048576);
 ok("payload_Merkle",mt(o.payloadTree,[["payload.original.json",payload]]).leaf_count===1);merkleTrees++;
 const env=parseLosslessIntegers(payload),raw=files["BODY.native.original.json"],n=parseLosslessIntegers(raw),body=files["stage-result.original.json"],bodyBytes=unb64(n.data_base64);
 ok("payload_exact_native",env.resultType==="complete"&&env.isError===false&&env.content.length===1&&env.content[0].text===raw&&pin(raw,o.nativeText));
 ok("body_native_exact_identity",n.path===need.path&&n.size===7665&&n.version===need.version&&n.offset===0&&n.next_offset===7665&&n.eof===true&&n.chunk_sha256===need.sha256);
 ok("body_decoded_bytes_and_SHA",bodyBytes.length===7665&&utf8Text(bodyBytes)===body&&encodeBase64Bytes(bodyBytes)===n.data_base64&&encodeBase64Bytes(utf8Bytes(body))===n.data_base64&&gitBlobMeta(body).sha256===need.sha256&&pin(body,idx.body.pin));
 ok("body_whole_Merkle",mt(idx.body.tree,[["stage-result.original.json",body]]).leaf_count===1);merkleTrees++;
 ok("recorded_closure",eq(o,s.completedObservers[3])&&o.completedInactive===true&&o.pages===2&&eq(idx.body,s.stageResultBody)&&s.stageResultBody.infoOperation===need.infoOperation&&s.stageResultBody.originalOperation===o.id);
 const b=parseLosslessIntegers(body);
 ok("stage_actual_candidate",b.status==="prepared"&&b.source_commit==="5767739cd25e458ac052dc8d384019bab8688ae0"&&b.source_tree==="42477d622dcf96e1e2b0929fe9ecc6b7ba484740"&&b.sole_parent==="02b90762b3d6cc8699cc88bffb6f76cb1f07e270");
 ok("whole_tree_index_actual",b.full_worktree.tracked_leaf_count===3932&&b.full_worktree.tracked_bytes===62553540&&b.full_worktree.full_leaf_index_sha256==="20ff64f463eb63a45a6dda92a17f23e814503b77ca5325d1b2c4a0ee4f4a5423"&&b.full_worktree.index_matches_tree===true&&b.full_worktree.all_tracked_worktree_blobs_and_modes_match===true);
 ok("canonical_history_independent_clone",b.canonical_history_count===3769&&b.full_strict_fsck_passed===true&&b.independent_git_directory===true&&b.no_alternates===true&&b.no_shared_object_links===true&&b.object_files_checked===208);
 ok("readonly_base_unchanged",eq(b.old_source_before,b.old_source_after)&&b.old_source_unchanged===true&&b.old_source_before.commit===b.sole_parent&&b.old_source_before.status===""&&b.old_source_before.tree==="9781e9615ac5fb068d217241c74bb54bf87942cf");
 ok("same_actual_bundle",b.canonical_bundle.bytes===5766&&b.canonical_bundle.sha256==="0683ebe3bcc1648387b5a891c958d1c855fef2aa6effa2c35910ffbfa3e6940a"&&b.canonical_bundle.header.header_sha256==="5599413cdc4c2e70cb471de0d407313f4d157a8bc6f0fba4c5e3ac1c458879c9"&&eq(b.canonical_bundle.header.prerequisites,[b.sole_parent])&&eq(b.canonical_bundle.header.heads,[[b.source_commit,"HEAD"]]));
 ok("original_31_children_closed",b.cleanup.length===31&&b.cleanup.every(x=>x.exit_code===0&&x.direct_child_reaped===true&&eq(x.remaining,[])&&!x.cleanup_error_type));
 ok("original_time_and_volume",b.within_new_stage_deadline===true&&b.elapsed_seconds_after_cleanup<300&&b.new_stage_total_seconds===300&&b.new_supervisor_seconds===360&&b.original_clone_cap_seconds===180&&b.original_git_leaf_cap_seconds===90&&b.external_volume_uuid==="FB804D1B-24CB-4D6E-AEA7-A9E180807758");
 ok("qualification_boundary",b.compiler_started===false&&b.controls_published===false&&b.server_started===false&&b.actual_build_qualification===false&&b.public_network_fetch_used===false&&r.current.laneReleased===true&&r.current.activeFutures===0&&a.normal117===false&&a.full34===false&&a.LAN===false);
 return {schema:"heptabao.mac576-stage-body.original-verification.v1",pass:true,check_count:checks.length,checks,originalNewCalls:4,originalObserver:1,immutablePages:2,merkleTrees,wholeBody:gitBlobMeta(body),actualStage:{commit:b.source_commit,tree:b.source_tree,leaves:3932,trackedBytes:62553540,history:3769,children:31,closed:true},NativeCallsPerformed:0,normal117:false,full34:false,LAN:false};
}