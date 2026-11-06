function verifyMac576StageInfoOriginalChain(files){
 const checks=[];function ok(n,v){if(!v)throw Error(n);checks.push(n);}
 function eq(a,b){return JSON.stringify(a)===JSON.stringify(b);}
 function pin(raw,p){const m=gitBlobMeta(raw);return m.blob===p.blob&&m.bytes===p.bytes&&m.sha256===p.sha256;}
 function merkle(sha,rows){return gitTreeAudit({sha,truncated:false,tree:rows.map(([path,raw])=>({path,mode:"100644",type:"blob",sha:gitBlobMeta(raw).blob}))});}
 const before=JSON.parse(files["STATE.before.original.json"]),s=JSON.parse(files["STATE.closed.original.json"]),idx=JSON.parse(files["CALL-INDEX.public.json"]),go=JSON.parse(files["ROOT-GO.original.json"]),actual=JSON.parse(files["ACTUAL.public.json"]),release=JSON.parse(files["RELEASE.public.json"]);
 ok("original_closed_stage_before",pin(files["STATE.before.original.json"],{blob:"c1ce8e3901479c1c99784569d3ea29ada9f35869",bytes:59491,sha256:"6bdb91838f2009cf45fb69a5dc2beab984b48f4ab894ef48ab0b93182d1b9bc1"}));
 ok("exact_closed_INFO_state",pin(files["STATE.closed.original.json"],{blob:"6cacd6b522bd9e068fdd83f850c7efeafe342f3f",bytes:71983,sha256:"204c5a55372cdae4a93af785bf87c5ab45534177b90f23579e856ad232c8d22e"}));
 ok("exact_INFO_GO",pin(files["ROOT-GO.original.json"],{blob:"a331c6278d4a539d67865f64db01aa27d9438f7a",bytes:2786,sha256:"76d824566717fa085c634513e6679fe2a79b36d46f863c6069e5344bbae477c6"})&&eq(s.stageResultInfoGO.pin,idx.rootGO)&&s.stageResultInfoGO.raw===files["ROOT-GO.original.json"]);
 ok("same_original_job_slot",s.job===before.job&&s.job==="1a1b2f48641-fc05-8042"&&go.slot==="successor576_mac_source_only_stage_gitfirst_r1");
 ok("original_seven_calls_unchanged",Object.keys(before.calls).length===7&&Object.keys(s.calls).length===10&&Object.keys(before.calls).every(k=>eq(before.calls[k],s.calls[k])));
 ok("original_two_observers_unchanged",before.completedObservers.length===2&&s.completedObservers.length===3&&eq(before.completedObservers,s.completedObservers.slice(0,2)));
 ok("original_stage_GO_and_cursors_unchanged",s.goRaw===before.goRaw&&eq(s.goPin,before.goPin)&&s.digest===before.digest&&s.fingerprint===before.fingerprint&&s.nextStdout===378&&s.nextStderr===0);
 ok("closed_INFO_lane",s.pending===null&&s.activeObserver===null&&s.nativeCallInFlight===false&&s.paused===false&&s.stageResultInfoStarted===true);
 ok("one_INFO_no_body",go.authorization==="GO"&&go.scope==="stage_result_file_info_only"&&go.maximum_file_info_starts===1&&go.binary_read_authorized===false&&s.stageResultBody===undefined&&idx.calls.length===3);
 const requests=[],native=[];let merkleTrees=0;
 for(const [i,row] of idx.calls.entries()){
  const c=s.calls[row.key],qraw=files[row.files.request],iraw=files[row.files.intent],araw=files[row.files.armed],sdkraw=files[row.files.sdk],nraw=files[row.files.native];
  const q=JSON.parse(qraw),intent=JSON.parse(iraw),armed=JSON.parse(araw),sdk=JSON.parse(sdkraw);requests.push(q);native.push(parseLosslessIntegers(nraw));
  ok("call"+i+"_request_pin",c.requestRaw===qraw&&pin(qraw,c.requestPin)&&eq(c.requestPin,row.request));
  ok("call"+i+"_SDK_native_raw_pin",pin(sdkraw,c.sdkPin)&&pin(nraw,c.nativePin)&&sdk.isError===false&&sdk.content.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===nraw);
  ok("call"+i+"_accepted_once",c.called===true&&c.phase==="accepted"&&c.armed.whole===true&&c.sdkArchive.whole===true);
  const locals={"request.json":qraw,"intent.json":iraw,"armed.json":araw};
  ok("call"+i+"_arm_whole_exact",c.armed.entries.length===3&&Object.entries(locals).every(([path,raw])=>{const e=c.armed.entries.find(x=>x.path===path);return e?.whole===true&&pin(raw,e);}));
  ok("call"+i+"_new_INFO_GO",eq(intent.rootGo,idx.rootGO)&&eq(armed.rootGo,idx.rootGO)&&intent.callKey===row.key&&armed.callKey===row.key&&intent.originalJob===s.job&&armed.originalJob===s.job&&intent.maximumNativeCalls===1&&armed.maximumNativeCalls===1);
  ok("call"+i+"_intent_before_dispatch_contract",intent.nativeNotYetCalled===true&&intent.lossOfAcknowledgmentNeverGrantsReplay===true&&armed.nativeNotYetCalled===true&&armed.mayHaveDispatchedAfterThisCheckpoint===true&&eq(intent.request,c.requestPin)&&eq(armed.request,c.requestPin));
  ok("call"+i+"_arm_Merkle",row.armTree===c.armed.tree&&merkle(row.armTree,Object.entries(locals)).leaf_count===3);merkleTrees++;
  ok("call"+i+"_SDK_Merkle",row.sdkTree===c.sdkArchive.tree&&merkle(row.sdkTree,[["original.sdk.json",sdkraw]]).leaf_count===1);merkleTrees++;
 }
 ok("exact_request_scope",pin(files["request.exact.json"],go.exact_request)&&files["request.exact.json"]===files[idx.calls[0].files.request]&&requests[0].operation.tool==="file_info"&&eq(Object.keys(requests[0].operation.arguments).sort(),["host","path"])&&requests[0].operation.arguments.host==="mac"&&requests[0].operation.arguments.path===go.metadata_guard.path);
 const o=idx.observer,ad=native[0],st=native[1],pg=native[2];
 ok("original_INFO_admission",ad.operation_id===o.id&&ad.operation_id==="a4d0d706264a5853d56306d21b1666527a5670a115edc5fd20d8405d000ff627"&&ad.tool_name==="file_info"&&ad.reused===false&&ad.automatic_retry===false);
 ok("same_ID_status_terminal",requests[1].operation_id===o.id&&st.operation_id===o.id&&st.async_state==="completed"&&st.owned_future_active===false&&st.payload_available===true&&st.result_state==="stored_observed"&&st.tool_name==="file_info");
 ok("same_ID_page_extent",requests[2].operation_id===o.id&&requests[2].offset===0&&requests[2].limit===8192&&pg.operation_id===o.id&&pg.offset===0&&pg.next_offset===606&&pg.total_bytes===606&&pg.eof===true&&pg.immutable_snapshot===true);
 const payload=files["payload.original.json"],bytes=unb64(pg.data_base64);
 ok("whole_payload_bytes_SHA",bytes.length===606&&utf8Text(bytes)===payload&&encodeBase64Bytes(bytes)===pg.data_base64&&pin(payload,o.payload)&&gitBlobMeta(payload).sha256===pg.result_sha256);
 ok("payload_Merkle",merkle(o.payloadTree,[["payload.original.json",payload]]).leaf_count===1);merkleTrees++;
 const envelope=parseLosslessIntegers(payload),nativeRaw=files["metadata.native.original.json"],v=parseLosslessIntegers(nativeRaw);
 ok("original_payload_native",envelope.resultType==="complete"&&envelope.isError===false&&envelope.content.length===1&&envelope.content[0].text===nativeRaw&&pin(nativeRaw,o.nativeText));
 ok("closed_observer_exact",eq(o,s.completedObservers[2])&&o.completedInactive===true&&o.pages===1);
 ok("exact_actual_metadata_identity",v.path===go.metadata_guard.path&&v.size===7665&&v.sha256==="c6051605fb282ed5e696e594a47f43ea501eb1484e5171adef6010d00e4865bb"&&v.version==="16777244:72764004:7665:1794003736370790810:1794003736370799227");
 ok("actual_mode_uid_gid_platform",v.mode===384&&v.metadata.mode===384&&v.metadata.uid===501&&v.metadata.gid===20&&v.metadata.link_count===1&&v.metadata.metadata_platform==="darwin"&&v.size<=65536);
 const parts=v.version.split(":"),full9=[parts[0],parts[1],String(v.metadata.uid),String(v.metadata.gid),String(32768|v.mode),String(v.metadata.link_count),parts[2],parts[3],parts[4]];
 ok("lossless_full9",parts.length===5&&parts.every(x=>/^[0-9]+$/.test(x))&&parts[2]===String(v.size)&&eq(full9,s.stageResultInfo.full9Strings));
 ok("recorded_actual_INFO",s.stageResultInfo.path===v.path&&s.stageResultInfo.size===v.size&&s.stageResultInfo.sha256===v.sha256&&s.stageResultInfo.version===v.version&&s.stageResultInfo.originalOperation===o.id&&eq(s.stageResultInfo.nativeText,o.nativeText)&&eq(actual.metadata,s.stageResultInfo));
 ok("release_preserves_body_unknown",release.current.laneReleased===true&&release.current.activeFutures===0&&release.newCalls===3&&release.newObservers===1&&release.bodyRead===false&&actual.bodyObserved===false&&actual.CargoStarted===false);
 return {schema:"heptabao.mac576-stage-info-original-verification.v1",pass:true,check_count:checks.length,checks,originalCalls:3,originalObservers:1,immutablePages:1,merkleTrees,metadata:s.stageResultInfo,priorStageCallsUnchanged:7,priorStageObserversUnchanged:2,NativeCallsPerformed:0,scope:"Exact original INFO metadata and closed transport only. No report body, controls, Cargo, normal117, full34 or LAN qualification."};
}