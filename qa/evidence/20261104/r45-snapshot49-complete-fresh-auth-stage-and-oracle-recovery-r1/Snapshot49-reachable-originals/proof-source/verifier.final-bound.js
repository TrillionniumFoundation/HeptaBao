function verifyFormatted23ActualEngine(input, mode) {
 const SLOT="snapshot_2379_formatted23_readonly_gitfirst_r1";
 const FAILED="sf23-r1-f10-info-p0",RECOVERY=FAILED+"-recovery1",GIT_REC="sf23-r1-f07-b01-p0";
 const FAILED16="sf23-r1-f16-b00-p0",RECOVERY16=FAILED16+"-recovery1";
 const FAILED20="sf23-r1-f20-b00-p3",RECOVERY20=FAILED20+"-recovery1";
 const BODY20_RECOVERY_BINDING = {"go":{"blob":"41b9b735676e83d5b8c779ec00950fe030ff59e2","bytes":4567,"sha256":"9bf988308ccecc4dcff6fb452c4c77d852477c0c56bbbae87778a9dd03a49164"},"armTree":"104a0888d861282ca32cd3589635099b7d6632fb","armEntries":[{"path":"armed.json","blob":"34fe1839761175663993bbc8dea6f1d28ca36b3a","bytes":2333,"sha256":"82ef255e085076d1879ae89ea403035f7c48b15cd58592e2d72e258e551d39d5"},{"path":"intent.json","blob":"9ecf8291f320a1e07e83566825fdbe69b72c1b3b","bytes":2259,"sha256":"8fa22c5d04a9e92e0a40574672effb77dea59c2cc7bb585949a56e5f66d7d924"},{"path":"original-failed-call.json","blob":"4911defb28498915832ce3202103a7f6541bcac7","bytes":2070,"sha256":"782cd589df161244a0c0e0452f0ed8ab54f274cb536c58ff04d2f7a606becd46"},{"path":"request.json","blob":"1ca4e7299a552ab1594a1c26a02909a56e808e5e","bytes":126,"sha256":"3e7d6ccdd56784adfb70e42d88e4bd0ccf122e6de69d6b28ffd403165b77084a"}],"sdk":{"blob":"b19d6f7b6275e4526a33bb2a9556d4acf5fd5d29","bytes":19660,"sha256":"7b5a4db3560af72e87cbb982c6cd402233de6e0525860729f90145006fb05fb4"},"native":{"blob":"c364975874bbe9285a54f3bf883fd9bce05b8431","bytes":19489,"sha256":"c3c6bc7e88208ff2e1c4bea134dd4842eeaa21403b9db376971fc9bc45adf259"}}; // Future actual root GO/4-leaf arm/SDK binding only; no qualification while null.
 const BODY16_RECOVERY_BINDING = {"go":{"blob":"748716dc20b7d61a5fe773aaefc44ba9d4a9ddac","bytes":3876,"sha256":"affe4439b1649e907d1df5be0a4bed06a0ed59d27ae6e8dba14d91d4527ca593"},"armTree":"c370ed05be5ee262616c26daeee0beca0f4f5a13","armEntries":[{"path":"armed.json","blob":"398925095ce1edbcaa677907d09756b52eff83ca","bytes":1969,"sha256":"397eb8a1d2cc54753c134b9350edf7ad6ad56e5fa4f3b60204218e5ce2439bbd"},{"path":"intent.json","blob":"494505a388d443199fe9825e0583f8409cd9cdec","bytes":1895,"sha256":"c358d981c725c5021598dffa3177e5ae66b9b10ac0532901abd5be02f554b45a"},{"path":"original-failed-call.json","blob":"593f02daca6b8ac9511ed460af8919eed0b7bc32","bytes":2066,"sha256":"f70e2ae9bac4c87df0faac3a2fbd4e507a64db29d4d1b010b3771028465d7776"},{"path":"request.json","blob":"bfd96536330ccc3704a2ba596203edf3680a0702","bytes":122,"sha256":"ede3d944c75b34dbcc7cf3b644e9d8374496f8348d375e792d565141c92b2ef5"}],"sdk":{"blob":"2776bd5f05ab70da6d48606a1ab96b3252350cd7","bytes":22705,"sha256":"23fbc257b38be670a42141a26baed551a8ba3b1a3e2c9ca73ffb4762637fa805"},"native":{"blob":"569162defbc1fc5340e8da3beb11c26cde9b222c","bytes":22534,"sha256":"0f9937a879ceade2af04e05595f7a9bb16b9bbd0f12c9b55f99f975513666d67"}}; // Literal-only actual GO/arm/SDK binding after successful original recovery; until then this successor cannot qualify any input.
 const pins={
  journal:{blob:"a154e8b3e4bbce818471dd10fe434e4ded570c8b",bytes:79062,sha256:"8ad44f98b72e37ae7037451eada7cf9c5616609ec5123f7bc8cef3b4fcf4f9d9"},
  originalGO:{blob:"25ea12c4406a12ba5ce263b10a2723f73276d74b",bytes:14304,sha256:"3a763b6eeef5ace6f210d059d860ad315fc8302a5326d499a24ca16a7dbf05f1"},
  report:{blob:"b99fe67dc434a0d856a8caff6fe75de597d6d5ed",bytes:118925,sha256:"5755903ce5696b6745d7af2b27a69a30e0d001697eeb85282df75eb25cea40d8"},
  formatterGO:{blob:"49ed50b1cf0b1c6e7fb4ebac16ebb8d17d9cef20",bytes:22959,sha256:"219195a5c8323d35902184e57c7d4109dc8036a27fc39e50988e7759b06a2a7e"},
  failedRequest:{blob:"916332b53c58b018404b00324cb5aa1588975b52",bytes:121,sha256:"17f7fcfad72f016c11d8d7b0be379eb4f2043b20b9c33cc4698bb78d74173edd"},
  failedSDK:{blob:"923d6b0480a7a2c63d80ec91ffbc84d0dc6a4011",bytes:248,sha256:"cddbef2d67b84c98a2ab46bce54a59d2afcbd0e7d00254ba865eded8722ad173"},
  failedCall:{blob:"2b64176574dbb70da660cb4ec8eee657b1969eae",bytes:2065,sha256:"1d91200c87b3f9ae88631471212dae416cf697d341d0436ed7b8ea1db9ebc84b"},
  recoveryGO:{blob:"d5b3035c956e70c5d2ecdb697f0961d592011b86",bytes:3263,sha256:"f420b012de3dba1c77b3ad36930c53f8e4e6b62de40172170484f433859daf4d"},
  gitGO:{blob:"cfe99cdee399d804d29acc17b6c83b0495774f89",bytes:4073,sha256:"ea672ce90ece5f7f6a69f6f6b2c8c33b006fb3aa3bf210a004b4f64a753f12f2"},
  gitError:{blob:"ddc8b45cb9056b09ca3a6bc0e94ea3aff95211f2",bytes:304,sha256:"5710b903750ccc9853075a23278fc1cbcc7468c124b9087e9d09c592e5d2bede"},
  gitBefore:{blob:"71a18cded914b138235c1a7900f1d9f11aa72931",bytes:28592,sha256:"fbd562857be8235f917195c61e19882dc28b7ced7a6553d54e80a4ffe14a5fb0"},
  gitReconcile:{blob:"fa79c134e59e96aa5f08c82bcfe881dbcd98815e",bytes:878,sha256:"61ec8291826dbe22b0f5cdf7332ee1270fb793d99ffb9274850818a92edca8d7"},
  gitReconcileSDK:{blob:"4ef18c30ea5a589bb5192bf9ac4ba31ba55d416e",bytes:2801,sha256:"a56cbb2c052e983e3c4c8bdb556c354bf8379eadfa9ecafc0a3082719d8abda8"},
  gitCreateSDK:{blob:"e56cfdc5d9e3de782fad5fbaff5263845b96d5f9",bytes:195,sha256:"0a4e7614bcdea7ddb14a975bab86bd872469cac6ab74cb2790bd11ee2ff08df7"}
 };
 const checks=[],verifiedBlobs=new Map(),checkedCalls=new Map(),calls=input.state?.calls;
 function check(name,ok){checks.push({name,passed:ok===true});if(ok!==true)throw Error(name);}
 function canon(x){if(Array.isArray(x))return x.map(canon);if(x&&typeof x==="object")return Object.fromEntries(Object.keys(x).sort().map(k=>[k,canon(x[k])]));return x;}
 function eq(a,b){return JSON.stringify(canon(a))===JSON.stringify(canon(b));}
 function exactPin(a,b){return !!a&&a.blob===b.blob&&a.bytes===b.bytes&&a.sha256===b.sha256;}
 function blob(pin,label) {
  check(label+":pin",pin!==null&&typeof pin==="object"&&/^[a-f0-9]{40}$/.test(pin.blob)&&Number.isSafeInteger(pin.bytes)&&pin.bytes>=0&&/^[a-f0-9]{64}$/.test(pin.sha256));
  const raw=input.blobs?.[pin.blob];check(label+":text_present",typeof raw==="string");
  let actual=verifiedBlobs.get(pin.blob);
  if(!actual){actual=gitBlobMeta(raw);verifiedBlobs.set(pin.blob,actual);}
  check(label+":whole_identity",exactPin(actual,pin));return raw;
 }
 function known(sha,label) {
  const raw=input.blobs?.[sha];check(label+":known_blob_present",typeof raw==="string");
  const pin=gitBlobMeta(raw);check(label+":known_git_identity",pin.blob===sha);
  verifiedBlobs.set(sha,pin);return raw;
 }
 function flatTree(tree,entries,label) {
  check(label+":bounded_flat_tree",/^[a-f0-9]{40}$/.test(tree)&&Array.isArray(entries)&&entries.length>0&&entries.length<=128);
  const paths=entries.map(e=>e.path);
  check(label+":unique_paths",new Set(paths).size===paths.length);
  for(const e of entries){check(label+":"+e.path+":flat_path",/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,160}$/.test(e.path));blob(e,label+":"+e.path);}
  const audit=gitTreeAudit({sha:tree,truncated:false,tree:entries.map(e=>({path:e.path,mode:"100644",type:"blob",sha:e.blob,size:e.bytes}))});
  check(label+":merkle",audit.root_sha===tree&&audit.leaf_count===entries.length&&audit.trees_verified===1);
 }
 function archive(a,paths,label) {
  check(label+":whole_record",!!a&&a.whole===true&&a.count===a.entries?.length&&a.bytes===a.entries.reduce((n,e)=>n+e.bytes,0));
  check(label+":exact_paths",eq(a.entries.map(e=>e.path).sort(),paths.slice().sort())&&a.entries.every(e=>e.whole===true));
  flatTree(a.tree,a.entries,label);return Object.fromEntries(a.entries.map(e=>[e.path,e]));
 }
 check("pure_mode",mode==="history"||mode==="final");
 check("body16_actual_recovery_binding_available",BODY16_RECOVERY_BINDING!==null);
 check("body20_actual_recovery_binding_available",BODY20_RECOVERY_BINDING!==null);
 const s=input.state;
 check("state_object",s!==null&&typeof s==="object"&&calls!==null&&typeof calls==="object"&&!Array.isArray(calls));
 const journalRaw=blob(pins.journal,"frozen_journal");
 const tableLine=journalRaw.split("\n").find(x=>x.startsWith("const GF_OUTPUTS = "));
 check("fixed_table_declaration",typeof tableLine==="string"&&tableLine.endsWith(";"));
 const outputs=JSON.parse(tableLine.slice("const GF_OUTPUTS = ".length,-1));
 check("fixed_table_geometry",outputs.length===23&&outputs.reduce((n,r)=>n+r.ranges.length,0)===36&&outputs.reduce((n,r)=>n+r.bytes,0)===1346637);
 check("original_go_identity",exactPin(s.goPin,pins.originalGO)&&s.goRaw===blob(pins.originalGO,"original_GO")&&s.rootGoWhole===true);
 check("original_formatter_job",s.job==="1a1b02771c2-fc05-6e9f");
 const old=calls[FAILED],recovery=calls[RECOVERY],gcall=calls[GIT_REC];
 check("known_failed_row_required",!!old&&old.kind==="operation_result"&&old.called===true&&old.phase==="native_interpretation_refused"&&old.interpretationFailure==="Error: native_tool_error_preserved_stop"&&!Object.prototype.hasOwnProperty.call(old,"nativePin"));
 check("known_failed_request_exact",exactPin(old.requestPin,pins.failedRequest)&&old.requestRaw===blob(pins.failedRequest,"failed_request"));
 const failedQ=JSON.parse(old.requestRaw);
 check("failed_request_same_closed_id",eq(failedQ,{operation_id:"37a07e380c8f74019d9b6c20c86cfa339d409e3b6d01b42b3a4230cb767777dc",offset:0,limit:8192}));
 check("known_failed_sdk_exact",exactPin(old.sdkPin,pins.failedSDK));
 const errorRaw=blob(pins.failedSDK,"original_timeout_SDK"),error=JSON.parse(errorRaw);
 check("original_minus32603_timeout_not_deleted",error.isError===true&&error.content?.length===1&&error.content[0].type==="text"&&error.content[0].text==="tool call error: tool call failed for `codex_apps/heptaruntime_mac_controller.operation_result`\n\nCaused by:\n    Mcp error: -32603: MCP request timed out");
 archive(old.armed,["armed.json","intent.json","request.json"],"failed_original_arm");
 archive(old.sdkArchive,["original.sdk.json"],"failed_original_SDK_archive");
 check("failed_original_arm_pins",old.armed.tree==="3b7bdb2a9d20513b808603faf17b75466a4b5aba"&&old.sdkArchive.tree==="e675db61e07e6dfbb6d7f12b44e0f33c3fc4d6bc");
 check("failed_call_snapshot_unchanged",JSON.stringify(old,null,2)+"\n"===blob(pins.failedCall,"captured_failed_call"));
 check("only_three_exact_nonaccepted_historical_calls",eq(Object.keys(calls).filter(k=>calls[k].phase!=="accepted"),[FAILED,FAILED16,FAILED20]));
 check("recovery_original_same_request",!!recovery&&recovery.kind==="operation_result"&&recovery.called===true&&recovery.phase==="accepted"&&recovery.recoveryOfDelivery===FAILED&&recovery.requestRaw===old.requestRaw&&exactPin(recovery.requestPin,pins.failedRequest));
 const re=archive(recovery.armed,["armed.json","intent.json","original-failed-call.json","request.json"],"recovery_exact_four_leaf_arm");
 check("recovery_exact_immutable_arm_tree",recovery.armed.tree==="f8e7d259a405cd5318011350959a96f8006b5a1f");
 check("recovery_exact_immutable_arm_leaves",
  re["armed.json"].blob==="ceee8f50f5f93fd94c961692992330d702fb42d4"&&re["intent.json"].blob==="5c9bfb6a94b658c5a59af572f8c6b30c4db237ac"&&exactPin(re["original-failed-call.json"],pins.failedCall)&&exactPin(re["request.json"],pins.failedRequest));
 const ri=JSON.parse(blob(re["intent.json"],"recovery_intent")),ra=JSON.parse(blob(re["armed.json"],"recovery_armed"));
 check("recovery_intent_once_no_native_admission",ri.schema==="heptabao.gitfirst.closed-immutable-page-recovery-intent.r1"&&ri.callKey===RECOVERY&&ri.kind==="operation_result"&&ri.maximumNativeCalls===1&&ri.nativeNotYetCalled===true&&ri.noNativeAdmission===true&&ri.notRecoveryOfOriginalSDK===true&&ri.originalFailureRemains===true&&exactPin(ri.rootRecoveryGo,pins.recoveryGO)&&exactPin(ri.originalFailedCall,pins.failedCall)&&exactPin(ri.originalFailedSDK,pins.failedSDK));
 check("recovery_armed_once",ra.schema==="heptabao.gitfirst.closed-immutable-page-recovery-armed.r1"&&ra.automaticRetry===false&&ra.mayHaveDispatchedAfterThisCheckpoint===true);
 const rg=JSON.parse(blob(pins.recoveryGO,"recovery_GO"));
 check("recovery_go_exact_scope",rg.scope==="snapshot_formatted23_info10_page0_retrieval_recovery"&&rg.failed_call_key===FAILED&&rg.recovery_call_key===RECOVERY&&rg.original_operation===failedQ.operation_id&&rg.maximum_recovery_page_calls===1&&rg.operation_start_authorized===false&&rg.operation_status_authorized===false&&rg.failed_call_preserved===true);
 check("recovery_state_does_not_clear_old",s.info10Page0Recovery?.oldKey===FAILED&&s.info10Page0Recovery.callKey===RECOVERY&&s.info10Page0Recovery.oldFailureUnchanged===true&&exactPin(s.info10Page0Recovery.goPin,pins.recoveryGO)&&s.info10Page0Recovery.goRaw===blob(pins.recoveryGO,"recovery_state_GO"));
 const gg=JSON.parse(blob(pins.gitGO,"file7_recovery_GO")),gb=JSON.parse(blob(pins.gitBefore,"file7_before")),gr=JSON.parse(blob(pins.gitReconcile,"file7_readonly_reconcile"));
 const ge=JSON.parse(blob(pins.gitError,"file7_original_Git_error")),gc=JSON.parse(blob(pins.gitCreateSDK,"file7_original_Git_create")),gs=JSON.parse(blob(pins.gitReconcileSDK,"file7_Git_reconcile_SDK"));
 check("file7_error_is_Git_not_Native",ge.isError===true&&ge.structuredContent?.error_code==="UNKNOWN"&&ge.content?.[0]?.text==="RemoteProtocolError: Server disconnected without sending a response.");
 check("file7_original_arm_create_already_acknowledged",gc.isError===false&&gc.structuredContent?.sha==="2c9943bd00cb04e94b6b357739b3c7efea35faba");
 check("file7_exact_GO_and_original_pending",gg.pendingKey===GIT_REC&&gg.existingArmTree==="2c9943bd00cb04e94b6b357739b3c7efea35faba"&&gb.slot===SLOT&&gb.pending===GIT_REC&&gb.paused===true&&gb.nativeCallInFlight===false);
 check("file7_before_native_page_not_called",gb.calls[GIT_REC]?.called===false&&gb.calls[GIT_REC]?.phase==="arming"&&gb.activeObserver.id==="8d29aac0c040a47a18f5631b618a6aea98568bb05955db0d2ff49c15cdf6fb0b"&&gb.activeObserver.futureClosed===true&&gb.activeObserver.pageCalled===0&&gb.activeObserver.nextPageOffset===0&&gb.activeObserver.pages.length===0);
 check("file7_final_original_call_preserved",!!gcall&&gcall.kind==="operation_result"&&gcall.called===true&&gcall.phase==="accepted"&&gcall.archiveFailure==="Error: git_tree_read_error_preserved"&&gcall.requestRaw===gb.calls[GIT_REC].requestRaw&&gcall.requestPin.blob==="2c7017d653f759a89c1a99340b3aae0d8f1ae28b");
 archive(gcall.armed,["armed.json","intent.json","request.json"],"file7_reconciled_original_arm");
 check("file7_same_arm_no_mutation_retry",eq(gcall.armed,gr)&&gr.tree===gg.existingArmTree&&gr.recoveryReadOnly===true&&gr.mutationRepeated===false&&gr.nativeCalled===false);
 check("file7_only_readonly_tree_reconcile",gs.isError!==true&&typeof gs.structuredContent?.content==="string");
 const gta=gitTreeAudit(JSON.parse(gs.structuredContent.content));
 check("file7_exact_Git_tree_readback",gta.root_sha===gr.tree&&gta.leaf_count===3&&gta.trees_verified===1);
 const fail16=calls[FAILED16],rec16=calls[RECOVERY16],b16=BODY16_RECOVERY_BINDING;
 const fail16Pin={blob:"593f02daca6b8ac9511ed460af8919eed0b7bc32",bytes:2066,sha256:"f70e2ae9bac4c87df0faac3a2fbd4e507a64db29d4d1b010b3771028465d7776"};
 const req16Pin={blob:"bfd96536330ccc3704a2ba596203edf3680a0702",bytes:122,sha256:"ede3d944c75b34dbcc7cf3b644e9d8374496f8348d375e792d565141c92b2ef5"};
 const status16Pin={blob:"237b2709d1ca13c6b56fdd4be8012920bac38b7a",bytes:802,sha256:"9b667dd791f4fb7a67710f127b0b4475d9c15ca9b5e09b45c67f22410bc769b3"};
 const op16="9037480fbf014345c1d2bbe1894020e30602a9adb2d8c1a864f6eff35368f1b0";
 check("body16_original_failed_row_required",!!fail16&&fail16.called===true&&fail16.phase==="native_interpretation_refused"&&fail16.kind==="operation_result"&&fail16.interpretationFailure==="Error: native_tool_error_preserved_stop"&&!Object.prototype.hasOwnProperty.call(fail16,"nativePin"));
 check("body16_failed_row_exact_snapshot",JSON.stringify(fail16,null,2)+"\n"===blob(fail16Pin,"body16_original_failed_call"));
 check("body16_exact_request_and_error_SDK",exactPin(fail16.requestPin,req16Pin)&&fail16.requestRaw===blob(req16Pin,"body16_failed_request")&&exactPin(fail16.sdkPin,pins.failedSDK)&&eq(JSON.parse(fail16.requestRaw),{operation_id:op16,offset:0,limit:16384}));
 archive(fail16.armed,["armed.json","intent.json","request.json"],"body16_original_failed_arm");
 archive(fail16.sdkArchive,["original.sdk.json"],"body16_original_error_SDK_archive");
 check("body16_original_arm_identity",fail16.armed.tree==="e8b011038b5afae7a1df8bb9d78bacfe3d118074"&&fail16.sdkArchive.tree==="e675db61e07e6dfbb6d7f12b44e0f33c3fc4d6bc");
 check("body16_separate_recovery_exact_request",!!rec16&&rec16.kind==="operation_result"&&rec16.called===true&&rec16.phase==="accepted"&&rec16.recoveryOfDelivery===FAILED16&&rec16.requestRaw===fail16.requestRaw&&exactPin(rec16.requestPin,req16Pin));
 const re16=archive(rec16.armed,["armed.json","intent.json","original-failed-call.json","request.json"],"body16_exact_four_leaf_arm");
 check("body16_actual_root_approved_arm",rec16.armed.tree===b16.armTree&&eq(rec16.armed.entries.map(x=>({path:x.path,blob:x.blob,bytes:x.bytes,sha256:x.sha256})),b16.armEntries)&&exactPin(re16["original-failed-call.json"],fail16Pin)&&exactPin(re16["request.json"],req16Pin));
 const ri16=JSON.parse(blob(re16["intent.json"],"body16_recovery_intent")),ra16=JSON.parse(blob(re16["armed.json"],"body16_recovery_armed")),go16=JSON.parse(blob(b16.go,"body16_recovery_GO"));
 check("body16_GO_exact_scope",go16.authorization==="GO"&&go16.scope==="snapshot_formatted23_body16_page0_retrieval_recovery"&&go16.slot===SLOT&&go16.original_operation===op16&&go16.failed_call_key===FAILED16&&go16.recovery_call_key===RECOVERY16&&exactPin(go16.request,req16Pin)&&exactPin(go16.failed_sdk,pins.failedSDK)&&exactPin(go16.failed_call,fail16Pin)&&go16.maximum_recovery_page_calls===1&&go16.page_bytes===16384&&go16.native_payload_cap===1048576&&go16.operation_start_authorized===false&&go16.operation_status_authorized===false&&go16.failed_call_preserved===true&&go16.original_go===pins.originalGO.blob);
 check("body16_recovery_intent_keeps_originals",ri16.schema==="heptabao.gitfirst.closed-immutable-page-recovery-intent.r1"&&ri16.callKey===RECOVERY16&&ri16.kind==="operation_result"&&exactPin(ri16.request,req16Pin)&&exactPin(ri16.rootRecoveryGo,b16.go)&&exactPin(ri16.originalRootGo,pins.originalGO)&&ri16.originalOperation===op16&&exactPin(ri16.originalFailedSDK,pins.failedSDK)&&exactPin(ri16.originalFailedCall,fail16Pin)&&exactPin(ri16.originalCompletedStatus,status16Pin)&&ri16.maximumNativeCalls===1&&ri16.nativeNotYetCalled===true&&ri16.noNativeAdmission===true&&ri16.notRecoveryOfOriginalSDK===true&&ri16.originalFailureRemains===true);
 check("body16_recovery_armed_once",ra16.schema==="heptabao.gitfirst.closed-immutable-page-recovery-armed.r1"&&ra16.mayHaveDispatchedAfterThisCheckpoint===true&&ra16.automaticRetry===false);
 check("body16_recovery_before_actual_boundary",eq(ri16.before,{pending:FAILED16,paused:true,failedCall:fail16Pin,admissionsCalled:47,bodyBytes:1184165,pageCalled:1,completedObservers:46,wholeFiles:16}));
 const known16=JSON.parse(blob(status16Pin,"body16_original_completed_status"));
 check("body16_original_future_closed_before_delivery_error",known16.operation_id===op16&&known16.async_state==="completed"&&known16.result_state==="stored_observed"&&known16.owned_future_active===false&&known16.payload_available===true);
 check("body16_recovery_state_no_history_rewrite",s.body16Page0Recovery?.oldKey===FAILED16&&s.body16Page0Recovery.callKey===RECOVERY16&&s.body16Page0Recovery.oldFailureUnchanged===true&&exactPin(s.body16Page0Recovery.goPin,b16.go)&&s.body16Page0Recovery.goRaw===blob(b16.go,"body16_state_GO"));
 check("body16_recovery_actual_SDK_pin",exactPin(rec16.sdkPin,b16.sdk)&&exactPin(rec16.nativePin,b16.native));
 const fail20=calls[FAILED20],rec20=calls[RECOVERY20],b20=BODY20_RECOVERY_BINDING;
 const fail20Pin={"blob":"4911defb28498915832ce3202103a7f6541bcac7","bytes":2070,"sha256":"782cd589df161244a0c0e0452f0ed8ab54f274cb536c58ff04d2f7a606becd46"};
 const req20Pin={"blob":"1ca4e7299a552ab1594a1c26a02909a56e808e5e","bytes":126,"sha256":"3e7d6ccdd56784adfb70e42d88e4bd0ccf122e6de69d6b28ffd403165b77084a"};
 const status20Pin={"blob":"7dab61f4aeded51aff5f7db244935bb4082e092b","bytes":802,"sha256":"4684defb10483cba79917d47a3337f9b1a739a7c5eb83b142877449dbb453708"};
 const op20="2d748c65bb3394cc8a97b59b24027a4f3ee24a18885a04523c98435b3fefc1fe";
 check("body20_original_failed_row_required",!!fail20&&fail20.called===true&&fail20.phase==="native_interpretation_refused"&&fail20.kind==="operation_result"&&fail20.interpretationFailure==="Error: native_tool_error_preserved_stop"&&!Object.prototype.hasOwnProperty.call(fail20,"nativePin"));
 check("body20_failed_row_exact_snapshot",JSON.stringify(fail20,null,2)+"\n"===blob(fail20Pin,"body20_original_failed_call"));
 check("body20_exact_request_and_error_SDK",exactPin(fail20.requestPin,req20Pin)&&fail20.requestRaw===blob(req20Pin,"body20_failed_request")&&exactPin(fail20.sdkPin,pins.failedSDK)&&eq(JSON.parse(fail20.requestRaw),{operation_id:op20,offset:49152,limit:16384}));
 archive(fail20.armed,["armed.json","intent.json","request.json"],"body20_original_failed_arm");
 archive(fail20.sdkArchive,["original.sdk.json"],"body20_original_error_SDK_archive");
 check("body20_original_arm_identity",fail20.armed.tree==="be2fc85483c56ed335bf66832515564c8b12e517"&&fail20.sdkArchive.tree==="e675db61e07e6dfbb6d7f12b44e0f33c3fc4d6bc");
 check("body20_separate_recovery_exact_request",!!rec20&&rec20.kind==="operation_result"&&rec20.called===true&&rec20.phase==="accepted"&&rec20.recoveryOfDelivery===FAILED20&&rec20.requestRaw===fail20.requestRaw&&exactPin(rec20.requestPin,req20Pin));
 const re20=archive(rec20.armed,["armed.json","intent.json","original-failed-call.json","request.json"],"body20_exact_four_leaf_arm");
 check("body20_actual_root_approved_arm",rec20.armed.tree===b20.armTree&&eq(rec20.armed.entries.map(x=>({path:x.path,blob:x.blob,bytes:x.bytes,sha256:x.sha256})),b20.armEntries)&&exactPin(re20["original-failed-call.json"],fail20Pin)&&exactPin(re20["request.json"],req20Pin));
 const ri20=JSON.parse(blob(re20["intent.json"],"body20_recovery_intent")),ra20=JSON.parse(blob(re20["armed.json"],"body20_recovery_armed")),go20=JSON.parse(blob(b20.go,"body20_recovery_GO"));
 check("body20_GO_exact_scope",go20.authorization==="GO"&&go20.scope==="snapshot_formatted23_body20_page3_retrieval_recovery"&&go20.slot===SLOT&&go20.original_operation===op20&&go20.failed_call_key===FAILED20&&go20.recovery_call_key===RECOVERY20&&exactPin(go20.request,req20Pin)&&exactPin(go20.failed_sdk,pins.failedSDK)&&exactPin(go20.failed_call,fail20Pin)&&go20.maximum_recovery_page_calls===1&&go20.page_bytes===16384&&go20.native_payload_cap===1048576&&go20.operation_start_authorized===false&&go20.operation_status_authorized===false&&go20.failed_call_preserved===true&&go20.original_go===pins.originalGO.blob);
 check("body20_recovery_intent_keeps_originals",ri20.schema==="heptabao.gitfirst.closed-immutable-page-recovery-intent.r1"&&ri20.callKey===RECOVERY20&&ri20.kind==="operation_result"&&exactPin(ri20.request,req20Pin)&&exactPin(ri20.rootRecoveryGo,b20.go)&&exactPin(ri20.originalRootGo,pins.originalGO)&&ri20.originalOperation===op20&&exactPin(ri20.originalFailedSDK,pins.failedSDK)&&exactPin(ri20.originalFailedCall,fail20Pin)&&exactPin(ri20.originalCompletedStatus,status20Pin)&&ri20.maximumNativeCalls===1&&ri20.nativeNotYetCalled===true&&ri20.noNativeAdmission===true&&ri20.notRecoveryOfOriginalSDK===true&&ri20.originalFailureRemains===true);
 check("body20_recovery_armed_once",ra20.schema==="heptabao.gitfirst.closed-immutable-page-recovery-armed.r1"&&ra20.mayHaveDispatchedAfterThisCheckpoint===true&&ra20.automaticRetry===false);
 check("body20_recovery_before_actual_boundary",eq(ri20.before,{pending:FAILED20,paused:true,failedCall:fail20Pin,admissionsCalled:55,bodyBytes:1277974,pageCalled:4,completedObservers:54,wholeFiles:20,nextPageOffset:49152,payloadTotal:63251,payloadSHA256:"bce3955483b6d29d658e121b03cec9a94f71eccf44d7b49e5b704b7bf6f64787",successfulPages:3,originalPages:{"blob":"fb9d5d834822d46ad7344cafebe47aa12850c259","bytes":66600,"sha256":"f05ff4ac9fb138c8f4553ca5064e33640db9375cd1edd6f71080f9b044d99182"}}));
 const known20=JSON.parse(blob(status20Pin,"body20_original_completed_status"));
 check("body20_original_future_closed_before_delivery_error",known20.operation_id===op20&&known20.async_state==="completed"&&known20.result_state==="stored_observed"&&known20.owned_future_active===false&&known20.payload_available===true);
 check("body20_recovery_state_no_history_rewrite",s.body20Page3Recovery?.oldKey===FAILED20&&s.body20Page3Recovery.callKey===RECOVERY20&&s.body20Page3Recovery.oldFailureUnchanged===true&&exactPin(s.body20Page3Recovery.goPin,b20.go)&&s.body20Page3Recovery.goRaw===blob(b20.go,"body20_state_GO"));
 check("body20_recovery_actual_SDK_pin",exactPin(rec20.sdkPin,b20.sdk)&&exactPin(rec20.nativePin,b20.native));
 const previous20=JSON.parse(blob({"blob":"fb9d5d834822d46ad7344cafebe47aa12850c259","bytes":66600,"sha256":"f05ff4ac9fb138c8f4553ca5064e33640db9375cd1edd6f71080f9b044d99182"},"body20_exact_original_three_pages"));
 check("body20_original_three_page_geometry",previous20.length===3&&previous20.every((p,i)=>p.offset===i*16384&&p.next===(i+1)*16384));
 for(let i=0;i<3;i++){
  const k="sf23-r1-f20-b00-p"+i,c=calls[k],p=previous20[i];
  check("body20_prior_page_"+i+"_row_required",!!c&&c.kind==="operation_result"&&c.called===true&&c.phase==="accepted"&&exactPin(c.sdkPin,p.originalSDK)&&exactPin(c.nativePin,p.nativeText)&&eq(JSON.parse(c.requestRaw),{operation_id:op20,offset:i*16384,limit:16384}));
 }
 const last20=JSON.parse(blob(b20.native,"body20_actual_recovery_page_native"));
 check("body20_single_last_page_exact_end",last20.operation_id===op20&&last20.offset===49152&&last20.next_offset===63251&&last20.total_bytes===63251&&last20.eof===true);
 check("no_unapproved_recovery_keys",eq(Object.keys(calls).filter(k=>k.includes("recovery")),[RECOVERY,RECOVERY16,RECOVERY20]));
 check("no_extra_Git_failure_exceptions",eq(Object.keys(calls).filter(k=>Object.prototype.hasOwnProperty.call(calls[k],"archiveFailure")),[GIT_REC]));
 function call(k) {
  if(checkedCalls.has(k))return checkedCalls.get(k);
  const c=calls[k];check(k+":row_present",!!c);
  check(k+":called_once_recorded",c.called===true&&["operation_start","operation_status","operation_result"].includes(c.kind));
  check(k+":request_whole",c.requestRaw===blob(c.requestPin,k+":request"));
  const a=archive(c.armed,(k===RECOVERY||k===RECOVERY16||k===RECOVERY20)?["armed.json","intent.json","original-failed-call.json","request.json"]:["armed.json","intent.json","request.json"],k+":arm");
  check(k+":request_inside_arm",exactPin(a["request.json"],c.requestPin));
  const q=JSON.parse(c.requestRaw);
  if(k!==RECOVERY&&k!==RECOVERY16&&k!==RECOVERY20){
   const intent={schema:"heptabao.gitfirst.fixed-native-call-intent.r1",callKey:k,kind:c.kind,request:c.requestPin,rootGo:s.goPin,originalJob:s.job,originalOperation:c.kind==="operation_start"?null:q.operation_id,maximumNativeCalls:1,nativeNotYetCalled:true,lossOfAcknowledgmentNeverGrantsReplay:true,localFirstExplicitlyReplacedByExactRootGO:true};
   const armed={...intent,schema:"heptabao.gitfirst.fixed-native-call-armed.r1",mayHaveDispatchedAfterThisCheckpoint:true,recovery:"Read exact original job/operation only; absence of later ACK is UNKNOWN."};
   check(k+":intent_exact_bytes",JSON.stringify(intent,null,2)+"\n"===blob(a["intent.json"],k+":intent"));
   check(k+":armed_exact_bytes",JSON.stringify(armed,null,2)+"\n"===blob(a["armed.json"],k+":armed"));
  }
  const sa=archive(c.sdkArchive,["original.sdk.json"],k+":SDK_archive");
  check(k+":exact_original_SDK_leaf",exactPin(sa["original.sdk.json"],c.sdkPin));
  const sdkRaw=blob(c.sdkPin,k+":SDK"),sdk=JSON.parse(sdkRaw);
  if(k===FAILED||k===FAILED16||k===FAILED20){check(k+":only_known_failure",c.phase==="native_interpretation_refused"&&sdkRaw===errorRaw);const r={c,q,failed:true};checkedCalls.set(k,r);return r;}
  check(k+":success_phase",c.phase==="accepted"&&!Object.prototype.hasOwnProperty.call(c,"interpretationFailure"));
  check(k+":success_original_SDK",sdk.isError!==true&&sdk.content?.length===1&&sdk.content[0].type==="text");
  check(k+":native_text_whole",sdk.content[0].text===blob(c.nativePin,k+":native"));
  const v=parseLosslessIntegers(sdk.content[0].text);
  check(k+":no_generic_recovery_property",k===RECOVERY?c.recoveryOfDelivery===FAILED:k===RECOVERY16?c.recoveryOfDelivery===FAILED16:k===RECOVERY20?c.recoveryOfDelivery===FAILED20:!Object.prototype.hasOwnProperty.call(c,"recoveryOfDelivery"));
  const result={c,q,v,failed:false};checkedCalls.set(k,result);return result;
 }
 for(const k of Object.keys(calls))call(k);
 const beforeDone=JSON.parse(blob(ri.originalCompletedStatus,"info10_original_known_closed_status"));
 check("info10_original_future_closed_before_failure",beforeDone.operation_id===failedQ.operation_id&&beforeDone.async_state==="completed"&&beforeDone.result_state==="stored_observed"&&beforeDone.owned_future_active===false&&beforeDone.payload_available===true);
 const rv=call(RECOVERY).v;
 check("info10_recovery_same_immutable_page",rv.operation_id===failedQ.operation_id&&rv.offset===0&&rv.eof===true&&rv.immutable_snapshot===true&&rv.payload_kind==="native_result"&&rv.total_bytes===606&&rv.next_offset===606&&rv.result_sha256==="516f24af6feef2f1f7ce6765381c9710dd5dc8ff9a04f7317f5abc014eebf463");
 const rb=unb64(rv.data_base64);
 check("info10_recovery_actual_payload_bytes",rb.length===606&&sha256Latin1(byteString(rb))===rv.result_sha256);
 const ro=s.completedObservers.filter(o=>o.id===failedQ.operation_id);
 check("info10_recovery_closed_original_INFO_once",ro.length===1&&ro[0].tool==="file_info"&&ro[0].pages===1&&ro[0].completedInactive===true&&utf8Text(rb)===blob(ro[0].payload,"info10_recovery_payload"));
 if(mode==="history")return {schema:"heptabao.formatted23-known-history-validation.v1",passed:true,checks:checks.length,rows:checks,scope:"Only preserved known failures, exact recovery arms and original call-envelope identities. No final23 qualification.",final23Qualified:false,nativeFailureCalls:3,immutablePageRecoveryCalls:3,gitArmFailureRecords:1,newRuntimeCalls:0};

 check("final23_requires_all_files",s.outputFiles?.length===23);
 check("final23_clean_boundary",s.pending===null&&s.activeObserver===null&&s.nativeCallInFlight===false&&s.paused===false);
 check("final23_exact_native_admissions_and_observers",s.admissionsCalled===59&&s.completedObservers?.length===59);
 check("final23_original_arrays_exact",s.outputInfos?.length===23&&s.outputRanges?.length===23&&s.infoStarted?.length===23&&s.bodyStarted?.length===23&&s.infoStarted.every(x=>x===true));
 check("final23_body_total",s.bodyBytes===1346637);
 check("failed_outer_record_not_cleared",eq(s.outerFailure,{schema:"heptabao.gitfirst.outer-caught-failure.r1",action:"accept",name:"Error",message:"native_tool_error_preserved_stop",automaticRetry:false,newAdmissionAllowed:false,returnedNormally:true}));
 const expectedOrder=[],seenIds=new Set(),seenAdmissionKeys=new Set();
 let observerIndex=0,pageCount=0,statusCount=0,actualBytes=0;
 function runObserver(label,requestRaw,expectedTool) {
  const admitKey=label+"-admit",ad=call(admitKey);
  expectedOrder.push(admitKey);
  check(label+":exact_request_bytes",ad.c.kind==="operation_start"&&ad.c.requestRaw===requestRaw);
  const q=JSON.parse(requestRaw),id=ad.v.operation_id;
  check(label+":exact_frozen_admission_scope",Object.keys(q).sort().join(",")==="idempotency_key,operation"&&q.operation.tool===expectedTool&&q.operation.arguments.host==="rog"&&typeof q.idempotency_key==="string"&&!seenAdmissionKeys.has(q.idempotency_key));
  seenAdmissionKeys.add(q.idempotency_key);
  check(label+":original_unique_ACK",/^[a-f0-9]{64}$/.test(id)&&!seenIds.has(id)&&ad.v.tool_name===expectedTool&&ad.v.reused===false&&ad.v.automatic_retry===false&&ad.v.idempotency_binding_retained===true);
  seenIds.add(id);
  const statusKeys=Object.keys(calls).filter(k=>new RegExp("^"+label+"-s(0|[1-9][0-9]*)$").test(k));
  check(label+":status_count",statusKeys.length>=1&&statusKeys.length<=8);
  for(let i=0;i<statusKeys.length;i++) {
   const k=label+"-s"+i;check(label+":status_sequence_"+i,statusKeys[i]===k);
   const r=call(k);expectedOrder.push(k);statusCount++;
   check(k+":status_exact_request",r.c.kind==="operation_status"&&r.c.requestRaw===JSON.stringify({operation_id:id},null,2)+"\n");
   check(k+":same_operation_status",r.v.operation_id===id&&r.v.tool_name===expectedTool&&r.v.automatic_retry===false);
   if(i===statusKeys.length-1)check(k+":terminal_closed",r.v.async_state==="completed"&&r.v.result_state==="stored_observed"&&r.v.owned_future_active===false&&r.v.payload_available===true);
   else check(k+":only_live_prior_status",r.v.async_state==="queued"||r.v.async_state==="running");
  }
  const originalPageKeys=Object.keys(calls).filter(k=>new RegExp("^"+label+"-p(0|[1-9][0-9]*)$").test(k));
  const width=expectedTool==="binary_read"?16384:8192,maximum=expectedTool==="binary_read"?64:128;
  check(label+":page_count",originalPageKeys.length>=1&&originalPageKeys.length+((label==="sf23-r1-f10-info"||label==="sf23-r1-f16-b00"||label==="sf23-r1-f20-b00")?1:0)<=maximum);
  let bytes=[],next=0,total=null,digest=null;
  for(let i=0;i<originalPageKeys.length;i++) {
   const originalOrdinal=label==="sf23-r1-f16-b00"&&i>0?i+1:i;
   const originalKey=label+"-p"+originalOrdinal;check(label+":page_sequence_"+i,originalPageKeys[i]===originalKey);
   let key=originalKey;
   if(originalKey===FAILED){expectedOrder.push(FAILED);check("failed_page_not_payload",call(FAILED).failed===true);key=RECOVERY;}
   if(originalKey===FAILED16){expectedOrder.push(FAILED16);check("body16_failed_page_not_payload",call(FAILED16).failed===true);key=RECOVERY16;}
   if(originalKey===FAILED20){expectedOrder.push(FAILED20);check("body20_failed_page_not_payload",call(FAILED20).failed===true);key=RECOVERY20;}
   expectedOrder.push(key);
   const p=call(key);pageCount++;
   check(key+":page_exact_request",p.c.kind==="operation_result"&&p.c.requestRaw===JSON.stringify({operation_id:id,offset:next,limit:width},null,2)+"\n");
   const v=p.v;
   check(key+":same_immutable_result",v.operation_id===id&&v.offset===next&&v.immutable_snapshot===true&&v.payload_kind==="native_result"&&v.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization");
   check(key+":bounded_payload_identity",Number.isSafeInteger(v.total_bytes)&&v.total_bytes>=0&&v.total_bytes<=1048576&&/^[a-f0-9]{64}$/.test(v.result_sha256));
   if(total===null){total=v.total_bytes;digest=v.result_sha256;}
   check(key+":one_payload_identity",v.total_bytes===total&&v.result_sha256===digest);
   const b=unb64(v.data_base64);
   check(key+":original_page_extent",b.length<=width&&encodeBase64Bytes(b)===v.data_base64&&v.next_offset===next+b.length&&v.next_offset<=total&&(b.length>0||v.eof===true)&&v.eof===(v.next_offset===total));
   check(key+":EOF_only_last_original_page",v.eof===(i===originalPageKeys.length-1));
   bytes=bytes.concat(b);next=v.next_offset;
  }
  check(label+":original_payload_complete",next===total&&bytes.length===total&&sha256Latin1(byteString(bytes))===digest);
  const raw=utf8Text(bytes),payloadPin=gitBlobMeta(raw),record=s.completedObservers[observerIndex++];
  check(label+":closed_record_order",!!record&&record.id===id&&record.tool===expectedTool&&record.completedInactive===true&&record.pages===originalPageKeys.length);
  check(label+":closed_payload_whole",exactPin(record.payload,payloadPin)&&blob(record.payload,label+":original_payload")===raw);
  flatTree(record.payloadTree,[{path:"payload.original.json",...payloadPin}],label+":payload_tree");
  const payload=parseLosslessIntegers(raw);
  check(label+":native_result_success",payload.resultType==="complete"&&payload.isError===false&&payload.content?.length===1&&payload.content[0].type==="text");
  check(label+":native_result_whole",payload.content[0].text===blob(record.nativeText,label+":native_result"));
  return {id,record,q,v:parseLosslessIntegers(payload.content[0].text)};
 }
 const actualFiles=[];
 for(let i=0;i<outputs.length;i++){
  const row=outputs[i],label="sf23-r1-f"+String(i).padStart(2,"0");
  check(label+":frozen_row_ordinal",row.index===i&&row.bytes>0&&row.bytes<=2097152&&row.ranges.length>0);
  check(label+":frozen_INFO_pin",exactPin(gitBlobMeta(row.infoRaw),row.info));
  const infoLabel=i===0?"sf23-r1-i00":label+"-info";
  const oi=runObserver(infoLabel,row.infoRaw,"file_info"),v=oi.v,md=v.metadata,parts=typeof v.version==="string"?v.version.split(":"):[];
  check(label+":actual_metadata_exact_content",v.path===row.path&&v.size===row.bytes&&v.sha256===row.sha256&&v.mode===384&&md?.metadata_platform==="linux"&&md.mode===384&&md.uid===1000&&md.gid===1000&&md.link_count===1);
  check(label+":lossless_version",parts.length===5&&parts.every(x=>/^(0|[1-9][0-9]*)$/.test(x))&&parts[2]===String(row.bytes));
  const full9=[parts[0],parts[1],"1000","1000","33152","1",String(row.bytes),parts[3],parts[4]],storedInfo=s.outputInfos[i];
  check(label+":actual_INFO_not_source_input_identity",!!storedInfo&&storedInfo.index===i&&storedInfo.path===row.path&&storedInfo.size===row.bytes&&storedInfo.sha256===row.sha256&&storedInfo.version===v.version&&storedInfo.originalOperation===oi.id&&eq(storedInfo.full9Strings,full9)&&storedInfo.firstOutputIdentityObservation===true&&storedInfo.originalSourceInputIdentityReused===false&&storedInfo.regularFileFromNativeFileInfoContract===true&&exactPin(storedInfo.nativeText,oi.record.nativeText)&&exactPin(storedInfo.originalPayload,oi.record.payload));
  check(label+":exact_range_arrays",s.outputRanges[i].length===row.ranges.length&&s.bodyStarted[i].length===row.ranges.length&&s.bodyStarted[i].every(x=>x===true));
  let fileBytes=[],next=0;
  const actualRanges=[];
  for(let j=0;j<row.ranges.length;j++){
   const range=row.ranges[j],rawTemplate=range.templateRaw;
   check(label+":template_pin_"+j,exactPin(gitBlobMeta(rawTemplate),range.template)&&range.index===j&&range.offset===next&&range.limit>0&&range.limit<=65536);
   const q=JSON.parse(rawTemplate);
   check(label+":null_template_version_"+j,q.operation.arguments.expected_version===null);
   q.operation.arguments.expected_version=v.version;
   const ob=runObserver(label+"-b"+String(j).padStart(2,"0"),JSON.stringify(q,null,2)+"\n","binary_read"),b=ob.v,args=q.operation.arguments;
   check(label+":range_bound_"+j,args.path===row.path&&args.offset===range.offset&&args.limit===range.limit&&args.expected_version===v.version&&b.path===row.path&&b.version===v.version&&b.size===row.bytes&&b.offset===range.offset&&b.next_offset===range.offset+range.limit&&b.eof===(b.next_offset===row.bytes));
   const chunk=unb64(b.data_base64),chunkSHA=sha256Latin1(byteString(chunk)),stored=s.outputRanges[i][j];
   check(label+":range_bytes_SHA_before_decode_"+j,chunk.length===range.limit&&encodeBase64Bytes(chunk)===b.data_base64&&chunkSHA===b.chunk_sha256);
   check(label+":retained_original_range_"+j,stored.index===j&&stored.offset===range.offset&&stored.next===b.next_offset&&stored.limit===range.limit&&stored.base64===b.data_base64&&stored.chunkSha256===chunkSHA&&stored.operationId===ob.id&&stored.sourceFileVersion===v.version&&exactPin(stored.nativeText,ob.record.nativeText));
   actualRanges.push({offset:range.offset,next:b.next_offset,limit:range.limit,chunkSha256:chunkSHA,originalOperation:ob.id,nativeText:ob.record.nativeText});
   fileBytes=fileBytes.concat(chunk);next=b.next_offset;actualBytes+=chunk.length;
  }
  check(label+":whole_file_SHA_before_UTF8",next===row.bytes&&fileBytes.length===row.bytes&&sha256Latin1(byteString(fileBytes))===row.sha256);
  const fileRaw=utf8Text(fileBytes),filePin=gitBlobMeta(fileRaw),storedFile=s.outputFiles[i];
  check(label+":whole_UTF8_roundtrip",filePin.bytes===row.bytes&&filePin.sha256===row.sha256&&eq(utf8Bytes(fileRaw),fileBytes));
  check(label+":whole_actual_output_record",storedFile.index===i&&storedFile.name===row.name&&storedFile.path===row.path&&exactPin(storedFile.body,filePin)&&storedFile.version===v.version&&eq(storedFile.full9Strings,full9)&&storedFile.metadataOperation===oi.id&&eq(storedFile.ranges,actualRanges)&&storedFile.wholeUTF8DecodedAfterByteSHA===true&&storedFile.semanticQualification===false);
  check(label+":whole_actual_output_external_bytes",blob(storedFile.body,label+":whole_output")===fileRaw);
  flatTree(storedFile.bodyTree,[{path:"formatted-output.rs",...filePin}],label+":whole_output_tree");
  actualFiles.push({canonicalPath:row.canonicalPath,name:row.name,body:filePin,evidenceKind:"fresh_changed_output_INFO_and_version_bound_body",version:v.version,full9Strings:full9,metadataOperation:oi.id});
 }
 check("all_original_call_order_including_failed_and_recovery",eq(Object.keys(calls),expectedOrder));
 check("all59_original_observers_accounted",observerIndex===59&&seenIds.size===59&&seenAdmissionKeys.size===59&&actualBytes===1346637);
 const report=parseLosslessIntegers(blob(pins.report,"qualified_formatter_report")),fg=JSON.parse(blob(pins.formatterGO,"formatter_GO"));
 check("49_input_output_bijection",report.files?.length===49&&fg.input_files?.length===49&&new Set(report.files.map(f=>f.name)).size===49&&new Set(fg.input_files.map(f=>f.name)).size===49);
 const changed=report.files.filter(f=>f.beforeBytes!==f.afterBytes||f.beforeSha256!==f.afterSha256),unchanged=report.files.filter(f=>f.beforeBytes===f.afterBytes&&f.beforeSha256===f.afterSha256);
 check("23_changed_exact_frozen_order",eq(changed.map(f=>[f.name,f.afterBytes,f.afterSha256]),outputs.map(f=>[f.name,f.bytes,f.sha256])));
 check("26_unchanged_content_total",unchanged.length===26&&unchanged.reduce((n,f)=>n+f.afterBytes,0)===686814);
 const mapping=[];
 for(const f of report.files){
  const source=fg.input_files.find(x=>x.name===f.name);
  check("49:"+f.name+":frozen_before_source",!!source&&source.bytes===f.beforeBytes&&source.sha256===f.beforeSha256);
  const actual=actualFiles.find(x=>x.name===f.name);
  if(actual){const row=outputs.find(x=>x.name===f.name);check("49:"+f.name+":changed_canonical_binding",source.path===actual.canonicalPath&&exactPin(source,row.source));mapping.push(actual);}
  else {
   const raw=blob(source,"49:"+f.name+":whole_frozen_unchanged_source"),p=gitBlobMeta(raw);
   check("49:"+f.name+":unchanged_actual_after_content",p.bytes===f.afterBytes&&p.sha256===f.afterSha256);
   mapping.push({canonicalPath:source.path,name:f.name,body:p,evidenceKind:"reuse_of_whole_frozen_source_matching_qualified_formatter_after_SHA",independentOutputMetadataObserved:false,version:null,full9Strings:null});
  }
 }
 check("49_distinct_canonical_outputs",mapping.length===49&&new Set(mapping.map(x=>x.canonicalPath)).size===49);
 check("old_report_UNKNOWN_preserved_by_exact_reference",s.oldUnknown?.blob==="b174296c1b46c119356df90d5c68b6ca5bc4c19c"&&s.originalRelease?.blob==="8f2d2d10591fb59b191378535672dc31c3df2875"&&exactPin(s.originalReport,pins.report));
 blob(s.oldUnknown,"old_report_UNKNOWN_original");blob(s.originalRelease,"original_report_owner_release");
 return {schema:"heptabao.formatted23-final-original-chain-verification.v1",passed:true,checks:checks.length,rows:checks,changedFiles:23,changedBodyBytes:1346637,unchangedWholeSourceReuses:26,unchangedBodyBytes:686814,canonicalMapping:mapping,originalObservers:59,originalAdmissions:59,originalStatusCalls:statusCount,successfulImmutablePages:pageCount,historicalNativeErrorCalls:3,separateImmutablePageRecoveryCalls:3,historicalGitArmReadErrors:1,totalOriginalCallRecords:Object.keys(calls).length,unknownRecordsPreserved:true,newRuntimeCalls:0,productTestOrBuildQualification:false};

}

function verifyFormatted23FinalActual(input) { return verifyFormatted23ActualEngine(input,"final"); }
function verifyFormatted23KnownHistory(input) { return verifyFormatted23ActualEngine(input,"history"); }
