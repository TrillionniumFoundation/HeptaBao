async function verifyMac4aInfoImmutableRetrieval(files){
 const checks=[];function ck(name,v){checks.push({name,pass:!!v});if(!v)throw Error(name);}
 const plan=JSON.parse(files["PLAN.public.json"]),before=files["reader.before.original.js"],after=files["reader.after.js"];
 function pinEq(raw,p){const m=gitBlobMeta(raw);return m.blob===p.blob&&m.bytes===p.bytes&&m.sha256===p.sha256;}
 function fn(s,name){const i=s.indexOf("function "+name+"("),b=i>5&&s.slice(i-6,i)==="async "?i-6:i;const next=s.slice(i+1).search(/\n(?:async )?function /);return s.slice(b,next<0?s.length:i+1+next);}
 ck("before_exact_approved_reader",pinEq(before,plan.referenceSource)&&plan.referenceSource.blob==="ec8b3b469d113bfa96c07f4021e52fa66d1abbad");
 ck("after_exact",pinEq(after,plan.source));
 ck("strict_forward",applyStrict(before,files["reader.forward.diff"])===after);
 ck("strict_reverse",applyStrict(after,files["reader.reverse.diff"])===before);
 ck("five_hunks",(files["reader.forward.diff"].match(/^@@/gm)||[]).length===5);
 for(const n of ["fipNeed","fipJ","fipEq","fipDecodeOnePage"])ck("original_function_"+n,fn(before,n)===fn(after,n));
 ck("one_native_method_only",(after.match(/tools\./g)||[]).length===1&&after.includes("tools.mcp__codex_apps__heptaruntime_mac_controller_operation_result("));
 ck("one_old_slot_no_build_slot",!after.includes("FIP_OLD_BUILD")&&!after.includes("FIP_BUILD_PIN")&&!after.includes("store(FIP_OLD_INFO"));
 const oldRaw=files["STATE.paused.original.json"],old=JSON.parse(oldRaw),status=parseLosslessIntegers(files["status0.native.original.json"]);
 ck("old_whole_paused_state",pinEq(oldRaw,plan.originalState)&&old.paused===true&&old.pending===plan.originalFailedCallKey&&old.nativeCallInFlight===false);
 ck("original_completed_inactive_status",pinEq(files["status0.native.original.json"],plan.originalStatus)&&status.operation_id===plan.originalOperation&&status.tool_name==="file_info"&&status.async_state==="completed"&&status.owned_future_active===false&&status.payload_available===true);
 const sdk=JSON.parse(files["status0.sdk.original.json"]);
 ck("closed_status_from_whole_SDK",sdk.isError!==true&&sdk.content[0].text===files["status0.native.original.json"]);
 ck("failed_SDK_exact_context",pinEq(files["page0.failed.sdk.original.json"],plan.originalFailedPageSDK)&&old.calls[plan.originalFailedCallKey].sdkPin.blob===plan.originalFailedPageSDK.blob&&old.calls[plan.originalFailedCallKey].called===true);
 ck("no_accepted_page_or_guessed_digest",old.activeObserver.pages.length===0&&old.activeObserver.nextPageOffset===0&&old.activeObserver.total===null&&old.activeObserver.digest===null&&plan.originalPayloadTotal===null&&plan.originalPayloadSHA256===null);
 const q=JSON.parse(files["request.exact.json"]);ck("exact_same_id_request",pinEq(files["request.exact.json"],plan.request)&&q.operation_id===plan.originalOperation&&q.offset===0&&q.limit===8192);
 const archiveKeys=[...after.matchAll(/archiveFlatPublicTextsOnce\(\{key:"([^"]+)"/g)].map(m=>m[1]);
 ck("three_fresh_function_body_archive_keys",JSON.stringify(archiveKeys)===JSON.stringify(plan.archiveKeys)&&new Set(archiveKeys).size===3&&!archiveKeys.some(k=>k.includes("c4a-failed")));
 function setup(){
  const map=new Map([[plan.originalSlot,JSON.parse(oldRaw)],[plan.originalSlot+":native_raw:4a-mac-stage-r1-result-info-status0",files["status0.native.original.json"]],[plan.originalSlot+":original_sdk_raw:"+plan.originalFailedCallKey,files["page0.failed.sdk.original.json"]]]),archives=[];
  const archive=async function(args){archives.push(JSON.parse(JSON.stringify(args)));return {tree:"1".repeat(40),whole:true,entries:Object.entries(args.texts).map(([path,raw])=>({path,...gitBlobMeta(raw),whole:true}))};};
  const api=new Function("store","load","tools","archiveFlatPublicTextsOnce",files["pure_helpers.original.js"]+"\n"+after+"\nreturn{fipRun,fipDecodeOnePage};")((k,v)=>map.set(k,v),k=>map.get(k),{},archive);
  const g={authorization:"GO",scope:"mac4a_stage_info_original_page0_once",maximumNativeCalls:1,operationId:plan.originalOperation,request:plan.request,originalInfoState:plan.originalState},goRaw=JSON.stringify(g,null,2)+"\n";
  return {map,archives,api,goRaw,goPin:gitBlobMeta(goRaw)};
 }
 const a=setup(),prepared=await a.api.fipRun("prepare",{goRaw:a.goRaw,goPin:a.goPin,goWholeReadback:true});
 ck("actual_prepare_with_fake_archive_only",prepared.ok&&a.archives.length===1&&prepared.value.requiresModelBoundary===true);
 ck("actual_arm_binds_new_GO",JSON.parse(a.archives[0].texts["armed.json"]).rootGo.blob===a.goPin.blob&&a.archives[0].texts["request.json"]===files["request.exact.json"]);
 ck("old_state_unchanged_after_prepare",JSON.stringify(a.map.get(plan.originalSlot),null,2)+"\n"===oldRaw);
 ck("prepare_reentry_rejected",(await a.api.fipRun("prepare",{goRaw:a.goRaw,goPin:a.goPin,goWholeReadback:true})).ok===false);
 const decoder=setup().api.fipDecodeOnePage;
 let refused=false;try{decoder(JSON.parse(files["page0.failed.sdk.original.json"]));}catch(e){refused=true;}ck("actual_error_SDK_not_metadata",refused);
 const payload='{"resultType":"complete","isError":false,"content":[]}\n',bytes=utf8Bytes(payload),page={operation_id:plan.originalOperation,offset:0,total_bytes:bytes.length,next_offset:bytes.length,eof:true,immutable_snapshot:true,payload_kind:"native_result",format:"serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization",result_sha256:gitBlobMeta(payload).sha256,data_base64:encodeBase64Bytes(bytes)};
 const make=v=>({isError:false,content:[{type:"text",text:JSON.stringify(v)}]});
 ck("opaque_whole_page_decode",decoder(make(page)).raw===payload);
 for(const [n,delta]of [["wrong_id",{operation_id:"0".repeat(64)}],["nonzero_offset",{offset:1}],["not_EOF",{eof:false}],["oversize",{total_bytes:8193,next_offset:8193}],["wrong_SHA",{result_sha256:"0".repeat(64)}]]){
  let fail=false;try{decoder(make({...page,...delta}));}catch(e){fail=true;}ck("reject_"+n,fail);
 }
 const b=setup();await b.api.fipRun("prepare",{goRaw:b.goRaw,goPin:b.goPin,goWholeReadback:true});
 const br=JSON.stringify(make(page),null,2)+"\n",bs=b.map.get(plan.retrievalSlot);bs.called=true;bs.inflight=false;bs.phase="sdk_whole_uninterpreted";bs.sdk=gitBlobMeta(br);bs.sdkArchive={whole:true};b.map.set(plan.retrievalSlot+":original-sdk-raw",br);
 const accepted=await b.api.fipRun("accept",{});
 ck("accept_archives_whole_opaque_before_semantics",accepted.ok&&accepted.value.semanticParsed===false&&accepted.value.metadataQualified===false&&b.archives.at(-1).texts["payload.original.json"]===payload);
 ck("only_retrieval_context_closed",b.map.get(plan.retrievalSlot).closed===true&&JSON.stringify(b.map.get(plan.originalSlot),null,2)+"\n"===oldRaw);
 const c=setup();await c.api.fipRun("prepare",{goRaw:c.goRaw,goPin:c.goPin,goWholeReadback:true});const cs=c.map.get(plan.retrievalSlot);cs.phase="sdk_whole_uninterpreted";cs.sdk=gitBlobMeta(br);cs.sdkArchive={whole:false};c.map.set(plan.retrievalSlot+":original-sdk-raw",br);
 ck("SDK_whole_gate_rejects",(await c.api.fipRun("accept",{})).ok===false);
 return {schema:"heptabao.mac4a.stage-info.immutable-source-verification.r1",pass:checks.every(x=>x.pass),checkCount:checks.length,checks,NativeCalls:0,toolsPassedToFake:{},runtimeQualification:false,metadataQualification:false};
}
