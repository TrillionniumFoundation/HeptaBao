function verifyOracleInfoReconciliationActual(files) {
 const checks=[];function ck(name,v){checks.push({name,passed:!!v});if(!v)throw Error(name);}
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),meta=gitBlobMeta;
 const go=JSON.parse(files["ROOT-GO.public.json"]),old=JSON.parse(files["ORIGINAL.paused-state.before.json"]),state=JSON.parse(files["STATE.reconcile.closed.json"]),release=JSON.parse(files["RELEASE.public.json"]),index=JSON.parse(files["CALL-INDEX.public.json"]);
 ck("exact original paused bytes",same(meta(files["ORIGINAL.paused-state.before.json"]),go.original_state));
 ck("original paused context byteidentical",files["ORIGINAL.paused-state.before.json"]===files["ORIGINAL.paused-state.after.json"]);
 ck("original status remains called unknown",old.paused&&old.pending===go.original_failed_status_key&&old.calls[go.original_failed_status_key].called&&old.activeObserver.futureClosed===false);
 ck("original status SDK exact",same(meta(files["ORIGINAL.failed-status.sdk.json"]),go.original_failed_status_SDK));
 ck("original status SDK timeout",JSON.parse(files["ORIGINAL.failed-status.sdk.json"]).isError===true&&files["ORIGINAL.failed-status.sdk.json"].includes("-32603"));
 const ackSDK=JSON.parse(files["ORIGINAL.admission.sdk.json"]),ack=parseLosslessIntegers(ackSDK.content[0].text);
 ck("original ACK recovered operation identity",ack.operation_id===go.original_operation_id&&ack.tool_name==="file_info"&&ack.reused===false);
 ck("new scope status only no admission",go.authorization==="GO"&&go.maximum_operation_start_calls===0&&go.maximum_process_start_calls===0&&go.maximum_new_operation_status_calls===1);
 ck("exact authorized journal",same(meta(files["journal.original.js"]),go.source));
 ck("new two calls only status and result",index.length===2&&index[0].kind==="operation_status"&&index[1].kind==="operation_result");
 ck("new context closed",!state.paused&&!state.nativeCallInFlight&&state.pending===null&&state.activeObserver===null&&state.completedObservers.length===1);
 ck("one new plus one original status within eight",state.reconcileStatusCalls===1&&state.originalStatusCalls===1&&release.totalStatusQueries===2&&release.maximumAllowedStatusQueries===8);
 let status=null,page=null;
 for(let i=0;i<index.length;i++){
  const row=index[i],pre="call-"+String(i).padStart(2,"0"),q=JSON.parse(files[pre+".request.original.json"]),intent=JSON.parse(files[pre+".intent.original.json"]),armed=JSON.parse(files[pre+".armed.original.json"]),sdk=JSON.parse(files[pre+".sdk.original.json"]),nativeRaw=files[pre+".native.original.json"],native=parseLosslessIntegers(nativeRaw),c=state.calls[row.key];
  ck(pre+" request whole",same(meta(files[pre+".request.original.json"]),row.request)&&c.requestRaw===files[pre+".request.original.json"]);
  ck(pre+" intent root binding",same(intent.rootGo,meta(files["ROOT-GO.public.json"]))&&same(intent.request,row.request)&&intent.originalOperation===go.original_operation_id&&intent.originalJob===go.original_job&&intent.maximumNativeCalls===1);
  ck(pre+" arm byte derivation",same(armed,{...intent,schema:"heptabao.gitfirst.fixed-native-call-armed.r1",mayHaveDispatchedAfterThisCheckpoint:true,recovery:"Read exact original job/operation only; absence of later ACK is UNKNOWN."}));
  const ents=["request","intent","armed"].map(n=>({path:n+".json",mode:"100644",type:"blob",sha:meta(files[pre+"."+n+".original.json"]).blob,size:meta(files[pre+"."+n+".original.json"]).bytes}));
  ck(pre+" three leaf arm Merkle",gitTreeAudit({sha:row.armedTree,truncated:false,tree:ents}).root_sha===row.armedTree);
  ck(pre+" SDK whole",same(meta(files[pre+".sdk.original.json"]),row.sdk)&&same(c.sdkPin,row.sdk)&&c.sdkArchive.whole===true);
  ck(pre+" SDK accepted after archive",c.phase==="accepted"&&c.called===true&&c.armed.whole===true&&sdk.isError!==true);
  ck(pre+" native byteexact",sdk.content.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===nativeRaw&&same(meta(nativeRaw),row.native));
  ck(pre+" same original ID",q.operation_id===go.original_operation_id&&native.operation_id===go.original_operation_id);
  if(i===0){
   status=native;
   ck("same exact89 status request",same(meta(files[pre+".request.original.json"]),go.exact_status_request));
   ck("original future now closed",native.async_state==="completed"&&native.owned_future_active===false&&native.result_state==="stored_observed"&&native.payload_available===true&&native.tool_name==="file_info"&&native.automatic_retry===false);
  }else{
   page=native;
   ck("exact original page zero8192",q.offset===0&&q.limit===8192&&native.offset===0&&native.eof===true&&native.immutable_snapshot===true&&native.payload_kind==="native_result");
   ck("one whole immutable payload",native.total_bytes===578&&native.next_offset===578&&utf8Text(unb64(native.data_base64))===files["INFO.payload.original.json"]&&meta(files["INFO.payload.original.json"]).sha256===native.result_sha256);
  }
 }
 const payload=parseLosslessIntegers(files["INFO.payload.original.json"]),infoRaw=files["INFO.native.original.json"],info=parseLosslessIntegers(infoRaw),md=info.metadata,parts=info.version.split(":");
 ck("native whole payload successful",payload.resultType==="complete"&&payload.isError===false&&payload.content.length===1&&payload.content[0].type==="text"&&payload.content[0].text===infoRaw);
 ck("INFO exact expected path size SHA",info.path===go.report_target.path&&info.size===go.report_target.bytes&&info.sha256===go.report_target.sha256);
 ck("INFO mode owner link",info.mode===384&&md.mode===384&&md.metadata_platform==="linux"&&md.uid===1000&&md.gid===1000&&md.link_count===1);
 ck("INFO empty ACL and xattrs",md.acl_sha256==="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"&&md.xattr_names.length===0&&Object.keys(md.xattr_sha256).length===0);
 ck("INFO decimal version fields",parts.length===5&&parts.every(x=>/^[0-9]+$/.test(x))&&parts[2]===String(info.size));
 const full9=[parts[0],parts[1],"1000","1000",String(32768|info.mode),"1",String(info.size),parts[3],parts[4]];
 ck("INFO full9 exact original stdout",same(full9,go.report_target.full9Strings)&&same(full9,state.oracleReportInfo.full9Strings));
 const o=state.completedObservers[0];
 ck("closed observer whole exact pins",o.id===go.original_operation_id&&o.tool==="file_info"&&o.completedInactive&&o.pages===1&&same(o.payload,meta(files["INFO.payload.original.json"]))&&same(o.nativeText,meta(infoRaw)));
 ck("actual version recorded",state.oracleReportInfo.version===info.version&&same(state.oracleReportInfo.nativeText,meta(infoRaw)));
 ck("release exact state pin",same(release.state,meta(files["STATE.reconcile.closed.json"])));
 ck("release zero calls/futures",release.currentNativeCalls===0&&release.currentActiveFutures===0&&release.laneReleased&&release.bodyReadAuthorized===false);
 ck("release does not invent child closure",release.ownerChildClosureObserved===false);
 return {schema:"heptabao.oracle-original-info-reconcile-actual-check.r1",passed:true,check_count:checks.length,checks,new_calls:2,new_status_queries:1,original_status_queries:1,immutable_pages:1,payload_bytes:578,body_bytes_observed:0,original_unknown_preserved:true,old_context_byte_identical:true,product_cases:0};
}