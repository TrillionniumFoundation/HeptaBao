function makeFailedTestBodies(before,reference,st) {
 const expected=st.logInfos.map(x=>({path:x.path,bytes:x.size,sha256:x.sha256,version:x.version,infoOperation:x.originalOperation,infoNative:x.nativeText,full9Strings:x.full9Strings}));
 const requests=expected.map((x,i)=>({idempotency_key:"heptabao-native-jwt-pki-025b05a3-build149-failed-test2-"+(i===0?"stderr":"stdout")+"-body-r1",operation:{tool:"binary_read",arguments:{host:"rog",path:x.path,offset:0,limit:x.bytes,expected_version:x.version}}}));
 const requestRaws=requests.map(x=>JSON.stringify(x,null,2)+"\n"),requestPins=requestRaws.map(gitBlobMeta);
 const prerequisites=st.completedObservers.map(x=>({id:x.id,tool:x.tool,nativeText:x.nativeText}));
 let extra=reference.slice(reference.indexOf("/* Separate exact GO:"),reference.indexOf("\nfunction gfNeed"));
 const replaceExtra=(a,b)=>{if(!extra.includes(a))throw Error("extension token:"+a);extra=extra.split(a).join(b);};
 extra=extra.replace(/const GF_STDERR_BODY_REQUEST = .*;\n/, "const GF_LOG_BODY_REQUESTS = "+JSON.stringify(requestPins)+";\n")
 .replace(/const GF_STDERR_BODY_EXPECTED = .*;\n/,"const GF_LOG_BODY_EXPECTED = "+JSON.stringify(expected)+";\n")
 .replace(/const GF_LOG_INFO_PREREQUISITES = .*;\n/,"const GF_LOG_INFO_PREREQUISITES = "+JSON.stringify(prerequisites)+";\n");
 extra=extra.slice(0,extra.indexOf("function gfAuthorize"))+
`function gfAuthorizeFailedTestLogBodiesOnly({goRaw,goPin,goWholeReadback}) {
 const s=gfState();
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null && s.activeObserver===null
   && s.onlyFixedCompilerLogInfos===true && s.logInfos.length===2
   && s.completedObservers.length===2 && s.logInfoStarted.every(x=>x===true)
   && Object.keys(s.calls).length===6 && Object.values(s.calls).every(c=>c.phase==="accepted"&&c.sdkArchive.whole===true)
   && s.failedTestLogBodiesGO===undefined && s.failedTestLogBodies===undefined,
   "both_original_log_infos_closed_before_two_bodies");
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin) && goPin.blob!==s.goPin.blob,
   "separate_whole_two_log_bodies_GO");
 const g=JSON.parse(goRaw);
 gfNeed(g.authorization==="GO" && g.scope==="build_failed_test2_logs_binary_read_only"
   && g.original_job==="1a1b10cad9b-fc05-7560"
   && g.maximum_binary_read_starts===2 && g.maximum_file_info_starts===0
   && g.maximum_process_start_calls===0 && g.immutable_body_page_bytes===16384
   && Array.isArray(g.exact_requests) && g.exact_requests.length===2
   && g.exact_requests.every((x,i)=>x.blob===GF_LOG_BODY_REQUESTS[i].blob
    && x.bytes===GF_LOG_BODY_REQUESTS[i].bytes && x.sha256===GF_LOG_BODY_REQUESTS[i].sha256)
   && JSON.stringify(g.info_operations)===JSON.stringify(GF_LOG_INFO_PREREQUISITES.map(x=>x.id)),
   "two_exact_original_test_bodies_only_scope");
 for(let i=0;i<2;i++) {
  const p=GF_LOG_INFO_PREREQUISITES[i],o=s.completedObservers[i],info=s.logInfos[i],need=GF_LOG_BODY_EXPECTED[i];
  gfNeed(o?.id===p.id && o.completedInactive===true && o.tool==="file_info"
   && o.nativeText.blob===p.nativeText.blob
   && gfMetaEquals(load(GF_SLOT+":closed_native:"+p.id),p.nativeText),
   "both_independent_log_infos_whole");
  gfNeed(info.path===need.path && info.size===need.bytes && info.sha256===need.sha256
   && info.version===need.version && info.originalOperation===need.infoOperation
   && JSON.stringify(info.full9Strings)===JSON.stringify(need.full9Strings)
   && need.bytes===[191,375][i] && need.bytes<=65536,"whole_actual_log_info_binding");
 }
 s.failedTestLogBodiesGO={pin:goPin,raw:goRaw,whole:true};
 s.failedTestLogBodies=[];s.failedTestLogBodyStarted=[false,false];
 gfSave(s);
 return {exactRequests:GF_LOG_BODY_REQUESTS,maximumBinaryReads:2,bytes:566};
}
`;
 extra=extra.replace(/\/\* Separate exact GO:[\s\S]*?\*\//,"/* Separate exact GO: failed-test stderr191 then stdout375, total566.\n * Both original INFOs closed. Only new binary payload pages use16KiB.\n */");
 let after=before;const rep=(a,b)=>{if(after.split(a).length!==2)throw Error("unique actual-before token:"+a);after=after.replace(a,b);};
 rep("function gfNeed(value, code)",extra+"\nfunction gfNeed(value, code)");
 const admission=`  if(s.failedTestLogBodiesGO?.whole===true) {
   const i=s.failedTestLogBodies.length,need=GF_LOG_BODY_EXPECTED[i],a=q.operation?.arguments;
   gfNeed(i<2 && s.activeObserver===null && s.failedTestLogBodyStarted[i]===false
     && s.logInfos.length===2 && s.completedObservers.length===2+i
     && Object.values(s.calls).filter(c=>c.kind==="operation_start").length===2+i
     && gfMetaEquals(raw,GF_LOG_BODY_REQUESTS[i])
     && Object.keys(q).sort().join(",")==="idempotency_key,operation"
     && q.operation?.tool==="binary_read"
     && Object.keys(q.operation).sort().join(",")==="arguments,tool"
     && a && Object.keys(a).sort().join(",")==="expected_version,host,limit,offset,path"
     && a.host==="rog" && a.path===need.path && a.offset===0
     && a.limit===need.bytes && a.expected_version===need.version,
     "two_sequential_exact_log_bodies_no_path_or_version_fallback");
   return;
  }
`;
 rep(' } else if(kind==="operation_start") {\n  const i=s.logInfos.length,need=GF_LOG_TARGETS[i];',' } else if(kind==="operation_start") {\n'+admission+'  const i=s.logInfos.length,need=GF_LOG_TARGETS[i];');
 rep("q.limit===8192",'q.limit===(s.activeObserver.tool==="binary_read"?16384:8192)');
 rep(' if(c.kind==="operation_start")s.logInfoStarted[s.logInfos.length]=true;',` if(c.kind==="operation_start" && q.operation.tool==="file_info")s.logInfoStarted[s.logInfos.length]=true;
 if(c.kind==="operation_start" && q.operation.tool==="binary_read")s.failedTestLogBodyStarted[s.failedTestLogBodies.length]=true;`);
 rep("gfNeed(b.length<=8192",'gfNeed(b.length<=(a.tool==="binary_read"?16384:8192)');
 const close=`  if(a.tool==="binary_read") {
   const i=s.failedTestLogBodies.length,need=GF_LOG_BODY_EXPECTED[i];
   gfNeed(i<2 && s.failedTestLogBodiesGO?.whole===true && s.failedTestLogBodyStarted[i]===true
    && a.request.operation.arguments.path===need.path
    && v.path===need.path && v.size===need.bytes && v.offset===0
    && v.next_offset===need.bytes && v.eof===true
    && v.version===need.version && v.chunk_sha256===need.sha256,
    "exact_versioned_original_test_log_body");
   const b=unb64(v.data_base64),bodyRaw=utf8Text(b),bodyPin=gitBlobMeta(bodyRaw);
   gfNeed(b.length===need.bytes && bodyPin.bytes===need.bytes
     && bodyPin.sha256===need.sha256,"whole_original_test_log_bytes");
   const bodyArchive=await archiveFlatPublicTextsOnce({
    key:"gcc-testlog-"+a.id,repository:"TrillionniumFoundation/HeptaBao",
    texts:{[GF_LOG_TARGETS[i].role+".original.txt"]:bodyRaw,"native.original.json":nativeRaw}});
   s.failedTestLogBodies.push({...bodyPin,index:i,role:GF_LOG_TARGETS[i].role,
     archiveTree:bodyArchive.tree,whole:true,originalOperation:a.id,version:need.version,path:need.path});
   store(GF_SLOT+":test_log_original:"+i,bodyRaw);
  } else if(a.tool==="file_info") {`;
 rep('  if(a.tool==="file_info") {',close);
 rep('  if(action==="initialize")value=gfInitializeOnlyAfterRootGO(args);','  if(action==="authorize_failed_test_log_bodies")value=gfAuthorizeFailedTestLogBodiesOnly(args);\n  else if(action==="initialize")value=gfInitializeOnlyAfterRootGO(args);');
 return {before,after,expected,prerequisites,requests,requestRaws,requestPins,sourcePin:gitBlobMeta(after),beforePin:gitBlobMeta(before),stateRaw:JSON.stringify(st,null,2)+"\n",statePin:gitBlobMeta(JSON.stringify(st,null,2)+"\n")};
}
