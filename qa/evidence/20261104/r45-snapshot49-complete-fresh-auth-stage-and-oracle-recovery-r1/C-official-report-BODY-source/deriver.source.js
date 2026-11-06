function deriveOracleReportBodyFromReconciledInfo(infoSource,stateRaw,infoRaw) {
 const state=JSON.parse(stateRaw),info=parseLosslessIntegers(infoRaw),record=state.oracleReportInfo;
 if(state.paused||state.pending!==null||state.activeObserver!==null||state.nativeCallInFlight
   ||Object.keys(state.calls).length!==2||state.completedObservers.length!==1
   ||state.reconcileStatusCalls!==1||state.originalStatusCalls!==1||!record)throw Error("new INFO reconcile context fully closed");
 const observed=state.completedObservers[0];
 if(observed.id!==record.originalOperation||!observed.completedInactive||observed.tool!=="file_info"
   ||JSON.stringify(gitBlobMeta(infoRaw))!==JSON.stringify(observed.nativeText))throw Error("same actual original INFO");
 const expected={path:info.path,bytes:info.size,sha256:info.sha256,version:info.version,
   full9Strings:record.full9Strings,infoOperation:observed.id,infoNative:observed.nativeText};
 if(expected.path!=="/home/qian/heptabao-official271-acl23-oracle-20261106-r1/result.public.json"
   ||expected.bytes!==36658||expected.sha256!=="4b72f600f6b794c5cf7198ebe76696179cd2477da587113a5ee7bfe81be3eece"
   ||record.version!==info.version)throw Error("actual report content binding");
 const request={idempotency_key:"heptabao-official271-x230-acl23-oracle-report-body-r1",
  operation:{tool:"binary_read",arguments:{host:"x230",path:expected.path,offset:0,limit:expected.bytes,expected_version:expected.version}}};
 const requestRaw=JSON.stringify(request,null,2)+"\n",requestPin=gitBlobMeta(requestRaw),priorPin=gitBlobMeta(stateRaw);
 let after=infoSource.after;
 const replace=(a,b)=>{if(after.split(a).length!==2)throw Error("unique BODY graft "+a.slice(0,50));after=after.replace(a,b);};
 replace("function gfNeed(value, code)",
  "const GF_ORACLE_REPORT_BODY_REQUEST = "+JSON.stringify(requestPin)+";\n"
  +"const GF_ORACLE_REPORT_BODY_EXPECTED = "+JSON.stringify(expected)+";\n"
  +"const GF_ORACLE_REPORT_BODY_PRIOR_STATE = "+JSON.stringify(priorPin)+";\n\nfunction gfNeed(value, code)");
 const authorize=`function gfAuthorizeOracleReportBody({goRaw,goPin,goWholeReadback,priorStateRaw}) {
 const s=gfState();
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin) && goPin.blob!==s.goPin.blob,
        "separate_whole_report_body_GO");
 const g=JSON.parse(goRaw),need=GF_ORACLE_REPORT_BODY_EXPECTED;
 gfNeed(g.authorization==="GO" && g.scope==="official271_oracle_result_binary_read_only"
  && g.original_job==="1a1b17f9eff-fc05-7932" && g.maximum_binary_read_operations===1
  && g.maximum_file_info_operations===0 && g.maximum_process_start_calls===0
  && g.maximum_operation_status_calls===8 && g.maximum_operation_result_calls===128
  && g.maximum_payload_bytes===1048576 && g.immutable_body_page_bytes===16384
  && g.info_operation===need.infoOperation
  && JSON.stringify(g.exact_request)===JSON.stringify(GF_ORACLE_REPORT_BODY_REQUEST),
  "one_exact_actual_versioned_report_body_authority");
 gfNeed(gfMetaEquals(priorStateRaw,GF_ORACLE_REPORT_BODY_PRIOR_STATE)
  && JSON.stringify(s,null,2)+"\\n"===priorStateRaw && !s.paused && !s.nativeCallInFlight
  && s.pending===null && s.activeObserver===null && s.completedObservers.length===1
  && Object.keys(s.calls).length===2 && Object.values(s.calls).every(c=>c.phase==="accepted"&&c.sdkArchive?.whole===true)
  && s.reconcileStatusCalls===1 && s.originalStatusCalls===1
  && s.oracleReportBodyGO===undefined && s.oracleReportBody===undefined,
  "actual_INFO_reconciliation_whole_closed_body_boundary");
 const o=s.completedObservers[0],i=s.oracleReportInfo;
 gfNeed(o.id===need.infoOperation && o.tool==="file_info" && o.completedInactive===true
  && gfMetaEquals(load(GF_SLOT+":closed_native:"+o.id),need.infoNative)
  && i.originalOperation===o.id && i.path===need.path && i.size===need.bytes
  && i.sha256===need.sha256 && i.version===need.version
  && JSON.stringify(i.full9Strings)===JSON.stringify(need.full9Strings) && need.bytes<=65536,
  "single_independent_actual_metadata_prerequisite");
 s.oracleReportBodyGO={raw:goRaw,pin:goPin,whole:true};s.onlyOracleReportBody=true;
 s.oracleReportBodyStarted=false;s.oracleReportBody=null;gfSave(s);
 return {authorized:true,bytes:need.bytes,maximumBinaryReads:1,immutablePageBytes:16384};
}
function gfValidateRequest(s,kind,q,raw) {
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null,"single_call_boundary");
 gfNeed(s.oracleReportBodyGO?.whole===true && s.onlyOracleReportBody===true,
        "separate_report_body_GO_before_any_new_call");
 if(kind==="operation_start") {
  const n=GF_ORACLE_REPORT_BODY_EXPECTED;
  gfNeed(s.activeObserver===null && s.oracleReportBody===null && s.oracleReportBodyStarted===false
   && s.completedObservers.length===1 && Object.values(s.calls).filter(c=>c.kind==="operation_start").length===0
   && gfMetaEquals(raw,GF_ORACLE_REPORT_BODY_REQUEST)
   && q.operation?.tool==="binary_read" && q.operation.arguments.host==="x230"
   && q.operation.arguments.path===n.path && q.operation.arguments.offset===0
   && q.operation.arguments.limit===n.bytes && q.operation.arguments.expected_version===n.version,
   "one_original_versioned_public_report_body_only");
 } else if(kind==="operation_status") {
  gfNeed(s.oracleReportBodyStarted===true && s.activeObserver?.tool==="binary_read"
   && !s.activeObserver.futureClosed && Object.keys(q).join(",")==="operation_id"
   && q.operation_id===s.activeObserver.id
   && Object.values(s.calls).filter(c=>c.kind==="operation_status"&&JSON.parse(c.requestRaw).operation_id===q.operation_id).length<8,
   "only_returned_body_original_ID_status_within_eight");
 } else if(kind==="operation_result") {
  gfNeed(s.oracleReportBodyStarted===true && s.activeObserver?.tool==="binary_read"
   && s.activeObserver.futureClosed===true && !s.activeObserver.eof
   && s.activeObserver.pages.length<128 && Object.keys(q).sort().join(",")==="limit,offset,operation_id"
   && q.operation_id===s.activeObserver.id && q.limit===16384
   && q.offset===s.activeObserver.nextPageOffset,"closed_body_immutable_next_page_only");
 } else throw new Error("only_one_fixed_body_admission_and_original_result");
}
`;
 const start=after.indexOf("function gfValidateRequest("),end=after.indexOf("async function gfPrepareOne(",start);
 if(start<0||end<start)throw Error("validator bounds");after=after.slice(0,start)+authorize+after.slice(end);
 replace("rootGo:s.goPin,originalJob:s.job","rootGo:s.oracleReportBodyGO?.pin??s.goPin,originalJob:s.job");
 replace(' if(c.kind==="operation_status")s.reconcileStatusCalls++;',' if(c.kind==="operation_start")s.oracleReportBodyStarted=true;');
 replace('  if(c.kind==="operation_status")sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_status(q);',
  '  if(c.kind==="operation_start")sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_start(q);\n  else if(c.kind==="operation_status")sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_status(q);');
 replace('  if(c.kind==="operation_status") {\n   const a=s.activeObserver;',`  if(c.kind==="operation_start") {
   gfNeed(typeof v.operation_id==="string" && /^[a-f0-9]{64}$/.test(v.operation_id)
    && v.tool_name==="binary_read" && typeof v.reused==="boolean" && v.automatic_retry===false,
    "same_fixed_binary_admission_ACK");
   s.activeObserver={id:v.operation_id,request:q,tool:"binary_read",futureClosed:false,
    nextPageOffset:0,eof:false,pages:[],total:null,digest:null};
  } else if(c.kind==="operation_status") {
   const a=s.activeObserver;`);
 replace("gfNeed(b.length<=8192 && v.next_offset","gfNeed(b.length<=(a.tool===\"binary_read\"?16384:8192) && v.next_offset");
 replace('  if(a.tool==="file_info") {',`  if(a.tool==="binary_read") {
   const n=GF_ORACLE_REPORT_BODY_EXPECTED;
   gfNeed(s.onlyOracleReportBody===true && s.oracleReportBodyStarted===true && s.oracleReportBody===null
    && a.request.operation.arguments.host==="x230" && a.request.operation.arguments.path===n.path
    && v.path===n.path && v.size===n.bytes && v.offset===0 && v.next_offset===n.bytes && v.eof===true
    && v.version===n.version && v.chunk_sha256===n.sha256,"actual_versioned_report_whole_extent");
   const bytes=unb64(v.data_base64),bodyRaw=utf8Text(bytes),bodyPin=gitBlobMeta(bodyRaw);
   gfNeed(bytes.length===n.bytes && bodyPin.bytes===n.bytes && bodyPin.sha256===n.sha256,
    "whole_actual_report_bytes_before_semantics");
   const bodyArchive=await archiveFlatPublicTextsOnce({key:"gcc-oracle-report-"+a.id,
    repository:"TrillionniumFoundation/HeptaBao",
    texts:{"report.original.json":bodyRaw,"native.original.json":nativeRaw}});
   s.oracleReportBody={body:bodyPin,whole:true,archiveTree:bodyArchive.tree,
    originalOperation:a.id,path:n.path,version:n.version};
   store(GF_SLOT+":oracle_report_body_original",bodyRaw);
  } else if(a.tool==="file_info") {`);
 replace('  if(action==="initialize")value=gfInitializeOnlyAfterRootGO(args);',
  '  if(action==="authorize_oracle_report_body")value=gfAuthorizeOracleReportBody(args);\n  else if(action==="initialize")value=gfInitializeOnlyAfterRootGO(args);');
 const diff=strictDiff(infoSource.after,after,"oracle.gitfirst.reconciled-report-body.js");
 if(applyStrict(infoSource.after,diff,false)!==after||applyStrict(after,diff,true)!==infoSource.after)throw Error("strict roundtrip");
 return {before:infoSource.after,after,diff,sourcePin:gitBlobMeta(after),request,requestRaw,requestPin,expected,stateRaw,statePin:priorPin,infoRaw};
}