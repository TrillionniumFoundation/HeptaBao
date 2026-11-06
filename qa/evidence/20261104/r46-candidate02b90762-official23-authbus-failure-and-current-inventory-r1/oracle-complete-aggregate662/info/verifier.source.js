function verifyOracleR2ReportInfoOriginalChain(files) {
 const checks=[];function ck(name,value){checks.push({name,passed:!!value});if(!value)throw Error(name);}
 const parse=raw=>parseLosslessIntegers(raw),same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const pin=(raw,p)=>same(gitBlobMeta(raw),{blob:p.blob,bytes:p.bytes,sha256:p.sha256});
 const g=parse(files["ROOT-GO.public.json"]),q=parse(files["REQUEST.exact.json"]),before=parse(files["PRIOR-STATE.original.json"]),s=parse(files["STATE.closed.original.json"]),ix=parse(files["CALL-INDEX.public.json"]);
 ck("whole exact INFO GO",pin(files["ROOT-GO.public.json"],{blob:"b73bc52094bcfb4e2a6fe3ac343a096293dc4afd",bytes:3364,sha256:"606ac5905629756fd4b04208498f44da847512d5ca529400719bc7aced8149cc"}));
 ck("exact INFO request and journal",pin(files["REQUEST.exact.json"],g.exact_request)&&pin(files["journal.source.js"],g.journal));
 ck("exact closed original prior state and stdout",pin(files["PRIOR-STATE.original.json"],g.prior_state)&&pin(files["STDOUT.original.txt"],g.original_stdout));
 ck("closed actual INFO state",s.job===g.original_job&&!s.paused&&!s.nativeCallInFlight&&s.pending===null&&s.activeObserver===null);
 ck("original seven calls retained",Object.keys(before.calls).length===7&&Object.keys(s.calls).length===10&&Object.keys(before.calls).every(k=>same(before.calls[k],s.calls[k])));
 ck("two old closed observers retained",before.completedObservers.length===2&&s.completedObservers.length===3&&same(before.completedObservers,s.completedObservers.slice(0,2)));
 ck("only three new kinds",ix.length===3&&same(ix.map(x=>x.kind),["operation_start","operation_status","operation_result"]));
 const values=[];
 for(const row of ix){
  const base=row.prefix,c=s.calls[row.key],requestRaw=files[base+".request.original.json"],sdkRaw=files[base+".sdk.original.json"],nativeRaw=files[base+".native.original.json"];
  const request=parse(requestRaw),sdk=parse(sdkRaw),native=parse(nativeRaw),intent=parse(files[base+".intent.original.json"]),armed=parse(files[base+".armed.original.json"]);
  ck(base+" request/SDK/native whole identities",pin(requestRaw,c.requestPin)&&pin(sdkRaw,c.sdkPin)&&pin(nativeRaw,c.nativePin));
  ck(base+" original accepted external boundary",c.called===true&&c.phase==="accepted"&&c.armed.whole===true&&c.sdkArchive.whole===true);
  ck(base+" SDK text precedes interpretation",sdk.isError!==true&&sdk.content.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===nativeRaw);
  ck(base+" separate INFO GO scoped intent",same(intent.rootGo,s.oracleReportInfoGO.pin)&&same(intent.rootGo,gitBlobMeta(files["ROOT-GO.public.json"]))&&intent.callKey===row.key&&intent.kind===row.kind&&intent.maximumNativeCalls===1&&intent.nativeNotYetCalled===true&&same(intent.request,c.requestPin));
  ck(base+" exact armed boundary",armed.callKey===row.key&&armed.mayHaveDispatchedAfterThisCheckpoint===true&&same(armed.rootGo,intent.rootGo)&&same(armed.request,intent.request));
  ck(base+" three-leaf arm Merkle",gitTreeAudit({sha:row.armedTree,truncated:false,tree:[["request.json",requestRaw],["intent.json",files[base+".intent.original.json"]],["armed.json",files[base+".armed.original.json"]]].map(([path,raw])=>({path,type:"blob",mode:"100644",sha:gitBlobMeta(raw).blob}))}).leaf_count===3);
  ck(base+" one-leaf SDK Merkle",gitTreeAudit({sha:row.sdkTree,truncated:false,tree:[{path:"original.sdk.json",type:"blob",mode:"100644",sha:gitBlobMeta(sdkRaw).blob}]}).leaf_count===1);
  values.push({request,native});
 }
 const [admit,status,page]=values,o=s.completedObservers[2],a=admit.native;
 ck("one exact public file_info admission",same(admit.request,q)&&q.operation.tool==="file_info"&&q.operation.arguments.host==="x230"&&q.operation.arguments.path===g.target.path);
 ck("unique returned INFO ID",a.operation_id===o.id&&a.tool_name==="file_info"&&a.reused===false&&a.automatic_retry===false);
 ck("known same ID closed/stored/inactive",status.request.operation_id===o.id&&status.native.operation_id===o.id&&status.native.async_state==="completed"&&status.native.owned_future_active===false&&status.native.result_state==="stored_observed"&&status.native.payload_available===true);
 ck("same ID one immutable page request",page.request.operation_id===o.id&&page.request.offset===0&&page.request.limit===8192);
 const b=unb64(page.native.data_base64),raw=files["INFO.payload.original.json"];
 ck("whole immutable payload range",page.native.operation_id===o.id&&page.native.offset===0&&page.native.next_offset===b.length&&page.native.total_bytes===b.length&&page.native.eof===true&&page.native.immutable_snapshot===true&&b.length<=8192&&utf8Text(b)===raw);
 ck("whole immutable payload digest",pin(raw,o.payload)&&gitBlobMeta(raw).sha256===page.native.result_sha256&&o.pages===1&&o.completedInactive===true);
 ck("whole payload Merkle",gitTreeAudit({sha:o.payloadTree,truncated:false,tree:[{path:"payload.original.json",type:"blob",mode:"100644",sha:gitBlobMeta(raw).blob}]}).leaf_count===1);
 const env=parse(raw),nativeRaw=files["INFO.native.original.json"];
 ck("original success native envelope",env.resultType==="complete"&&env.isError===false&&env.content.length===1&&env.content[0].text===nativeRaw&&pin(nativeRaw,o.nativeText));
 const n=parse(nativeRaw),md=n.metadata,t=g.target,parts=n.version.split(":");
 ck("actual path/size/SHA exactly terminal",n.path===t.path&&n.size===651803&&n.size===t.bytes&&n.sha256===t.sha256&&n.sha256==="9048f3b5c854a190dadde86f5d7eec180c497313065bd70bd23a87124789a62d");
 ck("actual Linux single-link permission/owner",n.mode===384&&md.metadata_platform==="linux"&&md.mode===384&&md.uid===1000&&md.gid===1000&&md.link_count===1);
 ck("actual decimal native version",parts.length===5&&parts.every(x=>/^[0-9]+$/.test(x))&&parts[2]===String(n.size));
 const full9=[parts[0],parts[1],"1000","1000",String(32768|n.mode),"1",String(n.size),parts[3],parts[4]],terminal=parse(files["STDOUT.original.txt"]);
 ck("independent full9 exactly original terminal",same(full9,t.full9Strings)&&same(full9,terminal.report.full9_decimal));
 ck("closed state binds actual metadata",s.oracleReportInfo.originalOperation===o.id&&s.oracleReportInfo.version===n.version&&s.oracleReportInfo.path===n.path&&s.oracleReportInfo.size===n.size&&s.oracleReportInfo.sha256===n.sha256&&same(s.oracleReportInfo.full9Strings,full9));
 ck("body still unobserved and unauthorized",s.oracleReportInfo.bodyReadAuthorized===false&&!Object.values(s.calls).some(c=>c.kind==="operation_start"&&parse(c.requestRaw).operation.tool==="binary_read"));
 const release=parse(files["RELEASE.public.json"]);
 ck("C released with no future",release.laneReleased===true&&release.nativeCallsInFlight===0&&release.activeFutures===0&&release.reportBodyRead===false&&release.ownerReceiptQualified===false);
 return {schema:"heptabao.official271.r2.report-info.actual-checks.r1",pass:true,check_count:checks.length,checks,calls:3,observers:1,pages:1,metadataBytes:n.size,metadataSHA256:n.sha256,actualVersion:n.version,full9Strings:full9,RuntimeCallsByVerifier:0,bodyReadByVerifier:false,ownerReceiptQualified:false,aclCaseResultsQualified:false};
}
