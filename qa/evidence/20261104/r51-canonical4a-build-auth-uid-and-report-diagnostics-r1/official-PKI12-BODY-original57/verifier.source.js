function verifyOfficialPki12BodyOriginalChain(files){
 const checks=[],same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),read=n=>{if(typeof files[n]!=="string")throw Error("missing "+n);return files[n];},parse=n=>parseLosslessIntegers(read(n));
 function ck(name,ok){checks.push({name,passed:!!ok});if(!ok)throw Error(name);}
 function pin(n,p){ck("whole pin "+n,same(gitBlobMeta(read(n)),p));}
 function tree(sha,rows){const a=gitTreeAudit({sha,truncated:false,tree:rows.map(r=>({path:r.path,mode:"100644",type:"blob",sha:gitBlobMeta(r.raw).blob}))});ck("Merkle "+sha,a.trees_verified===1&&a.leaf_count===rows.length);}
 const info=parse("STATE.before-INFO-closed.original.json"),failed=parse("STATE.failed-page0.original.json"),recovered=parse("STATE.recovered-page0.actual.json"),closed=parse("STATE.closed.original.json"),calls=parse("CALL-INDEX.public.json");
 const op="decec225ffa9d077603bcf55dea04d12f8f80273cf1d5547d5582fb54c217706",goPin=gitBlobMeta(read("BODY-GO.original.json")),req=parse("BODY-request.original.json");
 const target=info.oracleReportInfo;
 ck("exact actual INFO identity",target.size===41509&&target.sha256==="5d28fb22f023d9a4e10e3124f45e1ce68b89d0b3e0797e8c08db59bef8ea22a0"&&target.version==="2053:3321457:41509:1794009102635552960:1794009102635552960"&&same(target.full9Strings,["2053","3321457","1000","1000","33152","1","41509","1794009102635552960","1794009102635552960"]));
 ck("old ten calls and three closed observers",Object.keys(info.calls).length===10&&info.completedObservers.length===3&&info.pending===null&&info.activeObserver===null&&!info.paused);
 ck("all old calls unchanged",Object.keys(info.calls).every(k=>same(info.calls[k],closed.calls[k])));
 ck("all old closed observers unchanged",same(info.completedObservers,closed.completedObservers.slice(0,3)));
 ck("one exact whole body request",req.operation.tool==="binary_read"&&req.operation.arguments.host==="x230"&&req.operation.arguments.path===target.path&&req.operation.arguments.expected_version===target.version&&req.operation.arguments.offset===0&&req.operation.arguments.limit===target.size);
 ck("six new calls only",calls.length===6&&Object.keys(closed.calls).length===16&&Object.keys(failed.calls).length===13&&Object.keys(recovered.calls).length===13);
 const native=[];
 for(const [n,row] of calls.entries()){
  const c=row.originalCall,p=row.prefix,request=parse(p+"request.json"),intent=parse(p+"intent.json"),arm=parse(p+"armed.json");
  ck("actual call exact "+n,same(closed.calls[row.key],c)&&c.called===true&&c.armed.whole===true&&c.sdkArchive.whole===true&&same(gitBlobMeta(read(p+"request.json")),c.requestPin));
  ck("arm request GO and once "+n,same(intent.request,c.requestPin)&&same(arm.request,c.requestPin)&&same(intent.rootGo,goPin)&&same(arm.rootGo,goPin)&&arm.callKey===row.key&&arm.kind===c.kind&&arm.maximumNativeCalls===1&&arm.nativeNotYetCalled===true&&arm.mayHaveDispatchedAfterThisCheckpoint===true);
  tree(c.armed.tree,["request.json","intent.json","armed.json"].map(k=>({path:k,raw:read(p+k)})));
  pin(p+"original.sdk.json",c.sdkPin);tree(c.sdkArchive.tree,[{path:"original.sdk.json",raw:read(p+"original.sdk.json")}]);
  const sdk=JSON.parse(read(p+"original.sdk.json"));
  ck("whole SDK native exact "+n,sdk.isError!==true&&sdk.content.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===read(p+"native.original.json"));
  if(c.nativePin)pin(p+"native.original.json",c.nativePin);
  native.push(parse(p+"native.original.json"));
  if(n===0)ck("original binary admission",c.kind==="operation_start"&&same(request,req)&&native[n].operation_id===op&&native[n].tool_name==="binary_read"&&native[n].reused===false&&native[n].automatic_retry===false);
  else if(n===1)ck("original completed stored inactive status",c.kind==="operation_status"&&request.operation_id===op&&native[n].operation_id===op&&native[n].async_state==="completed"&&native[n].owned_future_active===false&&native[n].result_state==="stored_observed"&&native[n].payload_available===true);
  else ck("only original ordered page request "+n,c.kind==="operation_result"&&request.operation_id===op&&request.offset===(n-2)*16384&&request.limit===16384);
 }
 ck("page0 original rejection remains",calls[2].originalCall.phase==="native_interpretation_refused"&&same(failed.calls[calls[2].key],closed.calls[calls[2].key]));
 ck("all thirteen pre-continuation calls unchanged",Object.keys(failed.calls).every(k=>same(failed.calls[k],recovered.calls[k])&&same(failed.calls[k],closed.calls[k])));
 ck("original outer failure preserved",same(failed.outerFailure,recovered.outerFailure)&&same(failed.outerFailure,closed.outerFailure)&&failed.outerFailure.message==="exact_original_page_extent");
 const ap=parse("RECOVERY-APPLY.actual.json"),recoveryGO=gitBlobMeta(read("RECOVERY-GO.original.json"));
 ck("actual zero-Native cached apply",ap.applied===true&&ap.phase==="applied_once"&&ap.nativeCalls===0&&ap.gitCalls===0&&ap.failedCallRetained===true&&same(ap.rootGo,recoveryGO)&&same(ap.beforeState,gitBlobMeta(read("STATE.failed-page0.original.json")))&&same(ap.afterState,gitBlobMeta(read("STATE.recovered-page0.actual.json"))));
 const restored=JSON.parse(JSON.stringify(recovered));for(const k of ["paused","pending","activeObserver"])restored[k]=failed[k];
 ck("pure recovery exactly three fields",same(restored,failed)&&recovered.paused===false&&recovered.pending===null&&recovered.activeObserver.nextPageOffset===16384&&recovered.activeObserver.pages.length===1);
 const cont=parse("CONTINUATION-ADMISSION.original.json");
 ck("external whole continuation preserves original body GO",same(cont.continuationGO,gitBlobMeta(read("CONTINUATION-GO.original.json")))&&same(cont.originalBodyGO,goPin)&&cont.originalArmGOContinuesUnchanged===true&&cont.maximumNativeCalls===3&&cont.page0Replay===false&&same(cont.actualRecoveredState,ap.afterState));
 let bytes=[],cursor=0;
 for(let n=2;n<6;n++){
  const p=native[n],b=unb64(p.data_base64);
  ck("immutable original page "+(n-2),p.operation_id===op&&p.immutable_snapshot===true&&p.offset===cursor&&b.length<=16384&&p.next_offset===cursor+b.length&&p.total_bytes===55762&&p.result_sha256==="dfad7e61e08ada43dc512c7a5014db31584d41babd5839b6271ab59516f06502"&&p.eof===(n===5)&&p.automatic_retry===false);
  bytes=bytes.concat(b);cursor=p.next_offset;
 }
 ck("all four pages reconstruct exact payload",cursor===55762&&utf8Text(bytes)===read("payload.original.json")&&gitBlobMeta(read("payload.original.json")).sha256==="dfad7e61e08ada43dc512c7a5014db31584d41babd5839b6271ab59516f06502");
 const payload=JSON.parse(read("payload.original.json"));
 ck("whole payload original native",payload.isError===false&&payload.content.length===1&&payload.content[0].type==="text"&&payload.content[0].text===read("binary.native.original.json"));
 const v=parse("binary.native.original.json"),bodyBytes=unb64(v.data_base64),bodyPin=gitBlobMeta(read("REPORT.original.json"));
 ck("actual exact-version whole decoded report",v.path===target.path&&v.version===target.version&&v.size===41509&&v.offset===0&&v.next_offset===41509&&v.eof===true&&v.chunk_sha256===target.sha256&&bodyBytes.length===41509&&utf8Text(bodyBytes)===read("REPORT.original.json")&&bodyPin.sha256===target.sha256);
 for(const [receiptName,originalName,storedName] of [["PAYLOAD-ARCHIVE-WHOLE.original.json","payload.original.json","payload.original.json"],["BODY-ARCHIVE-WHOLE.original.json","REPORT.original.json","report.original.json"]]){
  const a=parse(receiptName);ck("external whole "+receiptName,a.whole===true&&a.entries.length===1&&a.entries[0].whole===true&&a.entries[0].path===storedName);
  ck("whole exact entry "+receiptName,["blob","bytes","sha256"].every(k=>a.entries[0][k]===gitBlobMeta(read(originalName))[k]));
  tree(a.tree,[{path:storedName,raw:read(originalName)}]);
 }
 ck("final physical and logical closure",closed.paused===false&&closed.pending===null&&closed.activeObserver===null&&closed.nativeCallInFlight===false&&closed.completedObservers.length===4&&closed.completedObservers.at(-1).id===op&&closed.completedObservers.at(-1).completedInactive===true&&closed.completedObservers.at(-1).pages===4&&closed.oracleReportBody.whole===true&&same(closed.oracleReportBody.bodyPin,bodyPin));
 const r=parse("REPORT.original.json"),expected={"pki.mount":204,"pki.root":200,"pki.role":200,"pki.role_read":200,"pki.issue":200,"pki.cert_lookup":200,"pki.crl_json":200,"pki.lease_lookup":200,"pki.lease_revoke":204,"pki.revoked_lease_absent":400,"pki.lease_expire_issue":200,"pki.lease_expire_lookup":400};
 ck("raw twelve-case denominator no candidate or ACL rerun",r.capture_complete===true&&r.failure===null&&r.pki.pki12_passed===true&&r.pki.denominator===12&&r.pki_case_denominator===12&&r.pki_requests_observed===12&&r.pki_request_cap===12&&r.status_normalization===false&&r.strict_raw_status_required===true&&r.candidate_started===false&&r.official_acl23_reexecuted===false&&r.parity_qualified===false&&r.pki.independent_fixture_qualification===false&&Object.keys(r.pki.cases).length===12);
 for(const [id,status]of Object.entries(expected)){
  const c=r.pki.cases[id],o=c.original_result,w=c.wire;
  ck("raw PKI "+id,o.http_status===status&&same(o.expected_http_status,[status])&&o.result==="passed"&&Object.values(o.semantics).every(x=>x===true)&&w.length===1&&w[0].case_id===id&&w[0].status===status&&w[0].complete===true&&w[0].context_closed===true&&w[0].open_calls===1&&w[0].read_calls===1&&w[0].normalized_status===false&&w[0].retried===false);
 }
 ck("source input nine once closed",r.source_inputs.length===9&&r.source_fd_rows_before_publication.length===9&&r.source_fd_rows_before_publication.every((x,i)=>x.opened===true&&x.closed===true&&x.close_attempts===1&&same(x.full9_decimal,r.source_inputs[i].full9_decimal)&&x.bytes===r.source_inputs[i].bytes&&x.sha256===r.source_inputs[i].sha256));
 ck("four actual original children closed",r.original_owner.profile_seconds===360&&r.original_owner.external_original_deadline===true&&r.original_owner.passed_process_method===true&&r.original_owner.same_originals_closed===true&&r.original_owner.children.length===4&&r.original_owner.children.every(x=>x.exit_code===0&&x.completed_original_wait_count===1&&x.same_original_Popen_wait===true&&x.original_SID_retired_observed===true&&x.gaps.length===0&&x.SID_observation_gaps.length===0&&x.SID_survivors.length===0));
 ck("meaningful fake component eight and zero HTTP",r.components.classes===4&&r.components.variants===8&&r.components.HTTP_requests===0&&r.components.fixture_or_subprocess_launches===0&&r.components.product_cases===0&&r.components.results.length===8&&r.components.results.every(x=>x.passed===true&&x.suite_call_restored===true));
 ck("original synthetic cleanup and final publication boundary",r.pki.original_cleanup.result==="passed"&&r.pki.original_cleanup.failure_count===0&&r.publication_close_verdict_is_in_terminal_stdout===true);
 return {schema:"heptabao.official271-pki12.body-original-chain-verification.r1",passed:true,check_count:checks.length,checks,scope:{newOriginalCalls:6,immutablePages:4,payloadBytes:55762,reportBytes:41509,originalTotalCalls:16,closedObservers:4,cachedPage0NativeCalls:0,originalFailureRetained:true,officialPkiCases:12,candidateParityQualified:false}};
}