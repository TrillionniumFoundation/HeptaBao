function verify4aStageBodyRoot(i){
 const checks=[];const ck=(name,v)=>{checks.push({name,pass:v===true});if(v!==true)throw Error(name);};const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const f=i.files,s=JSON.parse(f["STATE.original.json"]),old=JSON.parse(i.oldState),rel=JSON.parse(f["RELEASE.public.json"]),op="c577930dab615d3c97a41b0296313ca4d03805b614becfbe033a40fdb736edd3";
 ck("exact-BODY-GO",f["GO.BODY.original.json"]===i.bodyGO);
 ck("INFO-original-exact",f["INFO.native.original.json"]===i.oldINFO);
 ck("old-ten-calls-exact",Object.keys(old.calls).length===10&&Object.entries(old.calls).every(([k,c])=>eq(c,s.calls[k])));
 ck("old-three-observers-exact",old.completedObservers.length===3&&old.completedObservers.every((o,n)=>eq(o,s.completedObservers[n])));
 ck("local-error-recovery-retained",eq(s.outerFailure,old.outerFailure)&&eq(rel.localCloseActionError,s.outerFailure)&&rel.localRecovery.NativeCalls===0&&rel.localRecovery.goPin.blob===i.recoveryGO.blob);
 const calls=Object.entries(s.calls).slice(10),native=[];ck("eight-original-delta",calls.length===8);
 for(const[k,c]of calls){
  const entry=i.originals[k],arm=entry.arm,sdkFiles=entry.sdk,intent=JSON.parse(arm["intent.json"]),armed=JSON.parse(arm["armed.json"]),sdkRaw=sdkFiles["original.sdk.json"],sdk=JSON.parse(sdkRaw);
  ck(k+"-request-exact",c.requestRaw===arm["request.json"]&&eq(c.requestPin,gitBlobMeta(c.requestRaw))&&c.called===true&&c.phase==="accepted");
  ck(k+"-original-arm",intent.callKey===k&&armed.callKey===k&&intent.kind===c.kind&&armed.kind===c.kind&&eq(intent.request,c.requestPin)&&eq(armed.request,c.requestPin)&&intent.maximumNativeCalls===1&&intent.nativeNotYetCalled===true&&armed.mayHaveDispatchedAfterThisCheckpoint===true);
  ck(k+"-original-sdk",eq(c.sdkPin,gitBlobMeta(sdkRaw))&&sdk.isError===false&&sdk.content.length===1&&sdk.content[0].type==="text");
  const raw=sdk.content[0].text;ck(k+"-native-exact",eq(c.nativePin,gitBlobMeta(raw)));
  const n=parseLosslessIntegers(raw);ck(k+"-original-op",n.operation_id===op);native.push(n);
 }
 const startQ=JSON.parse(calls[0][1].requestRaw);ck("one-reviewed-body-request",calls[0][1].requestRaw===i.bodyRequest&&startQ.operation.tool==="binary_read");
 ck("one-start-nonreused",native[0].reused===false&&native[0].tool_name==="binary_read"&&native[0].automatic_retry===false);
 ck("status-completed-inactive",native[1].async_state==="completed"&&native[1].owned_future_active===false&&native[1].payload_available===true);
 ck("status-sdk-exact-min",i.originals[calls[1][0]].sdk["original.sdk.json"]===f["BODY.status.SDK.original.json"]);
 let joined=[],offset=0;for(let j=2;j<native.length;j++){
  const n=native[j],q=JSON.parse(calls[j][1].requestRaw),bytes=unb64(n.data_base64);
  ck("page"+(j-2)+"-cursor",q.operation_id===op&&q.limit===8192&&q.offset===offset&&n.offset===offset&&n.next_offset===offset+bytes.length&&bytes.length<=8192);
  ck("page"+(j-2)+"-snapshot",n.immutable_snapshot===true&&n.total_bytes===42091&&n.result_sha256===rel.originalBodyObserver.payload.sha256&&n.eof===(j===7));
  joined.push(...bytes);offset=n.next_offset;
 }
 const payload=utf8Text(joined);ck("six-pages-whole",joined.length===42091&&offset===42091&&payload===f["BODY.payload.original.json"]&&eq(gitBlobMeta(payload),rel.originalBodyObserver.payload));
 const envelope=JSON.parse(payload);ck("payload-native-exact",envelope.resultType==="complete"&&envelope.isError===false&&envelope.content.length===1&&envelope.content[0].text===f["BODY.native.original.json"]);
 const b=JSON.parse(f["BODY.native.original.json"]),md=JSON.parse(f["INFO.native.original.json"]);
 ck("binary-path-version",b.path===md.path&&b.version===md.version&&b.version===i.expectedVersion);
 ck("binary-fixed-extent",b.offset===0&&b.size===31257&&b.next_offset===31257&&b.eof===true);
 const report=utf8Text(unb64(b.data_base64));ck("decoded-original-report",report===f["stage-result.original.json"]&&report===i.reportRaw&&gitBlobMeta(report).sha256===b.chunk_sha256&&b.chunk_sha256===md.sha256&&eq(gitBlobMeta(report),rel.report));
 ck("all-eighteen-calls-accepted",Object.keys(s.calls).length===18&&Object.values(s.calls).every(c=>c.called&&c.phase==="accepted"));
 ck("four-observers-closed",s.completedObservers.length===4&&s.completedObservers.every(o=>o.completedInactive)&&eq(s.completedObservers[3],rel.originalBodyObserver));
 ck("state-released",s.pending===null&&s.activeObserver===null&&!s.nativeCallInFlight&&!s.paused);
 ck("release-agrees",rel.NativeLaneReleased===true&&rel.NativeFutureCount===0&&rel.increment.calls===8&&rel.increment.pages===6&&rel.cumulative.calls===18&&rel.cumulative.observers===4&&rel.cumulative.pages===9);
 return {schema:"heptabao.root.4a-stage-report-BODY-original-qualification.r1",ok:true,checks:checks.length,results:checks,originalJob:s.job,operation:op,report:gitBlobMeta(report),originalCallsIndependentlyRead:8,originalArmsIndependentlyRead:8,originalImmutablePages:6,allCalls18Closed:true,knownLocalActionErrorPreserved:true,pureRecoveryPreserved:true,NativeLaneReleased:true,productQualification:false};
}