
function verifySnapshotBody0Actual(p,expectedSource,expectedGO,oldPacket){
 const checks=[];const ck=(name,v)=>{checks.push({name,passed:v===true});if(v!==true)throw Error(name)};
 const raw=p.raw,rel=JSON.parse(raw["RELEASE.public.json"]),idx=JSON.parse(raw["CHAIN.index.public.json"]);
 const byBlob=new Map(Object.values(raw).map(s=>[gitBlobMeta(s).blob,s]));
 const blob=b=>{const t=byBlob.get(b);if(t===undefined)throw Error("missing_whole_blob:"+b);return t};
 const pinEq=(s,v)=>{const m=gitBlobMeta(s);return ["blob","bytes","sha256"].every(k=>m[k]===v[k])};
 ck("complete54MerklePacket",p.audit.whole===true&&p.audit.files===54&&p.audit.bytes===519955&&p.audit.tree==="d87a8a11c329d76639c6d9caf6537319d7298977");
 ck("exactPreviouslyQualifiedSource",raw["journal.executed.js"]===expectedSource&&pinEq(expectedSource,rel.source));
 ck("exactConditionalRootGO",raw["root-GO.original.json"]===expectedGO.text&&pinEq(expectedGO.text,rel.rootGO));
 const calls=idx.calls.map((x,i)=>{const prefix=String(i).padStart(2,"0")+"-"+x.kind;return {key:x.callKey,kind:x.kind,phase:x.phase,requestPin:x.request,sdkPin:x.sdk,nativePin:x.native,requestText:raw[prefix+".request.original.json"],sdkText:raw[prefix+".sdk.original.json"],nativeText:raw[prefix+".native.original.json"],armedText:raw[prefix+".armed.original.json"],intentText:raw[prefix+".intent.original.json"],armedTree:x.armTree}});
 const cs=verifyOriginalJournal({label:"body0_reused",calls,observers:[rel.observedBinding],blob,goPins:[rel.rootGO],pageLimit:()=>16384,ck});
 for(let i=0;i<calls.length;i++)ck("sdk_tree_"+i,immediateTreeSha([{path:"original.sdk.json",mode:"100644",type:"blob",sha:calls[i].sdkPin.blob}])===idx.calls[i].sdkTree);
 const start=cs[0],native=JSON.parse(raw["range0.native.original.json"]),bytes=unb64(native.data_base64);
 ck("exactOriginal432ByteRequest",start.c.requestPin.blob==="06f7a3eccf5de1c877b552cab886d14086d0c51c"&&start.c.requestPin.bytes===432&&start.c.requestPin.sha256==="35921fca79a714035d0033a003d481862326e4a8dc6409f5017bbc4fb37ea992"&&start.q.idempotency_key==="heptabao-native-snapshot-2379d02b-formatter-observe-r1-result-body0");
 ck("reusedExistingImmutableBinding",start.n.reused===true&&start.n.operation_id==="36a74adfd7493cdb489a3426c421ac9d83e772f674a3aaab3c83fb3deea207af"&&start.n.idempotency_binding_retained===true&&start.n.admission_is_not_dispatch_completion===true);
 ck("oneStartOneStatusSixPages",calls.length===8&&calls.filter(x=>x.kind==="operation_start").length===1&&calls.filter(x=>x.kind==="operation_status").length===1&&calls.filter(x=>x.kind==="operation_result").length===6);
 ck("exactOriginalPathAndVersion",native.path===start.q.operation.arguments.path&&native.version==="66306:31236133:118925:1793956739343592677:1793956739343592677"&&native.version===start.q.operation.arguments.expected_version&&native.size===118925);
 ck("range0ExtentAndHash",native.offset===0&&native.next_offset===65536&&bytes.length===65536&&native.eof===false&&sha256Latin1(byteString(bytes))===native.chunk_sha256&&native.chunk_sha256==="e18d09bf4ecf8ad38c46d8ee3c46c5fa7d7816f680b98bce43f493053ce6f09e");
 ck("nativeAndPayloadWholeIdentity",pinEq(raw["range0.native.original.json"],rel.originalRangeNativeWhole)&&pinEq(raw["payload.original.json"],rel.originalPayloadWhole));
 const oldUnknown=JSON.parse(raw["old-UNKNOWN.original.json"]);
 ck("preservedOriginalUnknownWhole",gitBlobMeta(raw["old-UNKNOWN.original.json"]).blob==="b174296c1b46c119356df90d5c68b6ca5bc4c19c"&&Object.values(oldPacket.raw).includes(raw["old-UNKNOWN.original.json"]));
 ck("preservedOriginalErrorWhole",gitBlobMeta(raw["old-error.SDK.original.json"]).blob==="f181c1e93e7b64c402b332fd29b23d0141762082"&&Object.values(oldPacket.raw).includes(raw["old-error.SDK.original.json"]));
 ck("oldHistoricalAttemptNotRewritten",oldUnknown.paused===true&&oldUnknown.readonlyAdmissionOutcome==="UNKNOWN"&&oldUnknown.observedOperationId===null&&oldUnknown.secondBodySubmitted===false&&rel.originalAttemptOutcome==="UNKNOWN"&&rel.originalContextPausedPreserved===true&&rel.originalContextPendingPreserved===true);
 ck("currentLaneClosedAndBody1Absent",rel.currentToolCallsInFlight===0&&rel.currentOwnedFutureObservedActive===false&&rel.currentPending===null&&rel.currentActiveObserver===null&&rel.secondBodySubmitted===false&&rel.lineBReleased===true&&rel.decodedRange.wholeFileBody===false);
 return {schema:"heptabao.root.snapshot2379-body0-reconciliation-actual-qualification.r1",passed:true,checkCount:checks.length,checks,source:rel.source,rootGO:rel.rootGO,packet:p.audit,originalHistoricalAttempt:"UNKNOWN_PRESERVED",actualBinding:start.n.operation_id,reused:true,originalPayload:rel.originalPayloadWhole,range:rel.decodedRange,NativeCalls:0,actualCalls:8,completedObservers:1,immutablePages:6,body1Submitted:false,wholeReportQualified:false,currentLineBReleased:true,productionSwitch:false};
}