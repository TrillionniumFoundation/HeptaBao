function verify4aStageInfoActualRoot(i){
 const checks=[];const ck=(name,v)=>{checks.push({name,pass:v===true});if(v!==true)throw Error(name);};const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const files=i.files,s=JSON.parse(files["STATE.original.json"]),md=JSON.parse(files["METADATA.public.json"]),rel=JSON.parse(files["RELEASE.public.json"]),old=JSON.parse(i.oldState);
 for(const e of JSON.parse(files["MANIFEST.public.json"]).entries)ck("manifest-"+e.path,eq(gitBlobMeta(files[e.path]),{blob:e.blob,bytes:e.bytes,sha256:e.sha256}));
 ck("old-seven-calls-exact",Object.keys(old.calls).length===7&&Object.entries(old.calls).every(([k,v])=>eq(v,s.calls[k])));
 ck("old-two-observers-exact",old.completedObservers.length===2&&old.completedObservers.every((v,n)=>eq(v,s.completedObservers[n])));
 ck("GO-INFO-exact",files["GO.INFO.original.json"]===i.infoGo);
 ck("GO-RECOVERY-exact",files["GO.RECOVERY.original.json"]===i.recoveryGo);
 ck("known-local-error-retained",eq(JSON.parse(files["LOCAL-ERROR.original.json"]),s.outerFailure)&&s.outerFailure.message==="closed_gfRun_action"&&s.outerFailure.action==="close");
 const recovered=JSON.parse(i.recoveredState);ck("recovered-original-calls-exact",eq(recovered.calls,s.calls)&&eq(recovered.outerFailure,s.outerFailure));
 const op="578da6337fdfe69127df760cd01b59b0916e181914666ba5f1be3c97fa82bd00";
 const ns={};for(const suffix of ["start","status0","p0"]){
  const k="c4a-source-r1-reportinfo-"+suffix,c=s.calls[k],req=files[k+".request.json"],intent=JSON.parse(files[k+".intent.json"]),arm=JSON.parse(files[k+".armed.json"]),sdk=JSON.parse(files[k+".SDK.original.json"]),raw=files[k+".native.original.json"];
  ck(suffix+"-accepted-single-call",c.called===true&&c.phase==="accepted"&&c.requestRaw===req&&eq(c.requestPin,gitBlobMeta(req)));
  ck(suffix+"-armed-binding",intent.callKey===k&&arm.callKey===k&&intent.originalJob===s.job&&intent.maximumNativeCalls===1&&intent.nativeNotYetCalled===true&&arm.mayHaveDispatchedAfterThisCheckpoint===true&&eq(intent.request,c.requestPin)&&eq(arm.request,c.requestPin));
  ck(suffix+"-SDK-whole-original",!sdk.isError&&sdk.content.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===raw&&eq(c.sdkPin,gitBlobMeta(files[k+".SDK.original.json"]))&&eq(c.nativePin,gitBlobMeta(raw)));
  ck(suffix+"-archives-whole",c.sdkArchive.whole===true&&c.armed.whole===true);
  ns[suffix]=parseLosslessIntegers(raw);ck(suffix+"-same-operation",ns[suffix].operation_id===op);
 }
 const q=JSON.parse(files["c4a-source-r1-reportinfo-start.request.json"]);
 ck("fixed-file-info",q.operation.tool==="file_info"&&q.operation.arguments.host==="rog"&&q.operation.arguments.path===md.path);
 ck("admission-one-nonreused",ns.start.reused===false&&ns.start.tool_name==="file_info"&&ns.start.automatic_retry===false);
 ck("original-completed-inactive",ns.status0.async_state==="completed"&&ns.status0.owned_future_active===false&&ns.status0.payload_available===true);
 const page=ns.p0,payload=utf8Text(unb64(page.data_base64));
 ck("one-contiguous-original-page",page.offset===0&&page.next_offset===579&&page.total_bytes===579&&page.eof===true&&page.immutable_snapshot===true);
 ck("payload-original-exact",payload===files["INFO.payload.original.json"]&&gitBlobMeta(payload).sha256===page.result_sha256);
 const envelope=JSON.parse(payload);ck("original-native-exact",envelope.resultType==="complete"&&envelope.isError===false&&envelope.content.length===1&&envelope.content[0].text===files["INFO.native.original.json"]);
 const info=parseLosslessIntegers(files["INFO.native.original.json"]);
 ck("metadata-actual-fixed-path",info.path==="/home/qian-qi/hb-4a49405b-src-20261106-r1/control/stage-result.public.json"&&md.path===info.path);
 ck("metadata-actual-size-SHA",info.size===31257&&info.sha256==="5f7d5a19bd785dd3bd258a21de2452bf7029c5e5c91a2f69b8c0be19b2ae5be5"&&md.size===info.size&&md.sha256===info.sha256);
 ck("metadata-original-version",info.version==="66306:34603472:31257:1794007676686666010:1794007676686666010"&&md.version===info.version);
 ck("metadata-owner-mode-link",info.mode===384&&info.metadata.mode===384&&info.metadata.uid===1000&&info.metadata.gid===1000&&info.metadata.link_count===1&&info.metadata.metadata_platform==="linux");
 ck("empty-ACL-xattrs",info.metadata.acl_sha256==="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"&&info.metadata.xattr_names.length===0&&Object.keys(info.metadata.xattr_sha256).length===0);
 ck("full9-derived-strings",eq(md.full9Strings,["66306","34603472","1000","1000","33152","1","31257","1794007676686666010","1794007676686666010"]));
 ck("native-pin-and-state-metadata",eq(md.nativeText,gitBlobMeta(files["INFO.native.original.json"]))&&eq(s.stageResultInfo,md));
 ck("original-state-closed",s.job==="1a1b3307dc2-fc05-80f8"&&s.pending===null&&s.activeObserver===null&&!s.nativeCallInFlight&&!s.paused&&Object.keys(s.calls).length===10&&s.completedObservers.length===3&&s.completedObservers.every(x=>x.completedInactive));
 ck("release-bound-state",eq(rel.state,gitBlobMeta(files["STATE.original.json"]))&&rel.NativeLaneReleased===true&&rel.NativeFutureCount===0&&rel.pending===null&&rel.activeObserver===null&&rel.bodyAuthorized===false&&rel.detailReportQualified===false);
 ck("release-original-observer",eq(rel.originalOperation,s.completedObservers[2])&&rel.originalOperation.id===op&&rel.increment.calls===3&&rel.increment.observers===1&&rel.increment.pages===1);
 return {schema:"heptabao.root.4a-stage-info-actual-qualification.r1",ok:true,checks:checks.length,results:checks,sourceTree:i.tree,originalJob:s.job,operation:op,metadata:md,release:gitBlobMeta(files["RELEASE.public.json"]),knownLocalErrorPreserved:true,recoveryOnlyLocalPausedFlag:true,nativeReplay:false,bodyQualified:false,productQualified:false,NativeLaneReleased:true};
}