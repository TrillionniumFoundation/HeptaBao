function verifyDualInfoActual(input) {
 const checks=[];const ck=(name,v)=>{checks.push({name,pass:v===true});if(v!==true)throw Error(name);};
 const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const pin=(raw,p)=>{const q=gitBlobMeta(raw);return q.blob===p.blob&&q.bytes===p.bytes&&q.sha256===p.sha256;};
 const min=input.min,go=input.go,plan=input.plan,act=JSON.parse(min["ACTUAL-BINDINGS.public.json"]),rel=JSON.parse(min["RELEASE.public.json"]);
 ck("root-GO-exact",min["ROOT-GO.original.json"]===go);
 ck("two-bindings",act.length===2);
 ck("release-six-two-two",rel.originalCalls===6&&rel.closedObservers===2&&rel.pages===2);
 ck("released",rel.C_lane_released===true&&rel.pending===null&&rel.activeObservers===0&&rel.nativeCallsInFlight===0&&rel.unresolvedFutures===0);
 ck("reported-serial-release",rel.firstContextReleasedBeforeSecondInitialize===true);
 ck("no-body-stage-build",rel.binaryBodyRead===false&&rel.MacStageQualified===false&&rel.CargoExecuted===false);
 for(let i=0;i<2;i++){
  const tag=i===0?"mac":"x230",b=act[i],e=plan.ordered_bindings[i],s=JSON.parse(min[tag+".closed-state.original.json"]);
  const n=JSON.parse(min[tag+".info.native.original.json"]),o=s.completedObservers[0],calls=Object.entries(s.calls);
  ck(tag+"/tag",b.tag===tag&&b.slot===e.slot);
  ck(tag+"/native-pin",pin(min[tag+".info.native.original.json"],b.native)&&pin(min[tag+".closed-state.original.json"],b.state));
  ck(tag+"/state-GO",s.goRaw===go&&s.rootGoWhole===true);
  ck(tag+"/never-process",s.job===null&&s.startCalled===false);
  ck(tag+"/closed-state",s.pending===null&&s.activeObserver===null&&s.nativeCallInFlight===false&&s.paused===false);
  ck(tag+"/three-calls",calls.length===3&&eq(calls.map(x=>x[1].kind),["operation_start","operation_status","operation_result"]));
  ck(tag+"/observer",s.completedObservers.length===1&&o.id===b.operation&&o.tool==="file_info"&&o.completedInactive===true&&o.pages===1);
  ck(tag+"/metadata-path-size-sha",n.path===e.expected.path&&n.size===e.expected.bytes&&n.sha256===e.expected.sha256);
  const f=e.expected.full9;
  ck(tag+"/version-lossless",n.version===[f[0],f[1],f[6],f[7],f[8]].join(":"));
  ck(tag+"/linux-owner-mode",n.mode===384&&n.metadata.mode===384&&n.metadata.uid===1000&&n.metadata.gid===1000&&n.metadata.link_count===1&&n.metadata.metadata_platform==="linux");
  ck(tag+"/metadata-no-acl-xattrs",n.metadata.acl_sha256==="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"&&eq(n.metadata.xattr_names,[])&&eq(n.metadata.xattr_sha256,{}));
  ck(tag+"/actual-binding-native",eq(n,b.metadata));
  const payload=input.archives[tag].payload["payload.original.json"],pv=JSON.parse(payload);
  ck(tag+"/payload-pin",pin(payload,b.payload)&&pin(payload,o.payload));
  ck(tag+"/payload-complete",pv.resultType==="complete"&&pv.isError===false&&pv.content.length===1&&pv.content[0].type==="text");
  ck(tag+"/payload-exact-native",pv.content[0].text===min[tag+".info.native.original.json"]);
  const nv=[];
  for(let j=0;j<3;j++){
   const [key,c]=calls[j],a=input.archives[tag].calls[key],arm=a.arm,sdkraw=a.sdk["original.sdk.json"],sdk=JSON.parse(sdkraw);
   ck(tag+"/"+j+"/arm-request",arm["request.json"]===c.requestRaw&&pin(c.requestRaw,c.requestPin));
   ck(tag+"/"+j+"/arm-root-go",eq(JSON.parse(arm["armed.json"]).rootGo,s.goPin)&&eq(JSON.parse(arm["intent.json"]).rootGo,s.goPin));
   ck(tag+"/"+j+"/accepted-original",c.called===true&&c.phase==="accepted"&&c.armed.whole===true&&c.sdkArchive.whole===true);
   ck(tag+"/"+j+"/sdk-pin",pin(sdkraw,c.sdkPin));
   ck(tag+"/"+j+"/sdk-shape",sdk.isError===false&&sdk.content.length===1&&sdk.content[0].type==="text");
   ck(tag+"/"+j+"/native-pin",pin(sdk.content[0].text,c.nativePin));
   nv.push(JSON.parse(sdk.content[0].text));
  }
  ck(tag+"/exact-info-request",calls[0][1].requestRaw===input.source[tag+".request.exact.json"]);
  ck(tag+"/admission",nv[0].operation_id===b.operation&&nv[0].tool_name==="file_info"&&nv[0].reused===false);
  ck(tag+"/status-request",eq(JSON.parse(calls[1][1].requestRaw),{operation_id:b.operation}));
  ck(tag+"/status-terminal",nv[1].operation_id===b.operation&&nv[1].tool_name==="file_info"&&nv[1].async_state==="completed"&&nv[1].owned_future_active===false&&nv[1].payload_available===true);
  ck(tag+"/closed-status-original",min[tag+".closed-status.sdk.original.json"]===input.archives[tag].calls[calls[1][0]].sdk["original.sdk.json"]);
  const pageReq=JSON.parse(calls[2][1].requestRaw),page=nv[2],bytes=unb64(page.data_base64);
  ck(tag+"/page-request",pageReq.operation_id===b.operation&&pageReq.offset===0&&pageReq.limit===8192);
  ck(tag+"/immutable-page-bounds",page.operation_id===b.operation&&page.immutable_snapshot===true&&page.offset===0&&page.next_offset===bytes.length&&page.total_bytes===bytes.length&&page.eof===true&&bytes.length<=8192);
  ck(tag+"/page-payload",utf8Text(bytes)===payload&&page.result_sha256===gitBlobMeta(payload).sha256);
 }
 return {schema:"heptabao.root.dual-bundle-info-original-qualification.r1",passed:true,checkCount:checks.length,checks,originalSDKsIndependentlyWhole:6,armTreesIndependentlyWhole:6,payloadTreesIndependentlyWhole:2,NativeCallsAdded:0,CReleased:true,bundleBodyQualified:false};
}