async function verifyMacStageBodySource(input) {
 const rows=[];function check(name,v){if(!v)throw Error(name);rows.push(name);}
 const H=new Function(input.pure+"\n"+input.strict+"\nreturn {gitBlobMeta,applyStrict};")();
 const before=JSON.parse(input.stateRaw),slot="successor576_mac_source_only_stage_gitfirst_r1";
 const need=input.need,request=JSON.parse(input.requestRaw),rp=H.gitBlobMeta(input.requestRaw);
 check("strict forward",H.applyStrict(input.before,input.diff,false)===input.after);
 check("strict reverse",H.applyStrict(input.after,input.diff,true)===input.before);
 check("source unchanged exact metadata 10 calls",Object.keys(before.calls).length===10&&before.completedObservers.length===3);
 check("closed original context",before.pending===null&&before.activeObserver===null&&!before.paused&&!before.nativeCallInFlight);
 check("info identity exact",before.stageResultInfo.path===need.path&&before.stageResultInfo.size===7665&&before.stageResultInfo.sha256===need.sha256&&before.stageResultInfo.version===need.version);
 check("actual Mac metadata observed",before.stageResultInfo.metadataPlatform==="darwin"&&JSON.stringify(before.stageResultInfo.full9Strings)===JSON.stringify(need.full9)&&need.full9[2]==="501"&&need.full9[3]==="20"&&need.full9[4]==="33152");
 check("original info whole native",H.gitBlobMeta(input.nativeRaw).blob===need.infoNative.blob);
 check("one exact offset zero body",request.operation.tool==="binary_read"&&request.operation.arguments.offset===0&&request.operation.arguments.limit===7665&&request.operation.arguments.expected_version===need.version&&request.operation.arguments.path===need.path&&request.operation.arguments.host==="mac");
 const start=input.after.indexOf("async function gfInvokePreparedOnce"),body=input.after.slice(start,input.after.indexOf("function gfAcceptArchivedSDK",start));
 check("once body before native",body.indexOf("s.stageResultBodyStarted=true")<body.indexOf("sdk=await tools."));
 check("SDK immutable before interpretation",body.indexOf('store(GF_SLOT+":original_sdk:"+callKey,sdk)')<body.indexOf("c.sdkArchive=await archiveFlatPublicTextsOnce"));
 check("payload whole before parse",input.after.indexOf('texts:{"payload.original.json":raw}')<input.after.indexOf("const p=parseLosslessIntegers(raw)"));
 check("body whole before record",input.after.indexOf('texts:{"stage-result.original.json":bodyRaw}')<input.after.indexOf('store(GF_SLOT+":stage_result_body_raw",bodyRaw)'));
 check("original page ceiling unchanged",input.after.includes("q.limit===8192")&&input.after.includes("b.length<=8192")&&input.after.includes("v.total_bytes<=1048576"));
 const go={authorization:"GO",scope:"stage_result_binary_read_only",original_job:before.job,info_operation:need.infoOperation,maximum_binary_read_starts:1,immutable_page_bytes:8192,exact_request:rp};
 const goRaw=JSON.stringify(go,null,2)+"\n",goPin=H.gitBlobMeta(goRaw);
 function env() {
  const map=new Map([[slot,JSON.parse(input.stateRaw)],[slot+":closed_native:"+need.infoOperation,input.nativeRaw]]),captured=[];
  const put=(k,v)=>map.set(k,JSON.parse(JSON.stringify(v))),get=k=>map.get(k);
  const fakeArchive=async args=>{captured.push(args);return {tree:"0".repeat(40),whole:true,entries:Object.entries(args.texts).map(([path,raw])=>({path,...H.gitBlobMeta(raw),whole:true}))};};
  const noTools=new Proxy({}, {get(){throw Error("SOURCE verification forbids all external tools");}});
  const J=new Function("store","load","tools","archiveFlatPublicTextsOnce",input.pure+"\n"+input.after+"\nreturn {gfRun,gfValidateRequest};")(put,get,noTools,fakeArchive);
  return {map,captured,J};
 }
 const authorized=async()=>{const e=env(),r=await e.J.gfRun("authorize_stage_result_body",{goRaw,goPin,goWholeReadback:true});check("source-only fake authorization "+rows.length,r.ok);return e;};
 const missing=env();let r=await missing.J.gfRun("prepare",{callKey:"fake-body-no-go",kind:"operation_start",requestRaw:input.requestRaw});
 check("no BODY without separate GO",!r.ok&&missing.captured.length===0);
 for(const kind of ["operation_start","operation_status","operation_result"]){
  const e=await authorized(),state=e.map.get(slot),oldCalls=JSON.stringify(state.calls);
  let raw=input.requestRaw;
  if(kind!=="operation_start"){state.activeObserver={id:"a".repeat(64),tool:"binary_read",futureClosed:kind==="operation_result",nextPageOffset:0,eof:false};raw=JSON.stringify(kind==="operation_status"?{operation_id:state.activeObserver.id}:{operation_id:state.activeObserver.id,offset:0,limit:8192},null,2)+"\n";}
  const out=await e.J.gfRun("prepare",{callKey:"fake-"+kind.replaceAll("_","-"),kind,requestRaw:raw});
  check("actual prepare "+kind,out.ok&&e.captured.length===1);
  const ar=e.captured[0].texts,arm=JSON.parse(ar["armed.json"]),intent=JSON.parse(ar["intent.json"]);
  check("new arm body GO "+kind,arm.rootGo.blob===goPin.blob&&intent.rootGo.blob===goPin.blob&&arm.originalJob===before.job);
  check("all prior original calls immutable "+kind,JSON.stringify(Object.fromEntries(Object.keys(before.calls).map(k=>[k,e.map.get(slot).calls[k]])))===JSON.stringify(before.calls));
 }
 for(const mutation of ["offset","version","file_info","repeat"]){
  const e=await authorized(),q=JSON.parse(input.requestRaw),state=e.map.get(slot);
  if(mutation==="offset")q.operation.arguments.offset=1;
  if(mutation==="version")q.operation.arguments.expected_version+="0";
  if(mutation==="file_info")q.operation={tool:"file_info",arguments:{host:"mac",path:need.path}};
  if(mutation==="repeat")state.stageResultBodyStarted=true;
  r=await e.J.gfRun("prepare",{callKey:"fake-refuse-"+mutation.replaceAll("_","-"),kind:"operation_start",requestRaw:JSON.stringify(q,null,2)+"\n"});
  check("refuse "+mutation,!r.ok&&e.captured.length===0);
 }
 const e=await authorized();e.map.get(slot).activeObserver={id:"b".repeat(64),tool:"binary_read",futureClosed:false};
 for(let i=0;i<8;i++)e.map.get(slot).calls["old-fake-status-"+i]={kind:"operation_status",called:true,requestRaw:JSON.stringify({operation_id:"b".repeat(64)})};
 r=await e.J.gfRun("prepare",{callKey:"fake-ninth-status",kind:"operation_status",requestRaw:JSON.stringify({operation_id:"b".repeat(64)})});
 check("eighth original status cap",!r.ok&&e.captured.length===0);
 check("no original store mutation",JSON.stringify(before)===JSON.stringify(JSON.parse(input.stateRaw)));
 return {pass:true,check_count:rows.length,checks:rows,scope:"pure source and memory archive only; no Native/Git/Python/report body execution"};
}
