function runCliBodySelectedChecks(input) {
 const checks=[];let nativeCalls=0;
 const need=(name,ok)=>{checks.push({name,pass:!!ok});if(!ok)throw Error(name);};
 const meta=eval(input.pure+";gitBlobMeta");
 function instance() {
  const memory=new Map();
  const store=(k,v)=>memory.set(k,v),load=k=>memory.get(k);
  const tools=new Proxy({}, {get(){return ()=>{nativeCalls++;throw Error("No tools in SOURCE components");};}});
  const api=eval(input.pure+"\n"+input.native
    +";({authorize:gfAuthorizeCliResultBodyOnly,validate:gfValidateRequest,scope:GF_CLI_BODY_RANGES,page:GF_CLI_BODY_PAGE_BYTES})");
  const state={rootGoWhole:true,paused:false,nativeCallInFlight:false,pending:null,activeObserver:null,
    startCalled:true,job:"1a1aee01612-fc05-639b",goPin:input.liveGo,
    cliResultInfoGO:{whole:true,pin:input.infoGo},cliResultInfoStarted:true,
    cliResultInfo:JSON.parse(JSON.stringify(input.info)),
    completedObservers:[JSON.parse(JSON.stringify(input.completed))]};
  store("official271_phaseb_live_gitfirst_r1",state);
  store("official271_phaseb_live_gitfirst_r1:closed_native:"+input.expected.infoOperation,input.metadataNative);
  const go={component_fixture_only:true,authorization:"GO",scope:"cli_result_binary_read_ranges_only",
    original_job:state.job,info_operation:input.expected.infoOperation,
    maximum_binary_read_starts:13,immutable_body_page_bytes:16384,
    fixed_report:{path:input.expected.path,bytes:input.expected.bytes,sha256:input.expected.sha256,version:input.expected.version},
    exact_requests:input.requests.map(x=>({blob:x.blob,bytes:x.bytes,sha256:x.sha256}))};
  function authorize(g=go){const raw=JSON.stringify(g,null,2)+"\n";return api.authorize({goRaw:raw,goPin:meta(raw),goWholeReadback:true});}
  return {api,state,go,authorize};
 }
 function rejects(name,f){let denied=false;try{f();}catch{denied=true;}need(name,denied);}
 let x=instance(); const good=x.authorize();
 need("new13authorization",good.maximumBinaryReadStarts===13&&x.state.cliResultBodyStarted===0);
 rejects("cannotAuthorizeTwice",()=>x.authorize());
 for(const [key,value]of [["original_job","other"],["info_operation","0".repeat(64)],
    ["maximum_binary_read_starts",14],["immutable_body_page_bytes",8192]]) {
  x=instance();x.go[key]=value;rejects("GOReject_"+key,()=>x.authorize());
 }
 x=instance();x.go.exact_requests.reverse();rejects("GORejectReorderedRequests",()=>x.authorize());
 x=instance();x.go.fixed_report.version+="x";rejects("GORejectChangedVersion",()=>x.authorize());
 x=instance();x.state.cliResultInfo.version+="x";rejects("stateRejectChangedVersion",()=>x.authorize());
 x=instance();x.state.activeObserver={};rejects("activeObserverBlocksBodyAuthorization",()=>x.authorize());
 for(let i=0;i<input.requests.length;i++){
  x=instance();x.authorize();x.state.cliResultBodyRanges=Array.from({length:i},()=>({}));
  x.state.cliResultBodyStarted=i;
  const raw=input.requests[i].text,q=JSON.parse(raw);
  x.api.validate(x.state,"operation_start",q,raw);need("exactRange_"+i,true);
  x.state.cliResultBodyStarted=i+1;
  rejects("onceMarkerBlocksRepeatedRange_"+i,()=>x.api.validate(x.state,"operation_start",q,raw));
 }
 for(const [key,value]of [["offset",1],["limit",65537],["path","/not-the-report"],
   ["expected_version","wrong"],["host","rog"]]){
  x=instance();x.authorize();const q=JSON.parse(input.requests[0].text);q.operation.arguments[key]=value;
  rejects("exactBodyReject_"+key,()=>x.api.validate(x.state,"operation_start",q,JSON.stringify(q,null,2)+"\n"));
 }
 x=instance();x.authorize();x.state.cliResultBodyRanges=[{}];x.state.cliResultBodyStarted=1;
 rejects("rangeOrderReject",()=>x.api.validate(x.state,"operation_start",JSON.parse(input.requests[0].text),input.requests[0].text));
 x=instance();x.authorize();x.state.cliResultBodyRanges=Array.from({length:13},()=>({}));x.state.cliResultBodyStarted=13;
 rejects("noFourteenthRange",()=>x.api.validate(x.state,"operation_start",JSON.parse(input.requests[12].text),input.requests[12].text));
 for(const tool of ["binary_read","file_info","process_read"]){
  x=instance();x.authorize();
  x.state.activeObserver={id:"f".repeat(64),tool,futureClosed:true,nextPageOffset:0,eof:false};
  const limit=tool==="binary_read"?16384:8192;
  const q={operation_id:x.state.activeObserver.id,offset:0,limit};
  x.api.validate(x.state,"operation_result",q,JSON.stringify(q));need("correctPage_"+tool,true);
  q.limit=tool==="binary_read"?8192:16384;
  rejects("wrongPage_"+tool,()=>x.api.validate(x.state,"operation_result",q,JSON.stringify(q)));
 }
 need("zeroToolInvocations",nativeCalls===0);
 return {schema:"heptabao.cli13-source-selected-guards.actual.v1",pass:checks.every(x=>x.pass),
  checks:checks.length,results:checks,NativeCalls:nativeCalls,localExecutorCalls:0,
  scope:"Only new authorization/next-range/once/page branch. No archive/SDK/controller/product execution."};
}
