function verifyActualJobObservers(input){
 const cases=[],check=(v,n)=>{if(!v)throw new Error(n);cases.push({name:n,pass:true});};
 const reject=(n,f)=>{let yes=false;try{f();}catch{yes=true;}check(yes,n);};
 check(snapshotApply(input.before,input.diff)===input.after,"strict_forward");
 check(snapshotApply(input.after,input.diff,true)===input.before,"strict_reverse");
 const beforeState=JSON.parse(input.stateRaw),pin=gitBlobMeta(input.stateRaw);
 check(pin.blob==="a4fea6d283d0fb3d58d8045a8f4c7df637ecd578"&&beforeState.job==="1a1b3978da9-fc05-83bd","actual_ack_state_exact");
 const ack=beforeState.calls["c4a-exact-key-reconcile-r1-start"].sdkPin;
 const go={authorization:"GO",scope:"combined4a_actual_job_observations_only",jobId:beforeState.job,host:"rog",
  actualAck:ack,beforeState:pin,maximumStatusObservers:256,maximumReadObservers:129,statusCallsPerObserver:8,
  pagesPerObserver:128,pageBytes:8192,payloadCap:1048576,streamReadLimit:16384,streamByteCap:2097152,processStartAuthorized:false};
 let oldWrites=0,toolsUsed=0;
 function fixture(changes={}){
  const map=new Map([["combined_4a49405b_exact_key_conditional_admission_r1",JSON.parse(input.stateRaw)],
   ["combined_4a49405b_fresh_build_gitfirst_r1",JSON.parse(input.oldBuildRaw)],
   ["combined_4a49405b_unknown_report_info_gitfirst_r1",JSON.parse(input.oldInfoRaw)]]);
  const api=new Function("load","store","tools",input.pure+"\n"+input.after+
   "\nreturn {authorize:gfAuthorizeActualJobObservers,validate:gfValidateRequest,state:gfState,slot:GF_SLOT};")(
   k=>map.get(k),(k,v)=>{if(!k.startsWith("combined_4a49405b_exact_key_conditional_admission_r1"))oldWrites++;map.set(k,v);},
   new Proxy({}, {get(){toolsUsed++;throw new Error("no_tools");}}));
  const raw=JSON.stringify({...go,...changes},null,2)+"\n";
  return {api,map,args:{goRaw:raw,goPin:gitBlobMeta(raw),goWholeReadback:true}};
 }
 const f=fixture(),originalGo=JSON.stringify(beforeState.goPin);
 f.api.authorize(f.args);const s=f.api.state();
 check(s.sameJobObservationsAuthorized&&s.statusObserversCalled===0&&s.readObserversCalled===0
  &&JSON.stringify(s.goPin)===originalGo&&s.startCalled===true,"attach_no_initialize_no_deadline_or_old_go_reset");
 reject("second_authorization_refused",()=>f.api.authorize(f.args));
 for(const [field,value] of [["jobId","other"],["maximumStatusObservers",257],["maximumReadObservers",130],
  ["statusCallsPerObserver",9],["pagesPerObserver",129],["pageBytes",16384],["streamByteCap",4194304],["processStartAuthorized",true]]){
  const z=fixture({[field]:value});reject("wrong_go_"+field,()=>z.api.authorize(z.args));
 }
 const key="heptabao-combined-4a49405b-fresh-observe-r1-authority0";
 const qs={idempotency_key:key,operation:{tool:"process_status",arguments:{host:"rog",job_id:s.job}}};
 const qr={idempotency_key:key+"read",operation:{tool:"process_read",arguments:{host:"rog",job_id:s.job,limit:16384,stdout_offset:0,stderr_offset:0}}};
 const j=x=>JSON.stringify(x,null,2)+"\n";
 f.api.validate(s,"operation_start",qs,j(qs));f.api.validate(s,"operation_start",qr,j(qr));
 check(true,"same_job_status_and_stream_only");
 const wrong=JSON.parse(j(qs));wrong.operation.arguments.job_id="other";
 reject("different_job_refused",()=>f.api.validate(s,"operation_start",wrong,j(wrong)));
 const body=JSON.parse(j(qs));body.operation.tool="binary_read";
 reject("extra_file_or_body_tool_refused",()=>f.api.validate(s,"operation_start",body,j(body)));
 s.startCalled=false;reject("process_start_always_refused",()=>f.api.validate(s,"process_start",{}, ""));s.startCalled=true;
 s.statusObserversCalled=256;reject("status_observer257_refused",()=>f.api.validate(s,"operation_start",qs,j(qs)));s.statusObserversCalled=0;
 s.readObserversCalled=129;reject("read_observer130_refused",()=>f.api.validate(s,"operation_start",qr,j(qr)));s.readObserversCalled=0;
 const id="a".repeat(64);s.activeObserver={id,futureClosed:false,statusCalls:0,pageCalls:0,nextPageOffset:0,eof:false};
 reject("parallel_observer_refused",()=>f.api.validate(s,"operation_start",qs,j(qs)));
 f.api.validate(s,"operation_status",{operation_id:id},"");check(true,"same_active_operation_status");
 s.activeObserver.statusCalls=8;reject("status9_refused",()=>f.api.validate(s,"operation_status",{operation_id:id},""));
 s.activeObserver.futureClosed=true;
 f.api.validate(s,"operation_result",{operation_id:id,offset:0,limit:8192},"");check(true,"same_closed_contiguous_page");
 s.activeObserver.pageCalls=128;reject("page129_refused",()=>f.api.validate(s,"operation_result",{operation_id:id,offset:0,limit:8192},""));
 s.activeObserver.pageCalls=0;reject("page_cursor_drift_refused",()=>f.api.validate(s,"operation_result",{operation_id:id,offset:1,limit:8192},""));
 f.map.get("combined_4a49405b_fresh_build_gitfirst_r1").paused=false;reject("original_unknown_state_drift_refused",()=>f.api.state());
 check(oldWrites===0&&toolsUsed===0,"no_old_state_write_or_native");
 return {schema:"heptabao.actual-job-observation-source-checks.r1",cases,passed:cases.length,
 NativeCalls:0,PagesCalls:0,fixtureOnly:true,actualObserverResults:null};
}
