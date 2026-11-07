function verifyConditionalAdmissionSource(input){
 const checks=[],need=(v,n)=>{if(!v)throw new Error(n);checks.push({name:n,pass:true});};
 const reject=(n,f)=>{let bad=false;try{f();}catch{bad=true;}need(bad,n);};
 need(snapshotApply(input.before,input.diff)===input.after,"strict_forward_four_hunks");
 need(snapshotApply(input.after,input.diff,true)===input.before,"strict_reverse_four_hunks");
 const req=JSON.parse(input.requestRaw),rp=gitBlobMeta(input.requestRaw),typed=processStartBinding(req);
 need(rp.blob==="f2c05f2d50e494b1046b57e727f89ce49a4d5d5a"&&rp.bytes===158691,"original_request_all_bytes");
 need(typed.sha256==="33dcdfaa308ff7e6669737a1326ec90e9f6275038ee7f27d896aeb95981f2d50"
  &&typed.native_fingerprint==="3737107712862844902","correct_stdin_typed_identity_unchanged");
 need(req.timeout_seconds===12000&&req.idempotency_key==="heptabao-combined-4a49405b-fresh-build-20261106-r1-a4d59953","original_key_and_total_timeout");
 const go={authorization:"GO",scope:"combined4a_exact_key_conditional_admission_once",maximumProcessStartCalls:1,
  allowFirstAdmission:true,lookupOnly:false,sameJobObservationsAuthorized:false,request:rp,
  originalBuildState:gitBlobMeta(input.buildStateRaw),originalInfoState:gitBlobMeta(input.infoStateRaw),
  digest:typed.sha256,fingerprint:typed.native_fingerprint};
 let toolCount=0,oldWrites=0;
 const buildSlot="combined_4a49405b_fresh_build_gitfirst_r1",infoSlot="combined_4a49405b_unknown_report_info_gitfirst_r1";
 const callKey="c4a-exact-key-reconcile-r1-start";
 function make(overrides){
  const map=new Map([[buildSlot,JSON.parse(input.buildStateRaw)],[infoSlot,JSON.parse(input.infoStateRaw)]]);
  const api=new Function("load","store","tools",input.pure+"\n"+input.after+
   "\nreturn {init:gfInitializeOnlyAfterRootGO,validate:gfValidateRequest,accept:gfAcceptArchivedSDK,state:gfState,slot:GF_SLOT};")(
   k=>map.get(k),(k,v)=>{if(k===buildSlot||k===infoSlot)oldWrites++;map.set(k,v);},
   new Proxy({}, {get(){toolCount++;throw new Error("no_tools_in_pure_fixture");}}));
  const g={...go,...overrides},raw=JSON.stringify(g,null,2)+"\n";
  const args={goRaw:raw,goPin:gitBlobMeta(raw),goWholeReadback:true,digest:typed.sha256,fingerprint:typed.native_fingerprint};
  return {api,map,args};
 }
 function ack(f,reused,change={},isError=false){
  f.api.init(f.args);const s=f.api.state();s.startCalled=true;s.pending=callKey;
  const v={audit_recorded:true,local_record_pending:false,reused,launch:{ok:true},
   job:{id:"fixture-bound-job",host:req.host,execution_mode:"operator",idempotency_key:req.idempotency_key,
    executable:req.executable,cwd:req.cwd,args:req.args,request_digest:typed.sha256,request_fingerprint:"__FP__"}};
  for(const [k,x] of Object.entries(change)){if(k.startsWith("job."))v.job[k.slice(4)]=x;else if(k==="launch.ok")v.launch.ok=x;else v[k]=x;}
  const native=JSON.stringify(v).replace('"__FP__"',typed.native_fingerprint);
  const sdkRaw=JSON.stringify({isError,content:[{type:"text",text:native}]},null,2)+"\n";
  f.map.set(f.api.slot+":original_sdk_raw:"+callKey,sdkRaw);
  s.calls[callKey]={kind:"process_start",requestRaw:input.requestRaw,phase:"sdk_whole_uninterpreted",
   sdkPin:gitBlobMeta(sdkRaw),sdkArchive:{whole:true}};
  return f.api.accept(callKey);
 }
 for(const reused of [true,false]){
  const f=make(),a=ack(f,reused),s=f.api.state();
  need(a.job==="fixture-bound-job"&&a.conditionalAdmission.reused===reused
   &&a.conditionalAdmission.classification===(reused?"existing_durable_job_reconciled":"first_admission_possible_under_new_go")
   &&a.conditionalAdmission.originalTimeoutPreserved===true
   &&a.conditionalAdmission.originalNeverAdmittedInferred===false
   &&a.conditionalAdmission.originalStartOutcome==="UNKNOWN"
   &&a.conditionalAdmission.authoritativeLiveStatus===false
   &&a.conditionalAdmission.sameJobObservationsAuthorized===false,"branch_"+String(reused)+"_keeps_original_unknown");
  reject("branch_"+String(reused)+"_no_second_start",()=>f.api.validate(s,"process_start",req,input.requestRaw));
  reject("branch_"+String(reused)+"_no_job_observer_admission",()=>f.api.validate(s,"operation_start",{},""));
 }
 const failedLaunch=ack(make(),true,{"launch.ok":false});
 need(failedLaunch.conditionalAdmission.launchOk===false
  &&failedLaunch.conditionalAdmission.authoritativeLiveStatus===false,"bound_launch_false_is_identity_only_not_success");
 for(const [field,value] of [["reused",null],["launch.ok",null],["audit_recorded",false],["local_record_pending",true],
  ["job.host","other"],["job.execution_mode","other"],["job.idempotency_key","other"],
  ["job.request_digest","0".repeat(64)],["job.request_fingerprint",1],["job.executable","/other"],
  ["job.cwd","/other"],["job.args",[]],["job.id",""]]){
  reject("reject_ack_"+field,()=>ack(make(),true,{[field]:value}));
 }
 reject("tool_error_stops",()=>ack(make(),true,{},true));
 for(const [field,value] of [["lookupOnly",true],["allowFirstAdmission",false],["maximumProcessStartCalls",2],["sameJobObservationsAuthorized",true]]){
  const f=make({[field]:value});reject("reject_go_"+field,()=>f.api.init(f.args));
 }
 const f=make();f.api.init(f.args);const s=f.api.state();
 f.api.validate(s,"process_start",req,input.requestRaw);need(true,"original_request_once_valid");
 reject("request_byte_drift_rejected",()=>f.api.validate(s,"process_start",req,input.requestRaw+"\n"));
 for(const kind of ["operation_start","operation_status","operation_result"]){
  reject("observer_kind_"+kind+"_rejected",()=>f.api.validate(s,kind,{},""));
 }
 f.map.get(buildSlot).paused=false;reject("old_build_drift_rejected",()=>f.api.state());
 function fn(src,name){
  const ms=[...src.matchAll(/^(?:async )?function ([A-Za-z0-9_]+)\(/gm)];
  const i=ms.findIndex(m=>m[1]===name);if(i<0)throw new Error("missing_function");
  return src.slice(ms[i].index,i+1<ms.length?ms[i+1].index:src.length);
 }
 for(const name of ["gfPrepareOne","gfInvokePreparedOnce","gfCloseOriginalObserver","gfReconcileSameGitArchiveReadOnly","gfRun"]){
  need(fn(input.before,name)===fn(input.after,name),"original_"+name+"_whole");
 }
 need(oldWrites===0&&toolCount===0,"no_old_context_writes_no_tools");
 return {schema:"heptabao.same-key-conditional-admission-source-checks.r1",checks,passed:checks.length,
  NativeCalls:0,PagesCalls:0,GitCalls:0,fixtureOnly:true,actualReused:null,actualJob:null};
}
