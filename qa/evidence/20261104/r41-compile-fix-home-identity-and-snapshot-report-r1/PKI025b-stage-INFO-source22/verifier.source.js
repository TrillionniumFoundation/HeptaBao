function verifyInfoSource(input){
 const checks=[];function ck(v,c){checks.push({code:c,pass:!!v});if(!v)throw Error(c);}
 ck(applyStrictUnified(input.before,input.diff).text===input.after,"strict_forward");
 ck(applyStrictUnified(input.after,input.diff,true).text===input.before,"strict_reverse");
 ck(applyStrictUnified(input.before,input.diff).hunks===2,"two_literal_hunks");
 let rebuilt=input.before;
 for(const r of input.replacements){ck(rebuilt.split(r.old).length-1===1,"one_literal:"+r.why);rebuilt=rebuilt.replace(r.old,r.next);}
 ck(rebuilt===input.after,"entire_source_only_seven_literals");
 const q=JSON.parse(input.requestRaw);
 ck(q.operation.tool==="file_info"&&q.operation.arguments.host==="rog"&&q.operation.arguments.path===input.plan.expected.path,"exact_fixed_file_info");
 ck(q.idempotency_key==="heptabao-native-jwt-pki-025b05a3-rog-source-observe-r1-stage-result-info0","exact_new_read_key");
 ck(JSON.stringify(gitBlobMeta(input.requestRaw))===JSON.stringify(input.requestPin),"request_whole_pin");
 ck(input.state.job==="1a1b07b7e0b-fc05-70ca"&&input.state.completedObservers.length===2&&input.state.pending===null&&input.state.activeObserver===null&&!input.state.paused&&!input.state.nativeCallInFlight,"actual_closed_stage_input");
 ck(input.plan.expected.maximum_size===150000&&input.plan.limits.immutable_page_bytes===8192&&input.plan.limits.original_payload_bytes===1048576,"all_old_caps_unchanged");
 ck(input.plan.expected.actual_size===null&&input.plan.expected.actual_sha256===null&&input.plan.expected.actual_version===null&&input.plan.expected.actual_full9===null,"actual_info_remains_unobserved");
 function env(mutator){
  const state=JSON.parse(JSON.stringify(input.state)),memory={...input.prior,[input.plan.slot]:state};
  if(mutator)mutator(state,memory);
  const api=new Function("store","load",input.pure+"\n"+input.after+"\nreturn {authorize:gfAuthorizeStageResultInfoOnly,validate:gfValidateRequest,initialize:gfInitializeOnlyAfterRootGO};")((k,v)=>memory[k]=v,k=>memory[k]);
  return {state,memory,api};
 }
 const g={authorization:"GO",scope:"stage_result_file_info_only",original_job:input.state.job,maximum_file_info_starts:1,binary_read_authorized:false,exact_request:input.requestPin};
 function goArgs(value=g){const raw=JSON.stringify(value)+"\n";return {goRaw:raw,goPin:gitBlobMeta(raw),goWholeReadback:true};}
 const e=env();e.api.authorize(goArgs());ck(e.state.stageResultInfoGO.whole===true,"pure_positive_separate_GO_gate");
 e.api.validate(e.state,"operation_start",q,input.requestRaw);ck(true,"pure_positive_exact_INFO_gate");
 const rejects=[
  ["missing_new_GO",(x)=>x.api.validate(x.state,"operation_start",q,input.requestRaw),false],
  ["paused",(x)=>x.api.authorize(goArgs()),true,(s)=>s.paused=true],
  ["active_future",(x)=>x.api.authorize(goArgs()),true,(s)=>s.activeObserver={id:"x"}],
  ["wrong_actual_job",(x)=>x.api.authorize(goArgs()),true,(s)=>s.job="old-job"],
  ["changed_closed_native",(x)=>x.api.authorize(goArgs()),true,(s,m)=>m[Object.keys(input.prior)[0]]+=" "],
  ["wrong_GO_scope",(x)=>x.api.authorize(goArgs({...g,scope:"binary_read"})),true],
  ["body_GO_rejected",(x)=>x.api.authorize(goArgs({...g,binary_read_authorized:true})),true],
  ["wrong_GO_request",(x)=>x.api.authorize(goArgs({...g,exact_request:{...input.requestPin,blob:"0".repeat(40)}})),true],
  ["reinitialize_existing_slot",(x)=>x.api.initialize({}),true],
  ["repeat_INFO",(x)=>{x.api.authorize(goArgs());x.state.stageResultInfoStarted=true;x.api.validate(x.state,"operation_start",q,input.requestRaw);},true],
  ["process_START",(x)=>x.api.validate(x.state,"process_start",{}, "{}"),true],
  ["other_path",(x)=>{x.api.authorize(goArgs());const v=JSON.parse(input.requestRaw);v.operation.arguments.path+="-other";x.api.validate(x.state,"operation_start",v,JSON.stringify(v));},true],
  ["binary_read",(x)=>{x.api.authorize(goArgs());const v=JSON.parse(input.requestRaw);v.operation.tool="binary_read";x.api.validate(x.state,"operation_start",v,JSON.stringify(v));},true]
 ];
 for(const [name,fn,,mutator]of rejects){let rejected=false;try{fn(env(mutator));}catch(_){rejected=true;}ck(rejected,"guard_reject:"+name);}
 return {schema:"heptabao.jwt-pki-025b-stage-INFO-source-checks.r1",status:"PASS",checks:checks.length,results:checks,pure_guard_only:true,actual_Native_calls:0,actual_file_info_observed:false};
}
