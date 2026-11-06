function verifyBodySource(files){
 const checks=[];function ck(ok,code){checks.push({code,pass:!!ok});if(!ok)throw Error(code);}
 const before=files["journal.33b.body.before.js"],after=files["journal.025b.body.after.js"],infoBefore=files["journal.025b.info.before.js"],plan=JSON.parse(files["PLAN.public.json"]),state=JSON.parse(files["verifier.state-input.public.json"]),info=JSON.parse(files["reference.actual-INFO.json"]),observer=JSON.parse(files["reference.actual-INFO-observer.json"]);
 ck(applyStrictUnified(before,files["literal.strict.diff"]).text===after,"old_body_strict_forward");
 ck(applyStrictUnified(after,files["literal.strict.diff"],true).text===before,"old_body_strict_reverse");
 ck(applyStrictUnified(infoBefore,files["info-to-body.strict.diff"]).text===after,"current_info_strict_forward");
 ck(applyStrictUnified(after,files["info-to-body.strict.diff"],true).text===infoBefore,"current_info_strict_reverse");
 const rebound=bind025bStageBody({oldBodyJournal:before,oldRequestRaw:files["request.33b.body.before.json"],infoBindings:JSON.parse(files["INFO-literal-bindings.public.json"]),info,infoRaw:files["reference.actual-INFO-native.json"],closedObserver:observer,job:state.job});
 ck(rebound.source===after&&rebound.requestRaw===files["request.025b.body.exact.json"],"literal_generator_full_byte_reproduction");
 ck(JSON.stringify(gitBlobMeta(after))===JSON.stringify(plan.source),"candidate_full_pin");
 ck(JSON.stringify(gitBlobMeta(rebound.requestRaw))===JSON.stringify(plan.exact_request),"exact_request_pin");
 const q=JSON.parse(rebound.requestRaw),a=q.operation.arguments;
 ck(q.operation.tool==="binary_read"&&a.host==="rog"&&a.path===info.path,"only_fixed_public_body");
 ck(a.offset===0&&a.limit===28125&&a.expected_version===info.version,"actual_fixed_extent_version");
 ck(plan.expected.sha256===info.sha256&&plan.expected.infoOperation===observer.id&&observer.completedInactive,"actual_original_INFO_identity");
 ck(plan.limits.immutable_page_bytes===8192&&plan.limits.original_payload_bytes===1048576&&plan.maximum_binary_read_starts===1,"original_caps_and_one_start");
 function env(mutator){
  const copy=JSON.parse(JSON.stringify(state)),memory={[plan.slot]:copy,[plan.slot+":closed_native:"+info.originalOperation]:files["reference.actual-INFO-native.json"]};if(mutator)mutator(copy,memory);
  const api=new Function("store","load",files["helper.pure.original.js"]+"\n"+after+"\nreturn {authorize:gfAuthorizeStageResultBodyOnly,validate:gfValidateRequest};")((k,v)=>memory[k]=v,k=>memory[k]);return {copy,memory,api};
 }
 const g={authorization:"GO",scope:"stage_result_binary_read_only",original_job:state.job,info_operation:info.originalOperation,maximum_binary_read_starts:1,exact_request:plan.exact_request,schema:"pure_component_fixture_only"};
 function ga(v=g){const raw=JSON.stringify(v)+"\n";return{goRaw:raw,goPin:gitBlobMeta(raw),goWholeReadback:true};}
 const positive=env();positive.api.authorize(ga());positive.api.validate(positive.copy,"operation_start",q,rebound.requestRaw);ck(true,"pure_exact_closed_INFO_to_body_positive");
 const cases=[
 ["missing_body_GO",e=>e.api.validate(e.copy,"operation_start",q,rebound.requestRaw)],
 ["wrong_version",e=>{e.copy.stageResultInfo.version+="-changed";e.api.authorize(ga());}],
 ["changed_INFO_native",e=>{e.memory[plan.slot+":closed_native:"+info.originalOperation]+=" ";e.api.authorize(ga());}],
 ["future_unclosed",e=>{e.copy.activeObserver={id:"pending"};e.api.authorize(ga());}],
 ["paused_state",e=>{e.copy.paused=true;e.api.authorize(ga());}],
 ["already_started",e=>{e.copy.stageResultBodyStarted=true;e.api.authorize(ga());}],
 ["wrong_scope",e=>e.api.authorize(ga({...g,scope:"process_start"}))],
 ["wrong_exact_request",e=>e.api.authorize(ga({...g,exact_request:{...plan.exact_request,blob:"0".repeat(40)}}))],
 ["wrong_range",e=>{e.api.authorize(ga());const changed=JSON.parse(rebound.requestRaw);changed.operation.arguments.offset=1;e.api.validate(e.copy,"operation_start",changed,JSON.stringify(changed));}],
 ["new_INFO",e=>{e.api.authorize(ga());const changed=JSON.parse(rebound.requestRaw);changed.operation.tool="file_info";e.api.validate(e.copy,"operation_start",changed,JSON.stringify(changed));}],
 ["new_START",e=>e.api.validate(e.copy,"process_start",{}, "{}")]
 ];
 for(const[name,fn]of cases){let rejected=false;try{fn(env());}catch(_){rejected=true;}ck(rejected,"pure_guard_reject:"+name);}
 return{schema:"heptabao.025b-stage-body-source-verification.r1",status:"PASS",checks:checks.length,results:checks,Runtime_calls:0,body_observed:false,product_tests:0};
}
