function collectLiveEvidence(prefix) {
 const files={...Object.fromEntries(Object.entries(load(prefix+"intent_files")||{}).map(([k,v])=>["execution/intent/"+k,v])),...Object.fromEntries(Object.entries(load(prefix+"ack_files")||{}).map(([k,v])=>["execution/ACK/"+k,v]))};
 function originalCall(label,key){
  const req=load(prefix+key+"_request_r1"),raw=load(prefix+key+"_raw_r1"),text=load(prefix+key+"_text_r1");
  if(req)files[label+"/request.original.json"]=JSON.stringify(req,null,2)+"\n";
  if(raw!==undefined)files[label+"/original.sdk.json"]=JSON.stringify(raw,null,2)+"\n";
  if(typeof text==="string")files[label+"/original.native.txt"]=text;
  const error=load(prefix+key+"_error");if(error)files[label+"/error.public.json"]=JSON.stringify(error,null,2)+"\n";
 }
 const observations=[];
 for(const o of load(prefix+"observer_plan")||[]){
  const base="observations/"+o.name;
  for(const[k,v]of Object.entries(load(prefix+o.name+"_intent_files")||{}))files[base+"/intent/"+k]=v;
  originalCall(base+"/admission",o.name+"_start");
  const n=load(prefix+o.name+"_status_count_r1")||0;
  for(let i=0;i<n;i++)originalCall(base+"/status-"+i,o.name+"_status"+i);
  const pages=load(prefix+o.name+"_pages_r1")||[];
  for(const pg of pages)originalCall(base+"/pages/"+String(pg.offset).padStart(6,"0"),o.name+"_result"+pg.offset);
  const body=load(prefix+o.name+"_payload_text_r1"),native=load(prefix+o.name+"_native_text_r1");
  if(typeof body==="string")files[base+"/payload.original.json"]=body;
  if(typeof native==="string")files[base+"/native.original.json"]=native;
  const error=load(prefix+o.name+"_error");if(error)files[base+"/error.public.json"]=JSON.stringify(error,null,2)+"\n";
  observations.push({name:o.name,exact_operation:{idempotency_key:o.key,operation:{tool:o.tool,arguments:o.args}},operation_id:load(prefix+o.name+"_operation_id_r1")??null,completed:load(prefix+o.name+"_complete_r1")===true,closed_status:load(prefix+o.name+"_closed_status_r1")??null,pages,error:error??null});
 }
 files["READPLAN.public.json"]=JSON.stringify(load(prefix+"output_plan"),null,2)+"\n";
 const state={schema:"heptabao.current4e808.LAN-live-original-evidence-state.r1",job_id:load(prefix+"job_id"),root_GO:load(prefix+"go_pin"),request:load(prefix+"request_pin"),submission_count:load(prefix+"dispatch_started")?1:0,exact_ACK_bound:load(prefix+"ack_checks"),original_authority_latest:load(prefix+"latest_authority_value")??null,terminal_authority:load(prefix+"terminal_authority")??null,authority_observation:load(prefix+"latest_authority_observer")??null,original98:98,separate_extra12:12,original_outer_seconds:3000,original_controller_seconds:2400,observer_count:observations.length,observers:observations,new_admissions_paused:load(prefix+"new_admissions_paused")===true,product_qualification:false,production_changed:false,prior_UNKNOWN_preserved:true};
 files["STATE.public.json"]=JSON.stringify(state,null,2)+"\n";
 return{files,state};
}
