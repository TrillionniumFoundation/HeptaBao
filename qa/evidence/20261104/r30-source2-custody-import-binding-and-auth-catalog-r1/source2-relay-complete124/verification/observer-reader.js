async function(prefix,key,opKey,tool,args){
 const call=eval("("+load("ha_helper_operation_sdk_external_before_parse_r1")+")");
 let id=load(prefix+key+"_operation_id_r1");
 if(!id){
  if(load(prefix+key+"_start_started_r1"))throw Error("existing unbound admission; reconcile separately");
  const ack=await call(prefix,key+"_start","mcp__codex_apps__heptaruntime_mac_controller_operation_start",{idempotency_key:opKey,operation:{tool,arguments:args}});
  id=ack.value.operation_id;if(typeof id!=="string"||!id)throw Error("operation id");
  store(prefix+key+"_operation_id_r1",id);
 }
 if(load(prefix+key+"_complete_r1"))throw Error("observation already complete");
 let status=load(prefix+key+"_closed_status_r1");
 if(!status){
  const n=load(prefix+key+"_status_count_r1")||0;store(prefix+key+"_status_count_r1",n+1);
  const x=await call(prefix,key+"_status"+n,"mcp__codex_apps__heptaruntime_mac_controller_operation_status",{operation_id:id});
  if(x.value.operation_id!==id)throw Error("status id");
  if(x.value.async_state!=="completed"||x.value.result_state!=="stored_observed"||x.value.owned_future_active!==false||x.value.payload_available!==true)return {pending:true,operation_id:id,status:x.value};
  status=x.value;store(prefix+key+"_closed_status_r1",status);
 }
 const dec=eval("("+load("ha_helper_reconstructed_r1_b64decode")+")"),hash=eval("("+load("ha_helper_reconstructed_r1_sha256")+")");
 let binary="",offset=0,total=null,digest=null,pages=[];
 while(total===null||offset<total){
  const pk=key+"_result"+offset;
  let q=load(prefix+pk+"_value_r1"),external=load(prefix+pk+"_whole_r1")?.summary;
  if(!q){const x=await call(prefix,pk,"mcp__codex_apps__heptaruntime_mac_controller_operation_result",{operation_id:id,offset,limit:8192});q=x.value;external=x.external;}
  const b=dec(q.data_base64);
  if(q.operation_id!==id||q.offset!==offset||q.next_offset!==offset+b.length||b.length>8192||b.length===0&&q.total_bytes!==0||q.immutable_snapshot!==true||q.total_bytes>1048576||q.eof!==(q.next_offset===q.total_bytes))throw Error("immutable page");
  if(total===null){total=q.total_bytes;digest=q.result_sha256;}else if(total!==q.total_bytes||digest!==q.result_sha256)throw Error("immutable identity");
  binary+=b;pages.push({offset,bytes:b.length,external_tree:external.tree});offset=q.next_offset;
 }
 if(binary.length!==total||hash(binary)!==digest)throw Error("payload whole");
 const text=decodeURIComponent([...binary].map(c=>"%"+c.charCodeAt(0).toString(16).padStart(2,"0")).join(""));
 store(prefix+key+"_payload_text_r1",text);store(prefix+key+"_pages_r1",pages);
 const payload=JSON.parse(text);store(prefix+key+"_payload_value_r1",payload);
 const native=eval("("+load("ha_helper_reconstructed_r1_original_text")+")")(payload);store(prefix+key+"_native_text_r1",native);
 const value=JSON.parse(native);store(prefix+key+"_native_value_r1",value);store(prefix+key+"_complete_r1",true);
 return {pending:false,operation_id:id,closed:true,payload_bytes:total,pages:pages.length,value};
}
