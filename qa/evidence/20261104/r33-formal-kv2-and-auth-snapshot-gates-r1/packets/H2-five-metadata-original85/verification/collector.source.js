async function collectMetadata5(i,tools,store,load){
 const p="ha_h2_metadata5_actual_r1_";
 const H=new Function("tools","store","load",load(p+"pure_helpers")+"\n"+load(p+"git_helpers")+"\nreturn {save:saveVerifiedPublicBlobJournaled,lossless:parseLosslessIntegers,unb64,fromUtf8:utf8Text,meta:gitBlobMeta};")(tools,store,load);
 const seq=load(p+"sequence");if(seq.halted||seq.active_index!==i||!seq.active_id)throw Error("collect guard");
 async function observe(k,tool,req){
  if(load(p+i+"_"+k+"_raw"))throw Error("one observation guard "+k);
  store(p+i+"_"+k+"_request",req);
  store(p+i+"_"+k+"_request_pin",await H.save("ha-h2-info"+i+"-"+k+"-request",JSON.stringify(req,null,2)+"\n"));
  const it={schema:"heptabao.h2qa.destination.metadata5.observation.intent.v1",index:i,tool,request:req,authorization:"8c5542d05ace15c6d1405852ff69b091fa6c88ce",admission:load(p+i+"_admission_native_pin"),closed_status:tool==="operation_result"?load(p+i+"_status_native_pin"):null,new_native_admission:false};
  store(p+i+"_"+k+"_intent_pin",await H.save("ha-h2-info"+i+"-"+k+"-intent",JSON.stringify(it,null,2)+"\n"));
  let raw;try{raw=await tools["mcp__codex_apps__heptaruntime_mac_controller_"+tool](req);}catch(e){raw={transport_exception:true,name:e?.name||null,message:String(e?.message||e)};}
  store(p+i+"_"+k+"_raw",raw);
  const pin=await H.save("ha-h2-info"+i+"-"+k+"-sdk",JSON.stringify(raw,null,2)+"\n");store(p+i+"_"+k+"_sdk_pin",pin);
  if(raw.transport_exception||raw.isError){store(p+"sequence",{...load(p+"sequence"),halted:true,halt_reason:k+" error"});return {error:raw,pin};}
  const t=raw.content?.find(x=>x.type==="text")?.text;if(typeof t!=="string")throw Error(k+" shape");
  store(p+i+"_"+k+"_text",t);const n=H.lossless(t);store(p+i+"_"+k,n);
  store(p+i+"_"+k+"_native_pin",await H.save("ha-h2-info"+i+"-"+k+"-native",t));return n;
 }
 try{
  const s=await observe("status","operation_status",{operation_id:seq.active_id});if(s.error)return s;
  if(s.operation_id!==seq.active_id||s.async_state!=="completed"||s.owned_future_active!==false||s.result_state!=="stored_observed"||s.payload_available!==true)return {status:s,still_open:true};
  const n=await observe("page0","operation_result",{operation_id:seq.active_id,offset:0,limit:8192});if(n.error)return n;
  if(n.operation_id!==seq.active_id||n.offset!==0||n.immutable_snapshot!==true||n.eof!==true)throw Error("page identity/EOF");
  const b=H.unb64(n.data_base64),payload=H.fromUtf8(b),m=H.meta(payload);
  if(b.length!==n.total_bytes||n.next_offset!==b.length||m.sha256!==n.result_sha256)throw Error("payload whole");
  store(p+i+"_payload_text",payload);store(p+i+"_payload_pin",await H.save("ha-h2-info"+i+"-payload",payload));
  const out=H.lossless(payload);store(p+i+"_payload",out);if(out.isError||out.resultType!=="complete")throw Error("original native error");
  const nt=out.content?.find(x=>x.type==="text")?.text;if(typeof nt!=="string")throw Error("native missing");
  store(p+i+"_native_text",nt);store(p+i+"_native_pin",await H.save("ha-h2-info"+i+"-file-info-native",nt));const a=H.lossless(nt);store(p+i+"_native",a);
  const row=load("ha_h2_stage_r1_metadata5_plan").rows.find(x=>x.index===i),v=a.version.split(":"),full9=[v[0],v[1],String(a.metadata.uid),String(a.metadata.gid),String(32768+a.mode),String(a.metadata.link_count),String(a.size),v[3],v[4]];
  const checks={path:a.path===row.expected_historical_receiver.path,size:a.size===row.expected_historical_receiver.bytes,sha256:a.sha256===row.expected_historical_receiver.sha256,version:a.version===row.expected_historical_receiver.version,full9:JSON.stringify(full9)===JSON.stringify(row.expected_historical_receiver.full9_decimal),mode:a.mode===256&&a.metadata.mode===256,linux:a.metadata.metadata_platform==="linux",closed:true,one_payload:true};
  if(Object.values(checks).some(x=>x!==true))throw Error("metadata mismatch "+JSON.stringify(checks));
  const c={schema:"heptabao.h2qa.destination.metadata5.closed.v1",index:i,role:row.role,operation_id:seq.active_id,request:row.request,external_intent:load(p+i+"_intent_pin"),admission:load(p+i+"_admission_native_pin"),status:load(p+i+"_status_native_pin"),immutable_payload:load(p+i+"_payload_pin"),actual_file_info:load(p+i+"_native_pin"),checks,actual:{...a,full9_decimal:full9},full9_origin:"version dev/ino/size/mtime/ctime plus native uid/gid/mode/link_count; regular-file mode bit follows file_info contract",old_UNKNOWN_preserved:true,body_read_RPC:0,process_start:0};
  store(p+i+"_closure",c);const cp=await H.save("ha-h2-info"+i+"-closure",JSON.stringify(c,null,2)+"\n");store(p+i+"_closure_pin",cp);
  store(p+"sequence",{...seq,next_index:i===11?null:i+1,active_id:null,active_index:null,closed_indices:[...seq.closed_indices,i]});
  return {closure:cp,file_info:load(p+i+"_native_pin"),sequence:load(p+"sequence")};
 }catch(e){store(p+"sequence",{...load(p+"sequence"),halted:true,halt_reason:String(e?.message||e)});throw e;}
}
