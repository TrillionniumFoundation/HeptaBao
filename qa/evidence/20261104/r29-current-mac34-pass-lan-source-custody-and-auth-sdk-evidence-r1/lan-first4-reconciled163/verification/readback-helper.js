async function(i,kind,offset=0){
 const p="ha_lan_original_identity_recovery_r1_",plans=load("ha_current_lan_inert_readback_source_plan_r1").stages.source_readback_after_receipt,q=plans[i],u=eval("("+load("ha_helper_reconstructed_r1_utf8")+")"),h=eval("("+load("ha_helper_reconstructed_r1_sha256")+")"),d=eval("("+load("ha_helper_reconstructed_r1_b64decode")+")");
 if(load(p+"source_readback_paused_for_normal5_relay")||load(p+"source_readback_stop_new_admission"))throw Error("source readback paused");
 if(i>0&&!load(p+"source"+(i-1)+"_whole_complete"))throw Error("previous source not complete");
 const key="source"+i+"_"+(kind==="info"?"info":"body"+offset);
 try{
  let req,chunk;
  if(kind==="info"){req=q.info_request;}
  else{
   if(!load(p+"source"+i+"_info_complete_r1"))throw Error("independent info not complete");
   const info=load(p+"source"+i+"_info_native_value_r1");chunk=q.body_chunks.find(c=>c.offset===offset);if(!chunk)throw Error("not fixed offset");
   const index=q.body_chunks.indexOf(chunk);if(index>0&&!load(p+"source"+i+"_body"+q.body_chunks[index-1].offset+"_complete_r1"))throw Error("previous body not complete");
   req=JSON.parse(JSON.stringify(chunk.request_template));if(req.operation.arguments.expected_version!==null)throw Error("unexpected prebound version");
   req.operation.arguments.expected_version=info.version;
  }
  store(p+key+"_bound_request",req);
  const r=await eval("("+load("ha_helper_one_closed_public_operation_r1")+")")(p,key,req.idempotency_key,req.operation.tool,req.operation.arguments);
  if(r.pending)return {source_index:i,kind,offset,...r};
  const v=r.value,receipt=load(p+"source_readback_receipt_value").files[i],id=receipt.identity,version=[id[0],id[1],id[6],id[7],id[8]].join(":");
  if(kind==="info"){
   const checks={path:v.path===q.path,bytes:v.size===q.expected_bytes,sha256:v.sha256===q.expected_sha256,mode:v.mode===384,uid:v.metadata.uid===1000,gid:v.metadata.gid===1000,nlink:v.metadata.link_count===1,version_equals_original_receipt:v.version===version};
   store(p+"source"+i+"_info_checks",checks);if(!Object.values(checks).every(Boolean))throw Error("source info mismatch "+JSON.stringify(checks));
   return {source_index:i,kind,closed:true,operation_id:r.operation_id,version:v.version,checks};
  }
  const b=d(v.data_base64),checks={path:v.path===q.path,offset:v.offset===offset,next_offset:v.next_offset===offset+b.length,bytes:b.length===chunk.expected_decoded_bytes,size:v.size===q.expected_bytes,version:v.version===version,chunk_sha256:h(b)===v.chunk_sha256,eof:v.eof===(offset+b.length===q.expected_bytes)};
  store(p+key+"_chunk_checks",checks);if(!Object.values(checks).every(Boolean))throw Error("source body mismatch "+JSON.stringify(checks));
  store(p+key+"_binary",b);
  if(v.eof){
   const whole=q.body_chunks.map(c=>{const x=load(p+"source"+i+"_body"+c.offset+"_binary");if(typeof x!=="string")throw Error("missing chunk");return x;}).join("");
   if(whole.length!==q.expected_bytes||h(whole)!==q.expected_sha256)throw Error("source whole mismatch");
   const text=decodeURIComponent([...whole].map(c=>"%"+c.charCodeAt(0).toString(16).padStart(2,"0")).join(""));if(u(text)!==whole)throw Error("source encoding roundtrip");
   store(p+"source"+i+"_whole_text",text);store(p+"source"+i+"_whole_sha256",h(whole));store(p+"source"+i+"_whole_complete",true);
  }
  return {source_index:i,kind,offset,closed:true,operation_id:r.operation_id,decoded_bytes:b.length,eof:v.eof,whole_complete:!!load(p+"source"+i+"_whole_complete")};
 }catch(e){store(p+"source_readback_stop_new_admission",true);store(p+key+"_failure",String(e));return{source_index:i,kind,offset,stopped:true,error:String(e)};}
}
