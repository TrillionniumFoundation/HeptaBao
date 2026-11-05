function verifySdk13(data,H){
 const {u,bs,s256,unb64}=H,checks=[],chunks={}, operations=[];
 function ok(n,v){if(!v)throw Error(n);checks.push(n);}
 function digest(t){return s256(bs(u(t)));}
 function native(raw,n){const q=JSON.parse(raw);ok(n+":sdk-not-error",q.isError!==true);const c=q.content?.filter(x=>x.type==="text");ok(n+":one-text",c?.length===1);return {text:c[0].text,value:JSON.parse(c[0].text)};}
 const obs=JSON.parse(data.raw["all-13-observations.public.json"]),summary=JSON.parse(data.raw["SUMMARY.public.json"]);
 ok("exact-13-sequences",obs.length===13&&obs.every((x,i)=>x.sequence===i+1)&&new Set(obs.map(x=>x.operation_id)).size===13);
 for(const o of obs){
  const n="op"+o.sequence,req=JSON.parse(data.refs[o.request_blob].text),a=req.operation.arguments,sd=data.refs[o.original_sdk.blob],nd=data.refs[o.original_native.blob],wn=native(sd.text,n+":whole"),v=wn.value,b=unb64(v.data_base64);
  ok(n+":sdk-whole-pin",sd.bytes===o.original_sdk.bytes&&sd.sha256===o.original_sdk.sha256&&digest(sd.text)===o.original_sdk.sha256);
  ok(n+":native-whole-pin",nd.bytes===o.original_native.bytes&&nd.sha256===o.original_native.sha256&&wn.text===nd.text);
  ok(n+":fixed-request",req.operation.tool==="binary_read"&&a.host==="mac"&&a.path===o.path&&a.expected_version===o.version&&a.offset===o.offset&&a.limit===o.chunk_bytes);
  ok(n+":exact-file-identity",v.path===o.path&&v.version===o.version&&v.size===o.size);
  ok(n+":exact-range-eof",v.offset===o.offset&&v.next_offset===o.next_offset&&v.next_offset-v.offset===b.length&&v.eof===o.eof&&(v.next_offset===v.size)===v.eof);
  ok(n+":chunk-hash",b.length===o.chunk_bytes&&s256(bs(b))===v.chunk_sha256&&v.chunk_sha256===o.chunk_sha256);
  ok(n+":table-complete",o.known_complete&&o.async_state==="completed"&&o.result_state==="stored_observed"&&o.owned_future_active===false);
  chunks[o.sequence]=b;
  operations.push({sequence:o.sequence,operation_id:o.operation_id,path:v.path,offset:v.offset,bytes:b.length,next_offset:v.next_offset,eof:v.eof,chunk_sha256:v.chunk_sha256,original_sdk_blob:o.original_sdk.blob});
 }
 for(const [name,p] of Object.entries(summary.whole_sources)){
  const b=p.sequences.flatMap(i=>chunks[i]), t=data.raw["whole-sources/"+name+".js"];
  ok(name+":contiguous",p.sequences.every((seq,i)=>obs[seq-1].offset===(i===0?0:obs[p.sequences[i-1]-1].next_offset)));
  ok(name+":whole-original-concat",bs(b)===bs(u(t))&&b.length===p.bytes&&s256(bs(b))===p.sha256);
  ok(name+":ends-at-size",obs[p.sequences.at(-1)-1].next_offset===p.bytes&&obs[p.sequences.at(-1)-1].eof);
 }
 const details=[];
 for(const seq of [11,12,13]){
  const o=obs[seq-1],d="operations/"+String(seq).padStart(2,"0")+"-"+o.id,reqText=data.raw[d+"/request.original.json"];
  ok("op"+seq+":request-original-byte-exact",reqText===data.refs[o.request_blob].text);
  const start=native(data.raw[d+"/start.sdk.original.json"],"op"+seq+":start");
  ok("op"+seq+":ack-native-exact",start.text===data.raw[d+"/start.native.original.txt"]);
  ok("op"+seq+":ack-identity",start.value.operation_id===o.operation_id&&start.value.tool_name==="binary_read"&&start.value.idempotency_binding_retained===true&&start.value.reused===false);
  const statusIndex=seq===12?"01":"00",sp=d+"/status/"+statusIndex,st=native(data.raw[sp+"/sdk.original.json"],"op"+seq+":status"),sr=JSON.parse(data.raw[sp+"/request.public.json"]);
  ok("op"+seq+":status-native-exact",st.text===data.raw[sp+"/native.original.txt"]);
  ok("op"+seq+":original-future-closed",sr.operation_id===o.operation_id&&st.value.operation_id===o.operation_id&&st.value.tool_name==="binary_read"&&st.value.async_state==="completed"&&st.value.result_state==="stored_observed"&&st.value.owned_future_active===false&&st.value.payload_available===true);
  let parts=[],cursor=0;
  const dirs=Object.keys(data.raw).filter(p=>p.startsWith(d+"/pages/")&&p.endsWith("/sdk.original.json")).sort(),pages=[];
  for(const p of dirs){
   const pref=p.slice(0,-"/sdk.original.json".length),pr=JSON.parse(data.raw[pref+"/request.public.json"]),pg=native(data.raw[p],"op"+seq+":"+pref),v=pg.value,b=unb64(v.data_base64);
   ok(pref+":native-exact",pg.text===data.raw[pref+"/native.original.txt"]);
   ok(pref+":same-operation-offset",pr.operation_id===o.operation_id&&v.operation_id===o.operation_id&&pr.offset===cursor&&v.offset===cursor&&pr.limit===16384);
   ok(pref+":immutable-original",v.immutable_snapshot===true&&v.payload_kind==="native_result"&&v.total_bytes===o.original_sdk.bytes&&v.result_sha256===o.original_sdk.sha256);
   ok(pref+":length-and-eof",v.next_offset===cursor+b.length&&b.length<=pr.limit&&v.eof===(v.next_offset===v.total_bytes));
   cursor=v.next_offset;parts.push(...b);pages.push({offset:v.offset,bytes:b.length,eof:v.eof});
  }
  ok("op"+seq+":complete-serialized-sdk-reconstructed",cursor===o.original_sdk.bytes&&s256(bs(parts))===o.original_sdk.sha256&&bs(parts)===bs(u(data.refs[o.original_sdk.blob].text)));
  ok("op"+seq+":whole-files-original-exact",data.raw[d+"/whole.sdk.original.json"]===data.refs[o.original_sdk.blob].text&&data.raw[d+"/whole.native.original.txt"]===data.refs[o.original_native.blob].text);
  details.push({sequence:seq,operation_id:o.operation_id,pages,status_index:statusIndex,completed:true,owned_future_active:false});
 }
 for(const page of ["01","02"]){
  const d="references/prior-partial/operations/11-selector_589824/pages/"+page,sdk=JSON.parse(data.raw[d+"/sdk.original.json"]),req=JSON.parse(data.raw[d+"/request.public.json"]),now=JSON.parse(data.raw["operations/11-selector_589824/pages/"+page+"/request.public.json"]);
  ok("op11:prior-error-"+page+"-preserved",sdk.isError===true&&JSON.stringify(req)===JSON.stringify(now));
 }
 for(const p of ["request.original.json","start.sdk.original.json","start.native.original.txt","status/00/request.public.json","status/00/sdk.original.json","status/00/native.original.txt","pages/00/request.public.json","pages/00/sdk.original.json","pages/00/native.original.txt"]){
  ok("op11:unchanged-prior-"+p,data.raw["operations/11-selector_589824/"+p]===data.raw["references/prior-partial/operations/11-selector_589824/"+p]);
 }
 const err12=JSON.parse(data.raw["operations/12-selector_655360/status/00/sdk.original.json"]),oldReq12=JSON.parse(data.raw["operations/12-selector_655360/status/00/request.public.json"]),newReq12=JSON.parse(data.raw["operations/12-selector_655360/status/01/request.public.json"]);
 ok("op12:original-status-timeout-preserved",err12.isError===true&&JSON.stringify(oldReq12)===JSON.stringify(newReq12)&&oldReq12.operation_id===obs[11].operation_id);
 ok("seq3:prior-adoption-explicit",obs[2].observation_blob===null&&obs[2].prior_adoption_document==="6604b671c8fe49eddf3f5c516aa6e36db46bdec8"&&!!data.refs[obs[2].prior_adoption_document]);
 return {schema:"heptabao.root-sdk13-completion-review.r29.v1",status:"PASS_PUBLIC_BYTES_AND_ORIGINAL_READ_CLOSURE_ONLY",packet_tree:"abc61330ace8f4c2b9ab8f35a5e6a0d1932be8f9",packet:{files:116,bytes:1445423,merkle_trees:41},check_count:checks.length,checks,operations,new_original_chains:details,whole_sources:summary.whole_sources,prior_1_to_10_chain_review:"05bc0d3511efcb4936feabecdbb4ebb970c36927",seq3_adoption:"6604b671c8fe49eddf3f5c516aa6e36db46bdec8",historical_errors_preserved:{op11_page_offsets:[16384,32768],op12_status_timeout:true,git_archive_errors_are_separate:true},root_runtime_calls:0,SDK_code_executed:false,selected_owner_observed:false,credentials_read:false,production_qualified:false,full_replacement_qualified:false};
}
