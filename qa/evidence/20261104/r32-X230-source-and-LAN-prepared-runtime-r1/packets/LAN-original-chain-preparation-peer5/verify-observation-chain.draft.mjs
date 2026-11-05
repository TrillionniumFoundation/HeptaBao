function verifyHAObservationChain(input, sha256, gitSha1) {
 const checks=[],used=new Set(),seenIds=new Set(),results={};
 function check(name,pass){checks.push({name,passed:pass===true});if(pass!==true)throw Object.assign(new Error(name),{checks});}
 function bytes(s){return unescape(encodeURIComponent(s));}
 function equal(a,b){return JSON.stringify(a)===JSON.stringify(b);}
 function read(path){
  const v=input.files[path];check("file.present:"+path,Boolean(v)&&typeof v.raw==="string");
  if(!used.has(path)){const b=bytes(v.raw);check("file.pin:"+path,b.length===v.bytes&&sha256(b)===v.sha256&&gitSha1("blob "+b.length+"\0"+b)===v.blob);used.add(path);}
  return v.raw;
 }
 function json(path){return JSON.parse(read(path));}
 function oneText(v,name){check(name+".one_text",Array.isArray(v.content)&&v.content.length===1&&v.content[0].type==="text"&&typeof v.content[0].text==="string");return v.content[0].text;}
 function sdk(path,nativePath){
  const v=json(path);check("SDK.isError_false:"+path,v.isError===false);
  check("SDK.structured_null:"+path,v.structuredContent===null||v.structuredContent===undefined);
  const raw=oneText(v,path);check("SDK.native_exact:"+path,raw===read(nativePath));return{raw,value:JSON.parse(raw)};
 }
 function base64(s){
    check("base64.syntax",typeof s==="string"&&s.length%4===0&&/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s));
    const a="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let out="";
    for(let i=0;i<s.length;i+=4){
      const x=a.indexOf(s[i]),y=a.indexOf(s[i+1]),z=s[i+2]==="="?0:a.indexOf(s[i+2]),w=s[i+3]==="="?0:a.indexOf(s[i+3]);
      if(s[i+2]==="=")check("base64.pad2",(y&15)===0);
      else if(s[i+3]==="=")check("base64.pad1",(z&3)===0);
      out+=String.fromCharCode((x<<2)|(y>>4));
      if(s[i+2]!=="=")out+=String.fromCharCode(((y&15)<<4)|(z>>2));
      if(s[i+3]!=="=")out+=String.fromCharCode(((z&3)<<6)|w);
    }return out;
  }
 function nativeFromPayload(payloadPath,nativePath){
  const outer=json(payloadPath);
  check("payload.complete:"+payloadPath,outer.resultType==="complete"&&outer.isError===false);
  const raw=oneText(outer,payloadPath);check("payload.native_exact:"+payloadPath,raw===read(nativePath));
  return JSON.parse(raw);
 }
 function observer(name){
  const root="observations/"+name+"/";
  const request=json(root+"intent/exact-operation-start-request.public.json");
  check(name+".admission_request_exact",read(root+"admission/request.original.json")===read(root+"intent/exact-operation-start-request.public.json"));
  const intent=json(root+"intent/read-intent.public.json");
  check(name+".intent_request",equal(intent.request,request));
  const ack=sdk(root+"admission/original.sdk.json",root+"admission/original.native.txt").value;
  check(name+".id_shape",typeof ack.operation_id==="string"&&/^[0-9a-f]{64}$/.test(ack.operation_id));
  check(name+".unique_id",!seenIds.has(ack.operation_id));seenIds.add(ack.operation_id);
  check(name+".tool_binding",ack.tool_name===request.operation.tool);
  check(name+".new_original_admission",ack.reused===false&&ack.automatic_retry===false&&ack.idempotency_binding_retained===true);
  const statusPaths=Object.keys(input.files).filter(path=>path.startsWith(root)&&/^status-\d+\/request\.original\.json$/.test(path.slice(root.length))).sort((a,b)=>Number(a.slice(root.length).split("/")[0].slice(7))-Number(b.slice(root.length).split("/")[0].slice(7)));
  check(name+".status_present",statusPaths.length>0);
  let status;
  for(const path of statusPaths){
   const q=json(path),dir=path.slice(0,path.lastIndexOf("/")+1);
   check(name+".status_request:"+path,equal(q,{operation_id:ack.operation_id}));
   status=sdk(dir+"original.sdk.json",dir+"original.native.txt").value;
   check(name+".status_same_id:"+path,status.operation_id===ack.operation_id&&status.tool_name===request.operation.tool);
  }
  check(name+".closed",status.async_state==="completed"&&status.owned_future_active===false&&status.result_state==="stored_observed"&&status.payload_available===true);
  const pages=Object.keys(input.files).filter(path=>path.startsWith(root+"pages/")&&path.endsWith("/request.original.json")).map(path=>({path,request:json(path)})).sort((a,b)=>a.request.offset-b.request.offset);
  check(name+".pages_present",pages.length>0);
  let offset=0,joined="",total=null,digest=null;
  for(let i=0;i<pages.length;i++){
   const {path,request:q}=pages[i],dir=path.slice(0,path.lastIndexOf("/")+1);
   check(name+".page_request:"+i,q.operation_id===ack.operation_id&&q.offset===offset&&q.limit===8192);
   const page=sdk(dir+"original.sdk.json",dir+"original.native.txt").value;
   check(name+".page_snapshot:"+i,page.operation_id===ack.operation_id&&page.immutable_snapshot===true&&page.payload_kind==="native_result"&&
    page.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization");
   if(i===0){total=page.total_bytes;digest=page.result_sha256;check(name+".page_total_bound",Number.isSafeInteger(total)&&total>=0&&total<=1048576&&/^[0-9a-f]{64}$/.test(digest));}
   check(name+".page_identity:"+i,page.total_bytes===total&&page.result_sha256===digest&&page.offset===offset);
   const data=base64(page.data_base64);
   check(name+".page_extent:"+i,data.length<=8192&&page.next_offset===offset+data.length&&page.next_offset<=total);
   offset=page.next_offset;joined+=data;
   check(name+".page_eof:"+i,page.eof===(offset===total)&&(i===pages.length-1||page.eof===false));
  }
  check(name+".payload_whole",offset===total&&sha256(joined)===digest&&joined===bytes(read(root+"payload.original.json")));
  const native=nativeFromPayload(root+"payload.original.json",root+"native.original.json");
  results[name]={operation_id:ack.operation_id,tool:request.operation.tool,request,closed:true,pages:pages.length,payload_bytes:total,payload_sha256:digest,native};
  return results[name];
 }
 const exec=input.execution,req=json(exec.request),intent=json(exec.intent),go=json(exec.GO);
 check("execution.request_fixed_blob",input.files[exec.request].blob==="c97a08fa3f1844d678b800d04fc54daa22e07cce");
 check("execution.GO_fixed_blob",input.files[exec.GO].blob==="b1e1c5a77c225b989825a86de287241c5b369402");
 check("execution.intent_request",equal(req,intent.exact_request)&&equal(req,go.request.value));
 check("execution.intent_pin",intent.request.blob===input.files[exec.request].blob&&intent.request.bytes===input.files[exec.request].bytes&&intent.request.sha256===input.files[exec.request].sha256);
 const typed={args:req.args,cpu_quota_percent:null,cwd:req.cwd,env:{},executable:req.executable,host:req.host,memory_max_bytes:null,nice:null,stdin:null,timeout_seconds:req.timeout_seconds};
 const canonical=JSON.stringify(typed),digest=sha256(bytes(canonical));
 check("execution.typed_canonical",canonical===intent.typed_binding.canonical_json&&canonical===go.typed_binding.canonical_json);
 check("execution.typed_digest",digest==="a9b995a1bd91a05389653e25ea0d472b1de150ad473321453087c2e0330eff4f"&&digest===intent.typed_binding.request_digest&&digest===go.typed_binding.request_digest);
 const fp=BigInt("0x"+digest.slice(0,16)).toString();
 check("execution.fingerprint_decimal",fp==="12229970785004003411"&&fp===intent.typed_binding.request_fingerprint_decimal&&fp===go.typed_binding.expected_request_fingerprint_decimal);
 const ack=sdk(exec.ACK_SDK,exec.ACK_native);
 const fptokens=[...ack.raw.matchAll(/"request_fingerprint"\s*:\s*(\d+)/g)].map(m=>m[1]);
 check("execution.ACK_lossless_FP",fptokens.length===1&&fptokens[0]===fp);
 check("execution.ACK_binding",ack.value.job.host===req.host&&ack.value.job.id==="1a1ad3a6dd4-fc05-5919"&&ack.value.job.request_digest===digest&&
 ack.value.job.idempotency_key===req.idempotency_key&&ack.value.job.executable===req.executable&&ack.value.job.cwd===req.cwd&&equal(ack.value.job.args,req.args)&&equal(ack.value.job.env_keys,[]));
 check("execution.one_original_launched",ack.value.reused===false&&ack.value.audit_recorded===true&&ack.value.local_record_pending===false&&ack.value.job.launch_state==="launched"&&ack.value.job.launch_error===null&&ack.value.launch.ok===true);
 for(const name of input.observer_names)observer(name);
 const plan=json(input.body_plan);
 check("bodyplan.fixed_job",plan.job_id==="1a1ad3a6dd4-fc05-5919"&&plan.outputs.length===3&&plan.total_bytes===312076&&plan.total_body_operations===7&&plan.max_body_chunk===65536&&plan.immutable_page_limit===8192);
 const expectedInfos=[
 {bytes:4132,sha:"693d7ebdf0d0787cfdce443c4c504cce82c3b9180ecc3ec1e4bc161ece41fbad",version:"2050:7401922:4132:1793907654678586055:1793907654678586055"},
 {bytes:652,sha:"93a33f4d70249e597f7ecd5ef5cfef9ddfbdea733846b8146441254b9498a5a9",version:"2050:7401925:652:1793908088720162039:1793908088720162039"},
 {bytes:307292,sha:"87f4e3a08d87045de370d30555768bea5b8a95f3a8f317a684746f8c9a4250b1",version:"2050:7874221:307292:1793908086830161920:1793908086830161920"}
 ];
 let planned=0,chunkCount=0;
 for(let i=0;i<3;i++){
  const output=plan.outputs[i],expected=expectedInfos[i],info=json(input.info_plan_paths[i]);
  check("bodyplan.info"+i,equal(output.info,info)&&output.path===info.path&&info.size===expected.bytes&&info.sha256===expected.sha&&info.version===expected.version&&output.expected_whole_bytes===expected.bytes&&output.expected_whole_sha256===expected.sha);
  let offset=0;
  for(const c of output.chunks){
   const expectedRequest={idempotency_key:c.key,operation:{tool:c.tool,arguments:c.args}};
   check("bodyplan.request:"+c.name,equal(json(input.body_request_paths[c.name]),expectedRequest)&&c.tool==="binary_read"&&c.args.host==="desktop"&&
    c.args.path===output.path&&c.args.expected_version===expected.version&&c.args.offset===offset&&c.args.limit===Math.min(65536,expected.bytes-offset));
   offset+=c.args.limit;chunkCount++;
  }
  check("bodyplan.coverage"+i,offset===expected.bytes);planned+=offset;
 }
 check("bodyplan.total",planned===312076&&chunkCount===7);
 if(input.complete===true){
  check("complete.body_observers_present",plan.outputs.every(o=>o.chunks.every(c=>Boolean(results[c.name]))));
  for(let i=0;i<3;i++){
   const output=plan.outputs[i],expected=expectedInfos[i];let joined="";
   for(const c of output.chunks){
    const r=results[c.name],n=r.native,q=r.request;
    check("body.request_actual:"+c.name,equal(q,{idempotency_key:c.key,operation:{tool:c.tool,arguments:c.args}}));
    check("body.identity:"+c.name,n.path===output.path&&n.version===expected.version&&n.offset===c.args.offset&&n.size===expected.bytes);
    const data=base64(n.data_base64);
    check("body.chunk:"+c.name,data.length===c.args.limit&&sha256(data)===n.chunk_sha256&&n.next_offset===c.args.offset+data.length&&n.eof===(n.next_offset===expected.bytes));
    joined+=data;
   }
   check("body.whole"+i,joined.length===expected.bytes&&sha256(joined)===expected.sha&&joined===bytes(read(input.whole_output_paths[i])));
  }
 }
 return {schema:"heptabao.current4e808.HA-independent-original-chain-peer.result.v1",
  scope:input.complete?"returned_observation_chain_and_exact_bodies":"PREPARATION_ONLY_RUNNING35_AND_BODYPLAN11",
  ok:true,checks,passed:checks.length,failed:0,complete_claim:input.complete===true,
  observer_summary:Object.fromEntries(Object.entries(results).map(([name,r])=>[name,{operation_id:r.operation_id,tool:r.tool,closed:r.closed,pages:r.pages,payload_bytes:r.payload_bytes,payload_sha256:r.payload_sha256}])),
  used_files:[...used].sort().map(path=>({path,blob:input.files[path].blob,bytes:input.files[path].bytes,sha256:input.files[path].sha256})),
  running_authority_not_terminal:true,product_98plus12_semantics_reviewed:false,author_verifier_run:false,Runtime_calls:0};
}
