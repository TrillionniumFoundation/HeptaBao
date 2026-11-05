function verifyHAObservationChainIncrement(input, sha256, gitSha1) {
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

 const prior=json("peer-preparation/prepared-result.public.json");
 check("prior.exact_pin",input.files["peer-preparation/prepared-result.public.json"].blob==="c5040a809dfaec32f5bd739248ba1598c11e6065");
 check("prior187.adopt_not_rerun",prior.ok===true&&prior.passed===187&&prior.failed===0&&prior.complete_claim===false&&equal(Object.keys(prior.observer_summary).sort(),["authority0","authority1"]));
 for(const r of Object.values(prior.observer_summary)){check("prior.closed:"+r.operation_id,r.closed===true);seenIds.add(r.operation_id);}
 let unchangedOld=0;
 for(const [path,old] of Object.entries(input.running35_pins)){
  const mapped=path==="STATE.public.json"?"history/running35-STATE.original.json":path;
  check("preserved.running35:"+path,input.files[mapped]?.blob===old.blob&&input.files[mapped]?.bytes===old.bytes&&input.files[mapped]?.sha256===old.sha256);
  if(path!=="STATE.public.json")unchangedOld++;
 }
 check("preserved.corrected34",unchangedOld===34);
 for(const [path,old] of Object.entries(input.bodyplan11_pins)){
  const mapped="readback-plan/"+path;
  check("preserved.bodyplan11:"+path,input.files[mapped]?.blob===old.blob&&input.files[mapped]?.bytes===old.bytes&&input.files[mapped]?.sha256===old.sha256);
 }
 const oldPaths=Object.keys(input.original388_pins).sort();
 const actualChanged=Object.keys(input.final390_pins).filter(path=>input.original388_pins[path]?.blob!==input.final390_pins[path].blob).sort();
 check("packaging.only4_leaves",equal(actualChanged,["MANIFEST.public.json","READPLAN.public.json","history/full388-readplan-correction.public.json","history/merged-core15-READPLAN.original.json"]));
 check("packaging.no_removed",oldPaths.every(path=>input.final390_pins[path]));
 check("packaging.old388_readplan_exact",input.original388_pins["READPLAN.public.json"].blob==="0d2a159cfb78835f273772d308669e177f369afd");
 check("packaging.history_old_bodyplan",input.final390_pins["history/merged-core15-READPLAN.original.json"].blob==="0d2a159cfb78835f273772d308669e177f369afd");
 check("packaging.observations_unchanged",oldPaths.filter(path=>path.startsWith("observations/")).every(path=>equal(input.original388_pins[path],input.final390_pins[path])));
 check("packaging.actual_and_author_results_unchanged",oldPaths.filter(path=>path.startsWith("actual/")||path.startsWith("verification/")||path==="RELEASE.public.json").every(path=>equal(input.original388_pins[path],input.final390_pins[path])));
 const discovered=[...new Set(Object.keys(input.final390_pins).filter(path=>path.startsWith("observations/")).map(path=>path.split("/")[1]))].sort();
 const allNames=["authority0","authority1","authority2","authority3","streams0","output0_info","output1_info","output2_info","output0_body0","output1_body0","output2_body0","output2_body1","output2_body2","output2_body3","output2_body4"];
 check("exact15names",equal(discovered,allNames.slice().sort()));
 const newNames=allNames.filter(n=>!["authority0","authority1"].includes(n));
 for(const name of newNames){
  observer(name);
  const r=results[name],intent=json("observations/"+name+"/intent/read-intent.public.json");
  check(name+".fixed_intent",intent.job_id==="1a1ad3a6dd4-fc05-5919"&&intent.observation===name&&intent.root_GO.blob==="b1e1c5a77c225b989825a86de287241c5b369402");
  if(name.startsWith("authority")){
   check(name+".fixed_job",r.tool==="process_status"&&equal(r.request.operation.arguments,{host:"desktop",job_id:"1a1ad3a6dd4-fc05-5919"})&&r.native.job_id==="1a1ad3a6dd4-fc05-5919");
  }
 }
 check("no_prior_observer_rerun",Object.keys(results).length===13&&!results.authority0&&!results.authority1);
 check("authority2.running_preserved",results.authority2.native.state==="running");
 const authority=results.authority3.native;
 check("authority3.exact_actual_raw",read("observations/authority3/native.original.json")===read("actual/authority.original.json")&&input.files["actual/authority.original.json"].blob==="0f745b9078a5c27f3c9fc3923c88069a9040a967");
 check("authority3.known_terminal",authority.state==="succeeded"&&authority.exit_code===0&&authority.output_complete===true&&authority.output_durable===true&&authority.terminal_publication_confirmed===true&&authority.timed_out===false&&authority.cancelled===false&&authority.automatic_retry===false);
 const streams=results.streams0;
 check("streams.fixed_request",streams.tool==="process_read"&&equal(streams.request.operation.arguments,{host:"desktop",job_id:"1a1ad3a6dd4-fc05-5919",limit:16384,stdout_offset:0,stderr_offset:0}));
 check("streams.same_job",streams.native.job_id==="1a1ad3a6dd4-fc05-5919");
 function hex(s){check("hex.syntax",typeof s==="string"&&s.length%2===0&&/^[0-9a-f]*$/.test(s));let b="";for(let i=0;i<s.length;i+=2)b+=String.fromCharCode(parseInt(s.slice(i,i+2),16));return b;}
 for(const [which,count] of [["stdout",612],["stderr",0]]){
  const stream=streams.native[which],b=hex(stream.bytes_hex);
  check("streams."+which+".whole",stream.offset===0&&stream.next_offset===count&&stream.size===count&&stream.eof===true&&b.length===count&&b===bytes(stream.text)&&b===bytes(read("actual/"+which+".original.txt")));
  check("authority."+which+".full",authority.log_bytes[which].seen===count&&authority.log_bytes[which].stored===count&&authority.log_errors[which]===null&&authority.log_synced[which]===true&&authority.log_truncated[which]===false);
 }
 const plan=json("readback-plan/body-plan.public.json");
 check("bodyplan.adopt_exact",input.files["readback-plan/body-plan.public.json"].blob==="0d2a159cfb78835f273772d308669e177f369afd"&&plan.total_body_operations===7&&plan.total_bytes===312076);
 const actualPaths=["actual/launch.original.json","actual/exit.original.json","actual/summary.original.json"];
 const actualBlobs=["1887e1ad3917bfe532df19b83dc1aa8ad6013db6","f6b857e904694aa2dc6199e673ce96eb9535b434","74bc3f4393c3909de08c9f541570ed7c4043b162"];
 let bodyBytes=0,bodyOps=0;const bodies=[];
 for(let i=0;i<3;i++){
  const output=plan.outputs[i],infoObs=results["output"+i+"_info"],n=infoObs.native,stored=output.info;
  check("info"+i+".request",infoObs.tool==="file_info"&&equal(infoObs.request.operation.arguments,{host:"desktop",path:output.path}));
  check("info"+i+".actual_binding",n.path===output.path&&n.size===stored.size&&n.sha256===stored.sha256&&n.version===stored.version&&n.mode===stored.mode&&equal(n.metadata,stored.metadata));
  const v=n.version.split(":"),m=n.metadata;
  check("info"+i+".lossless_version",v.length===5&&v.every(s=>/^\d+$/.test(s))&&v[2]===String(n.size));
  const full9=[v[0],v[1],String(m.uid),String(m.gid),String((m.mode&0o170000)?m.mode:m.mode|0o100000),String(m.link_count),v[2],v[3],v[4]];
  check("info"+i+".full9_projection",equal(full9,stored.full9_decimal));
  let joined="";
  for(const c of output.chunks){
   const r=results[c.name],n=r.native,expected={idempotency_key:c.key,operation:{tool:c.tool,arguments:c.args}};
   check("body."+c.name+".exact_request",equal(r.request,expected)&&equal(json("readback-plan/requests/"+c.name+".public.json"),expected));
   check("body."+c.name+".identity",n.path===output.path&&n.version===stored.version&&n.offset===c.args.offset&&n.offset===joined.length&&n.size===stored.size);
   const b=base64(n.data_base64);
   check("body."+c.name+".chunk",b.length===c.args.limit&&sha256(b)===n.chunk_sha256&&n.next_offset===n.offset+b.length&&n.eof===(n.next_offset===stored.size));
   joined+=b;bodyOps++;
  }
  check("body"+i+".whole",joined.length===stored.size&&sha256(joined)===stored.sha256&&joined===bytes(read(actualPaths[i]))&&input.files[actualPaths[i]].blob===actualBlobs[i]);
  bodyBytes+=joined.length;bodies.push({path:output.path,bytes:joined.length,sha256:stored.sha256,version:stored.version,actual_blob:actualBlobs[i],chunks:output.chunks.length});
 }
 check("body.totals",bodyOps===7&&bodyBytes===312076);
 const summary={...prior.observer_summary,...Object.fromEntries(Object.entries(results).map(([name,r])=>[name,{operation_id:r.operation_id,tool:r.tool,closed:r.closed,pages:r.pages,payload_bytes:r.payload_bytes,payload_sha256:r.payload_sha256}]))};
 const pageCount=Object.values(summary).reduce((n,r)=>n+r.pages,0);
 check("observation.totals15_62",Object.keys(summary).length===15&&pageCount===62&&new Set(Object.values(summary).map(r=>r.operation_id)).size===15);
 const release=json("RELEASE.public.json");
 check("release.read_scope_matches",release.job_id==="1a1ad3a6dd4-fc05-5919"&&release.returned_read_observers===15&&release.immutable_pages===62&&release.all_returned_read_observers_completed_stored_inactive===true&&release.unclosed_current_native_futures===0&&release.inflight_runtime_tool_calls===0);
 return {schema:"heptabao.current4e808.HA-independent-original-chain-increment.result.v1",ok:true,
 original388_tree:"06d392d5d549d060efa77faeb44a0d48933d8d45",corrected390_tree:"625df69e7dbe4407686253564ccd607a3b60b939",
 prior_checks_adopted:187,prior_observers_adopted:2,prior_pages_adopted:2,prior187_rerun:false,
 incremental_checks:checks.length,failed:0,checks_sha256:sha256(bytes(JSON.stringify(checks))),
 new_observers_checked:13,new_pages_checked:pageCount-2,total_observers:15,total_pages:62,observer_summary:summary,
 original_payload_bytes:Object.values(summary).reduce((n,r)=>n+r.payload_bytes,0),
 body_operations:bodyOps,body_bytes:bodyBytes,bodies,
 terminal:{job_id:authority.job_id,exit_code:authority.exit_code,output_complete:authority.output_complete,output_durable:authority.output_durable,terminal_publication_confirmed:authority.terminal_publication_confirmed},
 streams:{stdout_bytes:612,stderr_bytes:0,whole_hex_text_EOF:true},
 packaging:{old388_unchanged_nonstate_running_paths:33,corrected390_unchanged_nonstate_running_paths:34,only_four_archive_leaves_changed:true,all_original_observations_unchanged:true,old388_retained:true},
 used_files:[...used].sort().map(path=>({path,blob:input.files[path].blob,bytes:input.files[path].bytes,sha256:input.files[path].sha256})),
 author_verifier_run:false,product98plus12_semantics_reviewed:false,owned_process_cleanup_semantics_reviewed:false,
 Runtime_calls:0,SDK_executions:0,actual_selected_owner:null};
}
