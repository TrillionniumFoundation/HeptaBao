async function(index){
 const p="ha_current_export81_original_archive_r1_",go=load(p+"log_go_value"),e=go.requests[index],q=load(p+e.name+"_request_value");
 if(!load(p+"intent_complete")||load(p+"stop_new_admission"))throw Error("log admission not permitted");
 if(index>0&&!load(p+go.requests[index-1].name+"_complete_r1"))throw Error("previous batch not closed");
 try{
  const r=await eval("("+load("ha_helper_one_closed_public_operation_r1")+")")(p,e.name,q.idempotency_key,q.operation.tool,q.operation.arguments);
  if(r.pending){store(p+"stop_new_admission",true);return {batch:e.name,...r};}
  const v=r.value,u=eval("("+load("ha_helper_reconstructed_r1_utf8")+")"),h=eval("("+load("ha_helper_reconstructed_r1_sha256")+")"),j=eval("("+load("ha_helper_reconstructed_r1_lossless_json")+")"),plan=load(p+"fixed_plan_value"),core=load(p+"original_core_value"),checks=[];
  const norm=z=>Array.isArray(z)?z.map(norm):z&&typeof z==="object"?Object.fromEntries(Object.keys(z).sort().map(k=>[k,norm(z[k])])):z,eq=(a,b)=>JSON.stringify(norm(a))===JSON.stringify(norm(b));
  const ck=(n,ok)=>{checks.push({name:n,passed:!!ok});store(p+e.name+"_checks",checks);if(!ok)throw Error(n);};
  ck("complete_independent_files",v.truncated===false&&v.atomic_snapshot===false&&v.snapshot_scope==="independent_file"&&v.encoding==="utf-8"&&v.files.length===q.operation.arguments.paths.length);
  let bytes=0;const saved={};
  for(let i=0;i<v.files.length;i++){
   const f=v.files[i],want=plan.command_log_rows.find(x=>x.path===q.operation.arguments.paths[i]);if(!want)throw Error("path not in fixed81");
   ck(i+"_exact_path_eof_size_hash",f.path===want.path&&f.eof===true&&f.size===want.bytes&&u(f.text).length===want.bytes&&f.sha256===want.sha256&&h(u(f.text))===want.sha256);
   ck(i+"_version_retained",typeof f.version==="string"&&/^\d+:\d+:\d+:\d+:\d+$/.test(f.version)&&f.version.split(":")[2]===String(f.size));
   const basename=f.path.split("/").at(-1),suffix=basename.endsWith(".public.json")?".public.json":basename.endsWith(".stdout")?".stdout":".stderr",label=basename.slice(0,-suffix.length),c=core.commands.find(x=>x.label===label);if(!c)throw Error("unbound command label");
   if(suffix===".public.json")ck(i+"_record_lossless_equals_original_core",eq(j(f.text),c));
   else {const stream=suffix.slice(1);ck(i+"_stream_exact_original_core",f.size===c[stream+"_bytes"]&&f.sha256===c[stream+"_sha256"]);}
   bytes+=f.size;saved[f.path]=f;
  }
  ck("batch_expected_bytes",bytes===e.expected_body_bytes);
  store(p+e.name+"_raw_files",saved);store(p+e.name+"_verified",true);
  const all=load(p+"all_raw_files")||{};for(const[path,f]of Object.entries(saved)){if(all[path])throw Error("duplicate file observation");all[path]=f;}store(p+"all_raw_files",all);
  return {batch:e.name,operation_id:r.operation_id,closed:true,files:v.files.length,bytes,checks:checks.length,total_files_closed:Object.keys(all).length,payload_bytes:r.payload_bytes,pages:r.pages};
 }catch(err){store(p+"stop_new_admission",true);store(p+e.name+"_failure",String(err));return{batch:e.name,stopped:true,error:String(err)};}
}
