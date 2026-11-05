function(prefix,name){
 const u=eval("("+load("ha_helper_reconstructed_r1_utf8")+")"),s2=eval("("+load("ha_helper_reconstructed_r1_sha256")+")"),lj=eval("("+load("ha_helper_reconstructed_r1_lossless_json")+")"),q=lj(load(prefix+name+"_native_text_r1")),plan=load(prefix+"command_plan"),observation=load(prefix+"observer_plan").find(x=>x.name===name),core=load(prefix+"core_value");
 const canonical=v=>v===null||typeof v!=="object"?JSON.stringify(v):Array.isArray(v)?"["+v.map(canonical).join(",")+"]":"{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+canonical(v[k])).join(",")+"}",eq=(a,b)=>canonical(a)===canonical(b);
 const checks=[],ck=(name,v)=>{checks.push({name,pass:!!v});if(!v)throw Error(name);};
 ck("closed, complete, independent file snapshot",load(prefix+name+"_complete_r1")===true&&load(prefix+name+"_closed_status_r1").owned_future_active===false&&q.truncated===false&&q.snapshot_scope==="independent_file"&&q.atomic_snapshot===false&&q.encoding==="utf-8");
 ck("exact fixed paths and order",eq(q.files.map(x=>x.path),observation.args.paths)&&new Set(q.files.map(x=>x.path)).size===q.files.length);
 const raw=load(prefix+"command_raw_files")||{},metadata=load(prefix+"command_file_metadata")||{};
 for(const f of q.files){
  const spec=plan.small_files.find(x=>x.path===f.path);ck("admitted file "+f.path,!!spec);
  const b=u(f.text);ck("whole SHA/EOF "+f.path,f.eof===true&&b.length===f.size&&s2(b)===f.sha256&&f.size<=65536);
  ck("lossless version "+f.path,/^[0-9]+(:[0-9]+){4}$/.test(f.version)&&f.version.split(":")[2]===String(f.size));
  if(spec.kind==="saved-stream")ck("original stream bytes/SHA "+spec.label+" "+spec.stream,f.size===spec.bytes&&f.sha256===spec.sha256);
  else if(spec.kind==="command-record")ck("original command exact terminal "+spec.label,eq(lj(f.text),spec.expected_command));
  else if(spec.kind==="original-controller")ck("exact original controller source",f.text===load(prefix+"source_text")&&f.size===spec.bytes&&f.sha256===spec.sha256);
  else if(spec.kind==="original-controller-intent"){
    const exp=Object.fromEntries(load(prefix+"initial_result_keys").map(k=>[k,core[k]]));exp.status="failed";exp.source_imported=false;
    for(const k of ["input_files_before","export_receipt_verified","transport_receipt_verified","raw_input_receipts_unchanged","bundle_header","controller"])exp[k]=core[k];
    const from=i=>({name:i.name,path:i.path,bytes:i.same_fd_readback.bytes,sha256:i.same_fd_readback.sha256,mode:i.mode,version:i.version});
    exp.files=core.input_files_before.slice(0,2).map(from);exp.transport_receipt=from(core.input_files_before[2]);exp.source=load(prefix+"go_value").fixed_destinations.repository;exp.receipt=plan.fixed_control+"/result.public.json";exp.binary_execution_allowed=false;exp.existing_source_used=false;
    ck("original preexecution intent exact source-defined snapshot",eq(lj(f.text),exp));
  }else throw Error("unadmitted role");
  const relative=f.path.slice(plan.fixed_control.length+1);ck("fixed direct control filename",!relative.includes("/")&&f.path===plan.fixed_control+"/"+relative);
  if(raw[relative]!==undefined)ck("no different duplicate file",raw[relative]===f.text);
  raw[relative]=f.text;metadata[f.path]={kind:spec.kind,size:f.size,sha256:f.sha256,version:f.version,original_observation:name};
 }
 store(prefix+"command_raw_files",raw);store(prefix+"command_file_metadata",metadata);store(prefix+name+"_checks",checks);store(prefix+name+"_verified",true);
 const all=load(prefix+"command_checks")||[];store(prefix+"command_checks",all.concat(checks));
 return {observation:name,files:q.files.length,bytes:q.files.reduce((n,f)=>n+f.size,0),checks:checks.length,passed:true,unique_small_files:Object.keys(metadata).length};
}
