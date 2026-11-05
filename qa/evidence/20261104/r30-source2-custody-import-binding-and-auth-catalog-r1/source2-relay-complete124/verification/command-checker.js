function(){
 const p="ha_current_source_carrier_relay_actual_r1_",u=eval("("+load("ha_helper_reconstructed_r1_utf8")+")"),h=eval("("+load("ha_helper_reconstructed_r1_sha256")+")"),parse=eval("("+load("ha_helper_reconstructed_r1_lossless_json")+")"),q=parse(load(p+"command_logs_native_text_r1")),plan=load(p+"command_plan"),c=load(p+"core_value"),base=load(p+"go_value").fresh_root+"/control/",checks=[],files={};
 const canonical=x=>x===null||typeof x!=="object"?JSON.stringify(x):Array.isArray(x)?"["+x.map(canonical).join(",")+"]":"{"+Object.keys(x).sort().map(k=>JSON.stringify(k)+":"+canonical(x[k])).join(",")+"}",eq=(a,b)=>canonical(a)===canonical(b);
 const ck=(n,ok)=>{checks.push({name:n,pass:!!ok});if(!ok)throw Error(n);};
 ck("closed read complete independent snapshot",load(p+"command_logs_complete_r1")&&load(p+"command_logs_closed_status_r1").owned_future_active===false&&q.truncated===false&&q.snapshot_scope==="independent_file"&&q.atomic_snapshot===false&&q.encoding==="utf-8");
 ck("ten fixed original files no missing extras",q.files.length===10&&new Set(q.files.map(x=>x.path)).size===10&&eq(q.files.map(x=>x.path),plan.paths));
 for(const f of q.files){
  ck(f.path+" full byte/hash EOF",f.eof===true&&u(f.text).length===f.size&&h(u(f.text))===f.sha256&&f.size<=32768);
  ck(f.path+" fixed stored version decimal size",/^([0-9]+:){4}[0-9]+$/.test(f.version)&&f.version.split(":")[2]===String(f.size));
  files[f.path]=f;
 }
 const read=n=>files[base+n].text;
 for(const row of c.commands)ck(row.label+" original record exact core",eq(parse(read(row.label+".public.json")),row));
 ck("five actual saved streams only; no sender stdout file",q.files.filter(x=>/\.(stdout|stderr)$/.test(x.path)).length===5&&!q.files.some(x=>x.path===base+"send-rog.stdout"));
 ck("sender stderr original exact core endpoint",eq(parse(read("send-rog.stderr")),c.sender));
 ck("receiver stderr original exact core endpoint",eq(parse(read("receive-desktop.stderr")),c.receiver));
 ck("expected two empty streams",read("rog-ts-effective-config.stderr")===""&&read("receive-desktop.stdout")==="");
 ck("effective config original full SHA",h(u(read("rog-ts-effective-config.stdout")))===c.ssh_preflight["rog-ts"].effective_config_sha256);
 ck("saved SSH preflight exact core",eq(parse(read("ssh-preflight.public.json")),c.ssh_preflight));
 const i=parse(read("intent.public.json"));
 ck("original intent canonical schema destination and source descriptors",i.schema===c.schema&&i.source_commit===c.source_commit&&i.source_tree===c.source_tree&&i.destination_root===c.destination_root&&i.source_alias===c.source_alias&&i.destination_host===c.destination_host&&eq(i.files,c.files));
 ck("original intent three source and trust full pins",eq(i.controller,c.controller)&&eq(i.helpers,c.helpers)&&eq(i.original_ha_controller,c.original_ha_controller_before)&&eq(i.trust_before,c.trust_before));
 ck("original intent old budgets and create-only zero product",i.overall_seconds===300&&i.ssh_child_seconds===90&&i.endpoint_seconds===90&&i.destination_create_only===true&&i.git_operations===0&&i.compiler_started===false&&i.server_started===false&&i.production_changed===false&&i.automatic_retry===false&&i.runtime_qualification===false);
 const ssh=["/usr/bin/ssh","-T","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o","ConnectTimeout=10","-o","ConnectionAttempts=1","-o","ClearAllForwardings=yes","-o","ForwardAgent=no","-o","UpdateHostKeys=no","-o","ControlMaster=no","-o","ControlPath=none"];
 ck("original strict SSH exact frozen argv",eq(i.ssh_argv_prefix,ssh));
 const config={};for(const line of read("rog-ts-effective-config.stdout").trimEnd().split("\n")){const n=line.indexOf(" ");ck("config line key value",n>0);const k=line.slice(0,n);if(!Object.hasOwn(config,k))config[k]=line.slice(n+1);}
 for(const[k,v]of Object.entries(c.ssh_preflight["rog-ts"].projection))ck("config projection "+k,(config[k]??null)===v);
 ck("original export input received hash preserved",c.receiver.source_export_provenance_verified===true&&c.receiver.files[1].same_fd_readback.sha256===load(p+"go_value").source_files[1].sha256);
 store(p+"command_raw_files",files);store(p+"command_checks",checks);store(p+"command_verified",true);
 return{checks:checks.length,all_pass:true,whole_files:q.files.length,total_bytes:q.files.reduce((s,x)=>s+x.size,0),original_commands:c.commands.length,actual_saved_streams:5,original_intent_initial_status:i.status,original_intent_status_note:"The source emits its initial failed default before execution; the authoritative result is the later transferred core and exit0."};
}
