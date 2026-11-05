function(){
 const p="ha_current_source_carrier_relay_actual_r1_",ip="ha_current_source_carrier_inert_actual_r1_",c=load(p+"core_value"),go=load(p+"go_value"),out=load(p+"stdout_value"),checks=[];
 const canonical=x=>x===null||typeof x!=="object"?JSON.stringify(x):Array.isArray(x)?"["+x.map(canonical).join(",")+"]":"{"+Object.keys(x).sort().map(k=>JSON.stringify(k)+":"+canonical(x[k])).join(",")+"}";
 const eq=(a,b)=>canonical(a)===canonical(b),ck=(name,ok)=>{checks.push({name,pass:!!ok});if(!ok)throw Error(name);};
 ck("known whole core and original authority",load(p+"core_whole_verified")&&load(p+"authority_verified")&&load(p+"streams_verified"));
 ck("schema and current canonical",c.schema==="heptabao.same-root-publication-4e808.public-source-carrier-relay.v1"&&c.source_commit==="4e808d0ecb1bcded22870a7ec960dfb2491cf6ec"&&c.source_tree==="eba5e650bd080b8ad41ea52a2bc68867f541d255");
 ck("transferred within unchanged 300/90 caps",c.status==="transferred"&&c.overall_seconds===300&&c.ssh_child_seconds===90&&c.endpoint_seconds===90&&c.elapsed_seconds<300&&out.elapsed_after_publication_seconds<300&&out.publication_within_original_deadline===true);
 ck("all local and endpoint closure without unknown",c.all_local_owned_stopped===true&&c.all_owned_stopped===true&&c.remote_endpoint_completion_verified===true&&c.remote_cleanup_unknown===false&&c.cleanup_errors.length===0);
 ck("fixed destination and source alias",c.destination_root===go.fresh_root&&c.destination_host==="desktop"&&c.source_alias==="rog-ts");
 ck("no Git compiler server product qualification or retry",c.git_operations===0&&c.compiler_started===false&&c.server_started===false&&c.production_changed===false&&c.runtime_qualification===false&&c.automatic_retry===false);
 ck("two exact input descriptors",eq(c.files,go.source_files));
 for(const role of ["sender","receiver"]){
  const e=c[role];
  ck(role+" endpoint schema identity and status",e.schema==="heptabao.same-root-publication-4e808.fixed-public-source-endpoint.v1"&&e.role===role&&e.status==="complete"&&e.source_commit===c.source_commit&&e.source_tree===c.source_tree);
  ck(role+" original deadline closure and no product",e.request_seconds===90&&e.elapsed_seconds<90&&e.within_original_deadline===true&&e.all_owned_stopped===true&&e.cleanup.length===0&&e.cleanup_errors.length===0&&e.git_operations===0&&e.compiler_started===false&&e.server_started===false);
  ck(role+" exactly two files",e.files.length===2);
 }
 ck("receiver create-only fsync mode provenance",c.receiver.destination_created_exclusive===true&&c.receiver.destination_directory_mode===320&&c.receiver.destination_fsynced===true&&c.receiver.raw_receipts_preserved===true&&c.receiver.source_export_provenance_verified===true);
 for(let i=0;i<2;i++){
  const f=go.source_files[i],s=c.sender.files[i],r=c.receiver.files[i],pin={bytes:f.bytes,sha256:f.sha256},si=s.source_identity_before,ri=r.identity;
  ck("source"+i+" exact path name version",s.source===f.path&&s.name===f.name&&s.source_version===f.version);
  ck("source"+i+" full9 before after stable and source metadata",eq(si,s.source_identity_after)&&si.length===9&&si[2]===1000&&si[3]===1000&&si[4]===32768+f.source_mode&&si[5]===1&&si[6]===f.bytes&&[si[0],si[1],si[6],si[7],si[8]].map(String).join(":")===f.version);
  ck("file"+i+" source whole stream and same-FD destination hashes",eq(s.initial_file,pin)&&eq(s.stream,pin)&&eq(r.same_fd_readback,pin)&&r.bytes===f.bytes&&r.sha256===f.sha256);
  ck("destination"+i+" exact create-only fixed path and mode",r.name===f.name&&r.path===go.fresh_root+"/incoming/"+f.name&&r.mode===f.target_mode&&r.create_only===true&&r.fsynced===true&&ri.length===9&&ri[2]===1000&&ri[3]===1000&&ri[4]===32768+f.target_mode&&ri[5]===1&&ri[6]===f.bytes);
 }
 for(const[name,pin]of [["sender.py",c.helpers["sender.py"]],["receiver.py",c.helpers["receiver.py"]],["relay.py",c.controller]]){
  const expected=load(ip+"stdout_value").files.find(x=>x.path.endsWith("/"+name)),actual=load(ip+"complete_state").outputs.find(x=>x.path.endsWith("/"+name));
  ck(name+" same reviewed whole and independent actual publication identity",pin.bytes===expected.bytes&&pin.sha256===expected.sha256&&eq(pin.identity,expected.identity)&&pin.sha256===actual.sha256);
 }
 ck("original HA controller whole before after retained",eq(c.original_ha_controller_before,c.original_ha_controller_after)&&c.original_ha_controller_before.bytes===12409&&c.original_ha_controller_before.sha256==="c70892cb19601fa9769ae3f36810bb123f756f335654f284a4001bf2d69c796e");
 ck("trust full before after unchanged",eq(c.trust_before,c.trust_after));
 const trust={"/home/qian-qi/.ssh/config":"e7b887aad30f6642876c09744c317387b143e4a4b21ddc4879df2b558379ccf4","/home/qian-qi/.ssh/hepta-transport/known_hosts":"1463442349bbb6b56e9ffbb66acce3c4abcceefe1c141c7b7f1ea9bb0dedf034"};
 ck("exact fixed trust paths and hashes",Object.keys(c.trust_before).length===2&&Object.entries(trust).every(([k,v])=>c.trust_before[k].sha256===v));
 const s=c.ssh_preflight["rog-ts"],x=s.projection;
 ck("strict SSH expected endpoint and connection settings",x.host==="rog-ts"&&x.hostname==="192.168.0.10"&&x.user==="qian-qi"&&x.port==="22"&&x.hostkeyalias==="hepta-node-rog"&&x.batchmode==="yes"&&["true","yes"].includes(x.stricthostkeychecking)&&x.connectionattempts==="1"&&x.connecttimeout==="10"&&x.forwardagent==="no"&&["false","no"].includes(x.updatehostkeys)&&x.clearallforwardings==="yes"&&["false","no"].includes(x.controlmaster));
 ck("preflight known_hosts same trust actual",eq(s.known_hosts_before["/home/qian-qi/.ssh/hepta-transport/known_hosts"],c.trust_before["/home/qian-qi/.ssh/hepta-transport/known_hosts"]));
 ck("exact three command and cleanup labels",c.commands.length===3&&c.cleanup.length===3&&new Set(c.commands.map(x=>x.pid)).size===3&&["rog-ts-effective-config","send-rog","receive-desktop"].every(l=>c.commands.filter(x=>x.label===l).length===1&&c.cleanup.filter(x=>x.label===l).length===1));
 for(const cmd of c.commands){
  const row=c.cleanup.find(x=>x.label===cmd.label);
  ck(cmd.label+" original command exit0 deadline and retained cleanup identity",cmd.exit_code===0&&cmd.timed_out===false&&cmd.limit_seconds===90&&cmd.elapsed_seconds<90&&cmd.direct_child_reaped===true&&cmd.remaining.length===0&&row.pid===cmd.pid&&row.exit_code===0&&row.direct_child_reaped===true&&row.remaining.length===0);
 }
 store(p+"core_checks",checks);store(p+"core_verified",true);return{checks:checks.length,all_pass:true,core:load(p+"core_pin"),destinations:c.receiver.files.map(x=>({name:x.name,identity:x.identity,bytes:x.bytes,sha256:x.sha256})),commands:c.commands};
}
