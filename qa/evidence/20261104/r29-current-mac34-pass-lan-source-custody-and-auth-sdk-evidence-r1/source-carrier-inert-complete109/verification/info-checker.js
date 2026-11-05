function(i){
 const p="ha_current_source_carrier_inert_actual_r1_",k="file"+i+"_info",parse=eval("("+load("ha_helper_reconstructed_r1_lossless_json")+")");
 if(!load(p+k+"_complete_r1"))throw Error("incomplete info");
 const q=parse(load(p+k+"_native_text_r1")),plan=load(p+"observer_plan").find(x=>x.name===k),vs=String(q.version).split(":"),checks=[];
 const ck=(name,ok)=>{checks.push({name,pass:!!ok});if(!ok)throw Error(name);};
 ck("fixed path",q.path===plan.request.operation.arguments.path);
 ck("version has five exact decimal fields",vs.length===5&&vs.every(x=>/^[0-9]+$/.test(x)));
 ck("mode uid gid nlink",q.mode===384&&q.metadata.mode===384&&q.metadata.uid===1000&&q.metadata.gid===1000&&q.metadata.link_count===1);
 ck("size version equality and cap",String(q.size)===vs[2]&&Number.isSafeInteger(q.size)&&q.size>0&&q.size<=32768);
 ck("whole hash format",/^[0-9a-f]{64}$/.test(q.sha256));
 if(i<3){
  const r=load(p+"stdout_value").files[i],h=load(p+"decoded_helpers")[q.path.split("/").pop()],e=r.identity;
  ck("publisher fixed path and source bytes",r.path===q.path&&r.bytes===q.size&&h.bytes===q.size);
  ck("publisher and reviewed whole SHA",r.sha256===q.sha256&&h.sha256===q.sha256);
  ck("publisher regular fullmode with matching permission projection",e[4]===32768+q.mode&&r.mode==="0600");
  ck("publisher all nine identity fields including nanoseconds",String(e[0])===vs[0]&&String(e[1])===vs[1]&&e[2]===q.metadata.uid&&e[3]===q.metadata.gid&&e[5]===q.metadata.link_count&&String(e[6])===vs[2]&&String(e[7])===vs[3]&&String(e[8])===vs[4]);
 }else ck("receipt identity independently observed; not claimed publisher emitted",q.path.endsWith("/inert-stage.result.public.json"));
 store(p+k+"_verified_value",q);store(p+k+"_identity_checks",checks);store(p+k+"_verified",true);
 return {name:k,path:q.path,bytes:q.size,sha256:q.sha256,version:q.version,checks:checks.length,passed:true};
}
