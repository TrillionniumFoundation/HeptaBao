function(i){
 const p="ha_current_source_carrier_relay_actual_r1_",k="dest"+i+"_info",q=load(p+k+"_native_value_r1"),r=load(p+"core_value").receiver.files[i],f=load(p+"go_value").source_files[i],v=q.version.split(":"),id=r.identity,checks=[];
 const ck=(n,ok)=>{checks.push({name:n,pass:!!ok});if(!ok)throw Error(n);};
 ck("closed original independent info",load(p+k+"_complete_r1")&&load(p+k+"_closed_status_r1").owned_future_active===false);
 ck("fixed path and exact whole source/receiver SHA size",q.path===r.path&&q.path===load(p+"go_value").fresh_root+"/incoming/"+f.name&&q.size===f.bytes&&q.sha256===f.sha256&&r.bytes===q.size&&r.sha256===q.sha256);
 ck("fixed mode owner nlink",q.mode===256&&q.metadata.mode===256&&q.metadata.uid===1000&&q.metadata.gid===1000&&q.metadata.link_count===1);
 ck("all full9 receiver identity fields match independent metadata",v.length===5&&v.every(x=>/^[0-9]+$/.test(x))&&String(id[0])===v[0]&&String(id[1])===v[1]&&id[2]===q.metadata.uid&&id[3]===q.metadata.gid&&id[4]===32768+q.mode&&id[5]===q.metadata.link_count&&String(id[6])===v[2]&&id[6]===q.size&&String(id[7])===v[3]&&String(id[8])===v[4]);
 store(p+k+"_checks",checks);store(p+k+"_verified",true);store(p+k+"_verified_value",q);
 return{index:i,checks:checks.length,all_pass:true,path:q.path,bytes:q.size,sha256:q.sha256,version:q.version};
}
