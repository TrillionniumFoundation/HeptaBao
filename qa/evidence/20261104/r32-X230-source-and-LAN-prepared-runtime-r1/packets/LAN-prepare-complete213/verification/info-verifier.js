function(prefix,index){
 const name="output"+index+"_info",spec=load(prefix+"output_specs")[index],q=eval("("+load("ha_helper_reconstructed_r1_lossless_json")+")")(load(prefix+name+"_native_text_r1")),checks=[];
 const ck=(name,v)=>{checks.push({name,pass:!!v});if(!v){store(prefix+"output"+index+"_info_check_failure",checks);throw Error(name);}};
 ck("original observation closed/full",load(prefix+name+"_complete_r1")===true&&load(prefix+name+"_closed_status_r1")?.owned_future_active===false);
 ck("fixed output path",q.path===spec.path);
 ck("whole file bytes/SHA",q.size===spec.expected_bytes&&q.sha256===spec.expected_sha256);
 ck("lossless version",typeof q.version==="string"&&/^[0-9]+(:[0-9]+){4}$/.test(q.version)&&q.version.split(":")[2]===String(q.size));
 ck("owner/group/mode/single-link",q.metadata?.uid===1000&&q.metadata?.gid===1000&&q.metadata?.mode===384&&q.metadata?.link_count===1);
 const v=q.version.split(":"),value={...q,full9_decimal:[v[0],v[1],"1000","1000","33152","1",String(q.size),v[3],v[4]],full9_origin:"device/inode/size/mtime_ns/ctime_ns from original version; uid/gid/mode/nlink from original metadata; regular file from file_info contract",original_operation_id:load(prefix+name+"_operation_id_r1")};
 store(prefix+"output"+index+"_info_value",value);store(prefix+"output"+index+"_info_checks",checks);store(prefix+"output"+index+"_info_verified",true);
 return{index,path:q.path,size:q.size,sha256:q.sha256,version:q.version,checks:checks.length,closed:true};
}
