function(prefix,index){
 const name="output"+index+"_body0",spec=load(prefix+"output_specs")[index],info=load(prefix+"output"+index+"_info_value"),q=eval("("+load("ha_helper_reconstructed_r1_lossless_json")+")")(load(prefix+name+"_native_text_r1")),dec=eval("("+load("ha_helper_reconstructed_r1_b64decode")+")"),h=eval("("+load("ha_helper_reconstructed_r1_sha256")+")"),s1=eval("("+load("ha_helper_reconstructed_r1_sha1")+")"),u=eval("("+load("ha_helper_reconstructed_r1_utf8")+")"),checks=[];
 const ck=(name,v)=>{checks.push({name,pass:!!v});if(!v){store(prefix+"output"+index+"_body_check_failure",checks);throw Error(name);}};
 ck("body original operation closed/full",load(prefix+name+"_complete_r1")===true&&load(prefix+name+"_closed_status_r1")?.owned_future_active===false);
 ck("independent info already verified",load(prefix+"output"+index+"_info_verified")===true);
 const b=dec(q.data_base64),sha=h(b);
 ck("fixed path/version/size",q.path===spec.path&&q.version===info.version&&q.size===info.size);
 ck("whole single bounded chunk",q.offset===0&&q.next_offset===b.length&&q.eof===true&&b.length===info.size&&b.length<=65536);
 ck("chunk + independent whole SHA",q.chunk_sha256===sha&&sha===info.sha256&&sha===spec.expected_sha256);
 const t=decodeURIComponent([...b].map(c=>"%"+c.charCodeAt(0).toString(16).padStart(2,"0")).join(""));
 ck("UTF8 bytes roundtrip",u(t)===b);
 const blob=s1("blob "+b.length+"\0"+b);
 if(spec.qualified_blob)ck("exact prior qualified public receipt Git blob",blob===spec.qualified_blob);
 const value=eval("("+load("ha_helper_reconstructed_r1_lossless_json")+")")(t);
 store(prefix+"output"+index+"_binary",b);store(prefix+"output"+index+"_text",t);store(prefix+"output"+index+"_value",value);store(prefix+"output"+index+"_pin",{blob,bytes:b.length,sha256:sha});store(prefix+"output"+index+"_body_checks",checks);store(prefix+"output"+index+"_body_verified",true);
 return{index,path:spec.path,bytes:b.length,sha256:sha,blob,version:info.version,checks:checks.length,closed:true};
}
