async function takeOneOriginalH2Page(label,tools,store,load) {
 const p="ha_h2_metadata5_actual_r1_",k="ha_h2_stage_execution_r1_";
 if(!/^streams[01]-page-[0-9]{6}$/.test(label))throw Error("fixed page label required");
 const stream=label.split("-page-")[0];
 const H=new Function("tools","store","load",load(p+"pure_helpers")+"\n"+load(p+"git_helpers")+"\nreturn {save:saveVerifiedPublicBlobJournaled,meta:gitBlobMeta,lossless:parseLosslessIntegers,unb64,fromUtf8:utf8Text};")(tools,store,load);
 const req=load(k+label+"_request");
 if(!req||!load(k+label+"_intent_pin")||load(k+label+"_submitted")||!load(k+stream+"_observer_closed")||load(k+"execution_state").halted)throw Error("page guard");
 const prior=load(k+stream+"_pages")||[];
 const last=prior.length?load(k+prior[prior.length-1]+"_native"):null;
 if(req.operation_id!==load(k+stream+"_operation_id")||req.limit!==8192||req.offset!==(last?last.next_offset:0))throw Error("fixed original ID/range");
 store(k+label+"_submitted",true);store(k+"execution_state",{...load(k+"execution_state"),current_read_call_inflight:true,current_query:label});
 let sdk;try{sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_result(req);}catch(e){sdk={local_transport_exception:true,error:String(e),name:e?.name??null};}
 store(k+label+"_sdk",sdk);store(k+"execution_state",{...load(k+"execution_state"),current_read_call_inflight:false});
 const txt=JSON.stringify(sdk,null,2)+"\n",path="/workspace/scratch/f86faac821c4/r32_recovery/ha-h2-stage-"+label+"-sdk-fsynced.json",wrapper=JSON.stringify({text:txt},null,2)+"\n";
 await tools.apply_patch("*** Begin Patch\n*** Add File: "+path+"\n"+wrapper.split("\n").map(x=>"+"+x).join("\n")+"\n*** End Patch");
 const fs=await tools.exec_command({cmd:"python3 - <<'PY'\nimport os\np='"+path+"'\nf=os.open(p,os.O_RDONLY)\ntry: os.fsync(f)\nfinally: os.close(f)\nd=os.open(os.path.dirname(p),os.O_RDONLY|os.O_DIRECTORY)\ntry: os.fsync(d)\nfinally: os.close(d)\nprint('SDK fsynced')\nPY",max_output_tokens:100});
 store(k+label+"_local_fsync",fs);if(fs.exit_code!==0)throw Error("fsync failed");
 const sp=await H.save("ha-h2-stage-"+label+"-sdk",txt);store(k+label+"_sdk_pin",sp);
 if(sdk.isError||sdk.local_transport_exception){store(k+"execution_state",{...load(k+"execution_state"),halted:true,reason:label+" error"});return{sdk:sp,error:sdk};}
 const ts=(sdk.content||[]).filter(x=>x.type==="text");if(ts.length!==1)throw Error("native text count");
 const np=await H.save("ha-h2-stage-"+label+"-native",ts[0].text);store(k+label+"_native_pin",np);
 const n=H.lossless(ts[0].text);store(k+label+"_native",n);
 const b=H.unb64(n.data_base64);
 if(n.operation_id!==req.operation_id||n.offset!==req.offset||n.immutable_snapshot!==true||n.next_offset!==req.offset+b.length||b.length!==Math.min(8192,n.total_bytes-req.offset)||n.eof!==(n.next_offset===n.total_bytes))throw Error("page identity/range/EOF");
 if(last&&(n.total_bytes!==last.total_bytes||n.result_sha256!==last.result_sha256))throw Error("original payload changed");
 store(k+stream+"_pages",[...prior,label]);
 return {sdk:sp,page:np,offset:n.offset,next_offset:n.next_offset,total_bytes:n.total_bytes,eof:n.eof,result_sha256:n.result_sha256};
}