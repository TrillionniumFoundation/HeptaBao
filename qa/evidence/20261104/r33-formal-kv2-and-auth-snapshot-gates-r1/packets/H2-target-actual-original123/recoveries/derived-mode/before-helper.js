
const P="ha_h2_target_reads_r2_";
const H=new Function("tools","store","load",load("ha_h2_metadata5_actual_r1_pure_helpers")+"\n"+load("ha_h2_metadata5_actual_r1_git_helpers")+"\nreturn {save:saveVerifiedPublicBlobJournaled,fb:fetchVerifiedPublicBlob,meta:gitBlobMeta,lossless:parseLosslessIntegers,persist:persistRecoveryText,unb64,fromUtf8:utf8Text,utf8:utf8Bytes};")(tools,store,load);
async function journal() {
 const s=load(P+"state"); await H.persist("ha-h2-target-reads-r2-state",JSON.stringify(s,null,2)+"\n"); return s;
}
async function prepare(label,phase,method,args,reference={}) {
 const s=load(P+"state");
 if(s.paused || s.inflight)throw Error("line paused or inflight");
 if(method==="operation_start" && s.active_operation)throw Error("original observer not closed");
 if(!["operation_start","operation_status","operation_result"].includes(method))throw Error("scope");
 if(method==="operation_result" && args.limit!==8192)throw Error("page cap");
 if(s.calls[label+"."+phase])throw Error("original call already prepared");
 const reqText=JSON.stringify(args,null,2)+"\n";
 const reqPin=await H.save("ha-h2-target-"+label+"-"+phase+"-request",reqText);
 const intent={schema:"heptabao.H2-target-read.exact-call-intent.v1",root_GO:"012b76fca8a176e1cc15e3115ad38a69977ef8d9",lane:"A",label,phase,method,request:reqPin,arguments:args,reference,previous_whole_closed:s.last_closed||null,only_readonly:true,stage_replay:false,prepare_or_live:false,one_future_per_lane:true};
 const pin=await H.save("ha-h2-target-"+label+"-"+phase+"-intent",JSON.stringify(intent,null,2)+"\n");
 s.calls[label+"."+phase]={label,phase,method,args,request:reqPin,intent:pin,submitted:false};
 if(method==="operation_start")s.observations[label]={request:args,request_pin:reqPin,intent_pin:pin,pages:[]};
 store(P+"state",s);await journal();return {request:reqPin,intent:pin};
}
async function call(label,phase) {
 let s=load(P+"state");const c=s.calls[label+"."+phase];
 if(!c||c.submitted||s.paused||s.inflight)throw Error("call gate");
 c.submitted="invoking-possible-submitted";s.inflight={label,phase,method:c.method,args:c.args};store(P+"state",s);await journal();
 let sdk;
 try {sdk=await tools["mcp__codex_apps__heptaruntime_mac_controller_"+c.method](c.args);}
 catch(e){sdk={local_transport_exception:true,name:e&&e.name||null,error:String(e)};}
 store(P+label+"."+phase+".rawSDK",sdk);
 s=load(P+"state");s.inflight=null;c.returned=true;c.submitted=true;store(P+"state",s);
 const raw=JSON.stringify(sdk,null,2)+"\n";
 const file="/workspace/scratch/f86faac821c4/r32_recovery/ha-h2-target-"+label+"-"+phase+"-sdk-fsynced.json";
 const wrapper=JSON.stringify({text:raw},null,2)+"\n";
 const patch="*** Begin Patch\n*** Add File: "+file+"\n"+wrapper.split("\n").map(x=>"+"+x).join("\n")+"\n*** End Patch";
 const wr=await tools.apply_patch(patch);
 const sync=await tools.exec_command({cmd:"python3 - <<'PY'\nimport os\np='"+file+"'\nf=os.open(p,os.O_RDONLY)\nos.fsync(f)\nos.close(f)\nf=os.open(os.path.dirname(p),os.O_RDONLY|os.O_DIRECTORY)\nos.fsync(f)\nos.close(f)\nPY",max_output_tokens:1000});
 if(sync.exit_code!==0)throw Error("raw SDK fsync failed; use same raw object, no Runtime repeat");
 c.sdk=await H.save("ha-h2-target-"+label+"-"+phase+"-SDK",raw);
 s=load(P+"state");s.calls[label+"."+phase]=c;store(P+"state",s);await journal();
 if(sdk.isError||sdk.local_transport_exception){
   s.paused=true;s.error={label,phase,sdk:c.sdk};store(P+"state",s);await journal();return {stopped:true,sdk:c.sdk,error:sdk};
 }
 if(!Array.isArray(sdk.content)||sdk.content.length!==1||sdk.content[0].type!=="text")throw Error("unexpected SDK format");
 const rawNative=sdk.content[0].text;
 c.native=await H.save("ha-h2-target-"+label+"-"+phase+"-native",rawNative);
 const n=H.lossless(rawNative);c.value=n;
 s=load(P+"state");s.calls[label+"."+phase]=c;
 const o=s.observations[label];
 if(c.method==="operation_start"){
   if(typeof n.operation_id!=="string" || n.tool_name!==o.request.operation.tool)throw Error("ACK binding mismatch");
   o.admission=n;o.admission_pin=c.native;o.admission_sdk=c.sdk;s.active_operation=n.operation_id;
 } else if(c.method==="operation_status"){
   if(n.operation_id!==o.admission.operation_id || n.tool_name!==o.request.operation.tool)throw Error("status ID/tool mismatch");
   o.status=n;o.status_pin=c.native;o.status_sdk=c.sdk;
 } else {o.pages.push({request:c.args,request_pin:c.request,intent_pin:c.intent,sdk_pin:c.sdk,native_pin:c.native,value:n});}
 store(P+"state",s);await journal();return {sdk:c.sdk,native:c.native,value:n};
}

async function closeObserver(label) {
 let s=load(P+"state"); const o=s.observations[label];
 if(!o || s.inflight || !o.status || o.status.async_state!=="completed" || o.status.result_state!=="stored_observed" || o.status.owned_future_active!==false || o.status.payload_available!==true)throw Error("closure gate");
 let offset=0,total=null,sha=null,all=[];
 for(let i=0;i<o.pages.length;i++){
   const p=o.pages[i],n=p.value,bs=H.unb64(n.data_base64);
   if(n.operation_id!==o.admission.operation_id || p.request.operation_id!==n.operation_id || p.request.offset!==offset || p.request.limit!==8192 || n.offset!==offset || n.next_offset!==offset+bs.length || bs.length>8192 || n.immutable_snapshot!==true || n.payload_kind!=="native_result")throw Error("page range/binding");
   if(i===0){total=n.total_bytes;sha=n.result_sha256;}
   if(n.total_bytes!==total || n.result_sha256!==sha || n.eof!==(n.next_offset===total))throw Error("page whole/EOF");
   all.push(...bs);offset=n.next_offset;
 }
 if(!all.length || offset!==total || o.pages.at(-1).value.eof!==true)throw Error("incomplete payload");
 const raw=H.fromUtf8(all);
 if(H.meta(raw).bytes!==total || H.meta(raw).sha256!==sha)throw Error("whole payload digest");
 o.payload_pin=await H.save("ha-h2-target-"+label+"-payload-original",raw);
 const payload=H.lossless(raw);
 if(payload.isError || payload.resultType!=="complete" || !Array.isArray(payload.content) || payload.content.length!==1 || payload.content[0].type!=="text"){s.paused=true;store(P+"state",s);await journal();throw Error("original payload error or unexpected shape");}
 const nativeText=payload.content[0].text;
 o.native_pin=await H.save("ha-h2-target-"+label+"-result-native-original",nativeText);
 o.native=H.lossless(nativeText);
 o.original_payload_verified_whole=true;
 if(o.request.operation.tool==="file_info"){
   const cfg=JSON.parse(load(P+"blob_69db067f16796f8ad85f8f73b0355c2f14707120").text);
   const ex=cfg.expected[label==="receipt-info"?0:1],n=o.native,md=n.metadata;
   if(n.path!==ex.path || n.size!==ex.bytes || n.sha256!==ex.sha256 || n.mode!==384 || md.mode!==384 || md.uid!==1000 || md.gid!==1000 || md.link_count!==1 || md.metadata_platform!=="linux")throw Error("file_info content/identity mismatch");
   if(!/^(?:0|[1-9][0-9]*)(?::(?:0|[1-9][0-9]*)){4}$/.test(n.version))throw Error("version format");
   const v=n.version.split(":");if(Number(v[2])!==n.size||BigInt(v[0])<=0n||BigInt(v[1])<=0n)throw Error("version fields");
   if(ex.role==="binding" && n.version!==ex.expected_stage_writer_version)throw Error("binding writer full9/version changed");
   o.full9={device:v[0],inode:v[1],uid:md.uid,gid:md.gid,full_mode:33152+n.mode,links:md.link_count,bytes:n.size,mtime_ns:v[3],ctime_ns:v[4],version:n.version};
   o.info=n;
 }
 o.closed=true;
 if(s.active_operation!==o.admission.operation_id)throw Error("active ID mismatch");
 s.active_operation=null;s.last_closed={label,operation_id:o.admission.operation_id,status:o.status_pin,payload:o.payload_pin,native:o.native_pin,whole:true};
 store(P+"state",s);await journal();
 return {label,operation_id:o.admission.operation_id,payload:o.payload_pin,native:o.native_pin,info:o.info||null,full9:o.full9||null,pages:o.pages.length};
}

return {H,prepare,call,journal,closeObserver};
