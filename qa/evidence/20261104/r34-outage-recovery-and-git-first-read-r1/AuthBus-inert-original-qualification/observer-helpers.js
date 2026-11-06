
function irHelpers(){return eval(load("owner_pure_source")+load("owner_git_source")+";({meta:gitBlobMeta,b64:encodeBase64Bytes,utf8:utf8Bytes,parse:parseLosslessIntegers,decode:unb64,text:utf8Text,fb:fetchVerifiedPublicBlob})");}
async function irLocal(rel,raw){
 if(!/^[A-Za-z0-9_./-]+$/.test(rel)||rel.split("/").some(x=>x===".."))throw Error("localPath");
 const h=irHelpers(),m=h.meta(raw),base="/workspace/scratch/f86faac821c4/authbus_registration_body4_recovery_r1/owner-bound-renew-r1/actual-inert-r1";
 const wrapper=base+"/local-wrappers/"+m.blob+".json",payload=JSON.stringify({text:raw},null,2)+"\n";
 await tools.apply_patch("*** Begin Patch\n*** Add File: "+wrapper+"\n"+payload.split("\n").map(x=>"+"+x).join("\n")+"\n*** End Patch");
 const q=await tools.exec_command({cmd:"python3 - <<'PY'\nfrom pathlib import Path\nimport json,hashlib,os\nw=Path('"+wrapper+"');b=json.loads(w.read_text())['text'].encode();p=Path('"+base+"/"+rel+"');p.parent.mkdir(parents=True,exist_ok=True)\nassert len(b)=="+m.bytes+" and hashlib.sha256(b).hexdigest()=='"+m.sha256+"'\nif p.exists():assert p.read_bytes()==b\nelse:\n with p.open('xb') as f:f.write(b);f.flush();os.fsync(f.fileno())\nwith w.open('rb') as f:os.fsync(f.fileno())\nprint('fsynced')\nPY",workdir:"/tmp",max_output_tokens:100});
 if(q.exit_code!==0){text(q);throw Error("localPersist:"+rel);}
 const rows=load("owner_inert_files")||{};rows[rel]={...m,local:base+"/"+rel};store("owner_inert_files",rows);return m;
}
async function irArchive(rel,raw){
 const m=await irLocal(rel,raw),h=irHelpers();
 const sdk=await tools.mcp__codex_apps__github_create_tree({repository_full_name:"TrillionniumFoundation/HeptaBao",tree_elements:[{path:"original",mode:"100644",type:"blob",content:raw}]});
 const gitRaw=JSON.stringify(sdk,null,2)+"\n";
 await irLocal("archive/"+m.blob+"/create-tree-"+h.meta(gitRaw).blob+".sdk.json",gitRaw);
 if(sdk.isError){store("owner_inert_archive_error",{rel,blob:m.blob,sdk});text({gitError:sdk,rel,pin:m});throw Error("immutableArchiveCreate:"+m.blob);}
 const got=await tools.mcp__codex_apps__github_fetch_blob({repository_full_name:"TrillionniumFoundation/HeptaBao",blob_sha:m.blob});
 const fetchRaw=JSON.stringify(got,null,2)+"\n";
 await irLocal("archive/"+m.blob+"/whole-"+h.meta(fetchRaw).blob+".sdk.json",fetchRaw);
 if(got.isError||got.structuredContent?.content!==raw){store("owner_inert_archive_error",{rel,blob:m.blob,sdk:got});text({gitError:got,rel,pin:m});throw Error("immutableArchiveWhole:"+m.blob);}
 const gm=h.meta(got.structuredContent.content);if(gm.blob!==m.blob||gm.bytes!==m.bytes||gm.sha256!==m.sha256)throw Error("immutableArchiveHash");
 const rows=load("owner_inert_files")||{};rows[rel].wholeGitVerified=true;store("owner_inert_files",rows);return m;
}
async function irCheckpoint(label){
 const value={schema:"heptabao.owner-renew-inert.original-journal.r1",job:load("owner_inert_actual_job"),startCalled:load("owner_inert_start_called")===true,rootGo:"964c58fa1ae491cad2f815362a2381686e64837a",runtimeCallInFlight:load("owner_inert_Runtime_call_inflight")===true,paused:load("owner_inert_paused")===true,observers:load("owner_inert_observers")||{},files:load("owner_inert_files")||{}};
 const raw=JSON.stringify(value,null,2)+"\n",h=irHelpers();return await irLocal("journal/"+label+"-"+h.meta(raw).blob+".json",raw);
}
async function irStartObserver(name,request){
 const h=irHelpers(),state=load("owner_inert_observers")||{};
 if(load("owner_inert_paused")||load("owner_inert_Runtime_call_inflight")||state[name]?.started||Object.values(state).some(x=>x.started&&!x.complete))throw Error("observerAdmission");
 const requestRaw=JSON.stringify(request,null,2)+"\n";
 const requestPin=await irArchive("observations/"+name+"/request.exact.json",requestRaw);
 const intent={schema:"heptabao.owner-renew-inert.original-observer-intent.r1",root_go:"964c58fa1ae491cad2f815362a2381686e64837a",request:requestPin,exact_request:request,original_job:load("owner_inert_actual_job"),lane:"A",maximumNativeAdmissions:1,startNotYetCalled:true,immutablePageLimit:8192};
 const intentPin=await irArchive("observations/"+name+"/intent.original.json",JSON.stringify(intent,null,2)+"\n");
 state[name]={request,requestPin,intentPin,started:false,complete:false,pages:{},pageCalls:{},statusCalls:0};store("owner_inert_observers",state);
 await irCheckpoint(name+"-intent");return {name,request:requestPin,intent:intentPin};
}
async function irAdmitPrepared(name){
 const h=irHelpers(),state=load("owner_inert_observers")||{},r=state[name],base="observations/"+name+"/";
 if(!r||r.started||load("owner_inert_paused")||load("owner_inert_Runtime_call_inflight")||Object.entries(state).some(([n,x])=>n!==name&&x.started&&!x.complete))throw Error("preparedAdmission");
 r.started=true;store("owner_inert_observers",state);await irCheckpoint(name+"-before-start");
 store("owner_inert_Runtime_call_inflight",true);
 const sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_start(r.request);
 store("owner_inert_Runtime_call_inflight",false);store("owner_inert_pending_sdk",{name,stage:"admission",sdk});
 const pin=await irArchive(base+"admission.original.sdk.json",JSON.stringify(sdk,null,2)+"\n");
 if(sdk.isError){store("owner_inert_paused",true);await irCheckpoint(name+"-native-error");text({nativeError:sdk,SDK:pin});return;}
 if(sdk.content?.length!==1||sdk.content[0].type!=="text")throw Error("admissionShape");
 const raw=sdk.content[0].text,np=await irLocal(base+"admission.original.native.txt",raw),v=h.parse(raw);
 if(!/^[0-9a-f]{64}$/.test(v.operation_id)||v.tool_name!==r.request.operation.tool||v.reused!==false||v.automatic_retry!==false)throw Error("admissionIdentity");
 r.operation_id=v.operation_id;r.ackSDK=pin;r.ackNative=np;store("owner_inert_observers",state);await irCheckpoint(name+"-ACK");
 return {name,operation_id:v.operation_id,tool:v.tool_name,SDK:pin,native:np,reused:v.reused,async_state:v.async_state};
}
async function irStatus(name){
 const h=irHelpers(),state=load("owner_inert_observers")||{},r=state[name],i=r?.statusCalls||0,base="observations/"+name+"/status-"+i+"/";
 if(!r?.operation_id||r.futureClosed||load("owner_inert_paused")||load("owner_inert_Runtime_call_inflight"))throw Error("statusAdmission");
 const q={operation_id:r.operation_id};await irArchive(base+"request.exact.json",JSON.stringify(q,null,2)+"\n");
 r.statusCalls=i+1;store("owner_inert_observers",state);await irCheckpoint(name+"-status-"+i+"-before");store("owner_inert_Runtime_call_inflight",true);
 const sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_status(q);
 store("owner_inert_Runtime_call_inflight",false);store("owner_inert_pending_sdk",{name,stage:"status",index:i,sdk});
 const pin=await irArchive(base+"original.sdk.json",JSON.stringify(sdk,null,2)+"\n");
 if(sdk.isError){store("owner_inert_paused",true);await irCheckpoint(name+"-status-error");text({nativeError:sdk,SDK:pin});return;}
 if(sdk.content?.length!==1||sdk.content[0].type!=="text")throw Error("statusShape");
 const raw=sdk.content[0].text,np=await irLocal(base+"original.native.txt",raw),v=h.parse(raw);
 if(v.operation_id!==r.operation_id||v.tool_name!==r.request.operation.tool||v.automatic_retry!==false)throw Error("statusIdentity");
 r.status=v;r.statusSDK=pin;r.statusNative=np;r.futureClosed=v.async_state==="completed"&&v.result_state==="stored_observed"&&v.owned_future_active===false&&v.payload_available===true;store("owner_inert_observers",state);await irCheckpoint(name+"-status-"+i+"-after");
 return {name,operation_id:r.operation_id,async_state:v.async_state,result_state:v.result_state,owned_future_active:v.owned_future_active,payload_available:v.payload_available,futureClosed:r.futureClosed,SDK:pin,native:np};
}
async function irPage(name,offset){
 const h=irHelpers(),state=load("owner_inert_observers")||{},r=state[name],base="observations/"+name+"/pages/"+String(offset).padStart(6,"0")+"/";
 if(!r?.futureClosed||r.complete||r.pages[offset]||r.pageCalls[offset]||load("owner_inert_paused")||load("owner_inert_Runtime_call_inflight"))throw Error("pageAdmission");
 const q={operation_id:r.operation_id,offset,limit:8192};await irArchive(base+"request.exact.json",JSON.stringify(q,null,2)+"\n");
 r.pageCalls[offset]=true;store("owner_inert_observers",state);await irCheckpoint(name+"-page-"+offset+"-before");store("owner_inert_Runtime_call_inflight",true);
 const sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_result(q);
 store("owner_inert_Runtime_call_inflight",false);store("owner_inert_pending_sdk",{name,stage:"page",offset,sdk});
 const pin=await irArchive(base+"original.sdk.json",JSON.stringify(sdk,null,2)+"\n");
 if(sdk.isError){store("owner_inert_paused",true);await irCheckpoint(name+"-page-error");text({nativeError:sdk,SDK:pin});return;}
 if(sdk.content?.length!==1||sdk.content[0].type!=="text")throw Error("pageShape");
 const raw=sdk.content[0].text,np=await irLocal(base+"original.native.txt",raw),v=h.parse(raw);
 if(v.operation_id!==r.operation_id||v.offset!==offset||v.immutable_snapshot!==true||v.payload_kind!=="native_result"||v.format!=="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization"||!Number.isSafeInteger(v.total_bytes)||v.total_bytes<0||v.total_bytes>1048576||!/^[a-f0-9]{64}$/.test(v.result_sha256))throw Error("pageIdentity");
 const bytes=h.decode(v.data_base64);if(bytes.length>8192||v.next_offset!==offset+bytes.length||v.next_offset>v.total_bytes||v.eof!==(v.next_offset===v.total_bytes)||(!bytes.length&&!v.eof))throw Error("pageExtent");
 if(r.total!==undefined&&(r.total!==v.total_bytes||r.digest!==v.result_sha256))throw Error("payloadIdentity");
 r.total=v.total_bytes;r.digest=v.result_sha256;r.pages[offset]={offset,next:v.next_offset,eof:v.eof,bytes:bytes.length,SDK:pin,native:np,base64:v.data_base64};store("owner_inert_observers",state);await irCheckpoint(name+"-page-"+offset+"-after");
 return {name,offset,next:v.next_offset,total:r.total,eof:v.eof,SDK:pin,native:np};
}
async function irClose(name){
 const h=irHelpers(),state=load("owner_inert_observers")||{},r=state[name],base="observations/"+name+"/";
 if(!r?.futureClosed||r.complete||load("owner_inert_paused")||load("owner_inert_Runtime_call_inflight"))throw Error("closeBoundary");
 const pages=Object.values(r.pages).sort((a,b)=>a.offset-b.offset);let off=0,bytes=[];
 for(const p of pages){if(p.offset!==off)throw Error("pageGap");bytes=bytes.concat(h.decode(p.base64));off=p.next;}
 if(off!==r.total||!pages.at(-1)?.eof)throw Error("missingEOF");
 const raw=h.text(bytes),m=h.meta(raw);if(m.bytes!==r.total||m.sha256!==r.digest)throw Error("originalPayloadHash");
 const pp=await irArchive(base+"payload.original.json",raw),p=h.parse(raw);
 if(p.resultType!=="complete"||p.isError!==false||p.content?.length!==1||p.content[0].type!=="text")throw Error("nativePayloadFailure");
 const nativeRaw=p.content[0].text,np=await irArchive(base+"native.original.json",nativeRaw),native=h.parse(nativeRaw);
 r.payloadPin=pp;r.nativePin=np;r.native=native;r.nativeRaw=nativeRaw;r.complete=true;delete r.pages;store("owner_inert_observers",state);await irCheckpoint(name+"-closed");
 return {name,operation_id:r.operation_id,complete:true,pages:pages.length,payload:pp,native:np,value:native};
}
