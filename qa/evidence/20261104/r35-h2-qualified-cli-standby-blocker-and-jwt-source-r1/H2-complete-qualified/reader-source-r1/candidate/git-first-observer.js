
function lh(){return hlH();}
const H2_REMAINING_BODY_REQUESTS=[
  {
    "offset": 65536,
    "limit": 65536,
    "blob": "97fa10f7aa705b265fe0bfa6b1f5a01b7d30c3b4",
    "bytes": 438,
    "sha256": "08e2c3baa4e3bae7a65a6e1a2acf83f785764b4084b631fa7eb43d62228737c5"
  },
  {
    "offset": 131072,
    "limit": 65536,
    "blob": "e45ec9bc5421e6c6ef1a91e5bba2cf5d8ac22a0f",
    "bytes": 440,
    "sha256": "86f2111c36f8d38f9d81817787b3c61bfafe36b19b7ff103506547cf4a9dccdc"
  },
  {
    "offset": 196608,
    "limit": 65536,
    "blob": "3dbb58645a1ccf4bc4573373b0aa9e170ab39c4f",
    "bytes": 440,
    "sha256": "b09def7abee32c9a014bd25f74b90747aa4d493e7ea883d9ac9d6001ac4c6b41"
  },
  {
    "offset": 262144,
    "limit": 65536,
    "blob": "2780c676c0d0fbb9ec30dfe1d8ebff149a09c763",
    "bytes": 440,
    "sha256": "08a5c6fe858ec479bd379330507c20d2ce714bed1122c5b82cfaeb42ad89f6b1"
  },
  {
    "offset": 327680,
    "limit": 65536,
    "blob": "e7bc24ca34853e1b47ca7cdc035a64a64f3bcdbf",
    "bytes": 440,
    "sha256": "7811cb921a12e67f10d2bc28aaca6018abc8b2dd7c21754e720ef62eb6d60bca"
  },
  {
    "offset": 393216,
    "limit": 65536,
    "blob": "32e1d307aee89492fe94faf73eb410d10b446a54",
    "bytes": 440,
    "sha256": "4a185faba57b528d343fc29471640b53467a3311c7961ef39c696dad940de802"
  },
  {
    "offset": 458752,
    "limit": 6818,
    "blob": "b20329116b397801a1834f2348d582fc92d15a93",
    "bytes": 439,
    "sha256": "574ba5639b6055626148fd39b88a76c0f8928ff1bd16bb41780f415b6dea57f8"
  }
];
async function ll(name,text){return await hlArchive(name,text);}
function lt(p){const x=load("h2_live_local_text_"+p.blob);if(typeof x!=="string"||hlH().meta(x).blob!==p.blob)throw Error("recover_exact_Git_blob_without_Runtime:"+p.blob);return x;}
async function lp(label,tool,q){
 const s=load("h2_live_execution_state");
 if(s.halted||s.Runtime_call_inflight||s.pending_call||s.calls.some(x=>x.label===label)||load("h2_live_git_first_archive_blocked")||!s.git_first_protocol_GO||!s.git_first_bootstrap)throw Error("live_call_state");
 if(!["operation_start","operation_status","operation_result"].includes(tool))throw Error("readonly_tool_only");
 if(tool==="operation_start"){
  if(!s.ACK_binding_verified||s.active_operation_id||s.observations.some(o=>!o.archived))throw Error("previous_observer_not_archived");
  const op=q.operation,a=op.arguments;if(a.host!=="desktop")throw Error("host_gate");
  if(op.tool!=="binary_read")throw Error("remaining_public_binary_only");
  const m=s.result_file_info,off=s.result_body_next_offset,fixed=H2_REMAINING_BODY_REQUESTS.find(x=>x.offset===off),raw=JSON.stringify(q,null,2)+"\n",pin=lh().meta(raw);
  if(!fixed||!s.result_metadata_verified||a.path!=="/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-native-h2-gate-live-r2/result.public.json"||m.size!==465570||m.sha256!=="6b51bc97ea77b2574eab86ddee638c69818773d54211c25bcb8a018c02ca107e"||a.expected_version!=="2050:7876768:465570:1793928419424368582:1793928419424368582"||a.offset!==off||s.body_offsets_admitted.includes(off)||a.limit!==fixed.limit||pin.blob!==fixed.blob||pin.bytes!==fixed.bytes||pin.sha256!==fixed.sha256)throw Error("fixed_remaining_range_gate");
 }else{
  const o=s.observations.at(-1);if(!o||o.operation_id!==s.active_operation_id||q.operation_id!==o.operation_id||o.closed)throw Error("same_original_operation_gate");
  if(tool==="operation_result"&&(!o.native_handler_closed||q.offset!==(o.next_offset??0)||q.limit!==(o.page_width??8192)))throw Error("original_page_gate");
 }
 const request=await ll("h2-live-"+label+"-request",JSON.stringify(q,null,2)+"\n");
 const intent=await ll("h2-live-"+label+"-intent",JSON.stringify({schema:"heptabao.h2-live.original-readonly-intent.v1",GO:s.GO,job_id:s.job_id,label,tool,request,Runtime_submitted:false,one_future:true,original_SDK_external_before_parse:true,Git_first_protocol_GO:s.git_first_protocol_GO},null,2)+"\n");
 s.pending_call={label,tool,request,intent,request_text:JSON.stringify(q,null,2)+"\n",submitted:false,Git_first_protocol_GO:s.git_first_protocol_GO};await hlState(s);text({prepared:label,request,intent,Runtime_submitted:false});
}
async function ls(){
 const s=load("h2_live_execution_state"),p=s.pending_call;
 if(!p||p.submitted||s.Runtime_call_inflight||s.halted||load("h2_live_git_first_archive_blocked")||!s.git_first_protocol_GO||p.Git_first_protocol_GO?.blob!==s.git_first_protocol_GO.blob)throw Error("single_readonly_submit_gate");
 const names={operation_start:"mcp__codex_apps__heptaruntime_mac_controller_operation_start",operation_status:"mcp__codex_apps__heptaruntime_mac_controller_operation_status",operation_result:"mcp__codex_apps__heptaruntime_mac_controller_operation_result"};
 if(!names[p.tool])throw Error("closed_readonly_tool_set");
 const q=JSON.parse(p.request_text);p.submitted=true;s.Runtime_call_inflight=true;await hlState(s);
 let sdk;try{sdk=await tools[names[p.tool]](q);}catch(e){sdk={local_transport_exception:true,name:e?.name??"Error",message:String(e)};}
 const raw=JSON.stringify(sdk,null,2)+"\n";
 store("h2_live_git_first_returned",{label:p.label,request_blob:p.request.blob,raw,raw_pin:lh().meta(raw),Native_tool_returned:true,processed:false});
 s.Runtime_call_inflight=false;store("h2_live_git_first_state_shadow",s);
 return await lc(s,p,raw);
}
async function lc(s,p,raw){
 const sp=await ll("h2-live-"+p.label+"-original-SDK",raw);
 // No Native SDK isError, content selection, or JSON parse precedes the above exact external whole readback.
 const sdk=JSON.parse(raw),q=JSON.parse(p.request_text);
 const out={...p,SDK:sp,isError:sdk.isError===true,local_transport_exception:sdk.local_transport_exception===true};let n=null;
 if(!out.local_transport_exception&&sdk.content?.length===1&&sdk.content[0].type==="text"){out.native=await ll("h2-live-"+p.label+"-original-native",sdk.content[0].text);if(!out.isError){try{n=lh().lossless(sdk.content[0].text);}catch(e){out.parse_error=String(e);}}}
 else if(!out.local_transport_exception)out.parse_error="unexpected_SDK_shape";
 s.Runtime_call_inflight=false;s.pending_call=null;s.calls.push(out);s.last_call=out;s.last_result=n;
 if(out.isError||out.local_transport_exception||out.parse_error)s.halted=true;
 if(p.tool==="operation_start"&&!s.halted){
  if(typeof n?.operation_id!=="string"||n.tool_name!=="binary_read"){s.halted=true;await hlState(s);throw Error("preserved_admission_shape");}
  s.active_operation_id=n.operation_id;s.observations.push({name:p.label.replace(/-admission$/,""),operation_id:n.operation_id,tool:"binary_read",arguments:q.operation.arguments,admission:out,page_width:16384,page_width_amendment:s.page_width_amendment,Git_first_protocol_GO:s.git_first_protocol_GO,status_calls:[],pages:[],closed:false,archived:false});
  s.body_offsets_admitted.push(q.operation.arguments.offset);
 }
 await hlState(s);store("h2_live_git_first_returned",null);
 text({label:p.label,SDK:sp,native:out.native,isError:out.isError,transport_exception:out.local_transport_exception,result:p.tool==="operation_result"?{operation_id:n?.operation_id,offset:n?.offset,next_offset:n?.next_offset,total_bytes:n?.total_bytes,eof:n?.eof}:n});
}
async function lr(){
 const s=load("h2_live_execution_state"),r=load("h2_live_git_first_returned"),p=s.pending_call;
 if(load("h2_live_git_first_archive_blocked")||!r?.Native_tool_returned||r.processed||!p?.submitted||p.label!==r.label||p.request.blob!==r.request_blob||s.Runtime_call_inflight||lh().meta(r.raw).blob!==r.raw_pin.blob)throw Error("same_returned_SDK_only");
 return await lc(s,p,r.raw);
}
async function laStatus(){
 const s=load("h2_live_execution_state"),n=s.last_result,o=s.observations.at(-1);
 if(s.halted||s.last_call.tool!=="operation_status"||n.operation_id!==o.operation_id||n.tool_name!==o.tool)throw Error("original_status_binding");
 o.status_calls.push(s.last_call);o.status=s.last_call;
 o.native_handler_closed=n.async_state==="completed"&&n.result_state==="stored_observed"&&n.owned_future_active===false&&n.payload_available===true;
 await hlState(s);text({operation_id:o.operation_id,native_handler_closed:o.native_handler_closed,async_state:n.async_state,result_state:n.result_state,owned_future_active:n.owned_future_active});return o;
}
async function laPage(){
 const s=load("h2_live_execution_state"),o=s.observations.at(-1),n=s.last_result,H=lh();
 if(s.halted||!o.native_handler_closed||s.last_call.tool!=="operation_result")throw Error("page_state");
 const b=H.unb64(n.data_base64),off=o.next_offset??0;
 if(n.operation_id!==o.operation_id||n.offset!==off||n.next_offset!==off+b.length||n.immutable_snapshot!==true||n.payload_kind!=="native_result"||!Number.isSafeInteger(n.total_bytes)||n.total_bytes>1048576||b.length!==Math.min(o.page_width??8192,n.total_bytes-off)||n.eof!==(n.next_offset===n.total_bytes))throw Error("page_geometry");
 if(o.payload_sha256&&o.payload_sha256!==n.result_sha256||o.payload_bytes&&o.payload_bytes!==n.total_bytes)throw Error("immutable_payload_drift");
 o.payload_sha256=n.result_sha256;o.payload_bytes=n.total_bytes;o.next_offset=n.next_offset;o.pages_complete=n.eof;
 o.pages.push({call:s.last_call,offset:n.offset,next_offset:n.next_offset,total_bytes:n.total_bytes,result_sha256:n.result_sha256,eof:n.eof});
 await hlState(s);text({operation_id:o.operation_id,pages:o.pages.length,next_offset:o.next_offset,total_bytes:o.payload_bytes,eof:o.pages_complete});return o;
}
async function lf(){
 const s=load("h2_live_execution_state"),o=s.observations.at(-1),H=lh();
 if(!o.native_handler_closed||!o.pages_complete||s.pending_call||s.Runtime_call_inflight||s.halted)throw Error("observer_finalize_gate");
 const bytes=new Uint8Array(o.payload_bytes);let off=0;
 for(const p of o.pages){const n=H.lossless(lt(p.call.native)),b=H.unb64(n.data_base64);if(n.offset!==off)throw Error("page_reassembly_order");bytes.set(b,off);off+=b.length;}
 const raw=H.utf8Text(bytes);if(off!==o.payload_bytes||H.sha256Latin1(H.byteString(bytes))!==o.payload_sha256||H.meta(raw).sha256!==o.payload_sha256)throw Error("whole_original_payload_hash");
 o.payload=await ll("h2-live-"+o.name+"-payload-original",raw);
 const sdk=JSON.parse(raw);o.payload_isError=sdk.isError===true;
 if(sdk.content?.length!==1||sdk.content[0].type!=="text")throw Error("original_payload_shape_preserved");
 o.native=await ll("h2-live-"+o.name+"-native-original",sdk.content[0].text);
 let n=null;if(!o.payload_isError)n=H.lossless(sdk.content[0].text);
 store("h2_live_observation_native_"+o.operation_id,n);o.closed=true;s.active_operation_id=null;if(o.payload_isError)s.halted=true;
 await hlState(s);
 const entries=[],add=(path,p)=>entries.push({path,...p}),call=(prefix,c)=>{add(prefix+"/request.json",c.request);add(prefix+"/intent.json",c.intent);add(prefix+"/original.sdk.json",c.SDK);if(c.native)add(prefix+"/original.native.json",c.native);};
 call("admission",o.admission);o.status_calls.forEach((c,i)=>call("status/"+String(i).padStart(3,"0"),c));o.pages.forEach(p=>call("pages/"+String(p.offset).padStart(6,"0"),p.call));add("payload.original.sdk.json",o.payload);add("payload.original.native.json",o.native);
 const manifest={schema:"heptabao.h2-live.one-original-observer.v1",GO:s.GO,job_id:s.job_id,name:o.name,operation_id:o.operation_id,tool:o.tool,arguments:o.arguments,native_handler_closed:o.native_handler_closed,payload_isError:o.payload_isError,closed:o.closed,pages:o.pages.length,page_width:o.page_width??8192,page_width_amendment:o.page_width_amendment??null,payload_sha256:o.payload_sha256,payload_bytes:o.payload_bytes,entries:entries.map(({path,blob,bytes,sha256,local_json})=>({path,blob,bytes,sha256,local_json}))};
 const mr=JSON.stringify(manifest,null,2)+"\n",mp=await ll("h2-live-"+o.name+"-observer-manifest",mr);add("MANIFEST.public.json",mp);
 const archive=await hgArchive(entries.map(p=>({path:p.path,text:lt(p)})),"observer:"+o.name);
 o.archive={...archive,manifest:mp};o.archived=true;s.last_closed_observer=o.name;
 store("h2_live_observer_entries_"+o.name,entries);await hlState(s);
 text({observer:o.name,operation_id:o.operation_id,tool:o.tool,closed:true,archived:true,pages:o.pages.length,payload:o.payload,native:o.native,archive:o.archive,native_keys:n?Object.keys(n):null});
 return o;
}

async function hgBootstrap(protocolGO){
 const s=load("h2_live_execution_state");
 if(s.Runtime_call_inflight||s.pending_call||s.active_operation_id||s.observations.length!==4||s.observations.some(o=>!o.closed||!o.archived)||s.body_offsets_admitted.length!==1||s.body_offsets_admitted[0]!==0||s.job_id!=="1a1ae76aacd-fc05-5fb4"||!s.authority_definitive||!s.original_streams_complete||!s.public_result_pointer_verified||!s.result_metadata_verified||s.git_first_bootstrap)throw Error("exact_closed_recovery_boundary");
 if(!protocolGO||!/^[0-9a-f]{40}$/.test(protocolGO.blob)||protocolGO.blob===s.GO.blob||!Number.isSafeInteger(protocolGO.bytes)||protocolGO.bytes<1||!/^[0-9a-f]{64}$/.test(protocolGO.sha256))throw Error("new_explicit_root_GO_required");
 const go=await hgBlob(protocolGO),body=await hgBlob({blob:"402c5c221b7d26afbf95c08656c0a86362e3ffee",bytes:87717,sha256:"c8bbcab41341310f342af3576d852707d5a1722c22bebe0e181348749d358bb0"}),info=await hgBlob({blob:"a6cd5b8b680504180763085574676fa6febfe592",bytes:482,sha256:"3ddd7c3ae88b2597519936742db7c5c4e840be607439df8ca983eeca44945203"});
 const n=lh().lossless(body.text),m=lh().lossless(info.text),b=lh().unb64(n.data_base64),o=s.observations.find(x=>x.name==="result-body-000000");
 if(!o||o.native.blob!==body.blob||n.offset!==0||b.length!==65536||n.next_offset!==65536||n.eof!==false||n.path!==m.path||n.version!==m.version||m.version!=="2050:7876768:465570:1793928419424368582:1793928419424368582"||n.size!==465570||m.size!==465570||m.sha256!=="6b51bc97ea77b2574eab86ddee638c69818773d54211c25bcb8a018c02ca107e"||s.stdout_result.result_sha256!==m.sha256||lh().sha256Latin1(lh().byteString(b))!==n.chunk_sha256||n.chunk_sha256!=="fafa2adac55a13e8683928148f2f4f06508abcef7f1360ef41b1326a577359a6"||m.mode!==384||m.metadata.mode!==384||m.metadata.uid!==1000||m.metadata.gid!==1000||m.metadata.link_count!==1||m.metadata.metadata_platform!=="linux")throw Error("original_body0_recovery_exact");
 store("h2_live_body_bytes_0",b);
 s.result_body_chunks=[{offset:0,bytes:65536,sha256:n.chunk_sha256,next_offset:65536,eof:false,operation_id:o.operation_id,native:o.native,payload:o.payload,observer_tree:o.archive.tree}];
 const staleOffset=s.result_body_next_offset;s.result_body_next_offset=65536;s.default_page_width=16384;
 s.git_first_protocol_GO={blob:go.blob,bytes:go.bytes,sha256:go.sha256};
 s.git_first_bootstrap={original_body0_blob:body.blob,original_info_blob:info.blob,rederived_next_offset:65536,stale_store_offset_was:staleOffset,remaining_ranges:7,remaining_bytes:400034,Native_replayed:false};
 await hlState(s);text({bootstrap:true,next_offset:65536,remaining_ranges:7,Native_calls:0});
}
async function hgAcceptRange(){
 const s=load("h2_live_execution_state"),o=s.observations.at(-1),n=load("h2_live_observation_native_"+o.operation_id),m=s.result_file_info,off=s.result_body_next_offset,H=lh();
 const fixed=H2_REMAINING_BODY_REQUESTS.find(x=>x.offset===off),b=H.unb64(n.data_base64);
 if(!fixed||!o.closed||!o.archived||o.tool!=="binary_read"||s.Runtime_call_inflight||s.pending_call||s.active_operation_id||load("h2_live_git_first_archive_blocked")||n.offset!==off||n.path!==m.path||n.version!==m.version||n.size!==465570||b.length!==fixed.limit||n.next_offset!==off+b.length||n.eof!==(n.next_offset===465570)||H.sha256Latin1(H.byteString(b))!==n.chunk_sha256||s.result_body_chunks.some(x=>x.offset===off))throw Error("original_binary_range_check");
 store("h2_live_body_bytes_"+off,b);
 s.result_body_chunks.push({offset:off,bytes:b.length,sha256:n.chunk_sha256,next_offset:n.next_offset,eof:n.eof,operation_id:o.operation_id,native:o.native,payload:o.payload,observer_tree:o.archive.tree});
 s.result_body_next_offset=n.next_offset;await hlState(s);
 text({range_verified:s.result_body_chunks.at(-1),remaining:465570-n.next_offset});
 return s.result_body_chunks.at(-1);
}
