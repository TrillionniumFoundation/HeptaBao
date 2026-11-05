function verifyBody4(files,sha256,sha1){
  // Pure V8 over exact archived UTF-8 bytes. No tools, clock, imports, SDK or host execution.
  const checks=[];
  function check(id,ok){checks.push({id,passed:!!ok});if(!ok)throw Error(id);}
  function bytes(x){return unescape(encodeURIComponent(x));}
  function read(path){check("present:"+path,!!files[path]&&typeof files[path].raw==="string");return files[path].raw;}
  function get(path){return JSON.parse(read(path));}
  function pin(path){const x=files[path];return {blob:x.blob,bytes:x.bytes,sha256:x.sha256};}
  function equal(a,b){return JSON.stringify(a)===JSON.stringify(b);}
  function base64(s){
    check("base64.syntax",typeof s==="string"&&s.length%4===0&&/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s));
    const a="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let out="";
    for(let i=0;i<s.length;i+=4){
      const x=a.indexOf(s[i]),y=a.indexOf(s[i+1]),z=s[i+2]==="="?0:a.indexOf(s[i+2]),w=s[i+3]==="="?0:a.indexOf(s[i+3]);
      if(s[i+2]==="=")check("base64.pad2",(y&15)===0);
      else if(s[i+3]==="=")check("base64.pad1",(z&3)===0);
      out+=String.fromCharCode((x<<2)|(y>>4));
      if(s[i+2]!=="=")out+=String.fromCharCode(((y&15)<<4)|(z>>2));
      if(s[i+3]!=="=")out+=String.fromCharCode(((z&3)<<6)|w);
    }return out;
  }
  for(const [path,f] of Object.entries(files)){
    const b=bytes(f.raw);check("whole:"+path,b.length===f.bytes&&sha256(b)===f.sha256&&sha1("blob "+b.length+"\0"+b)===f.blob);
  }
  const go=get("authorization/root-GO.public.json"),release=get("handoff/RELEASE.public.json"),proposal=get("reference/body-PROPOSAL.public.json");
  check("exact_body_GO",files["authorization/root-GO.public.json"].blob==="89d02183f27a783b27dd9d4a976529dcc32045dc"&&go.requests.length===4&&go.maximum_new_body_submissions===4&&go.total_new_body_bytes===127095&&go.immutable_result_page_limit===8192);
  check("same_proposal",files["reference/body-PROPOSAL.public.json"].blob===go.proposal.blob&&proposal.requests.length===4);
  function sdkPair(path){
    const sdk=get(path+"/original-sdk.json"),native=read(path+"/original-native.json");
    check("SDK_noerror:"+path,sdk.isError!==true&&Array.isArray(sdk.content)&&sdk.content.length===1&&sdk.content[0].type==="text");
    check("SDK_native_exact:"+path,sdk.content[0].text===native);return JSON.parse(native);
  }
  const ids=new Set(),keys=new Set(),rows=[],groups={},allPaths=Object.keys(files);let pageCount=0,bodyBytes=0;
  check("four_original_status_requests",allPaths.filter(x=>/^observations\/[0-9]{2}\/status-[0-9]+\/request.json$/.test(x)).length===4);
  for(let i=0;i<4;i++){
    const tag=String(i+1).padStart(2,"0"),dir="observations/"+tag,r=get(dir+"/intent/exact-request.public.json"),intent=get(dir+"/intent/intent.public.json"),frozen=go.requests[i],args=r.operation.arguments;
    check("exact_request:"+tag,equal(r,frozen.value)&&equal(pin(dir+"/intent/exact-request.public.json"),frozen.request)&&equal(r,proposal.requests[i].value));
    check("binary_read_scope:"+tag,r.operation.tool==="binary_read"&&args.host==="mac"&&args.limit>0&&args.limit<=65536&&!keys.has(r.idempotency_key));keys.add(r.idempotency_key);
    check("exact_intent:"+tag,intent.sequence===i+1&&equal(intent.exact_request,r)&&equal(intent.request,frozen.request)&&equal(intent.root_GO,pin("authorization/root-GO.public.json"))&&intent.immutable_result_page_limit===8192&&intent.maximum_inflight_call===1&&intent.maximum_owned_native_future===1&&intent.SDK_execution===false&&intent.new_submissions_before_this_intent===0);
    const expected=go.actual_files.find(x=>x.id===frozen.id);
    check("expected_file_current_metadata:"+tag,equal(intent.expected_file,expected));
    const info=get("reference/metadata/"+frozen.id+".native.json");
    check("metadata_actual_pin:"+tag,files["reference/metadata/"+frozen.id+".native.json"].blob===expected.native_info_blob&&info.path===expected.path&&info.size===expected.bytes&&info.sha256===expected.sha256&&info.version===expected.version);
    if(i>0){
      const prev="observations/"+String(i).padStart(2,"0"),b=intent.previous_body_closed_and_whole;
      check("previous_whole_before_next:"+tag,intent.previous_body_operations_completed===i&&b.operation_id===rows[i-1].operation_id&&equal(b.status,pin(prev+"/status-0/original-native.json"))&&equal(b.payload,pin(prev+"/original-payload.json"))&&equal(b.native,pin(prev+"/native-result.public.json"))&&equal(b.binding,pin(prev+"/actual-binding.public.json")));
    }else check("first_metadata_closed_intent",intent.prior_three_metadata_all_closed===true&&intent.previous_body_operations_completed===0);
    const ack=sdkPair(dir+"/start");
    check("original_ACK_unique:"+tag,ack.tool_name==="binary_read"&&/^[0-9a-f]{64}$/.test(ack.operation_id)&&ack.reused===false&&!ids.has(ack.operation_id));ids.add(ack.operation_id);
    const status=sdkPair(dir+"/status-0");
    check("status_request:"+tag,equal(get(dir+"/status-0/request.json"),{operation_id:ack.operation_id}));
    check("completed_stored_inactive:"+tag,status.operation_id===ack.operation_id&&status.tool_name==="binary_read"&&status.async_state==="completed"&&status.result_state==="stored_observed"&&status.owned_future_active===false&&status.payload_available===true);
    const pageDirs=allPaths.filter(x=>x.startsWith(dir+"/result-")&&x.endsWith("/request.json")).map(x=>x.slice(0,-13)).sort((a,b)=>Number(a.slice(a.lastIndexOf("-")+1))-Number(b.slice(b.lastIndexOf("-")+1)));
    let original="",total=null,digest=null,last=null;
    for(const pd of pageDirs){
      const req=get(pd+"/request.json"),page=sdkPair(pd),part=base64(page.data_base64),offset=original.length;
      check("page_request:"+pd,equal(req,{operation_id:ack.operation_id,offset,limit:8192}));
      check("page_fixed_protocol:"+pd,page.operation_id===ack.operation_id&&page.offset===offset&&page.immutable_snapshot===true&&page.payload_kind==="native_result"&&page.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization");
      check("page_bounds:"+pd,part.length>0&&part.length<=8192&&Number.isInteger(page.total_bytes)&&page.total_bytes>0&&page.total_bytes<=1048576&&page.next_offset===offset+part.length&&page.next_offset<=page.total_bytes&&page.eof===(page.next_offset===page.total_bytes));
      if(total===null){total=page.total_bytes;digest=page.result_sha256;}else check("page_snapshot_fixed:"+pd,total===page.total_bytes&&digest===page.result_sha256&&last.eof===false);
      original+=part;last=page;pageCount++;
    }
    check("whole_original_payload:"+tag,last!==null&&last.eof===true&&original.length===total&&sha256(original)===digest&&bytes(read(dir+"/original-payload.json"))===original);
    const payload=JSON.parse(read(dir+"/original-payload.json"));
    check("native_success:"+tag,payload.resultType==="complete"&&payload.isError===false&&payload.content.length===1&&payload.content[0].type==="text"&&payload.content[0].text===read(dir+"/native-result.public.json"));
    const native=JSON.parse(payload.content[0].text),body=base64(native.data_base64);
    check("native_range_version:"+tag,native.path===args.path&&native.version===args.expected_version&&native.size===expected.bytes&&native.offset===args.offset&&native.next_offset===frozen.expected_next_offset&&native.eof===frozen.expected_eof);
    check("native_body_chunk_SHA:"+tag,body.length===args.limit&&native.next_offset===native.offset+body.length&&sha256(body)===native.chunk_sha256);
    const binding=get(dir+"/actual-binding.public.json");
    check("actual_binding:"+tag,binding.operation_id===ack.operation_id&&equal(binding.status,pin(dir+"/status-0/original-native.json"))&&equal(binding.original_payload,pin(dir+"/original-payload.json"))&&equal(binding.native,pin(dir+"/native-result.public.json"))&&binding.chunk_bytes===body.length&&binding.chunk_sha256===native.chunk_sha256&&binding.original_operation_completed_stored_inactive===true&&binding.all_original_payload_pages_whole===true&&binding.SDK_execution===false);
    (groups[frozen.id]??=[]).push({sequence:i+1,native,body});
    bodyBytes+=body.length;rows.push({sequence:i+1,id:frozen.id,operation_id:ack.operation_id,pages:pageDirs.length,original_payload_bytes:total,original_payload_sha256:digest,body_bytes:body.length,body_sha256:native.chunk_sha256,offset:native.offset,next_offset:native.next_offset,eof:native.eof,status:pin(dir+"/status-0/original-native.json"),native:pin(dir+"/native-result.public.json")});
  }
  const sources=[];
  for(const expected of go.actual_files){
    const chunks=groups[expected.id];let whole="",cursor=0;
    for(let j=0;j<chunks.length;j++){
      const c=chunks[j];check("whole_source_chunk:"+expected.id+":"+j,c.native.offset===cursor&&c.native.version===expected.version&&c.native.path===expected.path&&c.native.eof===(j===chunks.length-1));whole+=c.body;cursor=c.native.next_offset;
    }
    const path="sources/"+expected.id+".original.js";
    check("actual_whole_source:"+expected.id,whole.length===expected.bytes&&cursor===expected.bytes&&sha256(whole)===expected.sha256&&bytes(read(path))===whole);
    sources.push({id:expected.id,path:expected.path,source:pin(path),version:expected.version,native_sequences:chunks.map(x=>x.sequence)});
  }
  check("four_body_total_and_pages",rows.length===4&&pageCount===23&&bodyBytes===127095&&sources.length===3);
  check("release_zero_and_counts",release.current_Runtime_calls_inflight===0&&release.current_owned_native_futures===0&&release.returned_original_operations===4&&release.original_immutable_pages===23&&release.original_body_bytes===127095&&release.tool_errors===0&&release.automatic_retries===0&&release.SDK_execution===0);
  check("prior_consumption_not_reset",release.prior_closed_body_window.files===3&&release.prior_closed_body_window.chunks===3&&release.prior_closed_body_window.bytes===13569&&release.cumulative_body_windows.files===6&&release.cumulative_body_windows.chunks===7&&release.cumulative_body_windows.bytes===140664);
  return {schema:"heptabao.auth.body4.raw-chain-verification.v1",ok:true,scope:"Pure V8 reconstruction of returned public source read chains. Not SDK/product execution or a selected-owner qualification.",checks,counts:{checks:checks.length,original_operations:4,original_immutable_pages:pageCount,body_bytes:bodyBytes,whole_files:sources.length},rows,sources,current_Runtime_calls_inflight:0,current_owned_native_futures:0,actual_selected_owner_proven:false,chronology_limit:"Intent/SDK save-before-parse followed during collection; immutable files independently prove exact bindings and bytes, not wall-clock save order."};
}
