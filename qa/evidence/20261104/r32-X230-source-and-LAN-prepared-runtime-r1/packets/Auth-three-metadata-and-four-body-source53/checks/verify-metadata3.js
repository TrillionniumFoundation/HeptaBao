function verifyMetadata3(files,sha256,sha1){
  // Pure V8. Input: path -> {raw UTF-8 text, blob, bytes, sha256}.
  // Hash arguments accept binary byte strings. No tools, I/O, clock, Runtime or SDK execution.
  const checks=[];
  function check(id,ok){checks.push({id,passed:!!ok});if(!ok)throw Error(id);}
  function bytes(raw){return unescape(encodeURIComponent(raw));}
  function read(path){check("present:"+path,!!files[path]&&typeof files[path].raw==="string");return files[path].raw;}
  function value(path){return JSON.parse(read(path));}
  function pin(path){const x=files[path];return {blob:x.blob,bytes:x.bytes,sha256:x.sha256};}
  function same(a,b){return JSON.stringify(a)===JSON.stringify(b);}
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
    const b=bytes(f.raw);
    check("whole:"+path,b.length===f.bytes&&sha256(b)===f.sha256&&sha1("blob "+b.length+"\0"+b)===f.blob);
  }
  const go=value("authorization/root-GO.public.json"),proposal=value("reference/source-proposal.public.json");
  check("exact_GO_identity",files["authorization/root-GO.public.json"].blob==="05401409ea379379875c69ffb04e6688f310d555");
  check("exact_handoff_identity",files["authorization/line-B-handoff.public.json"].blob==="e1edf77fc54e891486a5c4a16efb3042dcc51ca4");
  check("exact_proposal_identity",files["reference/source-proposal.public.json"].blob==="9d64664ed990d2d6a10287de0c4d09dd9d157395");
  check("GO_only_metadata3",go.maximum_new_file_info_operations===3&&go.body_requests_authorized===0&&go.protocol.immutable_result_page_limit===8192);
  check("proposal3",proposal.requests.length===3&&go.requests.length===3);
  function sdkPair(path){
    const sdk=value(path+"/original-sdk.json"),raw=read(path+"/original-native.json");
    check("originalSDK_success:"+path,sdk.isError!==true&&Array.isArray(sdk.content)&&sdk.content.length===1&&sdk.content[0].type==="text");
    check("originalSDK_native_exact:"+path,sdk.content[0].text===raw);
    return JSON.parse(raw);
  }
  const rows=[],ids=new Set(),keys=new Set();
  for(let i=0;i<3;i++){
    const tag=String(i+1).padStart(2,"0"),dir="observations/"+tag,request=value(dir+"/intent/exact-request.public.json"),intent=value(dir+"/intent/intent.public.json");
    check("request_exact_proposal:"+tag,same(request,proposal.requests[i].request)&&same(request,go.requests[i].request));
    check("file_info_exact_scope:"+tag,request.operation.tool==="file_info"&&request.operation.arguments.host==="mac"&&request.operation.arguments.path===proposal.requests[i].path);
    check("unique_key:"+tag,!keys.has(request.idempotency_key));keys.add(request.idempotency_key);
    check("intent_request:"+tag,same(intent.exact_request,request)&&same(intent.request,pin(dir+"/intent/exact-request.public.json"))&&intent.sequence===i+1);
    check("intent_GO:"+tag,same(intent.root_GO,pin("authorization/root-GO.public.json"))&&same(intent.handoff,pin("authorization/line-B-handoff.public.json")));
    check("intent_boundaries:"+tag,intent.prior_completed_operations===i&&intent.maximum_native_futures===1&&intent.immutable_page_limit===8192&&intent.body_reads_authorized===0&&intent.SDK_execution_authorized===false&&intent.new_submission_before_this_intent===0);
    if(i>0){const prev=rows[i-1],n=String(i).padStart(2,"0"),p="observations/"+n;check("prior_whole_closed_binding:"+tag,intent.previous_original_closed.operation_id===prev.operation_id&&intent.previous_original_closed.whole_verified===true&&same(intent.previous_original_closed.status,pin(p+"/status-0/original-native.json"))&&same(intent.previous_original_closed.payload,pin(p+"/original-payload.json"))&&same(intent.previous_original_closed.native,pin(p+"/native-result.public.json")));}
    const ack=sdkPair(dir+"/start");
    check("unique_original_ACK:"+tag,typeof ack.operation_id==="string"&&/^[0-9a-f]{64}$/.test(ack.operation_id)&&!ids.has(ack.operation_id)&&ack.tool_name==="file_info"&&ack.reused===false);ids.add(ack.operation_id);
    const status=sdkPair(dir+"/status-0");
    check("sameID_status_request:"+tag,same(value(dir+"/status-0/request.json"),{operation_id:ack.operation_id}));
    check("sameID_completed_stored_inactive:"+tag,status.operation_id===ack.operation_id&&status.tool_name==="file_info"&&status.async_state==="completed"&&status.result_state==="stored_observed"&&status.owned_future_active===false&&status.payload_available===true);
    const page=sdkPair(dir+"/result-0");
    check("sameID_page_request:"+tag,same(value(dir+"/result-0/request.json"),{operation_id:ack.operation_id,offset:0,limit:8192}));
    check("immutable_page_protocol:"+tag,page.operation_id===ack.operation_id&&page.immutable_snapshot===true&&page.payload_kind==="native_result"&&page.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization"&&page.offset===0&&page.eof===true);
    const b=base64(page.data_base64),payloadRaw=read(dir+"/original-payload.json");
    check("payload_exact_whole:"+tag,b.length<=8192&&b.length===page.total_bytes&&page.next_offset===b.length&&sha256(b)===page.result_sha256&&bytes(payloadRaw)===b);
    const payload=JSON.parse(payloadRaw);
    check("native_complete_no_error:"+tag,payload.resultType==="complete"&&payload.isError===false&&Array.isArray(payload.content)&&payload.content.length===1&&payload.content[0].type==="text");
    const nativeRaw=read(dir+"/native-result.public.json");
    check("native_original_text:"+tag,payload.content[0].text===nativeRaw);
    const info=JSON.parse(nativeRaw),v=String(info.version).split(":");
    check("native_metadata_shape:"+tag,info.path===request.operation.arguments.path&&Number.isSafeInteger(info.size)&&info.size>=0&&/^[0-9a-f]{64}$/.test(info.sha256)&&v.length===5&&v.every(x=>/^[0-9]+$/.test(x))&&v[2]===String(info.size));
    check("POSIX_observed:"+tag,info.metadata.metadata_platform==="darwin"&&info.mode===420&&info.metadata.mode===info.mode&&info.metadata.uid===501&&info.metadata.gid===80&&info.metadata.link_count===1&&Array.isArray(info.metadata.xattr_names)&&info.metadata.xattr_names.length===0);
    const full9=[v[0],v[1],String(info.metadata.uid),String(info.metadata.gid),String(32768|info.mode),String(info.metadata.link_count),v[2],v[3],v[4]];
    rows.push({sequence:i+1,id:proposal.requests[i].id,path:info.path,operation_id:ack.operation_id,status:pin(dir+"/status-0/original-native.json"),original_payload:pin(dir+"/original-payload.json"),native_info:pin(dir+"/native-result.public.json"),size:info.size,sha256:info.sha256,version:info.version,reported_mode:info.mode,regular_full9_decimal:full9,full9_derivation:"version fields remain decimal strings; uid/gid/mode/link_count are actual metadata; S_IFREG is normalized from the file_info regular-target contract, not a separate raw stat field.",closed:true});
  }
  check("original_error_history_preserved",!!files["history/local-status02-precall-error.public.json"]&&!!files["history/local-status03-field-correction.public.json"]);
  const correction=value("history/local-status03-field-correction.public.json");
  check("field_correction_no_Runtime_replay",correction.actual_protocol_field==="result_state"&&correction.additional_Runtime_calls===0&&correction.original_Runtime_status_unchanged===true);
  return {schema:"heptabao.auth.metadata3.raw-chain-verification.v1",ok:true,scope:"Pure verification of the three returned metadata observation chains. These are not product test cases or SDK execution.",checks,counts:{checks:checks.length,original_operations:3,original_ACKs:3,statuses:3,immutable_pages:3,metadata_only:true,body_reads:0,SDK_execution:0},rows,all_original_operations_completed_stored_inactive:true,actual_selected_owner_proven:false,body_read_permission:false,chronology_limit:"Collection followed external-save-before-parse and intent-before-start. This pure file verifier checks exact bindings and original bytes; file contents alone do not independently attest wall-clock save order."};
}
