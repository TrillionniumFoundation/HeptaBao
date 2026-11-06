/* Pure fixed-plan validation and body derivation. No tool, import, Native, SDK, file or process invocation. */
function validateFixedReadbackInfo(plan,index,v){
 const need=(x,c)=>{if(!x)throw Error(c);};
 need(Number.isSafeInteger(index)&&index>=0&&index<3,"fixed_info_ordinal");
 const t=plan.targets[index];
 need(v&&v.path===t.path&&v.size===t.bytes&&v.sha256===t.sha256,"actual_fixed_info_path_size_sha");
 need(v.mode===384&&v.metadata?.mode===384&&v.metadata.uid===501&&v.metadata.gid===20
      &&v.metadata.link_count===1&&v.metadata.metadata_platform==="darwin","actual_regular_0600_owner_single_link");
 need(typeof v.version==="string"&&/^[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9]+$/.test(v.version),"actual_version_opaque_decimal_shape");
 const z=v.version.split(":");
 need(z[2]===String(v.size),"version_size_agrees");
 const full9=[z[0],z[1],String(v.metadata.uid),String(v.metadata.gid),String(32768+v.mode),
              String(v.metadata.link_count),z[2],z[3],z[4]];
 need(JSON.stringify(full9)===JSON.stringify(t.stageFull9),"actual_full9_matches_final_inert_observation");
 return {ordinal:index+1,path:v.path,bytes:v.size,sha256:v.sha256,version:v.version,full9,
  regularFileTypeSource:"file_info rejects symlinks and non-regular targets; mode is permission bits"};
}

function deriveFixedReadbackBodies(plan,infos){
 const need=(x,c)=>{if(!x)throw Error(c);};
 need(Array.isArray(infos)&&infos.length===3,"all_three_original_infos_required");
 const validated=infos.map((v,i)=>validateFixedReadbackInfo(plan,i,v));
 const requests=[];let total=0;
 for(let i=0;i<3;i++){
  const t=plan.targets[i],m=validated[i];let offset=0;
  for(const limit of t.bodyChunks){
   need(Number.isSafeInteger(limit)&&limit>0&&limit<=65536&&offset+limit<=m.bytes,"fixed_body_chunk_bound");
   const request={idempotency_key:plan.keyPrefix+"body-"+String(requests.length+1).padStart(2,"0"),
    operation:{tool:"binary_read",arguments:{host:"mac",path:m.path,offset,limit,expected_version:infos[i].version}}};
   const raw=JSON.stringify(request,null,2)+"\n";
   requests.push({ordinal:requests.length+1,targetOrdinal:i+1,target:t.id,requestRaw:raw,requestPin:gitBlobMeta(raw)});
   offset+=limit;total+=limit;
  }
  need(offset===m.bytes,"fixed_complete_target_extent");
 }
 need(requests.length===4&&total===plan.bodyTotalBytes&&total===96654,"exact_four_body_total");
 return {metadata:validated,requests,totalBytes:total,bodyRequestVersionsComeFromActualInfos:true,
         NativeCalls:0,runtimeGO:false};
}

function validateFixedReadbackBody(plan,infos,partIndex,q,v,previousParts){
 const need=(x,c)=>{if(!x)throw Error(c);};
 const derived=deriveFixedReadbackBodies(plan,infos),e=derived.requests[partIndex];
 need(e&&JSON.stringify(q)===JSON.stringify(JSON.parse(e.requestRaw)),"exact_derived_body_arguments");
 const a=q.operation.arguments,t=plan.targets[e.targetOrdinal-1];
 need(v&&v.path===a.path&&v.version===a.expected_version&&v.size===t.bytes&&v.offset===a.offset,
      "actual_binary_path_version_size_offset");
 need(typeof v.data_base64==="string"&&typeof v.chunk_sha256==="string","actual_binary_encoding_and_hash");
 const bytes=unb64(v.data_base64);
 need(bytes.length===a.limit&&v.next_offset===a.offset+bytes.length&&v.eof===(v.next_offset===t.bytes),
      "exact_binary_length_next_eof");
 need(sha256Latin1(byteString(bytes))===v.chunk_sha256,"actual_chunk_sha256");
 const part={target:e.target,targetOrdinal:e.targetOrdinal,path:v.path,version:v.version,
  offset:v.offset,next_offset:v.next_offset,eof:v.eof,base64:v.data_base64,bytes:bytes.length,
  chunkSha256:v.chunk_sha256};
 let whole=null;
 if(v.eof){
  const selected=previousParts.filter(p=>p.target===e.target).concat(part);
  let all=[],next=0;
  for(const p of selected){need(p.offset===next&&p.version===v.version,"same_version_contiguous_whole");all=all.concat(unb64(p.base64));next=p.next_offset;}
  need(next===t.bytes&&all.length===t.bytes,"whole_file_exact_extent");
  const raw=utf8Text(all),pin=gitBlobMeta(raw);
  need(pin.bytes===t.bytes&&pin.sha256===t.sha256,"whole_file_matches_stage_sha256");
  if(t.sourcePin)need(pin.blob===t.sourcePin.blob,"whole_file_matches_frozen_public_source_blob");
  whole={target:e.target,path:t.path,version:v.version,full9:derived.metadata[e.targetOrdinal-1].full9,
   raw,pin,independentOriginalBinaryRead:true};
 }
 return {part,whole};
}
