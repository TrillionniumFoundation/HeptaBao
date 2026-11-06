function verifyFixedReadbackActual(data) {
 const checks=[];const need=(n,v)=>{checks.push({name:n,passed:v===true});if(v!==true)throw Error(n);};
 const s=data.state,p=data.plan;
 need("readback zero live Native and all accepted",s.nativeCallInFlight===false&&s.activeObserver===null&&s.pending===null&&!s.paused&&Object.keys(s.calls).length===35&&Object.values(s.calls).every(c=>c.called===true&&c.phase==="accepted"&&c.armed?.whole===true&&c.sdkArchive?.whole===true));
 need("seven once-admitted reads no process starts",s.processStartsInThisScope===0&&s.completedObservers.length===7&&Object.values(s.calls).filter(c=>c.kind==="operation_start").length===7&&!Object.values(s.calls).some(c=>c.kind==="process_start"));
 need("twenty-one completed original pages",s.completedObservers.every(o=>o.completedInactive===true)&&s.completedObservers.reduce((n,o)=>n+o.pages,0)===21);
 for(const [key,c]of Object.entries(s.calls)){
  const o=data.callOriginals[key],sdk=JSON.parse(o.sdkRaw);
  need("whole request/sdk/native "+key,gitBlobMeta(c.requestRaw).blob===c.requestPin.blob&&gitBlobMeta(o.sdkRaw).blob===c.sdkPin.blob&&gitBlobMeta(o.nativeRaw).blob===c.nativePin.blob&&sdk.isError!==true&&sdk.content?.length===1&&sdk.content[0].text===o.nativeRaw);
 }
 const admissions=Object.entries(s.calls).filter(([,c])=>c.kind==="operation_start");
 for(let i=0;i<7;i++){
  const o=s.completedObservers[i],[key,c]=admissions[i],q=JSON.parse(c.requestRaw),ack=parseLosslessIntegers(data.callOriginals[key].nativeRaw);
  need("read "+i+" exact ordered request and original ACK",c.requestRaw===s.readbackRequests[i]&&ack.operation_id===o.id&&ack.tool_name===q.operation.tool&&ack.reused===false&&ack.automatic_retry===false);
  const states=Object.entries(s.calls).filter(([,c])=>c.kind==="operation_status"&&JSON.parse(c.requestRaw).operation_id===o.id);
  need("read "+i+" exact one completed inactive state",states.length===1&&states.every(([key])=>{const v=parseLosslessIntegers(data.callOriginals[key].nativeRaw);return v.operation_id===o.id&&v.tool_name===o.tool&&v.async_state==="completed"&&v.owned_future_active===false&&v.result_state==="stored_observed"&&v.payload_available===true;}));
  const pages=Object.entries(s.calls).filter(([,c])=>c.kind==="operation_result"&&JSON.parse(c.requestRaw).operation_id===o.id).sort((a,b)=>JSON.parse(a[1].requestRaw).offset-JSON.parse(b[1].requestRaw).offset);
  let bytes=[],next=0,total=null,sha=null,lastEof=false;
  for(const [key,c]of pages){const q=JSON.parse(c.requestRaw),v=parseLosslessIntegers(data.callOriginals[key].nativeRaw),b=unb64(v.data_base64);
   need("page "+key+" identity extent and immutable hash",q.limit===8192&&q.offset===next&&v.offset===next&&v.operation_id===o.id&&v.immutable_snapshot===true&&v.payload_kind==="native_result"&&v.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization"&&b.length<=8192&&v.next_offset===next+b.length&&v.eof===(v.next_offset===v.total_bytes)&&(total===null||v.total_bytes===total&&v.result_sha256===sha));
   bytes=bytes.concat(b);next=v.next_offset;total=v.total_bytes;sha=v.result_sha256;lastEof=v.eof;
  }
  const payload=utf8Text(bytes),pin=gitBlobMeta(payload),original=parseLosslessIntegers(payload);
  need("read "+i+" exact payload and native reconstruction",pages.length===o.pages&&lastEof===true&&next===total&&pin.bytes===total&&pin.sha256===sha&&pin.blob===o.payload.blob&&payload===data.observerOriginals[o.id].payloadRaw&&original.resultType==="complete"&&original.isError===false&&original.content.length===1&&original.content[0].text===data.observerOriginals[o.id].nativeRaw&&gitBlobMeta(original.content[0].text).blob===o.nativeText.blob);
 }
 need("all three current metadata exact",s.readbackInfos.length===3&&s.derivedBodyPlan.metadata.every((m,i)=>m.path===p.targets[i].path&&m.bytes===p.targets[i].bytes&&m.sha256===p.targets[i].sha256&&JSON.stringify(m.full9)===JSON.stringify(p.targets[i].stageFull9)&&m.version===s.readbackInfos[i].version));
 need("four actual body pieces exact plan and total",s.readbackParts.length===4&&s.bodyReturnAccounting.length===4&&s.bodyReturnAccounting.every((x,i)=>x.byteCountUnknown===false&&x.bytes===[65536,8382,7499,15237][i])&&s.bodyReturnAccounting.reduce((n,x)=>n+x.bytes,0)===96654);
 for(let i=0;i<4;i++){const b=s.readbackParts[i],q=JSON.parse(s.readbackRequests[i+3]).operation.arguments;need("body "+i+" actual chunk version and digest",b.path===q.path&&b.version===q.expected_version&&b.offset===q.offset&&b.bytes===q.limit&&b.next_offset===q.offset+q.limit&&unb64(b.base64).length===q.limit&&sha256Latin1(byteString(unb64(b.base64)))===b.chunkSha256);}
 need("all three whole files exact",s.readbackWholeFiles.length===3&&s.readbackWholeFiles.every((f,i)=>f.target===p.targets[i].id&&f.path===p.targets[i].path&&f.version===s.readbackInfos[i].version&&gitBlobMeta(f.raw).sha256===p.targets[i].sha256&&gitBlobMeta(f.raw).bytes===p.targets[i].bytes&&(!p.targets[i].sourcePin||gitBlobMeta(f.raw).blob===p.targets[i].sourcePin.blob)));
 need("original inert context unchanged",gitBlobMeta(data.originalInertStateRaw).blob===p.originalState.blob);
 return {schema:"heptabao.home-r3-fixed-readback-actual-checks.v1",passed:true,checkCount:checks.length,checks,NativeCalls:35,originalOperations:7,immutablePages:21,bodyBytes:96654,noNewRuntimeInVerifier:true,noProductTestClaim:true};
}