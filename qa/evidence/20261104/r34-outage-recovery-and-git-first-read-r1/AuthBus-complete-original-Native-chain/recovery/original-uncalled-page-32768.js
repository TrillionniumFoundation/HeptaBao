async function wfResumeOriginalUncalledPage32768(){const name="streams-02",offset=32768,h=wfHelpers(),state=load("owner_worker_observers"),r=state[name],base="observations/"+name+"/pages/"+String(offset).padStart(6,"0")+"/";if(r.operation_id!=="156780d3049e1852407b08254293cd0082dd3b3c50215e0f3bc35bef1583f026"||!r.futureClosed||!r.pageCalls[offset]||r.pages[offset]||load("owner_worker_Runtime_call_inflight")||load("owner_worker_paused"))throw Error("original-page-recovery-boundary");const q={operation_id:r.operation_id,offset,limit:8192};store("owner_worker_Runtime_call_inflight",true);
 const sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_operation_result(q);
 store("owner_worker_Runtime_call_inflight",false);store("owner_worker_pending_sdk",{name,stage:"page",offset,sdk});
 const pin=await wfLocal(base+"original.sdk.json",JSON.stringify(sdk,null,2)+"\n");
 if(sdk.isError){store("owner_worker_paused",true);await wfCheckpoint(name+"-page-error");text({nativeError:sdk,SDK:pin});return;}
 if(sdk.content?.length!==1||sdk.content[0].type!=="text")throw Error("pageShape");
 const raw=sdk.content[0].text,np=await wfLocal(base+"original.native.txt",raw),v=h.parse(raw);
 if(v.operation_id!==r.operation_id||v.offset!==offset||v.immutable_snapshot!==true||v.payload_kind!=="native_result"||v.format!=="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization"||!Number.isSafeInteger(v.total_bytes)||v.total_bytes<0||v.total_bytes>1048576||!/^[a-f0-9]{64}$/.test(v.result_sha256))throw Error("pageIdentity");
 const bytes=h.decode(v.data_base64);if(bytes.length>8192||v.next_offset!==offset+bytes.length||v.next_offset>v.total_bytes||v.eof!==(v.next_offset===v.total_bytes)||(!bytes.length&&!v.eof))throw Error("pageExtent");
 if(r.total!==undefined&&(r.total!==v.total_bytes||r.digest!==v.result_sha256))throw Error("payloadIdentity");
 r.total=v.total_bytes;r.digest=v.result_sha256;r.pages[offset]={offset,next:v.next_offset,eof:v.eof,bytes:bytes.length,SDK:pin,native:np,base64:v.data_base64};store("owner_worker_observers",state);await wfCheckpoint(name+"-page-"+offset+"-after");
 return {name,offset,next:v.next_offset,total:r.total,eof:v.eof,SDK:pin,native:np};
}
