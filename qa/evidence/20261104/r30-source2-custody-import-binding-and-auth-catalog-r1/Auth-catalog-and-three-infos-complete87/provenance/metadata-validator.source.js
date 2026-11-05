function validateFixedInfo(row){
 const value=row.originalValue,def=row.definition;
 if(!row.nativeClosed||!row.wholePayloadVerified||row.state!=="closed_full_original_payload")throw Error("info original closure");
 if(!value||typeof value!=="object"||Array.isArray(value)||value.path!==def.path||!Number.isSafeInteger(value.size)||value.size<0||value.size>def.maxBytes||!/^[0-9a-f]{64}$/.test(value.sha256)||typeof value.version!=="string")throw Error("info exact path/size/hash");
 const parts=value.version.split(":");if(parts.length!==5||parts.some(x=>!/^\d+$/.test(x))||parts[2]!==String(value.size))throw Error("info immutable version");
 const m=value.metadata;if(!m||![m.uid,m.gid,m.mode,m.link_count,value.mode].every(Number.isSafeInteger)||m.mode!==value.mode||m.uid<0||m.gid<0||m.mode<0||m.mode>4095||m.link_count<1)throw Error("info metadata");
 const identity=[parts[0],parts[1],String(m.uid),String(m.gid),String(32768+m.mode),String(m.link_count),parts[2],parts[3],parts[4]];
 if(def.observed&&(value.size!==def.observed.bytes||value.sha256!==def.observed.sha256||JSON.stringify(identity)!==JSON.stringify(def.observed.identity)))throw Error("original observed Codex full9/pins drift");
 return{ordinal:def.ordinal,id:def.id,path:value.path,bytes:value.size,sha256:value.sha256,version:value.version,identity,regularNonSymlinkEvidence:"successful original file_info; advertised closed native API rejects symlinks and special files",fileInfoHashWorkIsNotBodyRead:true,bodyMaxBytes:def.maxBytes,bodyReadAuthorized:false,originalNative:row.originalNative.blob,originalPayload:row.originalPayload.blob,operationId:row.operationId,completedInactiveAndWhole:true};
}
