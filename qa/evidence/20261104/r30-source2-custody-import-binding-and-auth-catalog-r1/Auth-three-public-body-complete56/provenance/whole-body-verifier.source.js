function validateFixedPublicBody(row){
 const value=row.originalValue,expected=row.bodyDefinition.expectedWhole;
 if(!row.nativeClosed||!row.wholePayloadVerified||row.state!=="closed_full_original_payload")throw Error("body original operation closure");
 if(!value||value.path!==expected.path||value.version!==expected.version||value.offset!==0||value.next_offset!==expected.bytes||value.size!==expected.bytes||value.eof!==true)throw Error("body immutable version/length/EOF");
 if(typeof value.data_base64!=="string"||value.chunk_sha256!==expected.sha256)throw Error("body original base64/hash fields");
 const binary=decode64(value.data_base64);
 if(binary.length!==expected.bytes||sha(binary)!==expected.sha256)throw Error("body whole bytes/SHA");
 const raw=decodeURIComponent(escape(binary));
 if(unescape(encodeURIComponent(raw))!==binary)throw Error("body UTF8 exact");
 return{raw,bytes:binary.length,sha256:sha(binary),blob:h1("blob "+binary.length+"\0"+binary)};
}
