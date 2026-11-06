function qualifyBodyChunk(row,entry,h,input){
const n=row.native,a=entry.request.operation.arguments,need=(b,k)=>{if(b!==true)throw Error("body:"+entry.name+":"+k);};
need(row.complete===true&&row.futureClosed===true,"original_closed");
need(n.path===a.path&&n.version===a.expected_version&&n.version===entry.info.version&&n.size===entry.info.bytes,"fixed_path_version_size");
need(n.offset===a.offset&&n.next_offset===a.offset+a.limit&&n.eof===entry.expectedEof,"exact_range_eof");
const bytes=h.decode(n.data_base64);
need(bytes.length===a.limit&&bytes.length<=65536&&h.b64(bytes)===n.data_base64,"bounded_canonical_base64");
const chunkSha=h.byteSha(bytes);need(chunkSha===n.chunk_sha256,"native_chunk_sha256");
let equalsFrozenBytes=null;
if(entry.info.role!=="inert_receipt"){
const prefix="/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-owner-bind-r1/";
const rel=a.path.slice(prefix.length),whole=h.decode(rel.startsWith("qa/")?input.files[rel.slice(3)]:input.documents[rel]);
const expected=whole.slice(a.offset,a.offset+a.limit);
need(whole.length===entry.info.bytes&&expected.length===bytes.length&&expected.every((b,i)=>b===bytes[i]),"exact_published_stdin_bytes");
equalsFrozenBytes=true;
}
if(n.offset===0&&n.eof===true)need(chunkSha===entry.info.sha256,"single_chunk_whole_sha");
return{schema:"heptabao.owner-renew-inert.body-chunk.actual.r1",pass:true,name:entry.name,operation_id:row.operation_id,nativePin:row.nativePin,path:n.path,version:n.version,size:n.size,offset:n.offset,next_offset:n.next_offset,bytes:bytes.length,eof:n.eof,chunk_sha256:chunkSha,equalsFrozenBytes,originalObserverClosed:true};
}
