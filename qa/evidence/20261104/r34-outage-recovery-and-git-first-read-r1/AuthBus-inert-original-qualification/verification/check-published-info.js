function checkPublishedInfo(name,index,go,stdout,state){
const o=state[name],n=o?.native,t=go.conditionalBodies.targets[index],record=index===2?stdout.candidateReceipt:stdout.files.find(r=>r.name===t.expectedPublicationRecord.name);
const need=(b,k)=>{if(b!==true)throw Error("metadata:"+name+":"+k);};
need(o.complete===true&&o.futureClosed===true,"original_closed");
need(!!record&&record.kind===t.expectedPublicationRecord.kind,"record_bound");
need(n.path===t.path&&n.sha256===record.sha256&&n.size===record.bytes,"path_whole_pin");
need(Number.isInteger(n.size)&&n.size>0&&(index<2?n.size===t.bytes:n.size<=t.maxBytes),"fixed_size_bound");
need(n.metadata.metadata_platform==="darwin"&&n.mode===384&&n.metadata.mode===384&&n.metadata.uid===501&&n.metadata.link_count===1,"native_regular_singlelink_mode_owner_contract");
need(Number.isInteger(n.metadata.gid)&&n.metadata.gid>=0&&typeof n.version==="string"&&/^\d+:\d+:\d+:\d+:\d+$/.test(n.version),"lossless_version");
const v=n.version.split(":");
need(v[2]===String(n.size),"version_size");
const actual=[v[0],v[1],String(n.metadata.uid),String(n.metadata.gid),String(0o100000|n.mode),String(n.metadata.link_count),v[2],v[3],v[4]];
need(JSON.stringify(actual)===JSON.stringify(record.identity),"full9_equals_final_held_record");
need(index===2||n.sha256===t.sha256,"fixed_source_sha");
return{name,role:t.role,operation_id:o.operation_id,nativePin:o.nativePin,path:n.path,bytes:n.size,sha256:n.sha256,version:n.version,full9:actual,pass:true};
}
