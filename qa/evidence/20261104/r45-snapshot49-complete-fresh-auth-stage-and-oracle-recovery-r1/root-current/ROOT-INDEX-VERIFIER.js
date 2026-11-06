function verifyCheckpointIndex(index){
 const checks=[];const ck=(name,v)=>{checks.push({name,passed:v===true});if(v!==true)throw Error(name)};
 ck("all_unique_packet_labels",new Set(index.mounts.map(x=>x.label)).size===index.mounts.length);
 for(const m of index.mounts){
  ck("whole_members_"+m.label,m.whole===true&&m.files===m.members.length&&m.bytes===m.members.reduce((n,x)=>n+x.bytes,0)&&new Set(m.members.map(x=>x.path)).size===m.members.length);
  const leaves=m.members.map(x=>({path:x.path,mode:"100644",type:"blob",sha:x.blob,size:x.bytes}));
  ck("full_Merkle_"+m.label,rebuildTreeFromLeaves(leaves).root_sha===m.tree);
 }
 ck("exact_totals",index.mounts.length===index.totals.packets&&index.mounts.reduce((n,x)=>n+x.files,0)===index.totals.files&&index.mounts.reduce((n,x)=>n+x.bytes,0)===index.totals.bytes&&index.totals.allWhole===true);
 return {schema:"heptabao.r45-root-index-qualification.v1",passed:true,checkCount:checks.length,checks,totals:index.totals,scope:"Complete previously whole packet members and Merkle identities; no source/runtime qualification is inferred from archival.",NativeCalls:0};
}