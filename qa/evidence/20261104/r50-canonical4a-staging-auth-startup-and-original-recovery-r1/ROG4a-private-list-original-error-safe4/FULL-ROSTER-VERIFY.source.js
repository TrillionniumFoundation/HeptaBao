function b4pRequireFullOwner(a,pageId){
 b4pNeed(a.scope==="page_and_backing_library_folder"&&a.sharing_available===true,"full_roster_scope");
 b4pNeed(a.page_id===pageId&&a.backing_type==="drive","same_private_drive_page");
 b4pNeed(a.workspace_id===null&&a.space_id===null&&a.next_cursor===null,"no_workspace_space_or_roster_continuation");
 b4pNeed(a.owner?.principal_type==="user"&&typeof a.owner.principal_id==="string"
  &&a.owner.principal_id.length>0&&a.owner.principal_id===a.page_owner?.principal_id,"canonical_owner_only_identity");
 b4pNeed(Array.isArray(a.shares)&&a.shares.length===0,"zero_direct_nonowner_grants");
 for(const k of ["inherited_access","inherited_access_summary","inherited_workspace_link_access"]){
  b4pNeed(a[k]?.complete===true&&Array.isArray(a[k].sources)&&a[k].sources.length===0,"complete_zero_inherited_grants");
 }
 return {ownerOnly:true,basis:"complete_full_roster",originalLiteralOwnerOnlyFieldAbsent:!Object.prototype.hasOwnProperty.call(a,"owner_only")};
}

function b4pDecodeFullRoster(readSDK,sharingSDK,pageId,expectedRaw,packed){
 b4pNeed(readSDK.isError!==true&&sharingSDK.isError!==true,"private_read_or_sharing_tool_error");
 const r=readSDK.structuredContent,a=sharingSDK.structuredContent;
 b4pNeed(r&&!r.error&&a&&!a.error,"private_structured_read_and_sharing");
 b4pRequireFullOwner(a,pageId);
 if(a.complete!==undefined)b4pNeed(a.complete===true,"sharing_snapshot_not_partial");
 b4pNeed(r.metadata?.page_id===pageId&&r.content?.page_id===pageId
  &&r.content.title===B4P_TITLE
  &&["personal","workspace_private"].includes(r.metadata.drive_scope)
  &&Array.isArray(r.content.blocks),"exact_private_page_full_read");
 if(r.selection)b4pNeed(r.selection.whole_page_complete===true,"whole_page_required");
 const chunks=new Map();let manifest=null,fences=0;
 const f=String.fromCharCode(96).repeat(3);
 for(const block of r.content.blocks){
  b4pNeed(block.kind==="markdown"&&typeof block.markdown==="string","only_created_markdown_blocks");
  const matches=[...block.markdown.matchAll(new RegExp(f+"(json|text)\\n([\\s\\S]*?)\\n"+f,"g"))];
  for(const m of matches){
   fences++;
   if(m[1]==="json"){
    b4pNeed(manifest===null&&m[2]===JSON.stringify(packed.manifest,null,2),"one_exact_private_manifest");
    manifest=JSON.parse(m[2]);
   }else{
    const p=/^HEPTABAO_SDK_PART ([0-9]+) OF ([0-9]+)\n([A-Za-z0-9+/=]+)$/.exec(m[2]);
    b4pNeed(p&&Number(p[2])===packed.parts.length,"exact_chunk_marker");
    const i=Number(p[1]);b4pNeed(i<packed.parts.length&&!chunks.has(i),"unique_contiguous_chunk");
    b4pNeed(p[3]===packed.parts[i],"private_chunk_exact");chunks.set(i,p[3]);
   }
  }
 }
 b4pNeed(manifest&&chunks.size===packed.parts.length&&fences===packed.parts.length+1,"all_private_blocks");
 const bytes=unb64(packed.parts.map((_,i)=>chunks.get(i)).join("")),raw=utf8Text(bytes);
 b4pNeed(raw===expectedRaw&&b4pEq(raw,manifest.sdk)
  &&byteString(utf8Bytes(raw))===byteString(bytes),"private_original_all_bytes_and_hashes");
 return {sdk:manifest.sdk,ownerOnly:true,whole:true,raw};
}
