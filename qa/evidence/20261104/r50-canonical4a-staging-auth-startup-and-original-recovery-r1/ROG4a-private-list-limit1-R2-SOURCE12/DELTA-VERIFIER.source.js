function verifyPrivateListR2Delta(input){
 const h=eval(input.pure+"\n"+input.source+";({pack:b4pPack,decode:b4pDecode,meta:gitBlobMeta,title:B4P_TITLE})");
 const raw=JSON.stringify({content:[{type:"text",text:"synthetic codec only"}],isError:false},null,2)+"\n",packed=h.pack(raw),pageId="page_r2_pure_fixture";
 function read(){return {structuredContent:{metadata:{page_id:pageId,drive_scope:"personal",owner_workspace_id:null},content:{page_id:pageId,title:h.title,blocks:packed.request.initial_blocks.map(markdown=>({kind:"markdown",markdown}))}}};}
 function acl(){return {scope:"page_and_backing_library_folder",sharing_available:true,page_id:pageId,backing_type:"drive",workspace_id:null,space_id:null,next_cursor:null,owner:{principal_type:"user",principal_id:"synthetic-owner"},page_owner:{principal_id:"synthetic-owner"},shares:[],inherited_access:{complete:true,sources:[]},inherited_access_summary:{complete:true,sources:[]},inherited_workspace_link_access:{complete:true,sources:[]}};}
 const checks=[];function ok(name,pass){checks.push({name,pass:!!pass});if(!pass)throw Error(name);}
 function reject(name,change,changeRead){const a=acl(),r=read();if(change)change(a);if(changeRead)changeRead(r);let rejected=false;try{h.decode(r,{structuredContent:a},pageId,raw,packed);}catch{rejected=true;}ok(name,rejected);}
 ok("full_empty_roster_positive_whole",h.decode(read(),{structuredContent:acl()},pageId,raw,packed).raw===raw);
 reject("different_canonical_owner_reject",a=>a.page_owner.principal_id="another-owner");
 reject("one_direct_share_reject",a=>a.shares.push({principal_id:"someone-else"}));
 reject("inherited_incomplete_reject",a=>a.inherited_access.complete=false);
 reject("one_inherited_source_reject",a=>a.inherited_access_summary.sources.push({role:"viewer"}));
 reject("workspace_link_incomplete_reject",a=>a.inherited_workspace_link_access.complete=false);
 reject("roster_cursor_reject",a=>a.next_cursor="more");
 reject("workspace_roster_reject",a=>a.workspace_id="another-workspace");
 reject("space_roster_reject",a=>a.space_id="another-space");
 reject("not_personal_read_reject",null,r=>r.structuredContent.metadata.drive_scope="workspace_private");
 reject("owner_workspace_read_reject",null,r=>r.structuredContent.metadata.owner_workspace_id="workspace");
 reject("explicit_owner_unknown_reject",a=>a.owner_only=null);
 ok("request_exact_limit1",input.requestRaw===JSON.stringify({host:"rog",limit:1},null,2)+"\n");
 ok("old_start_key_and_state_retained",input.source.includes('const B4P_KEY="heptabao-combined-4a49405b-fresh-build-20261106-r1-a4d59953";')&&input.source.includes('blob:"2d512764d26256fabaaaf7deb3eae41120d92d3e"'));
 return checks;
}
