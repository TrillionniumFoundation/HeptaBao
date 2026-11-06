async function savePublicBatchViaTreeJournaled(label,items){
 if(!/^[A-Za-z0-9._-]+$/.test(label)||!Array.isArray(items)||!items.length)throw Error("invalid batch");
 const records=items.map(x=>({name:x.name,...gitBlobMeta(x.text)}));
 if(new Set(records.map(x=>x.name)).size!==records.length||records.some(x=>!/^[A-Za-z0-9._-]+$/.test(x.name)))throw Error("unsafe or duplicate item");
 for(let i=0;i<items.length;i++)await persistRecoveryText("pending-"+records[i].blob,items[i].text);
 const entries=records.map(x=>({path:x.name,mode:"100644",type:"blob",sha:x.blob}));
 const expected=immediateTreeSha(entries);
 await persistRecoveryText(label+"-tree-intent",JSON.stringify({schema:"root.immutable-public-archive.content-tree.r1",expected_tree:expected,records,runtime_calls:0},null,2)+"\n");
 const sdk=await tools.mcp__codex_apps__github_create_tree({repository_full_name:"TrillionniumFoundation/HeptaBao",tree_elements:items.map(x=>({path:x.name,mode:"100644",type:"blob",content:x.text}))});
 await persistRecoveryText(label+"-create-tree-original-sdk",JSON.stringify(sdk,null,2)+"\n");
 if(sdk.isError)throw Error("Git content tree error "+expected);
 let sc=sdk.structuredContent; if(typeof sc?.content==="string")sc=JSON.parse(sc.content);
 if(sc?.sha!==expected)throw Error("content tree returned unexpected SHA "+JSON.stringify(sc?.sha));
 const read=await tools.mcp__codex_apps__github_fetch({url:"https://api.github.com/repos/TrillionniumFoundation/HeptaBao/git/trees/"+expected+"?recursive=1"});
 await persistRecoveryText(label+"-tree-read-original-sdk",JSON.stringify(read,null,2)+"\n");
 if(read.isError)throw Error("tree read error "+expected);
 const tree=JSON.parse(read.structuredContent.content);
 if(tree.sha!==expected||tree.truncated||tree.tree.length!==records.length)throw Error("tree envelope mismatch");
 const merkle=gitTreeAudit(tree);
 for(const e of tree.tree){const p=records.find(x=>x.name===e.path);if(!p||e.type!=="blob"||e.mode!=="100644"||e.sha!==p.blob||e.size!==p.bytes)throw Error("tree member mismatch "+e.path);}
 for(let i=0;i<records.length;i+=4){
   const part=records.slice(i,i+4), rr=await Promise.allSettled(part.map(x=>fetchVerifiedPublicBlob(x.blob))); const errors=[];
   for(let j=0;j<rr.length;j++){const r=rr[j],p=part[j];if(r.status!=="fulfilled"){errors.push({name:p.name,error:String(r.reason)});continue;}
    if(r.value.text!==items.find(x=>x.name===p.name).text||r.value.sha256!==p.sha256)throw Error("whole read mismatch "+p.name);
    await persistRecoveryText("saved-"+p.blob,JSON.stringify(p,null,2)+"\n");store("r32_saved_"+p.name,p);
   }if(errors.length)throw Error(JSON.stringify(errors));
 }
 const out={tree:expected,records,merkle,wholeVerified:true};
 await persistRecoveryText(label+"-complete",JSON.stringify(out,null,2)+"\n");store(label,out);return out;
}