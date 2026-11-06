async function archiveReferencedEvidenceGroupOnce(key,refs) {
 const repository="TrillionniumFoundation/HeptaBao",prefix="formatted23_reference_group:"+key;
 if(!/^[a-zA-Z0-9_.-]{1,100}$/.test(key)||load(prefix)!==undefined)throw Error("new_reference_archive_once_key");
 if(!Array.isArray(refs)||refs.length<1||refs.length>64)throw Error("reference_group_cap64");
 if(new Set(refs.map(r=>r.path)).size!==refs.length)throw Error("unique_reference_names");
 for(const r of refs)if(!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,120}$/.test(r.path)||!/^[a-f0-9]{40}$/.test(r.tree)||r.whole!==true||!Array.isArray(r.rows))throw Error("whole_known_reference_required");
 const sorted=refs.slice().sort((a,b)=>a.path+"/"<b.path+"/"?-1:a.path+"/">b.path+"/"?1:0),bytes=[];
 for(const r of sorted){bytes.push(...utf8Bytes("40000 "+r.path+"\0"));for(let i=0;i<40;i+=2)bytes.push(parseInt(r.tree.slice(i,i+2),16));}
 const expectedTree=sha1Bytes(utf8Bytes("tree "+bytes.length+"\0").concat(bytes));
 const request={repository_full_name:repository,tree_elements:refs.map(r=>({path:r.path,mode:"040000",type:"tree",sha:r.tree}))};
 const rows=[];
 for(const r of refs){rows.push({path:r.path,mode:"040000",type:"tree",sha:r.tree});for(const x of r.rows)rows.push({...x,path:r.path+"/"+x.path});}
 const record={phase:"create_called_once",expectedTree,request,rows,refs,maximumCreateCalls:1,NativeCalls:0};
 store(prefix,record);
 try{
  const sdk=await tools.mcp__codex_apps__github_create_tree(request);
  recordGitSDKImmutable(prefix,"create_tree",sdk);store(prefix+":create-sdk",sdk);
  if(sdk.isError===true)throw Error("reference_create_error_preserved");
  if(sdk.structuredContent?.sha!==expectedTree)throw Error("reference_create_exact_SHA");
  record.phase="create_acknowledged";store(prefix,record);
  const got=await tools.mcp__codex_apps__github_fetch({url:"https://api.github.com/repos/"+repository+"/git/trees/"+expectedTree+"?recursive=1"});
  recordGitSDKImmutable(prefix,"recursive_tree",got);store(prefix+":tree-sdk",got);
  if(got.isError===true||typeof got.structuredContent?.content!=="string")throw Error("reference_read_error_preserved");
  const tree=JSON.parse(got.structuredContent.content),audit=gitTreeAudit(tree),wanted=new Map(rows.map(x=>[x.path,x]));
  if(audit.root_sha!==expectedTree||audit.leaf_count!==rows.filter(x=>x.type==="blob").length||audit.trees_verified!==1+rows.filter(x=>x.type==="tree").length)throw Error("reference_merkle");
  if(tree.tree.length!==rows.length||tree.tree.some(x=>{const e=wanted.get(x.path);return !e||x.mode!==e.mode||x.type!==e.type||x.sha!==e.sha||(x.type==="blob"&&x.size!==undefined&&x.size!==e.size);}))throw Error("reference_exact_members");
  const result={tree:expectedTree,whole:true,rows,audit,leafCount:audit.leaf_count,treeCount:audit.trees_verified,bytes:rows.filter(x=>x.type==="blob").reduce((n,x)=>n+x.size,0),NativeCalls:0};
  record.phase="whole";record.result=result;store(prefix,record);store(prefix+":complete",result);return result;
 }catch(error){record.failure={name:error.name,message:String(error.message),originalCreateMustNotReplay:true,NativeCalls:0};store(prefix,record);throw error;}
}
