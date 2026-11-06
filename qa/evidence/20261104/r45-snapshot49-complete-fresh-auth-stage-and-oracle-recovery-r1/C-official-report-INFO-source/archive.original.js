/* Full original SDK bytes are immutable by Git-blob hash; aliases are only convenience. */
function recordGitSDKImmutable(prefix,stage,sdk) {
 store(prefix+":pending_sdk",sdk);
 const raw=JSON.stringify(sdk,null,2)+"\n",pin=gitBlobMeta(raw);
 const immutable="original-sdk-by-blob:"+pin.blob,previous=load(immutable);
 if(previous!==undefined && previous!==raw)throw new Error("immutable_SDK_key_collision");
 if(previous===undefined)store(immutable,raw);
 const history=load(prefix+":sdk_history")||[];
 const event={ordinal:history.length+1,stage,pin,immutableStoreKey:immutable};
 history.push(event);store(prefix+":sdk_history",history);
 store(prefix+":sdk_alias:"+stage,event);
 return event;
}

/* Pure Git archival helper. Requires exact public pure_helpers.js symbols:
 * gitBlobMeta, utf8Bytes, utf8Text, sha1Bytes; functions store/load and tools.
 * This is not a Runtime helper and does not satisfy local-first native journaling.
 * A unique key admits one create_tree invocation. Failure never retries mutation.
 */
async function archiveFlatPublicTextsOnce({key,repository,texts}) {
  if(typeof key!=="string"||!/^[a-zA-Z0-9_.-]{1,100}$/.test(key))
    throw new Error("fixed_archive_key");
  if(repository!=="TrillionniumFoundation/HeptaBao")
    throw new Error("fixed_public_repository");
  const prefix="pure_git_once:"+key;
  if(load(prefix)!==undefined) throw new Error("archive_already_admitted_no_mutation_retry");
  const paths=Object.keys(texts).sort();
  if(paths.length<1||paths.length>128) throw new Error("bounded_flat_packet");
  const entries=paths.map(path=>{
    if(!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,160}$/.test(path)||typeof texts[path]!=="string")
      throw new Error("flat_public_text_entry");
    if(utf8Text(utf8Bytes(texts[path]))!==texts[path])
      throw new Error("utf8_exact_roundtrip");
    return {path,...gitBlobMeta(texts[path])};
  });
  if(entries.reduce((a,x)=>a+x.bytes,0)>8388608) throw new Error("bounded_packet_bytes");
  const bytes=[];
  for(const x of entries) {
    bytes.push(...utf8Bytes("100644 "+x.path+"\0"));
    for(let i=0;i<40;i+=2)bytes.push(parseInt(x.blob.slice(i,i+2),16));
  }
  const expectedTree=sha1Bytes(utf8Bytes("tree "+bytes.length+"\0").concat(bytes));
  const request={repository_full_name:repository,tree_elements:entries.map(x=>({
    path:x.path,mode:"100644",type:"blob",content:texts[x.path]
  }))};
  // Full exact input is retained before the single mutation; this store is volatile.
  store(prefix,{phase:"create_tree_admitted_once",expectedTree,entries,request,texts,
                localDurableJournal:false,runtimeAuthorized:false});
  let sdk;
  try { sdk=await tools.mcp__codex_apps__github_create_tree(request); }
  catch(error) {
    store(prefix+":transport_exception",{name:error.name,message:String(error.message)});
    throw error;
  }
  recordGitSDKImmutable(prefix,"create_tree",sdk);
  store(prefix+":create_sdk",sdk);
  if(sdk.isError===true) throw new Error("git_create_returned_error_preserved");
  if(sdk.structuredContent?.sha!==expectedTree)
    throw new Error("git_create_tree_exact_sha");
  const treeSDK=await tools.mcp__codex_apps__github_fetch({
    url:"https://api.github.com/repos/TrillionniumFoundation/HeptaBao/git/trees/"
      +expectedTree+"?recursive=1"});
  recordGitSDKImmutable(prefix,"tree_whole",treeSDK);
  store(prefix+":tree_sdk",treeSDK);
  if(treeSDK.isError===true || typeof treeSDK.structuredContent?.content!=="string")
    throw new Error("git_tree_read_error_preserved");
  const fetchedTree=JSON.parse(treeSDK.structuredContent.content),treeAudit=gitTreeAudit(fetchedTree);
  if(treeAudit.root_sha!==expectedTree||treeAudit.leaf_count!==entries.length
      ||treeAudit.trees_verified!==1)throw new Error("git_expected_flat_tree_merkle");
  const exactMap=new Map(entries.map(x=>[x.path,x.blob]));
  if(!fetchedTree.tree.every(x=>x.type==="blob"&&x.mode==="100644"&&exactMap.get(x.path)===x.sha))
    throw new Error("git_expected_flat_tree_members");
  store(prefix+":tree_whole_verified",treeAudit);
  const verified=[];
  for(let start=0;start<entries.length;start+=2) {
    const results=await Promise.allSettled(entries.slice(start,start+2).map(async x=>{
      let response;
      try { response=await tools.mcp__codex_apps__github_fetch_blob({
        repository_full_name:repository,blob_sha:x.blob}); }
      catch(error) {
        store(prefix+":whole_exception:"+x.path,{name:error.name,message:String(error.message)});
        throw error;
      }
      recordGitSDKImmutable(prefix,"whole:"+x.path,response);
      store(prefix+":whole_sdk:"+x.path,response); // Alias; immutable history is authoritative.
      if(response.isError===true) throw new Error("git_whole_error_preserved:"+x.path);
      const content=response.structuredContent?.content;
      if(typeof content!=="string"||content!==texts[x.path])
        throw new Error("git_whole_exact_bytes:"+x.path);
      const actual=gitBlobMeta(content);
      if(actual.blob!==x.blob||actual.sha256!==x.sha256||actual.bytes!==x.bytes)
        throw new Error("git_whole_all_hashes:"+x.path);
      return {...x,whole:true};
    }));
    store(prefix+":whole_batch:"+start,results.map((r,i)=>r.status==="fulfilled"
      ?{status:r.status,value:r.value}
      :{status:r.status,path:entries[start+i].path,error:String(r.reason)}));
    for(const r of results) {
      if(r.status==="fulfilled")verified.push(r.value);
    }
    if(results.some(r=>r.status==="rejected")) {
      store(prefix+":partial",{expectedTree,verified,remaining:entries.filter(
        x=>!verified.some(v=>v.path===x.path)),mutationMustNotRepeat:true});
      throw new Error("whole_read_incomplete_no_mutation_retry");
    }
  }
  const result={tree:expectedTree,entries:verified,count:entries.length,
    bytes:entries.reduce((a,x)=>a+x.bytes,0),whole:true,
    localDurableJournal:false,runtimeAuthorized:false};
  store(prefix+":complete",result);
  return result;
}
