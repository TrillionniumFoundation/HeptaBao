async function saveGitFirstPublicBatch(label,items){
 if(!/^[A-Za-z0-9._-]+$/.test(label)||!Array.isArray(items)||!items.length)throw Error("invalid batch");
 const records=items.map(x=>({name:x.name,...gitBlobMeta(x.text)}));
 if(new Set(records.map(x=>x.name)).size!==records.length||records.some(x=>!/^[A-Za-z0-9._-]+$/.test(x.name)||x.name==="ARCHIVE-INTENT.public.json"))throw Error("unsafe or duplicate item");
 const dataTree=immediateTreeSha(records.map(x=>({path:x.name,mode:"100644",type:"blob",sha:x.blob})));
 const intentText=JSON.stringify({schema:"heptabao.public-Git-first-archive-intent.v1",label,records,expected_data_tree:dataTree,executor_filesystem_used:false,Runtime_calls:0,mutation_replay_allowed:false},null,2)+"\n";
 const all=[...items,{name:"ARCHIVE-INTENT.public.json",text:intentText}],members=all.map(x=>({name:x.name,...gitBlobMeta(x.text)}));
 const expected=immediateTreeSha(members.map(x=>({path:x.name,mode:"100644",type:"blob",sha:x.blob})));
 const key="r34_gitfirst_batch_"+label;let state=load(key);
 if(state&&state.expected_tree!==expected)throw Error("label content changed");
 if(state?.wholeVerified)return state.result;
 if(!state){state={label,expected_tree:expected,records:members,items:all,phase:"prepared",SDKs:[]};store(key,state);}
 function keep(kind,sdk){const raw=JSON.stringify(sdk,null,2)+"\n",m=gitBlobMeta(raw);store("r34_gitfirst_SDK_"+m.blob,{kind,text:raw,...m});state.SDKs.push({kind,...m});store(key,state);return raw;}
 if(state.phase==="prepared"){
   state.phase="mutation_submitted";store(key,state);
   let sdk;try{sdk=await tools.mcp__codex_apps__github_create_tree({repository_full_name:"TrillionniumFoundation/HeptaBao",tree_elements:all.map(x=>({path:x.name,mode:"100644",type:"blob",content:x.text}))});}
   catch(e){state.original_mutation_exception=String(e);state.phase="mutation_outcome_unknown";store(key,state);throw e;}
   keep("original-create-tree",sdk);
   if(sdk.isError){state.phase="mutation_returned_error";store(key,state);throw Error("Git tree creation returned error; only exact-tree read-only reconciliation permitted");}
   let sc=sdk.structuredContent;if(typeof sc?.content==="string")sc=JSON.parse(sc.content);
   if(sc?.sha!==expected){state.phase="mutation_response_mismatch";store(key,state);throw Error("created tree SHA mismatch");}
   state.phase="mutation_acknowledged";store(key,state);
 }else{state.read_only_reconciliation=true;store(key,state);}
 const sdk=await tools.mcp__codex_apps__github_fetch({url:"https://api.github.com/repos/TrillionniumFoundation/HeptaBao/git/trees/"+expected+"?recursive=1"});
 keep("exact-tree-read",sdk);if(sdk.isError)throw Error("exact tree read failed");
 const t=JSON.parse(sdk.structuredContent.content);
 if(t.sha!==expected||t.truncated||t.tree.length!==members.length)throw Error("tree envelope mismatch");
 const merkle=gitTreeAudit(t);
 for(const e of t.tree){const p=members.find(x=>x.name===e.path);if(!p||e.type!=="blob"||e.mode!=="100644"||e.sha!==p.blob||e.size!==p.bytes)throw Error("tree member mismatch "+e.path);}
 const failures=[];
 for(let i=0;i<members.length;i+=4){
   const part=members.slice(i,i+4),r=await Promise.allSettled(part.map(async p=>{
     const reply=await tools.mcp__codex_apps__github_fetch_blob({repository_full_name:"TrillionniumFoundation/HeptaBao",blob_sha:p.blob});
     keep("whole-blob-read-"+p.name,reply);if(reply.isError)throw Error("blob read error "+p.name);
     const txt=reply.structuredContent?.content;if(typeof txt!=="string")throw Error("missing blob content "+p.name);
     const meta=gitBlobMeta(txt);if(meta.blob!==p.blob||meta.bytes!==p.bytes||meta.sha256!==p.sha256||txt!==all.find(x=>x.name===p.name).text)throw Error("whole blob mismatch "+p.name);
     store("r32_recovered_blob_"+p.blob,{...meta,text:txt});return p;
   }));
   for(let j=0;j<r.length;j++)if(r[j].status!=="fulfilled")failures.push({name:part[j].name,error:String(r[j].reason)});
 }
 if(failures.length){state.whole_read_failures=failures;store(key,state);throw Error(JSON.stringify(failures));}
 const result={tree:expected,records:members,data_records:records,merkle,wholeVerified:true,external_native_replies_parsed_by_this_helper:false,executor_filesystem_used:false,Runtime_calls:0,original_create_count:1,read_only_reconciliation:state.read_only_reconciliation===true,SDKs:state.SDKs};
 state.phase="whole_verified";state.wholeVerified=true;state.result=result;store(key,state);store(label,result);return result;
}