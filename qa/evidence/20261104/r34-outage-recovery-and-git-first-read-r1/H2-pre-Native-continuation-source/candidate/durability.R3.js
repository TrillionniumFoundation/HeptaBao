
/* SOURCE ONLY: a new root GO is required before bootstrap or any Native call.
   Scope: the seven original H2 public result ranges after the already closed offset 0.
   Every exported action is invoked through hgRun so caught failures retain V8 state.
   Git uncertainty permits exact expected-object reads only, never another create. */
function hlH(){return eval(load("h2_live_git_first_pure_source")+";({lossless:parseLosslessIntegers,unb64,utf8Text,utf8Bytes,byteString,sha256Latin1,sha1Bytes,treeAudit:gitTreeAudit,meta:gitBlobMeta})");}
function hgTree(entries){
 const H=hlH(),dirs=new Map([["",new Map()]]),leaves=new Set();
 for(const e of entries){
  if(!/^[A-Za-z0-9._/-]+$/.test(e.path)||e.path.split("/").some(p=>!p||p==="."||p==="..")||leaves.has(e.path)||!/^[0-9a-f]{40}$/.test(e.blob))throw Error("Git_entry");
  leaves.add(e.path);const p=e.path.split("/");let parent="";
  for(let i=0;i<p.length-1;i++){const d=parent?parent+"/"+p[i]:p[i];if(leaves.has(d))throw Error("Git_file_directory_collision");if(!dirs.has(d))dirs.set(d,new Map());dirs.get(parent).set(p[i],{name:p[i],type:"tree",dir:d});parent=d;}
  if(dirs.has(e.path)||dirs.get(parent).has(p.at(-1)))throw Error("Git_name_collision");
  dirs.get(parent).set(p.at(-1),{name:p.at(-1),type:"blob",sha:e.blob});
 }
 const hashes=new Map();
 for(const d of [...dirs.keys()].sort((a,b)=>b.split("/").length-a.split("/").length||b.length-a.length)){
  const es=[...dirs.get(d).values()].sort((a,b)=>{const x=H.utf8Bytes(a.name+(a.type==="tree"?"/":"")),y=H.utf8Bytes(b.name+(b.type==="tree"?"/":""));for(let i=0;i<Math.min(x.length,y.length);i++)if(x[i]!==y[i])return x[i]-y[i];return x.length-y.length;});
  const bytes=[];for(const e of es){const sha=e.type==="tree"?hashes.get(e.dir):e.sha;if(!sha)throw Error("Git_child_tree");bytes.push(...H.utf8Bytes((e.type==="tree"?"40000":"100644")+" "+e.name+"\0"));for(let i=0;i<40;i+=2)bytes.push(parseInt(sha.slice(i,i+2),16));}
  hashes.set(d,H.sha1Bytes(H.utf8Bytes("tree "+bytes.length+"\0").concat(bytes)));
 }
 return {root:hashes.get(""),trees:hashes.size};
}
function hgRetainGitReadSDK(kind,object_id,sdk){
 const raw=JSON.stringify(sdk,null,2)+"\n",pin=hlH().meta(raw),key="h2_live_git_first_Git_immutable_SDK_"+pin.blob,old=load(key);
 if(old!==undefined&&old!==raw)throw Error("Git_SDK_immutable_identity_collision");
 store(key,raw);
 const indexKey="h2_live_git_first_Git_"+kind+"_history_"+object_id,history=load(indexKey)??[];
 history.push({observation:history.length,immutable_key:key,...pin});store(indexKey,history);
 store("h2_live_git_first_Git_"+kind+"_SDK_"+object_id,raw);return {immutable_key:key,...pin};
}
async function hgBlob(pin){
 const sdk=await tools.mcp__codex_apps__github_fetch_blob({repository_full_name:"TrillionniumFoundation/HeptaBao",blob_sha:pin.blob});
 hgRetainGitReadSDK("read",pin.blob,sdk);
 if(sdk.isError||typeof sdk.structuredContent?.content!=="string")throw Error("Git_blob_read_unconfirmed:"+pin.blob);
 const text=sdk.structuredContent.content,m=hlH().meta(text);
 if(m.blob!==pin.blob||pin.bytes!==undefined&&m.bytes!==pin.bytes||pin.sha256!==undefined&&m.sha256!==pin.sha256)throw Error("Git_blob_identity");
 store("h2_live_local_text_"+m.blob,text);return {...m,text};
}
async function hgVerifyArchive(plan){
 const sdk=await tools.mcp__codex_apps__github_fetch({url:"https://api.github.com/repos/TrillionniumFoundation/HeptaBao/git/trees/"+plan.expected_tree+"?recursive=1"});
 hgRetainGitReadSDK("tree",plan.expected_tree,sdk);
 if(sdk.isError||typeof sdk.structuredContent?.content!=="string")throw Error("Git_tree_read_unconfirmed");
 const tree=JSON.parse(sdk.structuredContent.content),merkle=hlH().treeAudit(tree),leaves=tree.tree.filter(x=>x.type==="blob");
 if(tree.sha!==plan.expected_tree||leaves.length!==plan.entries.length||plan.entries.some(p=>!leaves.some(x=>x.path===p.path&&x.sha===p.blob&&x.size===p.bytes&&x.mode==="100644")))throw Error("Git_exact_tree");
 const unique=[...new Map(plan.entries.map(p=>[p.blob,p])).values()];
 for(let i=0;i<unique.length;i+=8){
  const part=unique.slice(i,i+8),rs=await Promise.allSettled(part.map(p=>hgBlob(p)));
  const results=[],failures=[];
  for(let j=0;j<rs.length;j++){
   const r=rs[j],p=part[j],ok=r.status==="fulfilled"&&r.value.text===load("h2_live_git_first_expected_text_"+p.blob);
   const row={path:p.path,blob:p.blob,status:r.status,whole_exact:ok,error:r.status==="rejected"?String(r.reason):ok?null:"whole_text_mismatch"};
   results.push(row);if(!ok)failures.push(row);
  }
  const raw=JSON.stringify({expected_tree:plan.expected_tree,batch_start:i,results},null,2)+"\n",pin=hlH().meta(raw),key="h2_live_git_first_Git_batch_results_"+pin.blob;
  store(key,raw);
  const historyKey="h2_live_git_first_Git_batch_history_"+plan.expected_tree,history=load(historyKey)??[];
  history.push({observation:history.length,batch_start:i,immutable_key:key,...pin});store(historyKey,history);
  if(failures.length)throw Error("Git_whole_readback_batch:"+JSON.stringify(failures));
 }
 plan.phase="whole_verified";plan.merkle=merkle;store("h2_live_git_first_archive_"+plan.expected_tree,plan);
 return {tree:plan.expected_tree,files:plan.entries.length,bytes:plan.entries.reduce((a,p)=>a+p.bytes,0),merkle,Git_batch_SDK:plan.create_SDK_pin};
}

function hgEffectiveArchiveBlock(){
 const b=load("h2_live_git_first_archive_blocked"),r=load("h2_live_git_first_armed_page_recovery");
 if(!b)return null;
 if(r?.schema==="heptabao.h2-live.explicit-armed-page-recovery.v1"&&r.recovery_tree==="811692431bf219ea0a217a95c43eaab871e75562"&&r.original_block_sha256==="7505abc72cc2f10c45b0846d95547fd874471e0884b392d489adc06a3aef1db3"&&r.new_root_GO?.blob&&r.old_create_outcome==="UNKNOWN"&&hlH().meta(JSON.stringify(b,null,2)+"\n").sha256===r.original_block_sha256)return null;
 return b;
}
function hgRetainHistoricalBlockAfterVerifiedArchive(){
 const r=load("h2_live_git_first_armed_page_recovery");
 if(r?.schema==="heptabao.h2-live.explicit-armed-page-recovery.v1")store("h2_live_git_first_archive_blocked",r.original_block);
 else store("h2_live_git_first_archive_blocked",null);
}

async function hgArchive(entries,purpose){
 const H=hlH(),pins=entries.map(e=>({path:e.path,...H.meta(e.text)})),geometry=hgTree(pins);
 let plan=load("h2_live_git_first_archive_"+geometry.root);
 if(plan?.phase==="whole_verified")return {tree:plan.expected_tree,files:plan.entries.length,bytes:plan.entries.reduce((a,p)=>a+p.bytes,0),merkle:plan.merkle,Git_batch_SDK:plan.create_SDK_pin};
 if(hgEffectiveArchiveBlock()||plan)throw Error("Git_reconcile_exact_objects_only");
 for(let i=0;i<pins.length;i++)store("h2_live_git_first_expected_text_"+pins[i].blob,entries[i].text);
 plan={schema:"heptabao.h2-live.Git-first.archive-intent.v1",purpose,expected_tree:geometry.root,entries:pins,phase:"create_intent",create_attempts:0};
 store("h2_live_git_first_archive_"+geometry.root,plan);
 notify({Git_archive_intent:purpose,expected_tree:geometry.root,files:pins.length});
 try{
  plan.create_attempts=1;plan.phase="create_called";store("h2_live_git_first_archive_"+geometry.root,plan);
  const sdk=await tools.mcp__codex_apps__github_create_tree({repository_full_name:"TrillionniumFoundation/HeptaBao",tree_elements:entries.map(e=>({path:e.path,mode:"100644",type:"blob",content:e.text}))});
  const raw=JSON.stringify(sdk,null,2)+"\n";store("h2_live_git_first_Git_create_SDK_"+geometry.root,raw);plan.create_SDK_pin=H.meta(raw);
  store("h2_live_git_first_archive_"+geometry.root,plan);
  if(sdk.isError||sdk.structuredContent?.sha!==geometry.root)throw Error("Git_create_unconfirmed");
  const result=await hgVerifyArchive(plan);hgRetainHistoricalBlockAfterVerifiedArchive();return result;
 }catch(e){
  plan.phase="unconfirmed";plan.error=String(e);store("h2_live_git_first_archive_"+geometry.root,plan);
  store("h2_live_git_first_archive_blocked",{expected_tree:geometry.root,entries:pins,error:String(e),only_exact_read_reconcile:true});
  throw e;
 }
}
async function hgReconcile(expected_tree){
 const b=load("h2_live_git_first_archive_blocked"),p=load("h2_live_git_first_archive_"+expected_tree);
 if(!b||b.expected_tree!==expected_tree||!p||p.create_attempts!==1)throw Error("Git_exact_pending_plan_required");
 const out=await hgVerifyArchive(p);hgRetainHistoricalBlockAfterVerifiedArchive();
 text({Git_reconciliation:out,Native_replayed:false,create_repeated:false,automatic_continuation:false});return out;
}
async function hlArchive(name,text){
 const m=hlH().meta(text);store("h2_live_git_first_expected_text_"+m.blob,text);
 const a=await hgArchive([{path:"original.txt",text}],"single:"+name);
 store("h2_live_local_text_"+m.blob,text);return {name,...m,archive_tree:a.tree,external_whole:true};
}
async function hlState(s){
 const checkpoint=JSON.parse(JSON.stringify(s));
 delete checkpoint.last_result;delete checkpoint.start_native_object;
 checkpoint.last_result_native=s.last_call?.native??null;
 for(const c of checkpoint.calls??[])delete c.request_text;
 for(const o of checkpoint.observations??[]){delete o.native_object;delete o.page_base64;for(const p of o.pages??[])if(p.call){p.call_label=p.call.label;p.native_page=p.call.native;delete p.call;}}
 checkpoint.original_SDKs_are_independent_immutable_files=true;
 checkpoint.storage_protocol="Git-first; no executor dependency";
 store("h2_live_git_first_state_shadow",s);
 const pin=await hlArchive("h2-live-execution-state",JSON.stringify(checkpoint,null,2)+"\n");
 store("h2_live_git_first_state_checkpoint",pin);store("h2_live_execution_state",s);
}
async function hgRun(action,arg){
 try{
  if(hgEffectiveArchiveBlock()&&action!=="reconcile-Git"&&action!=="continue-armed-page")throw Error("Git_unknown_all_actions_blocked_except_exact_read_reconcile");
  let out;
  if(action==="prepare")out=await lp(arg.label,arg.tool,arg.request);
  else if(action==="submit")out=await ls();
  else if(action==="status")out=await laStatus();
  else if(action==="page")out=await laPage();
  else if(action==="finish")out=await lf();
  else if(action==="accept-range")out=await hgAcceptRange();
  else if(action==="bootstrap")out=await hgBootstrap(arg);
  else if(action==="reconcile-Git")out=await hgReconcile(arg);
  else if(action==="resume-returned")out=await lr();
  else if(action==="continue-armed-page")out=await hgContinueArmedPage(arg);
  else throw Error("closed_action_set");
  text({Git_first_action:action,ok:true});return out;
 }catch(e){
  const shadow=load("h2_live_git_first_state_shadow")??load("h2_live_execution_state");
  if(shadow){if(!hgEffectiveArchiveBlock()){shadow.halted=true;shadow.Git_first_protocol_error={action,error:String(e)};}store("h2_live_execution_state",shadow);}
  const errors=load("h2_live_git_first_errors")??[];
  errors.push({action,error:String(e),archive_blocked:load("h2_live_git_first_archive_blocked"),Native_returned_unparsed:!!load("h2_live_git_first_returned")});
  store("h2_live_git_first_errors",errors);
  text({Git_first_action:action,ok:false,error:String(e),new_Native_calls_forbidden:true});
  return {ok:false,error:String(e)};
 }
}
