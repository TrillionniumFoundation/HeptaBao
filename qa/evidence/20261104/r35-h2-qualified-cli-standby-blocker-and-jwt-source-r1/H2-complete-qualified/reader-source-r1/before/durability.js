
async function hlArchive(name,text){
 const B=eval(load("r32_root_helpers_source")+";({save:saveVerifiedPublicBlobJournaled,persist:persistRecoveryText,fb:fetchVerifiedPublicBlob,meta:gitBlobMeta})"),m=B.meta(text);
 try{return await B.save(name,text);}catch(error){
  const first=load("r32_git_write_"+m.blob+"_sdk");
  const firstRaw=JSON.stringify(first??{local_archive_exception:String(error)},null,2)+"\n",ep=B.meta(firstRaw);
  await B.persist("h2-live-archive-first-error-"+m.blob,firstRaw);
  const tsdk=await tools.mcp__codex_apps__github_create_tree({repository_full_name:"TrillionniumFoundation/HeptaBao",tree_elements:[{path:"exact-public-content.txt",mode:"100644",type:"blob",content:text},{path:"original-archive-error.sdk.json",mode:"100644",type:"blob",content:firstRaw}]});
  await B.persist("h2-live-archive-content-tree-"+m.blob,JSON.stringify(tsdk,null,2)+"\n");
  if(tsdk.isError)throw Error("Git content-tree recovery failed "+m.blob);
  const got=await B.fb(m.blob),err=await B.fb(ep.blob);
  if(got.text!==text||err.text!==firstRaw)throw Error("Git identical-content recovery mismatch");
  const incidents=load("h2_live_git_archive_incidents")??[];
  incidents.push({name,content:m,original_error:ep,content_tree_SDK_local:"h2-live-archive-content-tree-"+m.blob+".json",native_replayed:false});
  store("h2_live_git_archive_incidents",incidents);
  await B.persist("h2-live-git-archive-incidents",JSON.stringify(incidents,null,2)+"\n");
  return {name,...m};
 }
}

function hlH(){return eval(load("r32_root_helpers_source")+";({save:hlArchive,persist:persistRecoveryText,lossless:parseLosslessIntegers,unb64,utf8Text,byteString,sha256Latin1,meta:gitBlobMeta})");}
async function hlSync(label){
 if(!/^[A-Za-z0-9._-]+$/.test(label))throw Error("unsafe_label");
 const p="/workspace/scratch/f86faac821c4/r32_recovery/"+label+".json";
 const H=hlH();
 let z=await tools.exec_command({cmd:"python3 - <<'PY'\nimport os\np="+JSON.stringify(p)+"\nf=os.open(p,os.O_RDONLY)\nos.fsync(f)\nos.close(f)\nd=os.open(os.path.dirname(p),os.O_RDONLY|os.O_DIRECTORY)\nos.fsync(d)\nos.close(d)\nPY",max_output_tokens:300,yield_time_ms:1000});
 if(z.exit_code===undefined&&Number.isInteger(z.session_id)){
  const original_session_id=z.session_id,returns=[{kind:"original_exec_yield",result:z}];
  const stateLabel="h2-live-local-fsync-session-"+original_session_id;
  async function journal(){const q={label,original_session_id,returns,complete:z.exit_code!==undefined};store("h2-live_local_fsync_session_"+original_session_id,q);await H.persist(stateLabel,JSON.stringify(q,null,2)+"\n");}
  await journal();
  while(z.exit_code===undefined){
   if(z.session_id!==original_session_id)throw Error("local_fsync_session_identity_changed");
   try{z=await tools.write_stdin({session_id:original_session_id,chars:"",yield_time_ms:1000,max_output_tokens:300});}
   catch(error){returns.push({kind:"original_session_poll_exception",error:String(error)});await journal();throw error;}
   returns.push({kind:"original_session_poll",result:z});await journal();
  }
 }
 if(z.exit_code!==0){await H.persist("h2-live-local-fsync-error-"+label,JSON.stringify(z,null,2)+"\n");store("h2-live_local_fsync_unresolved",{label,result:z});throw Error("local_fsync_not_terminal_zero: "+JSON.stringify(z));}
}
async function hlState(s){
 const H=hlH(),checkpoint=JSON.parse(JSON.stringify(s));
 delete checkpoint.last_result;delete checkpoint.start_native_object;
 checkpoint.last_result_native=s.last_call?.native??null;
 for(const c of checkpoint.calls??[])delete c.request_text;
 for(const o of checkpoint.observations??[]){
  delete o.native_object;delete o.page_base64;
  for(const p of o.pages??[])if(p.call){p.call_label=p.call.label;p.native_page=p.call.native;delete p.call;}
 }
 checkpoint.original_SDKs_are_independent_immutable_files=true;
 await H.persist("h2-live-execution-state",JSON.stringify(checkpoint,null,2)+"\n");
 await hlSync("h2-live-execution-state");store("h2_live_execution_state",s);
}
