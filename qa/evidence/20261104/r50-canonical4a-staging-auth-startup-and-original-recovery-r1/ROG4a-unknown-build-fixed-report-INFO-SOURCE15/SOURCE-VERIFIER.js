function verifyUnknownReportInfoSource(input){
 const cases=[],need=(v,n)=>{if(!v)throw new Error(n);cases.push({name:n,pass:true});};
 const meta=gitBlobMeta;
 need(snapshotApply(input.before,input.diff)===input.after,"strict_forward");
 need(snapshotApply(input.after,input.diff,true)===input.before,"strict_inverse");
 need(meta(input.oldRaw).blob==="2d512764d26256fabaaaf7deb3eae41120d92d3e","actual_original_unknown_state_pin");
 const req=JSON.parse(input.requestRaw),requestPin=meta(input.requestRaw);
 need(req.operation.tool==="file_info"&&req.operation.arguments.host==="rog"
  &&req.operation.arguments.path==="/home/qian-qi/hb-4a49405b-controls-20261106-r1/build-tests-r1/result.public.json","one_exact_path_tool");
 const fixtureGo={authorization:"GO",scope:"combined4a_unknown_start_fixed_report_info_only",
  request:requestPin,originalUnknownState:meta(input.oldRaw),maximumInfoAdmissions:1,
  maximumStatusCalls:8,maximumPageCalls:128,pageBytes:8192,payloadCap:1048576,fileSizeCap:4194304};
 let oldWrites=0,toolsAccessed=0;
 const oldSlot="combined_4a49405b_fresh_build_gitfirst_r1";
 function fixture(overrides){
  const m=new Map([[oldSlot,JSON.parse(input.oldRaw)]]);
  const api=new Function("load","store","tools",input.pure+"\n"+input.after+
   "\nreturn {initialize:gfInitializeOnlyAfterRootGO,validate:gfValidateRequest,metadata:gfValidateReportMetadata,state:gfState,slot:GF_SLOT};")(
   k=>m.get(k),(k,v)=>{if(k===oldSlot)oldWrites++;m.set(k,v);},
   new Proxy({}, {get(){toolsAccessed++;throw new Error("no_tools_in_fixture");}}));
  const g={...fixtureGo,...overrides},raw=JSON.stringify(g,null,2)+"\n";
  return {api,m,args:{goRaw:raw,goPin:meta(raw),goWholeReadback:true}};
 }
 function rejected(name,f){let failed=false;try{f();}catch{failed=true;}need(failed,name);}
 const f=fixture();f.api.initialize(f.args);const s=f.api.state();
 need(s.job===null&&s.originalBuildOutcome==="UNKNOWN"&&s.reportMetadata===null,"initialization_needs_no_job_and_infers_no_terminal");
 rejected("second_initialize_refused",()=>f.api.initialize(f.args));
 const bad=fixture({scope:"process_start"});rejected("wrong_go_scope_refused",()=>bad.api.initialize(bad.args));
 const large=fixture({maximumInfoAdmissions:2});rejected("go_start_cap_not_expandable",()=>large.api.initialize(large.args));
 const altered=fixture();altered.m.get(oldSlot).paused=false;
 rejected("changed_original_unknown_state_refused",()=>altered.api.initialize(altered.args));
 f.api.validate(s,"operation_start",req,input.requestRaw);need(true,"exact_info_admission_accepted");
 rejected("process_start_refused",()=>f.api.validate(s,"process_start",req,input.requestRaw));
 for(const tool of ["binary_read","process_status","process_read","process_list"]){
  const q=JSON.parse(input.requestRaw);q.operation.tool=tool;
  rejected(tool+"_admission_refused",()=>f.api.validate(s,"operation_start",q,JSON.stringify(q,null,2)+"\n"));
 }
 const rekey=JSON.parse(input.requestRaw);rekey.idempotency_key+="x";
 rejected("rekey_refused",()=>f.api.validate(s,"operation_start",rekey,JSON.stringify(rekey,null,2)+"\n"));
 s.infoCalled=true;
 rejected("second_info_admission_refused",()=>f.api.validate(s,"operation_start",req,input.requestRaw));
 const id="a".repeat(64);
 s.activeObserver={id,futureClosed:false,nextPageOffset:0,eof:false};
 f.api.validate(s,"operation_status",{operation_id:id},"");
 need(true,"same_id_status_accepted");
 s.infoStatusCalls=8;
 rejected("ninth_status_refused",()=>f.api.validate(s,"operation_status",{operation_id:id},""));
 s.activeObserver.futureClosed=true;
 f.api.validate(s,"operation_result",{operation_id:id,offset:0,limit:8192},"");
 need(true,"closed_contiguous_8k_page_accepted");
 rejected("wrong_operation_id_refused",()=>f.api.validate(s,"operation_result",{operation_id:"b".repeat(64),offset:0,limit:8192},""));
 rejected("skipped_page_refused",()=>f.api.validate(s,"operation_result",{operation_id:id,offset:1,limit:8192},""));
 rejected("page_width_increase_refused",()=>f.api.validate(s,"operation_result",{operation_id:id,offset:0,limit:16384},""));
 s.infoPageCalls=128;
 rejected("129th_page_refused",()=>f.api.validate(s,"operation_result",{operation_id:id,offset:0,limit:8192},""));
 const good={path:req.operation.arguments.path,size:123,sha256:"c".repeat(64),
  version:"66306:1234:123:1794000000000000000:1794000000000000000",mode:384,
  metadata:{mode:384,uid:1000,gid:1000,link_count:1,metadata_platform:"linux"}};
 const v=f.api.metadata(good);
 need(v.metadataOnly&&v.jobIdentityKnown===false&&v.processTerminalProven===false&&v.originalBuildOutcome==="UNKNOWN","valid_metadata_never_proves_process_terminal");
 need(f.api.metadata({...good,sha256:"d".repeat(64)}).sha256==="d".repeat(64),"actual_sha_learned_not_guessed");
 for(const [field,value] of [["path","/other"],["size",0],["size",4194305],["mode",420],["sha256","bad"],["version","66306:1234:124:1:1"]]){
  rejected("bad_"+field+"_"+String(value).slice(0,12),()=>f.api.metadata({...good,[field]:value}));
 }
 for(const [field,value] of [["uid",0],["gid",0],["link_count",2],["mode",420],["metadata_platform","other"]]){
  rejected("bad_metadata_"+field,()=>f.api.metadata({...good,metadata:{...good.metadata,[field]:value}}));
 }
 const native=[...input.after.matchAll(/tools\.(mcp__codex_apps__heptaruntime_[A-Za-z0-9_]+)/g)].map(x=>x[1]);
 need(native.length===3&&native.every(x=>/_operation_(start|status|result)$/.test(x)),"native_dispatch_only_three_original_observer_methods");
 need(oldWrites===0&&toolsAccessed===0,"no_old_context_write_and_no_native_or_git_call");
 return {schema:"heptabao.unknown-report-info-source-checks.r1",cases,passed:cases.length,NativeCalls:0,GitCalls:0,fixtureOnly:true,actualReportMetadata:null};
}
