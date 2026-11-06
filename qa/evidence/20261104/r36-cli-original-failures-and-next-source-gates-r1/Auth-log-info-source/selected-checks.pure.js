const pure=eval(load("owner_pure_source")+"\n;({pin:gitBlobMeta})");
const journal=load("owner_log_info_journal_source");
const guard=eval(load("owner_pure_source")+"\n"+journal+"\n;gfValidateRequest");
const derive=eval(load("owner_pure_source")+"\n"+load("owner_log_help_deriver_source")+"\n;deriveOwnedLogHelp");
const requestRaw=load("owner_log_info_exact_request"),request=JSON.parse(requestRaw);
const templateRaw=load("owner_log_help_template_source");
const output={schema:"heptabao.log-info-help.selected-pure-checks.r1",
  actualNativeCalls:0,actualFilesystemCalls:0,actualSignals:0,actualChildProcesses:0,
  actualLogToolExecuted:false,pythonTemplateExecutedOrCompiled:false,checks:[]};
function pass(name,fn){fn();output.checks.push({name,pass:true});}
function reject(name,fn){let rejected=false;try{fn();}catch(_){rejected=true;}if(!rejected)throw Error(name);output.checks.push({name,pass:true});}
const fresh=()=>({paused:false,nativeCallInFlight:false,pending:null,
  onlyFixedLogFileInfo:true,job:null,activeObserver:null,completedObservers:[],calls:{}});
pass("exact_unique_file_info_allowed",()=>guard(fresh(),"operation_start",request,requestRaw));
reject("process_start_refused",()=>guard(fresh(),"process_start",{}, "{}"));
reject("different_path_refused",()=>{const q=JSON.parse(requestRaw);q.operation.arguments.path="/usr/bin/other";guard(fresh(),"operation_start",q,JSON.stringify(q,null,2)+"\n");});
reject("second_metadata_admission_refused",()=>{const s=fresh();s.calls.first={kind:"operation_start"};guard(s,"operation_start",request,requestRaw);});
const op="a".repeat(64),ack={operation_id:op,tool_name:"file_info",automatic_retry:false,idempotency_binding_retained:true},
 status={operation_id:op,tool_name:"file_info",async_state:"completed",result_state:"stored_observed",owned_future_active:false,payload_available:true},
 info={path:"/usr/bin/log",size:32,sha256:"b".repeat(64),version:"1:2:32:1234567890123456789:1234567890123456790",
  mode:493,metadata:{metadata_platform:"darwin",uid:0,gid:0,mode:493,link_count:78}};
const args=()=>({templateRaw,expectedTemplate:pure.pin(templateRaw),metadataRequestRaw:requestRaw,
 expectedMetadataRequest:pure.pin(requestRaw),ackNativeRaw:JSON.stringify(ack),
 statusNativeRaw:JSON.stringify(status),infoNativeRaw:JSON.stringify(info)});
pass("fake_root_hardlinked_tool_derives_full9_and_stdin",()=>{const r=derive(args()),q=JSON.parse(r.requestRaw);
 if(r.binding.identity.join(":")!=="1:2:0:0:33261:78:32:1234567890123456789:1234567890123456790"
   ||q.stdin!==r.source||"stdin_text" in q||r.runtimeAuthorized!==false
   ||r.source.replace("BINDING_READY = True\nLOG_BINDING = "+JSON.stringify(r.binding)+"\n",
       "BINDING_READY = False\nLOG_BINDING = None\n")!==templateRaw)throw Error("binding");});
reject("version_size_mismatch_refused",()=>{const a=args();a.infoNativeRaw=JSON.stringify({...info,size:33});derive(a);});
reject("nonroot_tool_refused",()=>{const a=args();a.infoNativeRaw=JSON.stringify({...info,metadata:{...info.metadata,uid:501}});derive(a);});
reject("active_future_refused",()=>{const a=args();a.statusNativeRaw=JSON.stringify({...status,owned_future_active:true});derive(a);});
output.passed=output.checks.length;output.complete=true;
store("owner_log_info_help_selected_checks_actual",output);
const raw=JSON.stringify(output,null,2)+"\n";store("owner_log_info_help_selected_checks_stdout",raw);text(raw);