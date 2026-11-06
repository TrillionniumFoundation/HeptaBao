/* Pure future binding only. No Native, file, network, SDK or child action. */
function deriveActualHomeRuntimeRequest(input, publicRaw) {
 const need=(v,c)=>{if(!v)throw Error(c);};
 need(input&&publicRaw&&Object.keys(publicRaw).sort().join(',')===
      'authorityRaw,expectedJobId,finalStdoutRaw,receiptRaw','exact_derivation_input_fields');
 const a=JSON.parse(publicRaw.authorityRaw),r=JSON.parse(publicRaw.finalStdoutRaw),receipt=JSON.parse(publicRaw.receiptRaw);
 need(a.job_id===publicRaw.expectedJobId&&a.state==='succeeded'&&a.exit_code===0
      &&a.output_complete===true&&a.output_durable===true&&a.terminal_publication_confirmed===true
      &&a.timed_out===false&&a.cancelled===false,'inert_actual_authority_required');
 need(gitBlobMeta(publicRaw.finalStdoutRaw).bytes===a.log_bytes.stdout.stored
      &&a.log_bytes.stdout.seen===a.log_bytes.stdout.stored&&a.log_bytes.stderr.seen===0
      &&a.log_bytes.stderr.stored===0&&a.log_truncated.stdout===false&&a.log_truncated.stderr===false
      &&a.log_errors.stdout===null&&a.log_errors.stderr===null
      &&a.log_synced.stdout===true&&a.log_synced.stderr===true,'actual_full_stream_counts');
 need(r.schema==='heptabao.mac-current-home-launch-inert.r1'&&r.ok===true&&r.outcomeUnknown===false
      &&r.preparedCandidate===true&&r.originalDeadlineMetAfterClosure===true
      &&r.allOwnedCommandsStopped===true&&r.allOwnedDescriptorsClosed===true
      &&r.allReturnedHomeControlDescriptorsClosed===true
      &&r.homeControlInitializationStarted===true&&r.homeControlInitializationComplete===true
      &&r.inputSha256===input.publisherPayload.sha256&&r.inputBytes===input.publisherPayload.bytes,
      'known_post_finally_inert_success');
 need(r.currentPrivateInputsOpened===false&&r.productionSqliteOpened===false&&r.sqliteExecuted===false
      &&r.consumerExecuted===false&&r.serviceStarted===false&&r.inputEntrypointsExecuted===false,
      'inert_only_public_staging');
 const receiptPin=gitBlobMeta(publicRaw.receiptRaw);
 need(r.candidateReceiptSha256===receiptPin.sha256&&r.candidateReceipt.sha256===receiptPin.sha256
      &&r.candidateReceipt.bytes===receiptPin.bytes&&r.candidateReceipt.wholeReadbackVerified===true
      &&r.candidateReceipt.readbackUsesSeparateHeldFd===true&&receipt.ok===false
      &&receipt.preparedCandidate===true&&receipt.schema===r.schema,'actual_prefinal_receipt_not_terminal');
 need(r.commands.allOwnedCommandsStopped===true&&r.commands.unknownCommandCount===0
      &&r.heldT5Final.allDescriptorsClosed===true&&r.heldT5Final.lastAnchorCheckPassed===true
      &&r.heldT5Final.closeErrors.length===0,'original_t5_and_child_closure');
 const hf=r.homeControlFinal;
 need(hf.allReturnedDescriptorsClosed===true&&hf.allFiniteLeavesClosed===true
      &&hf.effectUnknown===false&&hf.openPending===0&&hf.registrationUnknown===false
      &&hf.closeErrors.length===0&&hf.initComplete===true&&hf.rootCreated===true
      &&hf.fdRows.every(x=>x.closeAttempted===true&&x.closed===true),
      'new_home_all_returned_fd_closure');
 const expectedFiles=Object.fromEntries(Object.entries(input.sourcePins).map(([n,p])=>['qa/'+n,{kind:'source',...p}]));
 for(const[n,p]of Object.entries(input.documentPins))expectedFiles[n]={kind:'public_document',...p};
 need(Array.isArray(r.files)&&r.files.length===30&&new Set(r.files.map(x=>x.name)).size===30,
      'actual_thirty_public_targets');
 for(const f of r.files){
  const e=expectedFiles[f.name];need(e&&f.kind===e.kind&&f.bytes===e.bytes&&f.sha256===e.sha256
       &&f.wholeReadbackVerified===true&&f.readbackUsesSeparateHeldFd===true,'every_actual_stage_file');
 }
 const h=r.homeControlBinding,copyNames=['mac_current_server_owner_r1.py','mac_current_phase_owner_r2.py'];
 const decimal9=v=>Array.isArray(v)&&v.length===9&&v.every(x=>typeof x==='string'&&/^[0-9]{1,30}$/.test(x));
 need(h&&Object.keys(h).sort().join(',')==='copies,parents,root,schema'
      &&h.schema==='heptabao.mac-owned-home-control-binding.r1'
      &&h.root.path===input.homeRoot&&decimal9(h.root.identity)
      &&h.root.identity[2]==='501'&&h.root.identity[3]==='20'
      &&h.root.identity[4]==='16832'
      &&Array.isArray(h.parents)&&h.parents.length===3,'actual_home_root_schema_identity');
 const parentPaths=['/','/Users','/Users/qianqi'];
 need(h.parents.every((x,i)=>x.path===parentPaths[i]&&decimal9(x.identity)),'actual_fixed_parents');
 need(Object.keys(h.copies).sort().join(',')===copyNames.slice().sort().join(',')
      &&Array.isArray(r.homeCopies)&&r.homeCopies.length===2
      &&new Set(r.homeCopies.map(x=>x.name)).size===2,'two_home_copies_only');
 for(const name of copyNames){
  const f=h.copies[name],e=input.sourcePins[name],observed=r.homeCopies.find(x=>x.name===name);
  need(f.path===input.homeRoot+'/'+name&&decimal9(f.identity)&&f.identity[2]==='501'
       &&f.identity[3]==='20'&&f.identity[4]==='33152'&&f.identity[5]==='1'
       &&Number(f.identity[6])===e.bytes&&f.bytes===e.bytes&&f.sha256===e.sha256
       &&observed.path===f.path&&observed.bytes===f.bytes&&observed.sha256===f.sha256
       &&JSON.stringify(observed.identity)===JSON.stringify(f.identity)
       &&observed.wholeReadbackVerified===true&&observed.readbackUsesSeparateHeldFd===true,
       'actual_home_copy_whole_and_full9');
 }
 need(JSON.stringify(receipt.homeControlBinding)===JSON.stringify(h)
      &&JSON.stringify(receipt.homeCopies)===JSON.stringify(r.homeCopies),'receipt_actual_home_binding_same');
 const bindingRaw=JSON.stringify(h,null,2)+'\n',sourcePinsRaw=input.sourcePinsRaw;
 need(gitBlobMeta(bindingRaw).bytes<=8192,'original_home_binding_byte_bound');
 const request=JSON.parse(input.originalRuntimeRequestRaw);
 need(request.host==='mac'&&request.timeout_seconds===1080&&request.cwd==='/Users/qianqi'
      &&request.args[0]==='-I'&&request.args[1]==='-S'&&request.args[2]==='-B',
      'original_runtime_envelope');
 request.args=request.args.map(v=>v.split(input.oldRoot).join(input.newRoot));
 function set(flag,value){const matches=request.args.filter(x=>x===flag);need(matches.length===1,'exact_old_flag');request.args[request.args.indexOf(flag)+1]=value;}
 set('--candidate-sha256',input.candidate.sha256);
 set('--public-source-pins-base64',encodeBase64Bytes(utf8Bytes(sourcePinsRaw)));
 set('--public-source-pins-sha256',gitBlobMeta(sourcePinsRaw).sha256);
 request.args.push('--public-home-control-binding-base64',encodeBase64Bytes(utf8Bytes(bindingRaw)),
                   '--public-home-control-binding-sha256',gitBlobMeta(bindingRaw).sha256);
 request.idempotency_key='heptabao-mac-current-five-agent-home-launch-'+input.outer.sha256.slice(0,8)+'-20261106-r3';
 need(request.executable===input.regularPython&&request.args[3]===input.newRoot+'/qa/mac_current_outer_wal_r1.py',
      'actual_regular_interpreter_fresh_outer');
 const requestRaw=JSON.stringify(request,null,2)+'\n';
 return {schema:'heptabao.deferred-actual-home-runtime-binding.v1',bindingRaw,bindingPin:gitBlobMeta(bindingRaw),
         requestRaw,requestPin:gitBlobMeta(requestRaw),nativeSubmitted:false,runtimeGoRequired:true,
         actualSelectedOwnerOrCredentialsNotProvenByStaging:true};
}
