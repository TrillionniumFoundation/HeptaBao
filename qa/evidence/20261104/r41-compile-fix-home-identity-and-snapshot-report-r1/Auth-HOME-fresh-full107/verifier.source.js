
function verifyFreshHomeAuthSource(input){
 const checks=[];const ok=(name,value)=>{checks.push({name,passed:value===true});if(value!==true)throw Error(name);};
 const {before,after,dispatch,home,deriver,baselinePins}=input;
 const norm=s=>s.split('mac-authbus-4e808-current-home-launch-r1').join('mac-authbus-4e808-current-owner-bind-r1');
 const functional=new Set(['mac_owned_launchd_r3.py','mac_current_server_owner_r1.py','mac_current_phase_owner_r2.py','mac_current_outer_wal_r1.py']);
 const changed=[];let exact=0,rootOnly=0;
 ok('22_exact_names',Object.keys(before).length===22&&JSON.stringify(Object.keys(before).sort())===JSON.stringify(Object.keys(after).sort()));
 for(const name of Object.keys(before)){
  ok('baseline_whole_'+name,gitBlobMeta(before[name]).blob===baselinePins[name].blob&&gitBlobMeta(before[name]).sha256===baselinePins[name].sha256);
  ok('no_old_runtime_root_'+name,!after[name].includes('mac-authbus-4e808-current-owner-bind-r1'));
  ok('current_source_pin_'+name,gitBlobMeta(after[name]).sha256===dispatch.pins[name][1]&&gitBlobMeta(after[name]).bytes===dispatch.pins[name][0]);
  if(after[name]===before[name])exact++;
  else {changed.push(name);if(!functional.has(name)){ok('root_literal_only_'+name,norm(after[name])===before[name]);rootOnly++;}}
 }
 ok('exact_delta_partition',exact===11&&rootOnly===7&&changed.length===11);
 const payload=JSON.parse(dispatch.payloadRaw),request=JSON.parse(dispatch.requestRaw);
 ok('native_not_submitted',dispatch.NativeCalls===0&&dispatch.runtimeExactRequest===null&&dispatch.actualHomeBinding===null&&dispatch.readyForRuntime===false);
 ok('correct_stdin_key',typeof request.stdin==='string'&&!Object.hasOwn(request,'stdin_text'));
 ok('inert_exact_argv',request.host==='mac'&&request.cwd==='/Users/qianqi'&&request.timeout_seconds===60&&request.args.length===5&&request.args.slice(0,4).join('|')==='-I|-S|-B|-c'&&request.args[4]===dispatch.source);
 ok('inert_regular_python',request.executable==='/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14');
 ok('stdin_exact',request.stdin===dispatch.payloadRaw&&gitBlobMeta(dispatch.payloadRaw).sha256===dispatch.payloadPin.sha256);
 for(const[name,raw]of Object.entries(after))ok('payload_whole_'+name,utf8Text(unb64(payload.files[name]))===raw);
 for(const[name,raw]of Object.entries(dispatch.documents))ok('public_doc_whole_'+name,utf8Text(unb64(payload.documents[name]))===raw);
 ok('22_sources_8_documents',Object.keys(payload.files).length===22&&Object.keys(payload.documents).length===8);
 ok('python_count_still_18',Object.keys(after).filter(n=>n.endsWith('.py')).length===18);
 const candidate=JSON.parse(dispatch.candidateRaw);
 ok('all_candidate_pins',Object.entries(after).every(([n,t])=>candidate.sourcePins[n]===gitBlobMeta(t).sha256));
 ok('actual_home_binding_deferred',candidate.homeControl.bindingRequiredAtRuntime===true&&candidate.homeControl.privateInputsRemainOnT5===true);
 const m=after['mac_owned_launchd_r3.py'],s=after['mac_current_server_owner_r1.py'],p=after['mac_current_phase_owner_r2.py'],o=after['mac_current_outer_wal_r1.py'];
 ok('identical_home_definition_in_manager',m.includes(home));
 ok('identical_home_definition_in_publisher',dispatch.source.includes(home));
 ok('home_fixed_root',home.includes("HOME_CONTROL=Path('/Users/qianqi/heptabao-mac-authbus-4e808-home-launch-20261106-r1')"));
 ok('home_only_fixed_copies',home.includes("HOME_COPY_NAMES=('mac_current_server_owner_r1.py','mac_current_phase_owner_r2.py')"));
 for(const c of ['HOME_FD_ATTEMPTS=64','HOME_METADATA_CALLS=4096','HOME_READ_CALLS=256','HOME_READ_BYTES=2*1024*1024','HOME_WRITE_CALLS=64','HOME_WRITE_BYTES=131072'])ok('new_cap_'+c,home.includes(c));
 ok('no_scanning_or_child_in_home',!/\b(os\.(listdir|scandir|walk|system|fork|exec\w*)|subprocess|socket|sqlite3|requests)\b/.test(home));
 ok('root_mkdir_once_site',(home.match(/os\.mkdir\(/g)||[]).length===1&&home.indexOf('self.root_creation_attempted=True')<home.indexOf('os.mkdir('));
 ok('create_only_leaf',home.includes('os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC'));
 ok('open_attempt_reserved',home.indexOf('self.open_attempts+=1;self.open_pending+=1')<home.indexOf('try:fd=os.open('));
 ok('oserror_no_return_narrow',home.includes("try:fd=os.open(name,flags,mode,dir_fd=parent)\n            except OSError:\n                self.open_pending-=1\n                raise\n            try:"));
 ok('returned_registration_unknown',home.includes("except BaseException:\n                self.registration_unknown=True\n                raise"));
 ok('unknown_in_final_fd_conjunction',home.includes('self.open_pending==0 and not self.registration_unknown and not self.close_errors'));
 ok('close_loop_protected',home.includes("with self.critical():\n            for row in reversed(self.rows):self._close_one(row)\n            self.closed=True"));
 ok('once_close_marker_first',home.indexOf("row['closeAttempted']=True")<home.indexOf("try:os.close(row['fd'])"));
 ok('returned_bytes_counted',home.indexOf("self.counts['readBytes']+=len(raw)")<home.indexOf("need(len(raw)<=count"));
 ok('whole_eof_preflight',home.includes("self.counts['readBytes']+info.st_size+1<=HOME_READ_BYTES"));
 ok('zero_read_hard_refusal',home.includes("need(bool(block),'home_nonempty_progress');raw.extend(block)"));
 ok('init_not_complete_before_whole',home.indexOf("self.init_complete=True")>home.indexOf("'home_actual_copy_whole_before_private_inputs'"));
 ok('no_dynamic_stderr_read',home.includes("not name.endswith('.stderr.private')"));
 ok('same_held_prefix_twice',home.includes("self._read(row['fd'],len(raw),0)==raw"));
 ok('shared_parent_first5_not_inventory',home.includes("actual[:5]==row['identity'][:5]")&&home.includes("'directoryContentsExhaustivelyInventoried':False"));
 ok('root_full9_before_runtime_effects',home.includes("ident==self._identity(binding['root']['identity'])"));
 ok('all_private_plans_stay_t5',m.includes("path=ROOT/'launchd'/(generation+'.private.json')")&&m.includes("self.guard.write_new(ROOT/'launchd'/(entry['generation']+'.admitted.private.json')"));
 ok('manager_initial_home_cwd',m.includes("'WorkingDirectory':str(HOME_CONTROL)"));
 ok('manager_regular_launcher',m.includes("return [PYTHON_LAUNCHER,'-I','-S','-B',str(home_wrapper),*common]"));
 ok('home_copy_is_whole_t5_equal',m.includes("need(self.home.read(home_wrapper,1048576)==raw"));
 ok('server_held_chdir_before_private',s.indexOf('os.fchdir(work_fd)')<s.indexOf("report['ownedPrivateInputReadAttempted']=True"));
 ok('phase_held_chdir_before_private',p.indexOf('os.fchdir(work_fd)')<p.indexOf('raw=private_read(args.plan)'));
 ok('server_kernel_and_launcher_distinct',s.includes("self_identity['executable']==PYTHON_KERNEL_IMAGE")&&s.includes("str(Path(sys.executable).resolve())==PYTHON_LAUNCHER"));
 ok('phase_kernel_and_launcher_distinct',p.includes("self_identity['executable']==PYTHON_KERNEL_IMAGE")&&p.includes("str(Path(sys.executable).resolve())==PYTHON_LAUNCHER"));
 ok('manager_kernel_image_field',m.includes("observed['executable']==PYTHON_KERNEL_IMAGE"));
 ok('exact78_still_failure',m.includes("name=='last exit code' and typed_value=='78: EX_CONFIG'")&&m.includes("typed_value='78'")&&m.includes("need(state.get('last exit code')==0,'actual_launchd_phase_exit_zero')"));
 ok('home_gate_before_private_current_inputs',o.indexOf('home_control.__init__(')<o.indexOf('inputs=Inputs(')&&o.indexOf('home_init_complete=True')<o.indexOf("report['productionCaptureAttempted']=True"));
 ok('outer_home_retained_before_init',o.includes('home_init_started=True;home_control=HomeControl.__new__(HomeControl)'));
 ok('publisher_home_retained_before_init',dispatch.source.includes('home_init_started=True;home=HomeControl.__new__(HomeControl)'));
 ok('outer_final_home_unknown',o.includes('or not manager_closed or not helpers_closed or not input_closed or not home_closed'));
 ok('home_close_after_manager_cleanup',o.indexOf('home_control.close()')>o.indexOf('manager.abort_cleanup_once()'));
 ok('home_close_before_report_publish',o.indexOf('home_control.close()')<o.indexOf("candidate_result=guard.write_new(ROOT/'outer-native-r1/result.public.json'"));
 ok('stage_compile_before_home',dispatch.source.indexOf("compile(ast.parse(content,filename=name)")<dispatch.source.indexOf('home.__init__('));
 ok('stage_no_business_main',dispatch.source.includes("'inputEntrypointsExecuted']=False")&&!dispatch.source.includes('OwnedLaunchd('));
 ok('inert_old45_30_clip',dispatch.source.includes('UNTIL=START+45.0')&&dispatch.source.includes('until=min(UNTIL,time.monotonic()+30)'));
 function topDef(src,name){
  const lines=src.split('\n'),start=lines.findIndex(x=>x.startsWith('def '+name+'('));
  if(start<0)throw Error('definition_not_found:'+name);
  let i=start+1;while(i<lines.length&&(lines[i]===''||/^\s/.test(lines[i])||lines[i].startsWith('#')))i++;
  return lines.slice(start,i).join('\n').trimEnd();
 }
 const names=[...before['mac_current_outer_wal_r1.py'].matchAll(/^def ([A-Za-z_][A-Za-z0-9_]*)\(/gm)].map(x=>x[1]).filter(x=>x!=='main');
 for(const n of names)ok('outer_nonmain_exact_'+n,norm(topDef(o,n))===topDef(before['mac_current_outer_wal_r1.py'],n));
 for(const name of ['mac_current_server_owner_r1.py','mac_current_phase_owner_r2.py']){
  const ns=[...before[name].matchAll(/^def ([A-Za-z_][A-Za-z0-9_]*)\(/gm)].map(x=>x[1]).filter(x=>x!=='main');
  for(const n of ns)ok(name+'_old_def_'+n,norm(topDef(after[name],n))===topDef(before[name],n));
 }
 for(const name of ['token_lifecycle_before','token_lifecycle','bootstrap_api','canonical_and_inbox'])
  ok('trusted_path_whole_'+name,norm(topDef(o,name))===topDef(before['mac_current_outer_wal_r1.py'],name));
 ok('renew_extension_after_inverse',o.indexOf("check('both_actual_renewal_expiries_increased'")>o.indexOf("phase_results.append(manager.run_phase('cold-new-process-inverse'))"));
 ok('all_original_proof_bodies',Object.entries(input.originalDocuments).filter(([n])=>n.startsWith('proofs/')).every(([n,t])=>dispatch.documents[n]===t));
 const beforeCandidate=JSON.parse(input.originalDocuments['candidate-current-manager-wal-r1.public.json']);
 for(const k of ['sourceCommit','sourceTree','syntheticBinding','nativeBinding','walBinding','publicVolumeAnchorSha256','utilityPins','budgets'])ok('candidate_unchanged_'+k,JSON.stringify(candidate[k])===JSON.stringify(beforeCandidate[k]));
 ok('pure_deriver_syntax',typeof new Function(deriver+';return deriveActualHomeRuntimeRequest;')()==='function');
 ok('deriver_no_IO',!/\btools\.|process_start|operation_start|fetch\(|require\(|import\s/.test(deriver));
 return{schema:'heptabao.fresh-home-auth-source-mechanical-checks.v1',passed:true,checkCount:checks.length,checks,sourceCount:22,wholeUnchanged:exact,rootLiteralOnly:rootOnly,functionalSources:4,pythonAstOrRuntimeExecuted:false,NativeCalls:0,qualification:'SOURCE_BINDING_ONLY'};
}
