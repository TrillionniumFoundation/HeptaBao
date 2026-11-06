function verifyPublicNodeStartupSource(files) {
 const checks=[];
 const check=(name,value,detail=null)=>{checks.push({name,passed:value===true,detail});};
 const needFile=name=>{if(typeof files[name]!=="string")throw Error("missing:"+name);return files[name];};
 const meta=raw=>gitBlobMeta(raw);
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const obj=name=>JSON.parse(needFile(name));
 const src=needFile("source.py"), req=obj("request.exact.json"), contract=obj("CONTRACT.public.json");
 const bindings=obj("BINDINGS.public.json"), main=needFile("main.py"), input=needFile("input-audit.py");
 const decodeConst=name=>{const m=new RegExp(name+"=json\\.loads\\(base64\\.b64decode\\('([A-Za-z0-9+/=]+)'\\)\\)").exec(src);
   if(!m)throw Error("missing constant "+name);return JSON.parse(utf8Text(unb64(m[1])));};
 const moduleData=decodeConst("MODULES"), publicData=decodeConst("PUBLIC_FILES");
 const m=obj("MANIFEST.public.json");
 for(const p of m.files)check("core_whole:"+p.path,same(meta(needFile(p.path)),{blob:p.blob,bytes:p.bytes,sha256:p.sha256}));
 check("request_exact_source",req.stdin===src && !("stdin_text" in req));
 check("request_seven_fields",same(Object.keys(req).sort(),["args","cwd","executable","host","idempotency_key","stdin","timeout_seconds"]));
 check("request_fixed_interpreter",req.host==="mac"&&req.executable===bindings.PYTHON&&same(req.args,["-I","-S","-B","-"])&&req.cwd==="/Users/qianqi"&&req.timeout_seconds===60);
 check("request_new_key",req.idempotency_key==="heptabao-mac-public-node-startup-"+meta(src).sha256.slice(0,8)+"-20261106-r1");
 check("contract_source_pin",same(contract.source,meta(src)));
 check("contract_request_pin",same(contract.request,meta(needFile("request.exact.json"))));
 check("contract_journal_pin",same(contract.journal,meta(needFile("journal.js"))));
 check("candidate_still_source",contract.nativeSubmitted===false&&contract.slotInitialized===false&&contract.sourceOnly===true);
 check("main_exact_included",src.endsWith(main));
 check("input_class_exact_included",src.includes(input));
 for(const key of ["INPUT_PINS","NODE_ALIAS","PUBLIC_SOURCE_PINS","HARNESS_ROOTS","HARNESS_BINDINGS","MARKERS"]){
  const name={INPUT_PINS:"inputPins",NODE_ALIAS:"nodeAlias",PUBLIC_SOURCE_PINS:"publicSourcePins",HARNESS_ROOTS:"harnessRoots",HARNESS_BINDINGS:"harnessBindings",MARKERS:"markers"}[key];
  check("constant:"+key,same(decodeConst(key),bindings[name]));
 }
 const helperNames=["mac_owned_unreaped_r1","mac_owned_commands_r1","mac_native_process_observer_r1","mac_t5_volume_guard_r1"];
 check("exact_four_helpers",same(Object.keys(moduleData),helperNames));
 for(const name of helperNames){
  const value=moduleData[name],raw=utf8Text(unb64(value.base64));
  check("module_whole:"+name,same(meta(raw),{blob:value.blob,bytes:value.bytes,sha256:value.sha256}));
  check("module_exact_file:"+name,raw===needFile("module-"+name+".py"));
 }
 for(const name of ["marker","rows","cache"]){
  const file={marker:"startup-imports.mjs",rows:"mac_auth_rows_cas_r1.mjs",cache:"mac_authbus_cache_cas_r1.mjs"}[name];
  check("public_file_exact:"+name,utf8Text(unb64(publicData[name]))===needFile(file));
 }
 check("rows_original_pin",meta(needFile("mac_auth_rows_cas_r1.mjs")).blob==="408959d22873855f79f28570c611d24db44005cd");
 check("cache_original_pin",meta(needFile("mac_authbus_cache_cas_r1.mjs")).blob==="a318e427095b6c9273f03208620296b57ab59bc0");
 check("commands_original_pin",meta(needFile("module-mac_owned_commands_r1.py")).blob==="c102dfdc565484421bf7dbbb04b7c8b9e4cd5511");
 check("unreaped_original_pin",meta(needFile("module-mac_owned_unreaped_r1.py")).blob==="53cddd9243f9f890d9a1b9975b435280ff58ab77");
 check("observer_original_pin",meta(needFile("module-mac_native_process_observer_r1.py")).blob==="6ca7a8debfe9d9a31d19d1237ca3e84176cc40f5");
 const diffs=[["guard","module-mac_t5_volume_guard_r1.before.py","module-mac_t5_volume_guard_r1.py",1],["capture","capture.before.py","capture.after.py",1],["journal","journal.before.js","journal.js",2]];
 for(const [name,before,after,hunks] of diffs){
  const f=needFile(name+".forward.diff"),r=needFile(name+".reverse.diff");
  const a=strictApplySource(needFile(before),f),b=strictApplySource(needFile(after),r);
  check("strict_forward:"+name,a.raw===needFile(after)&&a.hunks===hunks);
  check("strict_reverse:"+name,b.raw===needFile(before)&&b.hunks===hunks);
 }
 const oldRoot=bindings.oldRoot,newRoot=bindings.newRoot;
 check("guard_single_root_substitution",needFile("module-mac_t5_volume_guard_r1.py").split(newRoot.slice("/Volumes/T5/".length)).join(oldRoot.slice("/Volumes/T5/".length))===needFile("module-mac_t5_volume_guard_r1.before.py"));
 check("capture_only_output_caps",needFile("capture.after.py").replace("volume_guard.capture_sink(stdout_path, maximum=4096) as stdout, volume_guard.capture_sink(stderr_path, maximum=65536) as stderr:","volume_guard.capture_sink(stdout_path) as stdout, volume_guard.capture_sink(stderr_path) as stderr:")===needFile("capture.before.py"));
 check("capture_in_source",src.includes(needFile("capture.after.py")));
 const phase=needFile("phase.original.py"),materializer=needFile("materializer.original.py");
 check("phase_original_pin",meta(phase).blob==="57b38b5d7072cb425898159f1f5d491fc2b1647a");
 check("materializer_original_pin",meta(materializer).blob==="198feabe7aef20b302e5989fd72e99e0bc0d36c3");
 check("capture_original_excerpt",phase.includes(needFile("capture.before.py")));
 check("profile_original_excerpt",materializer.includes(needFile("consumer_profile.original.py")));
 check("profile_exact_in_source",src.includes(needFile("consumer_profile.original.py")));
 for(const name of ["open_fd","close_one","close"]){
  const method=needFile("input-"+name+".original.py");
  check("input_returned_fd_method:"+name,input.includes(method));
  check("input_method_prior_origin:"+name,needFile("readonly.original.py").includes(method));
 }
 const original=obj("original-runtime.stdout.json");
 check("original_runtime_whole",meta(needFile("original-runtime.stdout.json")).blob==="71201c9dc56be7704936677c6c31c8c9d5df2ae9");
 for(const [path,pin]of Object.entries(bindings.inputPins)){
  if(path===bindings.PYTHON)continue;
  const found=original.finiteInputClosure.sourceRecords.find(x=>x.path===path);
  check("actual_public_input:"+path,!!found&&found.private===false&&same(found.identity,pin.identity)&&found.bytes===pin.bytes&&found.sha256===pin.sha256);
 }
 check("node_alias_actual",same(original.finiteInputClosure.publicCodeAliases.find(x=>x.path==="/opt/homebrew/bin/node"),bindings.nodeAlias));
 const tools=new Set(Object.keys(original.utilityPins));
 const publics=Object.fromEntries(original.finiteInputClosure.publicCodeAliases.filter(x=>!tools.has(x.path)&&!x.path.endsWith("/artifacts/heptabao-server")).map(x=>[x.path,x.sha256]));
 check("policy_literal_public_origins",same(publics,bindings.publicSourcePins)&&Object.keys(publics).length===40);
 check("historical_endpoint_permission_only",original.controlHttp.onlyEndpoint==="127.0.0.1:63611"&&contract.sandbox.noConnectionOrAvailabilityClaim===true);
 const marker=needFile("startup-imports.mjs");
 const stages=JSON.parse(/const stages = (\[[^\n]+\]);/.exec(marker)[1]),imports=JSON.parse(/const modules = (\[[^\n]+\]);/.exec(marker)[1]);
 check("nine_builtins_two_cas",imports.length===11&&imports.filter(x=>x.startsWith("node:")).length===9&&same(imports.filter(x=>x.startsWith("./")),["./mac_auth_rows_cas_r1.mjs","./mac_authbus_cache_cas_r1.mjs"]));
 check("exact_24_markers",same(bindings.markers,["entered-js",...stages.flatMap(x=>["before-"+x,"after-"+x]),"complete"])&&bindings.markers.length===24);
 check("no_marker_static_import",!/^\s*import\s/m.test(marker));
 check("entry_await_precedes_dynamic_import",marker.indexOf("await emit('entered-js')")<marker.indexOf("await import(modules[i])"));
 check("before_await_precedes_import",marker.indexOf("await emit(current)")<marker.indexOf("await import(modules[i])"));
 check("marker_no_sdk_or_db_function",!/(new DatabaseSync|captureAuthRows\(|restoreAuthRowsWithCas\(|captureAuthBusCaches\(|restoreAuthBusCachesWithCas\(|https\.(request|get)|fetch\(|childProcess\.)/.test(marker));
 check("marker_error_text_not_exported",marker.includes("catch (_error)")&&!/(_error\.|String\(_error|JSON\.stringify\(_error)/.test(marker));
 const q=JSON.stringify,lines=['(version 1)','(deny default)','(allow process*)','(allow signal (target children))','(allow sysctl-read)','(allow mach-lookup)','(allow file-read-metadata)'];
 for(const p of ['/System','/usr','/bin','/sbin','/Library','/private/etc','/opt/homebrew','/dev/fd'])lines.push('(allow file-read* (subpath '+q(p)+'))');
 for(const p of [newRoot+'/qa',newRoot+'/installed-plugin-copy',newRoot+'/initial'])lines.push('(allow file-read* (subpath '+q(p)+'))');
 for(const p of [...new Set([bindings.harnessRoots[0],...bindings.harnessRoots])].sort())lines.push('(allow file-read* (subpath '+q(p)+'))');
 for(const p of Object.keys(publics).sort())lines.push('(allow file-read* (literal '+q(p)+'))');
 for(const n of ['ca.crt','role_id','secret_id'])lines.push('(allow file-read* (literal '+q(newRoot+'/credentials-consumer/'+n)+'))');
 lines.push('(allow file-read* (literal "/dev/urandom"))','(allow file-read* (literal "/dev/random"))','(allow file-write* (subpath '+q(newRoot+'/initial')+'))','(allow file-write* (literal "/dev/null"))','(allow network-outbound (remote ip "localhost:63611"))');
 check("profile_pure_reconstruction",lines.join("\n")+"\n"===needFile("consumer.sb"));
 check("profile_whole_pin",same(meta(needFile("consumer.sb")),contract.sandbox.derivedProfile));
 check("profile_not_historical_body_claim",contract.sandbox.originalProfileBodyNotRetrieved===true&&contract.sandbox.noByteExactHistoricalProfileClaim===true);
 check("no_extra_policy_operations",needFile("consumer.sb").split("\n").filter(x=>x.startsWith("(allow ")).every(x=>/^\(allow (?:process\*|signal|sysctl-read|mach-lookup|file-read-metadata|file-read\*|file-write\*|network-outbound)(?:\s|\))/.test(x)));
 check("original_env_seven_fields",same(Object.keys(contract.execution.worker.env),["PATH","HOME","TMPDIR","OPENCLAW_STATE_DIR","OPENCLAW_CONFIG_PATH","OPENCLAW_OAUTH_DIR","OPENCLAW_HOME"]));
 check("Popen_env_cwd_session_exact",needFile("capture.after.py").includes("proc=subprocess.Popen(argv,env=child_env,cwd=str(cwd),start_new_session=True,"));
 check("no_original_cycle_or_plan_arg",same(contract.execution.worker.argv,["/usr/bin/sandbox-exec","-f",newRoot+"/initial/consumer.sb","/opt/homebrew/bin/node",newRoot+"/qa/startup-imports.mjs"]));
 check("budgets_35_45_60",src.includes("UNTIL=START+35.0")&&src.includes("FINAL_UNTIL=START+45.0")&&req.timeout_seconds===60);
 check("node_10_and_diskutil_4",main.includes("min(UNTIL,time.monotonic()+10.0)")&&main.includes("until=min(UNTIL,time.monotonic()+4.0)"));
 const sum=Object.values(bindings.inputPins).reduce((a,p)=>a+p.bytes,0);
 check("five_fixed_input_sizes",Object.keys(bindings.inputPins).length===5&&sum===2313600);
 check("input_eof_bound",input.includes("2313605-self.read_bytes")&&contract.budgets.fixedInputPhysicalReadCapIncludingEOFReserve===sum+5);
 const created=meta(needFile("startup-imports.mjs")).bytes+meta(needFile("mac_auth_rows_cas_r1.mjs")).bytes+meta(needFile("mac_authbus_cache_cas_r1.mjs")).bytes+meta(needFile("consumer.sb")).bytes;
 check("created_bytes_17915",created===17915&&contract.budgets.createdInputBytes===created);
 check("six_body_reads_eof_budget",contract.budgets.successfulReadbackByteMaximum===created+4096+65536&&contract.budgets.physicalReadMaximumIncludingPerReadEOFSentinel===created+4096+65536+6);
 const mkdirRows=[1,2,2,2,3,4,4,3,3].reduce((a,x)=>a+x,0);
 check("guard_fd_static_79",3+mkdirRows+16+16+10+10===79&&contract.budgets.heldGuardReturnedFdStaticMaximum===79);
 check("guard_io_ops_21",9+4+4+2+2===21&&main.includes("operations==21"));
 check("input_pending_before_syscall",input.indexOf("ledger['pending'] += 1")<input.indexOf("fd = os.open"));
 check("input_registration_unknown_preserved",input.includes("ledger['registrationUnknown'] = True")&&input.includes("not ledger['pending'] and not ledger['registrationUnknown']"));
 check("guard_partial_init_unknown",main.includes("guard_started=True;volume_guard=HeldT5.__new__(HeldT5)")&&main.includes("or (guard_started and not guard_complete)"));
 check("guard_pending_blocks_closure",main.includes("guard_closed=(guard_complete and not guard_pending"));
 check("worker_pending_blocks_unknown",main.includes("command_pending or worker_pending or guard_pending"));
 check("no_cleanup_repeat",!main.includes("stop_once_unreaped(")&&main.includes("report['originalWorkerCleanupRepeated']=False"));
 check("close_loop_protected",input.includes("with self.signals.critical():\n            for row in reversed(self.rows):"));
 check("cancel_and_handlers_final",main.includes("pending_signal is not None or command_pending")&&main.includes("and not worker_pending and handlers_restored"));
 check("unknown_stderr_not_exported",main.includes("report['stderrContentOrHashExported']=False")&&!/sha\(stderr\)|stderr\.decode/.test(main));
 check("no_historical_closure",main.includes("'historicalManagedClosureClaimed':False")&&main.includes("'originalAbortCauseProved':False"));
 check("entry_absence_not_equated_nonexecution",main.includes("'entryMarkerObserved'")&&!main.includes("'enteredJavaScript'"));
 check("negative_exit_not_execution_success",main.includes("life.get('exitCode')==0")&&main.includes("life.get('finalReturnCode')==0"));
 check("observation_not_execution_conflated",main.includes("report['ok']=report['observationComplete']")&&main.includes("report['executionSucceeded']=bool(report['executionSucceeded'] and report['ok'])"));
 check("no_host_controls_in_main",!/(os\.kill|killpg\(|bootout|bootstrap|launchctl|shutil\.|os\.(remove|unlink|rmdir|chmod)\()/.test(main));
 const j=needFile("journal.js"),jb=needFile("journal.before.js");
 check("journal_exact_normalized",j.replace(/const GF_SLOT = [^\n]+/,/const GF_SLOT = [^\n]+/.exec(jb)[0])
 .replace(/const GF_REQUEST = \{[\s\S]*?\};/,/const GF_REQUEST = \{[\s\S]*?\};/.exec(jb)[0])
 .replaceAll("heptabao-mac-public-node-startup-"+meta(src).sha256.slice(0,8)+"-","heptabao-mac-original-scope-reconcile-39e1684a-")===jb);
 check("journal_new_absent_slot_literal",j.includes('const GF_SLOT = "owner_authbus_public_node_startup_gitfirst_r1";'));
 check("journal_request_pin",j.includes(meta(needFile("request.exact.json")).blob)&&j.includes(meta(needFile("request.exact.json")).sha256));
 return {schema:"heptabao.public-node-startup-source-verification.r1",passed:checks.every(x=>x.passed),checkCount:checks.length,
  pythonExecuted:false,nodeExecuted:false,componentsExecuted:false,nativeCalls:0,checks};
}
