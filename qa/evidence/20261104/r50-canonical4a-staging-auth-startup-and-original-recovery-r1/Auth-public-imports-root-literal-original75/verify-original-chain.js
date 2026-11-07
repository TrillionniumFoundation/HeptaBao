function verifyPublicImportsRootLiteralR1OriginalChain(files) {
 const checks=[];
 const stable=x=>Array.isArray(x)?x.map(stable):x&&typeof x==="object"?Object.fromEntries(Object.keys(x).sort().map(k=>[k,stable(x[k])])):x;
 const eq=(name,a,b)=>checks.push({name,passed:JSON.stringify(stable(a))===JSON.stringify(stable(b))});
 const yes=(name,x)=>checks.push({name,passed:x===true});
 const parse=path=>parseLosslessIntegers(files[path]);
 const meta=gitBlobMeta;
 const go=parse("GO.original.json"),calls=parse("calls.index.public.json"),obs=parse("observers.index.public.json");
 eq("controls/exact-source",meta(files["source.original.py"]),go.source);
 eq("controls/exact-request",meta(files["request.original.json"]),go.exact_request);
 eq("controls/exact-journal",meta(files["journal.original.js"]),go.journal);
 const state=parse("final-state.public.json"),release=parse("RELEASE.public.json"),report=parse("stdout.original.json");
 const job="1a1b36956f4-fc05-82c1";
 const integer=x=>Number.isSafeInteger(x)?String(x):x&&typeof x.$exactInteger==="string"?x.$exactInteger:null;
 eq("go/original-whole",meta(files["GO.original.json"]),{"blob":"a4fc8c2c3ceff33b784c211ae247214b7be5d65e","bytes":17548,"sha256":"f6f6db7ce07a2e236492293b4f2ed2c53aa2841cb7577972b49a197a188a4ed9"});
 eq("exact/counts",[calls.length,obs.length,obs.reduce((n,o)=>n+o.pages,0)],[11,2,6]);
 const observerById=new Map(obs.map(o=>[o.id,o])),keys=new Set(),ids=new Set(),counts={};
 let started=false,active=null,stdout="",stderr="",nextOut=0,nextErr=0,authority=null,finished=0;
 function tree(name,expected,texts){
  try{
   const rows=Object.entries(texts).map(([path,raw])=>({path,mode:"100644",type:"blob",sha:meta(raw).blob}));
   const a=gitTreeAudit({sha:expected,truncated:false,tree:rows});
   eq(name,[a.root_sha,a.leaf_count],[expected,rows.length]);
  }catch(e){checks.push({name,passed:false,error:String(e.message)});}
 }
 function finish(a){
  const o=observerById.get(a.id),raw=utf8Text(a.bytes);
  yes("observer/"+a.id+"/listed",!!o);
  eq("observer/"+a.id+"/payload-whole",raw,files[o.paths.payload]);
  eq("observer/"+a.id+"/payload-pin",meta(raw),o.payload);
  eq("observer/"+a.id+"/payload-sha-and-bytes",[meta(raw).sha256,meta(raw).bytes],[a.digest,a.total]);
  eq("observer/"+a.id+"/pages",[a.pages,o.pages],[o.pages,a.pages]);
  tree("observer/"+a.id+"/payload-tree",o.payloadTree,{"payload.original.json":raw});
  const p=parseLosslessIntegers(raw);
  yes("observer/"+a.id+"/native-success",p.resultType==="complete"&&p.isError===false&&p.content?.length===1&&p.content[0].type==="text");
  const native=p.content[0].text,v=parseLosslessIntegers(native);
  eq("observer/"+a.id+"/native-original",native,files[o.paths.native]);
  eq("observer/"+a.id+"/native-pin",meta(native),o.nativeText);
  eq("observer/"+a.id+"/job",v.job_id,job);
  eq("observer/"+a.id+"/tool",o.tool,a.tool);
  yes("observer/"+a.id+"/closed",a.futureClosed&&o.completedInactive===true);
  if(a.tool==="process_status"){
   authority=v;eq("authority/original",native,files["authority.original.json"]);
   yes("authority/terminal",v.state==="succeeded"&&v.exit_code===0&&v.output_complete===true&&v.output_durable===true&&v.terminal_publication_confirmed===true);
   yes("authority/no-cancel-timeout",v.cancelled===false&&v.timed_out===false);
   for(const n of ["stdout","stderr"]){
    const expected=n==="stdout"?10335:0;
    eq("authority/"+n+"/complete",[v.log_bytes[n].seen,v.log_bytes[n].stored],[expected,expected]);
    yes("authority/"+n+"/durable",v.log_synced[n]===true&&v.log_errors[n]===null&&v.log_truncated[n]===false);
   }
  }else{
   for(const n of ["stdout","stderr"]){
    const row=v[n],asked=a.request.operation.arguments[n+"_offset"],expected=n==="stdout"?nextOut:nextErr;
    eq("stream/"+a.id+"/"+n+"/cursor",[asked,row.offset],[expected,expected]);
    yes("stream/"+a.id+"/"+n+"/hex",typeof row.bytes_hex==="string"&&/^(?:[0-9a-f]{2})*$/.test(row.bytes_hex));
    const bytes=[];for(let i=0;i<row.bytes_hex.length;i+=2)bytes.push(parseInt(row.bytes_hex.slice(i,i+2),16));
    yes("stream/"+a.id+"/"+n+"/16K",bytes.length<=16384);
    eq("stream/"+a.id+"/"+n+"/text",utf8Text(bytes),row.text);
    eq("stream/"+a.id+"/"+n+"/extent",row.next_offset,row.offset+bytes.length);
    eq("stream/"+a.id+"/"+n+"/size",row.size,n==="stdout"?10335:0);
    eq("stream/"+a.id+"/"+n+"/eof",row.eof,row.next_offset===row.size);
    if(n==="stdout"){stdout+=row.text;nextOut=row.next_offset;}else{stderr+=row.text;nextErr=row.next_offset;}
   }
  }
  finished++;active=null;
 }
 for(let i=0;i<calls.length;i++){
  const c=calls[i],q=parse(c.paths.request),intent=parse(c.paths.intent),armed=parse(c.paths.armed),sdk=JSON.parse(files[c.paths.sdk]);
  eq("call/"+i+"/ordinal",c.ordinal,i);yes("call/"+i+"/unique",!keys.has(c.key));keys.add(c.key);
  counts[c.kind]=(counts[c.kind]||0)+1;
  eq("call/"+i+"/request-pin",meta(files[c.paths.request]),c.requestPin);
  eq("call/"+i+"/sdk-pin",meta(files[c.paths.sdk]),c.sdkPin);
  eq("call/"+i+"/native-pin",meta(files[c.paths.native]),c.nativePin);
  eq("call/"+i+"/intent-binding",[intent.callKey,intent.kind,intent.request,intent.rootGo],[c.key,c.kind,c.requestPin,meta(files["GO.original.json"])]);
  yes("call/"+i+"/armed-once",intent.maximumNativeCalls===1&&intent.nativeNotYetCalled===true&&intent.lossOfAcknowledgmentNeverGrantsReplay===true&&armed.mayHaveDispatchedAfterThisCheckpoint===true);
  eq("call/"+i+"/arm-identity",[armed.callKey,armed.kind,armed.request,armed.rootGo],[c.key,c.kind,c.requestPin,meta(files["GO.original.json"])]);
  tree("call/"+i+"/arm-merkle",c.armTree,{"request.json":files[c.paths.request],"intent.json":files[c.paths.intent],"armed.json":files[c.paths.armed]});
  tree("call/"+i+"/sdk-merkle",c.sdkTree,{"original.sdk.json":files[c.paths.sdk]});
  yes("call/"+i+"/actual-called-accepted",c.calledOnce===true&&c.phase==="accepted");
  yes("call/"+i+"/sdk-success",sdk.isError!==true&&sdk.content?.length===1&&sdk.content[0].type==="text");
  eq("call/"+i+"/native-raw",sdk.content[0].text,files[c.paths.native]);
  const v=parseLosslessIntegers(files[c.paths.native]);
  if(c.kind==="process_start"){
   yes("start/unique-first",i===0&&!started&&!active);started=true;
   eq("start/exact-request",meta(files[c.paths.request]),go.exact_request);
   eq("start/source",meta(q.stdin),go.source);
   eq("start/identity",[v.job.id,v.job.host,v.job.idempotency_key,v.job.executable,v.job.args,v.job.cwd],[job,"mac",q.idempotency_key,q.executable,q.args,q.cwd]);
   eq("start/typed-binding",[v.job.request_digest,integer(v.job.request_fingerprint)],[go.digest,go.fingerprint]);
   yes("start/unique-success",v.reused===false&&v.launch?.ok===true&&v.audit_recorded===true&&v.local_record_pending===false);
  }else if(c.kind==="operation_start"){
   yes("op/"+i+"/previous-closed",started&&!active);
   yes("op/"+i+"/key-prefix",q.idempotency_key.startsWith("heptabao-mac-public-node-startup-root-read-2cce4cec-"));
   yes("op/"+i+"/scope",["process_status","process_read"].includes(q.operation.tool)&&q.operation.arguments.host==="mac"&&q.operation.arguments.job_id===job);
   if(q.operation.tool==="process_read")eq("op/"+i+"/original-cursors",[q.operation.arguments.stdout_offset,q.operation.arguments.stderr_offset,q.operation.arguments.limit],[nextOut,nextErr,16384]);
   yes("op/"+i+"/admitted-once",v.reused===false&&v.automatic_retry===false&&v.tool_name===q.operation.tool&&/^[0-9a-f]{64}$/.test(v.operation_id)&&!ids.has(v.operation_id));
   ids.add(v.operation_id);active={id:v.operation_id,tool:v.tool_name,request:q,futureClosed:false,statuses:0,pages:0,total:null,digest:null,bytes:[]};
  }else if(c.kind==="operation_status"){
   yes("status/"+i+"/same-id",!!active&&q.operation_id===active.id&&v.operation_id===active.id&&v.tool_name===active.tool&&v.automatic_retry===false);
   active.statuses++;yes("status/"+i+"/bound",active.statuses<=8);
   yes("status/"+i+"/closed",v.async_state==="completed"&&v.owned_future_active===false&&v.result_state==="stored_observed"&&v.payload_available===true);
   active.futureClosed=true;
  }else if(c.kind==="operation_result"){
   yes("page/"+i+"/same-closed-id",!!active&&active.futureClosed&&q.operation_id===active.id&&v.operation_id===active.id);
   eq("page/"+i+"/original-width",q.limit,8192);
   eq("page/"+i+"/offset",[q.offset,v.offset],[active.bytes.length,active.bytes.length]);
   yes("page/"+i+"/native-immutable",v.immutable_snapshot===true&&v.payload_kind==="native_result"&&v.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization");
   yes("page/"+i+"/payload-bound",Number.isSafeInteger(v.total_bytes)&&v.total_bytes>=0&&v.total_bytes<=1048576);
   const bytes=unb64(v.data_base64);yes("page/"+i+"/size-bound",bytes.length<=8192);
   eq("page/"+i+"/extent",v.next_offset,v.offset+bytes.length);
   eq("page/"+i+"/eof",v.eof,v.next_offset===v.total_bytes);
   if(active.total!==null)eq("page/"+i+"/one-payload",[v.total_bytes,v.result_sha256],[active.total,active.digest]);
   active.total=v.total_bytes;active.digest=v.result_sha256;active.bytes.push(...bytes);active.pages++;
   yes("page/"+i+"/page-bound",active.pages<=128);
   if(v.eof)finish(active);
  }else yes("call/"+i+"/closed-kind",false);
 }
 eq("counts/native",counts,{process_start:1,operation_start:2,operation_status:2,operation_result:6});
 yes("final/all-observers-closed",active===null&&finished===2);
 eq("final/stdout-original",stdout,files["stdout.original.json"]);eq("final/stderr-original",stderr,files["stderr.original.txt"]);
 eq("final/extents",[nextOut,nextErr],[10335,0]);
 eq("final/whole-stdout",meta(stdout),{"blob":"22d0b8fa41b28404dcb6a5fe9f8e818827695451","bytes":10335,"sha256":"5d2bee00c02cdd74398d8a1d773cba848ff60ae3b4b0b7c0a4844c5f54314687"});
 yes("final/context-zero",state.job===job&&state.nativeCallInFlight===false&&state.pending===null&&state.activeObserver===null&&state.paused===false);
 yes("final/release-zero",release.lane.activeRuntimeCall===false&&release.lane.knownFuture===false&&release.lane.A===0);
 eq("final/release-counts",[release.NativeCalls,release.originalObservers.length,release.immutablePages],[11,2,6]);




 yes("report/no-error",!Object.hasOwn(report,"error")&&!Object.hasOwn(report,"errorCode"));
 eq("report/schema",report.schema,"heptabao.mac-public-node-startup-import-diagnostic.r2");
 eq("report/result",[report.ok,report.observationComplete,report.executionSucceeded,report.outcomeUnknown],[true,true,true,false]);
 eq("report/markers-exact",report.markers.markers,go.execution.publicMarkerSequence);
 eq("report/marker-boundary",[report.markers.complete,report.markers.entryMarkerObserved,report.markers.protocolValid,report.markers.reportedFailureMarker,report.markers.unknownOutputPresent],[true,true,true,null,false]);
 eq("report/marker-count",report.markers.markers.length,24);
 eq("report/capture",[report.stdoutBytes,report.stderrBytes,report.stderrEmpty,report.stderrContentOrHashExported],[317,0,true,false]);
 eq("report/exact-argv",report.argv,go.execution.worker.argv);
 eq("report/exact-cwd",report.cwd,go.execution.worker.cwd);
 eq("report/exact-env",report.environment,go.execution.worker.env);
 eq("report/fresh-root",report.scope,go.new_scope.root);
 eq("report/exclusive-directory-set",report.createdDirectories.map(x=>x.path),go.new_scope.directories);
 eq("report/directory-count",report.createdDirectories.length,9);
 for(let i=0;i<report.createdDirectories.length;i++){
  const d=report.createdDirectories[i];
  yes("directory/"+i+"/full9",Array.isArray(d.identity)&&d.identity.length===9&&d.identity.every(x=>typeof x==="string"&&/^[0-9]+$/.test(x)));
  eq("directory/"+i+"/shape",d.identity.slice(0,1).concat(d.identity.slice(2,5)),["16777244","501","20","16832"]);
 }
 eq("report/public-file-count",report.createdPublicFiles.length,4);
 for(let i=0;i<report.createdPublicFiles.length;i++){
  const f=report.createdPublicFiles[i],e=go.new_scope.fixedCreatedPublicFiles[i];
  eq("created/"+i+"/exact-pin",[f.path,f.bytes,f.sha256],[e.path,e.bytes,e.sha256]);
  yes("created/"+i+"/full9",Array.isArray(f.identity)&&f.identity.length===9&&f.identity.every(x=>typeof x==="string"&&/^[0-9]+$/.test(x)));
  eq("created/"+i+"/held-regular-owner-nlink-size",[f.identity[0],...f.identity.slice(2,7)],["16777244","501","20","33152","1",String(f.bytes)]);
 }
 eq("report/profile-pin",report.profileSha256,go.new_scope.fixedCreatedPublicFiles[3].sha256);
 eq("report/profile-only-root-literal",[report.rootDirectoryLiteralReadAdded,report.otherSandboxPermissionsBroadened],[true,false]);
 eq("report/no-unbound-compat-flags",report.nodeCompatibilityFlagsAdded,false);
 const w=report.workerLifecycle,cl=w.retainedChildCleanup;
 eq("worker/known-exit",[w.exitCode,w.finalReturnCode,w.timeout,w.interrupted,w.outcomeUnknown],[0,0,false,false,false]);
 eq("worker/custody",w.actualDirectChildCustody,cl.custody);
 eq("worker/observed-identity",[cl.pid,cl.pgid,cl.custody.ps.pid,cl.custody.ps.ppid,cl.custody.ps.pgid,cl.custody.ps.uid,cl.custody.sid_observed_while_live],[56403,56403,56403,56392,56403,501,56403]);
 eq("worker/actual-birth",cl.custody.ps.start,"Sat Nov  7 08:29:55 2026    ");
 eq("worker/retained",w.retainedExit,{code:1,pid:56403,signo:20,status:0});
 eq("worker/retained-cleanup",cl.retainedExit,w.retainedExit);
 yes("worker/retained-until-group-reap",w.directChildRetainedUntilGroupCleanup===true&&w.primaryReaped===true&&w.noGroupSurvivors===true);
 eq("worker/group",w.remainingGroupMembers,[]);
 yes("worker/cleanup-known",cl.ok===true&&cl.outcomeUnknown===false&&cl.directChildReaped===true&&cl.ownedLiveGroupEmptyBeforeReap===true&&cl.allGroupRowsEmptyAfterReap===true&&cl.stopAttempted===true);
 eq("worker/no-signal-or-group",[cl.signals,cl.initialLiveGroup,cl.remainingGroupRows,cl.postReapSignalSent],[[],[],[],false]);
 eq("worker/original-cleanup-caps",cl.cleanupCaps,{group:3,psMax:4,term:1,wait:5});
 yes("worker/finite-cleanup",cl.elapsedSeconds>=0&&cl.elapsedSeconds<9);
 eq("volume/helper-count",[report.commands.commands.length,report.commands.unknownCommandCount,report.commands.allOwnedCommandsStopped],[1,0,true]);
 eq("volume/helper-original",report.commands.commands[0],report.volumeCommand);
 const c=report.volumeCommand,cc=c.cleanup;
 eq("volume/helper-argv",c.argv,go.execution.diskutil.argv);
 eq("volume/helper-known",[c.pid,c.exitCode,c.stdoutBytes,c.stderrBytes,c.outcomeUnknown,c.streamsClosed,c.completeBeforeDeadline],[56394,0,3069,0,false,true,true]);
 yes("volume/helper-deadlines",c.elapsedSeconds>=0&&c.elapsedSeconds<4&&cc.elapsedSeconds>=0&&cc.elapsedSeconds<9);
 eq("volume/helper-custody",[cc.pid,cc.pgid,cc.custody.ps.pid,cc.custody.ps.ppid,cc.custody.ps.pgid,cc.custody.ps.uid,cc.custody.sid_observed_while_live],[56394,56394,56394,56392,56394,501,56394]);
 eq("volume/helper-birth",cc.custody.ps.start,"Sat Nov  7 08:29:55 2026    ");
 eq("volume/helper-retained",cc.retainedExit,{code:1,pid:56394,signo:20,status:0});
 yes("volume/helper-reaped",cc.ok===true&&cc.outcomeUnknown===false&&cc.directChildReaped===true&&cc.ownedLiveGroupEmptyBeforeReap===true&&cc.allGroupRowsEmptyAfterReap===true&&cc.stopAttempted===true);
 eq("volume/helper-no-signal-or-group",[cc.signals,cc.initialLiveGroup,cc.remainingGroupRows,cc.postReapSignalSent],[[],[],[],false]);
 eq("volume/helper-original-cleanup-caps",cc.cleanupCaps,{group:3,psMax:4,term:1,wait:5});
 eq("inputs/exact-closure",report.inputs,{allReturnedInputFdsClosed:true,closeErrors:[],fixedInputCount:5,metadataCalls:49,readBytes:2313600,readCalls:43,returnedFdLedger:{attempts:5,knownNoReturnErrors:0,pending:0,registered:5,registrationUnknown:false}});
 yes("inputs/budgets",report.inputs.metadataCalls<=go.budgets.inputMetadataCalls&&report.inputs.readCalls<=go.budgets.inputReadCalls&&report.inputs.readBytes===go.budgets.fixedInputBytes);
 const anchor=parseLosslessIntegers(utf8Text(unb64(go.anchor.base64)));
 eq("volume/held-anchors",report.volume.anchors,anchor.anchors);
 eq("volume/device",report.volume.expectedVolumeDevice,anchor.expectedVolumeDevice);
 eq("volume/closure",[report.volume.volumeUUIDVerified,report.volume.allDescriptorsClosed,report.volume.lastAnchorCheckPassed,report.volume.closeErrors],[true,true,true,[]]);
 eq("guard/initialized-and-closed",[report.guardInitializationStarted,report.guardInitializationCompleted,report.guardOperationPendingOrFailed,report.returnedGuardFdCount,report.operations],[true,true,false,79,21]);
 eq("guard/declared-bounds",[go.budgets.heldGuardReturnedFdStaticMaximum,go.budgets.fixedGuardPublicIoOperations],[79,21]);
 yes("guard/readback-cap",report.publicReadbackBytes===18265&&report.publicReadbackBytes<=go.budgets.successfulReadbackByteMaximum);
 eq("closure/total-application-fds",report.inputs.returnedFdLedger.registered+report.returnedGuardFdCount,84);
 eq("closure/all",[report.allFixedInputsAfter,report.allOwnDescriptorsAndChildrenClosed,report.handlersRestored,report.pendingSignalObserved,report.original45SecondDeadlineMetAfterClosure],[true,true,true,false,true]);
 yes("closure/original-time",report.elapsedSeconds>=0&&report.elapsedSeconds<go.budgets.afterClosureSeconds);
 for(const k of ["sdkImported","casFunctionCalled","applicationDatabaseMethodCalled","applicationNetworkCallDispatched","providerCalled","credentialFileReadRequested","oldPrivateFileReadRequested","launchdOperation","oldPidOperation","historicalFailureReclassified","historicalManagedClosureClaimed","originalWorkerCleanupRepeated","originalAbortCauseProved","kernelImageOfAbortedChildProved"])eq("scope/"+k,report[k],false);
 eq("scope/original-runtime-reference",report.originalRuntimeJob,"mac/1a1b1d28dc2-fc05-7afe");
 yes("scope/foreground-and-port-limits",report.foregroundOwnerDiffersFromOriginalLaunchdParent===true&&report.portPermissionIsNotReservationOrAvailabilityEvidence===true);
 eq("release/observed-marker-and-closure",[release.actual.markers,release.closure.enumeratedApplicationFDs],[report.markers,84]);
 eq("release/no-business-or-upgrade",[release.additionalNativeAuthorized,release.materializerDispatchAuthorized,release.SDKOrCredentialWorkExecuted,release.historicalUnknownUpgraded],[false,false,false,false]);
 return {schema:"heptabao.public-import-root-literal-r1-original-chain-pure-checks.r1",passed:checks.every(x=>x.passed),checkCount:checks.length,checks,originalCalls:11,returnedObservers:2,immutablePages:6,NativeCallsAdded:0,execution:"pure V8 original public SDK/intent/payload/stream verification only",publicImportsComplete:true,specificHistoricalCauseQualified:false,oldBusinessProgressQualified:false,SDKQualified:false,historicalUnknownPreserved:true};
}
