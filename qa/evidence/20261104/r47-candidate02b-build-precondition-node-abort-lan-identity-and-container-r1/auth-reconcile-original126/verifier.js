function verifyOriginalScopeReconcileActual(files) {
 const checks=[];
 const stable=x=>Array.isArray(x)?x.map(stable):x&&typeof x==="object"?Object.fromEntries(Object.keys(x).sort().map(k=>[k,stable(x[k])])):x;
 const eq=(name,a,b)=>checks.push({name,passed:JSON.stringify(stable(a))===JSON.stringify(stable(b))});
 const yes=(name,x)=>checks.push({name,passed:x===true});
 const parse=path=>parseLosslessIntegers(files[path]);
 const meta=gitBlobMeta;
 const go=parse("GO.original.json"),calls=parse("calls.index.public.json"),obs=parse("observers.index.public.json");
 const state=parse("final-state.public.json"),release=parse("RELEASE.public.json"),report=parse("stdout.original.json");
 const job="1a1b22f780d-fc05-7cd8";
 const integer=x=>Number.isSafeInteger(x)?String(x):x&&typeof x.$exactInteger==="string"?x.$exactInteger:null;
 eq("go/original-whole",meta(files["GO.original.json"]),{blob:"e10747a3ac9227d57db70fbb3f63d6ba5da8867f",bytes:3433,sha256:"a0ccd889f4d340a1267e67023fa108f8a84e27aaf0eccf90e974406b2fd33240"});
 eq("exact/counts",[calls.length,obs.length,obs.reduce((n,o)=>n+o.pages,0)],[21,3,14]);
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
    const expected=n==="stdout"?31091:0;
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
    eq("stream/"+a.id+"/"+n+"/size",row.size,n==="stdout"?31091:0);
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
   eq("start/exact-request",meta(files[c.paths.request]),go.exactRequest);
   eq("start/source",meta(q.stdin),go.source);
   eq("start/identity",[v.job.id,v.job.host,v.job.idempotency_key,v.job.executable,v.job.args,v.job.cwd],[job,"mac",q.idempotency_key,q.executable,q.args,q.cwd]);
   eq("start/typed-binding",[v.job.request_digest,integer(v.job.request_fingerprint)],[go.native_binding.sha256,go.native_binding.native_fingerprint]);
   yes("start/unique-success",v.reused===false&&v.launch?.ok===true&&v.audit_recorded===true&&v.local_record_pending===false);
  }else if(c.kind==="operation_start"){
   yes("op/"+i+"/previous-closed",started&&!active);
   yes("op/"+i+"/key-prefix",q.idempotency_key.startsWith(go.prefix));
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
 eq("counts/native",counts,{process_start:1,operation_start:3,operation_status:3,operation_result:14});
 yes("final/all-observers-closed",active===null&&finished===3);
 eq("final/stdout-original",stdout,files["stdout.original.json"]);eq("final/stderr-original",stderr,files["stderr.original.txt"]);
 eq("final/extents",[nextOut,nextErr],[31091,0]);
 eq("final/whole-stdout",meta(stdout),{blob:"47982e4809c94d66f0a4f899ce1e3fdfc155dad4",bytes:31091,sha256:"43b301e075128e0bf104a3c7888be27565e740bba46e74bfebd85cfa626f72f4"});
 yes("final/context-zero",state.job===job&&state.nativeCallInFlight===false&&state.pending===null&&state.activeObserver===null&&state.paused===false);
 yes("final/release-zero",release.NativeCallsInFlight===0&&release.NativeFuturesActive===0&&release.laneReleased===true);
 eq("final/release-counts",[release.calls,release.returnedObservers,release.immutablePages],[21,3,14]);
 yes("diagnostic/success-scope",report.ok===true&&report.observationComplete===true&&report.outcomeUnknown===false&&report.stage==="complete");
 yes("diagnostic/own-closure",report.allReturnedApplicationFdsClosed===true&&report.allDirectHelpersClosed===true&&report.deadlineMetAfterClosure===true);
 yes("diagnostic/no-new-controls",report.bootstrapBootoutOrManagedSignalCalled===false&&report.productBusinessOrCleanupDispatched===false&&report.privatePlansCapsuleOrCredentialsRead===false);
 yes("history/unknown-preserved",report.originalManagedOutcomeUnknown===true&&report.registrationClosureClaimed===false&&report.historicalReapClaimed===false&&report.historicalLineageClosureClaimed===false&&report.newCleanupQualificationClaimed===false);
 eq("diagnostic/old-custody-null",report.originalPsCustodyNullUnknownPreserved,[84947,85012]);
 eq("diagnostic/current-missing-label-count",report.registrationSummaries.filter(x=>x.exactMissingBoth===true).length,2);
 eq("diagnostic/current-esrch-target-count",report.currentProcessSummaries.filter(x=>x.allFourNumericSamplesReturnedESRCH===true).length,4);
 eq("diagnostic/actual-libproc-counts",[report.currentPidMetadata.numericCalls,report.currentPidMetadata.pathCalls,report.currentPidMetadata.directChildCountCalls],[18,0,0]);
 eq("diagnostic/FD-counts",[report.io.openLedger.attempts,report.io.openLedger.registered,report.io.openLedger.pending,report.io.openLedger.registrationUnknown],[30,30,0,false]);
 eq("diagnostic/read-write-counts",[report.io.counts.metadata,report.io.counts.readCalls,report.io.counts.readBytes,report.io.counts.writeCalls,report.io.counts.writeBytes],[424,22,97699,0,0]);
 eq("diagnostic/4-helper-terminal",report.directHelpers.commands.map(x=>[x.exitCode,x.cleanup.directChildReaped,x.cleanup.allGroupRowsEmptyAfterReap]),[[113,true,true],[113,true,true],[113,true,true],[113,true,true]]);
 const cr=report.publicFiles["consumer-result"],ct=report.publicFiles["consumer-first-lf"],rec=cr.projection.records[0];
 yes("consumer/result-and-terminal-present",cr.present===true&&ct.present===true&&ct.firstLfPresent===true&&ct.sameFdPrefixRepeated===true&&ct.exactRelatedPublicBodyHashMatches===true);
 eq("consumer/original-failure-fields",[cr.projection.booleans.ok,cr.projection.booleans.outcomeUnknown,cr.projection.recordCount,cr.projection.nativeWorkerCount,cr.projection.error.errorCodeKnown],[false,true,1,0,"worker_complete_known_success.authbus-five-agent-cycle"]);
 eq("consumer/cycle-original-terminal",[rec.nameKnown,rec.lifecycle.exitCode,rec.lifecycle.finalReturnCode,rec.lifecycle.primaryReaped,rec.lifecycle.noGroupSurvivors,rec.stdoutBytes,rec.stderrBytes],["authbus-five-agent-cycle",-6,-6,true,true,0,0]);
 eq("consumer/worker-report-unavailable",rec.workerReport.error.errorCodeKnown,"worker_report_unavailable");
 yes("consumer/terminal-failure-retained",ct.projection.booleans.ok===false&&ct.projection.booleans.outcomeUnknown===true&&ct.projection.volumeReported.allDescriptorsClosed===true);
 yes("consumer/no-phase-qualification",report.consumerPhaseQualificationClaimed===false&&cr.projection.phaseQualificationClaimed===false);
 return {schema:"heptabao.original-scope-reconcile-actual-pure-checks.v1",passed:checks.every(x=>x.passed),checkCount:checks.length,checks,
 originalCalls:21,returnedObservers:3,immutablePages:14,
 execution:"pure V8 verification of original public SDK/request/immutable payload/stream bytes only",
 runtimeReplayed:false,hostReadAdded:false,historicalManagedUnknownPreserved:true,productQualificationClaimed:false};
}
