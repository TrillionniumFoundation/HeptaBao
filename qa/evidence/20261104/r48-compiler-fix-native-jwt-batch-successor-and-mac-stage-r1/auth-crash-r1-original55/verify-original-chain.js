function verifyNodeCrashOriginalFailure(files) {
 const checks=[];
 const stable=x=>Array.isArray(x)?x.map(stable):x&&typeof x==="object"?Object.fromEntries(Object.keys(x).sort().map(k=>[k,stable(x[k])])):x;
 const eq=(name,a,b)=>checks.push({name,passed:JSON.stringify(stable(a))===JSON.stringify(stable(b))});
 const yes=(name,x)=>checks.push({name,passed:x===true});
 const parse=path=>parseLosslessIntegers(files[path]);
 const meta=gitBlobMeta;
 const go=parse("GO.original.json"),calls=parse("calls.index.public.json"),obs=parse("observers.index.public.json");
 const state=parse("final-state.public.json"),release=parse("RELEASE.public.json"),report=parse("stdout.original.json");
 const job="1a1b27a443e-fc05-7e31";
 const integer=x=>Number.isSafeInteger(x)?String(x):x&&typeof x.$exactInteger==="string"?x.$exactInteger:null;
 eq("go/original-whole",meta(files["GO.original.json"]),{blob:"534fead45b43bf119c03a6d4c1bcad528322ae94",bytes:8877,sha256:"c7ee1e95d6d1097aa185205f513f5d8c32cf4a2832b03e74810370e3b6929f8c"});
 eq("exact/counts",[calls.length,obs.length,obs.reduce((n,o)=>n+o.pages,0)],[7,2,2]);
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
   yes("authority/terminal",v.state==="failed"&&v.exit_code===1&&v.output_complete===true&&v.output_durable===true&&v.terminal_publication_confirmed===true);
   yes("authority/no-cancel-timeout",v.cancelled===false&&v.timed_out===false);
   for(const n of ["stdout","stderr"]){
    const expected=n==="stdout"?1783:0;
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
    eq("stream/"+a.id+"/"+n+"/size",row.size,n==="stdout"?1783:0);
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
   yes("op/"+i+"/key-prefix",q.idempotency_key.startsWith("heptabao-mac-public-node-crash-33b29c19-"));
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
 eq("counts/native",counts,{process_start:1,operation_start:2,operation_status:2,operation_result:2});
 yes("final/all-observers-closed",active===null&&finished===2);
 eq("final/stdout-original",stdout,files["stdout.original.json"]);eq("final/stderr-original",stderr,files["stderr.original.txt"]);
 eq("final/extents",[nextOut,nextErr],[1783,0]);
 eq("final/whole-stdout",meta(stdout),{blob:"2efead8a4275b7f1298c45833a64ec229fc240b4",bytes:1783,sha256:"5bc611df8194b881da135d0406b081d616289f3531aa848ea60328e4fdffdb2c"});
 yes("final/context-zero",state.job===job&&state.nativeCallInFlight===false&&state.pending===null&&state.activeObserver===null&&state.paused===false);
 yes("final/release-zero",release.lane.activeCalls===0&&release.lane.activeNativeFutures===0&&release.lane.released===true);
 eq("final/release-counts",[release.originalCalls,release.originalObservers,release.immutablePages],[7,2,2]);


 eq("failure/exact-error",report.error,{code:"fixed_directory_shape",errno:null,type:"Refused"});
 eq("failure/top-level",[report.ok,report.observationComplete,report.outcomeUnknown],[false,false,false]);
 yes("failure/own-close",report.allOwnResourcesClosed===true&&report.io.allReturnedFdsAndIteratorClosed===true&&report.finalHeldNamedFencesPassed===true&&report.handlersRestored===true&&report.afterClosureDeadlineMet===true&&report.pendingSignalObserved===false);
 eq("failure/io",[report.io.returnedFdLedger.attempts,report.io.returnedFdLedger.registered,report.io.returnedFdLedger.pending,report.io.returnedFdLedger.registrationUnknown,report.io.metadataCalls,report.io.readCalls,report.io.returnedReadBytes],[5,5,0,false,26,0,0]);
 eq("failure/no-enumeration",[report.io.scan.attempted,report.io.scan.returned,report.io.scan.entriesExamined,report.io.scan.coverageComplete],[false,false,0,false]);
 eq("failure/no-projection",[report.candidates,report.fixedPathChainObserved,report.matchedReportCount,report.matchingFreshReportFound],[[],[],0,false]);
 yes("failure/known-no-new-resource-ambiguity",report.io.closeErrors.length===0&&report.io.scan.pending===false&&report.io.scan.registrationUnknown===false);
 for(const key of ["historicalManagedClosureClaimed","originalRuntimeCauseProved","originalRuntimeProgressReclassified","newProbeCauseConclusionClaimed","oldPrivateLogsOrCapsuleRequested","SDKOrCredentialOrProviderCalled","otherPidSignalOrWait","launchdOperation","T5ReadOrWrite","fallbackDirectory","rawIpsOrUnknownTextOrHashExported"])
  eq("scope/"+key,report[key],false);
 eq("scope/writes-children",[report.filesystemWrites,report.childProcesses],[0,0]);
 return {schema:"heptabao.node-crash-original-failure-pure-checks.r1",passed:checks.every(x=>x.passed),checkCount:checks.length,checks,
 originalCalls:7,returnedObservers:2,immutablePages:2,NativeCallsAdded:0,
 execution:"pure V8 original public SDK/intent/payload/stream verification only",
 actualDirectoryPredicateIdentified:false,crashBodyRead:false,crashReportAbsenceClaimed:false,crashCauseClaimed:false,historicalUnknownPreserved:true};
}
