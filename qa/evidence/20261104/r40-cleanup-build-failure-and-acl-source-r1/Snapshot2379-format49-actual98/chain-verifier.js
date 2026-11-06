function verifyFormat49OriginalChain(texts){
 const checks=[];
 function check(name,value){checks.push({name,pass:!!value});if(!value)throw new Error(name);}
 const obj=parseLosslessIntegers,meta=gitBlobMeta;
 function exact(raw,p){const m=meta(raw);return m.blob===p.blob&&m.bytes===p.bytes&&m.sha256===p.sha256;}
 function eq(a,b){return JSON.stringify(a)===JSON.stringify(b);}
 const index=obj(texts["calls-and-observers.public.json"]),release=obj(texts["RELEASE.public.json"]);
 check("16-original-calls",index.calls.length===16);
 check("only-one-start",index.calls.filter(c=>c.kind==="process_start").length===1);
 check("3-original-observers",index.observers.length===3);
 check("9-original-pages",index.observers.reduce((n,o)=>n+o.pages,0)===9);
 check("original-closed-state",index.state.pending===null&&index.state.activeObserver===null&&index.state.nativeCallInFlight===false&&index.state.paused===false);
 for(const c of index.calls){
  check(c.key+":accepted-once",c.called===true&&c.phase==="accepted");
  for(const field of ["request","intent","armed","sdk","native"])check(c.key+":"+field+"-whole",exact(texts[c.prefix+"."+field+".json"],c[field]));
  const request=obj(texts[c.prefix+".request.json"]),intent=obj(texts[c.prefix+".intent.json"]),armed=obj(texts[c.prefix+".armed.json"]),sdk=obj(texts[c.prefix+".sdk.json"]);
  check(c.key+":request-intent-arm",eq(intent.request,c.request)&&eq(armed.request,c.request)&&intent.maximumNativeCalls===1&&intent.nativeNotYetCalled===true&&armed.mayHaveDispatchedAfterThisCheckpoint===true);
  check(c.key+":sdk-native-exact",sdk.isError!==true&&sdk.content.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===texts[c.prefix+".native.json"]);
  if(c.kind==="operation_start")check(c.key+":original-job-only",request.operation.arguments.host==="rog"&&request.operation.arguments.job_id===index.job&&["process_status","process_read"].includes(request.operation.tool));
 }
 const first=index.calls[0],q=obj(texts[first.prefix+".request.json"]),ack=obj(texts[first.prefix+".native.json"]);
 check("exact-original-request",first.request.blob==="0fce0771c8a4e42b85abfc10ffbc14e59e588616"&&first.request.bytes===34045&&first.request.sha256==="72289e6809a067df0df78ae0bd96383725ccbbcaca6fb219349c9ede1d4ce70f");
 check("source-stdin-byte-binding",q.args.length===5&&eq(q.args.slice(0,4),["-I","-S","-B","-c"])&&q.args[4]===texts["formatter-source.py"]&&q.stdin===texts["stdin-manifest.original.json"]);
 check("original-host-timeout-key",q.host==="rog"&&q.executable==="/usr/bin/python3"&&q.timeout_seconds===60&&q.idempotency_key==="heptabao-native-snapshot-forward-2379d02b-format-20261106-r1-5c461ab0");
 check("original-unique-ack",ack.reused===false&&ack.launch.ok===true&&ack.audit_recorded===true&&ack.local_record_pending===false&&ack.job.id===index.job&&ack.job.host==="rog"&&ack.job.request_digest==="8b4e78b9c28d7e9480bc4f3898aaec15e6fb5a08d236f687c939eb06a59da5cc"&&ack.job.request_fingerprint.$exactInteger==="10038093358683750036");
 const originalResults=[];
 for(let i=0;i<index.observers.length;i++){
  const o=index.observers[i],payloadRaw=texts["observer"+i+".payload.json"],nativeRaw=texts["observer"+i+".native.json"];
  check(o.id+":payload-whole",exact(payloadRaw,o.payload)&&o.completedInactive===true);
  check(o.id+":native-whole",exact(nativeRaw,o.nativeText));
  const payload=obj(payloadRaw);check(o.id+":sdk-envelope",payload.resultType==="complete"&&payload.isError===false&&payload.content.length===1&&payload.content[0].text===nativeRaw);
  const admits=index.calls.filter(c=>c.kind==="operation_start"&&obj(texts[c.prefix+".native.json"]).operation_id===o.id);
  check(o.id+":one-admission",admits.length===1&&obj(texts[admits[0].prefix+".native.json"]).reused===false);
  const statuses=index.calls.filter(c=>c.kind==="operation_status"&&obj(texts[c.prefix+".request.json"]).operation_id===o.id);
  check(o.id+":one-closed-status",statuses.length===1);
  const st=obj(texts[statuses[0].prefix+".native.json"]);check(o.id+":completed-inactive",st.operation_id===o.id&&st.async_state==="completed"&&st.owned_future_active===false&&st.result_state==="stored_observed"&&st.payload_available===true&&st.automatic_retry===false);
  const pages=index.calls.filter(c=>c.kind==="operation_result"&&obj(texts[c.prefix+".request.json"]).operation_id===o.id);
  check(o.id+":page-count",pages.length===o.pages);
  let off=0,bytes=[];
  for(const c of pages){const req=obj(texts[c.prefix+".request.json"]),p=obj(texts[c.prefix+".native.json"]),b=unb64(p.data_base64);
   check(c.key+":original-page",req.offset===off&&req.limit===8192&&p.operation_id===o.id&&p.offset===off&&p.next_offset===off+b.length&&b.length<=8192&&p.immutable_snapshot===true&&p.payload_kind==="native_result"&&p.total_bytes===o.payload.bytes&&p.result_sha256===o.payload.sha256&&p.eof===(p.next_offset===p.total_bytes));
   bytes=bytes.concat(b);off=p.next_offset;
  }
  check(o.id+":all-original-payload-bytes",off===o.payload.bytes&&utf8Text(bytes)===payloadRaw);
  const v=obj(nativeRaw);check(o.id+":original-result-job",v.job_id===index.job);originalResults.push(v);
 }
 const authority=originalResults[0];
 check("authority-terminal",authority.exit_code===0&&authority.state==="succeeded"&&authority.output_complete===true&&authority.output_durable===true&&authority.terminal_publication_confirmed===true&&authority.timed_out===false&&authority.cancelled===false);
 check("authority-original-stream-extents",authority.log_bytes.stdout.seen===17780&&authority.log_bytes.stdout.stored===17780&&authority.log_bytes.stderr.seen===0&&authority.log_bytes.stderr.stored===0&&authority.log_truncated.stdout===false&&authority.log_truncated.stderr===false&&authority.log_synced.stdout===true&&authority.log_synced.stderr===true);
 let sout="",serr="",so=0,se=0;
 for(let n=1;n<originalResults.length;n++){const r=originalResults[n];
  for(const [label,off]of[["stdout",so],["stderr",se]]){const v=r[label],b=[];for(let k=0;k<v.bytes_hex.length;k+=2)b.push(parseInt(v.bytes_hex.slice(k,k+2),16));check("stream"+n+":"+label+"-bytes",v.offset===off&&v.next_offset===off+b.length&&b.length<=16384&&utf8Text(b)===v.text&&v.size>=v.next_offset&&(!v.eof||v.next_offset===v.size));}
  sout+=r.stdout.text;serr+=r.stderr.text;so=r.stdout.next_offset;se=r.stderr.next_offset;
 }
 check("streams-final-eof",originalResults[2].stdout.eof===true&&originalResults[2].stderr.eof===true&&so===17780&&se===0);
 check("standalone-streams-whole",sout===texts["stdout.original.txt"]&&serr===texts["stderr.original.txt"]&&meta(sout).bytes===17780&&serr==="");
 const summary=obj(sout),inputs=index.expectedInputs;
 check("formatter-summary",summary.status==="passed"&&summary.allOwnedStopped===true&&summary.withinDeadline===true&&summary.elapsedSeconds>0&&summary.elapsedSeconds<50&&summary.error===null&&summary.publicationError===null);
 check("49-ordered-rows",summary.files.length===49&&inputs.length===49&&eq(summary.files.map(f=>f.name),inputs.map(f=>f.name)));
 for(let i=0;i<49;i++){const f=summary.files[i],p=inputs[i].unformattedSource;check(f.name+":source-and-output-pins",f.beforeBytes===p.bytes&&f.beforeSha256===p.sha256&&f.afterBytes>0&&f.afterBytes<=(f.name==="service.rs"?655360:262144)&&/^[a-f0-9]{64}$/.test(f.afterSha256)&&f.stderrBytes===0&&f.stderrSha256==="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");}
 check("release-original-associations",release.job===index.job&&exact(texts["authority.original.json"],release.authority)&&exact(sout,release.stdout)&&exact(serr,release.stderr)&&release.originalNativeCalls===16&&release.immutablePages===9&&release.activeNativeCalls===0&&release.activeNativeFutures===0&&release.activeNativeProcesses===0&&release.laneBReleased===true);
 return {schema:"heptabao.snapshot2379.format49.original-chain-checks.r1",pass:true,count:checks.length,checks,scope:"Original job terminal/full streams and declared per-file hashes only; detailed report, output file_info/full9 and independent formatted bodies still pending.",noNativeCalls:true};
}