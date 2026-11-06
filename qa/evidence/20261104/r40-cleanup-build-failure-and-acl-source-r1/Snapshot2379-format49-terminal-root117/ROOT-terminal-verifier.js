
function qualifySnapshot2379Format49Terminal(){
 const p=load("r34_packet_Snapshot2379-formatter49-full-actual98"),r=p.raw,idx=JSON.parse(r["calls-and-observers.public.json"]),rel=JSON.parse(r["RELEASE.public.json"]),go=load("r40_snapshot2379_formatter49_GO"),checks=[];
 const ck=(name,v)=>{checks.push({name,passed:v===true});if(v!==true)throw Error(name);},eq=(s,p)=>{const m=gitBlobMeta(s);return m.blob===p.blob&&m.bytes===p.bytes&&m.sha256===p.sha256;},same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),bm=Object.fromEntries(p.pins.map(x=>[x.blob,r[x.path]]));
 ck("whole98_623692",p.audit.whole===true&&p.audit.files===98&&p.audit.bytes===623692);
 ck("exact_GO_source_stdin_and_journal",eq(r["root-go.original.json"],go)&&eq(r["formatter-source.py"],go.value.source)&&eq(r["stdin-manifest.original.json"],go.value.stdin)&&eq(r["journal-source.js"],go.value.helpers.native));
 const calls=idx.calls.map(c=>({key:c.key,kind:c.kind,phase:c.phase,requestPin:c.request,sdkPin:c.sdk,nativePin:c.native,requestText:r[c.prefix+".request.json"],sdkText:r[c.prefix+".sdk.json"],nativeText:r[c.prefix+".native.json"],armedText:r[c.prefix+".armed.json"],intentText:r[c.prefix+".intent.json"],armedTree:c.armedTree}));
 const obs=idx.observers,cs=verifyOriginalJournal({label:"snapshot2379Formatter",calls,observers:obs,blob:x=>bm[x],goPins:[go],pageLimit:()=>8192,ck});
 ck("16_original_calls_3_observers_9_pages_once",cs.length===16&&idx.calls.every(c=>c.called===true&&c.phase==="accepted")&&cs.filter(x=>x.c.kind==="process_start").length===1&&obs.length===3&&obs.reduce((n,o)=>n+o.pages,0)===9&&same(obs,rel.completedObservers));
 const start=cs.find(x=>x.c.kind==="process_start"),ack=start.n,job=rel.job,binding=processStartBinding(start.q);
 ck("exact_START_binding_job",job==="1a1b02771c2-fc05-6e9f"&&eq(start.c.requestText,go.value.exact_request)&&eq(start.q.args[4],go.value.source)&&eq(start.q.stdin,go.value.stdin)&&ack.reused===false&&ack.audit_recorded===true&&ack.local_record_pending===false&&ack.launch.ok===true&&ack.job.id===job&&ack.job.host==="rog"&&ack.job.idempotency_key===go.value.start.idempotency_key&&ack.job.request_digest===binding.sha256&&binding.sha256===go.value.native_binding.sha256&&binding.native_fingerprint===go.value.native_binding.native_fingerprint&&ack.job.request_fingerprint.$exactInteger===binding.native_fingerprint);
 ck("only_original_job_observers",cs.filter(x=>x.c.kind==="operation_start").every(x=>["process_status","process_read"].includes(x.q.operation.tool)&&x.q.operation.arguments.host==="rog"&&x.q.operation.arguments.job_id===job));
 const a=JSON.parse(r["authority.original.json"]);
 ck("known_exit0_full_durable",eq(r["authority.original.json"],rel.authority)&&eq(r["authority.original.json"],obs[0].nativeText)&&a.job_id===job&&a.exit_code===0&&a.state==="succeeded"&&a.output_complete===true&&a.output_durable===true&&a.terminal_publication_confirmed===true&&!a.timed_out&&!a.cancelled&&!a.automatic_retry);
 ck("17780_stdout_zero_stderr_no_truncation",a.log_bytes.stdout.seen===17780&&a.log_bytes.stdout.stored===17780&&a.log_bytes.stderr.seen===0&&a.log_bytes.stderr.stored===0&&["stdout","stderr"].every(n=>a.log_errors[n]===null&&a.log_synced[n]===true&&a.log_truncated[n]===false));
 let stdout="",stderr="",so=0,se=0;
 for(let i=1;i<3;i++){
  const s=JSON.parse(bm[obs[i].nativeText.blob]),req=cs.find(x=>x.c.kind==="operation_start"&&x.n.operation_id===obs[i].id).q.operation.arguments;
  ck("stream"+i+"_request_cursors",req.stdout_offset===so&&req.stderr_offset===se&&req.limit===16384);
  for(const name of["stdout","stderr"]){
   const v=s[name],b=utf8Bytes(v.text),offset=name==="stdout"?so:se;
   ck("stream"+i+"_"+name+"_actual_bytes",s.job_id===job&&v.offset===offset&&v.next_offset===offset+b.length&&b.length<=16384&&v.bytes_hex===b.map(x=>x.toString(16).padStart(2,"0")).join("")&&v.size===(name==="stdout"?17780:0)&&v.eof===(v.next_offset===v.size));
  }
  stdout+=s.stdout.text;stderr+=s.stderr.text;so=s.stdout.next_offset;se=s.stderr.next_offset;
 }
 ck("whole_original_streams_EOF",so===17780&&se===0&&stdout===r["stdout.original.txt"]&&stderr===""&&stderr===r["stderr.original.txt"]&&eq(stdout,rel.stdout)&&eq(stderr,rel.stderr));
 const v=JSON.parse(stdout),union=load("r39_snapshot_Service49_unformatted_union");
 ck("actual_summary_49_original_budgets",v.status==="passed"&&v.allOwnedStopped===true&&v.withinDeadline===true&&v.error===null&&v.publicationError===null&&v.elapsedSeconds>0&&v.elapsedSeconds<50&&v.root===go.value.new_create_only_root&&v.files.length===49&&union.length===49);
 ck("ordered_49_frozen_source_bindings",same(v.files.map(x=>x.name),union.map(x=>x.name))&&idx.expectedInputs.length===49&&idx.expectedInputs.every((x,i)=>x.path===union[i].path&&x.name===union[i].name&&x.unformattedSource.blob===union[i].blob&&x.unformattedSource.bytes===union[i].bytes&&x.unformattedSource.sha256===union[i].sha256));
 for(let i=0;i<49;i++){const f=v.files[i],u=union[i];ck("declared_output_"+f.name,f.beforeBytes===u.bytes&&f.beforeSha256===u.sha256&&Number.isInteger(f.afterBytes)&&f.afterBytes>0&&f.afterBytes<=(f.name==="service.rs"?655360:262144)&&/^[0-9a-f]{64}$/.test(f.afterSha256)&&f.stderrBytes===0&&f.stderrSha256==="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");}
 ck("original_state_and_lane_fully_closed",idx.state.startCalled===true&&idx.state.pending===null&&idx.state.activeObserver===null&&idx.state.nativeCallInFlight===false&&idx.state.paused===false&&idx.state.nextStdout===17780&&idx.state.nextStderr===0&&rel.activeNativeCalls===0&&rel.activeNativeFutures===0&&rel.activeNativeProcesses===0&&rel.allOriginalObserversClosed===true&&rel.laneBReleased===true);
 const author=verifyFormat49OriginalChain(r);
 ck("author236_reproduced",author.pass===true&&author.count===236&&same(author,JSON.parse(r["chain-checks.actual.json"])));
 store("r40_snapshot2379_formatter49_summary",v);
 return {schema:"heptabao.root-qualification.snapshot2379-format49-terminal.v1",status:"PASS_ORIGINAL_TERMINAL_COMPLETE_STREAMS_AND_DECLARED_HASHES",evidence_qualified:true,checks,check_count:checks.length,packet:p.audit,original_job:"rog/"+job,authority:rel.authority,stdout:rel.stdout,stderr:rel.stderr,actual:{native_calls:16,observers:3,immutable_pages:9,exit_code:0,stdout_bytes:17780,stderr_bytes:0,full_durable:true,elapsed_seconds:v.elapsedSeconds,declared_files:49},declared_outputs:v.files.map((f,i)=>({path:union[i].path,...f})),author_pure_checks_reproduced:236,limitations:["Detailed report and per-command custody still require the independent report metadata/body.","These output hashes are actual formatter declarations. Formatted files,full9 and source/tool/config final fences need independent evidence before publication or build.","No formatter independent child-group-emptiness claim; direct Popen children retain the reviewed supervisor PGID.","No Cargo or product runtime qualification follows from formatting."],detailed_report_qualified:false,formatted_bodies_independently_qualified:false,compiled:false,full_replacement:false,production_cutover:false,legacy_cleanup:false,root_Runtime_calls:0};
}
