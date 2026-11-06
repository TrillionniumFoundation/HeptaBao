function verifyOriginalLanIdentityRoutes(input) {
 const checks=[],rows=[],go=JSON.parse(input.goRaw),pairs={};
 const canonical=x=>JSON.stringify(x,(_,v)=>v&&typeof v==="object"&&!Array.isArray(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v);
 const eq=(a,b)=>canonical(a)===canonical(b);
 const check=(name,ok)=>{checks.push({name,pass:!!ok});if(!ok)throw new Error(name);};
 const same=(raw,pin)=>{const a=gitBlobMeta(raw);return a.blob===pin.blob&&a.bytes===pin.bytes&&a.sha256===pin.sha256;};
 const integer=v=>Number.isSafeInteger(v)?String(v):v?.$exactInteger;
 function flatTree(texts){const b=[];for(const name of Object.keys(texts).sort()){b.push(...utf8Bytes("100644 "+name+"\0"));const h=gitBlobMeta(texts[name]).blob;for(let i=0;i<40;i+=2)b.push(parseInt(h.slice(i,i+2),16));}return sha1Bytes(utf8Bytes("tree "+b.length+"\0").concat(b));}
 let totalCalls=0,totalPages=0,totalObservers=0,totalStdout=0;
 check("six_fixed_routes",input.routes.length===6);
 for(let r=0;r<6;r++){
  const route=input.routes[r],f=route.files,expected=go.fixed_order[r],prefix=route.name+":",state=JSON.parse(f["STATE.original.json"]),calls=JSON.parse(f["CALL-INDEX.public.json"]),obs=JSON.parse(f["OBSERVERS.public.json"]),manifest=JSON.parse(f["MANIFEST.public.json"]);
  check(prefix+"source_packet_member_count",Object.keys(f).length===manifest.files.length+1);
  for(const leaf of manifest.files)check(prefix+"whole:"+leaf.path,same(f[leaf.path],leaf));
  check(prefix+"exact_GO",f["GO.original.json"]===input.goRaw);
  check(prefix+"exact_request",same(f["request.original.json"],expected.request));
  check(prefix+"exact_journal",same(f["journal.source.js"],expected.journal));
  check(prefix+"exact_probe",same(f["probe.source.py"],go.source));
  check(prefix+"state_closed",state.rootGoWhole===true&&state.startCalled===true&&state.pending===null&&state.activeObserver===null&&!state.nativeCallInFlight&&!state.paused&&!state.outerFailure);
  check(prefix+"state_GO",state.goRaw===input.goRaw&&same(input.goRaw,state.goPin)&&state.digest===expected.typed.sha256&&state.fingerprint===expected.typed.native_fingerprint);
  check(prefix+"call_index_order",eq(calls.map(x=>x.callKey),Object.keys(state.calls)));
  let job=null,active=null,starts=0,statusObservers=0,readObservers=0,authority=null,stdout="",stderr="",closed=0;
  for(let i=0;i<calls.length;i++){
   const c=calls[i],stem=c.stem,qraw=f[stem+".request.original.json"],q=JSON.parse(qraw),sdk=JSON.parse(f[stem+".SDK.original.json"]),nativeRaw=f[stem+".native.original.json"],v=parseLosslessIntegers(nativeRaw),intent=JSON.parse(f[stem+".intent.original.json"]),armed=JSON.parse(f[stem+".armed.original.json"]),sc=state.calls[c.callKey];
   check(prefix+"call"+i+":all_pins",same(qraw,c.request)&&same(f[stem+".SDK.original.json"],c.SDK)&&same(nativeRaw,c.native)&&eq(c.request,sc.requestPin)&&eq(c.SDK,sc.sdkPin)&&eq(c.native,sc.nativePin));
   check(prefix+"call"+i+":original_SDK_text",sdk.isError!==true&&sdk.content?.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===nativeRaw);
   check(prefix+"call"+i+":external_intent",intent.callKey===c.callKey&&intent.kind===c.kind&&eq(intent.request,c.request)&&eq(intent.rootGo,state.goPin)&&intent.originalJob===job&&intent.originalOperation===(active?.id??null)&&intent.nativeNotYetCalled&&intent.maximumNativeCalls===1&&intent.lossOfAcknowledgmentNeverGrantsReplay);
   check(prefix+"call"+i+":external_arm",armed.callKey===c.callKey&&armed.kind===c.kind&&eq(armed.request,c.request)&&eq(armed.rootGo,state.goPin)&&armed.mayHaveDispatchedAfterThisCheckpoint===true&&armed.nativeNotYetCalled===true);
   const at=flatTree({"request.json":qraw,"intent.json":f[stem+".intent.original.json"],"armed.json":f[stem+".armed.original.json"]}),st=flatTree({"original.sdk.json":f[stem+".SDK.original.json"]});
   check(prefix+"call"+i+":arm_Merkle_ACK",at===c.armed.tree&&c.armed.whole===true&&JSON.parse(f[stem+".armed.GitACK.original.sdk.json"]).structuredContent?.sha===at);
   check(prefix+"call"+i+":SDK_Merkle_ACK",st===c.SDK_archive.tree&&c.SDK_archive.whole===true&&JSON.parse(f[stem+".SDK.GitACK.original.sdk.json"]).structuredContent?.sha===st);
   check(prefix+"call"+i+":once_accepted",c.called===true&&c.phase==="accepted"&&sc.called===true&&sc.phase==="accepted"&&sc.requestRaw===qraw);
   if(c.kind==="process_start"){
    starts++;check(prefix+"start:exact",i===0&&job===null&&active===null&&qraw===f["request.original.json"]&&v.reused===false&&v.audit_recorded===true&&v.local_record_pending===false&&v.launch?.ok===true);
    check(prefix+"start:binding",v.job?.idempotency_key===q.idempotency_key&&v.job.host===q.host&&v.job.executable===q.executable&&eq(v.job.args,q.args)&&v.job.cwd===q.cwd&&v.job.execution_mode==="operator"&&v.job.request_digest===expected.typed.sha256&&integer(v.job.request_fingerprint)===expected.typed.native_fingerprint);
    job=v.job.id;
   } else if(c.kind==="operation_start"){
    const a=q.operation?.arguments;
    check(prefix+"observer:original_job:"+i,job!==null&&active===null&&a?.job_id===job&&a.host===JSON.parse(f["request.original.json"]).host&&q.idempotency_key.startsWith(expected.observer_key_prefix));
    check(prefix+"observer:unique_ACK:"+i,v.reused===false&&v.automatic_retry===false&&/^[a-f0-9]{64}$/.test(v.operation_id)&&v.tool_name===q.operation.tool);
    if(q.operation.tool==="process_status"){statusObservers++;check(prefix+"status:arguments:"+i,Object.keys(a).sort().join(",")==="host,job_id");}
    else{readObservers++;check(prefix+"read:arguments:"+i,q.operation.tool==="process_read"&&a.limit===16384&&a.stdout_offset===utf8Bytes(stdout).length&&a.stderr_offset===utf8Bytes(stderr).length&&Object.keys(a).sort().join(",")==="host,job_id,limit,stderr_offset,stdout_offset");}
    active={id:v.operation_id,tool:v.tool_name,args:a,closed:false,statuses:0,pages:[],bytes:[],next:0,total:null,digest:null};
   } else if(c.kind==="operation_status"){
    check(prefix+"status:same_id:"+i,active!==null&&!active.closed&&q.operation_id===active.id&&v.operation_id===active.id&&v.tool_name===active.tool&&v.automatic_retry===false&&Object.keys(q).join(",")==="operation_id");
    active.statuses++;
    check(prefix+"status:budget:"+i,active.statuses<=8);
    check(prefix+"status:closed:"+i,v.async_state==="completed"&&v.owned_future_active===false&&v.result_state==="stored_observed"&&v.payload_available===true);
    active.closed=true;
   } else {
    check(prefix+"page:request:"+i,c.kind==="operation_result"&&active?.closed===true&&q.operation_id===active.id&&q.offset===active.next&&q.limit===8192&&Object.keys(q).sort().join(",")==="limit,offset,operation_id");
    const b=unb64(v.data_base64);
    check(prefix+"page:identity:"+i,v.operation_id===active.id&&v.offset===q.offset&&v.immutable_snapshot===true&&v.payload_kind==="native_result"&&v.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization"&&v.total_bytes<=1048576&&/^[a-f0-9]{64}$/.test(v.result_sha256));
    check(prefix+"page:extent:"+i,b.length<=8192&&v.next_offset===q.offset+b.length&&v.eof===(v.next_offset===v.total_bytes)&&v.next_offset<=v.total_bytes&&(b.length>0||v.eof));
    check(prefix+"page:stable_payload:"+i,active.total===null||(active.total===v.total_bytes&&active.digest===v.result_sha256));
    active.total=v.total_bytes;active.digest=v.result_sha256;active.bytes.push(...b);active.next=v.next_offset;active.pages.push(c.native);
    check(prefix+"page:budget:"+i,active.pages.length<=128);totalPages++;
    if(v.eof){
     const o=obs[closed],payload=utf8Text(active.bytes),envelope=parseLosslessIntegers(payload);
     check(prefix+"payload:assembled:"+closed,o.id===active.id&&o.tool===active.tool&&o.completedInactive===true&&o.pages===active.pages.length&&f[o.stem+".payload.original.json"]===payload&&same(payload,o.payload)&&gitBlobMeta(payload).bytes===active.total&&gitBlobMeta(payload).sha256===active.digest);
     check(prefix+"payload:external_ACK:"+closed,JSON.parse(f[o.stem+".payload.GitACK.original.sdk.json"]).structuredContent?.sha===o.payloadTree&&flatTree({"payload.original.json":payload})===o.payloadTree);
     check(prefix+"payload:original_complete:"+closed,envelope.resultType==="complete"&&envelope.isError===false&&envelope.content?.length===1&&envelope.content[0].type==="text"&&envelope.content[0].text===f[o.stem+".native.original.json"]&&same(envelope.content[0].text,o.nativeText));
     const n=parseLosslessIntegers(envelope.content[0].text);check(prefix+"native:job:"+closed,n.job_id===job);
     if(active.tool==="process_status"){
      authority=n;check(prefix+"authority:terminal",n.state==="succeeded"&&n.exit_code===0&&n.output_complete&&n.output_durable&&n.terminal_publication_confirmed&&!n.cancelled&&!n.timed_out&&!n.automatic_retry);
      check(prefix+"authority:streams",["stdout","stderr"].every(k=>n.log_bytes[k].seen===n.log_bytes[k].stored&&n.log_synced[k]===true&&n.log_truncated[k]===false&&n.log_errors[k]===null));
     }else{
      for(const k of ["stdout","stderr"]){const x=n[k],b2=[];for(let z=0;z<x.bytes_hex.length;z+=2)b2.push(parseInt(x.bytes_hex.slice(z,z+2),16));
       check(prefix+"stream:"+k,x.offset===active.args[k+"_offset"]&&/^[0-9a-f]*$/.test(x.bytes_hex)&&x.bytes_hex.length%2===0&&b2.length<=16384&&x.next_offset===x.offset+b2.length&&x.eof===true&&x.next_offset===x.size&&utf8Text(b2)===x.text);
       if(k==="stdout")stdout+=x.text;else stderr+=x.text;}
     }
     closed++;totalObservers++;active=null;
    }
   }
  }
  check(prefix+"finished:counts",starts===1&&statusObservers<=8&&readObservers<=2&&active===null&&closed===obs.length&&closed===2&&job===state.job);
  check(prefix+"finished:whole_streams",stdout===f["stdout.original.txt"]&&stderr===f["stderr.original.txt"]&&stderr===""&&state.nextStdout===utf8Bytes(stdout).length&&state.nextStderr===0&&authority.log_bytes.stdout.stored===utf8Bytes(stdout).length&&authority.log_bytes.stderr.stored===0&&utf8Bytes(stdout).length<=8192);
  const report=JSON.parse(stdout),linux=expected.role!=="mac";
  check(prefix+"resources",report.resources.length===(linux?8:2)&&report.resources.every(x=>x.acquired&&x.close_attempted&&x.closed&&x.close_error===null)&&report.all_probe_resources_closed===true);
  check(prefix+"input_scope",linux?report.reads.length===6&&report.sysctls.length===0&&report.reads.every((x,i)=>x.path===["/sys/devices/virtual/dmi/id/product_name","/etc/machine-id","/proc/sys/kernel/random/boot_id"][i%3]&&x.maximum===[256,64,64][i%3]&&x.bytes>0&&x.bytes<=x.maximum&&x.eof&&x.metadata_before_after_name.length===9&&x.metadata_before_after_name.every(y=>typeof y==="string")):report.reads.length===0&&report.sysctls.length===4&&report.sysctls.every((x,i)=>x.key===["hw.model","kern.bootsessionuuid"][i%2]&&x.maximum===[256,64][i%2]&&x.bytes_including_nul>1&&x.bytes_including_nul<=x.maximum));
  if(!pairs[expected.role])pairs[expected.role]={};pairs[expected.role][expected.route]=report;
  totalCalls+=calls.length;totalStdout+=utf8Bytes(stdout).length;
  rows.push({name:route.name,job,calls:calls.length,observers:closed,pages:obs.reduce((n,x)=>n+x.pages,0),stdout:gitBlobMeta(stdout),stderr:gitBlobMeta(stderr),exit_code:authority.exit_code});
 }
 const comparison=compareFinalLanRoutes(pairs,null);
 check("actual_comparison_exact",eq(comparison,input.comparison));
 check("total_calls_46",totalCalls===46);check("total_observers_12",totalObservers===12);check("total_pages_16",totalPages===16);check("total_stdout_18894",totalStdout===18894);
 return {schema:"heptabao.final-lan-identity-original-chain-verification.r1",pass:true,check_count:checks.length,checks,rows,totals:{calls:totalCalls,observers:totalObservers,pages:totalPages,stdout:totalStdout,stderr:0},comparison,Native_calls:0,product_cases:0,old_unknown_contexts_unchanged:true};
}
