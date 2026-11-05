function verifyCurrentExporterInert(r,a,proposal,u,sha,decode,parse){
const checks=[],ck=(n,v)=>{if(!v)throw Error(n);checks.push(n);};
const canon=v=>v&&typeof v==="object"?Array.isArray(v)?v.map(canon):Object.fromEntries(Object.keys(v).sort().map(k=>[k,canon(v[k])])):v;
const same=(x,y)=>JSON.stringify(canon(x))===JSON.stringify(canon(y));
const q=JSON.parse(r["dispatch/inert.request.public.json"]),ack=JSON.parse(r["actual/ACK.original.json"]),authority=JSON.parse(r["actual/authority.original.json"]),streams=JSON.parse(r["actual/streams.original.json"]),source=r["actual/source_export_same_root_publication_4e808_r1.py"],index=JSON.parse(r["reads/index.public.json"]);
const D="/home/qian-qi/heptabao-same-root-publication-source-export-controls-20261105-r1";
ck("whole actual76 and 14 Merkle trees",a.files===76&&a.bytes===484967&&a.merkle.trees_verified===14);
ck("request byte exact approved SOURCE",r["dispatch/inert.request.public.json"]===proposal["dispatch/inert.request.json"]);
ck("inert carrier exactly approved SOURCE",r["source/exporter_inert_4e808_r1.py"]===proposal["candidate/exporter_inert_4e808_r1.py"]);
ck("actual exporter body byte exact approved SOURCE",source===proposal["candidate/source_export_same_root_publication_4e808_r1.py"]);
ck("original ACK from SDK exact",JSON.parse(r["actual/process-start.original.sdk.json"]).content[0].text===r["actual/ACK.original.json"]);
ck("ACK exact original job and request",ack.reused===false&&ack.job.id==="1a1abb9785a-fc05-5029"&&ack.job.host==="rog"&&ack.job.cwd===q.cwd&&ack.job.executable===q.executable&&same(ack.job.args,q.args)&&ack.job.idempotency_key===q.idempotency_key);
ck("original 60s stage budget unchanged",q.timeout_seconds===60);
ck("known zero durable complete original authority",authority.job_id===ack.job.id&&authority.exit_code===0&&authority.output_complete===true&&authority.output_durable===true&&authority.terminal_publication_confirmed===true&&authority.timed_out===false&&authority.cancelled===false);
const labels=["authority","streams","source-info","receipt-info","source-body","receipt-body"];
ck("six independent exact original read operations",index.read_operations.length===6&&same(index.read_operations.map(x=>x.label),labels)&&index.immutable_page_count===8);
let pages=0;
for(const row of index.read_operations){
 const prefix="reads/"+row.label+"/",qop=JSON.parse(r[prefix+"request.public.json"]),status=JSON.parse(r[prefix+"status.original.json"]);
 ck("closed original operation "+row.label,status.operation_id===row.operation_id&&status.async_state==="completed"&&status.result_state==="stored_observed"&&status.owned_future_active===false&&status.payload_available===true);
 const expectedTool=row.label==="authority"?"process_status":row.label==="streams"?"process_read":row.label.endsWith("-info")?"file_info":"binary_read";
 ck("only exact readonly type "+row.label,qop.operation.tool===expectedTool&&qop.operation.arguments.host==="rog");
 const pagePaths=Object.keys(r).filter(p=>p.startsWith(prefix+"page-")&&p.endsWith(".original.json")).sort();
 ck("exact page denominator "+row.label,pagePaths.length===row.pages);
 let raw="",offset=0;
 for(const p of pagePaths){
  const n=JSON.parse(r[p]),piece=decode(n.data_base64),sdk=JSON.parse(r[p.replace(".original.json",".original.sdk.json")]);
  ck("page SDK exact native "+p,sdk.isError===false&&sdk.content[0].text===r[p]);
  ck("immutable page continuous "+p,n.operation_id===row.operation_id&&n.offset===offset&&n.next_offset===offset+u(piece).length&&n.immutable_snapshot===true&&n.total_bytes===row.payload_bytes&&n.result_sha256===row.payload_sha256&&n.payload_kind==="native_result");
  raw+=piece;offset=n.next_offset;pages++;
  if(p===pagePaths[pagePaths.length-1])ck("final page EOF "+row.label,n.eof===true&&offset===row.payload_bytes);
 }
 ck("whole exact original SDK "+row.label,raw===r[prefix+"payload.original.sdk.json"]&&u(raw).length===row.payload_bytes&&sha(raw)===row.payload_sha256);
 const native=JSON.parse(raw);
 ck("original native success and exact actual "+row.label,native.resultType==="complete"&&native.isError===false&&native.content.length===1&&native.content[0].text===r["actual/"+(row.label==="authority"?"authority":row.label==="streams"?"streams":row.label)+".original.json"]);
}
ck("all eight pages closed",pages===8);
for(const name of ["stdout","stderr"]){
 const raw=r["actual/"+name+".original.txt"],stream=streams[name],bytes=u(raw),hex=bytes.map(x=>x.toString(16).padStart(2,"0")).join("");
 ck("original full byte hex text and EOF "+name,streams.job_id===ack.job.id&&stream.offset===0&&stream.next_offset===bytes.length&&stream.size===bytes.length&&stream.eof===true&&stream.text===raw&&stream.bytes_hex===hex);
 ck("original authority exact stored stream "+name,authority.log_bytes[name].seen===bytes.length&&authority.log_bytes[name].stored===bytes.length&&authority.log_synced[name]===true&&authority.log_truncated[name]===false&&authority.log_errors[name]===null);
}
ck("exact original stdout837 stderr0",u(r["actual/stdout.original.txt"]).length===837&&r["actual/stderr.original.txt"]==="");
const terminal=parse(r["actual/stdout.original.txt"]),receipt=parse(r["actual/inert-stage.result.public.json"]);
ck("receipt semantically exact original stdout lossless",same(receipt,terminal));
ck("prepared one source compile-only",terminal.status==="prepared"&&terminal.files.length===1&&terminal.python_compile_only===true&&["artifact_transfer_started","source_executed","git_started","compiler_started","service_started"].every(k=>terminal[k]===false));
const identity=terminal.files[0].identity.map(x=>x?.$exactInteger??String(x));
for(const kind of ["source","receipt"]){
 const info=JSON.parse(r["actual/"+kind+"-info.original.json"]),body=JSON.parse(r["actual/"+kind+"-body.original.json"]),raw=decode(body.data_base64),expected=kind==="source"?source:r["actual/inert-stage.result.public.json"],path=D+"/"+(kind==="source"?"source_export_same_root_publication_4e808_r1.py":"inert-stage.result.public.json"),rq=JSON.parse(r["reads/"+kind+"-body/request.public.json"]).operation.arguments;
 ck("actual independent identity and whole body "+kind,info.path===path&&info.mode===384&&info.metadata.mode===384&&info.metadata.uid===1000&&info.metadata.gid===1000&&info.metadata.link_count===1&&body.path===path&&body.version===info.version&&body.offset===0&&body.next_offset===info.size&&body.eof===true&&u(raw).length===info.size&&sha(raw)===info.sha256&&raw===expected);
 ck("original read exact version and limit "+kind,same(rq,{host:"rog",path,expected_version:info.version,offset:0,limit:16384}));
 if(kind==="source")ck("actual source full9 exact lossless version",info.version===[identity[0],identity[1],identity[6],identity[7],identity[8]].join(":")&&same(identity.slice(2,7),["1000","1000","33152","1","15364"]));
}
ck("exact source payload pin",terminal.files[0].sha256===sha(source)&&terminal.files[0].bytes===15364&&sha(source)==="9af6738da8526ad5a0dcd6402bf4693f652a4f428eb4b22d0914761292f66d20");
ck("actual stdin exact source payload",terminal.stdin_sha256===sha(q.stdin)&&terminal.stdin_bytes===u(q.stdin).length);
const ns=x=>BigInt(x?.$exactInteger??String(x)),elapsed=(ns(terminal.terminal_ns)-ns(terminal.started_ns)).toString();
ck("actual exact ns interval within original60s",elapsed==="6338962"&&BigInt(elapsed)<60000000000n);
const author=JSON.parse(r["verification/result.public.json"]),execution=JSON.parse(r["verification/executor.original.json"]);
ck("author86 original lossless verifier passed",author.checks_count===86&&author.checks.every(x=>x.passed===true)&&execution.exit_code===0&&execution.output===r["verification/result.public.json"]);
return {schema:"heptabao.root.current-source-export-inert-actual-review.r1",status:"PASS_COMPLETE_INERT_STAGE_ONLY",checksPassed:checks.length,checks,packet:{tree:a.tree,files:a.files,bytes:a.bytes},jobId:ack.job.id,sourceFullNineExactStrings:identity,actualElapsedNs:elapsed,readOnlyOperations:6,immutablePages:8,source: a.records.find(x=>x.path==="actual/source_export_same_root_publication_4e808_r1.py"),receipt:a.records.find(x=>x.path==="actual/inert-stage.result.public.json"),rootReviewedAuthor86:true,sourceExportNotYetSubmitted:true,qualification:{inertOnly:true,sourceExport:false,transport:false,import:false,product:false,fullReplacement:false}};
}