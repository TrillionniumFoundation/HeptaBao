function verifyQaInert(a,parse,u,bs,dec,h,get,request,sourceAudit){
 const checks=[],need=(x,s)=>{if(!x)throw Error(s);checks.push(s)};
 const raw=path=>{const r=a.records.find(r=>r.path===path);need(!!r,"record "+path);const x=get(r.blob);if(x===undefined)throw Error("uncached "+path);return x};
 const labels=a.records.filter(x=>x.path.startsWith("original-sdk/")).map(x=>x.path.slice(13,-5));let pages=0;const ids=new Set();
 for(const label of labels){
  const adm=parse(raw("operations/"+label+"-admission.txt")),st=parse(raw("operations/"+label+"-status.txt")),req=parse(raw("requests/"+label+".json")),sdkRaw=raw("original-sdk/"+label+".json"),sdk=parse(sdkRaw);
  need(!ids.has(adm.operation_id)&&st.operation_id===adm.operation_id,"same unique operation "+label);ids.add(adm.operation_id);
  need(st.async_state==="completed"&&st.owned_future_active===false&&st.payload_available&&st.result_state==="stored_observed"&&st.automatic_retry===false,"closed original readonly "+label);
  need(adm.automatic_retry===false&&(label==="authority"?(adm.reused===true&&adm.async_state==="unknown"):adm.reused===false),"preserved admission scope "+label);
  need(adm.tool_name===req.operation.tool&&st.tool_name===req.operation.tool,"request tool "+label);
  need(sdk.resultType==="complete"&&sdk.isError===false&&sdk.content.length===1&&sdk.content[0].text===raw("native/"+label+".original.json"),"exact native SDK "+label);
  const prs=a.records.filter(x=>x.path.startsWith("immutable-pages/"+label+"-")).sort((x,y)=>x.path.localeCompare(y.path));
  let offset=0,parts=[];const all=u(sdkRaw),sha=h(bs(all));
  for(const r of prs){const p=parse(raw(r.path)),d=dec(p.data_base64);need(p.operation_id===adm.operation_id&&p.immutable_snapshot&&p.payload_kind==="native_result","immutable "+r.path);need(p.offset===offset&&p.next_offset===offset+d.length&&p.total_bytes===all.length&&p.result_sha256===sha,"page bounds/hash "+r.path);offset+=d.length;need(p.eof===(offset===all.length),"EOF "+r.path);parts.push(bs(d));pages++;}
  need(offset===all.length&&parts.join("")===bs(all),"complete SDK "+label);
 }
 need(labels.length===7&&pages===26,"7 closed operations 26 pages");
 const ack=parse(raw("actual/ack.original.json")),authority=parse(raw("native/authority.original.json")),streams=parse(raw("native/streams.original.json")),core=parse(raw("actual-files/inert-stage.result.public.json"));
 for(const k of ["host","executable","args","cwd","idempotency_key"])need(JSON.stringify(ack.job[k])===JSON.stringify(request[k]),"job ACK exact "+k);
 need(ack.job.id==="1a1aa7c3dff-fc05-439c"&&ack.reused===false&&ack.job.launch_state==="launched","unique inert ACK");
 need(authority.job_id===ack.job.id&&authority.exit_code===0&&authority.output_complete&&authority.output_durable&&authority.state==="succeeded"&&!authority.timed_out&&!authority.automatic_retry,"actual terminal");
 for(const k of ["stdout","stderr"]){const s=streams[k],text=raw("streams/"+k+".original.txt"),b=u(text);need(s.text===text&&s.bytes_hex===b.map(x=>x.toString(16).padStart(2,"0")).join("")&&s.offset===0&&s.next_offset===b.length&&s.size===b.length&&s.eof,"complete stream "+k);need(authority.log_bytes[k].seen===b.length&&authority.log_bytes[k].stored===b.length&&authority.log_synced[k]&&!authority.log_truncated[k]&&authority.log_errors[k]===null,"durable stream "+k);}
 need(JSON.stringify(parse(raw("streams/stdout.original.txt")))===JSON.stringify(core),"compact stdout equals pretty disk receipt losslessly");
 need(raw("streams/stderr.original.txt")==="inputs/owned_reference_phaseb_r3.py:1088: SyntaxWarning: 'return' in a 'finally' block\ninputs/official_cli_reference_r4.py:915: SyntaxWarning: 'return' in a 'finally' block\n","two preserved compile-only warnings");
 need(core.status==="prepared"&&core.files.length===8&&core.python_compile_only===true&&["artifact_transfer_started","compiler_started","git_started","service_started","source_executed"].every(k=>core[k]===false),"inert only scope");
 const exactInt=v=>v&&typeof v==="object"?v.$exactInteger:String(v),delta=BigInt(exactInt(core.terminal_ns))-BigInt(exactInt(core.started_ns));
 need(delta===34527104n&&delta<60000000000n,"reported body interval (not entire supervisor)");
 need(core.stdin_bytes===u(request.stdin).length&&core.stdin_sha256===h(bs(u(request.stdin))),"actual carrier exact");
 const actualByPath={};
 for(const label of ["files-a","files-b"]){
  const n=parse(raw("native/"+label+".original.json")),q=parse(raw("requests/"+label+".json")).operation.arguments;
  need(n.atomic_snapshot===false&&n.truncated===false&&JSON.stringify(n.files.map(f=>f.path))===JSON.stringify(q.paths),"independent exact paths "+label);
  for(const f of n.files){const relative=f.path.slice("/home/qian-qi/heptabao-native-h2-qa-controls-df026-20261105-r1/".length);const s=raw("actual-files/"+relative);need(f.text===s&&f.eof&&f.size===u(s).length&&f.sha256===h(bs(u(s))),"whole small body "+relative);actualByPath[f.path]=f;}
 }
 const info=parse(raw("native/lock-info.original.json"));let parts=[],offset=0,unpinned=0;
 for(const label of ["lock-chunk-000000","lock-chunk-065536"]){
  const n=parse(raw("native/"+label+".original.json")),q=parse(raw("requests/"+label+".json")).operation.arguments,d=dec(n.data_base64);
  need(n.path===info.path&&n.size===info.size&&n.version===info.version&&n.offset===offset&&n.next_offset===offset+d.length&&q.offset===offset&&q.path===info.path&&d.length<=65536,"actual lock chunk bounds/version "+label);
  need(h(bs(d))===n.chunk_sha256,"lock chunk SHA "+label);
  if(q.expected_version===undefined){need(offset===0,"only initial binary read may lack pin");unpinned++;}else need(q.expected_version===info.version,"requested lock version "+label);
  offset+=d.length;need(n.eof===(offset===info.size),"lock EOF "+label);parts.push(bs(d));
 }
 need(offset===101193&&parts.join("")===bs(u(raw("actual-files/inputs/canonical.Cargo.lock")))&&h(parts.join(""))===info.sha256,"whole canonical lock");
 actualByPath[info.path]=info;
 need(info.metadata.uid===1000&&info.metadata.gid===1000&&info.mode===384&&info.metadata.link_count===1,"independent lock owner/mode/nlink");
 for(const f of core.files){
  const relative=f.path.slice("/home/qian-qi/heptabao-native-h2-qa-controls-df026-20261105-r1/".length),actual=a.records.find(x=>x.path==="actual-files/"+relative),expected=sourceAudit.records.find(x=>x.path==="source/"+relative),n=actualByPath[f.path],id=f.identity;
  need(expected&&actual.blob===expected.blob&&f.bytes===actual.bytes&&f.sha256===actual.sha256,"actual file exact reviewed source "+relative);
  need(f.publication==="created"&&f.mode==="0600"&&id.length===9&&id[2]===1000&&id[3]===1000&&id[4]===33152&&id[5]===1&&id[6]===f.bytes,"producer full9 fresh file "+relative);
  need(n&&n.version===[id[0],id[1],id[6],id[7],id[8]].map(exactInt).join(":"),"independent five-field version binds producer identity "+relative);
 }
 return {checks,summary:{check_count:checks.length,operations:7,pages:26,source_files:8,receipt_files:1,stdout_bytes:3168,stderr_bytes:173,body_interval_ns:String(delta),initial_unpinned_lock_reads:unpinned,output_complete:true,output_durable:true,exit_code:0,status:"PASS_INERT_ONLY"}};
}