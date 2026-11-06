function verifyFinalLanSource(input) {
 const checks=[];
 const ck=(name,value)=>{checks.push({name,passed:!!value});if(!value)throw Error(name);};
 const src=input.source,rows=input.observations;
 ck("six_frozen_requests",rows.length===6);
 ck("fixed_order",rows.map(x=>x.role+"/"+x.route).join(",")==="pocket4/native,pocket4/ssh,rog/native,rog/ssh,mac/native,mac/ssh");
 ck("source_fd_acquire_ledger_precedes_open",src.indexOf('RESOURCES.append(row)')<src.indexOf('fd = os.open('));
 ck("source_no_child_spawning",!/\b(?:subprocess|Popen|fork|posix_spawn|execv|system)\s*(?:\.|\()/.test(src));
 ck("source_no_network_listen_connect_accept",!/\.(?:listen|connect|connect_ex|accept)\s*\(/.test(src));
 ck("source_exact_three_file_inputs",JSON.stringify([...src.matchAll(/read_fixed\("([^"]+)"/g)].map(x=>x[1]))===JSON.stringify([
  "/sys/devices/virtual/dmi/id/product_name","/etc/machine-id","/proc/sys/kernel/random/boot_id"]));
 ck("source_exact_two_sysctls",JSON.stringify([...src.matchAll(/sysctl_text\(libc, b"([^"]+)"/g)].map(x=>x[1]))===JSON.stringify(["hw.model","kern.bootsessionuuid"]));
 ck("source_no_serial_uuid_fallback",!src.includes("IOPlatformUUID")&&!src.includes("product_uuid")&&!src.includes("product_serial"));
 ck("source_HMAC_not_raw_identifier",src.includes('return hmac.new(DOMAIN + kind, raw.lower(), hashlib.sha256).hexdigest()'));
 ck("source_hash_domain_fixed",src.includes('DOMAIN = b"heptabao.final-lan-endpoint-identity.20261106.r1\\0"'));
 ck("source_exact_ports",src.includes('PORTS = (46230, 46231)'));
 ck("source_absolute_no_reset",src.includes('UNTIL = START + SECONDS * 1000000000')&&src.includes('time.monotonic_ns() < UNTIL else 1'));
 ck("source_owned_close_paths_once",(src.match(/os\.close\(fd\)/g)||[]).length===1&&(src.match(/endpoint\.close\(\)/g)||[]).length===1);
 ck("source_failure_no_raw_repr",!src.includes("repr(")&&src.includes('"code": str(error) if type(error) is Refusal else "observation_error"'));
 ck("binary_templates_four_unbound",input.binaryTemplates.length===4&&input.binaryTemplates.every(x=>
   x.actual_path===null&&x.actual_sha256===null&&x.actual_full9===null&&x.actual_version===null&&
   x.request_template.idempotency_key===null&&x.request_template.operation.arguments.path===null&&x.execution_ready===false));
 for(const row of rows) {
  const tag="request_"+row.index;
  ck(tag+"_whole",JSON.stringify(gitBlobMeta(row.raw))===JSON.stringify(row.pin));
  ck(tag+"_typed",processStartBinding(row.request).sha256===row.typed.sha256
   &&processStartBinding(row.request).native_fingerprint===row.typed.native_fingerprint);
  ck(tag+"_unique_key",rows.filter(x=>x.request.idempotency_key===row.request.idempotency_key).length===1);
  ck(tag+"_new_source_not_old_oracle",row.request.idempotency_key.includes(gitBlobMeta(src).sha256.slice(0,8)));
  ck(tag+"_outer30",row.request.timeout_seconds===30&&row.request.cwd==="/");
  ck(tag+"_exact_source",row.route==="native"?row.request.args[4]===src&&row.request.stdin===undefined:row.request.stdin===src);
  ck(tag+"_journal_roundtrip",applyStrict(input.baseJournal,row.journal_diff)===row.journal
    &&applyStrict(row.journal,row.journal_diff,true)===input.baseJournal);
  const f=new Function("tools","store","load",input.pure+"\n"+input.archive+"\n"+row.journal+"\nreturn gfValidateRequest;")(
   new Proxy({}, {get(){throw Error("Native_forbidden_in_source_review");}}),
   ()=>{throw Error("store_forbidden_in_source_review");},()=>{throw Error("load_forbidden_in_source_review");});
  const start={paused:false,nativeCallInFlight:false,pending:null,startCalled:false,job:null,activeObserver:null};
  f(start,"process_start",row.request,row.raw);ck(tag+"_exact_start_guard_accepts",true);
  let rejected=false;try {f({...start,startCalled:true},"process_start",row.request,row.raw);}catch(e){rejected=true;}
  ck(tag+"_repeat_start_rejected",rejected);
  const active={...start,startCalled:true,job:"original-job-only"};
  const q={idempotency_key:row.observer_key_prefix+"authority0",operation:{tool:"process_status",
    arguments:{host:row.request.host,job_id:active.job}}};
  f(active,"operation_start",q,JSON.stringify(q));ck(tag+"_same_job_status_accepts",true);
  rejected=false;try{f(active,"operation_start",{...q,operation:{...q.operation,arguments:{host:"another-host",job_id:active.job}}},"");}catch(e){rejected=true;}
  ck(tag+"_other_host_rejected",rejected);
  rejected=false;try{f(active,"operation_start",{...q,operation:{tool:"file_info",arguments:{host:row.request.host,path:"/etc/machine-id"}}},"");}catch(e){rejected=true;}
  ck(tag+"_other_API_rejected",rejected);
  if(row.route==="ssh") {
   ck(tag+"_fixed_SSH_route",row.request.host==="desktop"&&row.request.executable==="/usr/bin/ssh"
     &&row.request.args.at(-2)===row.role+"-ts"&&row.request.args.at(-1).startsWith("exec /"));
   ck(tag+"_no_proxy_or_local_commands",["ProxyCommand=none","ProxyJump=none","PermitLocalCommand=no","ControlPath=none","ClearAllForwardings=yes","StrictHostKeyChecking=yes"].every(x=>row.request.args.includes(x)));
  }
 }
 const fake=(role,route)=>{
  const spec={mac:["Darwin","arm64","192.168.0.8","1"],rog:["Linux","x86_64","192.168.0.10","2"],pocket4:["Linux","x86_64","192.168.0.9","3"]}[role];
  const [os,architecture,ip,d]=spec,start=1000000000000n+(route==="ssh"?2000000n:0n);
  return {schema:"heptabao.final-lan-endpoint-identity.v1",role,status:"passed",failure:null,
    all_probe_resources_closed:true,identity_stable_before_after:true,signals:[],
    filesystem_writes:0,listen_calls:0,connect_calls:0,
    probe_process:{children_started_by_probe:0},
    machine_or_boot_identifier_raw_emitted:false,hardware_serial_or_hardware_uuid_read:false,
    started_monotonic_ns:String(start),finished_monotonic_ns:String(start+1000000n),
    absolute_deadline_monotonic_ns:String(start+15000000000n),
    identity:{hostname:"fake-"+role,os,architecture,declared_lan_ipv4:ip,uid:1000,euid:1000,gid:1000,
      model:{name:"FAKE-"+role,source:os==="Linux"?"/sys/devices/virtual/dmi/id/product_name":"sysctl:hw.model"},
      boot_identity:{source:os==="Linux"?"/proc/sys/kernel/random/boot_id":"sysctl:kern.bootsessionuuid",hmac_sha256:d.repeat(64)},
      machine_identity:os==="Linux"?{source:"/etc/machine-id",hmac_sha256:(role==="rog"?"4":"5").repeat(64)}:null,
      machine_identity_not_requested_on_darwin:os==="Darwin"},
    local_ports:[46230,46231].map(port=>({address:ip,port,bound:true,closed:true,listen_called:false,connect_called:false,reservation_retained:false}))};
 };
 const fixture=()=>Object.fromEntries(["mac","rog","pocket4"].map(r=>[r,{native:fake(r,"native"),ssh:fake(r,"ssh")}]));
 const compare=new Function(input.comparison+"\nreturn compareFinalLanRoutes;")();
 const actual=compare(fixture(),null);
 ck("comparison_fake_equal_routes_not_physical_label",actual.route_identity_binding===true&&actual.physical_model_labels_verified===false
    &&actual.final_candidate_binary_qualified===false&&actual.final_LAN_98_plus_12_qualified===false);
 const cases=[
 ["same_IP_different_boot",q=>q.pocket4.ssh.identity.boot_identity.hmac_sha256="f".repeat(64)],
 ["same_IP_different_machine",q=>q.pocket4.ssh.identity.machine_identity.hmac_sha256="e".repeat(64)],
 ["same_IP_different_model",q=>q.pocket4.ssh.identity.model.name="DIFFERENT"],
 ["permission_failure",q=>{q.pocket4.ssh.status="failed";q.pocket4.ssh.failure={errno:13};}],
 ["missing_model",q=>delete q.mac.native.identity.model],
 ["deadline_failure",q=>q.rog.native.finished_monotonic_ns=q.rog.native.absolute_deadline_monotonic_ns],
 ["duplicate_linux_machine",q=>{for(const x of Object.values(q.pocket4))x.identity.machine_identity.hmac_sha256="4".repeat(64);}],
 ["extra_port",q=>q.rog.native.local_ports.push({...q.rog.native.local_ports[0],port:46232})]
 ];
 for(const[name,mutate]of cases){const q=fixture();mutate(q);let refused=false;try{compare(q,null);}catch(e){refused=true;}ck("comparison_fake_"+name+"_refused",refused);}
 return {schema:"heptabao.final-lan-preobservation-pure-source-checks.v1",passed:true,
   check_count:checks.length,checks,Native_calls:0,Python_compilations:0,Python_executions:0,
   host_observations:0,product_cases:0,pure_fake_comparison_variants:9};
}
