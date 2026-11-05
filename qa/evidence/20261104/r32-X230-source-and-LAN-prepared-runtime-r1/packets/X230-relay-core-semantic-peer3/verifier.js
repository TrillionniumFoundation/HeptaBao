function verifyRelayCore(input,readyTree,sha1,sha256){
  // Pure original-data verifier. input maps logical keys to exact UTF-8 strings.
  // JSON integer tokens are kept as decimal strings for all identity comparisons.
  // Only numeric elapsed/cap checks convert bounded fields to Number.
  const checks=[],pins={};
  const check=(id,ok)=>{checks.push({id,passed:ok===true});if(ok!==true)throw Error("verification_failed:"+id);};
  const utf8=s=>unescape(encodeURIComponent(s));
  const stable=v=>Array.isArray(v)?"["+v.map(stable).join(",")+"]":v&&typeof v==="object"?"{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+stable(v[k])).join(",")+"}":JSON.stringify(v);
  const equal=(a,b)=>stable(a)===stable(b);
  function lossless(s){JSON.parse(s);return JSON.parse(s.replace(/"(?:\\.|[^"\\])*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g,t=>t[0]==='"'?t:JSON.stringify(t)));}
  function json(k){return JSON.parse(input[k]);}
  function lineContains(k,s){check("source_contract:"+k+":"+s,input[k].includes(s));}
  function bounded(value,cap){const n=Number(value);return Number.isFinite(n)&&n>=0&&n<cap;}
  const expected={
    core:["33f31d57e93545fd15c93600748d8d138f772b7f",58370,"b442f1ed6a5b3254aae79096c1a02d09895564a460a7f6333b809791109725b5"],
    info:["96761101a4960795af741933ac58a0f0ea0a38fc",504,"d83a4078525c1770e3f5ed7da3fb1eb84e579a79536b5ec8b151552619b08c85"],
    relay:["782f6def95fb551f167a7bcddcfb9ab0c0942784",25713,"cc5a9ed329bda9d1b51cf42343b3a9898516c1136b035fc63abb688982a9612f"],
    sender:["1a28125a74ba9fd7f59679bf8339da0cc43759f9",8960,"aac98a6512ccdfc525de9dd5cf544f474220d3415631ea39537672b21ca4b663"],
    receiver:["a6477df3b5c0a241e1675e99ca0d6410aa43c88e",30791,"8aa027334ad2a99603b0c54bcbe80ff67c194104aea0b5cbf44b68eb82447471"],
    go:["0de9e52cff21d0827a584387e178559c73d93a04",13197,"cf5a34ffe4bbe5280b934892945f23747a6ce67a1021eb53daf5bcc945bdc293"],
    intent:["3101506b954a8326b8b93192d281af079b6a8b1b",4090,"7cfa373a48afb764afe0fac1c47cdd9510622fa93e405e13e56e00db7028f01e"],
    "ack-sdk":["6d33209e0b75ba65c78b7246121508dbaac25c48",1398,"c2fec811685e73af11ac9a54349a8ca6bcf88a3b2c81edb306651448419ebb94"],
    authority:["094c1fb53c2b59aad284423fc65d2ce519f9f6e9",729,"98cbbd93055188f8f33aabd1b30fa1c66415b634ef400f261137ed9b42618de2"],
    request:["9241a86d71e9703259aed6e3d6f711c7568bcf39",386,"4a3e6ae8791bfb96e7fe97d93072ddaa048c5fe79b676082feccc1f8230d46d3"]
  };
  check("inputs.exact_count",Object.keys(input).length===Object.keys(expected).length);
  for(const[k,[blob,bytes,digest]]of Object.entries(expected)){
    check("input.raw:"+k,typeof input[k]==="string");
    const b=utf8(input[k]);check("input.whole:"+k,b.length===bytes&&sha256(b)===digest&&sha1("blob "+b.length+"\0"+b)===blob);
    pins[k]={blob,bytes,sha256:digest};
  }
  const sourceTree="4fdb7848257d917b8efdd4dd1bed296ae5c40dd2";
  check("known_ready_tree",readyTree.sha===sourceTree&&readyTree.truncated===false);
  for(const [role,path]of [["relay","candidate/relay.py"],["sender","candidate/sender.py"],["receiver","candidate/receiver.py"],["request","dispatch/relay.exact-request.json"]]){
    const row=readyTree.tree.find(x=>x.path===path);check("known_source_binding:"+role,!!row&&row.type==="blob"&&row.mode==="100644"&&row.sha===pins[role].blob&&row.size===pins[role].bytes);
  }
  const core=json("core"),L=lossless(input.core),go=json("go"),intent=json("intent"),request=json("request"),authority=json("authority"),info=json("info");
  const base="/home/qian-qi/heptabao-ha-closure-20261103-r1",root=base+"/normal-same-root-publication-x230-transfer-r1",target="/home/qian/heptabao-same-root-publication-normal-20261105-r1",src=target+"/source",art=target+"/artifacts",ctl=target+"/control";
  const H="4e808d0ecb1bcded22870a7ec960dfb2491cf6ec",T="eba5e650bd080b8ad41ea52a2bc68867f541d255",P="1c66541993662f92cf717154e33717abedb2ea74",R="67d79b3b5442ed033d38929eab2010403463e56d";
  const job="1a1ad0a9524-fc05-5839";
  check("GO.identity",go.status==="GO_ONCE_EXACT_EXISTING_RELAY"&&intent.root_go.blob===pins.go.blob&&intent.root_go.bytes===pins.go.bytes&&intent.root_go.sha256===pins.go.sha256);
  check("request.original_binding",equal(go.exact_request,request)&&equal(intent.exact_request,request)&&intent.request.blob===pins.request.blob&&go.request.blob===pins.request.blob&&intent.request.sha256===pins.request.sha256&&go.request.sha256===pins.request.sha256);
  check("request.fixed_context",request.host==="desktop"&&request.executable==="/usr/bin/python3"&&request.cwd===base&&request.timeout_seconds===360&&request.idempotency_key==="heptabao-4e808-x230-source-artifacts-relay-r1-cc5a9ed3"&&equal(request.args,["-I","-S","-B",base+"/normal-same-root-publication-x230-transfer-controls-r1/relay.py"]));
  check("intent.single_submission",intent.status==="DURABLE_BEFORE_SINGLE_EXACT_PROCESS_START"&&intent.previous_process_start_submissions===0);
  const ackEnvelope=json("ack-sdk");
  check("ack.not_error",ackEnvelope.isError===false&&ackEnvelope.structuredContent===null&&Array.isArray(ackEnvelope.content)&&ackEnvelope.content.length===1&&ackEnvelope.content[0].type==="text");
  const ackRaw=ackEnvelope.content[0].text,ack=JSON.parse(ackRaw),ackL=lossless(ackRaw);
  check("ack.request_binding",ack.reused===false&&ack.job.id===job&&ack.job.host===request.host&&ack.job.executable===request.executable&&ack.job.cwd===request.cwd&&equal(ack.job.args,request.args)&&equal(ack.job.env_keys,[])&&ack.job.idempotency_key===request.idempotency_key&&ack.job.request_digest===go.request_digest&&ack.job.request_digest===intent.request_digest);
  check("ack.fingerprint_exact",ackL.job.request_fingerprint===go.request_fingerprint_decimal&&ackL.job.request_fingerprint===intent.request_fingerprint_decimal);
  check("ack.launched",ack.job.launch_state==="launched"&&ack.job.launch_error===null&&ack.launch.ok===true);
  check("authority.same_job",authority.job_id===job&&authority.state==="succeeded"&&authority.exit_code===0&&authority.cancelled===false&&authority.timed_out===false);
  check("authority.full_durable",authority.output_complete===true&&authority.output_durable===true&&authority.terminal_publication_confirmed===true&&authority.audit_recorded===true);
  for(const stream of ["stdout","stderr"])check("authority.stream:"+stream,authority.log_bytes[stream].seen===authority.log_bytes[stream].stored&&authority.log_synced[stream]===true&&authority.log_truncated[stream]===false&&authority.log_errors[stream]===null);
  check("authority.original_stream_counts",authority.log_bytes.stdout.stored===368&&authority.log_bytes.stderr.stored===0);
  check("core.independent_info",info.path===root+"/control/result.public.json"&&info.size===pins.core.bytes&&info.sha256===pins.core.sha256&&info.version==="2050:7532625:58370:1793904542839702697:1793904542839702697"&&info.mode===384&&info.metadata.uid===1000&&info.metadata.gid===1000&&info.metadata.link_count===1);
  check("core.schema_canonical",core.schema==="heptabao.4e808.x230-standalone-source-artifacts-relay.v1"&&core.status==="transferred"&&core.source_commit===H&&core.source_tree===T&&core.source_host==="desktop"&&core.destination_alias==="x230-ts"&&core.destination_host==="x230"&&core.destination_root===target&&core.relay_root===root);
  const limits={native_outer_seconds:360,relay_overall_seconds:300,sender_seconds:90,receiver_seconds:300,ssh_config_seconds:90,clone_seconds:90,git_seconds:60,TERM_seconds:5,KILL_seconds:5,max_bundle_bytes:67108864,no_reset_or_widening:true};
  check("GO.original_limits",equal(go.unchanged_limits,limits)&&equal(intent.unchanged_limits,limits));
  check("core.original_limits",core.overall_seconds===300&&core.sender_seconds===90&&core.receiver_seconds===300&&core.ssh_config_seconds===90&&bounded(core.elapsed_seconds,300));
  for(const k of ["automatic_retry","production_changed","compiler_started","server_started","runtime_qualification"])check("core.no_extra_effect:"+k,core[k]===false);
  check("core.no_local_git",core.local_git_operations===0&&core.destination_source_materialization_allowed===true&&core.destination_materialization_verified===true&&core.destination_git_commands===21);
  const filesMatch=input.relay.match(/^FILES=(\[[\s\S]*?\n\])/m);check("source.FILES_JSON",!!filesMatch);
  const F=JSON.parse(filesMatch[1]);
  check("source.seven_files_exact",F.length===7&&equal(core.files,F)&&new Set(F.map(x=>x.name)).size===7);
  for(const role of ["sender","receiver"]){const m=input[role].match(/^FILES=(\[[\s\S]*?\n\])/m);check("source.shared_table:"+role,!!m&&equal(JSON.parse(m[1]),F));lineContains(role,"BINDING_READY=True");}
  lineContains("relay","BINDING_READY=True");
  const helperMatch=input.relay.match(/^HELPERS=(\{[^\n]+\})/m);check("source.HELPERS_JSON",!!helperMatch);
  const helpers=JSON.parse(helperMatch[1]);
  check("source.helper_sha",helpers["sender.py"]===pins.sender.sha256&&helpers["receiver.py"]===pins.receiver.sha256);
  for(const role of ["relay","sender","receiver"]){
    const binding=go.actual_control_files.find(x=>x.role===role),observed=role==="relay"?L.controller:L.helpers[role+".py"];
    check("control.pin:"+role,!!binding&&binding.body_blob===pins[role].blob&&binding.bytes===pins[role].bytes&&binding.sha256===pins[role].sha256&&observed.bytes===String(binding.bytes)&&observed.sha256===binding.sha256&&equal(observed.identity,binding.full9_decimal));
  }
  check("receiver.controller_same_bytes",core.receiver.controller.bytes===pins.receiver.bytes&&core.receiver.controller.sha256===pins.receiver.sha256);
  const seven=go.seven_actual_source_inputs;
  check("GO.seven_input_total",seven.length===7&&go.total_artifact_bytes===132647913&&F.reduce((n,x)=>n+x.bytes,0)===132647913&&intent.total_artifact_bytes===132647913);
  check("endpoints.exact_file_counts",core.sender.files.length===7&&core.receiver.file_results.length===7);
  const destinations=[];
  for(let i=0;i<7;i++){
    const f=F[i],g=seven[i],sent=L.sender.files[i],received=L.receiver.file_results[i],expectedHash={bytes:String(f.bytes),sha256:f.sha256},v=f.version.split(":");
    const sourceId=[v[0],v[1],"1000","1000",String(32768+f.source_mode),"1",v[2],v[3],v[4]];
    check("input.seven_GO:"+f.name,g.path===f.path&&g.bytes===f.bytes&&g.sha256===f.sha256&&g.version===f.version&&g.mode===f.source_mode&&g.destination_path===art+"/"+f.name&&parseInt(g.destination_mode,8)===f.target_mode);
    check("sender.file:"+f.name,sent.name===f.name&&sent.source===f.path&&sent.source_version===f.version&&equal(sent.source_identity_before,sourceId)&&equal(sent.source_identity_after,sourceId)&&equal(sent.initial_file,expectedHash)&&equal(sent.stream,expectedHash));
    check("receiver.file:"+f.name,received.name===f.name&&received.path===art+"/"+f.name&&received.bytes===String(f.bytes)&&received.sha256===f.sha256&&received.mode===String(f.target_mode)&&received.create_only===true&&received.fsynced===true&&equal(received.same_fd_readback,expectedHash));
    check("receiver.identity:"+f.name,received.identity.length===9&&received.identity.every(x=>typeof x==="string"&&/^\d+$/.test(x))&&received.identity[2]==="1000"&&received.identity[3]==="1000"&&received.identity[4]===String(32768+f.target_mode)&&received.identity[5]==="1"&&received.identity[6]===String(f.bytes));
    destinations.push({path:received.path,bytes:f.bytes,sha256:f.sha256,mode:f.target_mode,reported_full9_decimal:received.identity,independent_destination_info_verified_here:false});
  }
  const localLimits={"x230-ts-effective-config":90,"send-desktop":90,"receive-x230":300},localPids=new Set();
  check("local.exact_command_order",equal(core.commands.map(x=>x.label),["x230-ts-effective-config","send-desktop","receive-x230"]));
  check("local.exact_cleanup_creation_order",equal(core.cleanup.map(x=>x.label),["x230-ts-effective-config","receive-x230","send-desktop"]));
  check("local.no_cleanup_errors",core.cleanup_errors.length===0&&core.all_local_owned_stopped===true);
  for(const cmd of core.commands){
    const row=core.cleanup.find(x=>x.label===cmd.label);
    check("local.command:"+cmd.label,cmd.exit_code===0&&cmd.timed_out===false&&cmd.direct_child_reaped===true&&equal(cmd.remaining,[])&&cmd.limit_seconds===localLimits[cmd.label]&&bounded(cmd.elapsed_seconds,cmd.limit_seconds)&&Number.isSafeInteger(cmd.pid)&&cmd.pid>0&&!localPids.has(cmd.pid));localPids.add(cmd.pid);
    check("local.cleanup:"+cmd.label,!!row&&row.pid===cmd.pid&&row.exit_code===cmd.exit_code&&row.direct_child_reaped===true&&equal(row.remaining,[])&&!Object.hasOwn(row,"cleanup_error_type")&&!Object.hasOwn(row,"snapshot_error_type"));
  }
  lineContains("relay","receiver=start_child('receive-x230',[*SSH,'x230-ts',remote_command('/usr/bin/python3',helper_source['receiver.py'])]");
  lineContains("relay","sender=start_child('send-desktop',['/usr/bin/python3','-I','-S','-B','-c',helper_source['sender.py']]");
  lineContains("relay","stdout=receiver['process'].stdin");
  const s=core.sender,r=core.receiver;
  check("sender.complete",s.schema==="heptabao.4e808.x230-public-artifacts-sender.v1"&&s.role==="sender"&&s.status==="complete"&&s.request_seconds===90&&s.git_operations===0&&s.source_commit===H&&s.source_tree===T&&s.all_owned_stopped===true&&s.within_original_deadline===true&&bounded(s.elapsed_seconds,90)&&s.server_started===false&&s.compiler_started===false&&equal(s.cleanup,[])&&equal(s.cleanup_errors,[]));
  check("receiver.complete",r.schema==="heptabao.4e808.x230-standalone-source-receiver.v1"&&r.status==="complete"&&r.source_commit===H&&r.source_tree===T&&r.transfer_passed===true&&r.all_owned_stopped===true&&r.within_original_deadline===true&&r.publication_within_original_deadline===true&&bounded(r.elapsed_seconds,300));
  check("receiver.limits",r.overall_seconds===300&&r.clone_seconds===90&&r.git_command_seconds===60&&r.maximum_bundle_bytes===67108864&&r.expected_full_commit_count===3763&&equal(r.expected_prerequisites,[]));
  for(const k of ["automatic_retry","production_changed","compiler_started","server_started","runtime_qualification","network_git_protocols_enabled","old_source_opened"])check("receiver.no_extra_effect:"+k,r[k]===false);
  check("receiver.product_tests_zero",r.product_tests_executed===0&&r.raw_receipts_preserved===true&&r.normal_release_provenance_verified===true&&r.export_receipt_verified===true&&r.normal61_qualification_verified===true&&r.success_requires_authoritative_exit_zero===true&&r.success_requires_terminal_publication_within_original_deadline===true);
  check("receiver.canonical_proof",equal(r.canonical_proof,{commit:H,tree:T,parents:[P],root:R,commit_count:3763,full_fsck_passed:true}));
  const after=r.source_after;
  check("receiver.source_after",after.head===H&&after.tree===T&&after.clean===true&&after.git_directory===src+"/.git"&&after.git_common_directory===src+"/.git"&&after.independent_git_directory===true&&after.no_alternates===true&&after.no_partial_clone===true&&after.shallow===false&&equal(after.lock_files,{"index.lock":false,"packed-refs.lock":false,"shallow.lock":false,"config.lock":false}));
  const material=r.materialized;
  check("receiver.materialized",material.tracked_files===3914&&material.tree_equals_index===true&&material.actual_git_blob_bytes_verified===true&&material.no_sparse_checkout===true&&material.no_symlinks_or_hardlinks===true&&material.fsynced_files>=3914&&material.fsynced_directories>0);
  const header="# v2 git bundle\n"+H+" HEAD\n\n";
  check("receiver.bundle_header",equal(r.bundle_header,{version:2,prerequisites:[],heads:[[H,"HEAD"]],header_bytes:utf8(header).length,header_sha256:sha256(utf8(header))}));
  const gitPrefix=["/usr/bin/git","-c","gc.auto=0","-c","maintenance.auto=false","-c","core.hooksPath="+ctl+"/empty-hooks","-c","core.fsmonitor=false","-c","log.showSignature=false","-c","protocol.allow=never","-c","protocol.file.allow=always","-c","pack.threads=1","-C"];
  const commands=[
    ["standalone-clone",target,["clone","--no-checkout","--no-hardlinks","--",art+"/canonical-4e808-full.bundle",src],90],
    ["bundle-verify",src,["bundle","verify",art+"/canonical-4e808-full.bundle"],60],
    ["bundle-heads",src,["bundle","list-heads",art+"/canonical-4e808-full.bundle"],60],
    ["canonical-checkout",src,["checkout","--detach",H],60],
    ["remove-local-origin",src,["remote","remove","origin"],60],
    ["canonical-kind",src,["cat-file","-t",H],60],
    ["canonical-tree",src,["rev-parse",H+"^{tree}"],60],
    ["canonical-parents",src,["show","-s","--format=%P",H],60],
    ["canonical-count",src,["rev-list","--count",H],60],
    ["canonical-roots",src,["rev-list","--max-parents=0",H],60],
    ["canonical-full-fsck",src,["fsck","--full","--strict","--no-reflogs","--no-dangling",H],60],
    ["materialized-tree",src,["ls-tree","-rz","--full-tree",H],60],
    ["materialized-index",src,["ls-files","--stage","-z"],60],
    ["no-sparse-config",src,["config","--local","--get-regexp","^(core[.]sparseCheckout|core[.]sparseCheckoutCone|extensions[.]worktreeConfig)$"],60],
    ["source-after-head",src,["rev-parse","--verify","HEAD"],60],
    ["source-after-tree",src,["rev-parse","HEAD^{tree}"],60],
    ["source-after-status",src,["status","--porcelain=v1","--untracked-files=all"],60],
    ["source-after-git-dir",src,["rev-parse","--absolute-git-dir"],60],
    ["source-after-common-dir",src,["rev-parse","--git-common-dir"],60],
    ["source-after-shallow",src,["rev-parse","--is-shallow-repository"],60],
    ["source-after-partial-config",src,["config","--local","--get-regexp","^(extensions[.]partialclone|remote[.].*[.]promisor|remote[.].*[.]partialclonefilter)$"],60]
  ];
  check("remote.command_count",r.commands.length===21&&r.cleanup.length===21);
  const remotePids=new Set(),remoteRows=[];
  const expectedStdout={2:H+" HEAD\n",4:"",5:"commit\n",6:T+"\n",7:P+"\n",8:"3763\n",9:R+"\n",10:"",13:"",14:H+"\n",15:T+"\n",16:"",17:src+"/.git\n",18:".git\n",19:"false\n",20:""};
  for(let i=0;i<commands.length;i++){
    const[label,where,args,limit]=commands[i],cmd=r.commands[i],end=r.cleanup[i],name=String(i).padStart(3,"0")+"-"+label,allowed=(i===13||i===20)?[0,1]:[0];
    check("remote.exact_argv:"+name,cmd.label===name&&equal(cmd.argv,[...gitPrefix,where,...args]));
    check("remote.command_terminal:"+name,allowed.includes(cmd.exit_code)&&cmd.timed_out===false&&cmd.direct_child_reaped===true&&equal(cmd.remaining,[])&&cmd.limit_seconds===limit&&bounded(cmd.elapsed_seconds,limit)&&Number.isSafeInteger(cmd.pid)&&cmd.pid>0&&!remotePids.has(cmd.pid));remotePids.add(cmd.pid);
    check("remote.cleanup_same_child:"+name,end.label===name&&end.pid===cmd.pid&&end.exit_code===cmd.exit_code&&end.direct_child_reaped===true&&equal(end.remaining,[])&&!Object.hasOwn(end,"cleanup_error_type")&&!Object.hasOwn(end,"snapshot_error_type"));
    for(const stream of ["stdout","stderr"])check("remote.log_pin_shape:"+name+":"+stream,Number.isSafeInteger(cmd[stream+"_bytes"])&&cmd[stream+"_bytes"]>=0&&cmd[stream+"_bytes"]<=2097152&&/^[0-9a-f]{64}$/.test(cmd[stream+"_sha256"]));
    if(Object.hasOwn(expectedStdout,i)){const b=utf8(expectedStdout[i]);check("remote.reported_stdout_contract:"+name,cmd.stdout_bytes===b.length&&cmd.stdout_sha256===sha256(b));}
    remoteRows.push({label:name,pid:cmd.pid,exit_code:cmd.exit_code,limit_seconds:limit,elapsed_seconds:cmd.elapsed_seconds,direct_child_reaped:true,remaining:[],argv_exact:true});
  }
  check("remote.NUL_reported_canonical_digests",r.commands[11].stdout_bytes===450459&&r.commands[11].stdout_sha256==="d7d6a445b6f66b8c9e07bc138c048a257d11a5bf343f83eed11a71afcd2f3548"&&r.commands[12].stdout_bytes===438717&&r.commands[12].stdout_sha256==="a762e59dfaa7b4a2b1e3120fb83161f14578d9da5ef038573c98540f1083574e");
  check("receiver.receipt_descriptor_only",r.receipt.path===art+"/transfer.result.public.json"&&r.receipt.bytes===35212&&r.receipt.sha256==="dd36121b4d65ced9ef686039f9c2869cc52c33adda58e5e185fcb32eceb4973f");
  for(const token of ["UNTIL=START+300","timeout=5","p.wait(timeout=5)","if not result['publication_within_original_deadline']:","sys.exit(0 if result['status']=='complete' and time.monotonic()<UNTIL else 1)"])lineContains("receiver",token);
  for(const token of ["UNTIL=START+90","for fd in reversed(handles):os.close(fd)","sys.exit(0 if result['status']=='complete' and time.monotonic()<UNTIL else 1)"])lineContains("sender",token);
  const fenceTuple=name=>{const m=input.relay.match(new RegExp("^"+name+"=\\(([^\\n]+)\\)","m"));check("fence.literal_present:"+name,!!m);return m[1].split(",").map(x=>x.trim());};
  const fenceRootId=fenceTuple("OLD_FENCE_ROOT_ID"),fenceMarkerId=fenceTuple("OLD_FENCE_MARKER_ID");
  const markerPath=base+"/normal-cold-h2-x230-transfer-r1/relay-effect-fence.public.json",markerSha="69a6a00997c2165414238ad27b699b34aab569ef003a579c0e568ea8d272ee33",markerVersion="2050:7237359:2709:1793876790283098805:1793876790283098805";
  check("fence.GO_bound",go.original_fence.old_relay==="desktop/1a1aa57458d-fc05-4156"&&go.original_fence.state==="UNKNOWN_PRESERVED"&&go.original_fence.marker_sha256===markerSha&&go.original_fence.three_held_readonly_FDs_required===true);
  for(const key of ["effect_fence_before","effect_fence_before_endpoints","effect_fence_after_cleanup"]){
    const f=L[key];check("fence.lossless_full9:"+key,equal(f.root_identity,fenceRootId)&&equal(f.marker_identity,fenceMarkerId));
    check("fence.positive_gate:"+key,f.held_and_named_verified===true&&f.marker_path===markerPath&&f.marker_sha256===markerSha&&f.marker_version===markerVersion&&f.original_relay_state==="UNKNOWN"&&f.original_relay_termination_proven===false);
  }
  check("fence.descriptor_names",equal(core.effect_fence_descriptors.map(x=>x.name),[base,"normal-cold-h2-x230-transfer-r1","relay-effect-fence.public.json"]));
  for(const row of core.effect_fence_descriptors)check("fence.once_closed:"+row.name,row.close_attempted===true&&row.closed===true&&row.error_type===null&&!Object.hasOwn(row,"fd"));
  check("fence.positive_final_flags",core.effect_fence_before_verified===true&&core.effect_fence_after_cleanup_verified===true&&core.effect_fence_all_descriptors_closed===true);
  check("old_UNKNOWN_stays_separate",core.original_relay_state==="UNKNOWN"&&core.original_relay_termination_proven===false&&intent.old_relay_state==="UNKNOWN preserved");
  const stages=["result['effect_fence_before']=acquire_effect_fence()","ROOT.mkdir(mode=0o700)","result['effect_fence_before_endpoints']=verify_effect_fence()","receiver=start_child(","wait_child(sender)","wait_child(receiver)","remote_endpoints_verified=True","result['effect_fence_after_cleanup']=verify_effect_fence()","fence_closed=close_effect_fence()"];
  let cursor=-1;for(const stage of stages){const at=input.relay.indexOf(stage);check("source.fence_stage_order:"+stage,at>cursor);cursor=at;}
  lineContains("relay","tuple(identity(os.fstat(parent))[:5])==OLD_FENCE_BASE_ID==tuple(identity(BASE.lstat())[:5])");
  lineContains("relay","if row['close_attempted']:continue");
  lineContains("relay","row['close_attempted']=True");
  lineContains("relay","if pending_signal is not None or not result['all_owned_stopped'] or time.monotonic()>=UNTIL or not (fence_verified_before and fence_verified_after_cleanup and fence_closed):result['status']='failed'");
  check("old_HA_controller_unchanged",equal(L.original_ha_controller_before,L.original_ha_controller_after)&&core.original_ha_controller_before.bytes===12409&&core.original_ha_controller_before.sha256==="c70892cb19601fa9769ae3f36810bb123f756f335654f284a4001bf2d69c796e");
  const trustExpected={
    [base.replace("/heptabao-ha-closure-20261103-r1","")+"/.ssh/config"]:"e7b887aad30f6642876c09744c317387b143e4a4b21ddc4879df2b558379ccf4",
    "/home/qian-qi/.ssh/hepta-transport/known_hosts":"1463442349bbb6b56e9ffbb66acce3c4abcceefe1c141c7b7f1ea9bb0dedf034"
  };
  check("trust.unchanged_lossless",equal(L.trust_before,L.trust_after)&&equal(Object.keys(core.trust_before).sort(),Object.keys(trustExpected).sort()));
  for(const path of Object.keys(trustExpected))check("trust.expected_pin:"+path,core.trust_before[path].sha256===trustExpected[path]&&L.trust_before[path].identity.length===9);
  const ssh=core.ssh_preflight["x230-ts"];
  check("ssh.exact_host_policy",equal(ssh.projection,{host:"x230-ts",hostname:"192.168.0.13",user:"qian",port:"22",hostkeyalias:"hepta-node-x230",stricthostkeychecking:"true",batchmode:"yes",connecttimeout:"10",connectionattempts:"1",forwardagent:"no",updatehostkeys:"false",clearallforwardings:"yes",controlmaster:"false",controlpath:null}));
  check("ssh.known_hosts_same",equal(L.ssh_preflight["x230-ts"].known_hosts_before["/home/qian-qi/.ssh/hepta-transport/known_hosts"],L.trust_before["/home/qian-qi/.ssh/hepta-transport/known_hosts"])&&/^[0-9a-f]{64}$/.test(ssh.effective_config_sha256));
  check("remote_positive_closure_conjunction",core.remote_endpoint_completion_verified===true&&core.remote_cleanup_unknown===false&&core.all_local_owned_stopped===true&&core.all_owned_stopped===true);
  const groups={};for(const x of checks){const k=x.id.split(/[.:]/)[0];groups[k]=(groups[k]||0)+1;}
  return {
    schema:"heptabao.authbus.peer.X230-relay-desktop-core-semantic.v1",status:"PASS_REPORTED_DESKTOP_CORE_CONTRACT_ONLY",
    original_inputs:pins,ready_source_tree:sourceTree,original_job:job,
    executed_pure_predicate_checks:checks.length,failed:0,check_groups:groups,
    canonical:{commit:H,tree:T,sole_parent:P,root_commit:R,history_commits:3763,tracked_files:3914},
    actual_timing:{relay_seconds:core.elapsed_seconds,receiver_seconds:r.elapsed_seconds,sender_seconds:s.elapsed_seconds,unchanged_limits:limits},
    local_owned_commands:core.commands,local_cleanup:core.cleanup,local_child_count:3,
    receiver_reported_commands:remoteRows,remote_child_count:21,
    receiver_reported_materialization:material,receiver_receipt_descriptor:r.receipt,
    reported_destination_files:destinations,total_artifact_bytes:132647913,
    fence:{observations:3,held_descriptors:3,all_once_closed:true,marker_path:markerPath,marker_sha256:markerSha,marker_version:markerVersion,root_identity_decimal:fenceRootId,marker_identity_decimal:fenceMarkerId,continuous_atomic_namespace_proof:false,old_relay:"desktop/1a1aa57458d-fc05-4156",old_state:"UNKNOWN_PRESERVED",old_termination_proven:false},
    runtime_calls:0,SDK_executions:0,candidate_executions:0,host_reads:0,
    independent_destination_infos_verified:false,independent_receiver_receipt_body_verified:false,full_observer_chain_verified:false,
    full_transfer_qualification:false,X230_runtime_qualification:false,production_qualification:false,
    evidence_limits:[
      "Embedded receiver values and original local SSH exit0 satisfy the frozen relay's positive endpoint contract; they are not an independent destination read.",
      "The seven destination infos, complete receiver receipt and their original observation chains remain with Compat/root.",
      "Original desktop authority records 368 stdout bytes and zero stderr; the whole terminal stream body is not one of this verifier's inputs.",
      "Only three held-fence descriptors are individually enumerated in the core. Other normal-path closes are enforced by source exceptions, not a new universal FD ledger.",
      "The fence checks are bounded sequential held/named observations, not continuous atomic custody or evidence of old relay termination.",
      "Normal61 and export proof flags are checked as required endpoint report fields; this review does not rerun those product tests or independently re-audit their receipt bodies."
    ]
  };
}