function verifyX230OriginalObservers(files,tree,readyTree,sha1,sha256){
  // Pure V8. Exact raw UTF-8 strings and two recursive Git-tree JSON objects.
  // SHA functions take binary byte strings. No tools/process/filesystem/network.
  const checks=[],used=new Set(),pins={},observers=[];
  const job="1a1ace08ffa-fc05-576b",host="desktop",packetTree="6b7781609be0345b5730aabb1b4394652d4d74be";
  const readyRoot="4fdb7848257d917b8efdd4dd1bed296ae5c40dd2";
  const base="/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-same-root-publication-x230-transfer-controls-r1";
  const check=(id,condition)=>{checks.push({id,passed:condition===true});if(condition!==true)throw Error("verification_failed:"+id);};
  const utf8=s=>unescape(encodeURIComponent(s)),text=b=>decodeURIComponent(escape(b)),cmp=(a,b)=>a<b?-1:a>b?1:0;
  const raw=p=>{check("input.present:"+p,typeof files[p]==="string");used.add(p);return files[p];};
  const json=p=>JSON.parse(raw(p));
  const stable=v=>Array.isArray(v)?"["+v.map(stable).join(",")+"]":v&&typeof v==="object"?"{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+stable(v[k])).join(",")+"}":JSON.stringify(v);
  const equal=(a,b)=>stable(a)===stable(b);
  function oneText(value,id){
    check(id+".one_text",Array.isArray(value.content)&&value.content.length===1&&value.content[0].type==="text"&&typeof value.content[0].text==="string");
    return value.content[0].text;
  }
  function sdk(p){
    const envelope=json(p);check("sdk.not_error:"+p,envelope.isError===false);
    check("sdk.structured_null:"+p,envelope.structuredContent===null||envelope.structuredContent===undefined);
    return JSON.parse(oneText(envelope,p));
  }
  function timeout(p,tool){
    const envelope=json(p);check("error.isError:"+p,envelope.isError===true);
    const t=oneText(envelope,p);
    check("error.exact_tool:"+p,t.includes("heptaruntime_mac_controller."+tool));
    check("error.timeout:"+p,t.includes("Mcp error: -32603: MCP request timed out"));
    return {path:p,blob:pins[p].blob,sha256:pins[p].sha256,bytes:pins[p].bytes};
  }
  function fromHex(s){check("hex.syntax",typeof s==="string"&&s.length%2===0&&/^[0-9a-f]*$/.test(s));let out="";for(let i=0;i<s.length;i+=2)out+=String.fromCharCode(parseInt(s.slice(i,i+2),16));return out;}
  function base64(s){
    check("base64.syntax",typeof s==="string"&&s.length%4===0&&/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s));
    const a="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let out="";
    for(let i=0;i<s.length;i+=4){
      const x=a.indexOf(s[i]),y=a.indexOf(s[i+1]),z=s[i+2]==="="?0:a.indexOf(s[i+2]),w=s[i+3]==="="?0:a.indexOf(s[i+3]);
      if(s[i+2]==="=")check("base64.pad2",(y&15)===0);
      else if(s[i+3]==="=")check("base64.pad1",(z&3)===0);
      out+=String.fromCharCode((x<<2)|(y>>4));
      if(s[i+2]!=="=")out+=String.fromCharCode(((y&15)<<4)|(z>>2));
      if(s[i+3]!=="=")out+=String.fromCharCode(((z&3)<<6)|w);
    }return out;
  }

  function verifyTree(api,expected,expectedLeaves,expectedTrees){
    check("tree.exact_root:"+expected,api.sha===expected&&api.truncated===false&&Array.isArray(api.tree));
    const leaves=api.tree.filter(x=>x.type==="blob"),dirs=api.tree.filter(x=>x.type==="tree"),rows=new Map(),children=new Map([["",[]]]),digests={};
    check("tree.count:"+expected,leaves.length===expectedLeaves&&dirs.length+1===expectedTrees);
    for(const row of api.tree){
      check("tree.unique:"+row.path,!rows.has(row.path));rows.set(row.path,row);
      check("tree.mode:"+row.path,(row.type==="blob"&&row.mode==="100644")||(row.type==="tree"&&row.mode==="040000"));
      if(row.type==="tree")children.set(row.path,[]);
    }
    for(const row of api.tree){const i=row.path.lastIndexOf("/"),parent=i<0?"":row.path.slice(0,i);check("tree.parent:"+row.path,children.has(parent));children.get(parent).push({...row,name:row.path.slice(i+1)});}
    for(const path of [...dirs.map(x=>x.path).sort((a,b)=>b.split("/").length-a.split("/").length),""]){
      const entries=children.get(path).slice().sort((a,b)=>cmp(utf8(a.name)+(a.type==="tree"?"/":""),utf8(b.name)+(b.type==="tree"?"/":"")));
      let bytes="";
      for(const row of entries){if(row.type==="tree")check("tree.child:"+row.path,digests[row.path]===row.sha);bytes+=(row.type==="tree"?"40000":row.mode)+" "+utf8(row.name)+"\0"+fromHex(row.sha);}
      const value=sha1("tree "+bytes.length+"\0"+bytes);check("tree.merkle:"+path,value===(path===""?expected:rows.get(path).sha));digests[path]=value;
    }return rows;
  }
  const originalRows=verifyTree(tree,packetTree,154,28),sourceRows=verifyTree(readyTree,readyRoot,34,6);
  const leaves=tree.tree.filter(x=>x.type==="blob");
  check("packet.bytes_count",Object.keys(files).length===154&&leaves.reduce((n,x)=>n+x.size,0)===1139834);
  for(const row of leaves){
    const b=utf8(raw(row.path)),blob=sha1("blob "+b.length+"\0"+b);check("packet.whole:"+row.path,b.length===row.size&&blob===row.sha);
    pins[row.path]={path:row.path,blob,bytes:b.length,sha256:sha256(b)};
  }
  const manifest=json("manifest.public.json"),manifested=new Set();
  check("manifest.count_bytes",manifest.files.length===153&&manifest.files_excluding_manifest===153&&manifest.total_bytes_excluding_manifest===1099183);
  for(const row of manifest.files){const pin=pins[row.path];check("manifest.unique:"+row.path,!manifested.has(row.path));manifested.add(row.path);check("manifest.pin:"+row.path,!!pin&&row.mode==="100644"&&row.blob===pin.blob&&row.bytes===pin.bytes&&row.sha256===pin.sha256);}
  check("manifest.excludes_self",manifested.size===153&&!manifested.has("manifest.public.json"));
  const references=[
    ["reference/request.original.json","dispatch/inert.exact-request.json"],
    ["reference/stdin.original.json","dispatch/inert.stdin.json"],
    ["reference/publisher.py","candidate/inert.py"],
    ["reference/sender.candidate.py","candidate/sender.py"],
    ["reference/receiver.candidate.py","candidate/receiver.py"],
    ["reference/relay.candidate.py","candidate/relay.py"]
  ];
  for(const [actual,source]of references){const row=sourceRows.get(source);check("source.request_binding:"+source,!!row&&row.type==="blob"&&row.sha===pins[actual].blob&&row.size===pins[actual].bytes);}
  const request=json("reference/request.original.json"),intent=json("execution/intent.original.json"),go=json("reference/go.original.json");
  const pinMatches=(object,path)=>object.blob===pins[path].blob&&object.bytes===pins[path].bytes&&object.sha256===pins[path].sha256;
  check("execution.root_GO",pins["reference/go.original.json"].blob==="247a9f4b56bec7251f2fbcaff0fab536bd29288a"&&pinMatches(intent.root_go,"reference/go.original.json"));
  check("execution.ready_source",intent.source_packet===readyRoot);
  check("execution.request_identity",pins["reference/request.original.json"].blob==="af6bcaafa3b8368a98a9f49f4ceb9f1028c43eeb"&&pinMatches(intent.request,"reference/request.original.json")&&pinMatches(go.request,"reference/request.original.json"));
  check("execution.publisher_stdin_pins",pinMatches(go.stdin,"reference/stdin.original.json")&&pinMatches(go.source,"reference/publisher.py"));
  check("execution.args_exact",equal(request.args.slice(0,4),["-I","-S","-B","-c"])&&request.args.length===5&&request.args[4]===raw("reference/publisher.py"));
  check("execution.stdin_exact",request.stdin===raw("reference/stdin.original.json"));
  check("execution.fixed_context",request.host===host&&request.executable==="/usr/bin/python3"&&request.cwd==="/home/qian-qi/heptabao-ha-closure-20261103-r1"&&request.timeout_seconds===60&&request.idempotency_key==="heptabao-4e808-x230-controls-inert-r1-f6f06d56");
  for(const key of ["host","executable","cwd","timeout_seconds","idempotency_key"])check("execution.intent_field:"+key,intent[key]===request[key]&&go.exact_process_start[key]===request[key]);
  check("execution.intent_pre_submission",intent.status==="INTENT_DURABLE_BEFORE_UNIQUE_SUBMIT"&&intent.process_start_submissions_before_this_intent===0);
  check("execution.intent_source_stdin",intent.code_bytes===pins["reference/publisher.py"].bytes&&intent.code_sha256===pins["reference/publisher.py"].sha256&&intent.stdin_bytes===pins["reference/stdin.original.json"].bytes&&intent.stdin_sha256===pins["reference/stdin.original.json"].sha256);
  const payload=json("reference/stdin.original.json");
  check("execution.payload_names",equal(Object.keys(payload.files).sort(),["receiver.py","relay.py","sender.py"]));
  for(const name of ["sender","receiver","relay"])check("execution.payload_code:"+name,base64(payload.files[name+".py"])===utf8(raw("reference/"+name+".candidate.py")));
  const canonicalRaw=raw("verification/typed-request-canonical.json"),canonical=JSON.parse(canonicalRaw);
  const expectedBinding={args:request.args,cpu_quota_percent:null,cwd:request.cwd,env:{},executable:request.executable,host:request.host,memory_max_bytes:null,nice:null,stdin:request.stdin,timeout_seconds:request.timeout_seconds};
  check("execution.canonical_binding_fields",equal(canonical,expectedBinding));
  check("execution.canonical_digest",sha256(utf8(canonicalRaw))===intent.request_digest&&intent.request_digest===go.exact_process_start.request_digest_sha256);
  const ack=sdk("execution/start.original.sdk.json"),ackText=oneText(json("execution/start.original.sdk.json"),"execution.ack");
  check("execution.ack_text_exact",ackText===raw("execution/start.original.json"));
  check("execution.ack_identity",ack.job.host===host&&ack.job.id===job&&ack.job.idempotency_key===request.idempotency_key&&ack.job.request_digest===intent.request_digest);
  check("execution.ack_args_context",equal(ack.job.args,request.args)&&ack.job.executable===request.executable&&ack.job.cwd===request.cwd&&equal(ack.job.env_keys,[]));
  const fingerprint=/\"request_fingerprint\"\s*:\s*(\d+)/.exec(ackText);
  check("execution.fingerprint_lossless",!!fingerprint&&fingerprint[1]===intent.request_fingerprint_decimal&&fingerprint[1]===go.exact_process_start.request_fingerprint_decimal);
  check("execution.unique_launched",ack.reused===false&&ack.job.launch_state==="launched"&&ack.job.launch_error===null);
  const index=json("observations/index.public.json");
  const specs=[
    {name:"authority",tool:"process_status",offsets:[0]},
    {name:"streams",tool:"process_read",offsets:[0],recovered:true},
    {name:"info-sender",tool:"file_info",file:"sender.py",offsets:[0]},
    {name:"info-receiver",tool:"file_info",file:"receiver.py",offsets:[0]},
    {name:"info-relay",tool:"file_info",file:"relay.py",offsets:[0]},
    {name:"info-receipt",tool:"file_info",file:"inert-stage.result.public.json",offsets:[0]},
    {name:"body-sender",tool:"binary_read",file:"sender.py",offsets:[0]},
    {name:"body-receiver",tool:"binary_read",file:"receiver.py",offsets:[0,16384,32768]},
    {name:"body-relay",tool:"binary_read",file:"relay.py",offsets:[0,16384,32768]},
    {name:"body-receipt",tool:"binary_read",file:"inert-stage.result.public.json",offsets:[0]}
  ];
  check("observers.index_labels",index.observer_count===10&&index.immutable_page_count===14&&equal(index.observers.map(x=>x.label),specs.map(x=>x.name)));
  const ids=new Set(),keys=new Set(),native={};let totalPages=0;
  for(const spec of specs){
    const name=spec.name,p="observations/"+name+"/",requestPath=p+"request.original.json",req=json(requestPath),args=req.operation.arguments;
    check(name+".typed_scope",req.operation.tool===spec.tool&&args.host===host&&typeof req.idempotency_key==="string"&&!keys.has(req.idempotency_key));keys.add(req.idempotency_key);
    const expectedKey="heptabao-4e808-x230-inert-"+(["authority","streams"].includes(name)?"observe-":"")+name+"-r1";
    check(name+".fixed_key",req.idempotency_key===expectedKey);
    if(name==="authority")check(name+".fixed_job",args.job_id===job);
    if(name==="streams")check(name+".fixed_streams",args.job_id===job&&args.stdout_offset===0&&args.stderr_offset===0&&args.limit===16384);
    if(spec.file)check(name+".fixed_path",args.path===base+"/"+spec.file);
    if(spec.tool==="binary_read")check(name+".version_bound_request",args.offset===0&&args.limit===65536&&typeof args.expected_version==="string"&&/^\d+:\d+:\d+:\d+:\d+$/.test(args.expected_version));
    const admissionPath=p+"admission.original.sdk.json",admission=sdk(admissionPath),id=admission.operation_id;
    check(name+".admission_text_exact",oneText(json(admissionPath),name+".admission")===raw(p+"admission.original.json"));
    check(name+".admission_ID",typeof id==="string"&&/^[0-9a-f]{64}$/.test(id)&&!ids.has(id));ids.add(id);
    check(name+".admission_scope",admission.tool_name===spec.tool&&admission.reused===false&&admission.admission_is_not_dispatch_completion===true&&admission.automatic_retry===false);
    const statusPrefix=spec.recovered?p+"recovery-01/status.original":p+"status.original",statusPath=statusPrefix+".sdk.json";
    const statusRequest=json(p+"status.exact-request.json"),status=sdk(statusPath);
    check(name+".status_exact_ID",equal(statusRequest,{operation_id:id})&&status.operation_id===id&&status.tool_name===spec.tool);
    check(name+".status_text_exact",oneText(json(statusPath),name+".status")===raw(statusPrefix+".json"));
    check(name+".closed",status.async_state==="completed"&&status.result_state==="stored_observed"&&status.owned_future_active===false&&status.payload_available===true);
    check(name+".status_not_remote_termination_proof",status.remote_termination_confirmed===false);
    let joined="",digest=null,total=null;const pageRows=[];
    for(const offset of spec.offsets){
      const stem=p+"pages/"+String(offset).padStart(6,"0")+".original",pageRequestPath=stem+".request.json",pageSdkPath=stem+".sdk.json",pageNativePath=stem+".json";
      const pageRequest=json(pageRequestPath),page=sdk(pageSdkPath);
      check(name+".page_request:"+offset,equal(pageRequest,{operation_id:id,offset,limit:16384}));
      check(name+".page_text_exact:"+offset,oneText(json(pageSdkPath),name+".page")===raw(pageNativePath));
      check(name+".page_identity:"+offset,page.operation_id===id&&page.offset===offset&&page.immutable_snapshot===true&&page.payload_kind==="native_result"&&page.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization");
      check(name+".page_size_digest:"+offset,Number.isSafeInteger(page.total_bytes)&&page.total_bytes>=0&&/^[0-9a-f]{64}$/.test(page.result_sha256));
      if(total===null){total=page.total_bytes;digest=page.result_sha256;}
      check(name+".same_total_digest:"+offset,page.total_bytes===total&&page.result_sha256===digest);
      const bytes=base64(page.data_base64);
      check(name+".contiguous:"+offset,offset===joined.length&&bytes.length<=16384&&page.next_offset===offset+bytes.length&&page.next_offset<=total);
      check(name+".eof:"+offset,page.eof===(page.next_offset===total));
      joined+=bytes;totalPages++;
      pageRows.push({offset,bytes:bytes.length,next_offset:page.next_offset,eof:page.eof,request_path:pageRequestPath,sdk_path:pageSdkPath,page_native_path:pageNativePath});
    }
    const originalPayloadPath=p+"payload.original.json",nativePath=p+"native.original.json";
    check(name+".whole_payload_hash",joined.length===total&&sha256(joined)===digest);
    check(name+".whole_payload_exact",joined===utf8(raw(originalPayloadPath)));
    const original=JSON.parse(text(joined));check(name+".payload_success",original.resultType==="complete"&&original.isError===false);
    const nativeText=oneText(original,name+".native");
    check(name+".native_exact",nativeText===raw(nativePath));native[name]=JSON.parse(nativeText);
    const indexed=index.observers.find(x=>x.label===name),expectedStatus=spec.recovered?p+"recovery-01/status.original":p+"status.original";
    check(name+".index_bindings",indexed.operation_id===id&&indexed.request===requestPath&&indexed.admission===p+"admission.original"&&indexed.status===expectedStatus&&indexed.original_payload===originalPayloadPath&&indexed.native===nativePath&&equal(indexed.pages,spec.offsets.map(o=>p+"pages/"+String(o).padStart(6,"0")+".original")));
    check(name+".index_closed",indexed.completed===true&&indexed.owned_future_active===false&&indexed.result_state==="stored_observed");
    observers.push({name,tool:spec.tool,operation_id:id,request_path:requestPath,admission_sdk_path:admissionPath,status_request_path:p+"status.exact-request.json",status_sdk_path:statusPath,pages:pageRows,original_payload_path:originalPayloadPath,payload_bytes:joined.length,payload_sha256:digest,native_path:nativePath,native_bytes:utf8(nativeText).length,native_sha256:sha256(utf8(nativeText)),completed:true,owned_future_active:false});
  }
  check("observers.exact_count",ids.size===10&&keys.size===10&&observers.length===10&&totalPages===14);
  const errorPath="observations/streams/status.original.sdk.json",originalError=timeout(errorPath,"operation_status");
  check("recovery.error_text_exact",oneText(json(errorPath),"streams.error")===raw("observations/streams/status.error.original.txt"));
  const recovery=json("reference/recovery-go.original.json"),recoveryIntent=json("observations/streams/recovery-01/intent.original.json"),statusRequest=json("observations/streams/status.exact-request.json");
  check("recovery.GO_pin",pins["reference/recovery-go.original.json"].blob==="45520f0274ef96844ab797dc01ca5227393d3bdd"&&pinMatches(recoveryIntent.root_go,"reference/recovery-go.original.json"));
  check("recovery.request_same_ID",equal(recovery.exact_status_request,statusRequest)&&recovery.original_status_request_blob===pins["observations/streams/status.exact-request.json"].blob&&pinMatches(recoveryIntent.request,"observations/streams/status.exact-request.json"));
  check("recovery.original_operation",recoveryIntent.operation_id===statusRequest.operation_id&&equal(recovery.original_process_read_request,json("observations/streams/request.original.json")));
  check("recovery.error_pin",pinMatches(recoveryIntent.prior_error,errorPath)&&recoveryIntent.prior_error_preserved===true);
  check("recovery.no_new_admission",recoveryIntent.operation_start_allowed===false&&recoveryIntent.process_read_allowed===false&&recoveryIntent.process_start_allowed===false&&recovery.scope.one_exact_operation_status_call===true&&recovery.scope.no_new_operation_start_or_process_read===true&&recovery.scope.no_process_start_replay===true);
  const historical=json("historical/PARTIAL_AFTER_STREAM_STATUS_ERROR.public.json"),closure=json("actual/closure.public.json");
  check("recovery.historical_identity",historical.job_id===job&&historical.stream_operation_id===statusRequest.operation_id&&pinMatches(historical.stream_status_error_sdk,errorPath));
  check("recovery.historical_partial_preserved",historical.status==="INERT_KNOWN_SUCCESS_STREAM_READ_OBSERVER_UNKNOWN"&&historical.stream_future_state==="UNKNOWN_after_status_RPC_error"&&historical.stream_original_payload_bytes_received===0);
  check("recovery.historical_no_replay",historical.fixed_file_infos_submitted===0&&historical.fixed_body_reads_submitted===0&&historical.relay_submitted===false&&historical.old_X230_relay==="UNKNOWN preserved");
  check("recovery.current_scope",closure.job_id===job&&closure.first_streams_status_transport_error_preserved===true&&closure.recovery_was_same_operation_id===true&&closure.relay_submitted===false&&closure.old_X230_relay_state==="UNKNOWN preserved; inert did not newly execute or verify the transport effect fence");
  // Only stream transport and authority; publisher receipt/FD/file semantics are
  // deliberately left to the parent, including 1514 stdout vs 1924 receipt.
  const authority=native.authority,streams=native.streams;
  check("authority.identity",authority.job_id===job&&authority.exit_code===0&&authority.state==="succeeded"&&authority.output_complete===true&&authority.output_durable===true&&authority.terminal_publication_confirmed===true&&authority.timed_out===false&&authority.cancelled===false);
  check("authority.byte_counts",authority.log_bytes.stdout.seen===1514&&authority.log_bytes.stdout.stored===1514&&authority.log_bytes.stderr.seen===0&&authority.log_bytes.stderr.stored===0);
  check("authority.no_log_loss",authority.log_errors.stdout===null&&authority.log_errors.stderr===null&&authority.log_synced.stdout===true&&authority.log_synced.stderr===true&&authority.log_truncated.stdout===false&&authority.log_truncated.stderr===false);
  check("streams.job",streams.job_id===job);
  const streamResult={};
  for(const kind of ["stdout","stderr"]){
    const row=streams[kind],bytes=fromHex(row.bytes_hex),expectedBytes=kind==="stdout"?1514:0,savedPath="actual/"+kind+".original.txt";
    check("streams.hex_text:"+kind,bytes===utf8(row.text));
    check("streams.complete:"+kind,row.offset===0&&row.next_offset===expectedBytes&&row.size===expectedBytes&&row.eof===true&&bytes.length===expectedBytes);
    check("streams.saved_exact:"+kind,bytes===utf8(raw(savedPath)));
    streamResult[kind]={bytes:bytes.length,sha256:sha256(bytes),path:savedPath};
  }
  const groups={};for(const c of checks){const g=c.id.split(/[.:]/)[0];groups[g]=(groups[g]||0)+1;}
  return {
    schema:"heptabao.x230-inert-original-ten-observer-chain.peer-result.r1",
    status:"PASS_ORIGINAL_OBSERVATION_CHAIN_ONLY",
    input_packet:packetTree,input_files:154,input_bytes:1139834,input_tree_objects:28,source_tree:readyRoot,source_tree_objects:6,
    actual_pure_predicate_evaluations:checks.length,passed:checks.length,failed:0,check_groups:groups,
    execution:{host,job_id:job,exact_request_blob:pins["reference/request.original.json"].blob,source_publisher_blob:pins["reference/publisher.py"].blob,stdin_blob:pins["reference/stdin.original.json"].blob,request_digest:intent.request_digest,request_fingerprint_decimal:fingerprint[1]},
    returned_observers:observers,returned_observer_count:10,complete_immutable_pages:14,
    streams:streamResult,authority:{exit_code:0,full:true,durable:true,confirmed:true},
    recovery:{original_error:originalError,recovery_GO:pins["reference/recovery-go.original.json"].blob,same_status_request_blob:pins["observations/streams/status.exact-request.json"].blob,original_operation_id:statusRequest.operation_id,later_same_operation_closed:true,new_operation_start:false,original_historical_partial_preserved:true,old_X230_relay_UNKNOWN_preserved:true},
    root_owned_semantics_not_audited:["four file_info actual full9","four decoded whole body semantics and source qualification","1514 stdout versus 1924 receipt content","publisher resource/FD custody","subsequent exact relay GO"],
    author_513_not_executed_or_relabelled_as_product_tests:true,
    chronology_limit:"Exact durable request objects and the global execution/recovery intents are checked. Git IDs do not independently prove historical persistence-before-call timestamps.",
    source_or_product_qualification:false,runtime_calls:0,sdk_executions:0,candidate_executions:0,new_runtime_permissions:false,
    original_paths_used:[...used].sort().map(p=>pins[p]),
    source_path_bindings:references.map(([actual,source])=>({actual_packet_path:actual,source_tree_path:source,blob:pins[actual].blob,bytes:pins[actual].bytes,sha256:pins[actual].sha256}))
  };
}
