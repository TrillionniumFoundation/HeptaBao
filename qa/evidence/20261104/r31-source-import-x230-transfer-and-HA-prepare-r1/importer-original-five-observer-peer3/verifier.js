function verifyImporterOriginalObservers(files,tree,sha1,sha256){
  // Pure V8 interface: files maps original packet paths to exact UTF-8 strings;
  // tree is the complete Git recursive-tree JSON; hashes accept binary byte strings.
  // No tools, filesystem, process, network, SDK import or candidate execution.
  const checks=[],used=new Set(),pins={},observations=[];
  const job="1a1acd0d62d-fc05-571a",host="desktop";
  const corePath="/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-same-root-publication-source-import-r1/control/result.public.json";
  const coreHash="484ebbd31e94213c526bbde8664a516658fbab48a273bace01396a6ca10adb72";
  const packetTree="4c144a705c7278f1b3b0d364e3be9d6b30b546e2";
  const check=(id,condition)=>{checks.push({id,passed:condition===true});if(condition!==true)throw Error("verification_failed:"+id);};
  const utf8=s=>unescape(encodeURIComponent(s));
  const text=b=>decodeURIComponent(escape(b));
  const cmp=(a,b)=>a<b?-1:a>b?1:0;
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
  function compact(s){
    let quoted=false,escaped=false,out="";
    for(const c of s){if(quoted){out+=c;if(escaped)escaped=false;else if(c==="\\")escaped=true;else if(c==='"')quoted=false;}
      else if(c==='"'){quoted=true;out+=c;}else if(!" \t\r\n".includes(c))out+=c;}
    check("json.complete_tokens",!quoted&&!escaped);return out;
  }
  function topValues(s){
    JSON.parse(s);let i=0;const out={};
    const ws=()=>{while(i<s.length&&" \t\r\n".includes(s[i]))i++;};
    ws();check("json.top_object",s[i++]==="{");
    while(true){ws();if(s[i]==="}"){i++;break;}
      const begin=i;check("json.key_quote",s[i++]==='"');let esc=false;
      while(i<s.length){const c=s[i++];if(esc)esc=false;else if(c==="\\")esc=true;else if(c==='"')break;}
      const key=JSON.parse(s.slice(begin,i));check("json.unique_top_key:"+key,!Object.prototype.hasOwnProperty.call(out,key));
      ws();check("json.colon",s[i++]===":");ws();const start=i;
      let depth=0,quoted=false,escaped=false;
      while(i<s.length){const c=s[i];if(quoted){if(escaped)escaped=false;else if(c==="\\")escaped=true;else if(c==='"')quoted=false;i++;continue;}
        if(c==='"'){quoted=true;i++;continue;}if(c==="{"||c==="["){depth++;i++;continue;}
        if(c==="}"||c==="]"){if(depth===0)break;depth--;i++;continue;}if(c===","&&depth===0)break;i++;}
      out[key]=s.slice(start,i).trim();ws();if(s[i]===","){i++;continue;}check("json.object_end",s[i++]==="}");break;
    }ws();check("json.no_tail",i===s.length);return out;
  }
  // Whole original packet identity and manifest; these are data-integrity checks,
  // not an audit of the candidate code or importer command semantics.
  check("packet.exact_root",tree.sha===packetTree&&tree.truncated===false&&Array.isArray(tree.tree));
  const leaves=tree.tree.filter(x=>x.type==="blob"),dirs=tree.tree.filter(x=>x.type==="tree");
  check("packet.count",leaves.length===115&&dirs.length===57&&Object.keys(files).length===115);
  check("packet.bytes",leaves.reduce((n,x)=>n+x.size,0)===886981);
  const rowsByPath=new Map(),children=new Map([["",[]]]);
  for(const row of tree.tree){
    check("packet.unique_path:"+row.path,!rowsByPath.has(row.path));rowsByPath.set(row.path,row);
    check("packet.object_mode:"+row.path,(row.type==="blob"&&row.mode==="100644")||(row.type==="tree"&&row.mode==="040000"));
    if(row.type==="tree")children.set(row.path,[]);
  }
  for(const row of tree.tree){const i=row.path.lastIndexOf("/"),parent=i<0?"":row.path.slice(0,i);check("packet.parent:"+row.path,children.has(parent));children.get(parent).push({...row,name:row.path.slice(i+1)});}
  for(const row of leaves){
    const s=raw(row.path),b=utf8(s),blob=sha1("blob "+b.length+"\0"+b);
    check("packet.whole:"+row.path,b.length===row.size&&blob===row.sha);
    pins[row.path]={path:row.path,blob,bytes:b.length,sha256:sha256(b)};
  }
  const treeDigests={};
  for(const path of [...dirs.map(x=>x.path).sort((a,b)=>b.split("/").length-a.split("/").length),""]){
    const entries=children.get(path).slice().sort((a,b)=>cmp(utf8(a.name)+(a.type==="tree"?"/":""),utf8(b.name)+(b.type==="tree"?"/":"")));
    let bytes="";
    for(const row of entries){if(row.type==="tree")check("packet.child_merkle:"+row.path,treeDigests[row.path]===row.sha);bytes+=(row.type==="tree"?"40000":row.mode)+" "+utf8(row.name)+"\0"+fromHex(row.sha);}
    const actual=sha1("tree "+bytes.length+"\0"+bytes);check("packet.merkle:"+path,actual===(path===""?packetTree:rowsByPath.get(path).sha));treeDigests[path]=actual;
  }
  const manifest=json("MANIFEST.public.json");check("manifest.count",manifest.entries.length===114);
  const manifested=new Set();
  for(const row of manifest.entries){const pin=pins[row.path];check("manifest.unique:"+row.path,!manifested.has(row.path));manifested.add(row.path);check("manifest.pin:"+row.path,!!pin&&row.blob===pin.blob&&row.bytes===pin.bytes&&row.sha256===pin.sha256);}
  check("manifest.scope",manifested.size===114&&!manifested.has("MANIFEST.public.json"));
  // Original execution identity: observe-only linkage, no command semantic audit.
  const requestPath="execution/intent/exact-process-start-request.public.json";
  const request=json(requestPath),executionIntent=json("execution/intent/execution-intent.public.json"),executionAck=sdk("execution/ack/original-sdk.json");
  check("execution.exact_requests",raw(requestPath)===raw("execution/ack/exact-request.public.json"));
  check("execution.intent_request",equal(executionIntent.request,request));
  check("execution.intent_pin",executionIntent.exact_request.blob===pins[requestPath].blob&&executionIntent.exact_request.bytes===pins[requestPath].bytes&&executionIntent.exact_request.sha256===pins[requestPath].sha256);
  check("execution.intent_unsubmitted",executionIntent.submission_count_before_intent===0&&executionIntent.submitted===false);
  check("execution.ack_identity",executionAck.job.id===job&&executionAck.job.host===host&&executionAck.job.idempotency_key===request.idempotency_key);
  check("execution.ack_request_fields",executionAck.job.executable===request.executable&&executionAck.job.cwd===request.cwd&&equal(executionAck.job.args,request.args));
  check("execution.ack_digest",executionAck.job.request_digest===executionIntent.request_digest);
  const fingerprint=/\"request_fingerprint\"\s*:\s*(\d+)/.exec(oneText(json("execution/ack/original-sdk.json"),"execution.ack"));
  check("execution.fingerprint_lossless",!!fingerprint&&fingerprint[1]===executionIntent.request_fingerprint_decimal);
  check("execution.ack_launched",executionAck.reused===false&&executionAck.job.launch_state==="launched"&&executionAck.job.launch_error===null);
  const state=json("STATE.public.json");
  check("state.same_job",state.job_id===job&&state.execution_submissions===1);
  check("state.claims_limited",state.original_commands_raw_complete===false&&state.full_source_import_qualification===false);
  const layouts=[
    {name:"authority0",tool:"process_status",offsets:[0]},
    {name:"streams0",tool:"process_read",offsets:[0,8192,16384,24576,32768,40960,49152]},
    {name:"streams1",tool:"process_read",offsets:[0,8192,16384,24576,32768],ack:"recovery/tail/ACK/original-sdk.json"},
    {name:"core_info",tool:"file_info",offsets:[0],recoveredPage:true},
    {name:"core_body",tool:"binary_read",offsets:[0,8192,16384,24576,32768,40960]}
  ];
  const native={},ids=new Set();let totalPages=0;
  for(const spec of layouts){
    const name=spec.name,p="observers/"+name+"/",exactPath=p+"intent/exact-operation-start-request.public.json",exact=json(exactPath),intent=json(p+"intent/read-intent.public.json");
    check(name+".exact_request_files",raw(exactPath)===raw(p+"start/request.json"));
    check(name+".intent_request",equal(intent.request,exact)&&intent.job_id===job&&intent.observation===name&&intent.product_replay===false&&intent.one_native_future===true);
    check(name+".original_scope",exact.operation.tool===spec.tool&&exact.operation.arguments.host===host);
    const args=exact.operation.arguments;
    if(name==="authority0")check(name+".job",args.job_id===job);
    if(name.startsWith("streams"))check(name+".offset_limit",args.job_id===job&&args.stdout_offset===0&&args.stderr_offset===(name==="streams0"?0:16384)&&args.limit===16384);
    if(name==="core_info"||name==="core_body")check(name+".path",args.path===corePath);
    if(name==="core_body")check(name+".offset_limit",args.offset===0&&args.limit===65536);
    const ackPath=spec.ack||p+"start/original-sdk.json",ack=sdk(ackPath),id=ack.operation_id;
    check(name+".returned_ID",typeof id==="string"&&/^[0-9a-f]{64}$/.test(id)&&!ids.has(id));ids.add(id);
    check(name+".ack_tool_scope",ack.tool_name===spec.tool&&ack.admission_is_not_dispatch_completion===true&&ack.automatic_retry===false);
    const statusRequest=json(p+"status-0/request.json"),status=sdk(p+"status-0/original-sdk.json");
    check(name+".status_same_ID",equal(statusRequest,{operation_id:id})&&status.operation_id===id&&status.tool_name===spec.tool);
    check(name+".closed",status.async_state==="completed"&&status.owned_future_active===false&&status.result_state==="stored_observed"&&status.payload_available===true);
    check(name+".status_not_remote_termination_proof",status.remote_termination_confirmed===false);
    let joined="",digest=null,total=null;const pageRecords=[];
    for(const offset of spec.offsets){
      const requestPath=spec.recoveredPage?"recovery/core-info-page/result/request.json":p+"result-"+offset+"/request.json";
      const sdkPath=spec.recoveredPage?"recovery/core-info-page/result/original-sdk.json":p+"result-"+offset+"/original-sdk.json";
      const pageRequest=json(requestPath),page=sdk(sdkPath);
      check(name+".page_request:"+offset,equal(pageRequest,{operation_id:id,offset,limit:8192}));
      check(name+".page_identity:"+offset,page.operation_id===id&&page.offset===offset&&page.immutable_snapshot===true&&page.payload_kind==="native_result");
      check(name+".original_payload_format:"+offset,page.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization");
      check(name+".page_total_digest:"+offset,Number.isSafeInteger(page.total_bytes)&&page.total_bytes>=0&&typeof page.result_sha256==="string"&&/^[0-9a-f]{64}$/.test(page.result_sha256));
      if(digest===null){digest=page.result_sha256;total=page.total_bytes;}
      check(name+".same_total_digest:"+offset,page.total_bytes===total&&page.result_sha256===digest);
      const bytes=base64(page.data_base64);
      check(name+".page_contiguous:"+offset,offset===joined.length&&bytes.length<=pageRequest.limit&&page.next_offset===offset+bytes.length&&page.next_offset<=total);
      check(name+".page_eof:"+offset,page.eof===(page.next_offset===total));
      joined+=bytes;totalPages++;
      pageRecords.push({offset,bytes:bytes.length,next_offset:page.next_offset,eof:page.eof,request_path:requestPath,sdk_path:sdkPath});
    }
    const payloadPath=p+"original-payload.json",nativePath=p+"native-result.public.json";
    check(name+".assembled_total_hash",joined.length===total&&sha256(joined)===digest);
    check(name+".assembled_original_exact",joined===utf8(raw(payloadPath)));
    const payload=JSON.parse(text(joined));
    check(name+".native_payload_not_error",payload.resultType==="complete"&&payload.isError===false);
    const nativeText=oneText(payload,name+".native_payload");
    check(name+".native_text_exact",nativeText===raw(nativePath));
    native[name]=JSON.parse(nativeText);
    const summary=state.observers.find(x=>x.name===name);
    check(name+".state_original_identity",!!summary&&summary.operation_id===id&&equal(summary.request,exact)&&equal(summary.closed_status,status)&&summary.complete===true);
    observations.push({name,operation_id:id,tool:spec.tool,ack_path:ackPath,exact_request_path:exactPath,intent_path:p+"intent/read-intent.public.json",status_sdk_path:p+"status-0/original-sdk.json",status_request_path:p+"status-0/request.json",pages:pageRecords,payload_path:payloadPath,payload_bytes:joined.length,payload_sha256:digest,native_path:nativePath,native_bytes:utf8(nativeText).length,native_sha256:sha256(utf8(nativeText)),completed:true,owned_future_active:false});
  }
  check("observers.exact_count",ids.size===5&&observations.length===5&&totalPages===20);
  // Preserve the lost admission, and only close the returned fresh observer.
  const originalTailError=timeout("observers/streams1/start/original-sdk.json","operation_start");
  check("tail.error_copy",raw("observers/streams1/start/original-sdk.json")===raw("recovery/tail/intent/original-admission-error-sdk.json"));
  const tailGO=json("recovery/tail/intent/root-reconciliation-GO.public.json"),tailIntent=json("recovery/tail/intent/reconciliation-intent.public.json"),tailRequest=json("observers/streams1/start/request.json");
  check("tail.GO_exact_blob",pins["recovery/tail/intent/root-reconciliation-GO.public.json"].blob==="86c17bb7cab6fbf5e45ec1475759fb283e86d204");
  check("tail.GO_exact_request",equal(tailGO.exact_original_request,tailRequest)&&equal(tailIntent.request,tailRequest));
  check("tail.request_unchanged",raw("recovery/tail/ACK/request.json")===raw("observers/streams1/start/request.json")&&raw("recovery/tail/intent/exact-operation-start-request.public.json")===raw("observers/streams1/start/request.json"));
  check("tail.intent_scope",tailIntent.root_GO===pins["recovery/tail/intent/root-reconciliation-GO.public.json"].blob&&tailIntent.original_future==="UNKNOWN"&&tailIntent.reconciliation_submissions_before_intent===0&&tailIntent.process_start===false&&tailIntent.offset_key_or_deadline_change===false);
  const recoveredTailAck=sdk("recovery/tail/ACK/original-sdk.json");
  check("tail.reused_false",recoveredTailAck.reused===false&&state.reconciliation_reused===false&&state.first_tail_admission_without_ACK==="UNKNOWN_PRESERVED");
  check("tail.GO_unknown_retained",tailGO.original_timeout.operation_id===null&&tailGO.original_timeout.native_future.includes("UNKNOWN")&&tailGO.interpretation.reused_false.includes("UNKNOWN"));
  // Original core-info operation was already closed; only its exact page was retried.
  const originalInfoError=timeout("observers/core_info/result-0/original-sdk.json","operation_result");
  check("info.error_copy",raw("observers/core_info/result-0/original-sdk.json")===raw("recovery/core-info-page/intent/original-error-sdk.json"));
  const infoGO=json("recovery/core-info-page/intent/root-GO.public.json"),infoIntent=json("recovery/core-info-page/intent/intent.public.json"),originalInfoRequest=json("observers/core_info/result-0/request.json");
  check("info.GO_exact_blob",pins["recovery/core-info-page/intent/root-GO.public.json"].blob==="c5c343caee651e0025c1317fd81c6b615eac241d");
  check("info.same_page_request",raw("observers/core_info/result-0/request.json")===raw("recovery/core-info-page/result/request.json")&&equal(infoGO.exact_operation_result_request,originalInfoRequest)&&equal(infoIntent.request,originalInfoRequest));
  check("info.intent_scope",infoIntent.root_GO===pins["recovery/core-info-page/intent/root-GO.public.json"].blob&&infoIntent.new_operation_start===false&&infoIntent.new_file_info===false&&infoIntent.product_replay===false&&infoIntent.once_only===true);
  check("info.original_closed_status",equal(json("recovery/core-info-page/intent/original-completed-status.public.json"),sdk("observers/core_info/status-0/original-sdk.json")));
  check("info.preserved_error_and_unknown",state.first_core_info_immutable_page_timeout==="PRESERVED; same ID/page explicitly recovered"&&infoIntent.previous_tail_lost_ACK_future==="UNKNOWN_PRESERVED");
  // Original native process streams: raw hex is authoritative, text is cross-checked.
  const authority=native.authority0;
  check("authority.exact_terminal",authority.job_id===job&&authority.state==="succeeded"&&authority.exit_code===0&&authority.output_complete===true&&authority.output_durable===true&&authority.terminal_publication_confirmed===true&&authority.timed_out===false&&authority.cancelled===false);
  check("authority.saved_copy",raw("terminal-scope/authority.public.json")===raw("observers/authority0/native-result.public.json"));
  check("authority.logs",authority.log_bytes.stdout.seen===0&&authority.log_bytes.stdout.stored===0&&authority.log_bytes.stderr.seen===28576&&authority.log_bytes.stderr.stored===28576&&authority.log_errors.stdout===null&&authority.log_errors.stderr===null&&authority.log_synced.stdout===true&&authority.log_synced.stderr===true&&authority.log_truncated.stdout===false&&authority.log_truncated.stderr===false);
  let stderr="";
  for(const name of ["streams0","streams1"]){
    const v=native[name],s=v.stderr,o=v.stdout,bytes=fromHex(s.bytes_hex),stdout=fromHex(o.bytes_hex);
    check(name+".stream_job",v.job_id===job);
    check(name+".stdout_empty",o.offset===0&&o.next_offset===0&&o.eof===true&&o.size===0&&stdout===""&&o.text==="");
    check(name+".stderr_hex_text",bytes===utf8(s.text));
    check(name+".stderr_contiguous",s.offset===stderr.length&&s.next_offset===s.offset+bytes.length&&s.size===28576&&s.eof===(s.next_offset===28576));
    check(name+".stderr_limit",bytes.length<=16384);stderr+=bytes;
  }
  check("terminal.complete_stderr",stderr.length===28576&&stderr===utf8(raw("terminal-scope/terminal.stderr.complete.json")));
  check("terminal.complete_stdout",raw("terminal-scope/terminal.stdout.complete.txt")==="");
  // Independent core metadata and version-bound binary body.
  const info=native.core_info,body=native.core_body,bodyRequest=json("observers/core_body/start/request.json").operation.arguments,coreBytes=base64(body.data_base64);
  check("core.info_copy",raw("actual/result.file_info.public.json")===raw("observers/core_info/native-result.public.json"));
  check("core.info_binding",info.path===corePath&&info.size===36163&&info.sha256===coreHash&&info.mode===384&&info.metadata.mode===384&&info.metadata.uid===1000&&info.metadata.gid===1000&&info.metadata.link_count===1);
  const version=info.version.split(":");check("core.version_shape",version.length===5&&version.every(x=>/^\d+$/.test(x))&&version[2]==="36163");
  check("core.request_version",bodyRequest.path===info.path&&bodyRequest.expected_version===info.version);
  check("core.binary_version_path",body.path===info.path&&body.version===info.version&&body.offset===0&&body.next_offset===36163&&body.size===36163&&body.eof===true);
  check("core.binary_complete_sha",coreBytes.length===36163&&sha256(coreBytes)===coreHash&&body.chunk_sha256===coreHash);
  check("core.binary_exact_saved",coreBytes===utf8(raw("actual/result.public.json"))&&pins["actual/result.public.json"].blob==="575f3ef51bb6e859ee28b0cf268966ce2b6a7513");
  // Compare publication copies without rounding any JSON number token.
  const terminalValues=topValues(text(stderr)),coreValues=topValues(text(coreBytes));
  check("core.terminal_extra_fields_only",equal(Object.keys(terminalValues).filter(k=>!Object.prototype.hasOwnProperty.call(coreValues,k)).sort(),["publication_within_original_deadline","receipt"])&&Object.keys(coreValues).every(k=>Object.prototype.hasOwnProperty.call(terminalValues,k)));
  for(const key of Object.keys(coreValues))check("core.terminal_lossless_field:"+key,compact(coreValues[key])===compact(terminalValues[key]));
  const receipt=JSON.parse(terminalValues.receipt);
  check("core.terminal_receipt_binding",receipt.path===corePath&&receipt.bytes===36163&&receipt.sha256===coreHash&&terminalValues.publication_within_original_deadline==="true");
  const groups={};for(const c of checks){const group=c.id.split(/[.:]/)[0];groups[group]=(groups[group]||0)+1;}
  return {
    schema:"heptabao.importer-original-five-observer-chain.peer-result.r1",
    status:"PASS_ORIGINAL_OBSERVER_CHAIN_ONLY",
    packet_tree:packetTree,files:115,bytes:886981,tree_objects:58,
    executed_pure_checks:checks.length,passed:checks.length,failed:0,check_group_counts:groups,
    execution_identity:{host,job_id:job,request_blob:pins[requestPath].blob,request_digest:executionIntent.request_digest,request_fingerprint_decimal:fingerprint[1]},
    returned_observers:observations,returned_observer_count:5,complete_immutable_pages:totalPages,
    terminal:{authority_exit_code:0,full:true,durable:true,stdout_bytes:0,stderr_bytes:stderr.length,stderr_sha256:sha256(stderr)},
    independent_core:{path:corePath,version:info.version,bytes:coreBytes.length,sha256:sha256(coreBytes),blob:pins["actual/result.public.json"].blob,metadata_path:"actual/result.file_info.public.json",body_path:"actual/result.public.json"},
    preserved_errors:{first_streams1_admission:originalTailError,first_streams1_future:"UNKNOWN_PRESERVED",returned_reconciliation_reused:false,returned_reconciliation_closed:true,first_core_info_page:originalInfoError,core_info_recovery:"EXACT_SAME_ID_OFFSET_LIMIT"},
    source_qualification:false,semantic_core_and_21_command_audit_performed:false,original_business_replayed:false,runtime_calls:0,sdk_executions:0,
    chronology_limit:"Stored exact intents and request/ACK linkages are verified. Git blob existence has no independent wall-clock timestamp; this peer does not newly prove execution-time persistence order from object IDs alone.",
    original_paths_used:[...used].sort().map(p=>pins[p])
  };
}
