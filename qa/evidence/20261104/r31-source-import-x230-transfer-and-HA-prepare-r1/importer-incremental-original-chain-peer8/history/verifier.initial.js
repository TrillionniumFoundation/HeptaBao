function verifyImporterIncrement(files,tree,oldTree,oldResultRaw,currentNulInfoReviewRaw,nulReconstructionReviewRaw,sha1,sha256){
  // Pure data verification. UTF-8 file strings; recursive Git-tree JSON objects.
  // Hash callbacks accept binary byte strings. No tools, filesystem, subprocess,
  // Runtime, SDK execution, candidate execution or importer command semantics.
  const checks=[],used=new Set(),pins={},observers=[],extracted=[];
  const packetTree="52f3258ff47319da11db9c6f586687ab31b1fc99",oldRoot="4c144a705c7278f1b3b0d364e3be9d6b30b546e2";
  const job="1a1acd0d62d-fc05-571a",host="desktop";
  const planPath="plan/finite-original-file-read-plan.public.json";
  const check=(id,condition)=>{checks.push({id,passed:condition===true});if(condition!==true)throw Error("verification_failed:"+id);};
  const utf8=s=>unescape(encodeURIComponent(s)),text=b=>decodeURIComponent(escape(b)),cmp=(a,b)=>a<b?-1:a>b?1:0;
  const raw=p=>{check("input.present:"+p,typeof files[p]==="string");used.add(p);return files[p];};
  const json=p=>JSON.parse(raw(p));
  const stable=v=>Array.isArray(v)?"["+v.map(stable).join(",")+"]":v&&typeof v==="object"?"{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+stable(v[k])).join(",")+"}":JSON.stringify(v);
  const equal=(a,b)=>stable(a)===stable(b);
  function externalPin(label,s,expected){
    check("basis.raw:"+label,typeof s==="string");
    const bytes=utf8(s),pin={blob:sha1("blob "+bytes.length+"\0"+bytes),bytes:bytes.length,sha256:sha256(bytes)};
    check("basis.pin:"+label,equal(pin,expected));return pin;
  }
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

  verifyTree(tree,packetTree,289,110);
  const oldRows=verifyTree(oldTree,oldRoot,115,58);
  const leaves=tree.tree.filter(x=>x.type==="blob");
  check("packet.count_bytes",Object.keys(files).length===289&&leaves.reduce((n,x)=>n+x.size,0)===2556370);
  for(const row of leaves){const b=utf8(raw(row.path)),blob=sha1("blob "+b.length+"\0"+b);check("packet.whole:"+row.path,b.length===row.size&&blob===row.sha);pins[row.path]={path:row.path,blob,bytes:b.length,sha256:sha256(b)};}
  const manifest=json("MANIFEST.public.json"),manifested=new Set();
  check("manifest.shape",manifest.schema==="heptabao.whole-public-packet.manifest.v1"&&manifest.entries.length===288);
  for(const entry of manifest.entries){const pin=pins[entry.path];check("manifest.unique:"+entry.path,!manifested.has(entry.path));manifested.add(entry.path);check("manifest.whole:"+entry.path,!!pin&&entry.blob===pin.blob&&entry.bytes===pin.bytes&&entry.sha256===pin.sha256);}
  check("manifest.no_self",manifested.size===288&&!manifested.has("MANIFEST.public.json"));
  const priorPin=externalPin("core115-result",oldResultRaw,{blob:"641955a9ec8cd980691cb78cd69b4b1c0bac09ac",bytes:42569,sha256:"1964a6cbfc06b884adf1884306fd4250d5129b4fe872663e7fdc3a6182ee3454"});
  const old=JSON.parse(oldResultRaw);
  check("prior.scope",old.packet_tree===oldRoot&&old.failed===0&&old.returned_observer_count===5&&old.complete_immutable_pages===20&&old.runtime_calls===0&&old.semantic_core_and_21_command_audit_performed===false);
  const aggregatePaths=new Set(["MANIFEST.public.json","STATE.public.json","README.md"]),aggregateChanges=[],oldOriginalPaths=[];
  check("prior.pins_count",old.original_paths_used.length===115);
  for(const prior of old.original_paths_used){
    const oldRow=oldRows.get(prior.path);
    check("prior.tree_pin:"+prior.path,!!oldRow&&oldRow.sha===prior.blob&&oldRow.size===prior.bytes);
    const now=pins[prior.path];
    if(aggregatePaths.has(prior.path)){
      check("prior.aggregate_successor:"+prior.path,!!now&&now.blob!==prior.blob);
      aggregateChanges.push({path:prior.path,old_blob:prior.blob,new_blob:now.blob,old_tree_retained:oldRoot});
    }else{
      check("prior.original_unchanged:"+prior.path,!!now&&now.blob===prior.blob&&now.bytes===prior.bytes&&now.sha256===prior.sha256);
      oldOriginalPaths.push(prior.path);
    }
  }
  check("prior.112_unchanged_3_summaries",oldOriginalPaths.length===112&&aggregateChanges.length===3);
  const state=json("STATE.public.json"),plan=json(planPath),representations=json("actual/65-file-content-representations.public.json");
  check("plan.original_pin",pins[planPath].blob==="593b26c016e9410c09e2622665f0dc34765e4353"&&pins[planPath].bytes===62424&&pins[planPath].sha256==="6766f34c76e43725147e2d7f410c102c5a2e0dc5629ff1ef51295205fd1c84a4");
  check("plan.63_2_5",plan.small_files.length===63&&plan.large_files.length===2&&plan.small_batches.length===5&&plan.total_files===65);
  check("plan.original_job",plan.job_id===job&&state.job_id===job);
  check("representations.scope",representations.original_plan_tree==="bc3ac1786389aa597cdd980d2fd5bff5b7ef66e8"&&representations.native_small_file_reads===63&&representations.canonical_reconstructed_large_representations===2&&representations.entries.length===65&&representations.current_host_large_body_RPC_count===0);
  const representationMap=new Map(representations.entries.map(x=>[x.path,x])),planMap=new Map(plan.small_files.map(x=>[x.path,x]));
  check("representations.unique_paths",representationMap.size===65&&planMap.size===63);
  const ids=new Set(),keys=new Set();
  for(const prev of old.returned_observers){
    const current=state.observers.find(x=>x.name===prev.name);
    const prevStatus=json(prev.status_sdk_path);
    const status=JSON.parse(oneText(prevStatus,prev.name+".already_verified_status"));
    const req=json(prev.exact_request_path);
    check("prior.state_exact_request:"+prev.name,equal(current.request,req));
    check("prior.state_exact_status:"+prev.name,equal(current.closed_status,status));
    check("prior.state_identity:"+prev.name,current.operation_id===prev.operation_id&&current.complete===true);
    check("prior.state_pages:"+prev.name,equal(current.pages.map(x=>({offset:x.offset,bytes:x.bytes})),prev.pages.map(x=>({offset:x.offset,bytes:x.bytes}))));
    ids.add(prev.operation_id);keys.add(req.idempotency_key);
    observers.push({name:prev.name,operation_id:prev.operation_id,pages:prev.pages.length,verification_basis:"PRIOR_CORE115_RESULT_AND_UNCHANGED_ORIGINALS",complete:true});
  }
  check("prior.old_tail_preserved",state.first_tail_admission_without_ACK==="UNKNOWN_PRESERVED"&&state.reconciliation_reused===false&&old.preserved_errors.first_streams1_future==="UNKNOWN_PRESERVED"&&old.preserved_errors.returned_reconciliation_reused===false);
  const specs=[
    ["commandlogs1","920f6a80051c19da978c785219e0ea603f41e3b2f15411e707e44156d7019859",15,53447,7],
    ["commandlogs2","03c5b38ed78e5f813bc7a19d400c0192ec7bda138be682ee2e822722d70c13c0",15,12150,2],
    ["commandlogs3","73b13cbbe33cf212fe58efb35a0c7e84e5155518c01d3b3793bb7aea5384d08f",15,12260,2],
    ["commandlogs4","9af4422fa6f71fa03e6ce3bffb73910c23d09f4ac6bd2f00a79e515a038fac5d",15,12099,2],
    ["commandlogs5","e089f4ebc2efeb150f7fd80efaefe8af43701be8a0ba28c78785b17fb9eb6fd8",3,2686,1]
  ];
  const seenFiles=new Set();let newPages=0;let originalSmallBytes=0;
  for(let i=0;i<specs.length;i++){
    const [name,expectedId,count,total,pageCount]=specs[i],p="observers/"+name+"/";
    const requestPath=p+"intent/exact-operation-start-request.public.json",request=json(requestPath);
    const intentPath=p+"intent/read-intent.public.json",intent=json(intentPath),batch=plan.small_batches[i],args=request.operation.arguments;
    check(name+".exact_start_bytes",raw(p+"start/request.json")===raw(requestPath));
    check(name+".intent_exact_request",equal(intent.request,request)&&intent.observation===name&&intent.job_id===job&&intent.one_native_future===true&&intent.product_replay===false);
    check(name+".original_GO",intent.root_GO.blob==="f1fcb91c33a38ba8074281c300f8f3c7b8f1534e");
    check(name+".batch_exact",batch.name===name&&batch.tool==="read_multiple_files"&&request.operation.tool===batch.tool&&equal(args,batch.args));
    check(name+".fixed_caps",args.host===host&&args.paths.length===count&&args.max_file_bytes===65536&&args.max_response_bytes===131072);
    check(name+".fixed_key",request.idempotency_key==="ha-4e808-source-import-commandlogs-"+String(i+1).padStart(2,"0")+"-r1-20261105"&&!keys.has(request.idempotency_key));keys.add(request.idempotency_key);
    const ackPath=i===2?"recovery/smallbatch3/ACK/original-sdk.json":p+"start/original-sdk.json";
    const ack=sdk(ackPath),id=ack.operation_id;
    check(name+".ACK_exact_id",id===expectedId&&!ids.has(id)&&ack.tool_name==="read_multiple_files");ids.add(id);
    check(name+".ACK_reuse",ack.reused===(i===2)&&ack.idempotency_binding_retained===true&&ack.admission_is_not_dispatch_completion===true&&ack.delivery_proven===false);
    const statusRequestPath=p+"status-0/request.json",statusPath=p+"status-0/original-sdk.json";
    const statusReq=json(statusRequestPath),status=sdk(statusPath);
    check(name+".same_status_id",equal(statusReq,{operation_id:id})&&status.operation_id===id&&status.tool_name==="read_multiple_files");
    check(name+".closed_status",status.async_state==="completed"&&status.result_state==="stored_observed"&&status.owned_future_active===false&&status.payload_available===true);
    const current=state.observers.find(x=>x.name===name);
    check(name+".state_matches",!!current&&current.complete===true&&current.operation_id===id&&equal(current.request,request)&&equal(current.closed_status,status)&&current.original_admission_error===(i===2));
    const pagePaths=Object.keys(files).filter(x=>x.startsWith(p+"result-")&&x.endsWith("/original-sdk.json")).sort((a,b)=>Number(a.slice((p+"result-").length).split("/")[0])-Number(b.slice((p+"result-").length).split("/")[0]));
    check(name+".exact_page_count",pagePaths.length===pageCount);
    let binary="",digest=null;const pages=[];
    for(let j=0;j<pagePaths.length;j++){
      const sdkPath=pagePaths[j],offset=j*8192,page=sdk(sdkPath),pageRequestPath=sdkPath.replace("original-sdk.json","request.json"),pageReq=json(pageRequestPath);
      check(name+".page_request:"+offset,equal(pageReq,{operation_id:id,offset,limit:8192}));
      check(name+".page_identity:"+offset,page.operation_id===id&&page.offset===offset&&page.total_bytes===total&&page.immutable_snapshot===true&&page.payload_kind==="native_result"&&page.format==="serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization");
      if(digest===null)digest=page.result_sha256;
      check(name+".page_digest_consistent:"+offset,page.result_sha256===digest&&/^[0-9a-f]{64}$/.test(digest));
      const chunk=base64(page.data_base64),expectedBytes=Math.min(8192,total-offset);
      check(name+".page_bounds:"+offset,chunk.length===expectedBytes&&page.next_offset===offset+chunk.length&&page.eof===(j===pagePaths.length-1)&&binary.length===offset);
      binary+=chunk;pages.push({offset,bytes:chunk.length,request_path:pageRequestPath,sdk_path:sdkPath});newPages++;
    }
    const payloadPath=p+"original-payload.json",nativePath=p+"native-result.public.json";
    check(name+".whole_payload",binary.length===total&&sha256(binary)===digest&&binary===utf8(raw(payloadPath)));
    const payload=JSON.parse(text(binary));
    check(name+".original_payload_not_error",payload.resultType==="complete"&&payload.isError===false);
    check(name+".native_exact",oneText(payload,name+".payload")===raw(nativePath));
    const native=JSON.parse(raw(nativePath));
    check(name+".native_independent_scope",native.atomic_snapshot===false&&native.snapshot_scope==="independent_file"&&native.encoding==="utf-8"&&native.truncated===false&&Array.isArray(native.files)&&native.files.length===count);
    check(name+".native_exact_paths",equal(native.files.map(x=>x.path),args.paths));
    check(name+".state_exact_pages",equal(current.pages.map(x=>({offset:x.offset,bytes:x.bytes})),pages.map(x=>({offset:x.offset,bytes:x.bytes}))));
    let nativeContentBytes=0;
    for(const file of native.files){
      check(name+".file_not_duplicate:"+file.path,!seenFiles.has(file.path)&&planMap.has(file.path));seenFiles.add(file.path);
      const bytes=utf8(file.text),declared=planMap.get(file.path),mapped=representationMap.get(file.path);
      check(name+".file_EOF_and_bound:"+file.path,file.eof===true&&typeof file.text==="string"&&file.size===bytes.length&&file.size<=args.max_file_bytes);
      check(name+".file_digest:"+file.path,sha256(bytes)===file.sha256&&file.size===declared.bytes&&file.sha256===declared.sha256);
      check(name+".file_version:"+file.path,typeof file.version==="string"&&/^\d+:\d+:\d+:\d+:\d+$/.test(file.version)&&Number(file.version.split(":")[2])===file.size);
      check(name+".extraction_scope:"+file.path,!!mapped&&mapped.content_origin==="ACTUAL_NATIVE_READ_MULTIPLE_FILES_WHOLE"&&mapped.original_observation===name&&mapped.operation_id===id&&mapped.snapshot_scope==="independent_file"&&mapped.atomic_snapshot===false);
      check(name+".extraction_metadata:"+file.path,mapped.bytes===file.size&&mapped.sha256===file.sha256&&mapped.version===file.version&&mapped.kind===declared.kind);
      const artifact="actual/original-fixed-files/"+file.path.slice(file.path.lastIndexOf("/")+1),pin=pins[artifact];
      check(name+".extraction_whole:"+file.path,mapped.artifact===artifact&&!!pin&&mapped.content_blob===pin.blob&&pin.bytes===file.size&&pin.sha256===file.sha256&&raw(artifact)===file.text);
      extracted.push({path:file.path,artifact,content_blob:pin.blob,bytes:pin.bytes,sha256:pin.sha256,version:file.version,observer:name,operation_id:id,native_path:nativePath});
      nativeContentBytes+=bytes.length;originalSmallBytes+=bytes.length;
    }
    check(name+".response_cap",nativeContentBytes<=args.max_response_bytes&&pins[nativePath].bytes<=args.max_response_bytes);
    observers.push({name,operation_id:id,verification_basis:"NEW_RAW_CHAIN_VERIFIED",request_path:requestPath,intent_path:intentPath,ack_path:ackPath,status_path:statusPath,status_request_path:statusRequestPath,pages:pageCount,page_records:pages,payload_path:payloadPath,payload_bytes:total,payload_sha256:digest,native_path:nativePath,native_sha256:pins[nativePath].sha256,native_bytes:pins[nativePath].bytes,complete:true,reused:ack.reused,files:count});
  }
  check("new.5_chains_14_pages_63files",newPages===14&&seenFiles.size===63&&extracted.length===63);
  check("new.63_plan_order",equal(extracted.map(x=>x.path),plan.small_files.map(x=>x.path)));
  check("new.exact63_artifacts",equal(Object.keys(files).filter(x=>x.startsWith("actual/original-fixed-files/")).sort(),extracted.map(x=>x.artifact).sort()));
  const recoveryGOPath="recovery/smallbatch3/intent/root-GO.public.json",recoveryIntentPath="recovery/smallbatch3/intent/reconciliation-intent.public.json";
  const recoveryGO=json(recoveryGOPath),recoveryIntent=json(recoveryIntentPath),thirdRequest=json("observers/commandlogs3/intent/exact-operation-start-request.public.json");
  check("recovery.exact_root_GO",pins[recoveryGOPath].blob==="8854ac7521bd01af93fda983e84e933d6d56c118"&&pins[recoveryGOPath].sha256==="d6196120c97cfd478be71a3d0ba26f4519e51150bda35c9938c98a2488484622");
  check("recovery.intent_GO_pin",recoveryIntent.root_GO.blob===pins[recoveryGOPath].blob&&recoveryIntent.root_GO.bytes===pins[recoveryGOPath].bytes&&recoveryIntent.root_GO.sha256===pins[recoveryGOPath].sha256);
  check("recovery.exact_original_request",equal(recoveryGO.exact_original_request,thirdRequest)&&equal(recoveryIntent.request,thirdRequest));
  check("recovery.exact_ACK_request",raw("recovery/smallbatch3/ACK/request.json")===raw("observers/commandlogs3/start/request.json")&&raw("recovery/smallbatch3/intent/exact-operation-start-request.public.json")===raw("observers/commandlogs3/start/request.json"));
  check("recovery.bounds",recoveryIntent.maximum_new_submissions===1&&recoveryIntent.process_start===false&&recoveryIntent.product_replay===false&&recoveryIntent.reused_false_does_not_close_original_future===true&&recoveryIntent.SDK_external_before_isError_or_parse===true);
  const thirdError=timeout("observers/commandlogs3/start/original-sdk.json","operation_start");
  check("recovery.state_reused_true",state.first_smallbatch3_admission_without_ACK==="ORIGINAL_LOST_ACK_ERROR_PRESERVED"&&state.smallbatch3_reconciliation.reused===true&&state.smallbatch3_reconciliation.returned_operation_id===specs[2][1]&&state.smallbatch3_reconciliation.returned_ID_closed_full===true&&state.smallbatch3_reconciliation.prior_SDK_error_unchanged===true);
  check("recovery.shared_error_not_shared_operation",thirdError.blob===old.preserved_errors.first_streams1_admission.blob&&thirdRequest.idempotency_key!==json("observers/streams1/intent/exact-operation-start-request.public.json").idempotency_key&&state.reconciliation_reused===false);
  const infoPin=externalPin("root-current-NUL-info",currentNulInfoReviewRaw,{blob:"f78b31c2d625c00256e92cfea22f923ab42aeb09",bytes:4652,sha256:"3817cf9a2fe108484c638e1b022c808be33d0c67ecf70eda23126a833d26f4c2"});
  const reconstructionPin=externalPin("root-NUL-reconstruction",nulReconstructionReviewRaw,{blob:"9bfb8c03027d17a8b87838a5b7c4fffba3df65bf",bytes:1646,sha256:"38d75597f4ca4a0d7e1c36a66e83c45d20fc3712e5695b4f8e65f0b1dcfdde1e"});
  const infoBasis=JSON.parse(currentNulInfoReviewRaw),reconstructionBasis=JSON.parse(nulReconstructionReviewRaw),reusePath="content-addressed-reuse/root-reuse-GO.public.json",reuse=json(reusePath);
  check("reuse.exact_GO",pins[reusePath].blob==="f7eda3b5696e478342b58999871788d009fef97a"&&representations.root_reuse_GO===pins[reusePath].blob);
  check("reuse.basis_pins",reuse.independent_current_metadata_root_review.blob===infoPin.blob&&reuse.independent_current_metadata_root_review.sha256===infoPin.sha256&&reuse.independent_reconstruction_root_review.blob===reconstructionPin.blob&&reuse.independent_reconstruction_root_review.sha256===reconstructionPin.sha256);
  check("reuse.prior_34_info_checks",infoBasis.status==="PASS_CURRENT_WHOLE_HASH_AND_RECONSTRUCTED_CONTENT_IDENTITY"&&infoBasis.checks_passed===34&&infoBasis.original_info_operations_closed===2&&infoBasis.original_immutable_pages===2&&infoBasis.original_native_large_body_requests_submitted===0);
  check("reuse.canonical_basis",reconstructionBasis.canonical_tree==="eba5e650bd080b8ad41ea52a2bc68867f541d255"&&reconstructionBasis.canonical_leaves===3914&&reconstructionBasis.current_host_body_read===false);
  check("reuse.GO_provenance",reuse.authorized_delta.replace_only_14_unsubmitted_large_body_transport_requests===true&&reuse.mandatory_provenance.current_host_large_body_RPC_count===0&&reuse.mandatory_provenance.claim_current_native_body_retrieval===false);
  const reusedContents=[];
  for(let i=0;i<2;i++){
    const name="inventory"+i+"_info",p="observers/"+name+"/",basis=infoBasis.files[i],g= reuse.files[i],mapped=representationMap.get(basis.path),prior=reconstructionBasis.matches[i],current=state.observers.find(x=>x.name===name);
    check(name+".root_basis_exact",equal(basis,g)&&mapped.path===plan.large_files[i].path);
    const request=json(p+"intent/exact-operation-start-request.public.json"),currentInfoPath=p+"native-result.public.json";
    const info=json(currentInfoPath),status=sdk(p+"status-0/original-sdk.json");
    check(name+".info_only_scope",request.operation.tool==="file_info"&&request.operation.arguments.host===host&&request.operation.arguments.path===basis.path);
    check(name+".info_PIN",pins[currentInfoPath].blob===basis.current_info_blob&&pins["content-addressed-reuse/actual-info/inventory"+i+".json"].blob===basis.current_info_blob);
    check(name+".prior_closed_binding",current.operation_id===basis.current_info_operation&&current.complete===true&&equal(current.request,request)&&equal(current.closed_status,status)&&status.operation_id===basis.current_info_operation&&status.async_state==="completed"&&status.result_state==="stored_observed"&&status.owned_future_active===false&&current.pages.length===1);
    check(name+".no_duplicate",!ids.has(current.operation_id)&&!keys.has(request.idempotency_key));ids.add(current.operation_id);keys.add(request.idempotency_key);
    const entryPin=pins[mapped.artifact];
    check(name+".canonical_content_exact",mapped.content_origin==="CANONICAL_GIT_TREE_RECONSTRUCTION_BOUND_TO_CURRENT_NATIVE_FULL_FILE_SHA"&&mapped.content_blob===basis.reconstructed_content_blob&&entryPin.blob===mapped.content_blob&&entryPin.bytes===basis.bytes&&entryPin.sha256===basis.sha256&&prior.blob===entryPin.blob&&prior.bytes===entryPin.bytes&&prior.sha256===entryPin.sha256);
    check(name+".current_info_reference",mapped.current_file_info_operation===basis.current_info_operation&&mapped.current_file_info_blob===basis.current_info_blob&&mapped.version===basis.version&&equal(mapped.full9_decimal,basis.full9_decimal)&&mapped.root_reuse_GO===pins[reusePath].blob);
    check(name+".zero_body_RPC",mapped.current_host_body_RPC_count===0&&mapped.replaced_unsubmitted_body_slots===7&&!seenFiles.has(basis.path)&&!extracted.some(x=>x.path===basis.path));
    observers.push({name,operation_id:current.operation_id,pages:1,complete:true,verification_basis:"PRIOR_ROOT_34_INFO_CHECKS_PLUS_EXACT_CURRENT_INFO_PIN",root_review:infoPin.blob,native_path:currentInfoPath,native_blob:basis.current_info_blob});
    reusedContents.push({path:basis.path,artifact:mapped.artifact,blob:entryPin.blob,bytes:entryPin.bytes,sha256:entryPin.sha256,version:basis.version,current_info_operation:basis.current_info_operation,current_info_blob:basis.current_info_blob,content_origin:mapped.content_origin,current_host_body_RPC_count:0});
  }
  check("overall.12_returned_36_pages",observers.length===12&&ids.size===12&&keys.size===12&&observers.reduce((n,x)=>n+x.pages,0)===36&&state.returned_observer_count===12&&state.returned_observers_closed_full===true);
  check("overall.exact_observer_names",equal(state.observers.map(x=>x.name).sort(),observers.map(x=>x.name).sort()));
  const allPagePaths=Object.keys(files).filter(x=>/^observers\/[^/]+\/result-\d+\/original-sdk\.json$/.test(x));
  check("overall.base36_page_paths_including_preserved_core_info_error",allPagePaths.length===36);
  check("overall.qualification_not_granted",state.full_source_import_qualification===false&&state.root_actual_review_pending===true&&state.current_host_large_body_RPC_count===0&&state.native_small_file_reads_complete===63&&state.tool_calls_inflight===0);
  const groups={};for(const x of checks){const prefix=x.id.split(/[.:]/)[0];groups[prefix]=(groups[prefix]||0)+1;}
  return {
    schema:"heptabao.authbus.peer.importer-full289-incremental-raw-chain.v1",status:"PASS_FINITE_INCREMENTAL_ORIGINAL_CHAIN",
    packet_tree:packetTree,files:289,bytes:2556370,Merkle_trees:110,
    executed_pure_predicate_checks:checks.length,failed:0,check_groups:groups,
    prior_basis:{core115_tree:oldRoot,core115_result:priorPin,root_current_NUL_info_review:infoPin,root_NUL_reconstruction_review:reconstructionPin,old_chain_checks_rerun:false,NUL_34_checks_rerun:false},
    retained_old_original_paths:oldOriginalPaths.length,aggregate_successors:aggregateChanges,old_aggregate_blobs_remain_in_old_immutable_tree:true,
    returned_observers:observers,returned_observer_count:12,complete_immutable_pages:36,new_batches:5,new_raw_chain_pages:14,
    extracted_native_small_files:extracted,native_small_file_count:extracted.length,native_small_content_bytes:originalSmallBytes,
    reused_large_contents:reusedContents,current_host_large_body_RPC_count:0,
    preserved_errors:{old_tail_original_future:"UNKNOWN_PRESERVED",old_tail_returned_reconciliation_reused:false,old_core_info_page_error_unchanged:true,smallbatch3_original_start_error:thirdError,smallbatch3_reconciliation_reused:true,smallbatch3_returned_ID_closed:true,same_generic_error_blob_is_not_event_identity:true},
    source_import_qualified:false,semantic_core_or_21_command_audit_performed:false,candidate_executed:false,runtime_calls:0,SDK_executions:0,
    chronology_limit:"Exact stored intents, requests and SDK links are verified; archive bytes alone are not independent wall-clock evidence of save-before-call ordering.",
    original_paths_used:[...used].sort()
  };
}
