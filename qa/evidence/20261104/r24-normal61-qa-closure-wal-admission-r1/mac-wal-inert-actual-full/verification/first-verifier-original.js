function verifyMacInertActual(files, byteSha, gitSha, decodeBase64) {
  const checks=[];
  function need(name,value){if(!value)throw new Error(name);checks.push({case:name,passed:true});}
  function binary(raw){return unescape(encodeURIComponent(raw));}
  function pin(raw){const b=binary(raw);return {bytes:b.length,sha256:byteSha(b),blob:gitSha("blob "+b.length+"\0"+b)};}
  function json(path){return JSON.parse(files[path]);}
  function paired(stem){
    const sdk=json(stem+".sdk-snapshot.json"),raw=files[stem+".native.json"];
    const texts=(sdk.content??[]).filter(x=>x.type==="text");
    need("sdk_native_exact."+stem,sdk.isError!==true&&texts.length===1&&texts[0].text===raw);
    return JSON.parse(raw);
  }
  function topTokens(raw){
    JSON.parse(raw);
    let i=0;
    const white=()=>{while(/\s/.test(raw[i]??"")&&i<raw.length)i++;};
    function stringEnd(at){let j=at+1;for(;j<raw.length;j++){if(raw[j]==="\\"){j++;continue;}if(raw[j]==='"')return j+1;}throw new Error("token_string");}
    white();if(raw[i++]!=="{")throw new Error("token_object");
    const result={};
    while(true){
      white();if(raw[i]==="}"){i++;break;}
      if(raw[i]!=='"')throw new Error("token_key");
      const end=stringEnd(i),key=JSON.parse(raw.slice(i,end));i=end;white();
      if(raw[i++]!==":")throw new Error("token_colon");white();
      const start=i;
      if(raw[i]==='"')i=stringEnd(i);
      else if(raw[i]==="{"||raw[i]==="["){
        const stack=[raw[i++]];
        while(stack.length){
          if(i>=raw.length)throw new Error("token_nesting");
          const ch=raw[i];
          if(ch==='"'){i=stringEnd(i);continue;}
          if(ch==="{"||ch==="[")stack.push(ch);
          else if(ch==="}"||ch==="]"){
            const open=stack.pop();if((open==="{"&&ch!=="}")||(open==="["&&ch!=="]"))throw new Error("token_pair");
          }
          i++;
        }
      } else while(i<raw.length&&raw[i]!==","&&raw[i]!=="}")i++;
      if(Object.prototype.hasOwnProperty.call(result,key))throw new Error("duplicate_key");
      result[key]=raw.slice(start,i).trimEnd();white();
      if(raw[i]===","){i++;continue;}if(raw[i]==="}"){i++;break;}throw new Error("token_separator");
    }
    white();if(i!==raw.length)throw new Error("token_trailing");return result;
  }
  const go=json("root-go.original.public.json"),request=json("request.original.public.json"),intent=json("intent.public.json");
  const ack=paired("actual/start"),authority=paired("actual/authority"),page=paired("actual/read-00000");
  const report=json("actual/stdout.original.json"),anchor=json("references/t5-anchor.original.json");
  const requestPin=pin(files["request.original.public.json"]);
  need("root_exact_one_inert_go",go.decision==="GO_ONE_EXACT_INERT_STAGE_ONLY"&&go.maximum_submissions===1&&go.future_runtime_go===false&&go.production_cutover_go===false);
  need("exact_go_request_full_bytes",JSON.stringify(requestPin)===JSON.stringify({bytes:go.exact_request.bytes,sha256:go.exact_request.sha256,blob:go.exact_request.blob}));
  need("external_intent_exact_request",intent.exactRequest.blob===requestPin.blob&&intent.exactRequest.sha256===requestPin.sha256&&intent.exactRequest.bytes===requestPin.bytes&&intent.maximumSubmissions===1&&intent.submittedAtIntentPublication===false);
  need("fixed_job",ack.job.id==="1a1ab9595af-fc05-4ec7"&&authority.job_id===ack.job.id&&page.job_id===ack.job.id);
  need("typed_original_request_ack",ack.job.host===request.host&&request.host==="mac"&&ack.job.executable===request.executable&&request.executable==="/opt/homebrew/bin/python3"&&ack.job.cwd===request.cwd&&request.cwd==="/Users/qianqi"&&JSON.stringify(ack.job.args)===JSON.stringify(request.args));
  need("one_fresh_key_ack",ack.reused===false&&ack.launch.ok===true&&ack.job.launch_state==="launched"&&ack.job.launch_error===null&&ack.job.idempotency_key===request.idempotency_key&&request.idempotency_key===go.idempotency_key);
  need("original_supervisor60",request.timeout_seconds===60&&go.allowed_scope.supervisor_seconds===60);
  need("known_complete_durable_exit0",authority.exit_code===0&&authority.state==="succeeded"&&authority.output_complete===true&&authority.output_durable===true&&authority.terminal_publication_confirmed===true&&authority.timed_out===false&&authority.cancelled===false&&authority.automatic_retry===false);
  for(const streamName of["stdout","stderr"]){
    const s=page[streamName],raw=files["actual/"+streamName+(streamName==="stdout"?".original.json":".original.txt")];
    const bytes=s.bytes_hex.match(/../g)?.map(v=>String.fromCharCode(parseInt(v,16))).join("")??"";
    need("full_stream_original."+streamName,s.offset===0&&s.next_offset===s.size&&s.eof===true&&bytes.length===s.size&&decodeURIComponent(escape(bytes))===s.text&&s.text===raw);
    need("authority_full_stream."+streamName,authority.log_bytes[streamName].seen===bytes.length&&authority.log_bytes[streamName].stored===bytes.length&&authority.log_synced[streamName]===true&&authority.log_truncated[streamName]===false&&authority.log_errors[streamName]===null);
  }
  need("empty_stderr",files["actual/stderr.original.txt"]==="");
  need("final_report_success",report.ok===true&&report.outcomeUnknown===false&&report.preparedCandidate===true&&report.authoritativeExitZeroRequired===true);
  need("original45_after_all_closure",report.newOriginalInertSeconds===45&&report.originalDeadlineMetAfterClosure===true&&report.elapsedSeconds>=0&&report.elapsedSeconds<45);
  need("t5_original27_strings",JSON.stringify(report.heldT5Final.anchors)===JSON.stringify(anchor.anchors)&&report.heldT5Final.expectedVolumeDevice===anchor.expectedVolumeDevice&&anchor.expectedVolumeDevice==="16777244"&&report.heldT5Final.volumeUUIDVerified===true&&report.heldT5Final.lastAnchorCheckPassed===true);
  need("all_t5_descriptors_closed",report.heldT5Final.allDescriptorsClosed===true&&report.heldT5Final.closeErrors.length===0&&report.allOwnedDescriptorsClosed===true);
  need("only_fixed_diskutil_owned",report.commands.commands.length===1&&report.commands.unknownCommandCount===0&&report.commands.allOwnedCommandsStopped===true&&report.allOwnedCommandsStopped===true);
  const command=report.commands.commands[0],cleanup=command.cleanup;
  need("diskutil_exact_argv_natural0",JSON.stringify(command.argv)===JSON.stringify(["/usr/sbin/diskutil","info","-plist","/Volumes/T5"])&&command.exitCode===0&&command.errorType===null&&command.errorCode===null&&command.completeBeforeDeadline===true&&command.elapsedSeconds<30&&command.outcomeUnknown===false);
  need("diskutil_cleanup_all_closed",command.streamsClosed===true&&cleanup.ok===true&&cleanup.directChildReaped===true&&cleanup.exitCode===0&&cleanup.outcomeUnknown===false&&cleanup.ownedLiveGroupEmptyBeforeReap===true&&cleanup.allGroupRowsEmptyAfterReap===true&&cleanup.remainingGroupRows.length===0&&cleanup.postReapSignalSent===false);
  need("original_child_cleanup_caps",JSON.stringify(cleanup.cleanupCaps)===JSON.stringify({group:3,psMax:4,term:1,wait:5}));
  for(const name of["currentPrivateInputsOpened","productionSqliteOpened","sqliteExecuted","consumerExecuted","serviceStarted","gitStarted","cargoStarted","inputEntrypointsExecuted"])
    need("no_side_effect."+name,report[name]===false);
  need("22source_8document_18compile",report.sourceCount===22&&report.publicDocumentCount===8&&report.files.length===30&&report.compiledSources.length===18&&report.byteVerifiedJavascriptSources.length===4&&report.compiledPythonCountExpected===18);
  need("only_three_definition_libraries",JSON.stringify(report.loadedLibraryDefinitions)===JSON.stringify(["mac_owned_unreaped_r1.py","mac_owned_commands_r1.py","mac_t5_volume_guard_r1.py"])&&report.fixedLibraryDefinitionsLoadedOnly===true);
  const root=go.allowed_scope.root,payload=JSON.parse(request.stdin),expected={};
  need("actual_input_exact",pin(request.stdin).sha256===go.stdin.sha256&&pin(request.stdin).bytes===go.stdin.bytes&&report.inputBytes===go.stdin.bytes&&report.inputSha256===go.stdin.sha256);
  need("fresh_only_root_paths",report.createdRoot===root&&report.createdQa===root+"/qa"&&report.createdProofs===root+"/proofs"&&report.freshRootAbsence.path===root&&JSON.stringify(report.freshRootAbsence.twoEnoentObservations)===JSON.stringify([true,true]));
  need("actual_parent_full9_strings",report.freshRootAbsence.heldParentIdentity.length===9&&report.freshRootAbsence.heldParentIdentity.every(x=>typeof x==="string"));
  for(const[name,b64]of Object.entries(payload.files))expected["qa/"+name]=decodeBase64(b64);
  for(const[name,b64]of Object.entries(payload.documents))expected[name]=decodeBase64(b64);
  need("fixed30_public_payload",Object.keys(expected).length===30);
  const records=[...report.files,report.candidateReceipt],bodyRows=[];
  need("unique31_fixed_published_names",records.length===31&&new Set(records.map(x=>x.name)).size===31&&report.candidateReceipt.name==="inert-registry-wal-4e808-result.public.json");
  let chunks=0,pairs=3,wholeBytes=0;
  for(let i=0;i<records.length;i++){
    const row=records[i],ordinal=i+1,prefix="independent/"+String(ordinal).padStart(2,"0")+"/";
    const info=paired(prefix+"file-info");pairs++;
    const id=row.identity;
    need("actual_full9_strings."+ordinal,id.length===9&&id.every(v=>typeof v==="string"&&/^[0-9]+$/.test(v)));
    need("held_file_expected_custody."+ordinal,id[2]==="501"&&id[3]==="20"&&id[4]==="33152"&&id[5]==="1"&&Number(id[6])===row.bytes&&row.wholeReadbackVerified===true&&row.readbackUsesSeparateHeldFd===true);
    const version=[id[0],id[1],id[6],id[7],id[8]].join(":");
    need("independent_info_exact."+ordinal,info.path===root+"/"+row.name&&info.size===row.bytes&&info.sha256===row.sha256&&info.version===version&&info.mode===384&&info.metadata.mode===384&&info.metadata.uid===501&&info.metadata.gid===20&&info.metadata.link_count===1);
    let offset=0,whole="";
    const offsets=[];
    while(true){
      const stem=prefix+"read-"+String(offset).padStart(5,"0"),chunk=paired(stem);pairs++;chunks++;
      const binaryChunk=decodeBase64(chunk.data_base64);
      need("pinned_chunk_exact."+ordinal+"."+offset,chunk.offset===offset&&chunk.path===info.path&&chunk.version===version&&chunk.size===row.bytes&&binaryChunk.length<=65536&&chunk.next_offset===offset+binaryChunk.length&&chunk.next_offset<=row.bytes&&chunk.chunk_sha256===byteSha(binaryChunk)&&chunk.eof===(chunk.next_offset===row.bytes));
      offsets.push(offset);whole+=binaryChunk;offset=chunk.next_offset;
      if(chunk.eof)break;
      need("progress_no_retry."+ordinal+"."+offset,binaryChunk.length>0&&offset<row.bytes);
    }
    const raw=files[prefix+"body.original.txt"];
    need("full_independent_body."+ordinal,whole.length===row.bytes&&byteSha(whole)===row.sha256&&decodeURIComponent(escape(whole))===raw);
    if(i<30)need("original_frozen_public_bytes."+ordinal,whole===expected[row.name]);
    wholeBytes+=whole.length;
    bodyRows.push({ordinal,name:row.name,...pin(raw),version,chunkOffsets:offsets});
  }
  const candidateRaw=files["independent/31/body.original.txt"],candidate=JSON.parse(candidateRaw);
  need("candidate_receipt_hash_bound",pin(candidateRaw).sha256===report.candidateReceiptSha256&&pin(candidateRaw).sha256===report.candidateReceipt.sha256);
  need("candidate_is_preclosure_not_success",candidate.ok===false&&candidate.preparedCandidate===true&&report.ok===true&&candidate.candidateFileAloneIsNotQualification===true&&candidate.files.length===30);
  const early=topTokens(candidateRaw),final=topTokens(files["actual/stdout.original.json"]);
  for(const[key,value]of Object.entries(early))need("candidate_raw_token."+key,key==="ok"?value==="false"&&final[key]==="true":value===final[key]);
  need("complete31_independent_32chunks_66pairs",bodyRows.length===31&&chunks===32&&pairs===66&&wholeBytes===596491);
  return {schema:"heptabao.mac-current-registry-wal-4e808-inert-actual-review.r1",ok:true,qualification:"PASS_INERT_ONLY_INDEPENDENT_READBACK_COMPLETE",
    originalJob:ack.job.id,checkCount:checks.length,checks,exactMcpNativePairs:pairs,independentFileInfoCount:31,
    independentWholeBodyCount:31,binaryChunks:chunks,totalIndependentWholeBytes:wholeBytes,
    elapsedSeconds:report.elapsedSeconds,candidatePreclosureKeys:Object.keys(early).length,
    originalAuthority:pin(files["actual/authority.native.json"]),originalStdout:pin(files["actual/stdout.original.json"]),
    candidateReceipt:pin(candidateRaw),bodies:bodyRows,verifiedIntegerPolicy:"Full identity fields and file versions compared as original decimal strings; candidate shared values compared as original JSON tokens. All original raw bodies retained.",
    noPublisherReplay:true,noFutureRuntimeSubmission:true,noCurrentPrivateCapture:true,noProductionCutover:true};
}
