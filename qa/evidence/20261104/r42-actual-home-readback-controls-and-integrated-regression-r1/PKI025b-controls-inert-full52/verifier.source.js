function verify025bControlsInertActual(files){
 const checks=[],eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 function ck(ok,name){checks.push({name,pass:!!ok});if(!ok)throw Error(name);}
 const rows=JSON.parse(files["CALL-INDEX.public.json"]),s=JSON.parse(files["STATE.public.json"]),g=JSON.parse(files["GO.original.json"]),pins=JSON.parse(files["EXPECTED-PINS.public.json"]);
 ck(rows.length===7&&rows.map(x=>x.kind).join(",")==="process_start,operation_start,operation_status,operation_result,operation_start,operation_status,operation_result","one_start_six_original_observer_calls");
 const calls=[];
 for(const row of rows){const pre=row.key+"--",qraw=files[pre+"request.json"],sdkRaw=files[pre+"sdk.original.json"],sdk=JSON.parse(sdkRaw);
  ck(eq(gitBlobMeta(qraw),row.request),row.key+":exact_request");
  ck(eq(gitBlobMeta(sdkRaw),row.sdk)&&row.sdkWhole===true&&row.phase==="accepted"&&row.called===true,row.key+":whole_SDK_before_accept");
  ck(sdk.isError!==true&&sdk.content?.length===1&&sdk.content[0].type==="text",row.key+":original_SDK_success");
  ck(sdk.content[0].text===files[pre+"native.original.json"]&&eq(gitBlobMeta(sdk.content[0].text),row.native),row.key+":native_byte_exact");
  const intent=JSON.parse(files[pre+"intent.json"]),arm=JSON.parse(files[pre+"armed.json"]);
  ck(row.armWhole===true&&intent.maximumNativeCalls===1&&intent.nativeNotYetCalled===true&&eq(intent.request,row.request)&&eq(arm.request,row.request)&&arm.mayHaveDispatchedAfterThisCheckpoint===true,row.key+":one_completed_external_arm");
  ck(eq(intent.rootGo,gitBlobMeta(files["GO.original.json"])),row.key+":exact_inert_GO");
  calls.push({q:JSON.parse(qraw),v:parseLosslessIntegers(sdk.content[0].text)});
 }
 const initial=calls[0],binding=processStartBinding(initial.q),fp=x=>Number.isSafeInteger(x)?String(x):x.$exactInteger;
 ck(eq(rows[0].request,g.exactRequest)&&initial.q.host==="rog"&&initial.q.timeout_seconds===60&&initial.q.idempotency_key===g.idempotencyKey,"exact_original_inert_request");
 ck(initial.q.args[4]===files["publisher.source.original.py"]&&eq(gitBlobMeta(initial.q.args[4]),g.source)&&eq(gitBlobMeta(initial.q.stdin),g.payload),"inline_source_and_carrier_identity");
 ck(binding.sha256===g.typedRequestDigest&&binding.native_fingerprint===g.typedRequestFingerprint&&gitBlobMeta(binding.canonical).bytes===g.canonicalBytes,"correct_typed_stdin_SHA_and_FP");
 ck(initial.v.reused===false&&initial.v.audit_recorded===true&&initial.v.local_record_pending===false&&initial.v.launch.ok===true&&initial.v.job.id===s.job&&initial.v.job.host==="rog"&&initial.v.job.idempotency_key===initial.q.idempotency_key&&initial.v.job.request_digest===binding.sha256&&fp(initial.v.job.request_fingerprint)===binding.native_fingerprint,"actual_unique_start_ACK_binding");
 ck(initial.v.job.executable===initial.q.executable&&initial.v.job.cwd===initial.q.cwd&&eq(initial.v.job.args,initial.q.args),"actual_ACK_exact_executable_argv_cwd");
 const natives=[];
 for(let i=0;i<2;i++){const o=s.completedObservers[i],ad=calls[1+3*i],st=calls[2+3*i],pg=calls[3+3*i];
  ck(ad.q.operation.arguments.host==="rog"&&ad.q.operation.arguments.job_id===s.job&&ad.q.operation.tool===o.tool&&ad.v.operation_id===o.id&&ad.v.tool_name===o.tool&&ad.v.reused===false&&ad.v.automatic_retry===false,"observer"+i+":original_admission");
  ck(st.q.operation_id===o.id&&st.v.operation_id===o.id&&st.v.tool_name===o.tool&&st.v.async_state==="completed"&&st.v.owned_future_active===false&&st.v.result_state==="stored_observed"&&st.v.payload_available===true,"observer"+i+":same_ID_closed");
  ck(pg.q.operation_id===o.id&&pg.q.offset===0&&pg.q.limit===8192&&pg.v.operation_id===o.id&&pg.v.offset===0&&pg.v.immutable_snapshot===true&&pg.v.eof===true,"observer"+i+":one_original_page");
  const raw=utf8Text(unb64(pg.v.data_base64));
  ck(raw===files["observer"+i+".payload.original.json"]&&eq(gitBlobMeta(raw),o.payload)&&pg.v.total_bytes===o.payload.bytes&&pg.v.next_offset===o.payload.bytes&&pg.v.result_sha256===o.payload.sha256,"observer"+i+":whole_payload");
  const payload=parseLosslessIntegers(raw);
  ck(payload.resultType==="complete"&&payload.isError===false&&payload.content.length===1&&payload.content[0].type==="text"&&payload.content[0].text===files["observer"+i+".native.original.json"]&&eq(gitBlobMeta(payload.content[0].text),o.nativeText),"observer"+i+":original_native_success_byte_exact");
  ck(o.completedInactive===true&&o.pages===1,"observer"+i+":full_closure");
  natives.push(parseLosslessIntegers(payload.content[0].text));
 }
 const authority=natives[0],streams=natives[1];
 ck(authority.job_id===s.job&&authority.exit_code===0&&authority.state==="succeeded"&&authority.output_complete===true&&authority.output_durable===true&&authority.terminal_publication_confirmed===true&&!authority.timed_out&&!authority.cancelled,"original_known_terminal_zero_full_durable");
 ck(authority.log_bytes.stdout.seen===1444&&authority.log_bytes.stdout.stored===1444&&authority.log_bytes.stderr.seen===0&&authority.log_bytes.stderr.stored===0&&authority.log_synced.stdout&&authority.log_synced.stderr&&!authority.log_truncated.stdout&&!authority.log_truncated.stderr,"actual_1444_zero_stream_authority");
 for(const name of ["stdout","stderr"]){const row=streams[name],raw=files[name+".original.txt"],bytes=utf8Bytes(raw),hex=bytes.map(x=>x.toString(16).padStart(2,"0")).join("");
  ck(row.offset===0&&row.next_offset===bytes.length&&row.size===bytes.length&&row.eof===true&&row.text===raw&&row.bytes_hex===hex,name+":original_complete_hex_text_extent");
 }
 const raw=files["stdout.original.txt"],pub=parseLosslessIntegers(raw),names=["native_jwt_build.py","launch_native_jwt_build.py","jwt-test-groups.public.json"];
 ck(pub.schema==="heptabao.native-jwt-pki-build-controls-inert.v1"&&pub.status==="prepared"&&pub.python_compile_only===true&&pub.files.length===3,"actual_prepared_compile_only_publication");
 ck(pub.stdin_bytes===g.payload.bytes&&pub.stdin_sha256===g.payload.sha256,"actual_exact_payload_consumed");
 for(let i=0;i<3;i++){const row=pub.files[i],pin=pins[names[i]],id=row.identity.map(fp);
  ck(row.path===g.fixedRoot+"/"+names[i]&&row.publication==="created"&&row.bytes===pin.bytes&&row.sha256===pin.sha256&&row.mode==="0600","file"+i+":exact_created_content");
  ck(id.length===9&&id.every(x=>/^[0-9]+$/.test(x))&&id[2]==="1000"&&id[3]==="1000"&&id[4]==="33152"&&id[5]==="1"&&id[6]===String(pin.bytes),"file"+i+":lossless_reported_full9");
 }
 const elapsed=BigInt(fp(pub.terminal_ns))-BigInt(fp(pub.started_ns));
 ck(elapsed>0n&&elapsed<60000000000n,"actual_publisher_epoch_span_within60");
 ck(["source_executed","git_started","compiler_started","service_started","artifact_transfer_started"].every(k=>pub[k]===false),"no_runner_Git_Cargo_service_or_transfer");
 ck(s.pending===null&&s.activeObserver===null&&!s.nativeCallInFlight&&!s.paused&&s.callsTotal===7&&s.completedObservers.length===2&&!s.controlsFilesObserved&&!s.buildStarted,"released_lane_not_independent_four_files_or_build");
 return {schema:"heptabao.025b-controls-inert-actual-verification.r1",status:"PASS",checkCount:checks.length,checks,job:s.job,stdout:gitBlobMeta(raw),elapsedNanoseconds:elapsed.toString(),elapsedSeconds:Number(elapsed)/1e9,originalCalls:7,originalObservers:2,originalPages:2,independentFourFilesQualified:false,buildQualified:false,NativeCalls:0,productTests:0};
}
