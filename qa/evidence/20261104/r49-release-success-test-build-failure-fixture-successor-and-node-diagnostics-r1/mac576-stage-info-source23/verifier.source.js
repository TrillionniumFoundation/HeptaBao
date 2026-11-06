async function verifyMac576StageInfoSource(files){
 const checks=[],check=(name,ok)=>{checks.push({name,pass:!!ok});if(!ok)throw Error(name);};
 const same=(x,y)=>JSON.stringify(x)===JSON.stringify(y),meta=gitBlobMeta;
 const baseline=files["journal.baseline.js"],source=files["journal.source.js"],current=files["journal.current-stage.js"],edits=JSON.parse(files["BINDING-EDITS.public.json"]);
 const plan=JSON.parse(files["PLAN.public.json"]),contract=JSON.parse(files["GO.CONTRACT.public.json"]),request=JSON.parse(files["request.exact.json"]);
 check("exact_old_Mac_INFO_baseline",meta(baseline).blob==="8d25ff1cfea6172e3728addfd9ffb5bb1e96b4e1");
 let replay=baseline;for(const [a,z]of edits){check("binding_once_"+checks.length,replay.split(a).length===2);replay=replay.replace(a,z);}
 check("only_seven_literal_bindings",edits.length===7&&replay===source);
 check("baseline_strict_forward_reverse",applyStrict(baseline,files["baseline.strict.diff"])===source&&applyStrict(source,files["baseline.strict.diff"],true)===baseline);
 check("current_stage_strict_forward_reverse",applyStrict(current,files["current-stage.strict.diff"])===source&&applyStrict(source,files["current-stage.strict.diff"],true)===current);
 check("source_and_request_whole_pins",same(meta(source),plan.source)&&same(meta(files["request.exact.json"]),plan.exact_request)&&same(plan.exact_request,contract.exact_request));
 check("one_path_INFO_scope",request.operation.tool==="file_info"&&request.operation.arguments.host==="mac"
 &&request.operation.arguments.path===contract.metadata_guard.path&&contract.maximum_file_info_starts===1&&contract.binary_read_authorized===false);
 check("original_Mac_metadata_guard",contract.metadata_guard.max_bytes===65536&&contract.metadata_guard.uid===501
 &&contract.metadata_guard.gid===null&&contract.metadata_guard.metadata_platform===null
 &&source.includes('typeof md?.metadata_platform==="string"')&&source.includes('Number.isSafeInteger(md.gid)')&&source.includes('md.link_count===1'));
 check("original_page_payload_caps",source.includes("q.limit===8192")&&source.includes("v.total_bytes<=1048576"));
 const original=JSON.parse(files["STATE.before.original.json"]),oldCalls=JSON.stringify(original.calls),oldObservers=JSON.stringify(original.completedObservers);
 check("closed_actual_original_state",same(meta(files["STATE.before.original.json"]),plan.original_state_pin)
 &&Object.keys(original.calls).length===7&&original.completedObservers.length===2
 &&original.pending===null&&original.activeObserver===null&&original.nativeCallInFlight===false&&!original.paused);
 const refs=plan.prerequisites,raws=[files["stage-authority.native.original.json"],files["stage-streams.native.original.json"]];
 check("exact_original_closure_native",refs.length===2&&refs.every((r,i)=>same(meta(raws[i]),r.nativeText)));
 const authority=JSON.parse(raws[0]),streams=JSON.parse(raws[1]),terminal=JSON.parse(files["stage-stdout.original.txt"]);
 check("actual_terminal_full_streams",authority.exit_code===0&&authority.output_complete&&authority.output_durable
 &&streams.stdout.eof&&streams.stderr.eof&&streams.stdout.text===files["stage-stdout.original.txt"]
 &&terminal.status==="prepared"&&terminal.all_owned_stopped&&terminal.result_path===request.operation.arguments.path);
 const fakeGO={...contract,authorization:"GO",source_only_synthetic_verifier_input:true},goRaw=JSON.stringify(fakeGO,null,2)+"\n",goPin=meta(goRaw);
 const state=JSON.parse(files["STATE.before.original.json"]),mem=new Map([[plan.slot,state]]),archives=[];
 for(let i=0;i<refs.length;i++)mem.set(plan.slot+":closed_native:"+refs[i].id,raws[i]);
 const fakeArchive=async args=>{archives.push(args);return{tree:"0".repeat(40),whole:true};};
 const module=new Function("store","load","tools","archiveFlatPublicTextsOnce",
 files["pure_helpers.original.js"]+"\n"+source+"\nreturn{gfAuthorizeStageResultInfoOnly,gfPrepareOne,gfValidateRequest};")
 ((k,v)=>mem.set(k,v),k=>mem.get(k),{},fakeArchive);
 module.gfAuthorizeStageResultInfoOnly({goRaw,goPin,goWholeReadback:true});
 check("authorize_preserves_all_original_calls_observers",JSON.stringify(state.calls)===oldCalls&&JSON.stringify(state.completedObservers)===oldObservers&&state.goRaw===original.goRaw&&same(state.goPin,original.goPin));
 const scenarios=[["info","operation_start",files["request.exact.json"],null],
 ["status","operation_status",JSON.stringify({operation_id:"1".repeat(64)})+"\n",{id:"1".repeat(64),tool:"file_info",futureClosed:false}],
 ["page","operation_result",JSON.stringify({operation_id:"1".repeat(64),offset:0,limit:8192})+"\n",{id:"1".repeat(64),tool:"file_info",futureClosed:true,nextPageOffset:0,eof:false}]];
 for(const [label,kind,raw,active]of scenarios){
  state.pending=null;state.activeObserver=active;
  await module.gfPrepareOne({callKey:"source-only-"+label+"-r1",kind,requestRaw:raw});
  const arch=archives.at(-1),intent=JSON.parse(arch.texts["intent.json"]),armed=JSON.parse(arch.texts["armed.json"]);
  check("new_"+label+"_arm_references_new_INFO_GO",same(intent.rootGo,goPin)&&same(armed.rootGo,goPin));
 }
 check("original_calls_untouched_after_fake_prepare",Object.keys(original.calls).every(k=>same(original.calls[k],state.calls[k])));
 check("actual_values_unobserved",plan.actual_size===null&&plan.actual_sha256===null&&plan.actual_version===null&&plan.actual_full9===null);
 return{schema:"heptabao.mac576-stage-INFO-source-verification.v1",pass:true,check_count:checks.length,checks,
 fake_archives:archives.length,Native_calls:0,Git_calls:0,Python_runs:0,real_slot_modified:false};
}

