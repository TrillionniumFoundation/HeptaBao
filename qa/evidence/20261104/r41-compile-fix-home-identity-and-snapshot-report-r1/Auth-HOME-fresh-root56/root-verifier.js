
function verifyAuthFreshHomeSource(p,core,component,author){
 const checks=[];const ck=(n,v)=>{checks.push({name:n,passed:v===true});if(v!==true)throw Error(n)};
 const raw=p.raw,contract=JSON.parse(raw["CONTRACT.public.json"]),changes=JSON.parse(raw["CHANGES.public.json"]),manifest=JSON.parse(raw["MANIFEST.public.json"]),input=JSON.parse(raw["verifier.inputs.public.json"]);
 const eq=(s,pin)=>{const x=gitBlobMeta(s);return ["blob","bytes","sha256"].every(k=>x[k]===pin[k])};
 ck("whole107_exact_tree",p.audit.whole===true&&p.audit.files===107&&p.audit.bytes===7295005&&p.audit.tree==="74deadc6eaa97085b124515a703b6b386f3d3a20");
 ck("manifest_all106_exact_bodies",manifest.entries.length===106&&new Set(manifest.entries.map(x=>x.path)).size===106&&manifest.entries.every(x=>eq(raw[x.path],x))&&manifest.entries.reduce((n,x)=>n+x.bytes,0)===manifest.bytesWithoutManifest);
 for(const name of Object.keys(input.after))ck("whole_before_after_"+name,raw["before."+name]===input.before[name]&&raw["after."+name]===input.after[name]);
 for(const r of component.value.component_pins)ck("reviewed_component_baseline_"+r.file,eq(raw["before."+r.file],r.before));
 ck("reviewed_outer_baseline",eq(raw["before.mac_current_outer_wal_r1.py"],component.value.outer_unchanged));
 ck("same_core13_candidate_and_helpers",core.raw["home-control.py"]===raw["home-control.py"]&&core.raw["candidate.public.json"]===raw["doc.candidate-current-manager-wal-r1.public.json"]&&core.raw["inert.publisher.py"]===raw["publisher.after.py"]&&core.raw["inert.journal.js"]===raw["journal.after.js"]&&["mac_current_outer_wal_r1.py","mac_current_phase_owner_r2.py","mac_current_server_owner_r1.py","mac_owned_launchd_r3.py"].every(n=>core.raw[n]===raw["after."+n]));
 let hunks=0;
 for(const x of changes.sources){
  const f=strictApply(raw["before."+x.name],raw["diff."+x.name+".diff"]),r=strictApply(raw["after."+x.name],raw["reverse."+x.name+".diff"]);
  ck("strict_bidirectional_"+x.name,f.text===raw["after."+x.name]&&r.text===raw["before."+x.name]&&f.hunks===x.hunks&&r.hunks===x.hunks);hunks+=f.hunks;
 }
 ck("eleven_changed_38_hunks",changes.sources.length===11&&hunks===38&&changes.wholeUnchanged.length===11&&changes.wholeUnchanged.every(x=>raw["before."+x.name]===raw["after."+x.name]&&eq(raw["after."+x.name],x.pin)));
 for(const n of ["publisher","journal"]){const f=strictApply(raw[n+".before."+ (n==="publisher"?"py":"js")],raw[n+".forward.diff"]),r=strictApply(raw[n+".after."+(n==="publisher"?"py":"js")],raw[n+".reverse.diff"]);ck("strict_"+n+"_bidirectional",f.text===raw[n+".after."+(n==="publisher"?"py":"js")]&&r.text===raw[n+".before."+(n==="publisher"?"py":"js")]&&f.hunks===changes[n].hunks&&r.hunks===(n==="publisher"?8:changes[n].hunks));}
 ck("222_author_checks_independently_reproduced",author.passed===true&&author.checkCount===222&&JSON.stringify(author)===JSON.stringify(JSON.parse(raw["verifier.result.public.json"])));
 const reqRaw=raw["dispatch.inert.exact-request.public.json"],request=JSON.parse(reqRaw),publisher=raw["publisher.after.py"],payload=raw["dispatch.inert.stdin.public.json"];
 ck("exact_inert_source_payload_request",eq(reqRaw,contract.inert.exactRequest)&&eq(publisher,contract.inert.publisher)&&eq(payload,contract.inert.payload)&&request.args[4]===publisher&&request.stdin===payload&&request.idempotency_key===contract.inert.idempotencyKey&&input.dispatch.requestRaw===reqRaw&&input.dispatch.payloadRaw===payload);
 ck("exact_journal_and_undeployed_deriver",eq(raw["journal.after.js"],contract.inert.journal)&&eq(raw["derive-runtime.js"],contract.runtime.deriver)&&eq(raw["derive-runtime.inputs.public.json"],contract.runtime.deriverInputs));
 const binding=processStartBinding(request);
 ck("typed_request_has_stdin",binding.canonical.includes('"stdin":')&&!binding.canonical.includes('"stdin_text":')&&request.timeout_seconds===60&&request.host==="mac"&&request.cwd==="/Users/qianqi"&&request.executable===contract.launcher.regularPython);
 const validate=new Function("gitBlobMeta",raw["journal.after.js"]+";return gfValidateRequest;")(gitBlobMeta);
 const s={paused:false,nativeCallInFlight:false,pending:null,startCalled:false,job:null,activeObserver:null};
 let exact=true;try{validate(s,"process_start",request,reqRaw)}catch(e){exact=false}
 ck("journal_accepts_only_exact_inert",exact);
 const altered=JSON.parse(reqRaw);altered.timeout_seconds=61;let rejected=false;try{validate(s,"process_start",altered,JSON.stringify(altered,null,2)+"\n")}catch(e){rejected=true}
 ck("journal_refuses_modified_inert",rejected);
 let readRejected=false;try{validate({...s,job:"fixed-original"},"operation_start",{idempotency_key:contract.inert.idempotencyKey+"-bad-file",operation:{tool:"file_info",arguments:{host:"mac",path:contract.locations.t5BusinessRoot}}},"{}")}catch(e){readRejected=true}
 ck("inert_journal_does_not_authorize_file_reads_or_runtime",readRejected&&contract.runtime.exactRequest===null&&contract.runtime.actualHomeBinding===null&&contract.runtime.readyForRuntime===false);
 const main=publisher.slice(publisher.indexOf("\ndef main("));
 ck("compile18_before_any_new_root_effect",main.indexOf("compile(ast.parse(content,filename=name)")<main.indexOf("home.__init__(")&&main.indexOf("compile(ast.parse(content,filename=name)")<main.indexOf("guard.mkdir_new(ROOT)")&&main.includes("need(len(compiled)==18"));
 ck("T5_volume_and_absence_before_HOME_create",main.indexOf("guard.accept_diskutil(out)")<main.indexOf("home.__init__(")&&main.indexOf("fresh_root_absent(guard)")<main.indexOf("home.__init__("));
 ck("HOME_copy_separate_whole_readback",main.includes("home.read(HOME_CONTROL/name,1048576)==content")&&main.includes("report['homeControlBinding']=home.actual_binding()"));
 ck("publisher_final_closure_not_prefinal_receipt",main.indexOf("home.close()")>main.indexOf("receipt=encode(report)")&&main.indexOf("report['ok']=bool")>main.indexOf("home.close()")&&main.includes("not stopped or not closed")&&main.includes("and stopped and closed and final_anchor and not report['outcomeUnknown'] and completed<UNTIL"));
 ck("create_only_no_launchd_business_or_credential_call",!publisher.includes("OwnedLaunchd(")&&!publisher.includes("launchctl")&&!publisher.includes("sqlite3.connect")&&!publisher.includes("Popen(")&&publisher.includes("UNTIL=START+45.0")&&publisher.includes("until=min(UNTIL,time.monotonic()+30)"));
 ck("full_runtime_paths_remain_deferred",contract.runtime.agents.join(",")==="main,trnm,hepta-ui,hepta,hepta-backend"&&contract.runtime.productionSwitch===false&&contract.preservedCaps.outerSeconds===900&&contract.preservedCaps.runtimeControllerSeconds===1080&&contract.preservedCaps.roleTokenTTLSeconds===180&&contract.preservedCaps.roleTokenMaximumTTLSeconds===600&&Object.keys(contract.preservedCaps.renewRequestBody).length===0);
 return {schema:"heptabao.root.fresh-home-t5-auth-source-review.r1",passed:true,checkCount:checks.length,checks,packet:p.audit,componentReview:{blob:component.blob,bytes:component.bytes,sha256:component.sha256},sourceContract:gitBlobMeta(raw["CONTRACT.public.json"]),inert:contract.inert,typedBinding:{sha256:binding.sha256,native_fingerprint:binding.native_fingerprint,canonical_bytes:utf8Bytes(binding.canonical).length},sourceDiffHunks:hunks,authorChecksReproduced:222,HomeControlPeerRequiredBeforeGO:true,NativeCalls:0,pythonCompileExecuted:false,runtimeCredentialsQualified:false,fullReplacement:false,productionCutover:false,legacyCleanup:false};
}