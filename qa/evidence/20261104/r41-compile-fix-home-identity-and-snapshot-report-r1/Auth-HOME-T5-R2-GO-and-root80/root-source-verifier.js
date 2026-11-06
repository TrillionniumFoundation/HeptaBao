function verifyHomeR2SourceRoot(p,prior,priorRoot,component,probe,author){
 const checks=[];const ck=(name,v)=>{checks.push({name,passed:v===true});if(v!==true)throw Error(name)},r=p.raw,c=JSON.parse(r["CONTRACT.public.json"]),ch=JSON.parse(r["CHANGES.public.json"]),man=JSON.parse(r["MANIFEST.public.json"]),eq=(x,y)=>JSON.stringify(x)===JSON.stringify(y),pm=(raw,p)=>{const m=gitBlobMeta(raw);return ["blob","bytes","sha256"].every(k=>m[k]===p[k])};
 ck("whole125_R2_source_packet",p.audit.whole&&p.audit.files===125&&p.audit.bytes===4231744&&p.audit.tree==="9204bd66dad2f266dd56cece33f455c5ffea9e2d");
 ck("root_predecessors_currently_qualified",priorRoot.passed&&priorRoot.checkCount===56&&component.passed&&component.checkCount===15&&probe.passed&&probe.checkCount===59&&probe.originalPartialEffectUnknownPreserved);
 ck("author182_exact_independently_reproduced",author.passed&&author.checkCount===182&&author.NativeCalls===0&&author.SDKExecuted===0&&eq(author,JSON.parse(r["verifier.result.public.json"])));
 ck("old_request_contract_and_publisher_exact",r["reference.inert-r1.exact-request.public.json"]===prior.raw["dispatch.inert.exact-request.public.json"]&&r["reference.r1.CONTRACT.public.json"]===prior.raw["CONTRACT.public.json"]&&r["publisher.before.py"]===prior.raw["publisher.after.py"]&&r["journal.before.js"]===prior.raw["journal.after.js"]);
 const ns=[
 ["/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-home-launch-r1","/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-home-launch-r2"],
 ["/Users/qianqi/heptabao-mac-authbus-4e808-home-launch-20261106-r1","/Users/qianqi/heptabao-mac-authbus-4e808-home-launch-20261106-r2"],
 ["mac-authbus-4e808-current-home-launch-r1","mac-authbus-4e808-current-home-launch-r2"],
 ["org.heptabao.qa.mac-authbus-4e808-home-r1.server","org.heptabao.qa.mac-authbus-4e808-home-r2.server"],
 ["org.heptabao.qa.mac-authbus-4e808-home-r1.consumer","org.heptabao.qa.mac-authbus-4e808-home-r2.consumer"]];
 ck("exact_five_namespace_literals",eq(ch.namespaces,ns)&&c.locations.homeControlRoot===ns[1][1]&&c.locations.t5BusinessRoot===ns[0][1]);
 const rebind=s=>ns.reduce((s,[a,b])=>s.split(a).join(b),s);
 ck("root_qualified_first5_components_exact",pm(r["component.home.first5.py"],component.helper)&&pm(r["component.manager.first5.py"],component.manager)&&pm(r["component.publisher.first5.py"],component.publisher));
 let hunks=0;
 for(const x of ch.sources){
 ck("original_R1_whole_"+x.name,r["before."+x.name]===prior.raw["after."+x.name]&&pm(r["before."+x.name],x.before));
 const expected=rebind(x.name==="mac_owned_launchd_r3.py"?r["component.manager.first5.py"]:r["before."+x.name]);
 ck("only_reviewed_change_"+x.name,r["after."+x.name]===expected&&pm(expected,x.after));
 if(x.changed){const f=strictApply(r["before."+x.name],r["diff."+x.name+".diff"]),b=strictApply(r["after."+x.name],r["reverse."+x.name+".diff"]);ck("strict_whole_"+x.name,f.text===r["after."+x.name]&&b.text===r["before."+x.name]&&f.hunks===x.forwardHunks&&b.hunks===x.reverseHunks);hunks+=f.hunks;}
 }
 ck("22_source_counts_15_hunks",ch.sources.length===22&&hunks===15&&ch.sources.filter(x=>x.category==="whole_unchanged").length===11&&ch.sources.filter(x=>x.category==="namespace_only").length===10&&ch.sources.filter(x=>x.category==="reviewed_first5_component_plus_namespace").length===1);
 for(const [n,b,a]of [["publisher","publisher.before.py","publisher.after.py"],["home","home.before.py","home.after.py"],["journal","journal.before.js","journal.after.js"],["runtime-deriver","derive-runtime.before.js","derive-runtime.after.js"],["candidate","candidate.before.public.json","doc.candidate-current-manager-wal-r1.public.json"]]){
 const f=strictApply(r[b],r[n+".forward.diff"]),back=strictApply(r[a],r[n+".reverse.diff"]);ck("extra_"+n+"_strict",f.text===r[a]&&back.text===r[b]&&f.hunks===ch.extras[n].forwardHunks&&back.hunks===ch.extras[n].reverseHunks);
 }
 const q=JSON.parse(r["dispatch.inert.exact-request.public.json"]),old=JSON.parse(r["reference.inert-r1.exact-request.public.json"]),pub=r["publisher.after.py"],payload=JSON.parse(q.stdin);
 ck("exact_payload_request_source",q.args[4]===pub&&q.stdin===r["dispatch.inert.stdin.public.json"]&&pm(pub,c.inert.publisher)&&pm(q.stdin,c.inert.payload)&&pm(r["dispatch.inert.exact-request.public.json"],c.inert.exactRequest)&&pm(r["journal.after.js"],c.inert.journal));
 ck("exact_original_interpreter_and_deadline",q.host==="mac"&&q.cwd==="/Users/qianqi"&&q.executable===c.launcher.regularPython&&q.executable===old.executable&&q.timeout_seconds===60&&q.args.slice(0,4).join(",")==="-I,-S,-B,-c"&&c.inert.seconds===45&&c.inert.originalDiskutilClippedSeconds===30);
 ck("30_fixed_public_payload_objects",Object.keys(payload.files).length===22&&Object.keys(payload.documents).length===8&&Object.entries(payload.files).every(([n,b64])=>utf8Text(unb64(b64))===r["after."+n])&&Object.entries(payload.documents).every(([n,b64])=>utf8Text(unb64(b64))===r["doc."+n.replaceAll("/","__")]));
 ck("shared_actual_runtime_binding_still_null",c.runtime.actualHomeBinding===null&&c.runtime.exactRequest===null&&!c.runtime.readyForRuntime&&c.inert.slotInitialized===false);
 ck("new_inert_only_slot_and_key",c.inert.slot==="owner_authbus_current_home_inert_gitfirst_r2"&&q.idempotency_key==="heptabao-mac-current-home-launch-inert-19b91f34-20261106-r2"&&c.inert.idempotencyKey===q.idempotency_key);
 ck("all_original_runtime_budgets_preserved",eq(c.preservedCaps,JSON.parse(prior.raw["CONTRACT.public.json"]).preservedCaps)&&eq(c.runtime.agents,["main","trnm","hepta-ui","hepta","hepta-backend"]));
 const main=pub.slice(pub.indexOf("\ndef main("));
 ck("compile18_and_diskutil_before_creation",main.indexOf("compile(ast.parse(content,filename=name)")<main.indexOf("home.__init__(")&&main.indexOf("guard.accept_diskutil(out)")<main.indexOf("home.__init__(")&&main.indexOf("fresh_root_absent(guard)")<main.indexOf("home.__init__("));
 ck("new_home_two_copies_readback",main.includes("home.read(HOME_CONTROL/name,1048576)==content")&&main.includes("report['homeControlBinding']=home.actual_binding()"));
 ck("first5_diagnostic_current_named_full9_in_publisher",pub.includes("need(current==named_root and current[:5]==before_root[:5],")&&pub.includes("'lastOwnCreateRootObservation':self.last_own_create_root_observation"));
 ck("all_old_active_paths_removed_from_executable_sources",[pub,...ch.sources.map(x=>r["after."+x.name])].every(s=>ns.every(([a])=>!s.includes(a))));
 const typed=processStartBinding(q),oldTyped=processStartBinding(old);
 ck("prior_typed_stdin_positive_control",oldTyped.sha256==="042bcf68044c67c47c65a6422f39aa0b41165106634761cf2334f5bfef64725a"&&oldTyped.native_fingerprint==="300561845805934532"&&typed.canonical.includes('"stdin":')&&!typed.canonical.includes('"stdin_text":'));
 const validate=new Function("gitBlobMeta",r["journal.after.js"]+"\nreturn gfValidateRequest;")(gitBlobMeta),s={paused:false,nativeCallInFlight:false,pending:null,startCalled:false,job:null,activeObserver:null};
 validate(s,"process_start",q,r["dispatch.inert.exact-request.public.json"]);ck("exact_inert_journal_admits",true);
 let denied=false;const drift={...q,timeout_seconds:61};try{validate(s,"process_start",drift,JSON.stringify(drift,null,2)+"\n")}catch(e){denied=true}ck("modified_request_refused",denied);
 return {schema:"heptabao.root.AuthBus-fresh-HOME-T5-R2-source-qualification.r1",passed:true,checkCount:checks.length,checks,sourcePacket:p.audit,inert:c.inert,locations:c.locations,sourceComponentRoot:gitBlobMeta(JSON.stringify(component,null,2)+"\n"),actualProbeRoot:gitBlobMeta(JSON.stringify(probe,null,2)+"\n"),typedBinding:{sha256:typed.sha256,native_fingerprint:typed.native_fingerprint,canonical_bytes:utf8Bytes(typed.canonical).length},sourceDiffHunks:15,publisherHunks:9,authorChecksReproduced:182,oldPartialHOMEUntouched:true,oldFailureUnknownPreserved:true,NativeCalls:0,actualHOMEQualified:false,runtimeCredentialsQualified:false,fullReplacement:false,productionCutover:false,legacyCleanup:false};
}