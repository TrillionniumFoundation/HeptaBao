function verifyCombinedBuildControlSource(t){
 const checks=[];function ck(name,pass){checks.push({name,pass:pass===true});if(pass!==true)throw Error(name);}
 const p=JSON.parse(t["PLAN.public.json"]),r=JSON.parse(t["REFERENCES.public.json"]),sw=JSON.parse(t["LITERAL-BINDINGS.public.json"]),q=JSON.parse(t["request.exact.json"]),payload=JSON.parse(t["payload.exact.json"]);
 const eq=(raw,pin)=>{const a=gitBlobMeta(raw);return a.blob===pin.blob&&a.bytes===pin.bytes&&a.sha256===pin.sha256;};
 for(const[name,pin]of [["runner.before.py",r.runnerBefore],["launcher.before.py",r.launcherBefore],["publisher.before.py",r.donorPublisher],["journal.before.js",r.donorJournal],["donor.publisher-GO.public.json",r.donorGO],["runner.after.py",p.files["native_jwt_build.py"]],["launcher.after.py",p.files["launch_native_jwt_build.py"]],["jwt-test-groups.public.json",r.groups],["publisher.after.py",p.publisher],["journal.after.js",p.journal],["payload.exact.json",p.payload],["request.exact.json",p.exact_request],["stage-result.actual.original.json",p.sourceCandidate.stageReport],["stage-root-qualification.public.json",p.sourceCandidate.rootDetailedStageQualification]])ck("whole_pin_"+name,eq(t[name],pin));
 for(const name of ["runner","launcher","publisher","journal"]){
  const ext=name==="journal"?"js":"py",before=t[name+".before."+ext],after=t[name+".after."+ext],f=t[name+".forward.diff"],v=t[name+".reverse.diff"];
  ck(name+"_forward_exact",snapshotApply(before,f)===after&&snapshotApply(after,f,true)===before);
  ck(name+"_reverse_exact",snapshotApply(after,v)===before&&snapshotApply(before,v,true)===after);
  let rebuilt=before;
  for(const item of sw[name]){const left=name==="runner"||name==="launcher"?item[0]:item[1],right=name==="runner"||name==="launcher"?item[1]:item[2];ck(name+"_unique_literal_"+(name==="runner"||name==="launcher"?left.split(" = ")[0]:item[0]),rebuilt.split(left).length===2);rebuilt=rebuilt.replace(left,right);}
  ck(name+"_only_bound_literals",rebuilt===after);
 }
 ck("finite_literal_counts",sw.runner.length===3&&sw.launcher.length===5&&sw.publisher.length===2&&sw.journal.length===3);
 const groups=JSON.parse(t["jwt-test-groups.public.json"]),all=groups.flatMap(g=>g.tests),profiles=groups.reduce((o,g)=>(o[g.libtest_profile]=(o[g.libtest_profile]||0)+g.tests.length,o),{});
 ck("whole_group_unchanged",eq(t["jwt-test-groups.public.json"],r.groups)&&eq(t["jwt-test-groups.public.json"],p.files["jwt-test-groups.public.json"]));
 ck("246_unique268_entries18_groups",groups.length===18&&all.length===268&&new Set(all).size===246);
 ck("three_exact_profiles",JSON.stringify(profiles)===JSON.stringify({file:22,default:229,"ha-native-v6-peer-ingress":17}));
 ck("600_each_family",groups.every(g=>g.runtime_seconds===600));
 ck("snapshot27_normal61_preserved",groups.slice(4,9).reduce((n,g)=>n+g.tests.length,0)===27&&groups.slice(9).reduce((n,g)=>n+g.tests.length,0)===61);
 ck("all_build_budgets_kept",p.futureBuildBudgets.outer===12000&&p.futureBuildBudgets.normalRelease===1800&&p.futureBuildBudgets.sharedCompile===3600&&p.futureBuildBudgets.family===600&&p.futureBuildBudgets.term===5&&p.futureBuildBudgets.kill===5);
 ck("source_caps_not_raised",p.caps.launcherSourceReadBytes===40000&&p.caps.actualLauncherBytes===39818&&p.caps.actualLauncherBytes<40000&&p.caps.runnerSourceReadBytes===40000&&p.caps.actualRunnerBytes===32059&&p.caps.groupsReadBytes===33825);
 ck("same_original_native_shape",Object.keys(q).sort().join(",")==="args,cwd,executable,host,idempotency_key,stdin,timeout_seconds"&&q.host==="rog"&&q.executable==="/usr/bin/python3"&&q.cwd==="/home/qian-qi"&&q.timeout_seconds===60&&q.args.length===5&&JSON.stringify(q.args.slice(0,4))===JSON.stringify(["-I","-S","-B","-c"]));
 ck("exact_inline_publisher",q.args[4]===t["publisher.after.py"]);
 ck("exact_stdin",q.stdin===t["payload.exact.json"]&&gitBlobMeta(q.stdin).bytes===141131&&gitBlobMeta(q.stdin).bytes<262144);
 ck("fixed_one_key",q.idempotency_key==="heptabao-combined-02b90762-controls-inert-r1-"+p.publisher.sha256.slice(0,8)&&q.idempotency_key.length<=128);
 const names=["jwt-test-groups.public.json","launch_native_jwt_build.py","native_jwt_build.py"];
 ck("payload_three_exact_members",Object.keys(payload).sort().join(",")==="files,schema"&&payload.schema==="heptabao.native-jwt-pki-build-control-inputs.v1"&&JSON.stringify(Object.keys(payload.files).sort())===JSON.stringify(names));
 const rawMap={"native_jwt_build.py":t["runner.after.py"],"launch_native_jwt_build.py":t["launcher.after.py"],"jwt-test-groups.public.json":t["jwt-test-groups.public.json"]};
 for(const[name,raw]of Object.entries(rawMap))ck("base64_exact_"+name,utf8Text(unb64(payload.files[name]))===raw&&eq(raw,p.files[name]));
 const pins=JSON.parse(t["publisher.after.py"].match(/^PINS = (\{[\s\S]*?\n\})\n/m)[1]);
 ck("publisher_whole_PINS",Object.keys(pins).length===3&&Object.entries(p.files).every(([name,pin])=>pins[name][0]===pin.bytes&&pins[name][1]===pin.sha256));
 ck("create_only_unchanged",t["publisher.after.py"].includes("assert not os.path.lexists(BASE)")&&t["publisher.after.py"].includes("assert not os.path.lexists(RECEIPT)")&&t["publisher.after.py"].includes("compile(raw, name, 'exec')")&&!t["publisher.after.py"].includes("subprocess"));
 ck("fixed_fresh_controls_root",t["publisher.after.py"].includes("BASE = PARENT / 'hb-02b90762-controls-20261106-r1'")&&t["launcher.after.py"].includes("ROOT = Path('/home/qian-qi/hb-02b90762-controls-20261106-r1')"));
 ck("both_final_source_constants",t["runner.after.py"].includes("DIAGNOSTIC_COMMIT = '"+p.sourceCandidate.commit+"'")&&t["runner.after.py"].includes("DIAGNOSTIC_TREE = '"+p.sourceCandidate.tree+"'")&&t["launcher.after.py"].includes("FINAL_COMMIT = '"+p.sourceCandidate.commit+"'")&&t["launcher.after.py"].includes("FINAL_TREE = '"+p.sourceCandidate.tree+"'")&&t["launcher.after.py"].includes("SOURCE_STAGE_ROOT = Path('"+p.sourceCandidate.stageRoot+"')"));
 const actual=parseLosslessIntegers(t["stage-result.actual.original.json"]),qual=JSON.parse(t["stage-root-qualification.public.json"]);
 ck("actual_stage_root_qualified",qual.ok===true&&qual.source_prepared_qualified===true&&qual.check_count===23&&qual.candidate_build_qualified===false&&qual.formatter_qualified===false);
 ck("actual_stage_matches_bound_source",actual.source_commit===p.sourceCandidate.commit&&actual.source_tree===p.sourceCandidate.tree&&actual.source===p.sourceCandidate.sourceRoot&&actual.root===p.sourceCandidate.stageRoot&&actual.status==="prepared"&&actual.source_clean===true);
 ck("actual_report_no_formatter_or_tests",actual.compiler_started===false&&actual.formatter_executed===false&&actual.rust_tests_executed===false&&actual.historical_controls_executed===false&&p.sourceCandidate.sourceFormatted===false);
 const b=processStartBinding(q);
 ck("correct_stdin_binding",b.sha256===p.nativeIdentity.sha256&&b.native_fingerprint===p.nativeIdentity.fingerprint&&gitBlobMeta(b.canonical).blob===p.nativeIdentity.canonical.blob&&t["correct_stdin_binding.js"].includes("stdin:r.stdin??null"));
 ck("source_only_no_new_host",p.authorization==="SOURCE_ONLY_NOT_GO"&&p.noNativeCallsInThisSourceTask===true&&p.futureExactBuildRequest===null&&p.publishedActualControls===null&&p.publishedControlReceipt===null&&p.buildAuthorized===false&&p.testsExecuted===0);
 return {schema:"heptabao.combined02b90762.controls-source-verification.r1",ok:true,checks:checks.length,results:checks,pureV8:true,candidatePythonOrJournalInvoked:false,NativeCalls:0,buildQualification:false};
}
