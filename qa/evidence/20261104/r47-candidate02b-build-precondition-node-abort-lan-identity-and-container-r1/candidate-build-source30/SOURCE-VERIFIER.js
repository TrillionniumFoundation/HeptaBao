function verifyMinimalCombinedBuildSource(texts) {
 const results=[];function ck(n,v){results.push({name:n,pass:!!v});if(!v)throw Error("combined build SOURCE "+n);}
 function eq(a,b){return JSON.stringify(a)===JSON.stringify(b);}
 function pin(raw,p){const m=gitBlobMeta(raw);return m.blob===p.blob&&m.bytes===p.bytes&&m.sha256===p.sha256;}
 const pins=JSON.parse(texts["INPUT-PINS.public.json"]),plan=JSON.parse(texts["PLAN.public.json"]);
 for(const[path,p]of Object.entries(pins))ck("whole_"+path,pin(texts[path],p));
 const swaps=JSON.parse(texts["LITERAL-BINDINGS.public.json"]);
 let bound=texts["journal.before.js"];
 for(const s of swaps){ck("singleton_"+s.name,bound.split(s.before).length===2);bound=bound.replace(s.before,s.after);}
 ck("only_three_journal_literals",swaps.length===3&&bound===texts["journal.after.js"]);
 ck("strict_forward",snapshotApply(texts["journal.before.js"],texts["journal.forward.diff"])===bound);
 ck("strict_reverse",snapshotApply(bound,texts["journal.reverse.diff"])===texts["journal.before.js"]);
 ck("two_hunks",(texts["journal.forward.diff"].match(/^@@ /gm)||[]).length===2);
 const q=JSON.parse(texts["request.exact.json"]),old=JSON.parse(texts["donor.request.exact.json"]),cgo=JSON.parse(texts["donor.BUILD-GO.public.json"]);
 ck("donor_whole_request",pin(texts["donor.request.exact.json"],cgo.exact_request));
 ck("same_native_request_fields",eq(Object.keys(q),Object.keys(old)));
 ck("same_native_execution_shape",q.host===old.host&&q.executable===old.executable&&q.cwd===old.cwd&&q.timeout_seconds===old.timeout_seconds&&q.args.length===old.args.length);
 ck("original_arg_flags",q.args.filter((x,i)=>i<3||i>3&&i%2===0).every((x,i)=>x===old.args.filter((x,j)=>j<3||j>3&&j%2===0)[i]));
 ck("unique_new_build_key",q.idempotency_key==="heptabao-combined-02b90762-build-246-268-r1-4c5de46d");
 ck("fixed_launcher_path",q.args[3]===plan.controlRoot+"/launch_native_jwt_build.py");
 const argv={};for(let i=4;i<q.args.length;i+=2)argv[q.args[i]]=q.args[i+1];
 ck("final_commit_tree",argv["--commit"]===plan.candidate.commit&&argv["--tree"]===plan.candidate.tree&&argv["--host"]==="rog");
 ck("actual_stage_binding",argv["--stage-sha256"]===pins["stage-result.actual.original.json"].sha256);
 ck("three_control_bindings",argv["--runner-sha256"]===pins["runner.py"].sha256&&argv["--groups-sha256"]===pins["jwt-test-groups.public.json"].sha256&&argv["--controls-sha256"]===pins["receipt.expected.derived.json"].sha256);
 const typed=processStartBinding(q);
 ck("correct_stdin_typed_binding",typed.sha256===plan.typed.sha256&&typed.native_fingerprint===plan.typed.native_fingerprint&&typed.canonical===plan.typed.canonical);
 ck("journal_exact_new_request",bound.includes(JSON.stringify(pins["request.exact.json"].blob))&&bound.includes(JSON.stringify(pins["request.exact.json"].sha256))&&bound.includes('const GF_SLOT = "combined_02b90762_build_gitfirst_r1";'));
 const pub=parseLosslessIntegers(texts["publisher.stdout.original.txt"]);
 ck("compact_original_lossless_reconstruction",exactPythonJSON(pub,false)+"\n"===texts["publisher.stdout.original.txt"]);
 ck("derived_receipt_exact",exactPythonJSON(pub,true)+"\n"===texts["receipt.expected.derived.json"]&&pins["receipt.expected.derived.json"].bytes===1818);
 const a=parseLosslessIntegers(texts["publisher.authority.native.original.json"]),s=parseLosslessIntegers(texts["publisher.streams.native.original.json"]);
 ck("actual_publisher_zero_full",a.job_id==="1a1b247b510-fc05-7d4e"&&a.exit_code===0&&a.output_complete===true&&a.output_durable===true&&a.terminal_publication_confirmed===true&&!a.timed_out&&!a.cancelled);
 ck("actual_complete_original_stdout",s.job_id===a.job_id&&s.stdout.offset===0&&s.stdout.next_offset===1408&&s.stdout.size===1408&&s.stdout.eof===true&&s.stdout.text===texts["publisher.stdout.original.txt"]&&s.stderr.eof===true&&s.stderr.text==="");
 ck("actual_three_exact_publications",pub.status==="prepared"&&pub.files.length===3&&pub.files.every(f=>{const name=f.path.slice(plan.controlRoot.length+1),k=name==="native_jwt_build.py"?"runner.py":name==="launch_native_jwt_build.py"?"launcher.py":name;return pins[k]&&f.bytes===pins[k].bytes&&f.sha256===pins[k].sha256&&f.publication==="created"&&eq(f.identity.slice(2,6),[1000,1000,33152,1]);}));
 const launcher=texts["launcher.py"],runner=texts["runner.py"],publisher=texts["publisher.py"];
 ck("same_python_controls",plan.anyControlCodeChanged===false&&plan.additionalPublisher===false&&plan.additionalFormatter===false);
 ck("full9_reader",launcher.includes("assert identity(before) == identity(os.fstat(fd)) == identity(path.lstat())")&&launcher.includes("os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK")&&launcher.includes("assert count == before.st_size and digest.hexdigest() == expected_sha"));
 ck("reader_regular_owner_single",launcher.includes("stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1"));
 ck("three_receipt_full9",launcher.includes("assert row['bytes'] == observed['bytes'] and row['sha256'] == observed['sha256']")&&launcher.includes("assert row['identity'] == observed['identity']")&&launcher.includes("assert observed['identity'][2:6] == [expected_uid, expected_uid, 0o100600, 1]"));
 ck("before_side_effect_admission",launcher.indexOf("assert row['identity'] == observed['identity']")<launcher.indexOf("ADMISSION.mkdir(mode=0o700)")&&launcher.indexOf("ADMISSION.mkdir(mode=0o700)")<launcher.indexOf("os.execv(argv[0], argv)"));
 ck("source_caps_kept",pins["launcher.py"].bytes===39818&&pins["launcher.py"].bytes<40000&&pins["runner.py"].bytes===32059&&launcher.includes("args.runner_sha256, 40000")&&launcher.includes("args.groups_sha256, 33825"));
 ck("receipt_read_SHA_bound",launcher.includes("args.controls_sha256, 65536)")&&launcher.includes("control_rows['launch_native_jwt_build.py']['sha256'], 40000)"));
 ck("receipt_publisher_verify_then_print",publisher.includes("publish(RECEIPT.name, raw)")&&publisher.indexOf("publish(RECEIPT.name, raw)")<publisher.indexOf("print(json.dumps(result, sort_keys=True), flush=True)")&&publisher.includes("return {'path': str(destination), 'publication': publication, **exact(destination, raw)}"));
 ck("same_pid_deadline_preserved",runner.includes("assert args.launcher_pid == os.getpid()")&&runner.includes("OUTER_UNTIL = args.outer_started_monotonic + ORIGINAL_OUTER_SECONDS"));
 ck("no_rustfmt_gate",!/(?:cargo.?fmt|rustfmt)/.test(launcher+runner));
 ck("unformatted_explicit",plan.candidate.sourceFormatted===false);
 const groups=JSON.parse(texts["jwt-test-groups.public.json"]),crates={"file":"heptabao-server","default":"heptabao-server","ha-native-v6-peer-ingress":"heptabao-ha-service"};
 const entries=groups.flatMap(g=>g.tests.map(n=>[crates[g.libtest_profile],n]));
 ck("246_268_18_exact",groups.length===18&&entries.length===268&&new Set(entries.map(x=>JSON.stringify(x))).size===246);
 ck("three_profiles",groups.filter(g=>g.libtest_profile==="file").reduce((n,g)=>n+g.tests.length,0)===22&&groups.filter(g=>g.libtest_profile==="default").reduce((n,g)=>n+g.tests.length,0)===229&&groups.filter(g=>g.libtest_profile==="ha-native-v6-peer-ingress").reduce((n,g)=>n+g.tests.length,0)===17);
 ck("original_family600",groups.every(g=>g.runtime_seconds===600));
 ck("normal61_snapshot27",groups.slice(4,9).reduce((n,g)=>n+g.tests.length,0)===27&&groups.slice(9).reduce((n,g)=>n+g.tests.length,0)===61);
 ck("execution_budget_identity",plan.sourceBudgets.outerSeconds===12000&&plan.sourceBudgets.releaseSeconds===1800&&plan.sourceBudgets.allCompileGatesSharedSeconds===3600&&plan.sourceBudgets.perFamilySeconds===600&&plan.sourceBudgets.listSeconds===30&&plan.sourceBudgets.cleanupTermSeconds===5&&plan.sourceBudgets.cleanupKillSeconds===5);
 ck("donor_observation_caps_unchanged",eq(plan.originalObservationScope,cgo.bounded_observation_for_this_new_job));
 ck("target_and_lock_scope_unchanged",plan.target===cgo.target&&eq(plan.targetLockMeaning,cgo.existing_nonblocking_target_flock)&&plan.requiredRootSoleCargoWindow===true);
 ck("no_independent_Native_readback_claim",plan.independentNativeMetadataForControls===false&&plan.independentNativeBodiesForControls===false&&plan.evidence[1].actualReceiptFileInfo===false&&plan.evidence[1].actualReceiptBody===false&&plan.evidence[1].actualReceiptFull9===null);
 ck("source_only_separate_GO",plan.authorization==="NOT_GO"&&plan.rootActualBuildGO===null&&plan.NativeCalls===0&&plan.initializeCalled===false&&plan.fullReplacement===false&&plan.productionCutover===false);
 return {schema:"heptabao.combined02b90762.minimal-build-source-verification.r1",ok:true,checks:results.length,results,pureV8:true,candidatePythonOrJournalInvoked:false,NativeCalls:0,buildQualified:false};
}
