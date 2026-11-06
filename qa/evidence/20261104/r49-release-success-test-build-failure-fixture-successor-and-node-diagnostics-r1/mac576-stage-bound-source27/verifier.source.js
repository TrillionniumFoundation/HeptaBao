function verifyMac576BoundStageSource(files) {
 const checks=[],same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const check=(name,ok)=>{checks.push({name,pass:!!ok});if(!ok)throw Error("bound_stage_check:"+name);};
 const pin=(name)=>gitBlobMeta(files[name]),j=(name)=>JSON.parse(files[name]);
 const bindings=j("BUNDLE.bindings.actual.public.json");
 const originalBinderPin={blob:"e353530f3a579d88554928d070790661fa720114",bytes:6971,sha256:"bb79258cdd0357bcd56915c762eeafabb85bfca62715d8126e8d59ccb765f8a5"};
 check("original_reviewed_binder_unchanged",same(pin("binder.source.js"),originalBinderPin));
 const out=bindMac576SourceOnlyStage({sourceTemplate:files["stage.template.original.py"],
 canonicalBase64Text:files["canonical.bundle.base64.original.txt"],
 transportRaw:files["BINARY-TRANSPORT.original.json"],bindings,
 baseJournal:files["journal.before.js"]});
 for(const [field,file] of [["source","stage.source.py"],["sourceDiff","stage.actual-binding.diff"],
 ["carrier","carrier.exact.json"],["requestRaw","request.exact.json"],["journal","journal.source.js"],
 ["journalDiff","journal.actual-binding.diff"]])check("exact_original_binder_"+field,out[field]===files[file]);
 check("exact_bound_typed",same(out.typed,j("native-binding.public.json")));
 for(const [file,p] of [["producer-stage.original.json",bindings.producer.report],
 ["INFO.native.original.json",bindings.infoNative],
 ["root-producer-qualification.original.json",bindings.producer.rootQualification],
 ["root-transport-qualification.original.json",bindings.transportRootQualification]])
 check("original_actual_whole_"+file,same(pin(file),p));
 const rt=j("root-transport-qualification.original.json"),rp=j("root-producer-qualification.original.json");
 check("root_qualified_actual_transport",rt.qualified===true&&rt.CReleased===true
 &&rt.MacStageQualified===false&&rt.binaryBytes===bindings.bundle.bytes
 &&rt.binarySHA256===bindings.bundle.sha256&&same(rt.full9,bindings.bundle.full9)
 &&rt.version===bindings.bundle.version
 &&rt.originalBodyOperation===bindings.bodyOperations[0]&&rt.originalINFOOperation===bindings.infoOperation);
 check("root_qualified_actual_producer",rp.sourceStageQualified===true
 &&rp.candidateCommit===bindings.candidate.commit&&rp.candidateTree===bindings.candidate.tree
 &&rp.bundleReported.bytes===bindings.bundle.bytes&&rp.bundleReported.sha256===bindings.bundle.sha256
 &&rp.bundleReported.path===bindings.producer.path);
 const template=files["stage.template.original.py"],source=files["stage.source.py"];
 check("exact_two_source_constants_only",source.replace("CANONICAL_BUNDLE_BYTES = 5766\n","CANONICAL_BUNDLE_BYTES = None\n")
 .replace("CANONICAL_BUNDLE_SHA256 = '"+bindings.bundle.sha256+"'\n","CANONICAL_BUNDLE_SHA256 = None\n")===template);
 const q=j("request.exact.json");
 check("fixed_host_and_fresh_root",q.host==="mac"&&q.executable==="/opt/homebrew/bin/python3"
 &&q.cwd==="/Volumes/T5/hepta-vnext-recovery-20261013"
 &&source.includes("ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/hb-5767739c-src-20261106-r1')"));
 check("one_exact_inline_source_and_stdin",q.args[4]===source&&q.stdin===files["carrier.exact.json"]
 &&q.idempotency_key==="heptabao-5767739c-mac-source-only-20261106-r1-"+out.sourcePin.sha256.slice(0,8));
 check("original_budget_carrier",q.timeout_seconds===360&&out.carrierPin.bytes===7772&&out.carrierPin.bytes<=262144
 &&source.includes("STAGE_SECONDS = 300.0"));
 const p=j("PLAN.public.json");
 check("source_only_null_runtime",p.status==="SOURCE_ONLY_BOUND_AWAIT_EXACT_GO"
 &&p.actual.Mac_stage_qualified===false&&p.actual.Native_calls===0
 &&p.actual.Cargo_runs===0&&p.actual.controls_published===false&&p.actual.GO===null);
 check("successor_normal_matrix_reference",p.next_normal.unique_tests===89
 &&p.next_normal.profile_executions===117&&p.next_normal.source_tree==="66c0d39d1a8e6cdfea4af730bf053c95c70b8d4e"
 &&p.next_normal.actual_result===null);
 return {schema:"heptabao.mac576.bound-source-verification.v1",pass:true,check_count:checks.length,
 checks,Native_calls:0,Python_runs:0,old_template_27_repeated:false};
}

