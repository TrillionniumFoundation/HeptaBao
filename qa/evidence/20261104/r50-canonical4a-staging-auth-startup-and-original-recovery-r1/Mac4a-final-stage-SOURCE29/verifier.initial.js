function verifyMac4aFinalStageSource(files){
 const checks=[];function ok(v,label){checks.push({label,pass:!!v});if(!v)throw Error(label);}
 const b=JSON.parse(files["BUNDLE.bindings.actual.public.json"]),p=JSON.parse(files["PLAN.public.json"]);
 const got=bindMac4aSourceOnlyStage({sourceTemplate:files["stage.template.original.py"],canonicalBase64Text:files["canonical.bundle.base64.original.txt"],transportRaw:files["BINARY-TRANSPORT.original.json"],bindings:b,baseJournal:files["journal.before.js"]});
 for(const [key,path]of [["source","stage.source.py"],["sourceDiff","stage.actual-binding.diff"],["carrier","carrier.exact.json"],["requestRaw","request.exact.json"],["journal","journal.source.js"],["journalDiff","journal.actual-binding.diff"]])ok(got[key]===files[path],"exact binder replay "+key);
 ok(JSON.stringify(got.typed)===files["native-binding.public.json"].trim()&&JSON.stringify(got.typed)===JSON.stringify(p.typed),"exact typed binding and decimal fingerprint");
 ok(JSON.stringify(gitBlobMeta(files["root-transport-qualification.original.json"]))===JSON.stringify(b.transportRootQualification),"exact root transport qualification");
 const t=JSON.parse(files["root-transport-qualification.original.json"]),q=JSON.parse(files["root-producer-qualification.original.json"]),u=q.bundlesReported.canonical_bundle;
 ok(t.passed===true&&t.checkCount===38&&t.checks.every(x=>x.pass===true)&&t.NativeReplay===false&&t.MacStageQualified===false,"root transport facts only, no inherited Macstage");
 ok(JSON.stringify(t.candidate)===JSON.stringify(b.candidate)&&JSON.stringify(t.bundle)===JSON.stringify(b.bundle),"root exact candidate and actual bundle");
 ok(JSON.stringify(t.transportManifest)===JSON.stringify(b.transport)&&JSON.stringify(t.canonicalBase64)===JSON.stringify(b.base64),"root exact whole transport pins");
 ok(q.sourceStageQualified===true&&q.candidateCommit===b.candidate.commit&&q.candidateTree===b.candidate.tree&&q.fullTrackedLeaves===3932&&q.trackedBytes===62553956&&q.history===3770,"actual producer candidate whole source");
 ok(u.path===b.producer.path&&u.bytes===1253&&u.sha256===b.bundle.sha256&&JSON.stringify(u.full9Strings)===JSON.stringify(b.bundle.full9)&&u.header.header_sha256===b.bundle.headerSha256,"actual producer whole identity matches independently transferred bytes");
 const n=JSON.parse(files["INFO.native.original.json"]);
 ok(n.version===b.bundle.version&&n.path===b.producer.path&&n.size===b.bundle.bytes&&n.sha256===b.bundle.sha256,"independent metadata version pinned");
 const req=JSON.parse(files["request.exact.json"]);
 ok(req.host==="mac"&&req.executable==="/opt/homebrew/bin/python3"&&req.cwd==="/Volumes/T5/hepta-vnext-recovery-20261013"&&req.timeout_seconds===360&&req.stdin===files["carrier.exact.json"],"one original Mac source-stage interface");
 ok(req.args[4]===files["stage.source.py"]&&req.args[6]===got.sourcePin.sha256&&req.args[8]===got.carrierPin.sha256,"exact source self and complete carrier SHA");
 ok(got.carrierPin.bytes===1756&&got.carrierPin.bytes<=262144,"actual complete carrier original cap");
 ok(p.budgets.stageSeconds===300&&p.budgets.cloneSeconds===180&&p.budgets.gitSeconds===90&&p.budgets.NativeOuterSeconds===360,"original stage clocks unchanged");
 const archiveAudit=JSON.parse(files["ARCHIVE-KEY-AUDIT.public.json"]);
 ok(archiveAudit.fixedExecutionArchiveKeys.length===0&&!files["journal.source.js"].includes('key:"successor')&&archiveAudit.allFunctionBodyArchiveSites.length===4,"all function-body archive keys reviewed");
 ok(p.afterThisStage.normalUnique===89&&p.afterThisStage.normalProfileExecutions===117&&p.afterThisStage.full34OriginalChecks===31&&p.afterThisStage.actualBinary===null,"future normal117 and original full34 remain unobserved");
 ok(p.NativeCalls===0&&p.MacWritesPerformed===0&&!p.CargoPerformed&&p.MacStageGO===null,"source-only proposal");
 return {schema:"heptabao.mac4a-final-stage-source-checks.v1",pass:true,check_count:checks.length,checks,NativeCalls:0,PythonExecutions:0,sourceTemplateChecksReused:27};
}
