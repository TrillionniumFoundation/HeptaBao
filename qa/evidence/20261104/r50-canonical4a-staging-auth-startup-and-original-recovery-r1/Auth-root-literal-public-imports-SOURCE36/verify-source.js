function verifyPublicImportRootLiteralSource(files){
 const checks=[],stable=x=>Array.isArray(x)?x.map(stable):x&&typeof x==="object"?Object.fromEntries(Object.keys(x).sort().map(k=>[k,stable(x[k])])):x;
 const eq=(name,a,b)=>checks.push({name,passed:JSON.stringify(stable(a))===JSON.stringify(stable(b))});
 const yes=(name,value)=>checks.push({name,passed:value===true});
 const json=p=>JSON.parse(files[p]),meta=gitBlobMeta;
 const c=json("CONTRACT.public.json"),oldgo=json("original-public-import-GO.json"),b=files["source.before.py"],a=files["source.after.py"];
 const oldroot="/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-public-node-startup-20261106-r1",root=oldroot.replace(/r1$/,"r2"),rule='(allow file-read* (literal "/"))\n';
 function constant(source,name){const l=source.split("\n").find(s=>s.startsWith(name+"="));if(!l)throw Error("constant "+name);const token=l.match(/base64\.b64decode\('([^']+)'\)/);if(!token)throw Error("base64 constant "+name);return JSON.parse(utf8Text(unb64(token[1])));}
 function defs(source){const matches=Array.from(source.matchAll(/^(class|def) ([A-Za-z_][A-Za-z0-9_]*)[(:]/gm));return Object.fromEntries(matches.map((m,i)=>[m[2],source.slice(m.index,i+1<matches.length?matches[i+1].index:source.length)]));}
 const bd=defs(b),ad=defs(a),bm=defs(files["materializer.before.py"]),am=defs(files["materializer.after.py"]);
 eq("source/before-whole",meta(b),{blob:"350a7511e91644fd8e6652f9b6c9cbfdaca1e3d4",bytes:150406,sha256:"9f35cf7cc8f0c63cb678f5acbd0974f1c5127452af57b740f29908a77c783dba"});
 eq("source/after-whole",meta(a),c.source);
 eq("source/predecessor-GO",meta(files["original-public-import-GO.json"]),c.before.GO);
 eq("source/defs-same",Object.keys(ad),Object.keys(bd));
 for(const name of Object.keys(bd))if(!["consumer_profile","main"].includes(name))eq("source/unchanged-definition/"+name,ad[name],bd[name]);
 const append="    lines.append('(allow file-read* (literal \"/\"))')\n";
 eq("source/profile-one-statement",ad.consumer_profile.replace(append,""),bd.consumer_profile);
 eq("materializer/whole-before",meta(files["materializer.before.py"]),{blob:"198feabe7aef20b302e5989fd72e99e0bc0d36c3",bytes:25973,sha256:"1a2ba260cb9659cb52f429f77de1e7d5c40ecb4f36af37d6b245d1b11cc277c9"});
 eq("materializer/whole-after",meta(files["materializer.after.py"]),c.materializerComponent.after);
 eq("materializer/one-added-statement",files["materializer.after.py"].replace(append,""),files["materializer.before.py"]);
 eq("materializer/same-profile-function",am.consumer_profile,ad.consumer_profile);
 eq("materializer/before-same-profile",bm.consumer_profile,bd.consumer_profile);
 eq("materializer/class-whole-unchanged",am.Materializer,bm.Materializer);
 yes("materializer/hash-derived-after-policy",am.Materializer.includes("self.write(sandbox,policy);phase_pins[str(sandbox)]=sha(policy)"));
 yes("materializer/not-dispatchable",c.materializerComponent.dispatchable===false&&c.materializerComponent.fullOriginalRootLiteralStillUnboundToAnyNewRuntime===true);
 const expectedHunks={source:7,guard:1,materializer:1,journal:2,profile:2};
 for(const k of Object.keys(expectedHunks)){
  const ext=k==="journal"?"js":k==="profile"?"sb":"py",before=files[k+".before."+ext],after=files[k+".after."+ext];
  const forward=strictApplySource(before,files[k+".forward.diff"]),inverse=strictApplySource(after,files[k+".inverse.diff"]);
  eq("strict/"+k+"/forward",forward.raw,after);eq("strict/"+k+"/inverse",inverse.raw,before);
  eq("strict/"+k+"/hunks",[forward.hunks,inverse.hunks],[expectedHunks[k],expectedHunks[k]]);
 }
 const mb=constant(b,"MODULES"),ma=constant(a,"MODULES");
 eq("modules/names",Object.keys(ma),Object.keys(mb));
 for(const [name,item] of Object.entries(ma)){
  const raw=utf8Text(unb64(item.base64));
  eq("modules/"+name+"/whole",meta(raw),{blob:item.blob,bytes:item.bytes,sha256:item.sha256});
  if(name!=="mac_t5_volume_guard_r1")eq("modules/"+name+"/whole-unchanged",item,mb[name]);
  else {eq("modules/guard/decoded-before",utf8Text(unb64(mb[name].base64)),files["guard.before.py"]);eq("modules/guard/decoded-after",raw,files["guard.after.py"]);}
 }
 eq("guard/only-root",files["guard.after.py"].replace(root.slice("/Volumes/T5/".length),oldroot.slice("/Volumes/T5/".length)),files["guard.before.py"]);
 for(const name of ["INPUT_PINS","NODE_ALIAS","PUBLIC_SOURCE_PINS","HARNESS_ROOTS","HARNESS_BINDINGS","MARKERS","PUBLIC_FILES","ERROR_CODES"])eq("constants/unchanged/"+name,constant(a,name),constant(b,name));
 eq("constants/root",a.match(/^ROOT=Path\("([^"]+)"\)/m)?.[1],root);
 yes("namespace/fresh-equal-length",root!==oldroot&&root.length===oldroot.length);
 eq("profile/original-whole",meta(files["profile.before.sb"]),{blob:"84ff31f119c8d0a46fe0f09b1f1ba2f2335f7cbf",bytes:6909,sha256:"acfbd336488f774e3acb87392bf5305f62004a0f529cbcd876593407989e7a12"});
 eq("profile/namespace-only-plus-root",files["profile.after.sb"],files["profile.before.sb"].split(oldroot).join(root)+rule);
 eq("profile/after-whole",meta(files["profile.after.sb"]),c.proposedChange.profileAfter);
 eq("profile/exact-33-byte-rule",utf8Bytes(rule).length,33);
 yes("profile/retain-deny-default",files["profile.after.sb"].startsWith("(version 1)\n(deny default)\n"));
 yes("profile/no-map-rule",!files["profile.after.sb"].includes("file-map-executable"));
 eq("profile/source-expected-sha",a.match(/^EXPECTED_PROFILE_SHA='([^']+)'/m)?.[1],meta(files["profile.after.sb"]).sha256);
 yes("profile/source-length-fence",ad.main.includes("sha(profile)==EXPECTED_PROFILE_SHA and len(profile)==6942"));
 let normalizedMain=ad.main.replace("diagnostic.r2","diagnostic.r1").replace("'rootDirectoryLiteralReadAdded':True,'otherSandboxPermissionsBroadened':False","'sandboxPermissionsBroadened':False").replace("len(profile)==6942","len(profile)==6909").replace("readback_bytes<=87580","readback_bytes<=87547");
 eq("main/only-declared-identity-profile-bound-changes",normalizedMain,bd.main);
 const pub=constant(a,"PUBLIC_FILES");
 for(const [name,path] of [["marker","startup-imports.original.mjs"],["rows","mac_auth_rows_cas.original.mjs"],["cache","mac_authbus_cache_cas.original.mjs"]])eq("public-file/"+name+"/unchanged",utf8Text(unb64(pub[name])),files[path]);
 const script=files["startup-imports.original.mjs"],modules=JSON.parse(script.match(/^const modules = (.+);$/m)[1]),stages=JSON.parse(script.match(/^const stages = (.+);$/m)[1]);
 eq("marker/exact-eleven-imports",modules,c.execution.markerModules);
 eq("marker/builtins-nine",modules.filter(x=>x.startsWith("node:")).length,9);
 eq("marker/local-CAS-two",modules.filter(x=>x.startsWith("./")),["./mac_auth_rows_cas_r1.mjs","./mac_authbus_cache_cas_r1.mjs"]);
 eq("marker/24-ordered",["entered-js",...stages.flatMap(x=>["before-"+x,"after-"+x]),"complete"],constant(a,"MARKERS"));
 yes("marker/import-only-no-methods",script.includes("await import(modules[i]);")&&!/\b(captureAuthRows|restoreAuthRowsWithCas|captureAuthBusCaches|restoreAuthBusCachesWithCas|DatabaseSync)\s*\(/.test(script));
 yes("marker/no-error-text-output",script.includes("catch (_error)")&&script.includes("await emit('failed-' + current)")&&!script.includes("console."));
 const rq=json("request.exact.public.json"),rb=json("request.before.json");
 eq("request/whole",meta(files["request.exact.public.json"]),c.exactRequest);
 eq("request/stdin-is-exact-source",rq.stdin,a);
 eq("request/binding-fields-unchanged",Object.fromEntries(Object.entries(rq).filter(([k])=>!["stdin","idempotency_key"].includes(k))),Object.fromEntries(Object.entries(rb).filter(([k])=>!["stdin","idempotency_key"].includes(k))));
 eq("request/key",rq.idempotency_key,"heptabao-mac-public-node-startup-root-read-"+meta(a).sha256.slice(0,8)+"-20261106-r1");
 yes("request/correct-stdin-key",Object.hasOwn(rq,"stdin")&&!Object.hasOwn(rq,"stdin_text"));
 eq("journal/whole",meta(files["journal.after.js"]),c.journal);
 let j=files["journal.after.js"].replace(c.slot,oldgo.journal.slot).replace(c.exactRequest.blob,oldgo.exact_request.blob).replace(String(c.exactRequest.bytes),String(oldgo.exact_request.bytes)).replace(c.exactRequest.sha256,oldgo.exact_request.sha256).split(c.observerPrefix).join("heptabao-mac-public-node-startup-9f35cf7c-");
 eq("journal/only-three-binding-values",j,files["journal.before.js"]);
 eq("contract/own-direct-popencap",c.execution.ownDirectPopenEntries,2);
 eq("contract/old-input-five",constant(a,"INPUT_PINS"),oldgo.exact_input_pins);
 eq("contract/inputs-whole-hash-byte-sum",Object.values(constant(a,"INPUT_PINS")).reduce((n,x)=>n+x.bytes,0),2313600);
 const oldBudgets=oldgo.budgets;
 for(const k of ["workSeconds","afterClosureSeconds","nativeOuterSeconds","oldOnceCleanup","fixedInputFiles","fixedInputBytes","fixedInputPhysicalReadCapIncludingEOFReserve","inputReadCalls","inputMetadataCalls","heldGuardReturnedFdStaticMaximum","heldGuardRuntimeLedgerCeiling","inputFdAttemptMaximum","fixedGuardPublicIoOperations","publicReadbackCalls","stdoutCapturePostExitLimit","stderrCapturePostExitLimit","captureLimitsArePostExitChecksNotKernelRLIMIT","wholePublicReportMaximum","observation"])eq("budget/unchanged/"+k,c.budgets[k],oldBudgets[k]);
 eq("budget/created-exact",Object.values(pub).reduce((n,x)=>n+unb64(x).length,0)+meta(files["profile.after.sb"]).bytes,c.budgets.createdInputBytes);
 eq("budget/read-sum",c.budgets.createdInputBytes+4096+65536,c.budgets.successfulReadbackByteMaximum);
 eq("budget/read-physical-six-EOF",c.budgets.successfulReadbackByteMaximum+6,c.budgets.physicalReadMaximumIncludingPerReadEOFSentinel);
 eq("budget/exact33-only",[c.budgets.createdInputBytes-oldBudgets.createdInputBytes,c.budgets.successfulReadbackByteMaximum-oldBudgets.successfulReadbackByteMaximum,c.budgets.physicalReadMaximumIncludingPerReadEOFSentinel-oldBudgets.physicalReadMaximumIncludingPerReadEOFSentinel],[33,33,33]);
 yes("ownership/protected-closure-unchanged",ad.InputAudit===bd.InputAudit&&ad.run_owned_capture===bd.run_owned_capture);
 yes("scope/no-new-private-plan",c.execution.CASFunctionsCalled===false&&c.execution.databaseMethodsCalled===false&&c.execution.SDKImported===false&&c.execution.networkCallsDispatched===false&&c.newScope.privateCredentialsDirectoryCreated===false);
 const actual=json("positive-version.stdout.original.json"),release=json("positive-version.release.original.json");
 eq("actual/positive-whole",meta(files["positive-version.stdout.original.json"]),c.completedPublicVersionBasis.stdout);
 eq("actual/release-whole",meta(files["positive-version.release.original.json"]),c.completedPublicVersionBasis.release);
 yes("actual/version-only-closure",actual.bothVersionArmsSucceeded===true&&actual.observationComplete===true&&actual.outcomeUnknown===false&&actual.allOwnDescriptorsAndChildrenClosed===true&&release.lane.A===0&&release.lane.knownFuture===false);
 yes("actual/version-not-SDK",c.completedPublicVersionBasis.SDKQualified===false&&actual.SDKOrProviderOrCredentialOperationRequested===false);
 yes("source/not-executed",c.authorization==="SOURCE_ONLY_NO_NATIVE_GO"&&c.NativeCallsSubmitted===0&&c.slotInitialized===false);
 yes("scope/unresolved-owner-separate",c.independentUnresolvedIssues.oldPsHelpers84947And85012CustodyUnknown===true&&c.independentUnresolvedIssues.oldProcessReaderCountOrPIDRefusalNotProvedESRCH===true&&c.independentUnresolvedIssues.consumerTerminationGuardMustRemainRealExitZero===true);
 eq("future/actual-slots-null",[c.futureAuthBusBinding.wholeCurrentCandidate,c.futureAuthBusBinding.observedServerBinaryFull9,c.futureAuthBusBinding.observedServerBinaryVersion,c.futureAuthBusBinding.actualTrustedIssuer,c.futureAuthBusBinding.privateCredentialGeneration,c.futureAuthBusBinding.newExactRuntimeGO],[null,null,null,null,null,null]);
 yes("future/no-old-credential-reuse",c.futureAuthBusBinding.oldCredentialOrIssuerQualificationReused===false&&c.futureAuthBusBinding.requireExistingTrustedCredentialSameGenerationAndSameInstanceAssertions===true);
 const error=json("local-builder-error.r1.public.json");
 yes("history/local-builder-only",error.NativeCalls===0&&error.candidateCreated===false&&error.historicalResultUnchanged===true);
 return {schema:"heptabao.authbus-public-import-root-literal-source-pure-checks.r1",passed:checks.every(x=>x.passed),checkCount:checks.length,checks,NativeCalls:0,PythonExecution:false,JavaScriptCandidateExecution:false,SDKQualified:false,sourceOnly:true,historicalUnknownPreserved:true};
}
