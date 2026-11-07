/* Pure V8 SOURCE validation. Preload pure-helper, strict-diff-helper, actual-stdin-binding and boundary-verifier; then verifyFixedPsSignedUidSourceR3(files). No candidate/module/Python/Native execution. */
const FIXED_PS_R3_EXPECTED={"controller.before.py":{"blob":"a219542403173eac624081b938d846d60cab6795","bytes":58079,"sha256":"0ad2087613cce1e4cd6a543695689761421ff81b612263460a575ccbba583a3e"},"controller.py":{"blob":"111b392deb1a1f0b02aa27fd4c91ea8f2505b064","bytes":58347,"sha256":"35fa06300c0c2c1d66c5eca8fee7a434d04831fe5dfd5329388674175269efd7"},"manager.before.py":{"blob":"48f3e8394a15830953fb90e3470e8ba98e7df509","bytes":60016,"sha256":"edeb2b60dd102ea300887d3d2f23fc39682aa8700ce88d6273307f1b5d2ecbd4"},"manager.py":{"blob":"92a1293db9792644b378da07eb9650951979358a","bytes":60153,"sha256":"802d1502344b3806fd79f2549f618f8fb1318c16ead8911a7e2f7d976fca2adf"},"request.before.json":{"blob":"c476d9c59017b7da5b63a015968d18cddd7017b4","bytes":59007,"sha256":"f5a2b45c6e3739a59a0a738bef0212ffaf36be278b255c15721c73ac705ebf62"},"request.exact.public.json":{"blob":"cc6a8a0615576d50b1e2add3388314f10c53aac8","bytes":59279,"sha256":"4c88fc542a3a7c5a1ea237dc8846f3aa1a19cceb758004b5e473b486c1d0864b"},"journal.before.js":{"blob":"be81a15c4a832b47e08c02bfc2df653b40c53bf6","bytes":19056,"sha256":"9051db0cb379f4cfcf9f3ebd1be88fef9c73d92fb2ac123e29dfa695ce602f5a"},"journal.js":{"blob":"d76c9f956aad6d7bca2a48d75ce06dddc6c70ced","bytes":19056,"sha256":"6f882241d655f54b6e2b6a2d00da3eee2570478ca1b1f3f87054cf5e74c8cd38"},"CONTRACT.public.json":{"blob":"1a74edb96c6405f2cb99806355fc07d72a20eb07","bytes":11860,"sha256":"81a76aeeb6e59d611f370745592f319f252d7ef84d862e4d78e281b8e25bbc86"},"actual-r2.stdout.original.json":{"blob":"c3d203ed45894650efb2e35dcc37fa848459572d","bytes":5942,"sha256":"92f78f946fb9f059faa1fe414d6df48c1fe89eecb103a4c62418299220cdc05a"},"actual-r2.RELEASE.public.json":{"blob":"e1ecfaf881ad5c4abad1a1b13d29177ff1a882a5","bytes":8203,"sha256":"ac704f39e4798168d3b32137bf9f4e038d656b04c17135a7f5b7b1e5c34f7459"},"COMPONENT-CONTRACT.original.json":{"blob":"a2d219b2987339a70c5215325761df7aeda32f8e","bytes":6894,"sha256":"38324b889f94c7d6455daef7c22f38d2f363842ccbc1c8b2a8bc89eae5b0970b"},"sdk-original22-pins.original.json":{"blob":"3fb7441f4cc70ce938492b14f302709cdb5ab8b4","bytes":4384,"sha256":"dad5ae8f3dd971eb5e949b1989db9cb203529cf9a77a27cec573914a43c1bf11"}};
function verifyFixedPsSignedUidSourceR3(files){
 const checks=[];const check=(name,v)=>checks.push({name,passed:v===true});
 const eq=(name,a,b)=>check(name,JSON.stringify(a)===JSON.stringify(b));
 const meta=(raw,p)=>{const x=gitBlobMeta(raw);return x.blob===p.blob&&x.bytes===p.bytes&&x.sha256===p.sha256;};
 for(const [name,pin]of Object.entries(FIXED_PS_R3_EXPECTED))check("whole/"+name,meta(files[name],pin));
 const c=JSON.parse(files["CONTRACT.public.json"]),bc=JSON.parse(files["CONTRACT.before.json"]);
 const s=files["controller.py"],bs=files["controller.before.py"],m=files["manager.py"],bm=files["manager.before.py"],j=files["journal.js"],bj=files["journal.before.js"];
 const q=JSON.parse(files["request.exact.public.json"]),bq=JSON.parse(files["request.before.json"]);
 for(const [name,a,b,fw,iv,hunks]of [
  ["controller",bs,s,files["controller.forward.diff"],files["controller.inverse.diff"],2],
  ["manager",bm,m,files["manager.forward.diff"],files["manager.inverse.diff"],1],
  ["journal",bj,j,files["journal.forward.diff"],files["journal.inverse.diff"],2],
  ["sdk-source-pins",files["sdk-source-pins.before.public.json"],files["sdk-source-pins.public.json"],files["sdk-source-pins.forward.diff"],files["sdk-source-pins.inverse.diff"],1]]){
  const x=strictApplySource(a,fw),y=strictApplySource(b,iv);
  check(name+"/strict-forward",x.raw===b&&x.hunks===hunks);
  check(name+"/strict-inverse",y.raw===a&&y.hunks===hunks);
 }
 const oldGuard="need(len(fields)==5 and all(x.isdecimal() for x in fields[:4]),'typed_process_row')";
 const newGuard="need(len(fields)==5 and all(x.isdecimal() for x in fields[:3])\n                 and re.fullmatch(r'-?[0-9]{1,10}',fields[3]) is not None,'typed_process_row')";
 const range="\n            need(-(1<<31)<=uid<=(1<<32)-1,'typed_process_row')";
 const undo=s.replace("'heptabao.fixed-setuid-ps-lexical-diagnostic.r3'","'heptabao.fixed-setuid-ps-lexical-diagnostic.r2'")
  .replace("count=0;signed_uid_rows=0;self_rows=[]","count=0;self_rows=[]")
  .replace(newGuard,oldGuard).replace(range,"").replace("\n            signed_uid_rows+=int(fields[3].startswith('-'))","")
  .replace("report['table']={'typedRows':count,'signedUidRowsAccepted':signed_uid_rows,\n            'selfRowObserved':len(self_rows)==1,","report['table']={'typedRows':count,'selfRowObserved':len(self_rows)==1,");
 check("controller/only-exact-narrow-changes",undo===bs);
 check("manager/only-exact-parser-changes",m.replace(newGuard,oldGuard).replace(range,"")===bm);
 check("both/one-uid-grammar",s.split(newGuard).length===2&&m.split(newGuard).length===2);
 check("both/one-uid-range",s.split(range).length===2&&m.split(range).length===2);
 check("both/retain-signed-map-int",s.includes("pid,ppid,pgid,uid=map(int,fields[:4])")&&m.includes("pid,ppid,pgid,uid=map(int,fields[:4])"));
 check("manager/group-filter-data-only-unchanged",m.includes("if pgid in groups:values.append({'pid':pid,'ppid':ppid,'pgid':pgid,'uid':uid,'state':fields[4]})"));
 check("controller/finally-byte-identical",s.slice(s.indexOf("    finally:\n"))===bs.slice(bs.indexOf("    finally:\n")));
 check("manager/consumer-run-phase-byte-identical",m.slice(m.indexOf("    def run_phase("))===bm.slice(bm.indexOf("    def run_phase(")));
 check("manager/actual-exit-zero-still-required",m.includes("need(state.get('last exit code')==0,'actual_launchd_phase_exit_zero')"));
 check("controller/no-new-definitions",(s.match(/^\s*(?:async )?def /gm)||[]).length===(bs.match(/^\s*(?:async )?def /gm)||[]).length);
 check("manager/no-new-definitions",(m.match(/^\s*(?:async )?def /gm)||[]).length===(bm.match(/^\s*(?:async )?def /gm)||[]).length);
 check("projection/whole-original",s.includes(files["lexical-projection.original.py"])&&bs.includes(files["lexical-projection.original.py"]));
 const modules=text=>{const line=text.split("\n").find(x=>x.startsWith("MODULES="));return JSON.parse(utf8Text(unb64(line.slice(line.indexOf("'")+1,line.lastIndexOf("'")))));};
 eq("controller/embedded-helpers-byte-identical",modules(s),modules(bs));
 const embedded=modules(s),chain=JSON.parse(files["EMBEDDED-AND-SOURCE-PIN-CHAIN.public.json"]);
 eq("controller/two-original-helper-names",Object.keys(embedded).sort(),["mac_owned_commands_r1","mac_owned_unreaped_r1"]);
 for(const [name,item]of Object.entries(embedded)){
  const raw=utf8Text(unb64(item.base64));check("embedded/"+name+"/whole",meta(raw,item));
  eq("embedded/"+name+"/chain",chain.probe.embeddedModules[name],{blob:item.blob,bytes:item.bytes,sha256:item.sha256});
 }
 const oldInputs=bs.split("\n").find(x=>x.startsWith("INPUT_PINS=")),newInputs=s.split("\n").find(x=>x.startsWith("INPUT_PINS="));
 check("inputs/exact-pins-unchanged",oldInputs===newInputs);
 const inputs=JSON.parse(utf8Text(unb64(newInputs.slice(newInputs.indexOf("'")+1,newInputs.lastIndexOf("'")))));
 eq("inputs/contract",inputs,c.fixedPublicInputPins);
 check("request/exact-current-stdin",q.stdin===s&&!Object.hasOwn(q,"stdin_text"));
 const {stdin:qs,idempotency_key:qk,...qr}=q,{stdin:bqs,idempotency_key:bqk,...bqr}=bq;
 eq("request/all-other-fields-byte-value-equivalent",qr,bqr);
 check("request/fresh-key-source-derived",qk==="heptabao-mac-fixed-setuid-ps-lexical-"+gitBlobMeta(s).sha256.slice(0,8)+"-20261107-r3"&&qk!==bqk);
 check("journal/only-three-binding-literals",j.replace(c.slot,bc.slot).replace(JSON.stringify(c.exact_request),JSON.stringify(bc.exact_request)).replace(c.observer_prefix,bc.observer_prefix)===bj);
 check("journal/new-slot",c.slot==="owner_authbus_fixed_setuid_ps_lexical_gitfirst_r3"&&j.includes(JSON.stringify(c.slot)));
 check("journal/request-pin",j.includes(JSON.stringify(c.exact_request))&&meta(files["request.exact.public.json"],c.exact_request));
 check("journal/whole-pin",meta(j,c.journal));
 const nb=actualStdinProcessStartBinding(q);
 eq("binding/correct-stdin",c.nativeBinding,{sha256:nb.sha256,native_fingerprint:nb.native_fingerprint,canonicalBytes:gitBlobMeta(nb.canonical).bytes,field:"stdin"});
 check("binding/chain",chain.probe.actualStdinBinding.sha256===nb.sha256&&chain.probe.actualStdinBinding.nativeFingerprint===nb.native_fingerprint);
 eq("caps/original-budgets",c.budgets,bc.budgets);eq("caps/original-observe",c.observe,bc.observe);
 eq("caps/original-primary-admission",c.primaryCommand,bc.primaryCommand);
 eq("caps/accounting",c.accounting,bc.accounting);
 const comp=JSON.parse(files["COMPONENT-CONTRACT.original.json"]),orig=JSON.parse(files["sdk-original22-pins.original.json"]);
 const prior=JSON.parse(files["sdk-source-pins.before.public.json"]),next=JSON.parse(files["sdk-source-pins.public.json"]);
 const reconstructed=JSON.parse(JSON.stringify(orig));
 for(const x of comp.beforeAndAfter)reconstructed[x.file]=x.after;
 eq("pin-chain/prior-six-components-exact",prior,reconstructed);
 eq("pin-chain/only-manager-leaf-changed",Object.keys(next).filter(k=>JSON.stringify(prior[k])!==JSON.stringify(next[k])),["mac_owned_launchd_r3.py"]);
 check("pin-chain/manager-current-whole",meta(m,next["mac_owned_launchd_r3.py"])&&meta(m,chain.SDKLibrary.after));
 check("pin-chain/current-source-overlay",meta(files["sdk-source-pins.public.json"],chain.SDKLibrary.newOverlay));
 check("pin-chain/prior-overlay",meta(files["sdk-source-pins.before.public.json"],chain.SDKLibrary.priorSixComponentOverlay));
 check("pin-chain/old-manager-before",meta(bm,chain.SDKLibrary.before));
 check("pin-chain/old-namespace-not-dispatchable",c.sourceComponentsDispatchable===false&&c.managerLibrary.oldNamespaceDispatchable===false&&chain.futureRuntime.oldNamespaceNotDispatchable===true);
 check("pin-chain/no-invented-runtime-bindings",Object.entries(chain.futureRuntime).filter(([k])=>k!=="oldNamespaceNotDispatchable").every(([,v])=>v===null));
 const actual=JSON.parse(files["actual-r2.stdout.original.json"]),release=JSON.parse(files["actual-r2.RELEASE.public.json"]);
 const lex=actual.tableLexicalProjection;
 check("actual/retain-parent-failure",actual.ok===false&&actual.error.code==="typed_process_row"&&actual.allFixedHeldNamedFencesPassed===false);
 check("actual/current-custody-closure-only",actual.allOwnDescriptorsAndChildrenClosed===true&&actual.outcomeUnknown===false&&actual.command.exitCode===0&&actual.command.cleanup.directChildReaped===true);
 check("actual/exact-fresh-negative-UID-shape",lex.rowCount===719&&lex.fieldCountHistogram["5"]===719&&lex.rowsRejectedByOriginalPredicate===1&&JSON.stringify(lex.failedNumericColumnCounts)==="[0,0,0,1]"&&lex.numericColumnLexicalCounts[3].ascii_decimal===718&&lex.numericColumnLexicalCounts[3].negative_decimal===1);
 check("actual/no-value-export",lex.rawRowsOrTokensOrHashExported===false&&c.predecessor.actualUidTokenOrMagnitudeKnown===false);
 check("actual/current-lane-closed",release.activeNativeCalls===0&&release.knownActiveNativeFutures===0&&release.laneReleased===true&&release.originalNativeCalls===9&&release.originalObservers===2&&release.immutablePages===4);
 check("actual/old-unknown-preserved",c.predecessor.oldGitCreateStillUnknown===true&&c.predecessor.oldR1TableReconstructed===false&&c.historicalUnknownPreserved===true);
 const prim=JSON.parse(files["PRIMARY-SOURCES.public.json"]);
 for(const x of prim.sources)check("primary/"+x.path+"/whole",meta(files[x.path],x.pin));
 check("primary/signed-Apple-keyword",files["Apple-ps-keyword.original.c"].includes('#ifdef __APPLE__\n#define\tUIDFMT\t"d"'));
 check("primary/UID-format-consumed",files["Apple-ps-print.original.c"].includes("printval")&&files["Apple-ps-print.original.c"].includes('fmtcheck(ofmt, "%*u")'));
 check("primary/no-installed-build-attestation",c.installedBinaryBuildMatchesAppleCommitNotClaimed===true);
 const cases=JSON.parse(files["boundary-cases.public.json"]);
 const br=verifyFixedPsSignedUidBoundaries(s,m,cases);
 eq("boundaries/exact-pure-result",br,JSON.parse(files["boundary-result.public.json"]));
 check("boundaries/18-finite-cases-pass",br.passed===true&&br.caseCount===18&&br.NativeCallsAdded===0);
 check("boundaries/no-Python-or-product-claim",br.productQualification===false&&br.execution.includes("no Python/ps/host"));
 check("scope/no-execution-or-issuer-qualification",c.NativeAdded===0&&c.actualBusinessQualified===false&&c.currentProductBinaryAndIssuerQualification===null);
 return {schema:"heptabao.fixed-ps-signed-uid-source-checks.r3",passed:checks.every(x=>x.passed),checkCount:checks.length,checks,
  execution:"pure V8 exact source/diff/pin and finite-boundary validation only",NativeCallsAdded:0,PythonModulesExecuted:false,
  oldFailuresPreserved:true,sourceComponentsDispatchable:false,actualSignedBranchObserved:false,productQualification:false};
}
