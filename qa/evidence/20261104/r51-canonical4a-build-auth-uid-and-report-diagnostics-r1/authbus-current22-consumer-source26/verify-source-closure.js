/* Pure source/carrier consistency only; does not compile or execute Python. Preload pure-helper, strict-diff-helper and rebuild-source-pin-closure. */
function verifyAuthBusR3ConsumerPinClosure(files){
 const checks=[];const check=(name,v)=>checks.push({name,passed:v===true}),eq=(name,a,b)=>check(name,JSON.stringify(a)===JSON.stringify(b));
 const pinEqual=(a,b)=>a.blob===b.blob&&a.bytes===b.bytes&&a.sha256===b.sha256;
 const before=JSON.parse(files["payload.before.original.json"]),after=JSON.parse(files["payload.pin-sync-only.SOURCE.json"]);
 const oldPins=JSON.parse(files["source-pins.before.original.json"]),newPins=JSON.parse(files["source-pins.current.public.json"]);
 const sources={},oldSources={};
 check("before/fixed-carrier",gitBlobMeta(files["payload.before.original.json"]).blob==="aff137a45af0d8f529f94cf2d93ba2a754eac527");
 check("before/fixed-publisher",gitBlobMeta(files["publisher.before.original.py"]).blob==="77f84c87e203714bc8e809df51aa0900653b6260");
 eq("carrier/exact-top-level-fields",Object.keys(after),Object.keys(before));
 eq("carrier/exact-source-names",Object.keys(after.files),Object.keys(before.files));
 eq("carrier/exact-document-names",Object.keys(after.documents),Object.keys(before.documents));
 check("carrier/same-schema-anchor",after.schema===before.schema&&after.anchorBase64===before.anchorBase64);
 for(const name of Object.keys(oldPins)){
  const a=utf8Text(unb64(before.files[name])),b=utf8Text(unb64(after.files[name]));
  oldSources[name]=a;sources[name]=b;
  check("source/"+name+"/before-whole",pinEqual(gitBlobMeta(a),oldPins[name]));
  check("source/"+name+"/after-whole",pinEqual(gitBlobMeta(b),newPins[name]));
 }
 check("source/counts",Object.keys(sources).length===22&&Object.keys(sources).filter(n=>n.endsWith(".py")).length===18);
 const changed=Object.keys(sources).filter(n=>sources[n]!==oldSources[n]);
 eq("source/exact-six-repair-leaves",changed,["mac_current_fixture_materializer_r1.py","mac_current_outer_wal_r1.py","mac_native_process_observer_r1.py","mac_owned_commands_r1.py","mac_owned_launchd_r3.py","mac_owned_unreaped_r1.py"]);
 check("source/exact-current-manager",newPins["mac_owned_launchd_r3.py"].blob==="92a1293db9792644b378da07eb9650951979358a");
 const oldManager=oldPins["mac_owned_launchd_r3.py"],interim={blob:"48f3e8394a15830953fb90e3470e8ba98e7df509",sha256:"edeb2b60dd102ea300887d3d2f23fc39682aa8700ce88d6273307f1b5d2ecbd4"};
 check("source/no-stale-manager-literal-in-current-executable-leaves",Object.values(sources).every(s=>![oldManager.blob,oldManager.sha256,interim.blob,interim.sha256].some(x=>s.includes(x))));
 check("source/no-separate-MODULES-literal",Object.values(sources).every(s=>!/^MODULES\s*=/m.test(s)));
 const oldCandidate=JSON.parse(files["candidate.before.original.json"]),candidate=JSON.parse(files["candidate.pin-sync-only.SOURCE.json"]);
 eq("candidate/current-sha-pins",candidate.sourcePins,Object.fromEntries(Object.entries(newPins).map(([n,p])=>[n,p.sha256])));
 eq("candidate/only-pin-map-changed",{...candidate,sourcePins:oldCandidate.sourcePins},oldCandidate);
 check("candidate/carrier-exact",utf8Text(unb64(after.documents["candidate-current-manager-wal-r1.public.json"]))===files["candidate.pin-sync-only.SOURCE.json"]);
 check("proof/seven-whole-original-documents",Object.keys(after.documents).filter(n=>n!=="candidate-current-manager-wal-r1.public.json").length===7&&Object.entries(after.documents).filter(([n])=>n!=="candidate-current-manager-wal-r1.public.json").every(([n,v])=>v===before.documents[n]));
 const r=rebuildAuthBusR3SourcePinClosure({payloadRaw:files["payload.before.original.json"],publisher:files["publisher.before.original.py"],sourcePinsRaw:files["source-pins.before.original.json"]},sources,newPins);
 check("rebuild/carrier-byte-exact",r.payloadTemplateRaw===files["payload.pin-sync-only.SOURCE.json"]);
 check("rebuild/publisher-byte-exact",r.publisherTemplate===files["publisher.pin-sync-only.SOURCE.py"]);
 check("rebuild/candidate-byte-exact",r.candidateTemplateRaw===files["candidate.pin-sync-only.SOURCE.json"]);
 eq("rebuild/unbound-input-byte-value-exact",r.runtimeBindingTemplate,JSON.parse(files["runtime-binding.UNBOUND.SOURCE.json"]));
 for(const [key,a,b,h]of [
  ["publisher",files["publisher.before.original.py"],files["publisher.pin-sync-only.SOURCE.py"],4],
  ["candidate",files["candidate.before.original.json"],files["candidate.pin-sync-only.SOURCE.json"],1],
  ["source-pins",files["source-pins.before.original.json"],files["source-pins.current.public.json"],3]]){
  const x=strictApplySource(a,files[key+".forward.diff"]),y=strictApplySource(b,files[key+".inverse.diff"]);
  check("diff/"+key+"/strict-forward",x.raw===b&&x.hunks===h);
  check("diff/"+key+"/strict-inverse",y.raw===a&&y.hunks===h);
 }
 const pub=files["publisher.pin-sync-only.SOURCE.py"],bp=files["publisher.before.original.py"];
 const block=(s,a,b)=>s.slice(s.indexOf(a),s.indexOf(b,s.indexOf(a))).trimEnd()+"\n";
 check("publisher/HomeControl-class-current-identical",block(pub,"class HomeControl:","def stdin_once()")===block(sources["mac_owned_launchd_r3.py"],"class HomeControl:","class OwnedLaunchd:"));
 check("publisher/definition-loader-unchanged",block(pub,"def load_definition_module(","def fresh_root_absent(")===block(bp,"def load_definition_module(","def fresh_root_absent("));
 check("publisher/main-and-finally-unchanged",pub.slice(pub.indexOf("def main():"))===bp.slice(bp.indexOf("def main():")));
 eq("publisher/only-three-import-safe-definition-loads",pub.split("\n").filter(x=>x.includes("=load_definition_module(")),[
  "        custody=load_definition_module('mac_owned_unreaped_r1.py',decoded['mac_owned_unreaped_r1.py'])",
  "        runner=load_definition_module('mac_owned_commands_r1.py',decoded['mac_owned_commands_r1.py'])",
  "        volume=load_definition_module('mac_t5_volume_guard_r1.py',decoded['mac_t5_volume_guard_r1.py'])"]);
 check("publisher/compiled-current-decoded-source",pub.includes("content=base64.b64decode(payload['files'][name],validate=True)")&&pub.includes("compile(ast.parse(content,filename=name),name,'exec');compiled.append(name)"));
 check("outer/one-direct-manager-import",Object.values(sources).reduce((n,s)=>n+(s.match(/from mac_owned_launchd_r3 import/g)||[]).length,0)===1);
 check("outer/verify-all-pins-before-import",sources["mac_current_outer_wal_r1.py"].indexOf("for name,pin in pins.items():qa_identities[name]=read_public_source")<sources["mac_current_outer_wal_r1.py"].indexOf("from mac_owned_launchd_r3 import"));
 check("outer/shared-pins-to-manager-materializer",sources["mac_current_outer_wal_r1.py"].includes("qa_pins=pins,")&&sources["mac_current_outer_wal_r1.py"].includes("source_pins=source_pins,qa_pins=pins,"));
 check("materializer/consumer-plan-current-map",sources["mac_current_fixture_materializer_r1.py"].includes("'qaPins':dict(qa_pins),'workerCommon':copy.deepcopy(common)"));
 check("server/current-helper-map-before-import",sources["mac_current_server_owner_r1.py"].indexOf("need(sha(raw)==pins[name],'reviewed_public_source')")<sources["mac_current_server_owner_r1.py"].indexOf("from mac_owned_commands_r1 import"));
 check("consumer/current-helper-map-before-import",sources["mac_current_phase_owner_r2.py"].indexOf("need(file_sha(q/name)==plan['qaPins'][name]")<sources["mac_current_phase_owner_r2.py"].indexOf("from mac_native_process_observer_r1 import ProcessReader"));
 const state=JSON.parse(files["runtime-binding.UNBOUND.SOURCE.json"]);
 check("barrier/no-ready-runtime",state.readyForRuntime===false&&state.originalRuntimeRequestRaw===null&&state.inertExactRequest===null&&state.runtimeExactRequest===null);
 check("barrier/no-old-namespace-dispatch",state.newRoot===null&&state.homeRoot===null&&state.actualHomeBinding===null&&state.actualPort===null);
 check("barrier/no-current-binary-issuer-private-binding",["currentMacBinary","currentMacBinaryFull9","currentMacBinaryVersion","currentMacBuildQualification","trustedIssuer","privateCredentialGeneration","actualSelectedOwner"].every(k=>state[k]===null));
 const graph=JSON.parse(files["CONSUMER-BINDINGS.public.json"]);
 check("barrier/source-only-claims",graph.NativeCalls===0&&graph.PythonExecuted===false&&graph.SDKExecuted===false&&graph.newPrivateInputRead===false&&graph.historicalUnknownPreserved===true);
 check("barrier/historical-product-fields-not-qualified",graph.sourceOnlyBarrier.publisherTemplateDispatchable===false&&graph.sourceOnlyBarrier.oldNamespaceDispatchAuthorized===false);
 return {schema:"heptabao.AuthBus.r3.consumer-pin-closure-pure-result",passed:checks.every(x=>x.passed),checkCount:checks.length,checks,
  execution:"pure V8 decoding/reconstruction/strict diffs of fixed public SOURCE only",NativeCallsAdded:0,PythonModulesCompiledOrExecuted:false,privateInputsRead:false,readyForRuntime:false};
}
