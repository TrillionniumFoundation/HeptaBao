function verifyLanActualBoundSource(r,a,prior,priorAudit,oldInertRaw,macAudit,rogAudit,macCargoAudit,u,sha,bs,b64,patch){
const checks=[],ck=(n,v)=>{if(!v)throw Error(n);checks.push(n);};
const canon=v=>v&&typeof v==="object"?Array.isArray(v)?v.map(canon):Object.fromEntries(Object.keys(v).sort().map(k=>[k,canon(v[k])])):v;
const eq=(a,b)=>JSON.stringify(canon(a))===JSON.stringify(canon(b));
const binding=JSON.parse(r["binding.actual.public.json"]),req=JSON.parse(r["dispatch/inert.request.json"]),prep=JSON.parse(r["dispatch/prepare.request.json"]),payload=JSON.parse(req.stdin);
const launcher="launch_normal_same_root_publication_pocket_postrecovery_cold_r1.py",code=r["candidate/"+launcher],before=r["before/launcher.unbound.py"];
const D="/home/qian-qi/heptabao-ha-closure-20261103-r1",control=D+"/normal-same-root-publication-pocket3-mac1-postrecovery-cold-control-r1";
ck("exact whole immutable source40 denominator",a.tree==="6116305e15768546bd3f06ef38db865134b05190"&&a.files===40&&a.bytes===2119293&&a.merkle.trees_verified===11);
ck("original unbound tree and exact launcher",priorAudit.tree==="d93ea226dceadbed501799835f5d290faaf1f750"&&before===prior["candidate/"+launcher]);
let expected=before,edits=0;
for(const kind of ["linux","mac"]){
 const b=binding.all10_actual_artifact_pins[kind],info=binding.independent_normal61_required[kind];
 ck("actual normal source and ABI "+kind,b.source===info.canonical_source_root&&b.build===info.output&&b.build_driver_sha256===info.driver_sha256&&b.abi===(kind==="linux"?"x86_64-unknown-linux-gnu":"aarch64-apple-darwin"));
 const normal=JSON.parse(r["qualification/"+kind+"/normal-release-result.public.json"]),native=JSON.parse(r["qualification/"+kind+"/native-build.public.json"]),core=JSON.parse(r["qualification/"+kind+"/normal61.result.public.json"]),auth=JSON.parse(r["qualification/"+kind+"/authority.public.json"]);
 const want={"artifacts/heptabao-seed":normal.artifacts["heptabao-seed"].sha256,"artifacts/heptabao-server":normal.artifacts["heptabao-server"].sha256,"normal-release-build.stdout":normal.cargo_events_sha256,"native-build.public.json":sha(r["qualification/"+kind+"/native-build.public.json"]),"normal-release-result.public.json":sha(r["qualification/"+kind+"/normal-release-result.public.json"])};
 ck("all five exact actual build pins "+kind,eq(b.files,want));
 ck("normal product commit tree "+kind,normal.source_commit===binding.source_commit&&normal.source_tree===binding.source_tree&&native.source_commit===binding.source_commit&&native.source_tree===binding.source_tree);
 ck("normal/core receipt binding "+kind,native.provenance.result_sha256===want["normal-release-result.public.json"]&&core.native_build_receipt_sha256===want["native-build.public.json"]);
 ck("original normal61 success and total "+kind,core.status==="passed"&&core.selected_test_total===61&&core.original_60_test_total===60);
 ck("original normal job exact authority "+kind,auth.job_id===info.normal_job&&auth.exit_code===0&&auth.output_complete===true&&auth.output_durable===true&&auth.terminal_publication_confirmed===true&&auth.timed_out===false);
 ck("normal61 body exact frozen binding "+kind,sha(r["qualification/"+kind+"/normal61.result.public.json"])===info.normal_result_sha256);
 for(const name of ["normal-release-result.public.json","native-build.public.json","normal61.result.public.json","authority.public.json"]){const meta=a.records.find(x=>x.path==="qualification/"+kind+"/"+name);ck("root-accepted normal original member "+kind+"/"+name,(kind==="mac"?macAudit:rogAudit).records.some(x=>x.blob===meta.blob));}
 // Each repeated None appears once per platform. Replace in fixed linux-then-mac order.
 for(const [name,hash] of Object.entries(want)){const old='"'+name+'": None',replacement='"'+name+'": "'+hash+'"';ck("remaining exact placeholder "+kind+"/"+name,expected.includes(old));expected=expected.replace(old,replacement);edits++;}
}
ck("entire launcher only ten pin fills",edits===10&&expected===code);
const launchPatch=patch(before,r["diffs/launcher.actual-binding.diff"]);ck("strict one launcher hunk",launchPatch.text===code&&launchPatch.hunks===1);
const candidateNames=a.records.filter(x=>x.path.startsWith("candidate/")&&!x.path.endsWith("/inert-carrier.py")).map(x=>x.path.slice(10));
ck("nine exact staged source names",candidateNames.length===9&&eq(candidateNames.slice().sort(),Object.keys(payload.files).sort()));
for(const n of candidateNames){
 ck("decoded staged source exact "+n,bs(b64(payload.files[n]))===r["candidate/"+n]);
 if(n!==launcher)ck("whole unbound approved source unchanged "+n,r["candidate/"+n]===prior["candidate/"+n]);
}
const oldInert=JSON.parse(oldInertRaw),carrierBefore=r["before/inert-carrier.actual-df026.py"],carrier=r["candidate/inert-carrier.py"];
ck("original actual carrier exact original dispatch",oldInert.args[4]===carrierBefore);
const pinRegex=/^PINS = (\{[\s\S]*?^\})/m,oldPins=carrierBefore.match(pinRegex),newPins=carrier.match(pinRegex);
ck("derived nine whole source pins",eq(JSON.parse(newPins[1]),Object.fromEntries(candidateNames.map(n=>[n,[u(r["candidate/"+n]).length,sha(r["candidate/"+n])]]))));
const changes=[["normal-cold-h2-pocket3-mac1-postrecovery-cold-control-r1","normal-same-root-publication-pocket3-mac1-postrecovery-cold-control-r1"],[oldPins[0],newPins[0]],["heptabao.cold-h2-validation-control-inert-carrier.v1","heptabao.same-root-publication-validation-control-inert-carrier.v1"],["heptabao.cold-h2-validation-control-inert-inputs.v1","heptabao.same-root-publication-validation-control-inert-inputs.v1"]];
let c=carrierBefore;for(const [from,to] of changes){ck("unique inert allowed slot "+from.slice(0,90),c.split(from).length===2);c=c.replace(from,to);}
ck("entire carrier only namespace schemas and exact derived pins",c===carrier);
const carrierPatch=patch(carrierBefore,r["diffs/inert-carrier.diff"]);ck("strict two carrier hunks",carrierPatch.text===carrier&&carrierPatch.hunks===2);
ck("carrier machine and create-only guards unchanged",carrier.includes("assert not os.path.lexists(BASE)")&&carrier.includes("'d90fa41f7e59edf2f2a732ea082cac83085a2a3695a503cd82b6b4eef9cab9f3'"));
ck("exact inert argv stdin cap",eq(req.args,["-I","-S","-B","-c",carrier])&&req.stdin===r["dispatch/inert.stdin.json"]&&u(req.stdin).length===477056&&u(req.stdin).length<=1048576);
ck("inert exact key and host",req.idempotency_key==="heptabao-4e808-postcold-inert-r1-57cb2b31-7ee5ee82"&&req.host==="desktop"&&req.executable==="/usr/bin/python3"&&req.cwd===D&&req.timeout_seconds===60);
ck("future prepare exact command no extra arguments",eq(prep.args,["-I","-S","-B",control+"/"+launcher,"--prepare-only"])&&prep.host==="desktop"&&prep.cwd===D&&prep.timeout_seconds===360);
ck("payload schema and exact keys",payload.schema==="heptabao.same-root-publication-validation-control-inert-inputs.v1"&&eq(Object.keys(payload).sort(),["files","schema"]));
ck("current source identity",binding.source_commit==="4e808d0ecb1bcded22870a7ec960dfb2491cf6ec"&&binding.source_tree==="eba5e650bd080b8ad41ea52a2bc68867f541d255");
ck("desktop source actual import explicitly unresolved",binding.desktop_source.path===D+"/normal-same-root-publication-validation-source-r1"&&binding.desktop_source.actual_complete_import_sha256===null&&binding.desktop_source.exists_claimed===false);
ck("all runtime admission still false",binding.dispatch_authorized===false&&binding.actual_stage_or_runtime_submitted===false);
ck("all original normal logs not claimed complete",binding.full_original_build_log_archives_pending===true&&binding.linux_cargo_event_body_independent_archive_pending===true&&binding.independent_normal61_required.mac.full_original_log_archive_complete===false&&binding.independent_normal61_required.linux.full_original_log_archive_complete===false);
ck("Mac complete release event hash independently archived",macCargoAudit.tree==="14b4c7b731a4bc43476b984173c820cb365f9079"&&macCargoAudit.records.some(x=>x.sha256===binding.all10_actual_artifact_pins.mac.files["normal-release-build.stdout"]));
const report=JSON.parse(r["verification/selected-checks.result.public.json"]),read=JSON.parse(r["verification/result-read.original-executor.json"]),observed=JSON.parse(r["verification/selected-checks.observed-executor.json"]);
ck("69 author compile-only checks and exact 227 plus 5 definitions",report.checks.length===69&&report.checks.every(x=>x.passed===true)&&report.candidate_function_class_definitions===227&&report.inert_definitions===5&&report.candidate_modules_executed===0&&report.host_requests===0);
ck("author original checker transcript honestly marked",typeof observed.provenance==="string"&&observed.provenance.includes("not stored")&&observed.provenance.includes("transcribe"));
ck("author subsequent original local result read exit zero",read.exit_code===0&&read.output===r["verification/selected-checks.result.public.json"]);
return {schema:"heptabao.root.lan-actual-normal61-source-binding-review.r1",status:"PASS_SOURCE_ONLY_FOR_INERT_STAGE",checksPassed:checks.length,checks,packet:{tree:a.tree,files:a.files,bytes:a.bytes},strictHunks:{launcher:1,inert:2},launcherOnlyTenActualPinsChanged:true,eightOtherWholeSourcesUnchanged:true,inertOnlyFourLiteralSlotsChanged:true,originalDefinitionsUnchanged:{runtime:227,inert:5},inertRequest:a.records.find(x=>x.path==="dispatch/inert.request.json"),prepareRequest:a.records.find(x=>x.path==="dispatch/prepare.request.json"),actualPins:binding.all10_actual_artifact_pins,pending:{completeDesktopSourceImport:true,prepareAndLiveSeparateExactAdmission:true,normalBuildLargeLogsFullArchive:true},scope:{sourceOnly:true,prepareAuthorized:false,liveAuthorized:false,physicalLanQualified:false,fullReplacement:false},sourceCheckProvenance:observed.provenance};
}