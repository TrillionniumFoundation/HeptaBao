function verifyMac4aActualInertBinding(files){
 const checks=[];function need(v,n){if(!v)throw Error(n);checks.push(n);}
 const b=JSON.parse(files["BINDING.actual.json"]),p=JSON.parse(files["PLAN.public.json"]);
 const inputs={binding:b,templates:{"runner.candidate.py":files["runner.original.py"],"launcher.candidate.template.py":files["launcher.before.py"],"publisher.candidate.template.py":files["publisher.before.py"],"groups.original.json":files["groups.original.json"],"journal.source.js":files["journal.before.js"]},stageInfoRaw:files["INFO.native.original.json"],stageInfoPin:p.actual_stage.infoPin,stageReportRaw:files["REPORT.original.json"],stageReportPin:p.actual_stage.bodyPin,stageRootQualificationRaw:files["STAGE-root-qualification.original.json"],stageRootQualificationPin:p.actual_stage.rootQualificationPin};
 const actual=bindMac4aNormalControlsAfterActualStage(inputs);
 for(const [key,name]of [["launcher","launcher.bound.py"],["publisher","publisher.bound.py"],["carrierRaw","carrier.exact.json"],["requestRaw","request.exact.json"],["journal","journal.bound.js"]])need(actual[key]===files[name],"actual binder exact "+key);
 need(JSON.stringify(actual.typed)===JSON.stringify(JSON.parse(files["typed-binding.public.json"])),"typed stdin and uint64 decimal exact");
 need(actual.actualStage.infoPin.blob==="fe58365faf209bc91dac4a87c5ada5a7a6d6ecf3"&&actual.actualStage.bodyPin.blob==="49bd3864f607eea4d1997da57e5008cfe2131b61"&&actual.actualStage.rootQualificationPin.blob==="b927b14ecaed1b5091ca045df49c89324a33695a","three exact actual stage inputs");
 need(JSON.stringify(actual.actualStage)===JSON.stringify(p.actual_stage),"actual version and lossless full9 plan exact");
 for(const n of ["launcher","publisher","journal"]){
   need(applyStrict(files[n+".before.py"]||files[n+".before.js"],files[n+".forward.diff"])===(files[n+".bound.py"]||files[n+".bound.js"]),"strict forward "+n);
   need(applyStrict(files[n+".bound.py"]||files[n+".bound.js"],files[n+".reverse.diff"])===(files[n+".before.py"]||files[n+".before.js"]),"strict reverse "+n);
 }
 need(applyStrict(files["BINDING.before.pending.json"],files["binding.actual.diff"])===files["BINDING.actual.json"],"documentary binding exact");
 need(actual.runnerUnchanged.blob==="f9c914de8ab5ba65ab79747acacc24260f553252"&&actual.groupsUnchanged.blob==="c1cd3341b57860b199302b1adf86e336957700c1","unchanged runner and groups");
 const carrier=JSON.parse(files["carrier.exact.json"]);
 need(Object.keys(carrier.files).length===3&&Object.entries(actual.controls).every(([n,v])=>carrier.files[n]===encodeBase64Bytes(utf8Bytes(v)))&&carrier.source_stage_base64===encodeBase64Bytes(utf8Bytes(files["REPORT.original.json"])),"complete carrier exact source and three controls");
 const q=JSON.parse(files["request.exact.json"]);
 need(q.host==="mac"&&q.executable==="/opt/homebrew/bin/python3"&&q.args.join("\n")===["-I","-S","-B","-c",actual.publisher].join("\n")&&q.stdin===actual.carrierRaw&&q.timeout_seconds===60,"sole inert exact argv and stdin");
 const g=JSON.parse(files["groups.original.json"]);
 need(g.normal61_groups.reduce((n,x)=>n+x.tests.length,0)===44&&g.native_jwt_pki_groups.length===2&&g.native_jwt_pki_groups.every(x=>x.tests.length===28)&&JSON.stringify(g.native_jwt_pki_groups[0].tests)===JSON.stringify(g.native_jwt_pki_groups[1].tests)&&p.tests.selected_unique===61+28&&p.tests.selected_instances===61+56,"original 61 plus identical 28 in two profiles");
 const audit=JSON.parse(files["ARCHIVE-KEY-AUDIT.public.json"]),j=files["journal.bound.js"];
 need((j.match(/archiveFlatPublicTextsOnce\(/g)||[]).length===4&&audit.all_callsites.length===4&&audit.fixed_legacy_keys.length===0&&j.includes('key:"gfa-"+callKey')&&j.includes('key:"gfx-"+callKey')&&j.includes('key:"gfs-"+callKey')&&j.includes('const archiveKey="gfc-"+a.id;'),"all four archive callsites dynamic");
 need(actual.carrierPin.bytes===120653&&actual.carrierPin.bytes<=p.budgets.complete_stdin_cap_bytes&&actual.runnerUnchanged.bytes<=49152&&actual.launcherPin.bytes<=40000&&actual.groupsUnchanged.bytes<=40000,"whole carrier and individual caps");
 need(actual.MacBuildRequest===null&&actual.actualControlsReceipt===null&&actual.actualBinary===null&&!actual.normal117Qualified&&!actual.full34Qualified&&p.Native_calls===0&&!p.runtime_slot_initialized&&p.followup.exact_build_request===null,"no invented runtime or build identities");
 return {schema:"heptabao.mac4a.actual-inert-binding-check.r1",pass:true,check_count:checks.length,checks,request:actual.requestPin,journal:actual.journalPin,publisher:actual.publisherPin,launcher:actual.launcherPin,carrier:actual.carrierPin,typed:actual.typed,scope:"pure actual data binding only",Native_calls:0};
}
