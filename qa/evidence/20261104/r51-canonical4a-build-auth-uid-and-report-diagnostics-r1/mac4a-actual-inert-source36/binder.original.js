function bindMac4aNormalControlsAfterActualStage(input) {
 function need(v,m){if(!v)throw Error(m);}
 function pin(raw,p){const x=gitBlobMeta(raw);need(x.blob===p.blob&&x.bytes===p.bytes&&x.sha256===p.sha256,"whole bound input");return x;}
 function replaceOne(raw,a,b){need(raw.split(a).length===2,"single fixed binding marker");return raw.replace(a,b);}
 const expected={"source29":"f7942d13d97acc6e66733ed1ff424876c0b2b097","runner":{"blob":"f9c914de8ab5ba65ab79747acacc24260f553252","bytes":42977,"sha256":"9b05569375d5de0836ece83e9a93d04d6d60b50f455e535e980fefc7989f6a22"},"launcher":{"blob":"b9554a1a6852cbfb965ba766e73865a5af5eebbf","bytes":25832,"sha256":"16b5b0fec596e59f8d4369f2597487e25282aae206f3030b0839038acb7d9b68"},"publisher":{"blob":"dbf6dc6bc0d1611ad7c6f7f63d10bfeb6e8fe19a","bytes":8769,"sha256":"e0c76667ecc0c4985edac39e9cd86e5f4430f325465b35744f7e461254c7a347"},"groups":{"blob":"c1cd3341b57860b199302b1adf86e336957700c1","bytes":13725,"sha256":"3db98fdaf90b753b15e2c98fa256f3c5c7cd66667492db4422b2a0bfb902997d"},"buildBinder":{"blob":"5ad7e169fbe237b26b410c6230cc3bbdcbffc815","bytes":4706,"sha256":"bbcd65ec381f1368e7070c73d33822d8800793bfd18981c9f303ca572f214b59"},"journal":{"blob":"de11da67ee16e58248f939483b5f20fd09114a9d","bytes":19049,"sha256":"34efe4b61e146a99b9057d6ed1fddcdd92a46209328808fea79b2cda756b5211"},"paths":{"base":"/Volumes/T5/hepta-vnext-recovery-20261013","stageRoot":"/Volumes/T5/hepta-vnext-recovery-20261013/hb-4a49405b-src-20261106-r1","source":"/Volumes/T5/hepta-vnext-recovery-20261013/hb-4a49405b-src-20261106-r1/source","stageReport":"/Volumes/T5/hepta-vnext-recovery-20261013/hb-4a49405b-src-20261106-r1/control/stage-result.public.json","runRoot":"/Volumes/T5/hepta-vnext-recovery-20261013/hb-4a49405b-src-20261106-r1/normal-build-r1","control":"/Volumes/T5/hepta-vnext-recovery-20261013/hb-4a49405b-src-20261106-r1/normal-build-r1/control","admission":"/Volumes/T5/hepta-vnext-recovery-20261013/hb-4a49405b-src-20261106-r1/normal-build-r1/build-control-r1","output":"/Volumes/T5/hepta-vnext-recovery-20261013/hb-4a49405b-src-20261106-r1/normal-build-r1/normal-release-tests-r1","target":"/Volumes/T5/hepta-vnext-recovery-20261013/hb-4a49405b-src-20261106-r1/normal-build-r1/target-normal-r1","receipt":"/Volumes/T5/hepta-vnext-recovery-20261013/hb-4a49405b-src-20261106-r1/normal-build-r1/control/inert-stage.result.public.json"}},b=input.binding,t=input.templates;
 need(b.commit==="4a49405b93c45ab1c25ecba11cde63a7ede20dce"&&b.tree==="f02dd113d208d79f5275005dc65a5e8aecd0e9d3","frozen candidate");
 need(Object.keys(b.paths).length===Object.keys(expected.paths).length&&Object.entries(expected.paths).every(([k,v])=>b.paths[k]===v),"exact fixed source/control/output paths");
 for(const [name,file] of [["runner","runner.candidate.py"],["launcher","launcher.candidate.template.py"],["publisher","publisher.candidate.template.py"],["groups","groups.original.json"],["journal","journal.source.js"]])pin(t[file],expected[name]);
 need(input.stageInfoRaw!==null&&input.stageReportRaw!==null&&input.stageRootQualificationRaw!==null,"actual stage observations still pending");
 const infoPin=pin(input.stageInfoRaw,input.stageInfoPin),bodyPin=pin(input.stageReportRaw,input.stageReportPin),rootPin=pin(input.stageRootQualificationRaw,input.stageRootQualificationPin);
 const info=parseLosslessIntegers(input.stageInfoRaw),report=parseLosslessIntegers(input.stageReportRaw),md=info.metadata;
 const parts=typeof info.version==="string"?info.version.split(":"):[];
 need(info.path===b.paths.stageReport&&Number.isSafeInteger(info.size)&&info.size>0&&info.size<=65536
  &&/^[a-f0-9]{64}$/.test(info.sha256)&&info.mode===384
  &&typeof md?.metadata_platform==="string"&&md.metadata_platform.length>0&&md.metadata_platform.length<=64
  &&md.mode===384&&md.uid===501&&Number.isSafeInteger(md.gid)&&md.gid>=0&&md.link_count===1
  &&parts.length===5&&parts.every(v=>/^[0-9]+$/.test(v))&&parts[2]===String(info.size),"original fixed stage metadata admission");
 need(bodyPin.bytes===info.size&&bodyPin.sha256===info.sha256,"same actual metadata and whole report");
 const full9=[parts[0],parts[1],"501",String(md.gid),"33152","1",String(info.size),parts[3],parts[4]];
 need(report.schema==="heptabao.final-mac-source-only-stage.v1"&&report.status==="prepared"
  &&report.source_commit===b.commit&&report.source_tree===b.tree&&report.root===b.paths.stageRoot&&report.source===b.paths.source
  &&report.source_clean===true&&report.independent_git_directory===true&&report.full_strict_fsck_passed===true
  &&report.controls_published===false&&report.compiler_started===false&&report.within_new_stage_deadline===true
  &&report.external_volume_uuid==="FB804D1B-24CB-4D6E-AEA7-A9E180807758"
  &&report.full_worktree?.tracked_leaf_count===3932&&report.full_worktree.tracked_bytes===62553956
  &&report.full_worktree.full_leaf_index_sha256==="7e7acf5b5f4c0b2f9c410e6ead923258cb8b8750389d516b8998f6a45f5e8d7d"
  &&report.full_worktree.index_matches_tree===true&&report.full_worktree.all_tracked_worktree_blobs_and_modes_match===true
  &&Array.isArray(report.cleanup)&&report.cleanup.length>0
  &&report.cleanup.every(x=>x.direct_child_reaped===true&&Array.isArray(x.remaining)&&x.remaining.length===0&&!x.cleanup_error_type),"exact successful original stage substance");
 const stage={bytes:info.size,sha256:info.sha256,full9};
 const launcher=replaceOne(t["launcher.candidate.template.py"],"STAGE_EXPECTED_FULL9 = None","STAGE_EXPECTED_FULL9 = "+JSON.stringify(full9));
 const launcherPin=gitBlobMeta(launcher),runnerPin=expected.runner,groupsPin=expected.groups;
 const controls={"mac_normal_same_root_publication_build.py":t["runner.candidate.py"],"launch_normal_same_root_publication.py":launcher,"normal-test-groups.public.json":t["groups.original.json"]};
 const controlPins=Object.fromEntries(Object.entries(controls).map(([name,raw])=>[name,gitBlobMeta(raw)]));
 let publisher=replaceOne(t["publisher.candidate.template.py"],"BINDING_READY = False","BINDING_READY = True");
 publisher=replaceOne(publisher,"STAGE_EXPECTED = None","STAGE_EXPECTED = json.loads("+JSON.stringify(JSON.stringify(stage))+")");
 const oldPinsLine=t["publisher.candidate.template.py"].split("\n").find(x=>x.startsWith("PINS = "));
 need(typeof oldPinsLine==="string","old complete PINS literal");
 publisher=replaceOne(publisher,oldPinsLine,"PINS = "+JSON.stringify(Object.fromEntries(Object.entries(controlPins).map(([k,v])=>[k,[v.bytes,v.sha256]]))));
 const publisherPin=gitBlobMeta(publisher);
 const payload={schema:"heptabao.mac-normal61-native-jwt-pki28-controls-inputs.v1",files:Object.fromEntries(Object.entries(controls).map(([k,v])=>[k,encodeBase64Bytes(utf8Bytes(v))])),source_stage_base64:encodeBase64Bytes(utf8Bytes(input.stageReportRaw))};
 const carrierRaw=JSON.stringify(payload)+"\n",carrierPin=gitBlobMeta(carrierRaw);
 need(carrierPin.bytes<=262144&&runnerPin.bytes<=49152&&launcherPin.bytes<=40000&&groupsPin.bytes<=40000,"unchanged individual and complete carrier caps");
 const request={host:"mac",executable:"/opt/homebrew/bin/python3",args:["-I","-S","-B","-c",publisher],cwd:b.paths.base,env:{},stdin:carrierRaw,timeout_seconds:60,
  idempotency_key:"heptabao-4a49405b-mac-normal117-controls-inert-r1-"+publisherPin.sha256.slice(0,8)};
 const requestRaw=JSON.stringify(request,null,2)+"\n",requestPin=gitBlobMeta(requestRaw);
 let journal=t["journal.source.js"];
 journal=replaceOne(journal,'const GF_SLOT = "successor4a_mac_source_only_stage_gitfirst_r1";','const GF_SLOT = "successor4a_mac_normal117_controls_inert_gitfirst_r1";');
 const requestLine=journal.split("\n").find(x=>x.startsWith("const GF_REQUEST = "));
 journal=replaceOne(journal,requestLine,"const GF_REQUEST = "+JSON.stringify(requestPin)+";");
 journal=replaceOne(journal,"heptabao-4a49405b-mac-source-only-a88b3787-","heptabao-4a49405b-mac-normal117-controls-r1-");
 const typed=processStartBinding(request);
 return {sourceOnly:true,NativeGO:null,NativeExecuted:false,runnerUnchanged:runnerPin,groupsUnchanged:groupsPin,controls,controlPins,launcher,launcherPin,publisher,publisherPin,carrierRaw,carrierPin,requestRaw,requestPin,journal,journalPin:gitBlobMeta(journal),
  typed:{sha256:typed.sha256,native_fingerprint:typed.native_fingerprint,canonical_bytes:utf8Bytes(typed.canonical).length},
  actualStage:{infoPin,bodyPin,rootQualificationPin:rootPin,full9,version:info.version},MacBuildRequest:null,actualControlsReceipt:null,actualBinary:null,normal117Qualified:false,full34Qualified:false};
}

