function bind4aBuildControls(i) {
 const meta=gitBlobMeta,stage=parseLosslessIntegers(i.stageRaw);
 const sp=meta(i.stageRaw);
 if(stage.status!=="prepared"||stage.source_commit!=="4a49405b93c45ab1c25ecba11cde63a7ede20dce"||stage.source_tree!=="f02dd113d208d79f5275005dc65a5e8aecd0e9d3"||stage.root!=="/home/qian-qi/hb-4a49405b-src-20261106-r1"||!stage.source_clean||!stage.cleanup.every(x=>x.direct_child_reaped&&x.remaining.length===0))throw Error("actual closed4a stage required");
 if(stage.full_worktree?.full_leaf_index_sha256!=="7e7acf5b5f4c0b2f9c410e6ead923258cb8b8750389d516b8998f6a45f5e8d7d"||stage.full_worktree.tracked_leaf_count!==3932||stage.full_worktree.tracked_bytes!==62553956)throw Error("actual4a tree binding");
 if(!i.stageInfo||i.stageInfo.size!==sp.bytes||i.stageInfo.sha256!==sp.sha256)throw Error("actual stage info body binding");
 const runner=i.runner,launcher=i.launcher,groups=i.groups;
 if(meta(runner).blob!=="b3901c3ef34b4384c54e130637ea4ab8df0c6839"||meta(launcher).blob!=="4077f402625114c48cab2fd88b871cfeb877ab4d"||meta(groups).blob!=="0a3d746de42bfc31d3072cee1073f3908fc5811c")throw Error("frozen source identities");
 const publisherEdits=[],replace=(raw,name,before,after)=>{const n=raw.split(before).length-1;if(n!==1)throw Error(name+" must occur once");publisherEdits.push({name,before,after});return raw.replace(before,after);};
 let publisher=i.beforePublisher;
 publisher=replace(publisher,"fresh-controls-root","hb-5767739c-controls-20261106-r1","hb-4a49405b-controls-20261106-r1");
 publisher=replace(publisher,"runner-published-bytes","36346",String(meta(runner).bytes));
 publisher=replace(publisher,"runner-published-sha","b02b398a3dfe1ab2f57a6ab70056c2b4aa58f4e221644513187f991d80654166",meta(runner).sha256);
 publisher=replace(publisher,"launcher-published-sha","0f2419c1f9fb1ad10219b2c184108338693161200d74c2f0065311f7b394da3b",meta(launcher).sha256);
 publisher=replace(publisher,"candidate-commit","5767739cd25e458ac052dc8d384019bab8688ae0","4a49405b93c45ab1c25ecba11cde63a7ede20dce");
 publisher=replace(publisher,"candidate-tree","42477d622dcf96e1e2b0929fe9ecc6b7ba484740","f02dd113d208d79f5275005dc65a5e8aecd0e9d3");
 publisher=replace(publisher,"actual-stage-sha","ebff30386305001fd58ac147bfe18469d11b0a534c81a04f708d4da462641662",sp.sha256);
 const payload={schema:"heptabao.native-jwt-pki-build-control-inputs.v1",files:{
  "native_jwt_build.py":encodeBase64Bytes(utf8Bytes(runner)),
  "launch_native_jwt_build.py":encodeBase64Bytes(utf8Bytes(launcher)),
  "jwt-test-groups.public.json":encodeBase64Bytes(utf8Bytes(groups))}};
 const stdinRaw=JSON.stringify(payload,null,2)+"\n";
 if(meta(stdinRaw).bytes>262144||meta(runner).bytes>40000||meta(launcher).bytes>40000)throw Error("original size caps");
 const request=JSON.parse(i.beforeRequest);
 request.args=["-I","-S","-B","-c",publisher];request.stdin=stdinRaw;
 request.idempotency_key="heptabao-combined-4a49405b-fresh-build-20261106-r1-"+meta(publisher).sha256.slice(0,8);
 const requestRaw=JSON.stringify(request,null,2)+"\n",rp=meta(requestRaw),bp=meta(i.beforeRequest);
 const journalEdits=[
  {name:"slot",before:'const GF_SLOT = "combined_5767739c_fresh_build_gitfirst_r1";',after:'const GF_SLOT = "combined_4a49405b_fresh_build_gitfirst_r1";'},
  {name:"request_pin",before:'const GF_REQUEST = {blob:"'+bp.blob+'",\n bytes:'+bp.bytes+',sha256:"'+bp.sha256+'"};',after:'const GF_REQUEST = {blob:"'+rp.blob+'",\n bytes:'+rp.bytes+',sha256:"'+rp.sha256+'"};'},
  {name:"observer_prefix",before:"/^heptabao-combined-5767739c-fresh-observe-r1-/",after:"/^heptabao-combined-4a49405b-fresh-observe-r1-/"}];
 let journal=i.beforeJournal;
 for(const e of journalEdits){if(journal.split(e.before).length!==2)throw Error("journal literal "+e.name);journal=journal.replace(e.before,e.after);}
 return {publisher,launcher,runner,groups,stdinRaw,requestRaw,journal,publisherEdits,journalEdits,
  publisherPin:meta(publisher),launcherPin:meta(launcher),runnerPin:meta(runner),groupsPin:meta(groups),stdinPin:meta(stdinRaw),requestPin:rp,journalPin:meta(journal),stagePin:sp,typed:processStartBinding(request)};
}
