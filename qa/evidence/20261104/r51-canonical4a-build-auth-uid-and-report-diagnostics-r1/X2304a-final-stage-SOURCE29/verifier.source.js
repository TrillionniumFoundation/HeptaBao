function verifyX2304aFinalStageBindings(files){
 const checks=[],same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),r=n=>{if(typeof files[n]!=="string")throw Error("missing "+n);return files[n];},j=n=>JSON.parse(r(n));
 function ck(n,v){checks.push({name:n,passed:!!v});if(!v)throw Error(n);}
 const p=j("PLAN.public.json"),b=j("BINDING.actual.json"),candidate=j("accepted-candidate.public.json"),request=j("request.exact.json");
 ck("accepted unchanged controller",gitBlobMeta(r("stage.template.original.py")).blob==="d40b9565ddc74b93caf150fad29c612f7160c8c8");
 ck("accepted unchanged binder",gitBlobMeta(r("binder.original.js")).blob==="5ee4b7696af740666382c8af80d31aba37343b4e");
 ck("prior candidate binding whole",gitBlobMeta(r("BINDING.candidate.before.json")).blob==="9ce4569cf77a74b75f42f0d334b5a675933a546b");
 ck("actual candidate manifest whole",gitBlobMeta(r("CANDIDATE.original.json")).blob==="c38e8861e72700088d2c3dd797fce885d117d903");
 ck("exact accepted4a candidate",same(candidate,{commit:"4a49405b93c45ab1c25ecba11cde63a7ede20dce",tree:"f02dd113d208d79f5275005dc65a5e8aecd0e9d3",parent:"5767739cd25e458ac052dc8d384019bab8688ae0",leaves:3932,tracked_bytes:62553956,full_index_sha256:"7e7acf5b5f4c0b2f9c410e6ead923258cb8b8750389d516b8998f6a45f5e8d7d",history:3770})&&same(candidate,b.candidate));
 ck("first root transport exact",gitBlobMeta(r("first-transport-root.original.json")).blob==="6b95f49c60c5a7441668cb0edb43ea2769d0c606");
 ck("second root transport exact",gitBlobMeta(r("second-transport-root.original.json")).blob==="eaa9d89d4b5f9e9cd6c62c73be052a2474edb56e");
 ck("candidate binding strict data delta",applyStrict(r("BINDING.candidate.before.json"),r("binding.actual.diff"))===r("BINDING.actual.json"));
 const prev=j("BINDING.candidate.before.json"),revert=JSON.parse(JSON.stringify(b));
 revert.carrier=prev.carrier;revert.bundles[1]=prev.bundles[1];
 ck("only carrier and second-bundle actual fields",same(revert,prev)&&same(b.bundles[0],prev.bundles[0]));
 const carrier=r("carrier.exact.json"),carrierObject=j("carrier.exact.json");
 ck("whole exact stdin remains original cap",gitBlobMeta(carrier).bytes===237239&&gitBlobMeta(carrier).bytes<=262144&&same(gitBlobMeta(carrier),p.carrier));
 ck("actual bundle kinds and sizes",b.bundles.length===2&&b.bundles[0].bytes===171016&&b.bundles[1].bytes===6815&&b.bundles.reduce((n,x)=>n+x.bytes,0)===177831&&b.bundles[1].prerequisite==="02b90762b3d6cc8699cc88bffb6f76cb1f07e270"&&b.bundles[1].head===candidate.commit);
 for(const [i,x]of b.bundles.entries()){
  const bytes=unb64(carrierObject[x.field]),headerBytes=utf8Bytes(x.header);
  ck("whole canonical binary and header "+i,bytes.length===x.bytes&&encodeBase64Bytes(bytes)===carrierObject[x.field]&&sha256Latin1(byteString(bytes))===x.sha256&&sha256Latin1(byteString(headerBytes))===x.header_sha256&&bytes.slice(0,headerBytes.length).every((z,k)=>z===headerBytes[k])&&utf8Text(bytes.slice(headerBytes.length,headerBytes.length+4))==="PACK");
 }
 const bound=bindX230TwoBundleSource({binding:b,acceptedCandidate:candidate,carrier,template:r("stage.template.original.py")});
 ck("original binder source and request exact replay",bound.source===r("stage.bound.py")&&bound.requestRaw===r("request.exact.json")&&same(bound.sourcePin,p.runtime_source)&&same(bound.requestPin,p.request));
 ck("correct typed lossless exact replay",same(bound.typed,p.typed_binding)&&bound.typed.native_fingerprint==="9419901995709740558"&&bound.typed.sha256==="82ba36f4d145b60e1e9ddcc5d4d6cbcf0fa37a20484338aace8c9bbc44b8a075");
 ck("single binding line source change",applyStrict(r("stage.template.original.py"),r("stage.binding.diff"))===r("stage.bound.py")&&(r("stage.binding.diff").match(/^@@/gm)||[]).length===1&&r("stage.bound.py").replace("BINDING = json.loads("+JSON.stringify(JSON.stringify(b))+")","BINDING = None  # EXACT_PUBLIC_SOURCE_BINDING")===r("stage.template.original.py"));
 ck("fresh exact X230 process request",request.host==="x230"&&request.executable==="/usr/bin/python3"&&same(request.args,["-I","-S","-B","-c",bound.source,bound.sourcePin.sha256])&&request.cwd==="/home/qian"&&same(request.env,{})&&request.stdin===carrier&&request.timeout_seconds===360&&request.idempotency_key==="heptabao-4a49405b-x230-two-bundle-source-20261106-r1-b0efa636");
 ck("explicit request-envelope versus stdin sizes",gitBlobMeta(r("request.exact.json")).bytes===268539&&p.input_caps.exact_request_bytes===268539&&p.input_caps.actual_carrier_bytes===237239&&p.input_caps.request_envelope_is_not_stdin_cap===true);
 ck("original controller budget and cap values unchanged",same(p.original_budgets,{stageSeconds:300,cloneSeconds:90,gitCommandSeconds:60,outerSeconds:360,termSeconds:5,killSeconds:5,processSnapshotSeconds:5,commandStdoutAndStderrBytesEach:2097152})&&p.input_caps.stdin_bytes===262144&&p.input_caps.bundle_bytes_total===262144);
 ck("historical base current presence remains unknown",p.fixed_readonly_base.current_presence===null&&p.fixed_readonly_base.path==="/home/qian/heptabao-same-root-publication-normal-20261105-r1/source"&&b.base_commit==="4e808d0ecb1bcded22870a7ec960dfb2491cf6ec"&&b.base_history===3763);
 let journal=r("journal.before.js"),rows=j("journal-replacements.public.json");
 ck("five closed journal literals",rows.length===5);
 for(const [a,z,n]of rows){ck("unique journal replacement "+a,journal.split(a).length-1===n&&n===1);journal=journal.replace(a,z);}
 ck("journal full literal equality",journal===r("journal.source.js")&&same(gitBlobMeta(journal),p.journal));
 ck("journal three strict forward reverse hunks",applyStrict(r("journal.before.js"),r("journal.forward.diff"))===journal&&applyStrict(journal,r("journal.reverse.diff"))===r("journal.before.js")&&(r("journal.forward.diff").match(/^@@/gm)||[]).length===3);
 ck("new source only without actual host or product claims",p.NativeGO===null&&p.newSlotInitialized===false&&p.NativeCalls===0&&p.CargoStarted===false&&p.controls_published===false&&p.actualX230Stage===null&&p.actualCurrentCandidateBinary===null&&p.actualNormal117===null&&p.actualFull34===null&&p.actualLAN===null);
 return {schema:"heptabao.x2304a.two-qualified-bundle-final-binding.checks.r1",passed:true,check_count:checks.length,checks,NativeCalls:0,GitCalls:0,templateAlgorithmChanged:false,binderChanged:false,actualX230Stage:false};
}