function verifyNormal5BoundSource(r,a,rootCore,coreAudit,preflightAudit,utf8,sha,unb64,byteString,applyPatch){
const checks=[],changes=[];const ck=(n,v)=>{if(!v)throw Error(n);checks.push(n);};
const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const canonical=v=>v&&typeof v==="object"?Array.isArray(v)?v.map(canonical):Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
const same=(a,b)=>eq(canonical(a),canonical(b));
const binding=JSON.parse(r["binding.public.json"]),table=binding.files;
const old=JSON.parse(r["references/original-normal5-inert.request.json"]),oldPayload=JSON.parse(old.stdin);
const req=JSON.parse(r["dispatch/inert.request.json"]),relay=JSON.parse(r["dispatch/relay.request.json"]),payload=JSON.parse(r["dispatch/inert.stdin.json"]);
const names=["sender.py","receiver.py","relay.py","inert-carrier.py"];
const D="/home/qian-qi/heptabao-ha-closure-20261103-r1";
function assignment(code,n){let rx=n==="FILES"?/^FILES=(\[[\s\S]*?^\])/m:n==="PINS"?/^PINS = (\{[\s\S]*?^\})/m:/^HELPERS=(\{[^\n]+\})/m;const m=code.match(rx);ck("unique assignment "+n,!!m&&code.match(new RegExp("^"+n+"\\s*=","gm")).length===1);return {whole:m[0],text:m[1],value:JSON.parse(m[1])};}
function replaceOne(code,from,to,name){ck("unique reviewed literal "+name,code.split(from).length===2);changes.push({name,from,to});return code.replace(from,to);}
ck("exact packet denominator",a.tree==="1c48f9519ce6d13dbe2f4484db279102c9e33676"&&a.files===39&&a.bytes===494117&&a.merkle.trees_verified===10);
ck("current root147 qualification is already core accepted",rootCore.status==="PASS_CORE_ORIGINAL_TERMINAL_AND_NEW_TEST_STREAMS"&&binding.normal61_root_review==="fdf6e1228b24fdbcb56f350f88a7069c137d8661");
ck("current commit/tree only",binding.source_commit==="4e808d0ecb1bcded22870a7ec960dfb2491cf6ec"&&binding.source_tree==="eba5e650bd080b8ad41ea52a2bc68867f541d255");
ck("new control/incoming namespace",binding.source_controls===D+"/normal-same-root-publication-shared-artifact-controls-r1"&&binding.destination===D+"/normal-same-root-publication-shared-artifacts-r1/incoming");
ck("actual five files and aggregate",eq(table.map(x=>x.name),["heptabao-server","native-build.public.json","normal-release-result.public.json","normal-release-tests-result.public.json","groups.json"])&&table.reduce((s,x)=>s+x.bytes,0)===110287359&&binding.bytes===110287359);
ck("exact unchanged original caps",same(binding.original_caps,{inert_outer:60,inert_payload_bytes:262144,relay:300,endpoint:90,connect:10,cleanup:[5,5],supervisor:360}));
let hunks=0;
for(const name of names){
 const before=r["before/"+name],after=r["candidate/"+name],p=applyPatch(before,r["diffs/"+name+".diff"]);
 ck("strict full patch "+name,p.text===after);hunks+=p.hunks;
 ck("before source is original dispatch payload "+name,name==="inert-carrier.py"?old.args[4]===before:byteString(unb64(oldPayload.files[name]))===before);
 let expected=before;
 if(name!=="inert-carrier.py"){
   const b=assignment(before,"FILES"),c=assignment(after,"FILES");
   ck("actual five-row literal table "+name,same(c.value,table));
   expected=replaceOne(expected,b.whole,c.whole,name+" FILES table");
   expected=replaceOne(expected,"HEAD='df026fe323dd7cf0f0ec57d7d2d9c5a79897053c'","HEAD='"+binding.source_commit+"'",name+" HEAD");
   expected=replaceOne(expected,"TREE='424463ccd2310ddc1e7b2bbcd7b7af29ae58c825'","TREE='"+binding.source_tree+"'",name+" TREE");
   expected=replaceOne(expected,"heptabao.df026.","heptabao.4e808.",name+" schema");
   ck("ready flag unchanged true "+name,after.includes("ACTUAL_INPUTS_READY=True"));
 }
 if(name==="receiver.py")expected=replaceOne(expected,"normal-cold-h2-shared-artifacts-r1","normal-same-root-publication-shared-artifacts-r1",name+" ROOT");
 if(name==="relay.py"){
   expected=replaceOne(expected,"five fixed public df026 normal-build artifacts.","five fixed public 4e808 normal-build artifacts.","relay doc label");
   expected=replaceOne(expected,"normal-cold-h2-shared-artifact-controls-r1","normal-same-root-publication-shared-artifact-controls-r1","relay SOURCES");
   expected=replaceOne(expected,"normal-cold-h2-shared-artifacts-r1","normal-same-root-publication-shared-artifacts-r1","relay ROOT");
   const b=assignment(before,"HELPERS"),c=assignment(after,"HELPERS");
   ck("derived endpoint hashes",same(c.value,{"sender.py":sha(r["candidate/sender.py"]),"receiver.py":sha(r["candidate/receiver.py"])}));
   expected=replaceOne(expected,b.whole,c.whole,"relay HELPERS");
 }
 if(name==="inert-carrier.py"){
   expected=replaceOne(expected,"normal-cold-h2-shared-artifact-controls-r1","normal-same-root-publication-shared-artifact-controls-r1","inert BASE");
   const b=assignment(before,"PINS"),c=assignment(after,"PINS");
   ck("inert pins exact three candidate source bytes/hashes",same(c.value,Object.fromEntries(names.slice(0,3).map(n=>[n,[utf8(r["candidate/"+n]).length,sha(r["candidate/"+n])]]))));
   expected=replaceOne(expected,b.whole,c.whole,"inert PINS");
   expected=replaceOne(expected,"heptabao.df026-shared-normal5-inert-carrier.v1","heptabao.4e808-shared-normal5-inert-carrier.v1","inert output schema");
   expected=replaceOne(expected,"heptabao.df026-shared-normal5-inputs.v1","heptabao.4e808-shared-normal5-inputs.v1","inert stdin schema");
 }
 ck("entire source changed only reviewed literal slots "+name,expected===after);
}
ck("strict eight total hunks",hunks===8);
for(const [i,row] of table.entries()){
 const p="metadata/"+row.name+".file_info.original.json",m=JSON.parse(r[p]),sdk=JSON.parse(r["sdk/"+row.name+".file_info.original.json"]);
 ck("original SDK contains exact native metadata "+row.name,sdk.isError===false&&sdk.content.some(x=>x.type==="text"&&x.text===r[p]));
 ck("actual path size SHA version and mode "+row.name,row.path===m.path&&row.bytes===m.size&&row.sha256===m.sha256&&row.version===m.version&&row.source_mode===m.mode);
 ck("actual uid gid nlink and target mode "+row.name,m.metadata.uid===1000&&m.metadata.gid===1000&&m.metadata.link_count===1&&m.metadata.mode===(i===0?320:384)&&row.target_mode===(i===0?320:256));
 if(i>0){
   const body=r["actual/"+row.name],meta=a.records.find(x=>x.path==="actual/"+row.name);
   ck("actual whole public body "+row.name,utf8(body).length===row.bytes&&sha(body)===row.sha256);
   ck("root-accepted current actual body membership "+row.name,(i===4?preflightAudit:coreAudit).records.some(x=>x.blob===meta.blob));
 }
}
const native=JSON.parse(r["actual/native-build.public.json"]),normal=JSON.parse(r["actual/normal-release-result.public.json"]),core=JSON.parse(r["actual/normal-release-tests-result.public.json"]);
ck("server identity tied to normal/native actual provenance",native.binary_sha256===table[0].sha256&&normal.artifacts["heptabao-server"].sha256===table[0].sha256&&normal.artifacts["heptabao-server"].bytes===table[0].bytes);
ck("normal/native source current",native.source_commit===binding.source_commit&&normal.source_commit===binding.source_commit&&native.source_tree===binding.source_tree&&normal.source_tree===binding.source_tree);
ck("exact native receipt parent hash",native.provenance.result_sha256===table[2].sha256);
ck("normal/native exit and actual features",normal.build_exit_code===0&&native.build_exit_code===0&&eq(native.features,["default","native-v6-ha","native-v6-storage"]));
ck("inert exact isolated source argv",eq(req.args,["-I","-S","-B","-c",r["candidate/inert-carrier.py"]]));
ck("inert raw stdin identical and bounded",req.stdin===r["dispatch/inert.stdin.json"]&&utf8(req.stdin).length===44751&&utf8(req.stdin).length<=262144);
ck("inert exact key and 60s",req.idempotency_key==="heptabao-4e808-normal5-controls-inert-r1-895d6cc9"&&req.timeout_seconds===60);
ck("both desktop immutable parent",req.host==="desktop"&&relay.host==="desktop"&&req.executable==="/usr/bin/python3"&&relay.executable==="/usr/bin/python3"&&req.cwd===D&&relay.cwd===D);
ck("future relay exact argv and no extra SHA argument",eq(relay.args,["-I","-S","-B",binding.source_controls+"/relay.py"])&&relay.timeout_seconds===360&&relay.idempotency_key==="heptabao-4e808-normal5-artifact-relay-r1-075193b0");
ck("stdin three and only three source files",eq(Object.keys(payload).sort(),["files","schema"])&&payload.schema==="heptabao.4e808-shared-normal5-inputs.v1"&&eq(Object.keys(payload.files).sort(),names.slice(0,3).sort()));
for(const n of names.slice(0,3))ck("whole decoded stdin exact "+n,byteString(unb64(payload.files[n]))===r["candidate/"+n]);
const tests=JSON.parse(r["verification/stdout.json"]),exec=JSON.parse(r["verification/executor.original.json"]);
ck("author 53 pure source checks retained",tests.checks.length===53&&tests.checks.every(x=>x.passed)&&tests.total_definitions_unchanged===42&&tests.candidate_modules_executed===0&&exec.exit_code===0&&exec.output===r["verification/stdout.json"]);
return {schema:"heptabao.root.normal5-current-actual-bound-source-review.r1",status:"PASS_EXACT_INERT_SOURCE_ONLY",checksPassed:checks.length,checks,packet:{tree:a.tree,files:a.files,bytes:a.bytes},strictHunks:hunks,reviewedLiteralSlots:changes.length,changes,entireSourceOutsideReviewedLiteralSlotsUnchanged:true,orderedDefinitionsUnchanged:42,inertRequest:a.records.find(x=>x.path==="dispatch/inert.request.json"),futureRelayRequest:a.records.find(x=>x.path==="dispatch/relay.request.json"),currentFiles:table,bytes:binding.bytes,scope:{inertMayCreateOnlyThreeControlsAndReceipt:true,transportNotYetAuthorized:true,currentProductRuntimeNotExecuted:true,fullNormalArchivePending:true,oldInstrumentIdentitySeparate:true,fullReplacement:false},groupsInfoScope:binding.groups_metadata_provenance};
}