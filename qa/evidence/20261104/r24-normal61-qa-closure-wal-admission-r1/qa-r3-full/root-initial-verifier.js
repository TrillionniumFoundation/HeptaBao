function verifyQAR3FullActual(input,parse,utf8,latin1,sha256,unb64){
 const raw=input.raw,checks=[],ck=(n,v)=>{if(!v)throw Error(n);checks.push(n);},obj=p=>parse(raw[p]),hash=s=>sha256(latin1(utf8(s))),same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),root="/home/qian-qi/heptabao-native-h2-qa-df026-20261105-r3",core=obj("actual/result.public.json"),job="1a1ab68bbb6-fc05-4d8a";
 ck("prior_independent_core83_closed",input.coreRoot.status==="PASS_ORIGINAL_BUILD_CLOSURE_AND_SIX_COMPONENTS"&&input.coreRoot.checks===83&&input.coreRoot.job===job&&input.coreRoot.all12_original_children_closed===true&&input.coreRoot.all_input_FDs_closed===true&&input.coreRoot.actual_components_passed===6);
 const recordMap=Object.fromEntries(input.audit.records.map(r=>[r.path,r]));let inherited=0;
 for(const row of input.coreAudit.records.filter(r=>/^(actual|commands|request|sdk)\//.test(r.path))){ck("original_core_same."+row.path,recordMap[row.path]?.blob===row.blob&&recordMap[row.path]?.bytes===row.bytes&&recordMap[row.path]?.sha256===row.sha256);inherited++;}
 ck("core_originals_not_substituted",inherited>=35&&hash(raw["actual/result.public.json"])==="b8a2e83ea012f11cef7dc83bc79758d2b624df7eac2265efddbd32e2880db95e");
 const expectedLabels=["authority-01","streams-01","core-info-01","core-body-01","executable-info-01","component-binary-info-01","components-evidence-01","command-records-a-01","command-records-b-01","command-streams-a-01","command-streams-b-01","build-stdout-info-01","build-stdout-body-01","components-build-stdout-info-01","components-build-stdout-body-01","canonical-lock-info-01","qa-lock-info-01","qa-lock-body-01"].sort();
 const labels=[...new Set(Object.keys(raw).filter(p=>p.startsWith("operations/")&&p.split("/").length===3).map(p=>p.split("/")[1]))].sort(),readProof=obj("verification/original-read-payloads.public.json");
 ck("exact18_operation_labels",same(labels,expectedLabels)&&readProof.operations===18&&readProof.observations.length===18);
 let pageCount=0;
 for(const label of labels){
  const prefix="operations/"+label+"/",adSdk=obj(prefix+"admission.original.json"),ad=parse(adSdk.content[0].text),req=obj(prefix+"request.public.json"),statuses=Object.keys(raw).filter(p=>p.startsWith(prefix+"status-")).sort((a,b)=>Number(a.match(/status-(\d+)/)[1])-Number(b.match(/status-(\d+)/)[1])),sSdk=obj(statuses.at(-1)),s=parse(sSdk.content[0].text),proof=readProof.observations.find(r=>r.label===label);
  ck(label+".unique_original_admission",adSdk.isError===false&&ad.reused===false&&ad.automatic_retry===false&&ad.operation_id===s.operation_id&&ad.tool_name===req.operation.tool&&s.tool_name===req.operation.tool&&req.operation.arguments.host==="rog");
  ck(label+".closed_original_read",sSdk.isError===false&&s.async_state==="completed"&&s.result_state==="stored_observed"&&s.payload_available===true&&s.owned_future_active===false&&s.automatic_retry===false&&proof.operation_id===s.operation_id&&proof.read_tool===s.tool_name);
  const paths=Object.keys(raw).filter(p=>p.startsWith(prefix+"page-")).sort((a,b)=>Number(a.match(/page-(\d+)/)[1])-Number(b.match(/page-(\d+)/)[1]));
  let all=[],offset=0,total=null,digest=null,last=null;
  for(const path of paths){
   const sdk=obj(path),pg=parse(sdk.content[0].text),b=unb64(pg.data_base64);
   ck(label+".page."+offset,sdk.isError===false&&pg.operation_id===s.operation_id&&pg.immutable_snapshot===true&&pg.payload_kind==="native_result"&&pg.automatic_retry===false&&pg.offset===offset&&pg.next_offset===offset+b.length&&b.length>0&&b.length<=16384);
   if(total===null){total=pg.total_bytes;digest=pg.result_sha256;}
   ck(label+".same_snapshot."+offset,pg.total_bytes===total&&pg.result_sha256===digest&&pg.eof===(pg.next_offset===total));
   all.push(...b);offset=pg.next_offset;last=pg;pageCount++;
  }
  const sd=raw["sdk/"+label+".original.json"],nd=raw["actual/"+label+".original.json"],sdk=obj("sdk/"+label+".original.json");
  ck(label+".exact_whole_original_sdk",last?.eof===true&&offset===total&&sha256(latin1(all))===digest&&latin1(all)===latin1(utf8(sd))&&proof.original_sdk_bytes===total&&proof.original_sdk_sha256===digest);
  ck(label+".original_native_and_proof",sdk.isError===false&&sdk.content[0].text===nd&&proof.native_bytes===utf8(nd).length&&proof.native_sha256===hash(nd)&&proof.complete===true&&proof.owned_future_active===false&&proof.automatic_retry===false);
 }
 ck("all33_immutable_pages",pageCount===33&&readProof.immutable_page_count===33);
 const observed=new Map();
 for(const label of labels.filter(x=>obj("operations/"+x+"/request.public.json").operation.tool==="read_multiple_files")){
  const batch=obj("actual/"+label+".original.json"),req=obj("operations/"+label+"/request.public.json");
  ck(label+".untruncated_batch",batch.truncated===false&&batch.files.length>0);
  for(const file of batch.files){
   ck(label+".file."+file.path.slice(root.length+1),file.path.startsWith(root+"/")&&file.eof===true&&file.size===utf8(file.text).length&&file.sha256===hash(file.text));
   if(observed.has(file.path))ck(label+".repeat_body_same."+file.path,observed.get(file.path).text===file.text&&observed.get(file.path).version===file.version);
   observed.set(file.path,file);
  }
 }
 const commandPaths=Object.keys(raw).filter(x=>x.startsWith("commands/")).sort(),expectedPaths=core.commands.flatMap(c=>[".public.json",".stdout",".stderr"].map(s=>"commands/"+c.label+s)).sort();
 ck("exact12_records24_streams",core.commands.length===12&&new Set(core.commands.map(c=>c.label)).size===12&&same(commandPaths,expectedPaths));
 for(const c of core.commands){
  const rp="commands/"+c.label+".public.json",rr=observed.get(root+"/"+c.label+".public.json");
  ck(c.label+".original_record",same(obj(rp),c)&&rr?.text===raw[rp]);
  for(const stream of ["stdout","stderr"]){
   const p="commands/"+c.label+"."+stream,body=raw[p];
   ck(c.label+"."+stream+".whole_hash",hash(body)===c[stream+"_sha256"]);
   if(!(stream==="stdout"&&["build","components-build"].includes(c.label)))ck(c.label+"."+stream+".original_read",observed.get(root+"/"+c.label+"."+stream)?.text===body);
  }
 }
 const cargo={};
 for(const [label,role,test]of[["build","executable",false],["components-build","component_binary",true]]){
  const info=obj("actual/"+label+"-stdout-info-01.original.json"),body=obj("actual/"+label+"-stdout-body-01.original.json"),req=obj("operations/"+label+"-stdout-body-01/request.public.json"),data=unb64(body.data_base64),text=raw["commands/"+label+".stdout"],events=text.trimEnd().split("\n").map(JSON.parse),r=core[role];
  ck(label+".actual_binary_read",req.operation.tool==="binary_read"&&req.operation.arguments.path===root+"/"+label+".stdout"&&req.operation.arguments.expected_version===info.version&&body.path===info.path&&info.path===root+"/"+label+".stdout"&&body.version===info.version&&body.offset===0&&body.next_offset===body.size&&body.size===info.size&&body.eof===true&&body.size===data.length&&body.chunk_sha256===sha256(latin1(data))&&body.chunk_sha256===info.sha256&&info.sha256===r.cargo_stdout_sha256&&latin1(data)===latin1(utf8(text)));
  const finish=events.filter(e=>e.reason==="build-finished"),art=events.filter(e=>e.reason==="compiler-artifact"&&e.target?.name==="heptabao-native-h2-qa"&&e.executable);
  ck(label+".75_complete_cargo_events",events.length===75&&events.every(e=>e&&typeof e==="object"&&!Array.isArray(e))&&finish.length===1&&finish[0].success===true&&events.at(-1)===finish[0]&&!events.some(e=>e.reason==="compiler-message"&&e.message?.level==="error"));
  ck(label+".sole_owned_artifact_profile",art.length===1&&art[0].executable===r.compiler_executable&&art[0].manifest_path===root+"/project/Cargo.toml"&&art[0].target.src_path===root+"/project/native_h2_client.rs"&&same(art[0].features,[])&&same(art[0].profile,r.profile)&&r.profile.opt_level==="3"&&r.profile.debuginfo===0&&r.profile.debug_assertions===true&&r.profile.overflow_checks===true&&r.profile.test===test);
  cargo[label]=events.length;
 }
 for(const phase of ["before","after"]){ck(phase+".instrument_source_exact",raw["commands/source-"+phase+"-commit.stdout"]==="df026fe323dd7cf0f0ec57d7d2d9c5a79897053c\n"&&raw["commands/source-"+phase+"-tree.stdout"]==="424463ccd2310ddc1e7b2bbcd7b7af29ae58c825\n"&&raw["commands/source-"+phase+"-status.stdout"]==="");}
 const lockraw=raw["artifacts/Cargo.lock"],canonical=raw["reference/published-inert-inputs/inputs/canonical.Cargo.lock"],qi=obj("actual/qa-lock-info-01.original.json"),ci=obj("actual/canonical-lock-info-01.original.json");
 ck("qa_lock_actual_body_whole",observed.get(root+"/artifacts/Cargo.lock")?.text===lockraw&&hash(lockraw)===qi.sha256&&qi.sha256===core.lock_subset.qa_lock_sha256&&utf8(lockraw).length===qi.size);
 ck("canonical_lock_whole_hash_provenance",hash(canonical)==="d2d07ea13e42a8d4ba65fafc642ca98ae1a7de68f6cd46a69043332267f378d5"&&utf8(canonical).length===101193&&ci.sha256===hash(canonical)&&ci.size===101193&&core.lock_subset.canonical_sha256===ci.sha256&&recordMap["reference/published-inert-inputs/inputs/canonical.Cargo.lock"].blob==="f3b5394e274d5da977e7e1ec89940b0d0e9f55ff");
 for(const [name,i]of[["qa",qi],["canonical",ci]])ck(name+".lock_metadata",i.path===root+"/artifacts/"+(name==="qa"?"Cargo.lock":"canonical.Cargo.lock")&&i.mode===384&&i.metadata.mode===384&&i.metadata.uid===1000&&i.metadata.gid===1000&&i.metadata.link_count===1);
 function packages(s){
  const parts=s.split(/^\[\[package\]\]\s*$/m);ck("cargo_lock_header."+hash(s).slice(0,8),parts.length>1&&/^version = 4$/m.test(parts[0]));
  return parts.slice(1).map(t=>{
   const o={};for(const k of ["name","version","source","checksum"]){const matches=[...t.matchAll(new RegExp("^"+k+" = (\"[^\"\\n]*\")$","gm"))];if(matches.length>1)throw Error("duplicate "+k);if(matches.length)o[k]=JSON.parse(matches[0][1]);}
   if(!o.name||!o.version)throw Error("missing package identity");return o;
  });
 }
 const canonicalPkgs=packages(canonical),actualPkgs=packages(lockraw),key=o=>JSON.stringify([o.name,o.version,o.source??null]),allowed=new Map(canonicalPkgs.map(p=>[key(p),p.checksum??null]));
 ck("canonical_package_keys_unique",allowed.size===canonicalPkgs.length);
 ck("qa_package_keys_unique",new Set(actualPkgs.map(key)).size===actualPkgs.length&&actualPkgs.length===77);
 const owned=actualPkgs.filter(p=>p.name==="heptabao-native-h2-qa"),members=actualPkgs.filter(p=>p.name!=="heptabao-native-h2-qa").sort((a,b)=>a.name.localeCompare(b.name)||a.version.localeCompare(b.version)||a.source.localeCompare(b.source));
 ck("one_owned_qa_package",owned.length===1&&owned[0].version==="0.1.0"&&owned[0].source===undefined&&owned[0].checksum===undefined);
 for(const p of members)ck("registry."+p.name+"@"+p.version,p.source==="registry+https://github.com/rust-lang/crates.io-index"&&allowed.has(key(p))&&allowed.get(key(p))===p.checksum);
 const norm=x=>JSON.stringify(x.map(p=>[p.name,p.version,p.source,p.checksum]));
 ck("all76_dependency_versions_sources_checksums",members.length===76&&core.lock_subset.registry_package_count===76&&core.lock_subset.owned_qa_package_count===1&&core.lock_subset.exact_version_source_checksum_subset===true&&norm(members)===norm([...core.lock_subset.packages].sort((a,b)=>a.name.localeCompare(b.name)||a.version.localeCompare(b.version)||a.source.localeCompare(b.source))));
 for(const [prefix,count]of[["core-closure",106],["archive",220]]){
  const e=obj("verification/"+prefix+"-exec.original.json"),v=obj("verification/"+prefix+"-stdout.original.json");
  ck(prefix+".actual_lossless_verifier_result",e.exit_code===0&&e.output===raw["verification/"+prefix+"-stdout.original.json"]&&v.check_count===count&&v.checks.length===count&&v.checks.every(x=>x.passed===true)&&v.host_or_child_calls_by_this_verifier===0);
 }
 ck("six_components_one30second_original_budget",core.commands.find(c=>c.label==="components").outer_cap_seconds===30&&input.coreRoot.six_components_shared_seconds===30);
 const analysis=obj("ANALYSIS.public.json");ck("correct_qualification_scope",analysis.limits.product_or_http_requests===0&&analysis.limits.full_replacement===false&&analysis.limits.fixture_or_transport_go===false&&analysis.next_product_identity.normal61_qualification_not_inherited===true);
 return{schema:"heptabao.root.qa-r3-complete-actual.v1",status:"PASS_QUALIFIED_QA_INSTRUMENT_ONLY",packet:input.audit.tree,files:input.audit.files,bytes:input.audit.bytes,merkle_trees:input.audit.merkle.trees_verified,check_count:checks.length,checks,job,prior_independent_core_checks:83,inherited_whole_originals:inherited,closed_read_operations:18,immutable_original_sdk_pages:pageCount,actual_command_records:12,actual_command_streams:24,cargo_events:cargo,exact_registry_dependencies:76,actual_components_passed:6,components_shared_original_seconds:30,instrument_commit:"df026fe323dd7cf0f0ec57d7d2d9c5a79897053c",instrument_tree:"424463ccd2310ddc1e7b2bbcd7b7af29ae58c825",retained_artifacts:input.coreRoot.retained_artifacts,all_original_owned_children_closed:true,all_input_FDs_closed:true,canonical_copy_body_provenance:"retained independent whole file_info hash matches previous root-accepted input bytes; no new retained-copy payload body read claimed",host_calls_by_verifier:0,product_requests:0,current_product_qualified:false,h2_fixture_go:false,transport_go:false,full_replacement:false};
}