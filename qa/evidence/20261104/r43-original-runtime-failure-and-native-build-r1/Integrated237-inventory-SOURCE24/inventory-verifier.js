function verifyExactCombinedTestInventory(input) {
 const checks=[],ck=(name,ok)=>{checks.push({name,ok:!!ok});if(!ok)throw Error(name);};
 const meta=input.meta;
 for(const [name,x]of Object.entries(input.originals))ck("original_whole_"+name,JSON.stringify(meta(x.raw))===JSON.stringify(x.pin));
 for(const [name,x]of Object.entries(input.testSources))ck("test_source_whole_"+name,JSON.stringify(meta(x.raw))===JSON.stringify(x.pin));
 const cg=JSON.parse(input.originals.Cgroups.raw),ng=JSON.parse(input.originals.N44groups.raw);
 const C=cg.flatMap(g=>g.tests.map(name=>({crate:"heptabao-server",libtest_profile:g.libtest_profile,name,group:g.label})));
 ck("four_original_C_groups",cg.length===4&&cg.map(g=>g.tests.length).join(",")==="17,17,63,69");
 ck("original_C_profiles",cg.map(g=>g.libtest_profile).join(",")==="file,default,default,default");
 ck("original_C_group_budgets_unchanged",cg.every(g=>g.runtime_seconds===600));
 function tuple(name) {
  const re=new RegExp("^"+name+" = \\(([\\s\\S]*?)^\\)","m"),m=re.exec(input.originals.Nrunner.raw);
  ck("normal_constant_"+name,!!m);
  const names=[...m[1].matchAll(/"([A-Za-z0-9_:]+)"/g)].map(m=>m[1]);
  ck("normal_constant_only_literal_names_"+name,m[1].replace(/"[A-Za-z0-9_:]+"/g,"").replace(/[\s,]/g,"")==="");
  return names;
 }
 const N=ng.flatMap(g=>g.tests.map(name=>({crate:"heptabao-server",libtest_profile:"default",name,group:g.label})));
 ck("normal_six_original_groups44",ng.length===6&&N.length===44);
 for(const [constant,group,count]of [["INGRESS_OBSERVER_TESTS","ingress_observer",7],["COLD_H2_TESTS","cold_h2",9],["SAME_ROOT_PUBLICATION_TESTS","same_root_publication",1]]){
  const names=tuple(constant);ck("normal_named_count_"+group,names.length===count);
  N.push(...names.map(name=>({crate:"heptabao-server",libtest_profile:"default",name,group})));
 }
 const B=[];
 for(const spec of input.snapshotSpecs) {
  const x=input.testSources[spec.file],names=[...x.raw.matchAll(/#\[test\]\s*(?:#\[[^\n]+\]\s*)*fn ([A-Za-z0-9_]+)\(/g)].map(m=>m[1]);
  ck("snapshot_exact_source_count_"+spec.family,names.length===spec.count);
  B.push(...names.map(name=>({crate:spec.crate,libtest_profile:spec.profile,name:spec.prefix+name,
    family:spec.family,source:x.pin,sourceFile:spec.file,sourceEvidence:x.evidence})));
 }
 const minimal=xs=>xs.map(x=>[x.crate,x.libtest_profile,x.name]);
 ck("C_full_entry_order_matches_inventory",JSON.stringify(minimal(C))===JSON.stringify(minimal(input.expected.C)));
 ck("snapshot_full_entry_order_matches_inventory",JSON.stringify(minimal(B))===JSON.stringify(minimal(input.expected.B)));
 ck("normal_full_entry_order_matches_inventory",JSON.stringify(minimal(N))===JSON.stringify(minimal(input.expected.N)));
 const uk=x=>x.crate+"\0"+x.name,ek=x=>x.crate+"\0"+x.libtest_profile+"\0"+x.name;
 const set=(xs,f)=>new Set(xs.map(f));
 const CS=set(C,uk),BS=set(B,uk),NS=set(N,uk);
 ck("C149unique166profileentries",CS.size===149&&C.length===166&&set(C,ek).size===166);
 ck("snapshot27unique27entries",BS.size===27&&B.length===27&&set(B,ek).size===27);
 ck("normal61unique61entries",NS.size===61&&N.length===61&&set(N,ek).size===61);
 const intersect=(a,b)=>[...a].filter(k=>b.has(k));
 const intersections={C_snapshot:intersect(CS,BS),C_normal61:intersect(CS,NS),snapshot_normal61:intersect(BS,NS)};
 ck("all_three_pairwise_intersections_empty",Object.values(intersections).every(v=>v.length===0));
 const CB=C.concat(B),CBN=CB.concat(N);
 ck("C_snapshot_union176_193",set(CB,uk).size===176&&CB.length===193&&set(CB,ek).size===193);
 ck("required_final_union237_254",set(CBN,uk).size===237&&CBN.length===254&&set(CBN,ek).size===254);
 const profiles={};for(const x of CBN){const k=x.crate+"/"+x.libtest_profile;profiles[k]=(profiles[k]||0)+1;}
 ck("exact_final_profiles",profiles["heptabao-server/default"]===220&&profiles["heptabao-server/file"]===17&&profiles["heptabao-ha-service/ha-native-v6-peer-ingress"]===17&&Object.keys(profiles).length===3);
 ck("ha_explicit_feature_exists",input.originals.haCargo.raw.includes('native-v6-peer-ingress = [')&&input.originals.haCargo.raw.includes('default = []'));
 ck("server_default_native_ha_exists",input.originals.serverCargo.raw.includes('default = ["native-v6-storage", "native-v6-ha"]'));
 ck("server_feature_propagates_ha_peer_ingress",input.originals.serverCargo.raw.includes('native-v6-ha = ["native-v6-storage", "heptabao-ha-service/native-v6-peer-ingress"'));
 const cr=input.originals.Crunner.raw;
 ck("C_file_profile_exact_feature_selection",cr.includes("['--no-default-features', '--features', 'native-v6-storage']"));
 ck("C_default_profile_exact_feature_selection",cr.includes("['default', 'native-v6-ha', 'native-v6-storage']"));
 const unique=new Map();for(const x of CBN){const key=uk(x);if(!unique.has(key))unique.set(key,{crate:x.crate,name:x.name,profiles:[]});const y=unique.get(key);if(!y.profiles.includes(x.libtest_profile))y.profiles.push(x.libtest_profile);}
 return {schema:"heptabao.combined-candidate.exact-test-inventory-check.r1",pass:true,checks,
  intersections,counts:{C:{unique:149,entries:166},snapshot:{unique:27,entries:27},normal:{unique:61,entries:61},
   withoutNormal:{unique:176,entries:193},requiredWithNormal:{unique:237,entries:254}},profiles,
  executionEntries:CBN.map((x,i)=>({ordinal:i+1,...x})),
  uniqueCases:[...unique.values()].map((x,i)=>({ordinal:i+1,...x})),
  nativeCalls:0,cargoCalls:0,testsExecuted:0,actualLibtestListObserved:false,
  budgetsChanged:false,ordinaryNoDefaultCheckCountedAsTest:false,
  note:"Inventory only. New candidate, exact retained artifacts, runtime requests, deadlines and execution authorization remain separate."};
}