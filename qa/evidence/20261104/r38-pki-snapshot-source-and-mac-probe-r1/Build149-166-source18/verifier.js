function verify(input){
 const rows=[],ck=(name,ok)=>{rows.push({name,passed:ok===true});if(ok!==true)throw Error(name);};
 const pins=input.pins,g=input.groups,raw=input.groupsRaw,expected=gitBlobMeta(raw);
 ck("groups_original_digest_unchanged",expected.blob==="5d563b1c7a1b7070395f6d8a03b512ddb019fae0"&&expected.sha256==="35153ff5e90b582f83e4fbbb66ff5c9fb295e95153f08df152cefedecdb50869");
 const rmatch=input.after.runner.match(/assert args.groups_sha256 == '([a-f0-9]{64})'/);
 const lmatch=input.after.launcher.match(/GROUPS_SHA256 = '([a-f0-9]{64})'/);
 const pmatch=input.after.publisher.match(/^PINS = (\{[\s\S]*?^\})/m);
 ck("runner_exact_groups_admission",rmatch&&rmatch[1]===expected.sha256);
 ck("launcher_exact_groups_admission",lmatch&&lmatch[1]===expected.sha256);
 const p=JSON.parse(pmatch[1]),carrier=JSON.parse(input.payload);
 ck("publisher_exact_groups_pin",p["jwt-test-groups.public.json"][0]===expected.bytes&&p["jwt-test-groups.public.json"][1]===expected.sha256);
 for(const [name,body] of Object.entries(input.files)){
  const pin=gitBlobMeta(body);
  ck("publisher_pin_"+name,p[name][0]===pin.bytes&&p[name][1]===pin.sha256);
  ck("carrier_whole_"+name,utf8Text(unb64(carrier.files[name]))===body);
 }
 ck("carrier_exact_three_members",Object.keys(carrier.files).sort().join("|")===Object.keys(input.files).sort().join("|"));
 ck("carrier_size_within_original_cap",gitBlobMeta(input.payload).bytes<=262144);
 const names=g.flatMap(x=>x.tests),existing=new Set(g[2].tests.concat(g[3].tests)),newNames=new Set(g[0].tests);
 ck("four_original_family_caps",g.length===4&&g.every(x=>x.runtime_seconds===600));
 ck("family_shapes",JSON.stringify(g.map(x=>[x.label,x.libtest_profile,x.tests.length]))===JSON.stringify([["native-jwt-pki-file17","file",17],["native-jwt-pki-default17","default",17],["legacy-jwt-default63","default",63],["native-auth-identity-default69","default",69]]));
 ck("same_new_names_two_profiles",JSON.stringify(g[0].tests)===JSON.stringify(g[1].tests));
 ck("149_unique_166_instances",new Set(names).size===149&&names.length===166);
 ck("132_existing_17_new_disjoint",existing.size===132&&newNames.size===17&&[...newNames].every(n=>!existing.has(n)));
 ck("132_plus_17_equals_149",existing.size+newNames.size===149);
 ck("132_plus_34_equals_166",existing.size+2*newNames.size===166);
 ck("runner_new_count_17",input.after.runner.includes("'new_unique_test_total': 17, 'existing_unique_test_total': 132,"));
 ck("launcher_jwt15_30_separate",input.after.launcher.includes("new_jwt_test_names=15, new_jwt_profile_instances=30,"));
 ck("launcher_pki2_4_separate",input.after.launcher.includes("new_pki_test_names=2, new_pki_profile_instances=4,"));
 const definitions=raw=>{const a=raw.split("\n"),out={};for(let i=0;i<a.length;i++){const m=/^def ([A-Za-z_][A-Za-z_0-9]*)\(/.exec(a[i]);if(!m)continue;let j=i+1;for(;j<a.length;j++)if(a[j]!==""&&!/^\s/.test(a[j]))break;out[m[1]]=a.slice(i,j).join("\n");}return out;};
 for(const kind of ["runner","launcher","publisher"]){
  let f=input.before[kind];for(const x of input.replacements[kind]){ck(kind+"_replacement_forward_"+input.replacements[kind].indexOf(x),f.split(x.from).length-1===x.count);f=f.split(x.from).join(x.to);}
  ck(kind+"_exact_whole_forward",f===input.after[kind]);
  for(const x of [...input.replacements[kind]].reverse())f=f.split(x.to).join(x.from);
  ck(kind+"_exact_whole_reverse",f===input.before[kind]);
  ck(kind+"_definitions_byte_equal",JSON.stringify(definitions(input.before[kind]))===JSON.stringify(definitions(input.after[kind])));
  ck(kind+"_still_unbound",input.after[kind].includes("BINDING_READY = False"));
  ck(kind+"_no_old_groups_digest",!input.after[kind].includes("8651fc3043a14556734d2e1992ac941ffbd812671fa0f3486d8813084e5918ba"));
 }
 return {schema:"heptabao.jwt-pki-build22-correction-checks.r2",scope:"Pure V8 source and data checks only; no Python module, Rust, compiler or Native execution.",passed:rows.length,checks:rows};
}
