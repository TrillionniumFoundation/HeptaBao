function verifyBuildShapeR3(input,h,d) {
 const checks=[];function need(name,ok,detail=null){checks.push({name,pass:!!ok,detail});if(!ok)throw Error(name);}function eq(a,b){return JSON.stringify(a)===JSON.stringify(b);}
 function defs(s){const rows=s.split("\n"),out=[];for(let i=0;i<rows.length;i++){if(!/^def [A-Za-z0-9_]+\(/.test(rows[i]))continue;let j=i+1;while(j<rows.length&&(!rows[j]||/^\s|^#/.test(rows[j])))j++;out.push({name:rows[i].match(/^def (\w+)/)[1],text:rows.slice(i,j).join("\n")});i=j-1;}return out;}
 const {before,after,payloadBefore,payload,files,diffs}=input;
 for(const n of["launcher","publisher"]){const a=d.applyStrictUnified(before[n],diffs[n]),b=d.applyStrictUnified(after[n],diffs[n],true);need("strict_forward:"+n,a.text===after[n]&&a.hunks===1);need("strict_reverse:"+n,b.text===before[n]&&b.hunks===1);need("all_functions_unchanged:"+n,eq(defs(before[n]),defs(after[n])));}
 need("whole_runner_unchanged",before.runner===after.runner);
 const old="('native-jwt-file15', 'file', 15), ('native-jwt-default15', 'default', 15)";
 const neo="('native-jwt-pki-file17', 'file', 17), ('native-jwt-pki-default17', 'default', 17)";
 need("sole_launcher_change",before.launcher.split(old).length===2&&before.launcher.replace(old,neo)===after.launcher);
 const groups=JSON.parse(files["jwt-test-groups.public.json"]),shape=groups.map(g=>[g.label,g.libtest_profile,g.tests.length]);
 function tupleRows(s){return [...s.matchAll(/\('([^']+)', '(file|default)', (\d+)\)/g)].map(x=>[x[1],x[2],Number(x[3])]);}
 function launcherShape(s){const start=s.indexOf("assert [(g['label'], g['libtest_profile'], len(g['tests'])) for g in groups] == [");need("bounded_launcher_shape_present",start>=0);return tupleRows(s.slice(start,s.indexOf("\nassert all(set(g)",start)));}
 const runnerStart=after.runner.indexOf("EXPECTED_GROUP_SHAPES = ");
 need("bounded_runner_shape_present",runnerStart>=0);
 const runnerShape=tupleRows(after.runner.slice(runnerStart,after.runner.indexOf("]\n",runnerStart)+2));
 need("old_launcher_negative_refuses_exact_frozen_table",!eq(launcherShape(before.launcher),shape));
 need("new_launcher_accepts_exact_frozen_table",eq(launcherShape(after.launcher),shape));
 need("runner_matches_same_table",eq(runnerShape,shape));
 need("four_expected_groups",eq(shape,[["native-jwt-pki-file17","file",17],["native-jwt-pki-default17","default",17],["legacy-jwt-default63","default",63],["native-auth-identity-default69","default",69]]));
 need("same17_two_profiles",eq(groups[0].tests,groups[1].tests));
 need("no_duplicate_each_group",groups.every(g=>new Set(g.tests).size===g.tests.length));
 need("all_four_caps600",groups.every(g=>g.runtime_seconds===600));
 need("unique149",new Set(groups.flatMap(g=>g.tests)).size===149);
 need("instances166",groups.reduce((n,g)=>n+g.tests.length,0)===166);
 need("new17",groups[0].tests.length===17);
 need("existing132",groups[2].tests.length+groups[3].tests.length===132);
 need("JWT15_plus_PKI2",groups[0].tests.filter(x=>x.includes("pki_tests::")).length===2&&groups[0].tests.filter(x=>!x.includes("pki_tests::")).length===15);
 const table=h.gitBlobMeta(files["jwt-test-groups.public.json"]);
 need("frozen_groups_sha",table.sha256==="35153ff5e90b582f83e4fbbb66ff5c9fb295e95153f08df152cefedecdb50869");
 for(const [n,source]of Object.entries(after))need("groups_digest:"+n,source.includes(table.sha256));
 const cp=JSON.parse(payload),op=JSON.parse(payloadBefore);
 need("payload_schema_unchanged",cp.schema===op.schema&&cp.schema==="heptabao.native-jwt-pki-build-control-inputs.v1");
 need("exact_three_roles",eq(Object.keys(cp.files),Object.keys(files)));
 for(const [name,source]of Object.entries(files))need("payload_whole:"+name,h.utf8Text(h.unb64(cp.files[name]))===source);
 need("payload_only_launcher",payload.replace(cp.files["launch_native_jwt_build.py"],op.files["launch_native_jwt_build.py"])===payloadBefore);
 const oldpin=h.gitBlobMeta(before.launcher),newpin=h.gitBlobMeta(after.launcher);
 need("publisher_only_derived_pin",after.publisher.replace(String(newpin.bytes),String(oldpin.bytes)).replace(newpin.sha256,oldpin.sha256)===before.publisher);
 const pinsStart=after.publisher.indexOf("PINS = "),pinsEnd=after.publisher.indexOf("\n}\n",pinsStart)+2;
 const pins=JSON.parse(after.publisher.slice(pinsStart+7,pinsEnd));
 for(const [name,source]of Object.entries(files)){const m=h.gitBlobMeta(source);need("publisher_PIN:"+name,eq(pins[name],[m.bytes,m.sha256]));}
 for(const [n,s]of Object.entries(after))need("still_unbound:"+n,s.includes("BINDING_READY = False"));
 need("payload_below_original_cap",h.gitBlobMeta(payload).bytes<=262144);
 return {schema:"heptabao.native-jwt-pki.build-shape-correction-r3.actual.v1",status:"PASS_SOURCE_ONLY_UNBOUND",checks:checks.length,results:checks,definitions_preserved:Object.fromEntries(Object.entries(after).map(([n,s])=>[n,defs(s).map(x=>x.name)])),groups:shape,denominators:{existing_unique:132,new_jwt_unique:15,new_pki_unique:2,new_unique:17,selected_unique:149,profile_instances:166},original_18_preserved:true,Native:0,PythonExecutions:0,Cargo:0,productTests:0};
}