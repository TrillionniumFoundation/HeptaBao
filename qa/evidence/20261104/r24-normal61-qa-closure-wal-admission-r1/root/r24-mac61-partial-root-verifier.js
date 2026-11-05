function verifyMac61OriginalPartial(raw,audit,parse,utf8,latin1,sha256){
 const checks=[],ck=(n,v)=>{if(!v)throw Error(n);checks.push(n);},obj=p=>parse(raw[p]),hash=s=>sha256(latin1(utf8(s))),same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),core=obj("core/result.public.json"),root="/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261105-same-root-publication-normal-r2/normal-release-tests-r1",seen=new Set();
 const recpaths=audit.records.filter(x=>x.path.startsWith("commands/")&&x.path.endsWith(".public.json")).map(x=>x.path);
 ck("exact48_records_and94_streams",recpaths.length===48&&audit.records.filter(x=>x.path.startsWith("commands/")&&/\.(stdout|stderr)$/.test(x.path)).length===94);
 for(const p of Object.keys(raw).filter(x=>/^native\/(?:record|small_stream)_batch\d+\.json$/.test(x))){const n=obj(p),sdk=obj("sdk/"+p.slice(7));ck(p+".original_SDK_native_exact",sdk.isError===false&&sdk.content[0].text===raw[p]);ck(p+".bounded_independent_complete",n.atomic_snapshot===false&&n.truncated===false&&n.files.length<=16);for(const file of n.files){const path="commands/"+file.path.split("/").pop();ck(path+".independent_whole_original",file.path===root+"/"+file.path.split("/").pop()&&file.eof===true&&file.text===raw[path]&&file.size===utf8(file.text).length&&file.sha256===hash(file.text)&&typeof file.version==="string"&&!seen.has(path));seen.add(path);}}
 const critical=obj("native/critical_read.response.json"),criticalSdk=obj("sdk/critical_read.sdk.json"),newFiles=critical.files.filter(x=>x.path.split("/").pop().startsWith("same-root-publication-1."));
 ck("critical_original_SDK_and_three_new_test_files",criticalSdk.isError===false&&criticalSdk.content[0].text===raw["native/critical_read.response.json"]&&critical.truncated===false&&critical.atomic_snapshot===false&&newFiles.length===3);
 for(const file of newFiles){const name=file.path.split("/").pop(),p="commands/"+name;ck(p+".prior_independent_critical_whole_original",file.path===root+"/"+name&&file.eof===true&&file.text===raw[p]&&file.text===raw["core/"+name]&&file.size===utf8(file.text).length&&file.sha256===hash(file.text)&&typeof file.version==="string"&&!seen.has(p));seen.add(p);}
 ck("all142_unique_files_in_actual_reads",seen.size===142);
 const recs=new Map();
 for(const path of recpaths){const r=obj(path),label=path.slice(9,-12),cl=core.cleanup.find(x=>x.label===label),cap=["build","normal-release-build"].includes(label)?1800:label.endsWith("-list")?30:600;
  ck(label+".original_closed_success_and_cap",r.label===label&&r.exit_code===0&&r.timed_out===false&&r.direct_child_reaped===true&&r.remaining.length===0&&r.outer_cap_seconds>0&&r.outer_cap_seconds<=cap&&r.elapsed_seconds<r.outer_cap_seconds&&cl?.pid===r.owned_pgid&&cl.exit_code===0&&cl.direct_child_reaped===true&&cl.remaining.length===0);
  for(const side of ["stdout","stderr"]){const sp="commands/"+label+"."+side;if(sp in raw)ck(sp+".record_hash_exact",hash(raw[sp])===r[side+"_sha256"]);}
  recs.set(label,r);
 }
 ck("only_two_Cargo_stdout_missing",!seen.has("commands/build.stdout")&&!seen.has("commands/normal-release-build.stdout")&&recs.size===48&&seen.size===recs.size*3-2);
 const expected=new Map(core.group_results.map(g=>[g.label,g.actual_test_names]));
 for(const field of ["ingress_observer_regression","cold_h2_regression","same_root_publication_regression"]){for(const t of core[field].tests)expected.set(t.tests.label,[t.name]);}
 ck("exact23_list_and23_run_pairs",expected.size===23&&[...recs.keys()].filter(x=>x.endsWith("-list")).length===23&&[...recs.keys()].filter(x=>!x.endsWith("-list")&&!["build","normal-release-build"].includes(x)).length===23);
 let all=[];
 for(const [label,names] of expected){const list=raw["commands/"+label+"-list.stdout"],run=raw["commands/"+label+".stdout"],listed=list.split("\n").filter(x=>x.endsWith(": test")).map(x=>x.slice(0,-6)),passed=run.split("\n").filter(x=>/^test .+ \.\.\. ok$/.test(x)).map(x=>x.slice(5,-7)),counts=[...run.matchAll(/test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;/g)];
  ck(label+".exact_full_list_run_names",same(listed.slice().sort(),names.slice().sort())&&same(passed.slice().sort(),names.slice().sort())&&listed.length===names.length&&passed.length===names.length);
  ck(label+".actual_pass_zero_fail_ignore",counts.length===1&&Number(counts[0][1])===names.length&&Number(counts[0][2])===0&&Number(counts[0][3])===0&&Number(counts[0][4])===0);
  ck(label+".retained_exact_binary",recs.get(label).argv[0]===core.binary.path&&recs.get(label+"-list").argv[0]===core.binary.path);
  all=all.concat(passed);
 }
 ck("actual61_unique_not_summary_only",all.length===61&&new Set(all).size===61);
 ck("core_byte_identity_previous_review",hash(raw["core/result.public.json"])==="02422f0070827e4940ae819d117b80ead30b993dba5ec9fe4a1aee21f286c113");
 const missing=[];
 for(const [i,label,size]of [[0,"normal-release-build",440534],[1,"build",438208]]){const n=obj("native/cargo"+i+".file-info.json"),sdk=obj("sdk/cargo"+i+".file-info.json");ck(label+".missing_full_body_exact_metadata_known",sdk.isError===false&&sdk.content[0].text===raw["native/cargo"+i+".file-info.json"]&&n.path===root+"/"+label+".stdout"&&n.size===size&&n.sha256===recs.get(label).stdout_sha256&&typeof n.version==="string");missing.push({label,path:n.path,bytes:n.size,sha256:n.sha256,version:n.version});}
 return {schema:"heptabao.root.mac61-actual-originals-partial.v1",status:"PASS_ALL61_ACTUAL_TEST_STREAMS_AND48_RECORDS_TWO_CARGO_BODIES_PENDING",packet:audit.tree,files:audit.files,bytes:audit.bytes,checks:checks.length,checked:checks,original_command_records:48,original_small_streams:94,actual_list_run_pairs:23,actual_unique_tests_passed:61,failed:0,ignored:0,owned_children_closed:48,missing_full_original_bodies:missing,original_two_MCP_read_issues_not_closed_by_this_review:true,no_product_replay:true,full_replacement:false};
}