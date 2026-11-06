function verify025bControlsPrebind(i,h){
 const checks=[];function need(n,v){checks.push({name:n,pass:!!v});if(!v)throw Error(n);}
 function defs(s){const l=s.split("\n"),a=[];for(let n=0;n<l.length;n++){const m=/^def ([a-zA-Z_]\w*)\(/.exec(l[n]);if(!m)continue;let e=n+1;while(e<l.length&&(!l[e].trim()||/^\s/.test(l[e])||l[e].startsWith("#")))e++;a.push([m[1],l.slice(n,e).join("\n")]);}return a;}
 let defsCount=0;for(const e of i.edits){let r=e.after;for(const[a,b]of [...e.replacements].reverse()){need(e.name+"_unique_"+checks.length,r.split(b).length===2);r=r.replace(b,a);}need(e.name+"_inverse_original",r===e.before);need(e.name+"_forward_strict",h.applyStrictUnified(e.before,e.diff).text===e.after);need(e.name+"_reverse_strict",h.applyStrictUnified(e.after,e.diff,true).text===e.before);const a=defs(e.before),b=defs(e.after);defsCount+=a.length;need(e.name+"_all_definitions_unchanged",JSON.stringify(a)===JSON.stringify(b));need(e.name+"_first_ready_false",e.after.includes("BINDING_READY = False\nassert BINDING_READY,"));}
 const payload=JSON.parse(i.carrier);
 need("original_payload_schema",payload.schema==="heptabao.native-jwt-pki-build-control-inputs.v1");
 need("three_exact_files",Object.keys(payload.files).join(",")==="native_jwt_build.py,launch_native_jwt_build.py,jwt-test-groups.public.json");
 const sources={"native_jwt_build.py":i.runner,"launch_native_jwt_build.py":i.launcher,"jwt-test-groups.public.json":i.groups};
 for(const [name,source]of Object.entries(sources)){const decoded=h.utf8Text(h.unb64(payload.files[name])),m=h.gitBlobMeta(decoded);need(name+"_whole_payload",decoded===source);need(name+"_publisher_pin",i.pins[name][0]===m.bytes&&i.pins[name][1]===m.sha256);}
 const gp=h.gitBlobMeta(i.groups),groups=JSON.parse(i.groups);
 need("original_groups_hash",gp.sha256==="35153ff5e90b582f83e4fbbb66ff5c9fb295e95153f08df152cefedecdb50869"&&gp.bytes===19789);
 need("runner_groups_gate",i.runner.includes("assert args.groups_sha256 == '"+gp.sha256+"'"));
 need("launcher_groups_gate",i.launcher.includes("GROUPS_SHA256 = '"+gp.sha256+"'"));
 need("166_profile_instances",groups.reduce((n,g)=>n+g.tests.length,0)===166);
 need("149_unique_names",new Set(groups.flatMap(g=>g.tests)).size===149);
 need("four_original600_budgets",groups.length===4&&groups.every(g=>g.runtime_seconds===600));
 need("new17_twice",groups[0].tests.length===17&&JSON.stringify(groups[0].tests)===JSON.stringify(groups[1].tests));
 need("legacy_acl_test_not_replaced",i.groups.includes("native_jwt_role_operations_keep_the_existing_legacy_acl_contract"));
 need("new_root_only",i.launcher.includes("ROOT = Path('/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r2')")&&i.publisher.includes("BASE = PARENT / 'heptabao-native-jwt-pki-controls-20261106-r2'"));
 need("new_source_root",i.launcher.includes("SOURCE_STAGE_ROOT = Path('/home/qian-qi/heptabao-native-jwt-pki-source-025b05a3-20261106-r1')"));
 need("original_target",i.launcher.includes("TARGET = Path('/home/qian-qi/heptabao-cold-h2-normal-20261105-r1/target-normal-r3')"));
 need("original_fresh_NB_probe",i.launcher.includes("fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)"));
 const close=i.launcher.indexOf("        os.close(lock_fd)"),exec=i.launcher.indexOf("os.execv(argv[0], argv)");
 need("original_probe_close_before_exec",close>0&&exec>close);
 need("original_all_deadlines_literal",i.launcher.includes("ORIGINAL_OUTER_SECONDS = 12000")&&i.runner.includes("ORIGINAL_OUTER_SECONDS = 12000"));
 need("explicit_actual_unknowns",i.proposal.actualStage===null&&i.proposal.actualPublication===null&&i.proposal.actualBuild===null);
 need("template_no_dispatch",i.buildTemplate.dispatchAllowed===false&&i.buildTemplate.requestTemplate.idempotency_key===null);
 need("payload_measured_cap",h.gitBlobMeta(i.carrier).bytes===i.proposal.budgets.publisherPayloadActual&&h.gitBlobMeta(i.carrier).bytes<=262144);
 return {schema:"heptabao.native-jwt-pki.025b.controls-prebind.pure-checks.v1",pass:true,checks,total:checks.length,unchangedDefinitions:defsCount,Runtime:0,PythonExecuted:false,Cargo:false};
}
