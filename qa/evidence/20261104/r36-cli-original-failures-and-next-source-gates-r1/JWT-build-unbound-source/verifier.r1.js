function verifyJwtBuildDrafts(d,pure){
 const P=new Function(pure+"\nreturn {gitBlobMeta,unb64,utf8Text};")(),checks=[];
 function ck(name,v){checks.push({name,pass:!!v});if(!v)throw Error(name);}
 function defs(t){const lines=t.split(/(?<=\n)/);const out={};let offset=0;for(let i=0;i<lines.length;i++){const m=/^def ([A-Za-z_0-9]+)\(/.exec(lines[i]);if(m){let end=i+1;while(end<lines.length&&(/^\s/.test(lines[end])||!lines[end].trim()))end++;out[m[1]]=lines.slice(i,end).join("");}offset+=lines[i].length;}return out;}
 for(const k of ["runner","launcher","publisher"]){
  let text=d[k].before;for(const r of d[k].replacements){ck(k+" single forward "+r.label,text.split(r.before).length===2);text=text.replace(r.before,r.after);}ck(k+" whole forward",text===d[k].after);
  for(const r of [...d[k].replacements].reverse()){ck(k+" single reverse "+r.label,text.split(r.after).length===2);text=text.replace(r.after,r.before);}ck(k+" whole reverse",text===d[k].before);
  ck(k+" inert draft precedes first OS call",d[k].after.indexOf("BINDING_READY = False")<d[k].after.indexOf("os.umask(0o077)"));
 }
 const oldR=defs(d.runner.before),newR=defs(d.runner.after);ck("runner10 definitions",Object.keys(oldR).length===10&&Object.keys(newR).length===10);for(const n of Object.keys(oldR))ck("runner whole original helper "+n,oldR[n]===newR[n]);
 const oldL=defs(d.launcher.before),newL=defs(d.launcher.after);ck("launcher10 definitions",Object.keys(oldL).length===10&&Object.keys(newL).length===10);
 for(const n of Object.keys(oldL))ck("launcher helper "+n,n==="preserve_failed_observer"?oldL[n].replace("authority_path = CONTROL / FAILED_AUTHORITY_NAME","authority_path = SOURCE_STAGE_CONTROL / FAILED_AUTHORITY_NAME")===newL[n]:oldL[n]===newL[n]);
 const oldP=defs(d.publisher.before),newP=defs(d.publisher.after);ck("publisher5 definitions",Object.keys(oldP).length===5&&Object.keys(newP).length===5);for(const n of Object.keys(oldP))ck("publisher whole original helper "+n,oldP[n]===newP[n]);
 const r=d.runner.after,l=d.launcher.after,p=d.publisher.after;
 const tail="except BaseException as error:\n    result['failure_type']";
 ck("runner entire failure cleanup and terminal tail unchanged",d.runner.before.slice(d.runner.before.indexOf(tail))===r.slice(r.indexOf(tail)));
 const ltail="except BaseException as error:\n    result.update(error_type";
 const li=l.indexOf(ltail),bi=d.launcher.before.indexOf(ltail),lp=l.indexOf("\nprint(json.dumps({'status': 'preflight-admitted'",li),bp=d.launcher.before.indexOf("\nprint(json.dumps({'status': 'preflight-admitted'",bi);
 ck("launcher failure lock close refusal tail unchanged",l.slice(li,lp)===d.launcher.before.slice(bi,bp));
 ck("same-PID final deadline and exec unchanged",l.slice(l.indexOf("assert time.monotonic() < OUTER_UNTIL, 'original outer deadline expired before same-PID exec'"))===d.launcher.before.slice(d.launcher.before.indexOf("assert time.monotonic() < OUTER_UNTIL, 'original outer deadline expired before same-PID exec'")));
 ck("final source identities unresolved",r.includes("DIAGNOSTIC_COMMIT = None\nDIAGNOSTIC_TREE = None")&&l.includes("FINAL_COMMIT = None\nFINAL_TREE = None\nSOURCE_STAGE_ROOT = None"));
 ck("same target and first5",l.includes("identity(TARGET.stat())[:5] == (66306, 31606588, 1000, 1000, 16832)")&&l.includes(d.target));
 ck("target missing remains refusal",l.includes("assert TARGET.resolve(strict=True) == TARGET")&&!l.includes("TARGET.mkdir"));
 ck("original nonblocking flock probe",l.includes("fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)"));
 ck("same12000 outer runner and launcher",r.includes("ORIGINAL_OUTER_SECONDS = 12000")&&l.includes("ORIGINAL_OUTER_SECONDS = 12000"));
 ck("one shared3600 compile deadline",r.split("compile_until = min(compile_started + 3600.0, OUTER_UNTIL)").length===2&&!r.includes("compile_until += "));
 ck("ordinary no-default compile",r.includes("'--lib', '--no-default-features', '--message-format=json-render-diagnostics'"));
 ck("file-only profile",r.includes("('file', ['--no-default-features', '--features', 'native-v6-storage'], ['native-v6-storage'])"));
 ck("default profile explicit",r.includes("('default', [], ['default', 'native-v6-ha', 'native-v6-storage'])"));
 ck("build finished observed",r.split("e.get('reason') == 'build-finished'").length===4);
 ck("release original1800 clipped",r.includes("], 1800, deadline=OUTER_UNTIL)"));
 ck("families clipped original outer",r.includes("family_until = min(family_started + group['runtime_seconds'], OUTER_UNTIL)"));
 ck("exact listing and actual one pass",r.includes("selected == [name]")&&r.includes("test result: ok. 1 passed; 0 failed; 0 ignored;"));
 ck("default does not claim distributed JWT HA",r.includes("'distributed_native_jwt_ha_qualified': False"));
 ck("old qualified business denominator not rerun",r.includes("'old_normal61_full34_LAN98plus12_comparison69_rerun': False"));
 const gs=JSON.parse(d.groupsRaw);ck("four exact groups",JSON.stringify(gs.map(x=>[x.label,x.libtest_profile,x.tests.length,x.runtime_seconds]))===JSON.stringify([["native-jwt-file15","file",15,600],["native-jwt-default15","default",15,600],["legacy-jwt-default63","default",63,600],["native-auth-identity-default69","default",69,600]]));
 const all=gs.flatMap(g=>g.tests);ck("162 profile instances",all.length===162);ck("147 unique names",new Set(all).size===147);ck("same15 in both profiles",JSON.stringify(gs[0].tests)===JSON.stringify(gs[1].tests));
 for(const g of gs)ck("unique family "+g.label,new Set(g.tests).size===g.tests.length);
 ck("exact groups wholeSHA",P.gitBlobMeta(d.groupsRaw).sha256===d.groupsSha&&r.includes(d.groupsSha)&&l.includes(d.groupsSha));
 ck("groups cap retained",P.gitBlobMeta(d.groupsRaw).bytes<=20000);
 ck("runner cap retained",P.gitBlobMeta(r).bytes<=40000);
 ck("launcher cap retained",P.gitBlobMeta(l).bytes<=40000);
 const payload=JSON.parse(d.payloadRaw);
 ck("publisher input fixed three",payload.schema==="heptabao.native-jwt-build-control-inputs.v1"&&Object.keys(payload.files).sort().join(",")==="jwt-test-groups.public.json,launch_native_jwt_build.py,native_jwt_build.py");
 const pyfiles={"native_jwt_build.py":r,"launch_native_jwt_build.py":l,"jwt-test-groups.public.json":d.groupsRaw};
 for(const[name,t]of Object.entries(pyfiles))ck("payload exact "+name,P.utf8Text(P.unb64(payload.files[name]))===t);
 ck("payload within original262144",P.gitBlobMeta(d.payloadRaw).bytes<=262144&&p.includes("sys.stdin.buffer.read(262145)")&&p.includes("<= 262144"));
 ck("new owned controls root exactly",l.includes(d.controlRoot)&&p.includes("BASE = PARENT / 'heptabao-native-jwt-r2-controls-20261106-r1'"));
 ck("new own directory create only",p.includes("assert not os.path.lexists(BASE)")&&p.includes("BASE.mkdir(mode=0o700)")&&l.includes("assert not ADMISSION.exists() and not ADMISSION.is_symlink()"));
 ck("source no longer publisher root",l.includes("SOURCE = SOURCE_STAGE_ROOT / 'source'\nSOURCE_STAGE_CONTROL = SOURCE_STAGE_ROOT / 'control'\nCONTROL = ROOT"));
 ck("receipt exact three identity comparison",l.includes("row['identity'] == observed['identity']")&&l.includes("observed['identity'][2:6] == [expected_uid, expected_uid, 0o100600, 1]"));
 ck("no execute historical source-stage controls",!l.includes("stage['controls'][RUNNER_NAME]")&&l.includes("not stage['historical_controls_executed']"));
 ck("all new12 retained pins outside cache",d.retainedCurrent.length===6&&d.retainedCurrent.every(x=>!x.path.startsWith(d.target)));
 return{schema:"heptabao.jwt-r2-build-source.selected-checks.v1",checks,passed:checks.length,Runtime:0,PythonCompile:0,RustCompile:0,fullModuleExecuted:false,finalSourceBound:false,testResult:false};
}