function verifyFreshJointSource(t) {
 const checks=[];
 function check(ok,label){checks.push({label,ok:!!ok});if(!ok)throw new Error(label);}
 function meta(raw,pin){const m=gitBlobMeta(raw);return m.blob===pin.blob&&m.bytes===pin.bytes&&m.sha256===pin.sha256;}
 function defs(s){const ls=s.split("\n"),out={};for(let i=0;i<ls.length;i++){const m=/^def ([A-Za-z_][A-Za-z0-9_]*)\(/.exec(ls[i]);if(!m)continue;let j=i+1;while(j<ls.length&&(/^\s/.test(ls[j])||ls[j]===""))j++;out[m[1]]=ls.slice(i,j).join("\n").replace(/\n+$/,"")+"\n";}return out;}
 const plan=JSON.parse(t["PLAN.public.json"]),q=JSON.parse(t["request.exact.json"]);
 const lb=t["launcher.before.py"],l=t["launcher.after.py"],rb=t["runner.before.py"],r=t["runner.after.py"],pb=t["publisher.before.py"],pu=t["publisher.after.py"];
 for(const name of ["launcher","runner","publisher","journal"]){
   const ext=name==="journal"?"js":"py",a=t[name+".before."+ext],b=t[name+".after."+ext];
   check(snapshotApply(a,t[name+".forward.diff"])===b,name+" forward strict");
   check(snapshotApply(b,t[name+".forward.diff"],true)===a,name+" reverse strict");
 }
 check(meta(lb,{blob:"924d7ddc88ba8a8cf8f44ff3cc5cda037043aaef",bytes:39818,sha256:"4c5de46d61f90237ae6789d9efd8d347b7729621ad8a6c467205f3f18c378602"}),"actual old launcher");
 check(meta(rb,{blob:"4a67b5858bf4c1c2c202eb1bbaeb84e35189f7a3",bytes:32059,sha256:"326ec765e5fa8fa06b4e41673b49d84d5325294b90283e3faab6a00f88c5f29e"}),"actual old runner");
 check(meta(pb,{blob:"c4abedf72b4755a7d552406f173c99ce915a5437",bytes:5170,sha256:"5765113a6b80a81dd47e672f39e8d27d7a2b5c51aacc2d977f93beebbd268e5e"}),"actual old publisher");
 for(const[name,a,b]of [["launcher",lb,l],["runner",rb,r],["publisher",pb,pu]]){
   const da=defs(a),db=defs(b);for(const fn of Object.keys(da))check(da[fn]===db[fn],name+" old function "+fn+" exact");
 }
 check(gitBlobMeta(l).bytes<=40000&&gitBlobMeta(r).bytes<=40000,"unchanged control caps");
 const start="    rustc = subprocess.check_output(",end="\nfinally:\n    signal.signal(signal.SIGTERM";
 check(rb.slice(rb.indexOf(start),rb.indexOf(end,rb.indexOf(start)))===r.slice(r.indexOf(start),r.indexOf(end,r.indexOf(start))),"complete original compile and 268 cases code exact");
 const c0="finally:\n    signal.signal(signal.SIGTERM",c1="    if result.get('retained_df026_before'";
 check(r.includes(rb.slice(rb.indexOf(c0),rb.indexOf(c1))),"original owned cleanup exact");
 const d0="PRIOR_DF026_FILES = {",d1="\ndef preserve_prior_df026";
 check(rb.slice(rb.indexOf(d0),rb.indexOf(d1)).trim()===r.slice(r.indexOf(d0),r.indexOf(d1)).trim(),"old twelve-file table exact");
 check((r.match(/preserve_prior_df026\(/g)||[]).length===1,"old function retained uncalled");
 const lm=l.slice(l.indexOf("assert (os.uname().sysname, os.uname().machine)"));
 check(!/\b(?:holders|preserve_r9|preserve_r10|preserve_successful_observer|preserve_failed_observer|preserve_current_early_failure)\(/.test(lm),"old host fences not executed");
 check(!lm.includes("freeze(OLD_SOURCE)")&&!lm.includes("flock(")&&!lm.includes("release/.cargo-lock"),"no old source or target lock access");
 check(lm.includes("os.mkdir(TARGET.name, mode=0o700, dir_fd=parent_fd)")&&lm.includes("assert not os.path.lexists(TARGET)"),"create-only new target");
 check(lm.includes("identity(parent_before)[:5] == identity(parent_after)[:5]")&&lm.includes("identity(parent_after) == identity(ROOT.lstat())"),"own mkdir preserves parent object");
 check(lm.includes("identity(target_info) == identity(TARGET.lstat())")&&lm.includes("not os.listdir(target_fd)"),"actual new target full identity and empty");
 check(lm.includes("'--fresh-target-first5', json.dumps(list(identity(target_info)[:5])"),"actual first5 handed over");
 check(r.includes("assert list(fields[:5]) == expected")&&r.includes("assert path.parent == Path(__file__).resolve(strict=True).parent"),"runner exact target owner identity");
 check(r.indexOf("result['current_tools'] =")<r.indexOf(start),"whole tools before first rustc or cargo");
 check(r.includes("assert [str(x) for x in fresh_identity(before)] == expected"),"actual tool full9 strict");
 check(r.includes("before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o755")&&r.includes("min(1024 * 1024, before.st_size + 1 - count)"),"tool bounded full regular read");
 check(r.includes("fresh_identity(before) == fresh_identity(os.fstat(fd)) == fresh_identity(path.lstat())"),"tool fd/name stable");
 check(r.includes("'independent_prior_content_sha_observed': False")&&r.includes("'offline_contents_qualified': False"),"no invented prior tool hash or cache qualification");
 check(r.includes("global protected\n    expected = PUBLIC_TOOL_IDENTITIES")&&r.includes("    finally:\n        protected -= 1\n    if pending_signal is not None:\n        raise Cancelled()\n    return pin"),"new tool FD signal deferral and no retry");
 check(r.includes("known_missing_original_table_leaves': 6")&&r.includes("qualification_inherited': False"),"missing historical evidence remains distinct");
 const pubdefs=defs(pu);check(Object.keys(pubdefs).length===Object.keys(defs(pb)).length+1&&pubdefs.publication_timeout.includes("os._exit(124)"),"one publication deadline callback no child");
 check(pu.includes("JOINT_STARTED = time.monotonic()")&&pu.includes("PUBLICATION_UNTIL = JOINT_STARTED + 60")&&pu.includes("JOINT_UNTIL = JOINT_STARTED + 12000"),"joint original budgets");
 check(pu.includes("signal.setitimer(signal.ITIMER_REAL, max(0.001, PUBLICATION_UNTIL - time.monotonic()))"),"hard cap applies to original publication phase");
 check(pu.indexOf("publish(RECEIPT.name, raw)")<pu.indexOf("os.execv(argv[0], argv)"),"receipt byte verification before exec");
 check(pu.includes("'--controls-sha256', sha(raw)")&&pu.includes("'--publisher-started-monotonic', repr(JOINT_STARTED)")&&pu.includes("'--publisher-pid', str(os.getpid())"),"actual receipt hash and same PID clock");
 check(l.includes("args.publisher_pid == os.getpid()")&&l.includes("LAUNCHER_ENTERED - args.publisher_started_monotonic < 60")&&l.includes("OUTER_STARTED = args.publisher_started_monotonic"),"launcher does not reset deadline");
 check(r.includes("OUTER_UNTIL = args.outer_started_monotonic + ORIGINAL_OUTER_SECONDS")&&r.includes("args.launcher_pid == os.getpid()"),"runner original same PID deadline exact");
 check(l.includes("row['identity'] == observed['identity']")&&l.includes("0o100600, 1")&&l.indexOf("controls_raw, controls_pin")<l.indexOf("ADMISSION.mkdir"),"control whole receipt gate precedes writes");
 check(l.includes("'full_leaf_index_sha256': 'c6cef770842a1b0006b4c86a58e325802d00dd5779dede468262f2693c3246cc'")&&l.includes("'tracked_bytes': 62537554, 'tracked_leaf_count': 3932"),"actual stage complete source leaf index");
 check(l.includes("row['close_outcome_unknown'] = True")&&l.indexOf("result['fresh_directory_descriptors']")<l.indexOf("os.execv(argv[0], argv)"),"fresh FDs once closed before exec");
 const gs=t["jwt-test-groups.public.json"];
 check(meta(gs,{blob:"8945c9f8f2565807601f8197b93be026ca4e875b",bytes:33825,sha256:"7c0fb6c5b6819c2cab60f3044e0aec767ad8abbf22e31ff0f7fab742ea4cd786"}),"original entire groups unchanged");
 const groups=JSON.parse(gs),counts={};for(const g of groups){counts[g.libtest_profile]=(counts[g.libtest_profile]||0)+g.tests.length;check(g.runtime_seconds===600,"family "+g.label+" original600");}
 const entries=groups.flatMap(g=>g.tests.map(n=>[g.libtest_profile==="ha-native-v6-peer-ingress"?"heptabao-ha-service":"heptabao-server",n]));
 check(groups.length===18&&entries.length===268&&new Set(entries.map(x=>JSON.stringify(x))).size===246,"exact denominator 246/268/18");
 check(JSON.stringify(counts)===JSON.stringify({file:22,default:229,"ha-native-v6-peer-ingress":17}),"exact profile partition");
 const payload=JSON.parse(t["stdin.exact.json"]);
 check(q.stdin===t["stdin.exact.json"]&&gitBlobMeta(q.stdin).bytes<=262144,"exact stdin original cap");
 check(JSON.stringify(q.args.slice(0,4))===JSON.stringify(["-I","-S","-B","-c"])&&q.args.length===5&&q.args[4]===pu,"actual inline publisher argv");
 check(q.host==="rog"&&q.executable==="/usr/bin/python3"&&q.cwd==="/home/qian-qi"&&q.timeout_seconds===12000,"exact host executable cwd outer");
 for(const[name,raw]of [["native_jwt_build.py",r],["launch_native_jwt_build.py",l],["jwt-test-groups.public.json",gs]]){
   check(utf8Text(unb64(payload.files[name]))===raw,"whole payload source "+name);
   const m=gitBlobMeta(raw);check(pu.includes(String(m.bytes))&&pu.includes(m.sha256),"publisher exact pin "+name);
 }
 check(JSON.stringify(processStartBinding(q))===JSON.stringify(plan.typed),"correct stdin typed binding");
 let jj=t["journal.before.js"];for(const[a,b]of plan.journalLiteralChanges){check(jj.split(a).length===2,"single journal literal");jj=jj.replace(a,b);}
 check(jj===t["journal.after.js"],"journal only three bindings");
 const m=JSON.parse(t["prerequisite.actual.original.json"]);
 check(m.coverage_complete===true&&m.rows.length===121&&m.failure===null,"actual metadata complete finite list");
 for(const name of ["cargo","rustc"]){const row=m.rows.find(x=>x.path.endsWith("/bin/"+name));check(row.stable&&row.resolve.exact&&r.includes(JSON.stringify(row.before)),"actual lossless "+name+" full9 bound");}
 const ch=m.rows.find(x=>x.path.endsWith("c1bd-r1/cargo-home"));check(r.includes(JSON.stringify(ch.before.slice(0,5))),"actual Cargo-home object bound");
 check(plan.authorization==="NOT_GO"&&plan.NativeCalls===0&&!plan.runtimeQualificationInherited,"SOURCE only");
 return {schema:"heptabao.fresh-joint-build-source-verification.v1",status:"passed",checks:checks.length,details:checks,NativeCalls:0,pythonCompile:false,rustCompile:false,runtimeTests:false};
}