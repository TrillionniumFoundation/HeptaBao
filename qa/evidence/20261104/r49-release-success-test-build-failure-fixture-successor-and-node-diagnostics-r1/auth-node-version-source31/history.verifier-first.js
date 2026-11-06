function verifyPublicNodeVersionComparisonSource(files) {
 const checks=[],stable=x=>Array.isArray(x)?x.map(stable):x&&typeof x==="object"?Object.fromEntries(Object.keys(x).sort().map(k=>[k,stable(x[k])])):x;
 const eq=(name,a,b)=>checks.push({name,passed:JSON.stringify(stable(a))===JSON.stringify(stable(b))});
 const yes=(name,x)=>checks.push({name,passed:x===true});
 const parse=path=>JSON.parse(files[path]),meta=gitBlobMeta;
 const s=files["source.py"],before=files["startup.before.original.py"],q=parse("request.exact.json"),contract=parse("CONTRACT.public.json");
 const jsonConstant=(src,name)=>JSON.parse(src.match(new RegExp("^"+name+"=(.+)$","m"))[1]);
 const decodedJson=(src,name)=>JSON.parse(utf8Text(unb64(src.match(new RegExp("^"+name+"=json\\.loads\\(base64\\.b64decode\\('([^']+)'\\)\\)","m"))[1])));
 function def(src,name){const start=src.indexOf("def "+name+"(");if(start<0)return null;const tail=src.slice(start);const m=/\n(?:def |class |if __name__)/.exec(tail);return m?tail.slice(0,m.index+1):tail;}
 eq("source/pin",meta(s),contract.source);
 eq("request/pin",meta(files["request.exact.json"]),contract.exactRequest);
 eq("journal/pin",meta(files["journal.js"]),contract.journal);
 eq("source/old-probe-exact",meta(before),contract.originalFacts.publicProbeInputs.source);
 eq("source/strict-forward",strictApplySource(before,files["source.forward.diff"]).raw,s);
 eq("source/strict-inverse",strictApplySource(s,files["source.inverse.diff"]).raw,before);
 eq("source/six-hunks",[strictApplySource(before,files["source.forward.diff"]).hunks,strictApplySource(s,files["source.inverse.diff"]).hunks],[6,6]);
 for(const n of ["critical","need","interrupt","remaining","sha","encoded","identity","error_projection","public_command","load_modules"])
  eq("original-definition/"+n,def(s,n),def(before,n));
 const oldRequest=JSON.parse(JSON.stringify(q));delete oldRequest.stdin;delete oldRequest.idempotency_key;
 eq("request/only-fixed-python-wrapper",oldRequest,{host:"mac",executable:"/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14",args:["-I","-S","-B","-"],cwd:"/Users/qianqi",timeout_seconds:60});
 eq("request/exact-stdin",q.stdin,s);
 yes("request/no-wrong-field",!Object.hasOwn(q,"stdin_text"));
 eq("request/key",q.idempotency_key,"heptabao-mac-public-node-version-"+meta(s).sha256.slice(0,8)+"-20261106-r1");
 const journal=files["journal.js"],jb=files["journal.before.js"];
 eq("journal/strict-forward",strictApplySource(jb,files["journal.forward.diff"]).raw,journal);
 eq("journal/strict-inverse",strictApplySource(journal,files["journal.inverse.diff"]).raw,jb);
 eq("journal/2-2-hunks",[strictApplySource(jb,files["journal.forward.diff"]).hunks,strictApplySource(journal,files["journal.inverse.diff"]).hunks],[2,2]);
 const jnorm=journal.replace(contract.slot,"owner_authbus_public_node_ignition_log_gitfirst_r1")
   .replace(/const GF_REQUEST = \{blob:"[0-9a-f]+",\n bytes:[0-9]+,sha256:"[0-9a-f]+"\};/,
       jb.match(/const GF_REQUEST = \{blob:"[0-9a-f]+",\n bytes:[0-9]+,sha256:"[0-9a-f]+"\};/)[0])
   .replaceAll("heptabao-mac-public-node-version-"+meta(s).sha256.slice(0,8)+"-","heptabao-mac-public-node-ignition-f9b88153-");
 eq("journal/only-three-bindings",jnorm,jb);
 const m=decodedJson(s,"MODULES");
 eq("helpers/exact-two",Object.keys(m),["mac_owned_unreaped_r1","mac_public_node_version_commands_r1"]);
 for(const [n,path] of [["mac_owned_unreaped_r1","unreaped.original.py"],["mac_public_node_version_commands_r1","commands.after.py"]]){
  const raw=utf8Text(unb64(m[n].base64));
  eq("helper/"+n+"/literal",raw,files[path]);eq("helper/"+n+"/whole",meta(raw),{blob:m[n].blob,bytes:m[n].bytes,sha256:m[n].sha256});
 }
 eq("helper/original-unreaped",meta(files["unreaped.original.py"]),{blob:"53cddd9243f9f890d9a1b9975b435280ff58ab77",bytes:10990,sha256:"a143ba334159931d530b49a55c24471f56fa1b62f1e1012e12c75e21f3c22b1d"});
 const cb=files["commands.before.py"],ca=files["commands.after.py"];
 eq("commands/original",meta(cb),{blob:"c102dfdc565484421bf7dbbb04b7c8b9e4cd5511",bytes:5965,sha256:"eb676e6dedb6d594d944e921738cf9b384f2a98a37ee2bd1fa5433b848a36867"});
 eq("commands/strict-forward",strictApplySource(cb,files["commands.forward.diff"]).raw,ca);
 eq("commands/strict-inverse",strictApplySource(ca,files["commands.inverse.diff"]).raw,cb);
 eq("commands/2-2-hunks",[strictApplySource(cb,files["commands.forward.diff"]).hunks,strictApplySource(ca,files["commands.inverse.diff"]).hunks],[2,2]);
 const constantBlock=ca.slice(ca.indexOf("\n# Fixed public comparison"),ca.indexOf("\nclass CommandRefused"));
 let stripped=ca.replace("\n"+constantBlock,"")
   .replace("        need(label in VERSION_ARGV and argv==VERSION_ARGV[label]\n             and len(self.rows)<2 and not any(r['label']==label for r in self.rows),\n             'fixed_two_version_argv_once')\n        need(maximum==4096,'fixed_version_output_limit')\n","")
   .replace("env=VERSION_ENV,cwd=VERSION_CWD,","env={'PATH':'/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C','LC_ALL':'C'},");
 eq("commands/all-other-bytes-original",stripped,cb);
 const argvs=jsonConstant(ca,"VERSION_ARGV"),env=jsonConstant(ca,"VERSION_ENV"),cwd=jsonConstant(ca,"VERSION_CWD");
 eq("commands/argv-exact",argvs,contract.fixedProcessInputs.argv);
 eq("commands/restricted-versus-baseline",argvs["restricted-version"].slice(3),argvs["baseline-version"]);
 eq("commands/node-only-version",argvs["baseline-version"],["/opt/homebrew/Cellar/node/25.9.0_1/bin/node","--version"]);
 eq("commands/restricted-prefix",argvs["restricted-version"].slice(0,3),["/usr/bin/sandbox-exec","-f",contract.fixedProcessInputs.profileCopy]);
 eq("commands/environment",env,contract.fixedProcessInputs.environment);
 eq("commands/environment-five-keys",Object.keys(env).sort(),["HOME","LANG","LC_ALL","PATH","TMPDIR"]);
 eq("commands/empty-home-cwd-tmp",[env.HOME,env.TMPDIR,cwd],[contract.fixedProcessInputs.cwd,contract.fixedProcessInputs.cwd,contract.fixedProcessInputs.cwd]);
 yes("commands/no-node-dyld-options",Object.keys(env).every(k=>!k.startsWith("NODE_")&&!k.startsWith("DYLD_")));
 eq("home/exact-class",meta(files["HomeControl.class.original.py"]),contract.reusedSource.homeControlWhole);
 const hc=jsonConstant(s,"HOME_CLASS");
 eq("home/embedded-byte-equal",utf8Text(unb64(hc.base64)),files["HomeControl.class.original.py"]);
 eq("home/pin",{blob:hc.blob,bytes:hc.bytes,sha256:hc.sha256},contract.reusedSource.homeControlWhole);
 yes("home/fixed-two-configurations",s.includes("(name,root) in (('control',CONTROL),('empty',EMPTY))")&&s.includes("'HOME_COPY_NAMES':('consumer.sb',) if name=='control' else ()")&&s.includes("'HOME_GENERATIONS':()"));
 yes("home/preassigned-partial-init",s.indexOf("value=cls.__new__(cls)")<s.indexOf("home_entries.append(entry)")&&s.indexOf("home_entries.append(entry)")<s.indexOf("cls.__init__(value,"));
 yes("home/create-only-no-fallback",files["HomeControl.class.original.py"].includes("os.mkdir(HOME_CONTROL.name,0o700,dir_fd=parent)")&&files["HomeControl.class.original.py"].includes("home_create_only_root_already_exists"));
 yes("home/original-first5-current-full9",files["HomeControl.class.original.py"].includes("current==named_root and current[:5]==before_root[:5]"));
 const profile=jsonConstant(s,"PROFILE"),rawProfile=utf8Text(unb64(profile.base64)),oldPins=decodedJson(before,"INPUT_PINS"),newPins=decodedJson(s,"INPUT_PINS");
 eq("profile/body",rawProfile,files["consumer-profile.exact-original.sb"]);
 eq("profile/original-actual-whole",meta(rawProfile),{blob:"84ff31f119c8d0a46fe0f09b1f1ba2f2335f7cbf",bytes:6909,sha256:"acfbd336488f774e3acb87392bf5305f62004a0f529cbcd876593407989e7a12"});
 eq("profile/literal-original-paths-preserved",profile.sha256,contract.originalFacts.publicProbeInputs.profileSha256);
 yes("profile/independent-new-copy",contract.fixedProcessInputs.profileCopy.startsWith("/Users/qianqi/heptabao-public-node-version-")&&s.includes("control.write_new(CONTROL/'consumer.sb',profile,copy=True)"));
 delete oldPins["/usr/sbin/diskutil"];eq("inputs/exact-original-four",newPins,oldPins);
 eq("inputs/exact-cap-sum",Object.values(newPins).reduce((n,x)=>n+x.bytes,0),375824);
 eq("inputs/contract",newPins,contract.fixedProcessInputs.inputPins);
 const auditBefore=before.slice(before.indexOf("class InputAudit:"),before.indexOf("def consumer_profile("));
 const auditAfter=s.slice(s.indexOf("class InputAudit:"),s.indexOf("def public_command("));
 eq("inputs/only-four-input-reduction",auditAfter.replace("Four fixed public executables only","Five fixed public executables only").replace("self.max_rows=4","self.max_rows=5").replaceAll("375828","2313605"),auditBefore);
 eq("inputs/alias-unchanged",decodedJson(s,"NODE_ALIAS"),decodedJson(before,"NODE_ALIAS"));
 yes("scope/two-arms-order",s.includes("for label in ('restricted-version','baseline-version'):"));
 yes("scope/second-requires-known-closure",s.includes("'one_original_child_known_closed_before_next_arm'")&&s.includes("value['cleanup'].get('directChildReaped') is True")&&s.includes("value['cleanup'].get('allGroupRowsEmptyAfterReap') is True"));
 yes("time/same-35-45-60",s.includes("UNTIL=START+35.0")&&s.includes("FINAL_UNTIL=START+45.0")&&q.timeout_seconds===60);
 yes("time/reserve-original-cleanup",s.includes("remaining(UNTIL)>9.0")&&s.includes("until=min(UNTIL-9.0,time.monotonic()+10.0)"));
 yes("scope/no-t5-helper-or-libproc",!Object.hasOwn(m,"mac_t5_volume_guard_r1")&&!Object.hasOwn(m,"mac_native_process_observer_r1"));
 yes("scope/no-launchctl-exec-or-js-argv",!Object.values(argvs).flat().some(x=>x.includes("launchctl")||x.endsWith(".mjs")||x.endsWith(".js")||x==="--eval"||x==="--import"||x==="--require"));
 yes("report/unknown-text-withheld",s.includes("'unknownTextOrHashExported':False")&&s.includes("'stderrTextOrHashExported':False"));
 yes("report/version-only-128",s.includes("len(raw)<=128")&&s.includes("'value':raw[:-1].decode('ascii') if valid else None"));
 yes("scope/baseline-not-business",s.includes("'baselineWithoutTestProfileQualifiesSDK':False")&&s.includes("'businessQualificationClaimed':False")&&s.includes("'historicalOutcomeRewritten':False"));
 yes("scope/close-loop-protected",s.includes("for entry in reversed(home_entries):")&&s.includes("with critical():\n            if commands is not None:"));
 const linux=parse("linux576-interface.SOURCE.json"),decl=parse("linux576-release.original.json");
 eq("linux/declaration-whole",meta(files["linux576-release.original.json"]),linux.actualPhaseDeclaration.pin);
 eq("linux/current-candidate",decl.source_commit,"5767739cd25e458ac052dc8d384019bab8688ae0");
 eq("linux/phase-only",decl.phase,"normal-production-release-built");
 yes("linux/missing-actual-slots-stay-null",Object.values(linux.notYetBound).every(x=>x===null));
 yes("linux/no-port-or-credential-action",linux.noOldPrivateCapsuleRead===true&&linux.noProductionCutover===true&&linux.noAutomaticNewInventory===true&&linux.reachabilityAndTls.noPortOrFirewallOrScopeChangeAuthorized===true);
 return {schema:"heptabao.public-node-version-two-arm-source-checks.r1",passed:checks.every(x=>x.passed),checkCount:checks.length,checks,pythonExecuted:false,NodeExecuted:false,NativeCallsAdded:0,sourceOnly:true,originalFailurePreserved:true,rootRuntimeGORequired:true};
}
