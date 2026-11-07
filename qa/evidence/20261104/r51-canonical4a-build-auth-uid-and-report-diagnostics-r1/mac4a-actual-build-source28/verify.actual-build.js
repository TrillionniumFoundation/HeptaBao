function verifyMac4aActualBuildBinding(files){
 const checks=[];function need(v,n){if(!v)throw Error(n);checks.push(n);}
 const p=JSON.parse(files["PLAN.public.json"]),i=JSON.parse(files["BUILD-INPUTS.actual.json"]);
 const a={commit:i.commit,tree:i.tree,paths:i.paths,controlPins:i.controlPins,stage:i.stage,authorityNativeRaw:files["authority.original.json"],streamsNativeRaw:files["streams.original.json"]};
 need(JSON.stringify(gitBlobMeta(a.authorityNativeRaw))===JSON.stringify(i.authorityPin)&&JSON.stringify(gitBlobMeta(a.streamsNativeRaw))===JSON.stringify(i.streamsPin),"whole actual original authority and streams");
 const actual=bindFreshMacNormalBuild(a);
 need(actual.requestRaw===files["request.exact.json"],"unchanged binder exact request");
 const typed={sha256:actual.typed.sha256,native_fingerprint:actual.typed.native_fingerprint,canonical_bytes:utf8Bytes(actual.typed.canonical).length};
 need(JSON.stringify(typed)===JSON.stringify(JSON.parse(files["typed-binding.public.json"])),"exact absent-stdin typed digest and full uint64 fingerprint");
 need(JSON.stringify(actual.actualReceipt)===JSON.stringify(i.actualReceipt)&&actual.actualPublisherJob===i.actualPublisherJob,"actual receipt full9 and original publisher job");
 const q=JSON.parse(actual.requestRaw);
 need(q.host==="mac"&&q.executable==="/opt/homebrew/bin/python3"&&q.timeout_seconds===8280&&!Object.hasOwn(q,"stdin")&&!Object.hasOwn(q,"env"),"original fixed Mac executable and outer request");
 need(q.args.slice(0,4).join("\n")===["-I","-S","-B",i.paths.control+"/launch_normal_same_root_publication.py"].join("\n"),"same original launcher argv entry");
 need(q.args[q.args.indexOf("--controls-full9-json")+1]===JSON.stringify(i.actualReceipt.full9)&&q.args[q.args.indexOf("--controls-sha256")+1]===i.actualReceipt.sha256,"actual receipt exact launch arguments");
 need(applyStrict(files["journal.before.js"],files["journal.forward.diff"])===files["journal.after.js"]&&applyStrict(files["journal.after.js"],files["journal.reverse.diff"])===files["journal.before.js"],"strict journal forward and reverse");
 let expected=files["journal.before.js"];
 function rep(a,b){need(expected.split(a).length===2,"unique literal "+a.slice(0,30));expected=expected.replace(a,b);}
 rep('const GF_SLOT = "successor4a_mac_normal117_controls_inert_gitfirst_r1";','const GF_SLOT = "successor4a_mac_normal117_build_gitfirst_r1";');
 rep(expected.split("\n").find(x=>x.startsWith("const GF_REQUEST = ")),"const GF_REQUEST = "+JSON.stringify(actual.request)+";");
 rep("heptabao-4a49405b-mac-normal117-controls-r1-","heptabao-4a49405b-mac-normal117-build-r1-");
 need(expected===files["journal.after.js"],"only three journal binding literals");
 for(const [name,file]of [["mac_normal_same_root_publication_build.py","runner.original.py"],["launch_normal_same_root_publication.py","launcher.actual-published.py"],["normal-test-groups.public.json","groups.original.json"]])need(JSON.stringify(gitBlobMeta(files[file]))===JSON.stringify(i.controlPins[name]),"actual published source exact "+name);
 const s=parseLosslessIntegers(files["streams.original.json"]);
 need(s.stdout.text===files["stdout.original.json"]&&s.stdout.size===2988&&s.stderr.size===0,"whole original publisher stdout");
 need(p.tests.total_unique===61+28&&p.tests.total_instances===61+28+28&&p.budgets.outer_seconds===8280&&p.budgets.release_build_seconds===1800&&p.budgets.default_libtest_seconds===1800&&p.budgets.file_libtest_seconds===1800&&p.budgets.each_family_seconds===600,"unchanged normal117 selection and budgets");
 const j=files["journal.after.js"];
 need((j.match(/archiveFlatPublicTextsOnce\(/g)||[]).length===4&&j.includes('key:"gfa-"+callKey')&&j.includes('key:"gfx-"+callKey')&&j.includes('key:"gfs-"+callKey')&&j.includes('const archiveKey="gfc-"+a.id;'),"all archive callsite keys dynamic");
 need(p.NativeCalls===0&&!p.runtimeSlotInitialized&&p.actualNewBuildJob===null&&p.actualServer===null&&!p.normal117Qualified&&!p.full34Qualified&&actual.rootBuildGORequired===true,"no invented build execution or artifact identities");
 return {schema:"heptabao.mac4a.actual-build-binding-check.r1",pass:true,check_count:checks.length,checks,request:actual.request,typed,journal:gitBlobMeta(j),actualPublisherJob:actual.actualPublisherJob,actualReceipt:actual.actualReceipt,NativeCalls:0};
}
