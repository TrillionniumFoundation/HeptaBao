function checkFormatterReceipt(d,pure){
 const P=new Function(pure+"\nreturn {gitBlobMeta,parseLosslessIntegers};")(),r=P.parseLosslessIntegers(d.receiptRaw),s=JSON.parse(d.stdoutRaw),checks=[],ck=(n,v)=>{checks.push({name:n,pass:!!v});if(!v)throw Error(n);};
 const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b),capture=(name)=>JSON.parse(new RegExp("^"+name+"=(\\{[^\\n]*\\})$","m").exec(d.source)[1].replace(/\bNone\b/g,"null"));
 const expected=capture("EXPECTED"),sizes=capture("SOURCE_SIZES"),caps=capture("FORMAT_OUTPUT_CAPS"),names=Object.keys(expected);
 ck("whole actual receipt",P.gitBlobMeta(d.receiptRaw).bytes===22202&&P.gitBlobMeta(d.receiptRaw).sha256==="60776056ee93fa1fdb557233626ee392385bfe69c8335cd9bc8d236fb0974874");
 ck("exact formatter source",P.gitBlobMeta(d.source).blob==="1266e75033bee0962b0d77d3c35ee19ec53086db");
 ck("exact successful schema",r.schema==="heptabao.native-jwt-input-rustfmt.v1"&&r.status==="passed");
 ck("source identity exact unformatted commit",r.sourceCommit==="e3afc157447d35c861f275a761b29da3e42aff8e"&&r.sourceTree==="5497775d9d473541e13e1603be8c893a3e27681b");
 ck("original50 and60",r.internalSeconds===50&&r.newRemoteSupervisorSeconds===60&&r.elapsedSeconds<50&&r.withinDeadline===true);
 ck("no product or compile",r.productExecuted===false&&r.compileExecuted===false&&r.productionChanged===false);
 ck("nine fixed inputs and caps",equal(r.fixedFormattedOutputCaps,caps)&&equal(r.inputOriginalAndCandidatePins,expected)&&r.sourceInputTotalBytes===1221466);
 ck("current source fully pinned",r.uncommittedCandidateInputs===false&&r.sourceIdentityIsBaseOnly===false&&r.repositoryRustfmtConfigPresent===false);
 ck("same nine source observations",Object.keys(r.sourceInputsBefore).sort().join()===names.slice().sort().join()&&equal(r.sourceInputsBefore,r.sourceInputsAfter)&&r.allFixedSourceInputsUnchanged===true);
 ck("source full9 field order",equal(r.sourceIdentityFields,["dev","ino","size","mtime_ns","ctime_ns","full_mode","uid","gid","nlink"]));
 const integer=x=>Number.isSafeInteger(x)?String(x):x?.$exactInteger;
 for(const name of names){
  const p=r.sourceInputsBefore[name];ck("fixed source "+name,p.path===r.sourcePath+"/"+name&&p.bytes===sizes[name]&&p.sha256===expected[name][1]&&p.identity.length===9&&p.identity[2]===sizes[name]&&p.identity[5]===33152&&p.identity[6]===1000&&p.identity[7]===1000&&p.identity[8]===1);
  ck("lossless source ns "+name,/^[0-9]+$/.test(integer(p.identity[3]))&&/^[0-9]+$/.test(integer(p.identity[4])));
 }
 ck("tool before/after same",equal(r.rustfmtBefore,r.rustfmtAfter)&&r.rustfmtBefore.sha256==="5005cdcd39ded526dca8fa6ccd716d42fc7da54469034e055dbf54649bec7877"&&r.rustfmtBefore.bytes===5255144);
 ck("config before/after same",equal(r.formatConfigurationBefore,r.formatConfigurationAfter)&&r.formatConfigurationBefore.bytes===17&&r.formatConfigurationBefore.sha256==="f32d2f03b3f4b1e295c79ed49d543f1205c7dac7c3dc74f05a5a27af4fea0584");
 ck("nine original children",r.children.length===9&&r.allOwnedStopped===true);
 const root="/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1",fmt=r.rustfmtBefore.path,argv=[fmt,"--config-path",root+"/rustfmt.toml","--edition","2024","--emit","stdout"];
 r.children.forEach((c,i)=>ck("child"+i+" terminal/custody",c.exitCode===0&&c.reaped===true&&c.stopped===true&&c.newProcessGroupCreated===false&&c.pgid===c.supervisorGroup&&c.timeoutSeconds===10&&c.cwd===root&&equal(c.argv,argv)));
 ck("all nine files ordered",equal(r.files.map(x=>x.name),names));
 let changed=0,afterTotal=0;
 for(const f of r.files){ck("file contract "+f.name,f.beforeBytes===sizes[f.name]&&f.beforeSha256===expected[f.name][1]&&Number.isSafeInteger(f.afterBytes)&&f.afterBytes>0&&f.afterBytes<=caps[f.name]&&/^[a-f0-9]{64}$/.test(f.afterSha256)&&f.stderrBytes===0&&f.stderrSha256==="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");changed+=f.beforeSha256!==f.afterSha256?1:0;afterTotal+=f.afterBytes;}
 ck("original terminal summary agrees exactly",equal(r.files,s.files)&&s.status==="passed"&&s.withinDeadline&&s.allOwnedStopped&&s.error===null&&s.publicationError===null);
 ck("six actual changes",changed===6);
 ck("no reported fence error",!["error","errorType","sourceFenceError","fenceError","configFenceError","publicationError"].some(k=>Object.prototype.hasOwnProperty.call(r,k)));
 return{schema:"heptabao.jwt-formatter-receipt.semantic-checks.v1",passed:checks.length,checks,changedFiles:changed,sourceBytes:1221466,formattedBytes:afterTotal,all38IndependentOutputObservations:false,newCargoQualified:false,Runtime:0,productCases:0};
}