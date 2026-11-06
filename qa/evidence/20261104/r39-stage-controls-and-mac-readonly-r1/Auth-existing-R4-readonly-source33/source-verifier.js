function verifyReadonlySourcePacket(files) {
 const checks=[];
 function ck(name,value){checks.push({name,passed:!!value});if(!value)throw new Error("readonly_source_check:"+name);}
 function f(name){ck("input_"+name,typeof files[name]==="string");return files[name];}
 function pin(name,sha){ck("whole_"+name,gitBlobMeta(f(name)).blob===sha);}
 const source=f("diagnostic.source.py"),body=f("new-main.source.py");
 const requestRaw=f("request.exact.public.json"),request=JSON.parse(requestRaw);
 const journal=f("journal.js"),originalJournal=f("original.journal.r4.js");
 const contract=JSON.parse(f("CONTRACT.public.json"));
 pin("original.common.r4.py","16bc4fc1ea3359d6ac8c496d250b634b8a54a2e4");
 pin("original.constants.r4.py","663602cc45be9806bfc60b46e26a4d10d054f8e5");
 pin("original.reader.py","ec2182b5075246b30ef96c5b6472adeafb6654c8");
 pin("original.parse-print.py","67eebb1703023041fe375a6313bb5f1506c5c0b5");
 pin("original.child.r4.py","62a75849b5eb5568564a12ee5e0f00cea95f56e5");
 pin("original.parent-core.r3.py","8ee0b29ea750d1b752b8ab26e27914a377dc61dd");
 pin("original.journal.r4.js","03e72b0bd32b4fe9219b98b0c6d4dab57182bead");
 pin("original.r4.stdout.public.json","5e6a6ad62efe78bee580edd50cd7e96f36da68ca");
 for(const name of ["original.common.r4.py","original.constants.r4.py","original.reader.py","original.parse-print.py","original.missing-service.py","original.child-validators.py"])
  ck("unchanged_embedded_"+name,source.includes(f(name)));
 ck("exact_new_main_suffix",source.endsWith(body));
 ck("original_child_validators_source",f("original.parent-core.r3.py").includes(f("original.child-validators.py").trimEnd()));
 const oldChild=f("original.child.r4.py");
 const oldCodes=JSON.parse(oldChild.match(/PUBLIC_ERROR_CODES = frozenset\((\[[^\n]+\])\)/)[1]);
 const codes=JSON.parse(source.match(/PUBLIC_ERROR_CODES = frozenset\((\[[^\n]+\])\)/)[1]);
 const childCodes=JSON.parse(source.match(/CHILD_PUBLIC_ERROR_CODES = frozenset\((\[[^\n]+\])\)/)[1]);
 ck("unchanged_child_closed_error_set",JSON.stringify(oldCodes)===JSON.stringify(childCodes));
 const parserCodes=calls(f("original.parse-print.py"));
 ck("eleven_parser_codes",new Set(parserCodes).size===11&&parserCodes.length===11&&parserCodes.every(c=>codes.includes(c)));
 const expectedCodes=Array.from(new Set([...oldCodes,...calls(source)])).sort();
 ck("exact_error_union",JSON.stringify(expectedCodes)===JSON.stringify(codes));
 ck("no_parser_sentinel_admission",f("original.parse-print.py").includes("typed_value=='78: EX_CONFIG'")&&!f("original.parse-print.py").includes("never exited"));
 const modules=JSON.parse(source.match(/MODULES = json\.loads\(r'''([^\n]+)'''\)/)[1]);
 ck("only_original_two_modules",modules.length===2);
 for(const row of modules) {
  const raw=utf8Text(unb64(row.base64)),p=gitBlobMeta(raw);
  ck("module_whole_"+row.name,p.blob===row.blob&&p.bytes===row.bytes&&p.sha256===row.sha256);
 }
 ck("source_request_stdin",request.stdin===source&&!("stdin_text" in request));
 ck("exact_request_fields",Object.keys(request).sort().join(",")==="args,cwd,executable,host,idempotency_key,stdin,timeout_seconds");
 ck("fixed_host_argv",request.host==="mac"&&request.cwd==="/Users/qianqi"&&request.timeout_seconds===60&&JSON.stringify(request.args)==='["-I","-S","-B","-"]');
 ck("regular_python_path",request.executable==="/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14");
 const sp=gitBlobMeta(source),rp=gitBlobMeta(requestRaw),jp=gitBlobMeta(journal);
 ck("request_identity_from_source",request.idempotency_key==="heptabao-mac-owned-home-t5-readonly-"+sp.sha256.slice(0,8)+"-20261106-r1");
 ck("exact_journal_request_binding",journal.includes('blob:"'+rp.blob+'"')&&journal.includes("bytes:"+rp.bytes+',sha256:"'+rp.sha256+'"'));
 const forward=strictApplySource(originalJournal,f("journal.forward.diff")),reverse=strictApplySource(journal,f("journal.reverse.diff"));
 ck("journal_strict_two_way",forward.raw===journal&&reverse.raw===originalJournal&&forward.hunks===2&&reverse.hunks===2);
 const normalized=journal.replace("owner_launchd_home_t5_existing_readonly_gitfirst_r1","owner_launchd_home_t5_probe_gitfirst_r4")
 .replace(rp.blob,"158c70818b4cab3e39f87c31a5075a35e25dab6c")
 .replace("bytes:"+rp.bytes+',sha256:"'+rp.sha256+'"','bytes:170971,sha256:"34115f596b8942341d1eb6f89fd86aa2371bc44fba31ca53d1c51e280d1828ee"')
 .replace("home-t5-readonly-"+sp.sha256.slice(0,8)+"-","home-t5-probe-87ddc495-");
 ck("only_journal_bindings_changed",normalized===originalJournal);
 const actual=JSON.parse(f("original.r4.stdout.public.json"));
 const inputs=JSON.parse(source.match(/INPUT_PINS = json\.loads\(r'''([^\n]+)'''\)/)[1]);
 const argv=JSON.parse(source.match(/EXPECTED_ARGV = json\.loads\(r'''([^\n]+)'''\)/)[1]);
 ck("original_exact_managed_argv",JSON.stringify(argv)===JSON.stringify(actual.exactProgramArguments)&&argv.length===9);
 const leafCandidates=[];
 function walk(value) {
  if(value&&typeof value==="object") {
   if(typeof value.path==="string"&&Array.isArray(value.identity)&&typeof value.bytes==="number"&&typeof value.sha256==="string")leafCandidates.push(value);
   for(const v of Object.values(value))walk(v);
  }
 }
 walk(actual);
 for(const [path,p] of Object.entries(inputs)) {
  if(path===request.executable) {
   ck("python_original_pin",p.bytes===34640&&p.sha256==="cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13"&&JSON.stringify(p.identity)===JSON.stringify(["16777233","587518380","501","80","33261","1","34640","1793798038915516382","1793798038915695047"]));
  } else {
   ck("actual_created_leaf_"+path.split("/").pop(),leafCandidates.some(v=>v.path===path&&v.bytes===p.bytes&&v.sha256===p.sha256&&JSON.stringify(v.identity)===JSON.stringify(p.identity)));
  }
 }
 ck("four_pinned_inputs",Object.keys(inputs).length===4);
 ck("body_caps_arithmetic",Object.values(inputs).reduce((n,p)=>n+p.bytes,0)+8192+32768+4096===118977&&contract.budgets.sumSuccessfulBodyMaxima===118977);
 ck("contract_all_three_source_pins",JSON.stringify(contract.source)===JSON.stringify(sp)&&JSON.stringify(contract.request)===JSON.stringify(rp)&&JSON.stringify(contract.journal)===JSON.stringify(jp));
 ck("shared_deadlines",body.includes("PARENT_START_NS + 45000000000")&&body.includes("PARENT_START_NS + 35000000000")&&contract.budgets.outerSeconds===60);
 ck("bounded_four_commands",body.includes("self.calls < 4")&&body.includes("self.command_bytes < 1048576")&&body.includes("self.command_bytes <= 1048576"));
 ck("read_only_scope",body.includes("io.writable = set()")&&body.includes("io.max_writes = 0")&&!/\bio\.(write|mkdir|absent)\(/.test(body)&&!/\bos\.(open|mkdir|write|kill|killpg|chdir)\(/.test(body));
 ck("fixed_two_query_sites",body.includes("first,first_value = control.query(1)")&&body.includes("second,second_value = control.query(2)"));
 ck("no_unknown_command_hashes",!body.slice(body.indexOf("def safe_commands_public"),body.indexOf("def main")).includes("Sha256"));
 ck("unchanged_original_child_error_predicate_plus_extra_bound",body.includes("code is None or code in CHILD_PUBLIC_ERROR_CODES")&&body.includes("validate_child_terminal(raw,ready_identity)"));
 ck("actual_birth_shape_and_two_samples",body.includes("for _ in range(2):")&&body.includes("info.birth_sec > 0 and info.birth_usec < 1000000"));
 ck("no_success_claim_for_registration",body.includes("'registrationClosureClaimed':False")&&body.includes("'originalR4ManagedScopeStillUnknown':True"));
 ck("fresh_no_native_go",contract.status==="SOURCE_ONLY_NO_NATIVE_GO"&&contract.slotInitialized===false);
 ck("no_managed_signals_reap_or_bootout",contract.ownership.existingManagedPidSignalled===false&&contract.ownership.existingManagedPidReaped===false&&contract.ownership.bootout===false);
 return {ok:true,scope:"pure V8 source/literal/pin/reconstruction checks only",checkCount:checks.length,checks,source:sp,request:rp,journal:jp,parserCodes,pinnedBodyMaximum:118977,pythonModuleExecuted:false,nativeCalls:0,oldR4FailureUnchanged:true};
}