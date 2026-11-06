function verifyOfficialAcl23FixtureR2Source(files) {
 const checks=[];function ck(name,v){checks.push({name,passed:!!v});if(!v)throw Error(name);}
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b),meta=gitBlobMeta,plan=JSON.parse(files["PLAN.public.json"]);
 const before=files["acl.before.py"],after=files["acl.after.py"],entryBefore=files["entry.before.py"],entry=files["entry.after.py"],journalBefore=files["journal.before.js"],journal=files["journal.after.js"];
 for(const [name,a,b]of [["acl",before,after],["entry",entryBefore,entry],["journal",journalBefore,journal]]){
  ck(name+" strict forward",applyStrict(a,files[name+".strict.diff"],false)===b);
  ck(name+" strict reverse",applyStrict(b,files[name+".strict.diff"],true)===a);
 }
 ck("ACL five explicit hunks",(files["acl.strict.diff"].match(/^@@/gm)||[]).length===5);
 const build=new Function(files["pure.original.js"]+"\n"+files["strict-diff.original.js"]+"\n"+files["typed-binding.correct.original.js"]+"\n"+files["generator.source.js"]+"\nreturn makeOracleFixtureR2;")();
 const generated=build(files["REQUEST.before.exact.json"],journalBefore);
 ck("generator exact all source",generated.after===after&&generated.entry===entry&&generated.journal===journal);
 ck("generator exact request and payload",generated.requestRaw===files["REQUEST.after.exact.json"]&&generated.payloadRaw===files["PAYLOAD.after.original.json"]);
 ck("entry exact pin",same(meta(entry),plan.source));
 ck("ACL exact pin",same(meta(after),plan.aclExecutor));
 ck("journal exact pin",same(meta(journal),plan.journal));
 ck("request exact pin",same(meta(files["REQUEST.after.exact.json"]),plan.request));
 ck("payload exact pin",same(meta(files["PAYLOAD.after.original.json"]),plan.payload));
 ck("451 original public PEM unchanged",files["PUBLIC-KEY.source.pem"]===JSON.parse(JSON.parse(files["REQUEST.before.exact.json"]).stdin).files["PUBLIC-KEY.pem"]&&meta(files["PUBLIC-KEY.source.pem"]).bytes===451&&same(meta(files["PUBLIC-KEY.source.pem"]),plan.publicKeySource));
 ck("one LF removed only request value",files["PUBLIC-KEY.request-value.txt"]+"\n"===files["PUBLIC-KEY.source.pem"]&&files["PUBLIC-KEY.source.pem"].endsWith("-----END PUBLIC KEY-----\n")&&meta(files["PUBLIC-KEY.request-value.txt"]).bytes===450&&same(meta(files["PUBLIC-KEY.request-value.txt"]),plan.publicKeyRequestValue));
 ck("request canonicalization is one explicit slice",(after.match(/public_pem\[:-1\]/g)||[]).length===1&&after.includes('"jwt_validation_pubkeys": [public_pem[:-1]]'));
 ck("validated PEM format remains unchanged",before.slice(before.indexOf("        if (not isinstance(public_pem"),before.indexOf("        self.calls ="))===after.slice(after.indexOf("        if (not isinstance(public_pem"),after.indexOf("        self.calls =")));
 ck("public setup projection initialized None",after.includes("        self.setup_config_projection = None\n"));
 ck("public projection stored before same strict comparison",after.includes('        state = self.snapshot()\n        self.setup_config_projection = state["config"]\n        if state["config"] != self.baseline_config:\n            raise BaoError("common_config_projection_mismatch")'));
 ck("projection exposed in both success partial",(after.match(/"setup_config_projection": self.setup_config_projection/g)||[]).length===2);
 ck("only three public config fields",after.includes('COMMON_CONFIG_FIELDS = ("bound_issuer", "jwt_validation_pubkeys", "jwt_supported_algs")'));
 const method=(s,n)=>{const a=s.indexOf("    def "+n+"("),end=s.indexOf("\n    def ",a+1);return s.slice(a,end<0?s.length:end);};
 for(const n of ["admin_call","require_status","role_body","common_role","snapshot","issue_actor","case_payload","verify_transition"])ck("unchanged method "+n,method(before,n)===method(after,n));
 ck("run case loop and raw wire unchanged",method(before,"run").split('        return {"matrix_cases": 23')[0]===method(after,"run").split('        return {"matrix_cases": 23')[0]);
 ck("no actor default injection",after.includes('"policies": [policy_name], "no_default_policy": True')&&method(before,"issue_actor")===method(after,"issue_actor"));
 const q=JSON.parse(files["REQUEST.after.exact.json"]),oldQ=JSON.parse(files["REQUEST.before.exact.json"]),payload=JSON.parse(q.stdin),oldPayload=JSON.parse(oldQ.stdin);
 ck("eleven fixed input paths unchanged",same(Object.keys(payload.files),Object.keys(oldPayload.files))&&Object.keys(payload.files).length===11);
 ck("only one runtime input changed",Object.keys(payload.files).filter(k=>payload.files[k]!==oldPayload.files[k]).join(",")==="source/qa/openbao-acceptance/acl23_executor.py");
 ck("ten other inputs byteidentical",Object.keys(payload.files).filter(k=>k!=="source/qa/openbao-acceptance/acl23_executor.py").every(k=>payload.files[k]===oldPayload.files[k]));
 ck("original matrix whole untouched",same(meta(payload.files["MATRIX23.original.public.json"]),plan.matrixUnchanged));
 ck("all input pins exact",Object.keys(payload.files).every(k=>same(meta(payload.files[k]),plan.immutableInputs[k])));
 ck("source bytes explicit",Object.values(payload.files).reduce((n,s)=>n+meta(s).bytes,0)===127412&&plan.budgets.sourceBytes===127412);
 ck("same compact payload serializer",JSON.stringify(payload)+"\n"===q.stdin&&q.stdin===files["PAYLOAD.after.original.json"]);
 ck("entry implementation tail unchanged",entry.slice(entry.indexOf("class EntryFailure"))===entryBefore.slice(entryBefore.indexOf("class EntryFailure")));
 ck("fresh root literal",entry.includes('ROOT = Path("/home/qian/heptabao-official271-acl23-oracle-20261106-r2")')&&!entry.includes('ROOT = Path("/home/qian/heptabao-official271-acl23-oracle-20261106-r1")'));
 ck("fresh ports",entry.includes("PORT = 23625")&&plan.freshClusterPort===23626&&plan.freshHttpsPort!==plan.originalScopeUntouched.httpsPort);
 ck("fresh run ID",entry.includes('RUN_ID = "official271-acl23-r2"'));
 ck("Owner360 and report budget remain",entry.includes("OWNER_SECONDS = 360")&&entry.includes("ACL_REQUEST_CAP = 853")&&entry.includes("REPORT_CAP = 1048576")&&entry.includes("FD_LIMIT = 12")&&entry.includes("UNTIL_NS = START_NS + OWNER_SECONDS * 1_000_000_000"));
 ck("new entry exact self and stdin",q.args.length===6&&q.args.slice(0,4).join(",")==="-I,-S,-B,-c"&&q.args[4]===entry&&q.args[5]===meta(entry).sha256&&q.stdin===files["PAYLOAD.after.original.json"]);
 ck("same X230 launcher outer390",q.host==="x230"&&q.executable==="/usr/bin/python3"&&q.cwd==="/home/qian"&&q.timeout_seconds===390);
 ck("fresh explicit business key",q.idempotency_key==="heptabao-official271-x230-acl23-oracle-r2-"+meta(entry).sha256.slice(0,8)&&q.idempotency_key!==oldQ.idempotency_key);
 const bind=processStartBinding(q);
 ck("typed binding exact",bind.sha256===plan.typed.sha256&&bind.native_fingerprint===plan.typed.fingerprint_decimal&&utf8Bytes(bind.canonical).length===plan.typed.canonical_bytes);
 ck("fresh journal slot",journal.includes('const GF_SLOT = "official271_x230_acl23_oracle_gitfirst_r2";'));
 ck("journal only three data bindings",generated.journalBindings.length===3&&generated.journalBindings.reduce((s,[a,b])=>s.replace(b,a),journal)===journalBefore);
 ck("root primary evidence exact",same(meta(files["PRIMARY-FINDING.public.json"]),plan.primaryEvidence.finding));
 ck("source only preserves original fail",plan.nativeCalls===0&&plan.originalScopeUntouched.processMethodPassed===false&&plan.originalScopeUntouched.sameOriginalsClosed===true&&plan.originalScopeUntouched.bodyRootQualification===null);
 return {schema:"heptabao.official271.acl23.fixture-r2-source-check.r1",passed:true,check_count:checks.length,checks,python_runs:0,native_calls:0,product_cases:0,new_fixture_started:false};
}