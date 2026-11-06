/* Pure V8 source-byte verifier. No Python, native SDK or candidate execution.
 * Interface: verifyReadonlyLibprocR3(texts, {pin, apply, unb64, utf8Text}).
 * texts is the flat packet path->UTF-8 string map. Helpers are the exact
 * pure-helpers.original.js and unified-diff-helpers.original.js in this packet.
 */
function verifyReadonlyLibprocR3(t, api) {
  const checks=[];
  function need(ok,name) { checks.push({name,passed:!!ok}); if(!ok)throw Error(name); }
  const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
  const c=JSON.parse(t["CONTRACT.public.json"]);
  const before=t["diagnostic.r2.before.py"], after=t["diagnostic.libproc.r3.py"];
  const qb=JSON.parse(t["exact-request.r2.before.public.json"]);
  const qa=JSON.parse(t["exact-request.libproc.r3.public.json"]);
  const jb=t["journal.r2.before.js"],ja=t["journal.libproc.r3.js"];
  const pin=(p,e)=>need(same(api.pin(t[p]),e),"whole:"+p);
  try {
    pin("diagnostic.libproc.r3.py",c.source);
    pin("diagnostic.r2.before.py",c.previousReadonlyR2.source);
    pin("exact-request.libproc.r3.public.json",c.request);
    pin("exact-request.r2.before.public.json",c.previousReadonlyR2.request);
    pin("journal.libproc.r3.js",c.journal);
    pin("journal.r2.before.js",c.previousReadonlyR2.journal);
    const f=api.apply(before,t["diagnostic.r2-to-r3.diff"]);
    const r=api.apply(after,t["diagnostic.r3-to-r2.diff"]);
    need(f.raw===after&&r.raw===before&&f.hunks===6&&r.hunks===6,"strict-source-six-hunks-both-directions");
    const jf=api.apply(jb,t["journal.r2-to-r3.diff"]),jr=api.apply(ja,t["journal.r3-to-r2.diff"]);
    need(jf.raw===ja&&jr.raw===jb&&jf.hunks===2&&jr.hunks===2,"strict-journal-two-hunks-both-directions");
    need(qa.stdin===after&&qb.stdin===before&&!Object.hasOwn(qa,"stdin_text"),"typed-stdin-whole-source");
    need(qa.idempotency_key===c.requestIdempotencyKey&&qa.idempotency_key!==qb.idempotency_key,"fresh-observer-key");
    const omit=q=>Object.fromEntries(Object.entries(q).filter(([k])=>!["stdin","idempotency_key"].includes(k)));
    need(same(omit(qa),omit(qb)),"all-other-start-fields-exact");
    const nJournal=s=>s.replace(/const GF_SLOT = [^\n]+\n/,"const GF_SLOT = <slot>\n")
      .replace(/const GF_REQUEST = \{blob:"[0-9a-f]+",\n bytes:[0-9]+,sha256:"[0-9a-f]+"\};/,"const GF_REQUEST = <pin>;")
      .replace(/\^heptabao-mac-owned-home-t5-readonly-[0-9a-f]{8}-/g,"^heptabao-mac-owned-home-t5-readonly-<hash>-");
    need(nJournal(ja)===nJournal(jb),"journal-all-functions-unchanged-besides-three-bindings");
    need(ja.includes('const GF_SLOT = "'+c.newSlot+'";')&&c.slotInitialized===false,"fresh-slot-source-only");
    need(ja.includes(c.request.blob)&&ja.includes(c.request.sha256)&&ja.includes("bytes:"+c.request.bytes),"journal-exact-request-pin");
    const start="PARENT_START_NS = time.monotonic_ns()";
    const pre=s=>s.slice(0,s.indexOf(start)).replace(/^PUBLIC_ERROR_CODES = [^\n]+\n/m,"PUBLIC_ERROR_CODES=<set>\n");
    need(pre(before)===pre(after),"entire-embedded-preamble-unchanged-except-parent-error-allowlist");
    const line=(s,key)=>s.split("\n").find(v=>v.startsWith(key));
    const errors=s=>JSON.parse(line(s,"PUBLIC_ERROR_CODES = ").slice("PUBLIC_ERROR_CODES = frozenset(".length,-1));
    const eb=errors(before),ea=errors(after);
    const added=ea.filter(x=>!eb.includes(x));
    need(eb.every(x=>ea.includes(x))&&same(added,[
      "fixed_native_pid_call_cap","native_pid_absolute_query_deadline","native_pid_complete_numeric_sample",
      "native_pid_exact_numeric_offsets","native_pid_self_numeric_crosscheck","native_pid_two_sample_kind_changed"
    ]),"only-six-fixed-parent-error-codes-added");
    need(line(before,"CHILD_PUBLIC_ERROR_CODES = ")===line(after,"CHILD_PUBLIC_ERROR_CODES = "),"child-error-code-set-byte-exact");
    const moduleMatch=/^MODULES = json.loads\(r'''(.*)'''\)$/m.exec(after);
    need(moduleMatch!==null,"embedded-module-list-literal");
    for(const m of JSON.parse(moduleMatch[1])){
      const raw=api.utf8Text(api.unb64(m.base64));
      need(raw===t["reference."+m.name+".py"]&&same(api.pin(raw),{blob:m.blob,bytes:m.bytes,sha256:m.sha256}),"unchanged-helper:"+m.name);
    }
    const body=after.slice(after.indexOf(start));
    function block(s,needle,next){const a=s.indexOf(needle);if(a<0)throw Error("missing-block:"+needle);const b=s.indexOf(next,a+needle.length);if(b<0)throw Error("missing-next:"+next);return s.slice(a,b);}
    for(const [a,z,name] of [
      ["    def call(","    def query(","direct-call"],
      ["    def query(","    def pid_observation(","old-query"]
    ]){
      const oldBlock=block(before,a,z);
      const newBlock=block(after,a,name==="old-query"?"    def native_pid_once(":z);
      need(oldBlock===newBlock,"unchanged-"+name);
    }
    for(const [a,z,name] of [
      ["def check_leaf_metadata(","def read_pinned(","leaf-final-fence"],
      ["def observe_ready(","def observe_terminal(","ready-validator"],
      ["def observe_terminal(","def safe_commands_public(","terminal-validator"],
      ["def safe_commands_public(","def main(","helper-public-projection"]
    ])need(block(before,a,z)===block(after,a,z),"unchanged-"+name);
    need(before.includes(t["original-ready-pid-method.r2.py"])&&!after.includes(t["original-ready-pid-method.r2.py"])
      &&after.includes(t["changed-methods.libproc.r3.py"]),"only-explicit-ready-pid-method-replaced");
    const methods=t["changed-methods.libproc.r3.py"];
    need(!methods.includes("/bin/ps")&&!methods.includes("self.call("),"no-explicit-ready-pid-child");
    need(methods.includes("proc_pidinfo(pid,3,1,ctypes.byref(info),ctypes.sizeof(info))"),"fixed-flavor-and-zombie-request");
    need(methods.includes("self.native_calls < 6")&&methods.includes("self.native_calls += 1"),"six-call-cap-before-call");
    need(methods.includes("ctypes.set_errno(0)\n            count =")&&methods.includes("number = ctypes.get_errno()"),"clear-and-immediate-errno-capture");
    need(methods.includes("count == 0 and number == errno.ESRCH")&&methods.includes("'originalBirthPresent':None")
      &&methods.includes("'existenceOrDepartureAutomaticallyConcluded':False"),"esrch-is-api-observation-only");
    need(methods.includes("count == ctypes.sizeof(info) and info.pid == pid")
      &&methods.includes("info.birth_sec > 0 and info.birth_usec < 1000000"),"complete-present-numeric-shape");
    need(methods.includes("except BaseException:\n            self.unknown = True\n            raise"),"native-read-exception-retains-unknown");
    need(methods.includes("'status':4,'pid':12,'ppid':16,'uid':20,'pgid':100")
      &&methods.includes("'birth_sec':120,'birth_usec':128")&&methods.includes("ctypes.sizeof(BsdInfo) == 136"),"exact-ABI-layout-guard");
    need(methods.includes("expected = (os.getpid(),os.getppid(),os.getpgrp(),os.geteuid())")
      &&methods.includes("first['identity'] == second['identity']")
      &&methods.includes("first['identity'][:4] == expected and expected[3] == 501"),"two-self-identity-crosschecks");
    need(methods.includes("pid = ready_identity['pid']")&&!methods.includes("87650")&&!methods.includes("58228"),"only-qualified-ready-pid-no-guessed-or-unknown-helper-query");
    need(methods.includes("min(HELPER_ADMISSION_END_NS,time.monotonic_ns()+4000000000)")
      &&methods.split("time.monotonic_ns() < until_ns").length===3,"fixed-four-second-deadline-pre-post");
    need(methods.includes("'installedKernelWholePinClaimed':False")
      &&methods.includes("'zombieBranchExecutedBySelfClaimed':False"),"reference-not-installed-kernel-or-zombie-qualification");
    need(body.includes("all(row['kind'] == 'reused_different_birth' for row in result['pidObservations'])")
      &&!body.includes("row['kind'] in ('absent'"),"esrch-not-automatic-departure");
    need(body.includes("'registrationClosureClaimed':False,'originalR4ManagedScopeStillUnknown':True")
      &&body.includes("'historicalReadonlyR2Helper87650ClosureStillUnknown':True"),"both-historical-unknowns-explicitly-preserved");
    for(const text of [
      "PARENT_UNTIL_NS = PARENT_START_NS + 45000000000",
      "HELPER_ADMISSION_END_NS = PARENT_START_NS + 35000000000",
      "self.calls < 4 and self.command_bytes < 1048576",
      "read_cap=262144,write_cap=0",
      "io.max_writes = 0",
      "if len(final_raw) > 65536:",
      "raise SystemExit(0 if result['ok'] and time.monotonic_ns() < PARENT_UNTIL_NS else 1)"
    ])need(before.includes(text)&&after.includes(text),"unchanged-bound:"+text);
    need(qa.timeout_seconds===60&&c.budgets.nativeReturnedStructBytesMaximum===6*136,"outer60-and-finite-numeric-return-domain");
    for(const ref of c.primarySourceReferences){
      pin(ref.file,ref.pin);
      const sdk=JSON.parse(t[ref.originalSdkFile]);
      need(sdk.isError===false&&sdk.structuredContent.content===t[ref.file],"official-original-SDK-whole:"+ref.path);
      const q=JSON.parse(t[ref.file+".request.public.json"]);
      need(q.url===ref.url&&ref.url.includes("/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/"),"official-fixed-commit:"+ref.path);
    }
    need(t["reference.apple.libproc.c"].includes("if ((retval = __proc_info(PROC_INFO_CALL_PIDINFO, pid, flavor, arg, buffer, buffersize)) == -1) {\n\t\treturn 0;"),"wrapper-failure-to-zero-reference");
    need(t["reference.apple.proc_info.c"].includes("if (arg) {\n\t\t\tfindzomb = 1;")
      &&t["reference.apple.proc_info.c"].includes("p = proc_find_zombref(pid);")
      &&t["reference.apple.proc_info.c"].includes("if ((error = proc_security_policy(p, PROC_INFO_CALL_PIDINFO, flavor, check_same_user)))"),"arg1-and-policy-reference-boundary");
    pin("reference.original-r2.stdout.public.json",c.previousReadonlyR2.stdout);
    pin("reference.original-r2.authority.public.json",c.previousReadonlyR2.authority);
    const a=JSON.parse(t["reference.original-r2.stdout.public.json"]);
    const helper=a.directHelpers.commands.find(x=>x.pid===87650);
    need(a.ok===false&&a.observationComplete===false&&a.outcomeUnknown===true&&a.pidObservations.length===0
      &&helper.cleanup.custody===null&&helper.cleanup.directChildReaped===false
      &&helper.cleanup.errorCode==="owned_child_scope_mismatch","original-helper-unknown-not-backfilled");
    return {schema:"heptabao.readonly-libproc-r3.pure-source-checks.v1",passed:true,checkCount:checks.length,checks,
      scope:"Exact SOURCE/whole/strict-diff bindings only; no Python, candidate, SDK, Native or old component execution."};
  }catch(e){return {schema:"heptabao.readonly-libproc-r3.pure-source-checks.v1",passed:false,checkCount:checks.length,checks,
    error:String(e),candidateExecuted:false,runtimeCalls:0};}
}
