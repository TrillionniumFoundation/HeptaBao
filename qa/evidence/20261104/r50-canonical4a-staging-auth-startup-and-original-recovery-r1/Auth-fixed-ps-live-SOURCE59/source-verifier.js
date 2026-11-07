/* Pure V8 source binding review only. No Python, candidate code, Native, or host I/O.
 * Load pure-helper.original.js + strict-diff-helper.original.js +
 * actual-stdin-binding.js, then this file; call verifyOwnerAndFixedPsSourceR1(files).
 * files is an exact flat path->UTF-8 text map from this SOURCE packet.
 */
function verifyOwnerAndFixedPsSourceR1(files) {
 const checks=[];
 function check(name,value){checks.push({name,passed:value===true});}
 function whole(raw,pin){const m=gitBlobMeta(raw);return m.blob===pin.blob&&m.bytes===pin.bytes&&m.sha256===pin.sha256;}
 function section(s,a,b){const x=s.indexOf(a),y=s.indexOf(b,x+a.length);if(x<0||y<0)throw new Error("source_section:"+a);return s.slice(x,y);}
 function topDef(s,n){const start=s.indexOf("def "+n+"(");if(start<0)throw new Error("definition:"+n);const x=s.indexOf("\ndef ",start+1);return s.slice(start,x<0?s.length:x).trimEnd();}
 function parseB64Assignment(s,name){const m=s.match(new RegExp("^"+name+"=json\\.loads\\(base64\\.b64decode\\('([A-Za-z0-9+/=]+)'\\)\\)","m"));if(!m)throw new Error("assignment:"+name);return JSON.parse(utf8Text(unb64(m[1])));}
 const contract=JSON.parse(files["CONTRACT.public.json"]);
 const components=JSON.parse(files["COMPONENT-CONTRACT.corrected.json"]);
 const q=JSON.parse(files["request.exact.public.json"]), s=files["controller.py"],j=files["journal.js"];
 check("prospective controller exact whole",whole(s,contract.source));
 check("prospective request exact whole",whole(files["request.exact.public.json"],contract.exact_request));
 check("prospective journal exact whole",whole(j,contract.journal));
 check("wire input actual stdin only",q.stdin===s&&!Object.prototype.hasOwnProperty.call(q,"stdin_text"));
 check("exact Python isolated argv / cwd / 60",q.host==="mac"&&q.executable==="/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14"&&JSON.stringify(q.args)==='["-I","-S","-B","-"]'&&q.cwd==="/Users/qianqi"&&q.timeout_seconds===60);
 check("key and fresh slot/source binding",q.idempotency_key===contract.idempotency_key&&j.includes("const GF_SLOT = "+JSON.stringify(contract.slot)+";")&&j.includes("const GF_REQUEST = "+JSON.stringify(contract.exact_request)+";"));
 const binding=actualStdinProcessStartBinding(q);
 check("current stdin typed digest/fingerprint",binding.sha256===contract.nativeBinding.sha256&&binding.native_fingerprint===contract.nativeBinding.native_fingerprint&&gitBlobMeta(binding.canonical).bytes===contract.nativeBinding.canonicalBytes);
 const names={
 reader:"mac_native_process_observer_r1.py",unreaped:"mac_owned_unreaped_r1.py",
 commands:"mac_owned_commands_r1.py",manager:"mac_owned_launchd_r3.py",
 outer:"mac_current_outer_wal_r1.py",materializer:"mac_current_fixture_materializer_r1.py"};
 const expectedHunks={reader:3,unreaped:5,commands:7,manager:4,outer:1,materializer:1};
 for(const [key,n]of Object.entries(names)) {
  const before=files["before--"+n],after=files["after--"+n];
  const f=files["forward--"+n+".diff"],i=files["inverse--"+n+".diff"];
  const fp=strictApplySource(before,f),ip=strictApplySource(after,i);
  check(key+" strict forward whole",fp.raw===after&&fp.hunks===expectedHunks[key]);
  check(key+" strict inverse whole",ip.raw===before&&ip.hunks===expectedHunks[key]);
 }
 const mods=parseB64Assignment(s,"MODULES"),inputs=parseB64Assignment(s,"INPUT_PINS");
 check("only two repaired helper modules embedded",Object.keys(mods).join(",")==="mac_owned_unreaped_r1,mac_owned_commands_r1");
 for(const [name,payload] of Object.entries(mods)){
  const raw=utf8Text(unb64(payload.base64));
  check(name+" complete embedded pin matches source",raw===files["after--"+name+".py"]&&whole(raw,payload));
 }
 check("two fixed inputs only",JSON.stringify(inputs)===JSON.stringify(contract.fixedPublicInputPins)&&Object.keys(inputs).length===2);
 const fixed=inputs["/bin/ps"];
 check("actual ps fixed setuid full9/hash",fixed.bytes===170432&&fixed.sha256==="3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c"&&JSON.stringify(fixed.identity)==='["16777233","1152921500312571399","0","0","35309","1","170432","1786589515000000000","1786589515000000000"]');
 const ub=files["before--"+names.unreaped],u=files["after--"+names.unreaped];
 const cb=files["before--"+names.commands],c=files["after--"+names.commands];
 const rb=files["before--"+names.reader],r=files["after--"+names.reader];
 const mb=files["before--"+names.manager],m=files["after--"+names.manager];
 const ob=files["before--"+names.outer],o=files["after--"+names.outer];
 const matb=files["before--"+names.materializer],mat=files["after--"+names.materializer];
 for(const fn of ["require_waitid","exit_observation","stable","ps_rows","verify_unreaped","observed_returncode"])check("retained helper "+fn+" entire unchanged",topDef(ub,fn)===topDef(u,fn));
 check("fixed descriptor binds all fields and operator 501",u.includes('type(pin) is dict and pin == expected and os.geteuid() == 501')&&u.includes('"35309", "1", "170432"'));
 check("only fixed marker changes expected euid",u.includes("expected_uid = os.geteuid() if admitted is None else 0"));
 check("parent group and explicit effective uid still conjunctive",u.includes('need(row["ppid"] == os.getpid() and row["pgid"] == child.pid\n         and row["uid"] == expected_uid, "owned_child_scope_mismatch")'));
 check("fixed ps evidence precedes guard",u.indexOf("admission_evidence.update")<u.indexOf('need(row["ppid"] == os.getpid()'));
 check("uid0 exception is only exact stable primary",u.includes('admitted is not None and row["pid"] == child.pid\n                 and stable(row) == owner["ps"] and row["uid"] == 0')&&u.includes('need(all(row["uid"] == os.geteuid()'));
 const stopRestore=topDef(u,"stop_once_unreaped").replace("def stop_once_unreaped(child, owner, *, fixed_setuid_ps=None):","def stop_once_unreaped(child, owner):").replace("owner=capture_child(child,until=term_until,fixed_setuid_ps=fixed_setuid_ps)","owner=capture_child(child,until=term_until)");
 check("complete once cleanup only fixed-pin forwarding differs",stopRestore===topDef(ub,"stop_once_unreaped"));
 check("Commands explicit fixed opt-in default false",c.includes("fixed_setuid_ps=False):")&&c.includes("type(fixed_setuid_ps) is bool"));
 check("Commands exact label argv and 262144 guard",c.includes("label=='owned-launchd-group-observation'")&&c.includes("argv==['/bin/ps','-axo','pid=,ppid=,pgid=,uid=,stat=']")&&c.includes("and maximum==262144"));
 check("whole descriptor admission before any row",c.includes("self.fixed_setuid_ps is None and not self.rows"));
 check("exact two named full9 fences", (c.match(/verify_fixed_ps_name\(\)/g)||[]).length===3&&c.indexOf("verify_fixed_ps_name()\n        started")<c.indexOf("p=subprocess.Popen")&&c.includes("if admitted is not None:verify_fixed_ps_name()\n            row['completeBeforeDeadline']=True"));
 const commandStreamStart="            streams={p.stdout.fileno():out,p.stderr.fileno():err}";
 const commandStreamEnd="            row['completeBeforeDeadline']=True";
 const afterStream=section(c,commandStreamStart,commandStreamEnd).replace("            if admitted is not None:verify_fixed_ps_name()\n","");
 check("primary stream/select/bounds and retained exit unchanged",section(cb,commandStreamStart,commandStreamEnd)===afterStream);
 check("Popen explicit environment/setsid/close_fds unchanged",section(cb,"                p=subprocess.Popen","                row=")===section(c,"                p=subprocess.Popen","                row="));
 check("reader keeps actual use_errno",r.includes("use_errno=True")&&rb.includes("use_errno=True"));
 check("default read does not accept absence",r.includes("def read(self, pid, *, allow_absent=False):"));
 check("three original C calls unchanged",JSON.stringify((r.match(/^        (?:count|length) = self\.lib\.(?:proc_pidinfo|proc_pidpath).*$/gm)||[]))===JSON.stringify((rb.match(/^        (?:count|length) = self\.lib\.(?:proc_pidinfo|proc_pidpath).*$/gm)||[])));
 check("three explicit errno reset/capture pairs", (r.match(/ctypes\.set_errno\(0\)/g)||[]).length===3&&(r.match(/error_number = ctypes\.get_errno\(\)/g)||[]).length===3);
 check("only count/length zero plus ESRCH", (r.match(/if (?:count|length) == 0 and error_number == errno\.ESRCH:/g)||[]).length===3&&(r.match(/raise ProcessAbsent\(pid,/g)||[]).length===3);
 check("only phase reader uses opt-in", (m.match(/allow_absent=True/g)||[]).length===1);
 check("same observed PID before opt-in read",m.includes("need(state['pid']==entry['wrapperIdentity']['pid'],'same_phase_process')\n                try:\n                    observed=self.reader.read(state['pid'],allow_absent=True)"));
 check("ESRCH same registration runs1 noPID and exit-zero retained",m.includes("state=self._query(entry['label'],entry)\n                    need(state is not None and state.get('runs')==1 and state.get('pid') is None,")&&m.includes("'historicalReapProved':False")&&m.includes("need(state.get('last exit code')==0,'actual_launchd_phase_exit_zero')"));
 const terminalStart="            need(state.get('last exit code')==0,'actual_launchd_phase_exit_zero')";
 check("all phase terminal result resource and bootout gates unchanged",section(mb,terminalStart,"    def abort_cleanup_once")===section(m,terminalStart,"    def abort_cleanup_once"));
 check("manager ps flag reaches only same Commands call",m.includes("fixed_setuid_ps=ps")&&(m.match(/ps=True/g)||[]).length===(mb.match(/ps=True/g)||[]).length);
 check("outer existing tool loop retains full9 to admit fixed ps",o.includes("commands.admit_fixed_setuid_ps")&&o.indexOf("commands.admit_fixed_setuid_ps")<o.indexOf("commands.run('outer-t5-volume'")&&section(ob,"def read_system_tool","def ")===section(o,"def read_system_tool","def "));
 check("materializer exactly one root-literal append",mat.replace("    lines.append('(allow file-read* (literal \"/\"))')\n","")===matb);
 check("component contract actual LF33 correction only documentation",components.profile.onlyAddition==='(allow file-read* (literal "/"))\n'&&gitBlobMeta(components.profile.onlyAddition).bytes===33&&components.archivalWordingCorrection.sourceChanged===false);
 check("InputAudit controller slice exact",section(s,"class InputAudit:","def public_command(")===files["input-audit.after.py"]);
 check("InputAudit strict forward/inverse",strictApplySource(files["input-audit.before.py"],files["input-audit.forward.diff"]).raw===files["input-audit.after.py"]&&strictApplySource(files["input-audit.after.py"],files["input-audit.inverse.diff"]).raw===files["input-audit.before.py"]);
 check("controller common and loader entire inherited",section(s,"class Refused(RuntimeError):","class InputAudit:")===files["controller-common.original.py"]&&section(s,"def load_modules():","def main():").trimEnd()+"\n"===files["module-loader.original.py"]);
 const input=files["input-audit.after.py"],ib=files["input-audit.before.py"];
 check("InputAudit two held FDs plus pending/unknown ledger",input.includes("self.max_rows=2")&&input.includes("ledger['pending'] += 1")&&input.indexOf("ledger['pending'] += 1")<input.indexOf("fd = os.open")&&input.includes("ledger['registrationUnknown'] = True"));
 check("InputAudit full-loop critical once-close retained",section(input,"    def close_one","    def admit")===section(ib,"    def close_one","    def admit"));
 check("InputAudit no writes/alias/scans",!input.includes("def alias(")&&input.includes("os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK")&&!s.includes("os.scandir(")&&!s.includes("os.mkdir(")&&!s.includes("os.makedirs("));
 check("only one primary streaming fixed ps call",(s.match(/value,out,err=commands\.run\(/g)||[]).length===1&&s.includes("until=min(UNTIL-9.0,time.monotonic()+4.0),maximum=262144,fixed_setuid_ps=True"));
 check("four seconds plus nine cleanup reserved",s.includes("time.monotonic()+4.0+9.0<UNTIL")&&s.includes("UNTIL=START+35.0")&&s.includes("FINAL_UNTIL=START+45.0"));
 check("only own table row and bounded count exported",s.includes("if pid==value['pid']:")&&s.includes("count<=8192")&&s.includes("'otherRowsOrStateTextExported':False"));
 const pc=section(s,"def public_command(","def load_modules");
 check("public command projection excludes hashes/raw streams",!pc.includes("stdoutSha256")&&!pc.includes("stderrSha256")&&!pc.includes("'stdout'")&&!pc.includes("'stderr'"));
 check("known raw errors not exported by public command",pc.includes("value.get('errorCode') in ERROR_CODES")&&pc.includes("else None"));
 check("final fixed fences / FD / children / handler gates",s.includes("and report['inputs']")===false&&s.includes("report['allOwnDescriptorsAndChildrenClosed']")&&s.includes("and not report['outcomeUnknown'] and report['original45SecondDeadlineMetAfterClosure']"));
 check("journal strict forward/inverse",strictApplySource(files["journal.before.js"],files["journal.forward.diff"]).raw===j&&strictApplySource(j,files["journal.inverse.diff"]).raw===files["journal.before.js"]);
 const originalDescriptor=files["journal.before.js"].match(/const GF_REQUEST = \{[\s\S]*?\};/)[0];
 const restore=j.replace("const GF_SLOT = "+JSON.stringify(contract.slot)+";","const GF_SLOT = \"owner_authbus_public_node_startup_root_read_gitfirst_r1\";").replace(/const GF_REQUEST = \{[\s\S]*?\};/,originalDescriptor).split("heptabao-mac-fixed-setuid-ps-custody-"+contract.source.sha256.slice(0,8)+"-").join("heptabao-mac-public-node-startup-root-read-2cce4cec-");
 check("journal only slot request prefix changed",restore===files["journal.before.js"]);
 check("no original namespace or credential execution permission",contract.futureBusinessBindings.oldNamespaceDispatchable===false&&contract.futureBusinessBindings.binary===null&&contract.futureBusinessBindings.issuer===null&&contract.budgets.nativeTimeoutSeconds===60);
 const primary=JSON.parse(files["PRIMARY-SOURCES.public.json"]);
 for(const item of primary.sources)check("whole Apple primary "+item.path,whole(files[item.path],item.pin));
 check("Apple UID column means effective uid",files["Apple-ps-keyword.original.c"].includes("e_ucred.cr_uid")&&files["Apple-ps-keyword.original.c"].includes("e_pcred.p_ruid"));
 const failed=checks.filter(x=>!x.passed);
 return {schema:"heptabao.fixed-ps-source-review.result.r1",passed:failed.length===0,checkCount:checks.length,checks,failed,NativeCalls:0,PythonModulesExecuted:0,authorCandidateExecuted:false,scope:"Exact source bindings and finite safety predicates only; real ps custody remains unobserved."};
}
