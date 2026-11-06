function verifyOfficialPki12Source(x) {
 const checks=[];function check(name,ok){checks.push({name,passed:ok===true});if(ok!==true)throw new Error(name);}
 function block(raw,name){const lines=raw.split("\n"),a=lines.findIndex(v=>new RegExp("^(?:def|class) "+name+"[(:]").test(v));if(a<0)throw new Error("missing "+name);let b=a+1;while(b<lines.length&&!/^(?:def|class) /.test(lines[b])&&!/^if __name__/.test(lines[b]))b++;return lines.slice(a,b).join("\n");}
 function applyEdits(raw,edits){for(const e of edits){check("exact_edit_"+(e.label||checks.length),raw.split(e.before).length-1===(e.count||1));raw=raw.split(e.before).join(e.after);}return raw;}
 check("entry_full_derivation",applyEdits(x.beforeEntry,x.entryEdits)===x.entry);
 check("entry_forward_strict",snapshotApply(x.beforeEntry,x.forward)===x.entry);
 check("entry_reverse_strict",snapshotApply(x.entry,x.reverse)===x.beforeEntry);
 for(const n of ["EntryFailure","need","check_deadline","full9","snapshot_artifacts","write_exact","signal_pending","closed_fds"])check("entry_unchanged_"+n,block(x.beforeEntry,n)===block(x.entry,n));
 const b=JSON.parse(x.payload),old=JSON.parse(x.beforePayload);
 check("payload_schema",b.schema==="heptabao.X230-official271-pki12-fixed-inputs.v1");
 check("nine_exact_ordered_inputs",JSON.stringify(Object.keys(b.files))===JSON.stringify(x.inputs.map(r=>r[0]))&&x.inputs.length===9);
 let bytes=0;for(const [path,size,sha] of x.inputs){const m=gitBlobMeta(b.files[path]);bytes+=m.bytes;check("input_whole_"+path,m.bytes===size&&m.sha256===sha);if(path.endsWith("/acceptance.py"))check("current_acceptance_whole",b.files[path]===x.acceptance);else check("unchanged_donor_"+path,b.files[path]===old.files[path]);}
 check("source_total",bytes===133117);const pm=gitBlobMeta(x.payload);
 check("payload_bound",pm.bytes===140624&&x.entry.includes("PAYLOAD_BYTES = "+pm.bytes)&&x.entry.includes('PAYLOAD_SHA256 = "'+pm.sha256+'"'));
 const q=JSON.parse(x.request),oldq=JSON.parse(x.beforeRequest),em=gitBlobMeta(x.entry);
 check("request_exact_scope",Object.keys(q).sort().join(",")==="args,cwd,executable,host,idempotency_key,stdin,timeout_seconds"&&q.host==="x230"&&q.executable==="/usr/bin/python3"&&q.cwd==="/home/qian"&&q.timeout_seconds===390);
 check("request_original_transport_shape",q.host===oldq.host&&q.executable===oldq.executable&&q.cwd===oldq.cwd&&q.timeout_seconds===oldq.timeout_seconds);
 check("request_whole_inline_source",JSON.stringify(q.args)===JSON.stringify(["-I","-S","-B","-c",x.entry,em.sha256])&&q.stdin===x.payload);
 check("request_unique_fresh_key",q.idempotency_key==="heptabao-official271-x230-pki12-oracle-r1-"+em.sha256.slice(0,8)&&q.idempotency_key!==oldq.idempotency_key);
 const typed=processStartBinding(q);check("correct_stdin_native_binding",typed.sha256===x.expectedNative.sha256&&typed.native_fingerprint===x.expectedNative.native_fingerprint);
 check("journal_derivation",applyEdits(x.beforeJournal,x.journalEdits)===x.journal);
 check("journal_forward_strict",snapshotApply(x.beforeJournal,x.journalForward)===x.journal);
 check("journal_reverse_strict",snapshotApply(x.journal,x.journalReverse)===x.beforeJournal);
 check("journal_exact_request",x.journal.includes("const GF_REQUEST = "+JSON.stringify(gitBlobMeta(x.request))+";"));
 check("journal_fresh_slot",x.journal.includes('const GF_SLOT = "official271_x230_pki12_oracle_gitfirst_r1";'));
 check("original_deadline_and_cleanup",x.entry.includes("OWNER_SECONDS = 360")&&x.entry.includes("deadline_ns=UNTIL_NS")&&x.entry.includes('profile="official271_pki12_oracle"'));
 check("same_official_launcher_once",x.entry.split("oracle = launcher.start_oracle(").length===2&&x.entry.includes("launcher.stop_oracle(oracle)"));
 check("http15_and_original_owner_clock",x.entry.includes("token, timeout=15)")&&x.entry.includes("return owner.remaining()"));
 check("strict_original_suite_once",x.entry.split("raw.run_original_pki12(executor, calls)").length===2&&x.entry.includes('acceptance.Suite(client, RUN_ID, {"pki"}, True)'));
 check("two_exact400_expectations",/self\.check\("pki\.lease_expire_lookup", expired, 400,/.test(x.acceptance)&&/self\.check\("pki\.revoked_lease_absent", r, 400,/.test(x.acceptance));
 check("preserved_suite_cleanup_and_partial",x.entry.includes("cleanup = executor.cleanup()")&&x.entry.includes("capture = raw.pki_public_result(executor, calls, cleanup, stop_reason)")&&x.entry.includes('"pki_wire_records": calls.records if calls is not None else []'));
 check("twelve_wire_cap",x.entry.includes("PKI_REQUEST_CAP = 12")&&x.entry.includes('need(capture["denominator"] == 12')&&x.entry.includes("len(calls.records) == 12"));
 check("no_old_acl_reexecution",!x.entry.includes("FixedAcl23(")&&x.entry.includes('"official_acl23_reexecuted": False')&&!x.entry.includes("MATRIX23.original.public.json"));
 check("fixed_resource_limits",x.entry.includes("REPORT_CAP = 1048576")&&x.entry.includes("FD_LIMIT = 10")&&x.entry.includes("len(FD_ROWS) == 9"));
 check("report_not_parity",x.entry.includes('"parity_qualified": False')&&x.entry.includes('"candidate_started": False')&&x.entry.includes('"startup_requests_actual_count": None'));
 check("fresh_root_and_port",x.entry.includes('ROOT = Path("/home/qian/heptabao-official271-pki12-oracle-20261106-r1")')&&x.entry.includes("PORT = 23627"));
 return {schema:"heptabao.official271-strict-pki12-source-checks.r1",passed:true,checks:checks.length,results:checks,pythonExecuted:false,runtimeCalls:0,productCasePasses:0};
}
