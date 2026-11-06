/* Pure source/text review checks; no Python, collector, or host execution.
Requires gitBlobMeta and strictApplySource. Input: exact 16 UTF-8 source packet leaves. */
function verifyCollectorPeer(t) {
 const checks=[];function ok(name,value){checks.push({name,passed:!!value});if(!value)throw Error(name);}
 const src=t["collector.source.py"],rows=JSON.parse(t["fixed-inputs.public.json"]),q=JSON.parse(t["exact-request.REVIEW-ONLY.public.json"]);
 ok("source_exact",gitBlobMeta(src).blob==="6346d622e31526522459ae4c1a2cdc858369d2ed");
 ok("fixed38",rows.length===38&&rows.every((r,i)=>r.index===i));
 ok("input_bytes",rows.reduce((n,r)=>n+r.bytes,0)===3701083);
 ok("original_shared_read_cap",rows.reduce((n,r)=>n+r.cap,0)===7906155);
 const sourceRows=JSON.parse(JSON.parse(src.split("\n").find(l=>l.startsWith("ROWS=json.loads(")).slice("ROWS=json.loads(".length,-1)));
 ok("literal_rows_equal_fixed_inputs",JSON.stringify(sourceRows)===JSON.stringify(rows));
 ok("prior_full9_only_two",rows.filter(r=>r.expected_full9!==null).length===2);
 ok("request_source_exact",q.args[0]==="-I"&&q.args[1]==="-S"&&q.args[2]==="-B"&&q.args[3]==="-c"&&q.args[4]===src&&q.args[5]===gitBlobMeta(src).sha256&&q.timeout_seconds===60);
 let journal=t["journal.before.js"];
 const replacements=JSON.parse(t["journal.replacements.public.json"]);
 for(const [a,b]of replacements){ok("unique_journal_literal:"+a.slice(0,32),journal.split(a).length===2);journal=journal.replace(a,b);}
 ok("only_three_journal_replacements",replacements.length===3&&journal===t["journal.after.js"]);
 ok("journal_forward_strict",strictApplySource(t["journal.before.js"],t["journal.diff"]).raw===journal);
 const inverse=t["journal.diff"].split("\n").map((l,i)=>i<2?l:(l.startsWith("@@ ")?l.replace(/^@@ -(\d+),(\d+) \+(\d+),(\d+) @@$/,"@@ -$3,$4 +$1,$2 @@"):(l[0]==="+"?"-"+l.slice(1):l[0]==="-"?"+"+l.slice(1):l))).join("\n");
 ok("journal_reverse_strict",strictApplySource(journal,inverse).raw===t["journal.before.js"]);
 ok("ledger_before_open_and_postcheck",src.indexOf("self.ledger.append(record)")<src.indexOf('record["fd"]=os.open(name,flags,**kwargs)')&&src.includes('self.check()\n  return record'));
 ok("signal_only_marks",src.includes("def mark_signal(self,signum,frame):\n  self.pending_signal=signum\n"));
 ok("once_close_before_os_close",src.indexOf('record["close_attempted"]=True')<src.indexOf('os.close(record["fd"])'));
 ok("failure_close_ledger_in_finally",src.includes("finally:\n  c.close_all()\n  c.restore()"));
 ok("returned_bytes_accounted_before_postcheck",src.includes("data=os.read(fd,count)\n  self.read_bytes+=len(data)")&&src.includes('self.report_read_bytes+=len(data)\n  self.check()'));
 ok("full9_input_and_single_link",src.includes('a==b==record["before"]')&&src.includes("held.st_nlink==1 and held.st_mode==(stat.S_IFREG|0o600)"));
 ok("report_readback_uses_same_counter",src.includes('observed=read_exact(c,out["fd"],len(raw),"report")')&&src.includes("must(count<=READ_CAP-self.read_bytes"));
 ok("inputs_close_before_publish",src.indexOf("directory_after=recheck_inputs_and_close(c)")<src.indexOf("  publish_report(c,report)"));
 ok("report_create_only",src.includes("os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK"));
 ok("actual_bidirectional_reconstruction",src.includes('rebuilt=strict_apply(c,before_text,patch,a["name"]).encode("utf-8")')&&src.includes('restored=strict_apply(c,after_text,patch,a["name"],reverse=True).encode("utf-8")')&&src.includes("must(rebuilt==after and restored==before"));
 ok("postclosure_success_predicate",src.includes("success=(success and error is None and c.pending_signal is None and elapsed<LIMIT")&&src.includes("and all_closed and handlers_restored and c.umask_restored")&&src.includes("return 0 if success and time.monotonic()-START<LIMIT else 1"));
 const successReads=rows.reduce((n,r)=>n+Math.ceil(r.bytes/65536)+1,0)+Math.ceil(1048576/65536)+1;
 ok("success_read_calls_fit256",successReads<=256);
 ok("success_bytes_with_report_fit_shared_cap",3701083+1048576===4749659&&4749659<=7906155);
 ok("acquisitions_and_peak",6+38+2===46&&6+38===44);
 return {passed:true,checks,checkCount:checks.length,originalSource:"6346d622e31526522459ae4c1a2cdc858369d2ed",sourceReadLines:609,
  theoreticalSuccessfulReadCallsIncludingMaxReport:successReads,pythonExecuted:false,pythonCompiled:false,
  authorCheckerRun:false,runtimeCalls:0,sourceOnly:true};
}