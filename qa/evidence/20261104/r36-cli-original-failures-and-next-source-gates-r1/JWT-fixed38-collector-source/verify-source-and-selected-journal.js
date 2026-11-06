function verifyFormatter38Source(input) {
 const checks=[];
 function check(name,value,details=null){checks.push({name,pass:!!value,details});if(!value)throw Error(name);}
 function eq(a,b){return JSON.stringify(a)===JSON.stringify(b);}
 function mustThrow(name,fn){let refused=false;try{fn();}catch(e){refused=true;}check(name,refused);}
 function pydef(s,name,indent=0){
  const lines=s.split("\n"),needle=" ".repeat(indent)+"def "+name+"(";
  const start=lines.findIndex(x=>x.startsWith(needle));if(start<0)throw Error("missing "+name);
  let end=start+1;
  while(end<lines.length){const line=lines[end];if(line.trim() && line.length-line.trimStart().length<=indent)break;end++;}
  return lines.slice(start,end).join("\n")+"\n";
 }
 function strictUnified(base,patch,reverse=false){
  const a=base.match(/[^\n]*\n|[^\n]+$/g)||[],lines=patch.match(/[^\n]*\n|[^\n]+$/g)||[];
  if(lines.length<3||!lines[0].startsWith("--- ")||!lines[1].startsWith("+++ "))throw Error("headers");
  let pos=2,cursor=0,out=[],hunks=0;
  while(pos<lines.length){
   const m=lines[pos++].match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\n$/);if(!m)throw Error("hunk");
   let os=Number(m[1]),oc=m[2]===undefined?1:Number(m[2]),ns=Number(m[3]),nc=m[4]===undefined?1:Number(m[4]);
   if(reverse){[os,ns]=[ns,os];[oc,nc]=[nc,oc];}
   const at=oc?os-1:os,nt=nc?ns-1:ns;
   if(at<cursor||at>a.length||at+oc>a.length)throw Error("range");
   out.push(...a.slice(cursor,at));cursor=at;if(out.length!==nt)throw Error("new offset");
   let oldN=0,newN=0;
   while(pos<lines.length&&!lines[pos].startsWith("@@ ")){
    const line=lines[pos++];let tag=line[0];if(!" +-".includes(tag))throw Error("kind");
    if(reverse)tag=tag==="+"?"-":tag==="-"?"+":tag;
    const body=line.slice(1);
    if(tag===" "||tag==="-"){if(a[cursor]!==body)throw Error("context");cursor++;oldN++;}
    if(tag===" "||tag==="+"){out.push(body);newN++;}
    if(oldN>oc||newN>nc)throw Error("overflow");
   }
   if(oldN!==oc||newN!==nc)throw Error("counts");hunks++;
  }
  if(!hunks)throw Error("no hunks");out.push(...a.slice(cursor));return out.join("");
 }
 const {source,rows,plan,receipt,requestRaw,journalBefore,journalAfter,journalDiff,replacements}=input;
 check("collector.source-pin",eq(gitBlobMeta(source),plan.collector_source));
 check("request.original-pin",eq(gitBlobMeta(requestRaw),plan.exact_request));
 const q=JSON.parse(requestRaw),sourcePin=gitBlobMeta(source);
 check("request.exact-host-executable-cwd",q.host==="rog"&&q.executable==="/usr/bin/python3"&&q.cwd==="/home/qian-qi");
 check("request.exact-inline-isolation-selfsha",eq(q.args,["-I","-S","-B","-c",source,sourcePin.sha256]));
 check("request.original-outer-60",q.timeout_seconds===60);
 check("request.unique-bounded-key",q.idempotency_key==="heptabao-native-jwt-e3afc157-format38-collector-20261106-r1-"+sourcePin.sha256.slice(0,8)&&q.idempotency_key.length<=128);
 check("request.no-stdin",!Object.hasOwn(q,"stdin"));
 const literal=source.split("\n").find(x=>x.startsWith("ROWS=json.loads("));
 check("rows.exact-source-literal",eq(JSON.parse(JSON.parse(literal.slice(16,-1))),rows));
 check("rows.fixed38-unique",rows.length===38&&new Set(rows.map(x=>x.path)).size===38&&rows.every((x,i)=>x.index===i));
 check("rows.original-per-file-success-cap",rows.reduce((s,x)=>s+x.cap,0)===7906155);
 check("rows.actual-input-byte-total",rows.reduce((s,x)=>s+x.bytes,0)===3701083);
 check("rows.fixed-public-root",rows.every(x=>x.path===plan.input_root+"/"+x.relative&&!x.relative.split("/").some(t=>t===".."||t==="."||t==="")));
 check("rows.only-config-receipt-prior-full9",rows.filter(x=>x.expected_full9!==null).map(x=>x.role).join(",")==="config,receipt");
 check("rows.full9-decimal-strings",rows.filter(x=>x.expected_full9!==null).every(x=>x.expected_full9.length===9&&x.expected_full9.every(y=>/^\d+$/.test(y))));
 for(let i=0;i<9;i++){
  const group=rows.slice(i*4,i*4+4),r=receipt.files[i],a=group[0],b=group[1],o=group[2],e=group[3];
  check("quartet."+i+".fixed-role-order",group.map(x=>x.role).join(",")==="candidate,formatted,stdout,stderr"&&group.every(x=>x.name===r.name));
  check("quartet."+i+".candidate-receipt",a.bytes===r.beforeBytes&&a.sha256===r.beforeSha256&&/^[a-f0-9]{40}$/.test(a.canonical_blob));
  check("quartet."+i+".formatted-receipt-stdout",b.bytes===r.afterBytes&&b.sha256===r.afterSha256&&b.bytes===o.bytes&&b.sha256===o.sha256);
  check("quartet."+i+".stderr-empty-cap",e.bytes===0&&e.sha256===gitBlobMeta("").sha256&&e.cap===65536);
 }
 check("receipt.source-actual",receipt.sourceCommit===plan.source_commit&&receipt.sourceTree===plan.source_tree&&receipt.status==="passed");
 check("receipt.only-direct-reaped-not-independent-groups",receipt.children.length===9&&receipt.children.every(x=>x.exitCode===0&&x.reaped===true&&x.stopped===true&&x.newProcessGroupCreated===false&&x.pgid===x.supervisorGroup)&&source.includes('"independent_group_empty_observed":False'));
 check("source.deadline-single-initialization",(source.match(/^START=/gm)||[]).length===1&&(source.match(/^LIMIT=/gm)||[]).length===1&&source.includes("LIMIT=50.0"));
 check("source.no-reset-read-budget",(source.match(/self\.read_bytes=0/g)||[]).length===1&&source.includes("READ_CAP=7906155")&&source.includes("self.read_bytes+=len(data)"));
 const read=pydef(source,"read",1),acquire=pydef(source,"acquire",1),close=pydef(source,"close_once",1),closeAll=pydef(source,"close_all",1),main=pydef(source,"main"),pub=pydef(source,"publish_report");
 check("read.global-byte-cap-before-os-read",read.indexOf("count<=READ_CAP-self.read_bytes")<read.indexOf("data=os.read("));
 check("read.returned-bytes-accounted-before-postcheck",read.indexOf("self.read_bytes+=len(data)")>read.indexOf("data=os.read(")&&read.lastIndexOf("self.check()")>read.indexOf("self.read_bytes+=len(data)"));
 check("read.one-byte-eof-probe-shares-cap",pydef(source,"read_exact").includes('part=c.read(fd,min(READ_CHUNK,remaining+1),kind)'));
 check("report.readback-same-read-budget",pub.includes('read_exact(c,out["fd"],len(raw),"report")'));
 check("resource.maximum-success-read-bytes",3701083+1048576===4749659&&4749659<=7906155&&plan.resources_success_bound.maximum_read_bytes===4749659);
 const inputCalls=rows.reduce((s,x)=>s+Math.ceil(x.bytes/65536)+1,0);
 check("resource.maximum-success-read-calls",inputCalls===112&&inputCalls+17===129&&129<=256);
 check("resource.metadata-call-budget",plan.resources_success_bound.maximum_metadata_calls===273&&273<=320&&source.includes("META_CAP=320"));
 check("fd.preallocated-ledger-before-acquire",acquire.indexOf("self.ledger.append(record)")<acquire.indexOf('record["fd"]=os.open('));
 check("fd.both-open-branches-register-before-postcheck",(acquire.match(/record\["fd"\]=os\.open/g)||[]).length===2&&acquire.lastIndexOf("self.check()")>acquire.lastIndexOf('record["fd"]=os.open('));
 check("fd.close-marker-before-single-close",close.indexOf('record["close_attempted"]=True')<close.indexOf('os.close(record["fd"])')&&(source.match(/os\.close\(/g)||[]).length===1);
 check("fd.close-error-never-retried",close.includes('record["fd"] is None or record["close_attempted"]')&&close.includes('record["close_error"]=type(e).__name__'));
 check("fd.final-cleanup-attempts-all-without-deadline-block",closeAll.includes("for record in reversed(self.ledger)")&&!closeAll.includes("check("));
 check("fd.input38-known-close-before-publication",main.indexOf("recheck_inputs_and_close(c)")<main.indexOf("publish_report(c,report)")&&pydef(source,"recheck_inputs_and_close").includes('"input_once_close"'));
 check("fd.success-requires-all46",main.includes('and len(c.ledger)==46 and all(x["fd"] is not None for x in c.ledger)'));
 check("fd.peak44-and-acquisition46",source.includes("FD_CAP=46")&&source.includes("PEAK_FD_CAP=44")&&plan.resources_success_bound.total_acquisitions===46);
 check("signals.pending-only-handler",pydef(source,"mark_signal",1).trim()==='def mark_signal(self,signum,frame):\n  self.pending_signal=signum');
 check("signals.finally-close-then-restore",main.indexOf("finally:\n  c.close_all()\n  c.restore()")>=0&&main.indexOf("summary=")>main.indexOf("c.restore()"));
 check("signals.failed-restore-refuses-success",main.includes("and all_closed and handlers_restored and c.umask_restored"));
 check("namespace.shared3-stable-object-owned3-full9",pydef(source,"directory_pair").includes('a[:5]==b[:5]==record["before"][:5]')&&pydef(source,"directory_pair").includes('a==b==record["before"]')&&source.split("\n").filter(x=>x.startsWith(' ("')).length===6);
 check("namespace.all-input-full9-with-ns",pydef(source,"input_pair").includes('must(a==b==record["before"]')&&pydef(source,"identity").includes("s.st_mtime_ns,s.st_ctime_ns"));
 check("namespace.input-no-follow-regular-600-single-link",pydef(source,"open_inputs").includes("os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK")&&pydef(source,"open_inputs").includes("held.st_nlink==1 and held.st_mode==(stat.S_IFREG|0o600)"));
 check("publish.sole-new-root-and-file",pub.includes("os.mkdir(OUTPUT_NAME,0o700,dir_fd=parent)")&&pub.includes("os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,0o600")&&(source.match(/os\.mkdir\(/g)||[]).length===1);
 check("publish.no-delete-overwrite-or-retry",!/\bos\.(?:unlink|remove|rename|replace|rmdir|truncate|ftruncate|chmod|chown|link|symlink)\s*\(/.test(source)&&!source.includes("O_TRUNC"));
 check("publish.same-fd-byte-readback",pub.includes('observed=read_exact(c,out["fd"],len(raw),"report")')&&pub.includes('must(observed==raw and sha(observed)==sha(raw)')&&pub.includes('file_after==named_after==file_before'));
 check("publish.report-not-self-qualified-final",main.includes('"output_and_directory_fd_closure_requires_final_stdout_and_authority":True')&&main.includes('"input_observations_are_sequential":True'));
 check("output.final-stdout-postfinally-and-after-flush-deadline",main.indexOf("sys.stdout.write(output)")>main.indexOf("c.close_all()")&&main.includes("sys.stdout.flush()\n return 0 if success and time.monotonic()-START<LIMIT else 1"));
 check("output.failure-does-not-print-private-exception-body",main.includes('"code":str(e) if isinstance(e,Refused) else None')&&!source.includes("traceback"));
 check("scope.no-child-network-listing-private-path",!/\b(?:subprocess|socket|requests|urllib|scandir|listdir|walk|popen|fork|execve|system)\b/.test(source)&&!source.includes("openbao.db")&&!source.includes("sqlite"));
 check("scope.os-call-set-closed",eq([...new Set([...source.matchAll(/\bos\.([a-z_]+)\(/g)].map(x=>x[1]))].sort(),["close","fsync","lseek","mkdir","open","read","umask","write"].sort())&&source.includes("c.metadata(os.fstat,")&&source.includes("c.metadata(os.stat,"));
 const diff=pydef(source,"make_diffs"),apply=pydef(source,"strict_apply");
 check("diff.actual-both-opened-file-bytes",diff.includes('before=data[a["relative"]]')&&diff.includes('after=data[b["relative"]]')&&diff.includes('must(data[o["relative"]]==after and data[e["relative"]]==b""'));
 check("diff.fixed-headers-and-context3",diff.includes('fromfile="a/"+a["name"],tofile="b/"+a["name"],n=3,lineterm="\\n"'));
 check("diff.all-yielded-bytes-checked",diff.includes('patch_bytes+=len(line.encode("utf-8"))')&&diff.includes('must(total+patch_bytes<=DIFF_CAP'));
 check("diff.forward-and-reverse-byte-hash",diff.includes("rebuilt==after and restored==before")&&diff.includes('sha(rebuilt)==b["sha256"] and sha(restored)==a["sha256"]'));
 check("diff.unchanged3-explicit",diff.includes('changed==6 and len(result)-changed==3')&&diff.includes('bool(patch)==is_changed'));
 check("diff.strict-no-fuzz-exact-headers",apply.includes('lines[0]=="--- a/"+name+"\\n"')&&apply.includes('original[cursor]==body')&&apply.includes('used_old==old_count and used_new==new_count')&&apply.includes('len(out)==new_at'));
 check("journal.exact-after-pin",eq(gitBlobMeta(journalAfter),plan.journal_source));
 let rebuilt=journalBefore;
 for(const [before,after]of replacements){check("journal.unique-literal."+checks.length,rebuilt.split(before).length===2);rebuilt=rebuilt.replace(before,after);}
 check("journal.only3-literal-slots",replacements.length===3&&rebuilt===journalAfter);
 check("journal.diff-forward-whole",strictUnified(journalBefore,journalDiff)===journalAfter);
 check("journal.diff-reverse-whole",strictUnified(journalAfter,journalDiff,true)===journalBefore);
 const noTools=new Proxy({}, {get(){throw Error("offline-tools-forbidden");}});
 const local=new Map();
 const journal=new Function("tools","store","load",input.pure+"\n"+input.archive+"\n"+journalAfter+
  "\nreturn {validate:gfValidateRequest,slot:GF_SLOT};")(noTools,(k,v)=>local.set(k,v),k=>local.get(k));
 const fresh={paused:false,nativeCallInFlight:false,pending:null,startCalled:false,job:null,activeObserver:null,nextStdout:0,nextStderr:0};
 journal.validate(fresh,"process_start",q,requestRaw);check("journal.actual-guard-exact-start",true);
 mustThrow("journal.refuses-start-after-once",()=>journal.validate({...fresh,startCalled:true},"process_start",q,requestRaw));
 mustThrow("journal.refuses-request-byte-change",()=>journal.validate(fresh,"process_start",q,requestRaw+" "));
 const state={...fresh,startCalled:true,job:"fixed-public-fixture-job"};
 const status={idempotency_key:"heptabao-native-jwt-e3afc157-format38-observe-r1-status0",operation:{tool:"process_status",arguments:{host:"rog",job_id:state.job}}};
 journal.validate(state,"operation_start",status,JSON.stringify(status));check("journal.actual-guard-same-job-status",true);
 mustThrow("journal.refuses-host-change",()=>journal.validate(state,"operation_start",{...status,operation:{tool:"process_status",arguments:{host:"desktop",job_id:state.job}}},""));
 mustThrow("journal.refuses-job-change",()=>journal.validate(state,"operation_start",{...status,operation:{tool:"process_status",arguments:{host:"rog",job_id:"other-public-job"}}},""));
 mustThrow("journal.refuses-old-observer-prefix",()=>journal.validate(state,"operation_start",{...status,idempotency_key:"heptabao-native-jwt-e3afc157-formatter-observe-r1-status0"},""));
 mustThrow("journal.refuses-file-info-or-body-scope",()=>journal.validate(state,"operation_start",{...status,operation:{tool:"file_info",arguments:{host:"rog",job_id:state.job}}},""));
 const readReq={idempotency_key:"heptabao-native-jwt-e3afc157-format38-observe-r1-streams0",operation:{tool:"process_read",arguments:{host:"rog",job_id:state.job,limit:16384,stdout_offset:0,stderr_offset:0}}};
 journal.validate(state,"operation_start",readReq,"");check("journal.actual-guard-stream16384",true);
 mustThrow("journal.refuses-stream-offset-change",()=>journal.validate(state,"operation_start",{...readReq,operation:{...readReq.operation,arguments:{...readReq.operation.arguments,stdout_offset:1}}},""));
 mustThrow("journal.refuses-stream-cap-change",()=>journal.validate(state,"operation_start",{...readReq,operation:{...readReq.operation,arguments:{...readReq.operation.arguments,limit:65536}}},""));
 const oid="a".repeat(64),closed={...state,activeObserver:{id:oid,futureClosed:true,nextPageOffset:0,eof:false}};
 journal.validate(closed,"operation_result",{operation_id:oid,offset:0,limit:8192},"");check("journal.actual-guard-original-page8192",true);
 mustThrow("journal.refuses-page-cap-change",()=>journal.validate(closed,"operation_result",{operation_id:oid,offset:0,limit:16384},""));
 mustThrow("journal.refuses-page-before-native-closed",()=>journal.validate({...closed,activeObserver:{...closed.activeObserver,futureClosed:false}},"operation_result",{operation_id:oid,offset:0,limit:8192},""));
 check("journal.selected-guards-no-Tools-no-state-mutation",local.size===0);
 return {schema:"heptabao.formatter38-source-offline-verification.v1",passed:true,checks,
  scope:{source_literal_controlflow_and_resource_checks:true,actual_selected_journal_guards:true,
   python_collector_execution:false,python_compilation:false,collector_runtime:false,product_cases:0,
   strict_diff_runtime_correctness:"reviewed source; actual bidirectional reconstruction required inside the separately authorized observer",
   limitation:"No claim that lexical/source checks execute Python, perform OS custody, or qualify the 38 current output identities."}};
}
