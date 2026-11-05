function verifyRetainedAFormat(raw,utf8,byteString,sha256,unb64,parseLossless,applyUnified){
 const checks=[];function ck(n,v){if(!v)throw Error(n);checks.push(n);}
 const hash=s=>sha256(byteString(utf8(s)));
 const unwrap=s=>{const x=JSON.parse(s);return x.content?.[0]?.text?JSON.parse(x.content[0].text):x;};
 const decode=b=>decodeURIComponent(unb64(b).map(x=>"%"+x.toString(16).padStart(2,"0")).join(""));
 const req=JSON.parse(raw["request.public.json"]),ack=JSON.parse(raw["actual/ack.public.json"]),authority=JSON.parse(raw["actual/authority.public.json"]),intent=JSON.parse(raw["intent.public.json"]);
 for(const [sdk,native] of [["native/ack.sdk.json","actual/ack.public.json"],["native/status.sdk.json","actual/authority.public.json"]])ck(sdk+" original exact bytes",JSON.parse(raw[sdk]).isError===false&&JSON.parse(raw[sdk]).content[0].text===raw[native]);
 ck("pre-submit exact intent",intent.request.sha256===hash(raw["request.public.json"])&&intent.request.bytes===utf8(raw["request.public.json"]).length&&intent.root_go.sha256===hash(raw["root-go.public.json"])&&intent.disposition==="EXACT_ONCE_NOT_YET_SUBMITTED");
 ck("unique original formatter job",ack.reused===false&&ack.job.id==="1a1ab3898ba-fc05-4b73"&&ack.job.launch_state==="launched"&&ack.launch.ok&&authority.job_id===ack.job.id);
 for(const k of ["host","executable","args","cwd","idempotency_key"])ck("exact ACK "+k,JSON.stringify(req[k])===JSON.stringify(ack.job[k]));
 const canonical=JSON.stringify({args:req.args,cpu_quota_percent:null,cwd:req.cwd,env:{},executable:req.executable,host:req.host,memory_max_bytes:null,nice:null,stdin:req.stdin,timeout_seconds:req.timeout_seconds});
 ck("original request canonical digest",hash(canonical)===ack.job.request_digest);
 ck("known authoritative full durable0",authority.state==="succeeded"&&authority.exit_code===0&&authority.output_complete&&authority.output_durable&&authority.terminal_publication_confirmed&&!authority.timed_out&&!authority.cancelled&&!authority.automatic_retry);
 const streams=unwrap(raw["native/terminal-read.sdk.json"]);ck("original streams exact job",streams.job_id===ack.job.id);
 for(const s of ["stdout","stderr"]){const x=streams[s],t=raw["actual/terminal."+s],b=utf8(t);ck(s+" original complete hex text EOF",x.text===t&&x.bytes_hex===b.map(x=>x.toString(16).padStart(2,"0")).join("")&&x.offset===0&&x.next_offset===b.length&&x.size===b.length&&x.eof);ck(s+" authority durable bytes",authority.log_bytes[s].seen===b.length&&authority.log_bytes[s].stored===b.length&&authority.log_synced[s]&&!authority.log_truncated[s]&&authority.log_errors[s]===null);}
 const plan=JSON.parse(raw["retrieval/fixed-plan.public.json"]),requests=JSON.parse(raw["retrieval/exact-requests.public.json"]);
 ck("six fixed outputs exact independent retrieval",plan.fixed_outputs.length===6&&requests.files.length===6);
 for(let i=0;i<6;i++){
  const key=String(i).padStart(2,"0"),info=unwrap(raw["native/file-info-"+key+".sdk.json"]),read=unwrap(raw["native/binary-read-"+key+".sdk.json"]),file=raw["outputs/"+plan.fixed_outputs[i]],r=requests.files[i];
  ck("output"+i+" pinned request binding",r.file_info.host==="rog"&&r.binary_read.host==="rog"&&r.file_info.path===r.binary_read.path&&r.binary_read.path===info.path&&info.path===read.path&&read.path===plan.root+"/"+plan.fixed_outputs[i]&&r.binary_read.expected_version===info.version&&info.version===read.version);
  ck("output"+i+" whole bytes",decode(read.data_base64)===file&&read.offset===0&&read.next_offset===utf8(file).length&&read.eof&&read.size===utf8(file).length&&read.chunk_sha256===hash(file)&&info.sha256===hash(file)&&info.size===read.size);
  ck("output"+i+" independent regular-file metadata",info.mode===384&&info.metadata.uid===1000&&info.metadata.gid===1000&&info.metadata.link_count===1);
 }
 const core=parseLossless(raw["outputs/result.public.json"]),terminal=JSON.parse(raw["actual/terminal.stdout"]);
 ck("formatter only successful bounded actual",core.status==="passed"&&terminal.status==="passed"&&core.withinDeadline&&terminal.withinDeadline&&core.elapsedSeconds<50&&terminal.elapsedSeconds<50&&core.internalSeconds===50&&core.newRemoteSupervisorSeconds===60&&req.timeout_seconds===60&&!core.compileExecuted&&!core.productExecuted&&!core.productionChanged);
 ck("one original10 child reaped same supervisor group",core.children.length===1&&core.children[0].exitCode===0&&core.children[0].reaped&&core.children[0].stopped&&core.children[0].pgid===core.children[0].supervisorGroup&&!core.children[0].newProcessGroupCreated&&core.children[0].timeoutSeconds===10&&core.allOwnedStopped&&terminal.allOwnedStopped);
 ck("tool full-nine before after exact",JSON.stringify(core.rustfmtBefore)===JSON.stringify(core.rustfmtAfter)&&core.rustfmtBefore.identity.length===9&&core.rustfmtBefore.sha256==="5005cdcd39ded526dca8fa6ccd716d42fc7da54469034e055dbf54649bec7877"&&core.rustfmtBefore.bytes===5255144);
 ck("explicit config full-nine before after exact",JSON.stringify(core.formatConfigurationBefore)===JSON.stringify(core.formatConfigurationAfter)&&core.formatConfigurationBefore.identity.length===9&&core.formatConfigurationBefore.sha256===hash(raw["outputs/rustfmt.toml"])&&raw["outputs/rustfmt.toml"]==='edition = "2024"\n');
 ck("input source and actual candidate whole bound",req.args[4]===raw["source/controller.py"]&&req.stdin===raw["source/stdin.public.json"]&&core.inputCarrierSha256===hash(req.stdin)&&JSON.parse(req.stdin)[core.files[0].name]===raw["outputs/candidate/"+core.files[0].name]);
 const name=core.files[0].name,before=raw["reference/base-test.rs"],candidate=raw["outputs/candidate/"+name],formatted=raw["outputs/formatted/"+name];
 ck("actual formatter stdout equals formatted file",formatted===raw["outputs/"+name+".rustfmt.stdout"]&&raw["outputs/"+name+".rustfmt.stderr"]==="");
 ck("source sizes hashes exact formatter result",core.files.length===1&&core.files[0].beforeSha256===hash(candidate)&&core.files[0].afterSha256===hash(formatted)&&core.files[0].beforeBytes===utf8(candidate).length&&core.files[0].afterBytes===utf8(formatted).length);
 const fd=applyUnified(candidate,raw["diffs/rustfmt.diff"]),bd=applyUnified(before,raw["diffs/base-to-formatted.diff"]);
 ck("one formatter hunk strict forward bytes",fd.text===formatted&&fd.hunks===1&&candidate.replace(/\s/g,"")===formatted.replace(/\s/g,""));
 ck("four base correction hunks strict bytes",bd.text===formatted&&bd.hunks===4);
 const assertions=s=>s.split("\n").filter(x=>/^\s*assert(?:_[a-z]+)?!\(/.test(x));
 ck("all30 assertions exact",assertions(before).length===30&&JSON.stringify(assertions(before))===JSON.stringify(assertions(formatted)));
 const tail="    assert_eq!(third.root_digest(), first.root_digest());";
 ck("third equality and all warm cold reopen suffix exact",before.slice(before.indexOf(tail))===formatted.slice(formatted.indexOf(tail)));
 return {schema:"heptabao.root.retained-a-formatter-actual-verification.v1",status:"PASS_FORMATTING_ONLY",checks_count:checks.length,checks,job:ack.job.id,formatted:{bytes:utf8(formatted).length,sha256:hash(formatted)},no_rust_compile:true,no_regression_qualification:true};
}
