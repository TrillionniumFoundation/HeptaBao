function verifyFormatterJournal(data,pureSource) {
 const P=new Function(pureSource+"\nreturn {gitBlobMeta};")();
 const checks=[];function ck(name,v){checks.push({name,pass:!!v});if(!v)throw Error(name);}
 const {before,after,replacements:r,diff,requestRaw:req}=data,rp=P.gitBlobMeta(req),q=JSON.parse(req);
 let forward=before;for(const x of r){ck("one_before_"+x.why,forward.split(x.before).length===2);forward=forward.replace(x.before,x.after);}
 ck("forward_whole",forward===after);for(const x of [...r].reverse()){ck("one_after_"+x.why,forward.split(x.after).length===2);forward=forward.replace(x.after,x.before);}
 ck("reverse_whole",forward===before);
 ck("exact_formatter_request",rp.blob==="0ec62f939a62a2a23c73e33d25f1043957aeeb58"&&rp.bytes===12372&&rp.sha256==="1ad41c45534f842fdd7010ab184db3f46460f87f8ead786efc142461b709bc91");
 ck("operator_host_rog",q.host==="rog");ck("outer60",q.timeout_seconds===60);
 ck("request_key",q.idempotency_key==="heptabao-native-jwt-e3afc157-format-20261106-r1-f12b91c2");
 ck("inline_isolated_flags",q.executable==="/usr/bin/python3"&&q.args.slice(0,4).join(",")==="-I,-S,-B,-c");
 ck("candidate_exact",P.gitBlobMeta(q.args[4]).blob==="1266e75033bee0962b0d77d3c35ee19ec53086db");
 ck("two_actual_diff_hunks",(diff.match(/^@@/gm)||[]).length===2);
 function defs(t){const a=[...t.matchAll(/^(?:async )?function ([A-Za-z0-9_]+)\(/gm)],o={};for(let i=0;i<a.length;i++)o[a[i][1]]=t.slice(a[i].index,i+1<a.length?a[i+1].index:t.length);return o;}
 const bf=defs(before),af=defs(after);ck("same_13_defs",Object.keys(bf).length===13&&JSON.stringify(Object.keys(bf))===JSON.stringify(Object.keys(af)));
 for(const name of Object.keys(bf))ck("def_"+name,name==="gfValidateRequest"?af[name].replace(r[2].after,r[2].before)===bf[name]:bf[name]===af[name]);
 ck("two_host_bindings_same_rog",(after.match(/(?:a\.host|v\.job\?\.host)==="rog"/g)||[]).length===2);
 ck("no_file_or_body_new_branch",!after.includes('op.tool==="file_info"')&&!after.includes('op.tool==="binary_read"'));
 ck("stream16384_retained",after.includes("a.limit===16384")&&after.includes("b.length<=16384"));
 ck("page8192_retained",after.includes("q.limit===8192")&&after.includes("b.length<=8192"));
 ck("old_binding_function_never_called",!after.includes("processStartBinding("));
 return {schema:"heptabao.native-jwt.formatter-journal.source-checks.v1",checks,passed:checks.length,RuntimeCalls:0,GitMutations:0,helperFunctionsExecuted:false,formatterExecuted:false,sourceOnly:true};
}