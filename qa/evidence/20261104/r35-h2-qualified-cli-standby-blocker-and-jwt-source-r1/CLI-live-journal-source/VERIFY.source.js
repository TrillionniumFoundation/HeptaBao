function verifyCliGitFirstLiteralAdapter(files) {
 const H=eval(files["pure_helpers.js"]+";({meta:gitBlobMeta})");
 const D=eval(files["strict_diff.js"]+";({apply:strictApplyText})");
 const rows=[];
 function check(label,value){rows.push({label,pass:value===true});}
 const before=files["native_gitfirst.before.js"],after=files["native_gitfirst.cli.js"];
 const subs=JSON.parse(files["substitutions.public.json"]);
 let forward=before;
 for(const x of subs){check(x.label+"_unique_before",forward.split(x.old).length===2);forward=forward.replace(x.old,x.next);}
 check("only_five_named_replacements",forward===after);
 let inverse=after;
 for(const x of [...subs].reverse()){check(x.label+"_unique_after",inverse.split(x.next).length===2);inverse=inverse.replace(x.next,x.old);}
 check("inverse_complete_original_19027",inverse===before);
 const f=D.apply(before,files["native_gitfirst.review.diff"]),r=D.apply(after,files["native_gitfirst.review.diff"],true);
 check("three_strict_forward_hunks",f.hunks===3&&f.text===after);
 check("three_strict_reverse_hunks",r.hunks===3&&r.text===before);
 const sf=D.apply(files["steps.before.source.js"],files["steps.review.diff"]),sr=D.apply(files["steps.cli.source.js"],files["steps.review.diff"],true);
 check("one_strict_steps_forward_hunk",sf.hunks===1&&sf.text===files["steps.cli.source.js"]);
 check("one_strict_steps_reverse_hunk",sr.hunks===1&&sr.text===files["steps.before.source.js"]);
 function defs(s){const a=[...s.matchAll(/^(?:async )?function ([A-Za-z0-9_]+)\(/gm)];return a.map((x,i)=>({name:x[1],text:s.slice(x.index,a[i+1]?.index??s.length)}));}
 const bd=defs(before),ad=defs(after);
 check("same_function_names_order",JSON.stringify(bd.map(x=>x.name))===JSON.stringify(ad.map(x=>x.name)));
 for(let i=0;i<bd.length;i++){
  const old=bd[i],now=ad[i];
  let expected=old.text;
  for(const x of subs)expected=expected.split(x.old).join(x.next);
  check("function_exact_"+old.name,now.text===expected);
 }
 const changed=bd.filter((x,i)=>x.text!==ad[i].text).map(x=>x.name);
 check("only_two_host_prefix_function_edits",JSON.stringify(changed)===JSON.stringify(["gfValidateRequest","gfAcceptArchivedSDK"]));
 const calls=s=>[...s.matchAll(/tools\.([A-Za-z0-9_]+)\(/g)].map(x=>x[1]);
 check("identical_tool_call_statements",JSON.stringify(calls(before))===JSON.stringify(calls(after)));
 check("no_local_executor_or_fallback",!/(exec_command|apply_patch|write_stdin|fsync|fetch\()/.test(after.replace(/github_fetch\(/g,"github_tree_get(")));
 const requestRaw=files["request.exact.json"],q=JSON.parse(requestRaw),meta=H.meta(requestRaw);
 check("exact_746_request",meta.blob==="2c0692832bfe24fe8b728589900896ae64152852"&&meta.bytes===746&&meta.sha256==="11951f04874e55849a27d6abe812118124055245adfd8dd6321779a3b10886da");
 check("original_desktop_python",q.host==="desktop"&&q.executable==="/usr/bin/python3.12");
 check("original_timeout_3000",q.timeout_seconds===3000);
 check("original_r4_key",q.idempotency_key==="heptabao-official271-phaseb-4e808-live-10816-20261105-r4");
 check("fixed_binding_sha",q.args[q.args.indexOf("--binding-sha256")+1]==="7ef3458f4a54b74336941229307c0ffb6778e581c18b27518dc03a8fe6107eea");
 check("actual_prepare_sha",q.args[q.args.indexOf("--prepare-result-sha256")+1]==="8d9809f9da2493cb7f9d1ae8855ff31dab8464cc3919ea7fcd02163087cac615");
 const calc=eval(files["pure_helpers.js"]+"\n;("+files["process_start_binding_correct.js"]+")");
 const b=calc(q);
 check("typed_digest_correct_stdin",b.sha256==="f670cf418c6ae40943b7f0224e09f0bd556ceb3b5975c377ad0e524a317f5cd7");
 check("lossless_fingerprint",b.native_fingerprint==="17757921211157505033");
 check("canonical_stdin_null",JSON.parse(b.canonical).stdin===null&&!b.canonical.includes('"stdin_text"'));
 for(const x of [
  ["pure_helpers.js","b6890e8b7217c546bec073dcb04988fc37652721",6685,"44becefac5fb2ee5018a9044c4b32cf0f44f9ed4b59f9d4c0fb2d62ca5c93432"],
  ["git_archive_once.js","b093fdbf655511f7db94be2d95555606141bbb42",5957,"8153be93b7e737fb22ae010611ebd9c09d555e9663ce867e766f899563276397"],
  ["process_start_binding_correct.js","82e81aef13d858c865ea05dd762056553a3d1cc6",659,"e98c61fceb6eecdd55e6244ad43939320114809163afee67a6b8657235dae042"]
 ]){const p=H.meta(files[x[0]]);check("unchanged_"+x[0],p.blob===x[1]&&p.bytes===x[2]&&p.sha256===x[3]);}
 check("original_8192_page_cap",after.includes("q.limit===8192")&&after.includes("b.length<=8192"));
 check("original_16384_stream_cap",after.includes("a.limit===16384")&&after.includes("b.length<=16384"));
 check("original_1MiB_payload_cap",after.includes("v.total_bytes<=1048576"));
 check("no_file_observers_added",!after.includes('op.tool==="file_info"')&&!after.includes('op.tool==="binary_read"'));
 const syntax=new Function(files["pure_helpers.js"]+"\n"+files["git_archive_once.js"]+"\n"+after+"\nreturn {gfRun};");
 check("V8_compile_only",typeof syntax==="function");
 return {schema:"heptabao.official271-phaseb.gitfirst-literal-source-checks.r1",scope:"offline source and exact binding only",runtime_calls:0,candidate_functions_invoked:0,definition_count:bd.length,unchanged_definitions:bd.length-changed.length,checks:rows.length,passed:rows.filter(x=>x.pass).length,rows,candidate:H.meta(after),request:meta,binding:b};
}
